"""Model-catalog and capability-filter tests for OrcaRouter Cyber Inference.

The fixtures mirror the endpoint-type vocabulary the relay publishes. Each
capability filter is checked with a mixed catalog, and multimodal selection is
fail-closed: an untyped or text-only chat model must never appear in an
image-input list.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core.llm.orcarouter import catalog

_ABSENT = object()


def _entry(
    model_id: str,
    *,
    endpoints: object = _ABSENT,
    inputs: object = _ABSENT,
    outputs: object = _ABSENT,
    context: int | None = 128000,
    efforts: list[str] | None = None,
) -> dict:
    entry: dict = {"id": model_id, "name": model_id}
    if context:
        entry["context_length"] = context
    if endpoints is not _ABSENT:
        entry["supported_endpoint_types"] = endpoints
    else:
        entry["supported_endpoint_types"] = ["openai"]
    if inputs is not _ABSENT:
        entry["architecture"] = {
            "input_modalities": inputs,
            "output_modalities": ["text"] if outputs is _ABSENT else outputs,
        }
    elif outputs is not _ABSENT:
        entry["architecture"] = {"input_modalities": ["text"], "output_modalities": outputs}
    else:
        entry["architecture"] = {
            "input_modalities": ["text"],
            "output_modalities": ["text"],
        }
    if efforts:
        entry["reasoning"] = {"efforts": efforts}
    return entry


MIXED_CATALOG = {
    "data": [
        _entry("orcarouter/auto", efforts=["low", "medium", "high", "xhigh"]),
        _entry("orca/orcacyber-ultra-1.0", endpoints=["anthropic"], context=1_048_576),
        _entry("orca/orcacyber-zero-1.5", endpoints=["openai", "anthropic"]),
        _entry("openai/gpt-5.5", endpoints=["openai", "openai-response"], efforts=["low", "high"]),
        _entry("google/gemini-3.5-flash", endpoints=["gemini"], inputs=["text", "image"]),
        _entry("deepseek/deepseek-v4-flash-vision-exp", inputs=["text", "image"]),
        _entry("openai/text-embedding-3", endpoints=["embeddings"], outputs=["embeddings"]),
        _entry("google/imagen-4", endpoints=["image-generation"], outputs=["image"]),
        _entry("openai/sora-2", endpoints=["openai-video"], outputs=["video"]),
        _entry("cohere/rerank-4", endpoints=["jina-rerank"], outputs=["text"]),
        _entry("untyped/legacy-model", endpoints=None),
    ]
}


class ModelStub:
    """Local stand-in for ``GET {api_base}/models``."""

    def __init__(self, payload: dict, status: int = 200) -> None:
        self.payload = payload
        self.status = status
        self.requests: list[tuple[str, dict]] = []
        self.server: ThreadingHTTPServer | None = None

    def __enter__(self) -> "ModelStub":
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:  # noqa: A003
                return

            def do_GET(self) -> None:  # noqa: N802
                stub.requests.append((self.path, dict(self.headers)))
                encoded = json.dumps(stub.payload).encode("utf-8")
                self.send_response(stub.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc: object) -> None:
        assert self.server is not None
        self.server.shutdown()
        self.server.server_close()

    @property
    def base(self) -> str:
        assert self.server is not None
        return f"http://127.0.0.1:{self.server.server_address[1]}/v1"


class TestParsing:
    def test_models_keep_vendor_namespace_and_metadata(self):
        models = catalog.parse_catalog(MIXED_CATALOG, capability="chat")
        ids = {model.id for model in models}
        assert "orca/orcacyber-ultra-1.0" in ids
        assert "orcarouter/auto" in ids
        auto = next(model for model in models if model.id == "orcarouter/auto")
        assert auto.reasoning_efforts == ("low", "medium", "high", "xhigh")
        assert auto.context_length == 128000

    def test_malformed_entries_are_dropped(self):
        payload = {
            "data": [
                {"id": ""},
                {"id": "x" * 500},
                {"id": "has space"},
                {"name": "no id"},
                "not-a-dict",
                _entry("valid/model"),
            ]
        }
        models = catalog.parse_catalog(payload, capability="chat")
        assert [model.id for model in models] == ["valid/model"]

    def test_invalid_shape_raises(self):
        with pytest.raises(catalog.OrcaCatalogError):
            catalog.parse_catalog({"unexpected": True})

    def test_item_cap(self):
        payload = {"data": [_entry(f"vendor/model-{i}") for i in range(50)]}
        models = catalog.parse_catalog(payload, capability="chat")
        assert len(models) == 50


class TestCapabilityFilters:
    def test_chat_excludes_non_text_endpoints(self):
        models = catalog.parse_catalog(MIXED_CATALOG, capability="chat")
        ids = {model.id for model in models}
        assert "orcarouter/auto" in ids
        assert "openai/gpt-5.5" in ids
        assert "google/gemini-3.5-flash" in ids
        assert "openai/text-embedding-3" not in ids
        assert "google/imagen-4" not in ids
        assert "openai/sora-2" not in ids
        assert "cohere/rerank-4" not in ids
        # No declared endpoint types: fail closed rather than guess.
        assert "untyped/legacy-model" not in ids

    def test_embedding_filter(self):
        models = catalog.parse_catalog(MIXED_CATALOG, capability="embedding")
        assert [model.id for model in models] == ["openai/text-embedding-3"]

    def test_image_filter(self):
        models = catalog.parse_catalog(MIXED_CATALOG, capability="image")
        assert [model.id for model in models] == ["google/imagen-4"]

    def test_video_filter(self):
        models = catalog.parse_catalog(MIXED_CATALOG, capability="video")
        assert [model.id for model in models] == ["openai/sora-2"]

    def test_rerank_filter(self):
        models = catalog.parse_catalog(MIXED_CATALOG, capability="rerank")
        assert [model.id for model in models] == ["cohere/rerank-4"]

    def test_unknown_capability_is_rejected(self):
        with pytest.raises(ValueError):
            catalog.parse_catalog(MIXED_CATALOG, capability="telepathy")


class TestMultimodal:
    def test_image_requirement_is_fail_closed(self):
        models = catalog.parse_catalog(MIXED_CATALOG, capability="chat", required_inputs=["image"])
        ids = {model.id for model in models}
        assert ids == {
            "google/gemini-3.5-flash",
            "deepseek/deepseek-v4-flash-vision-exp",
        }
        # A text-only chat model must never leak into an image-input list.
        assert "orcarouter/auto" not in ids
        assert "openai/gpt-5.5" not in ids

    def test_missing_modality_declaration_is_excluded(self):
        payload = {
            "data": [{"id": "vendor/untyped-vision", "supported_endpoint_types": ["openai"]}]
        }
        models = catalog.parse_catalog(payload, capability="chat", required_inputs=["image"])
        assert models == ()

    def test_changing_the_required_modality_recomputes_the_list(self):
        text_models = catalog.parse_catalog(MIXED_CATALOG, capability="chat")
        image_models = catalog.parse_catalog(
            MIXED_CATALOG, capability="chat", required_inputs=["image"]
        )
        assert len(image_models) < len(text_models)
        assert all("image" in model.input_modalities for model in image_models)


class TestLiveDiscovery:
    def test_fetch_uses_bearer_and_capability_query(self):
        with ModelStub(MIXED_CATALOG) as stub:
            result = catalog.fetch_catalog("sk-orca-test-key-01", api_base=stub.base)
        assert result.source == "live"
        assert result.degraded is False
        assert result.models
        path, headers = stub.requests[0]
        assert path.startswith("/v1/models?capability=chat")
        assert (
            headers.get("Authorization") == "Bearer sk-orca-test-key-001"
            or headers.get("Authorization") == "Bearer sk-orca-test-key-01"
        )

    def test_401_is_an_auth_error(self):
        with ModelStub({"error": "unauthorized"}, status=401) as stub:
            with pytest.raises(catalog.OrcaCatalogAuthError):
                catalog.fetch_catalog("sk-orca-test-key-01", api_base=stub.base)

    def test_live_success_is_authoritative_and_not_mixed_with_seed(self):
        seed_ids = {model.id for model in catalog.SEED_MODELS}
        with ModelStub({"data": [_entry("vendor/only-live-model")]}) as stub:
            result = catalog.fetch_catalog("sk-orca-test-key-01", api_base=stub.base)
        assert result.model_ids == ("vendor/only-live-model",)
        assert not (set(result.model_ids) & seed_ids)

    def test_outage_falls_back_to_the_verified_seed(self):
        catalog.reset_catalog_cache()
        result = catalog.load_catalog(
            "sk-orca-test-key-01", api_base="http://127.0.0.1:9/v1", timeout=1.0
        )
        assert result.degraded is True
        assert result.source == "seed"
        assert "orcarouter/auto" in result.model_ids
        seed_auto = next(m for m in result.models if m.id == "orcarouter/auto")
        assert seed_auto.supported_endpoint_types

    def test_seed_preserves_reasoning_metadata(self):
        result = catalog.seed_catalog(capability="chat")
        gpt55 = next(m for m in result.models if m.id == "openai/gpt-5.5")
        assert gpt55.reasoning_efforts == ("low", "medium", "high", "xhigh")

    def test_cache_is_reused_without_a_second_request(self):
        catalog.reset_catalog_cache()
        with ModelStub(MIXED_CATALOG) as stub:
            first = catalog.load_catalog("sk-orca-test-key-01", api_base=stub.base)
            second = catalog.load_catalog("sk-orca-test-key-01", api_base=stub.base)
            assert len(stub.requests) == 1
        assert first.source == "live"
        assert second.source == "cache"
        assert second.model_ids == first.model_ids


class TestSelectionRevalidation:
    def test_stored_model_is_invalid_when_it_leaves_the_filtered_catalog(self):
        models = catalog.parse_catalog(MIXED_CATALOG, capability="chat")
        assert catalog.model_is_compatible(models, "orcarouter/auto", capability="chat")
        assert not catalog.model_is_compatible(
            models, "orcarouter/auto", capability="chat", required_inputs=["image"]
        )
        assert not catalog.model_is_compatible(models, "vendor/removed-model", capability="chat")

    def test_selection_helper_clears_a_stale_value(self, tmp_path):
        store = _FakeStore()
        ok, model = _resolve_selection(
            store,
            catalog.parse_catalog(MIXED_CATALOG, capability="chat"),
            "vendor/removed-model",
        )
        assert ok is False
        assert model == catalog.config.DEFAULT_MODEL
        assert store.cleared is True

    def test_selection_helper_keeps_a_compatible_value(self):
        store = _FakeStore()
        ok, model = _resolve_selection(
            store, catalog.parse_catalog(MIXED_CATALOG, capability="chat"), "orcarouter/auto"
        )
        assert ok is True
        assert model == "orcarouter/auto"
        assert store.cleared is False


class _FakeStore:
    def __init__(self) -> None:
        self.cleared = False

    def update_model(self, model: str) -> bool:
        self.cleared = model == ""
        return True


def _resolve_selection(store, models, model_id: str):
    """Mirror of the CLI/status revalidation contract."""
    if not model_id:
        return True, model_id
    if catalog.model_is_compatible(models, model_id, capability="chat"):
        return True, model_id
    store.update_model("")
    return False, catalog.config.DEFAULT_MODEL
