"""Model discovery and capability filtering for OrcaRouter Cyber Inference.

The authoritative catalog is ``GET {api_base}/models`` on the configured
inference origin.  The bundled seed exists only for a cold start or an outage
and is always labelled as such; it is never mixed into a successful live
result.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from . import config

logger = logging.getLogger(__name__)

_MAX_MODELS = 2000
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_ID_LENGTH = 200
_DEFAULT_TIMEOUT = 8.0
_CACHE_TTL_SECONDS = 300.0

# Endpoint types this client can actually speak for text chat.
CHAT_ENDPOINT_TYPES = frozenset({"openai", "anthropic", "gemini", "openai-response"})
NON_TEXT_ENDPOINT_TYPES = frozenset(
    {"image-generation", "openai-video", "jina-rerank", "embeddings"}
)
CAPABILITY_ENDPOINT_TYPE = {
    "chat": CHAT_ENDPOINT_TYPES,
    "embedding": frozenset({"embeddings"}),
    "image": frozenset({"image-generation"}),
    "video": frozenset({"openai-video"}),
    "rerank": frozenset({"jina-rerank"}),
}
SUPPORTED_CAPABILITIES = tuple(CAPABILITY_ENDPOINT_TYPE)

_cache: Dict[str, Tuple[float, "CatalogResult"]] = {}


class OrcaCatalogError(RuntimeError):
    """Catalog fetch failed (network, HTTP or parse)."""

    def __init__(self, message: str, *, status: Optional[int] = None, reason: str = ""):
        super().__init__(message)
        self.status = status
        self.reason = reason


class OrcaCatalogAuthError(OrcaCatalogError):
    """The catalog request was rejected (401/403)."""


@dataclass(frozen=True)
class ModelInfo:
    """One catalog entry, reduced to the metadata this client relies on."""

    id: str
    name: str = ""
    context_length: Optional[int] = None
    input_modalities: Tuple[str, ...] = ("text",)
    output_modalities: Tuple[str, ...] = ("text",)
    supported_endpoint_types: Tuple[str, ...] = ("openai",)
    reasoning_efforts: Tuple[str, ...] = ()
    supported_parameters: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name or self.id,
            "context_length": self.context_length,
            "input_modalities": list(self.input_modalities),
            "output_modalities": list(self.output_modalities),
            "supported_endpoint_types": list(self.supported_endpoint_types),
            "reasoning_efforts": list(self.reasoning_efforts),
            "supported_parameters": list(self.supported_parameters),
        }


@dataclass(frozen=True)
class CatalogResult:
    """A catalog snapshot plus how trustworthy it is."""

    models: Tuple[ModelInfo, ...] = field(default_factory=tuple)
    source: str = "seed"  # "live" | "seed" | "cache"
    degraded: bool = False
    error: str = ""
    fetched_at: float = 0.0

    @property
    def model_ids(self) -> Tuple[str, ...]:
        return tuple(model.id for model in self.models)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "degraded": self.degraded,
            "error": self.error,
            "count": len(self.models),
            "models": [model.to_dict() for model in self.models],
        }


# Verified cold-start seed.  It is deliberately small: these entries are the
# documented OrcaRouter models, and only metadata we can stand behind is kept.
# ``openai/gpt-5.5`` carries its verified reasoning ladder so a catalog outage
# does not erase reasoning support.
SEED_MODELS: Tuple[ModelInfo, ...] = (
    ModelInfo(
        id="openai/gpt-5.5",
        name="GPT-5.5",
        context_length=None,
        input_modalities=("text",),
        output_modalities=("text",),
        supported_endpoint_types=("openai", "openai-response"),
        reasoning_efforts=("low", "medium", "high", "xhigh"),
    ),
    ModelInfo(
        id="anthropic/claude-opus-4.8",
        name="Claude Opus 4.8",
        supported_endpoint_types=("anthropic",),
    ),
    ModelInfo(
        id="google/gemini-3.5-flash",
        name="Gemini 3.5 Flash",
        supported_endpoint_types=("gemini", "openai"),
    ),
    ModelInfo(
        id="deepseek/deepseek-v4-pro",
        name="DeepSeek V4 Pro",
        supported_endpoint_types=("openai",),
    ),
    ModelInfo(
        id=config.DEFAULT_MODEL,
        name="OrcaRouter Auto",
        supported_endpoint_types=("openai",),
    ),
)


def reset_catalog_cache() -> None:
    """Drop the in-process catalog cache (tests and post-login refresh)."""
    _cache.clear()


def seed_catalog(capability: str = "chat", inputs: Iterable[str] = ()) -> CatalogResult:
    """The verified fallback catalog, filtered like a live one would be."""
    models = filter_models(SEED_MODELS, capability=capability, required_inputs=inputs)
    return CatalogResult(models=models, source="seed", degraded=True, error="offline_seed")


def _parse_modalities(source: Mapping[str, Any], key: str) -> Tuple[str, ...]:
    raw = source.get(key)
    if not isinstance(raw, list):
        return ()
    out = []
    for item in raw[:_MAX_MODELS]:
        if isinstance(item, str) and item.strip():
            out.append(item.strip().lower())
    return tuple(out)


def _parse_model(entry: Mapping[str, Any]) -> Optional[ModelInfo]:
    model_id = entry.get("id")
    if not isinstance(model_id, str):
        return None
    model_id = model_id.strip()
    if not model_id or len(model_id) > _MAX_ID_LENGTH:
        return None
    if any(ch.isspace() for ch in model_id):
        return None

    architecture = entry.get("architecture")
    if not isinstance(architecture, dict):
        architecture = {}

    endpoints_raw = entry.get("supported_endpoint_types")
    endpoints: Tuple[str, ...] = ()
    if isinstance(endpoints_raw, list):
        endpoints = tuple(
            item.strip() for item in endpoints_raw[:32] if isinstance(item, str) and item.strip()
        )

    inputs = _parse_modalities(architecture, "input_modalities")
    outputs = _parse_modalities(architecture, "output_modalities")

    context_length = entry.get("context_length")
    if not isinstance(context_length, int) or context_length <= 0:
        context_length = None

    reasoning_efforts: Tuple[str, ...] = ()
    reasoning = entry.get("reasoning")
    if isinstance(reasoning, dict):
        efforts = reasoning.get("efforts") or reasoning.get("supported_efforts")
        if isinstance(efforts, list):
            reasoning_efforts = tuple(
                item.strip() for item in efforts[:16] if isinstance(item, str) and item.strip()
            )

    parameters_raw = entry.get("supported_parameters")
    parameters: Tuple[str, ...] = ()
    if isinstance(parameters_raw, list):
        parameters = tuple(
            item.strip() for item in parameters_raw[:64] if isinstance(item, str) and item.strip()
        )

    name = entry.get("name")
    return ModelInfo(
        id=model_id,
        name=name.strip()[:200] if isinstance(name, str) else model_id,
        context_length=context_length,
        input_modalities=inputs or ("text",),
        output_modalities=outputs or ("text",),
        supported_endpoint_types=endpoints,
        reasoning_efforts=reasoning_efforts,
        supported_parameters=parameters,
    )


def parse_catalog(
    payload: Any, *, capability: str = "chat", required_inputs: Iterable[str] = ()
) -> Tuple[ModelInfo, ...]:
    """Parse an OpenAI-compatible ``/models`` payload and filter it."""
    if isinstance(payload, dict):
        entries = payload.get("data")
        if entries is None:
            entries = payload.get("models")
    else:
        entries = payload
    if not isinstance(entries, list):
        raise OrcaCatalogError("Model catalog response was not a list.", reason="invalid_shape")

    models: List[ModelInfo] = []
    seen = set()
    for entry in entries[:_MAX_MODELS]:
        if not isinstance(entry, dict):
            continue
        model = _parse_model(entry)
        if model is None or model.id in seen:
            continue
        seen.add(model.id)
        models.append(model)
    return filter_models(models, capability=capability, required_inputs=required_inputs)


def filter_models(
    models: Iterable[ModelInfo],
    *,
    capability: str = "chat",
    required_inputs: Iterable[str] = (),
) -> Tuple[ModelInfo, ...]:
    """Apply one capability filter. Unknown metadata fails closed."""
    if capability not in CAPABILITY_ENDPOINT_TYPE:
        raise ValueError(f"Unsupported capability: {capability}")
    accepted_types = CAPABILITY_ENDPOINT_TYPE[capability]
    required = tuple(item.lower() for item in required_inputs if item)
    result: List[ModelInfo] = []
    for model in models:
        endpoints = set(model.supported_endpoint_types)
        if not endpoints.intersection(accepted_types):
            continue
        if capability == "chat" and endpoints and endpoints.issubset(NON_TEXT_ENDPOINT_TYPES):
            continue
        if required and not set(required).issubset(set(model.input_modalities)):
            continue
        result.append(model)
    return tuple(result)


def _catalog_url(api_base: str, capability: str) -> str:
    query = urllib.parse.urlencode({"capability": capability})
    return f"{api_base}{config.MODELS_PATH}?{query}"


def fetch_catalog(
    api_key: str,
    *,
    capability: str = "chat",
    api_base: Optional[str] = None,
    timeout: float = _DEFAULT_TIMEOUT,
    required_inputs: Iterable[str] = (),
    opener: Optional[Callable[..., object]] = None,
) -> CatalogResult:
    """Fetch and parse the live catalog. Raises :class:`OrcaCatalogError`."""
    if not api_key:
        raise OrcaCatalogAuthError(
            "A model catalog needs an OrcaRouter credential.", status=401, reason="no_credential"
        )
    base = api_base or config.api_base_url()
    request = urllib.request.Request(
        _catalog_url(base, capability),
        method="GET",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        },
    )
    open_url = opener or urllib.request.urlopen
    try:
        with open_url(request, timeout=timeout) as response:  # type: ignore[union-attr]
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise OrcaCatalogAuthError(
                "OrcaRouter rejected the credential while listing models.",
                status=exc.code,
                reason="unauthorized",
            ) from None
        raise OrcaCatalogError(
            f"OrcaRouter model catalog returned HTTP {exc.code}.",
            status=exc.code,
            reason="http_error",
        ) from None
    except (urllib.error.URLError, OSError) as exc:
        raise OrcaCatalogError(
            "Could not reach the OrcaRouter model catalog.",
            reason="network_error",
        ) from exc

    if len(raw) > _MAX_RESPONSE_BYTES:
        raise OrcaCatalogError("Model catalog response was too large.", reason="oversized")

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise OrcaCatalogError(
            "Model catalog response was not valid JSON.", reason="invalid_json"
        ) from None

    models = parse_catalog(payload, capability=capability, required_inputs=required_inputs)
    return CatalogResult(models=models, source="live", degraded=False, fetched_at=time.time())


def load_catalog(
    api_key: str,
    *,
    capability: str = "chat",
    api_base: Optional[str] = None,
    timeout: float = _DEFAULT_TIMEOUT,
    required_inputs: Iterable[str] = (),
    use_cache: bool = True,
    opener: Optional[Callable[..., object]] = None,
) -> CatalogResult:
    """Live catalog with a short in-process cache and seed fallback.

    A failed discovery never falls back to free-text model entry; it returns
    the verified seed marked ``degraded`` so callers can show a refresh hint.
    """
    base = api_base or config.api_base_url()
    cache_key = f"{base}|{capability}|{','.join(sorted(required_inputs))}"
    now = time.monotonic()
    if use_cache:
        cached = _cache.get(cache_key)
        if cached and now - cached[0] < _CACHE_TTL_SECONDS:
            return replace(cached[1], source="cache")

    try:
        result = fetch_catalog(
            api_key,
            capability=capability,
            api_base=base,
            timeout=timeout,
            required_inputs=required_inputs,
            opener=opener,
        )
    except OrcaCatalogError as exc:
        fallback = seed_catalog(capability=capability, inputs=required_inputs)
        fallback = replace(fallback, error=exc.reason or "catalog_error")
        return fallback

    if use_cache:
        _cache[cache_key] = (now, result)
    return result


def find_model(models: Iterable[ModelInfo], model_id: str) -> Optional[ModelInfo]:
    for model in models:
        if model.id == model_id:
            return model
    return None


def model_is_compatible(
    models: Iterable[ModelInfo],
    model_id: str,
    *,
    capability: str = "chat",
    required_inputs: Iterable[str] = (),
) -> bool:
    """Revalidate a stored selection against the current filtered catalog."""
    filtered = filter_models(models, capability=capability, required_inputs=required_inputs)
    return find_model(filtered, model_id) is not None


def catalog_models_for_ui(result: CatalogResult) -> List[Dict[str, Any]]:
    """Minimal, key-free metadata for a selector or CLI listing."""
    return [model.to_dict() for model in result.models]


__all__ = [
    "CAPABILITY_ENDPOINT_TYPE",
    "CatalogResult",
    "ModelInfo",
    "OrcaCatalogAuthError",
    "OrcaCatalogError",
    "SEED_MODELS",
    "SUPPORTED_CAPABILITIES",
    "catalog_models_for_ui",
    "fetch_catalog",
    "filter_models",
    "find_model",
    "load_catalog",
    "model_is_compatible",
    "parse_catalog",
    "reset_catalog_cache",
    "seed_catalog",
]
