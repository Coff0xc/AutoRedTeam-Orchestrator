"""Provider wiring tests for OrcaRouter Cyber Inference.

Covers the registry entry, relay routing (base URL + bearer), the shared
credential seam, terminal 401 handling that must not poison a newer
credential, and one opt-in live request through the provider code path.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from core.llm import provider as provider_module
from core.llm.orcarouter import PROVIDER_REGISTRATION, catalog, config
from core.llm.orcarouter.credentials import CredentialStore
from core.llm.provider import LLMProvider, reset_llm


class _AuthFailure(Exception):
    status_code = 401


@pytest.fixture()
def isolated(tmp_path, monkeypatch):
    """No environment key, no shared store; tests opt in explicitly."""
    monkeypatch.delenv("ORCAROUTER_API_KEY", raising=False)
    monkeypatch.delenv("AUTORT_LLM_API_KEY", raising=False)
    monkeypatch.delenv("AUTORT_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("AUTORT_LLM_MODEL", raising=False)
    monkeypatch.delenv("AUTORT_LLM_BASE_URL", raising=False)
    path = str(tmp_path / "orcarouter.json")
    monkeypatch.setenv("AUTORT_ORCA_CREDENTIALS", path)
    reset_llm()
    yield CredentialStore(path)
    reset_llm()


class TestRegistryEntry:
    def test_provider_tables_include_orcarouter(self):
        assert provider_module._DEFAULT_MODELS["orcarouter"] == "orcarouter/auto"
        assert provider_module._PROVIDER_KEY_ENV["orcarouter"] == "ORCAROUTER_API_KEY"
        assert provider_module._LITELLM_PREFIX["orcarouter"] == "openai/"

    def test_registration_is_named_and_cyber_scoped(self):
        assert PROVIDER_REGISTRATION["id"] == "orcarouter"
        assert PROVIDER_REGISTRATION["name"] == "OrcaRouter Cyber Inference"
        assert PROVIDER_REGISTRATION["base_url"] == "https://api.orcarouter.ai/v1"
        assert PROVIDER_REGISTRATION["auth_base_url"] == "https://www.orcarouter.ai"
        assert PROVIDER_REGISTRATION["auth_methods"] == ("api_key", "pkce")
        assert "orcacyber-ultra-1.0" in PROVIDER_REGISTRATION["recommended_cyber_models"]

    def test_config_schema_accepts_the_named_provider(self):
        from core.config.models import AIConfig, LLMConfig

        assert LLMConfig(provider="orcarouter").provider == "orcarouter"
        ai = AIConfig(provider="orcarouter", base_url="https://api.orcarouter.ai/v1")
        assert ai.base_url == "https://api.orcarouter.ai/v1"


class TestProviderRouting:
    def test_relay_base_url_and_model_are_used(self, isolated):
        isolated.save("sk-orca-test-key-00001", source="api_key")
        with patch("openai.OpenAI") as mock_client:
            instance = MagicMock()
            instance.chat.completions.create.return_value = MagicMock(
                choices=[MagicMock(message=MagicMock(content="ready"))]
            )
            mock_client.return_value = instance

            llm = LLMProvider(provider="orcarouter", model="orca/orcacyber-ultra-1.0")
            assert llm.available is True
            assert llm.base_url == "https://api.orcarouter.ai/v1"
            assert llm.complete("hi") == "ready"

        kwargs = mock_client.call_args.kwargs
        assert kwargs["base_url"] == "https://api.orcarouter.ai/v1"
        assert kwargs["api_key"] == "sk-orca-test-key-00001"
        create_kwargs = instance.chat.completions.create.call_args.kwargs
        assert create_kwargs["model"] == "orca/orcacyber-ultra-1.0"
        assert create_kwargs["messages"][-1] == {"role": "user", "content": "hi"}

    def test_environment_key_is_honoured(self, monkeypatch):
        monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-env-key-000001")
        monkeypatch.setenv("AUTORT_ORCA_CREDENTIALS", "/nonexistent/orcarouter.json")
        llm = LLMProvider(provider="orcarouter")
        assert llm.available is True
        assert llm.model == "orcarouter/auto"

    def test_missing_credential_is_unavailable_not_crashing(self, isolated):
        llm = LLMProvider(provider="orcarouter")
        assert llm.available is False
        assert llm.complete("hi") is None

    def test_other_providers_are_unchanged(self, isolated):
        llm = LLMProvider(provider="openai")
        assert llm.provider == "openai"
        assert llm.model == "gpt-4o-mini"
        assert llm.base_url == ""

    def test_pkce_and_api_key_share_the_same_downstream_path(self, isolated):
        """A stored PKCE key is consumed exactly like a pasted key."""
        pkce_credential = isolated.save(
            "sk-orca-pkce-key-000001", source="pkce", account_id="user-7"
        )
        llm = LLMProvider(provider="orcarouter")
        assert llm.credential is not None
        assert llm.credential.generation == pkce_credential.generation
        assert llm.api_key == "sk-orca-pkce-key-000001"

        isolated.save("sk-orca-pasted-key-001", source="api_key")
        pasted = LLMProvider(provider="orcarouter")
        assert pasted.credential is not None
        assert pasted.credential.source == "api_key"
        assert pasted.api_key == "sk-orca-pasted-key-001"

    def test_selected_model_is_restored(self, isolated):
        isolated.save("sk-orca-test-key-00001", source="pkce")
        isolated.update_model("orca/orcacyber-zero-1.5")
        llm = LLMProvider(provider="orcarouter")
        assert llm.model == "orca/orcacyber-zero-1.5"

    def test_catalog_uses_the_inference_origin(self, isolated, tmp_path):
        isolated.save("sk-orca-test-key-00001", source="api_key")
        llm = LLMProvider(provider="orcarouter")
        assert llm.base_url != config.auth_base_url()
        assert llm.base_url == config.api_base_url()


class TestTerminalAuthenticationFailure:
    def test_401_marks_only_the_rejected_generation(self, isolated):
        old = isolated.save("sk-orca-old-key-000001", source="pkce", account_id="u1")
        with patch("openai.OpenAI") as mock_client:
            instance = MagicMock()
            instance.chat.completions.create.side_effect = _AuthFailure("unauthorized")
            mock_client.return_value = instance
            llm = LLMProvider(provider="orcarouter")
            assert llm.credential is not None
            assert llm.credential.generation == old.generation
            # A newer login happens while the old request is still in flight.
            new = isolated.save("sk-orca-new-key-000002", source="pkce", account_id="u1")
            assert llm.complete("hi") is None

        current = isolated.current()
        assert current is not None
        assert current.generation == new.generation
        assert isolated.storable_status()["needs_reauth"] is False

    def test_401_on_the_current_generation_requires_reauth(self, isolated):
        isolated.save("sk-orca-current-key-001", source="pkce", account_id="u1")
        with patch("openai.OpenAI") as mock_client:
            instance = MagicMock()
            instance.chat.completions.create.side_effect = _AuthFailure("unauthorized")
            mock_client.return_value = instance
            llm = LLMProvider(provider="orcarouter")
            assert llm.complete("hi") is None

        assert isolated.storable_status()["needs_reauth"] is True
        assert isolated.current() is None
        assert LLMProvider(provider="orcarouter").available is False

    def test_non_401_errors_do_not_flag_the_credential(self, isolated):
        isolated.save("sk-orca-current-key-001", source="pkce", account_id="u1")

        class _ServerError(Exception):
            status_code = 500

        with patch("openai.OpenAI") as mock_client:
            instance = MagicMock()
            instance.chat.completions.create.side_effect = _ServerError("boom")
            mock_client.return_value = instance
            llm = LLMProvider(provider="orcarouter")
            assert llm.complete("hi") is None
        assert isolated.storable_status()["needs_reauth"] is False

    def test_error_text_is_redacted(self, isolated):
        isolated.save("sk-orca-secret-key-0001", source="api_key")

        class _LeakyError(Exception):
            status_code = 500

        with patch("openai.OpenAI") as mock_client:
            instance = MagicMock()
            instance.chat.completions.create.side_effect = _LeakyError(
                "bad request for sk-orca-secret-key-0001"
            )
            mock_client.return_value = instance
            llm = LLMProvider(provider="orcarouter")
            assert llm.complete("hi") is None
        assert llm.api_key not in llm._redact("bad request for sk-orca-secret-key-0001")
        assert (
            llm._redact("bad request for sk-orca-secret-key-0001") == "bad request for <redacted>"
        )


class TestMcpDecisionEngineWiring:
    def test_ai_decision_engine_uses_the_orcarouter_relay(self, isolated, monkeypatch):
        from core.ai_engine import AIDecisionEngine

        monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-env-key-000001")
        with patch("openai.OpenAI") as mock_client:
            engine = AIDecisionEngine({"provider": "orcarouter", "model": "orcarouter/auto"})
            client = engine._get_client()
        assert client is mock_client.return_value
        kwargs = mock_client.call_args.kwargs
        assert kwargs["base_url"] == "https://api.orcarouter.ai/v1"
        assert kwargs["api_key"] == "sk-orca-env-key-000001"

    def test_ai_decision_engine_falls_back_without_credential(self, isolated):
        from core.ai_engine import AIDecisionEngine

        engine = AIDecisionEngine({"provider": "orcarouter"})
        assert engine._get_client() == "local"

    def test_ai_decision_engine_does_not_use_vendor_base_for_other_providers(
        self, isolated, monkeypatch
    ):
        from core.ai_engine import AIDecisionEngine

        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        with patch("openai.OpenAI") as mock_client:
            engine = AIDecisionEngine({"provider": "openai"})
            engine._get_client()
        assert "base_url" not in mock_client.call_args.kwargs


class TestLiveProviderPath:
    """Opt-in live checks; skipped when no verification key is exported."""

    @pytest.mark.network
    def test_live_catalog_then_real_inference(self, monkeypatch):
        key = os.environ.get("ORCAROUTER_API_KEY")
        if not key:
            pytest.skip("ORCAROUTER_API_KEY is not set")
        monkeypatch.setenv("AUTORT_ORCA_CREDENTIALS", "/nonexistent/orcarouter.json")
        monkeypatch.delenv("AUTORT_LLM_MODEL", raising=False)

        result = catalog.fetch_catalog(key, capability="chat", timeout=30.0)
        assert result.models, "live catalog returned no chat models"
        assert all(
            set(model.supported_endpoint_types)
            & {"openai", "anthropic", "gemini", "openai-response"}
            for model in result.models
        )
        ids = set(result.model_ids)

        candidates = [
            "orca/orcacyber-ultra-1.0",
            "deepseek/deepseek-v4.1-flash",
            "orcarouter/auto",
        ]
        attempts = [model for model in candidates if model in ids] or [result.models[0].id]
        response = None
        used_model = ""
        for model in attempts:
            llm = LLMProvider(provider="orcarouter", model=model)
            assert llm.available is True
            assert llm.base_url == "https://api.orcarouter.ai/v1"
            response = llm.complete("Reply with the single word: ready", max_tokens=16)
            if response:
                used_model = model
                break
        assert response, f"no live completion succeeded through the provider ({attempts})"
        assert used_model in ids
