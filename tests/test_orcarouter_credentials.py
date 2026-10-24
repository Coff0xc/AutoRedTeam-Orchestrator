"""Credential seam tests: API-key adapter and PKCE adapter share one result.

Both adapters must yield the same credential shape, downstream code must not
care which one ran, and no secret may reach logs or error text.
"""

from __future__ import annotations

import json
import logging
import os
import stat

import pytest

from core.llm.orcarouter import pkce
from core.llm.orcarouter.credentials import (
    ApiKeyCredentialSource,
    CredentialStore,
    OrcaCredential,
    OrcaCredentialError,
    PkceCredentialSource,
    mask_key,
    resolve_credential,
)
from tests.test_orcarouter_pkce import AuthStub, browser_redirect


@pytest.fixture()
def store(tmp_path) -> CredentialStore:
    return CredentialStore(str(tmp_path / "orcarouter.json"))


@pytest.fixture()
def clean_env(monkeypatch, store):
    monkeypatch.delenv("ORCAROUTER_API_KEY", raising=False)
    monkeypatch.delenv("AUTORT_LLM_API_KEY", raising=False)
    monkeypatch.setenv("AUTORT_ORCA_CREDENTIALS", store.path)
    return store


class TestStore:
    def test_save_is_private_and_round_trips(self, store):
        credential = store.save("sk-orca-abcdef123456", source="pkce", account_id="user-7")
        assert credential.api_key == "sk-orca-abcdef123456"
        assert credential.generation
        mode = stat.S_IMODE(os.stat(store.path).st_mode)
        assert mode == 0o600
        loaded = store.current()
        assert loaded is not None
        assert loaded.account_id == "user-7"

    def test_clear(self, store):
        store.save("sk-orca-abcdef123456", source="api_key")
        assert store.clear() is True
        assert store.clear() is False
        assert store.current() is None

    def test_corrupt_file_is_ignored(self, tmp_path):
        path = tmp_path / "broken.json"
        path.write_text("{not json", encoding="utf-8")
        store = CredentialStore(str(path))
        assert store.current() is None
        assert store.storable_status() == {"stored": False}

    def test_status_is_masked(self, store):
        store.save("sk-orca-abcdef123456", source="pkce", account_id="user-7")
        status = store.storable_status()
        assert status["stored"] is True
        assert "sk-orca-abcdef123456" not in json.dumps(status)
        assert status["key"].startswith("sk-orca-")

    def test_empty_key_is_refused(self, store):
        with pytest.raises(OrcaCredentialError):
            store.save("", source="api_key")

    def test_mask_key_never_returns_the_full_secret(self):
        assert mask_key("sk-orca-abcdef123456") != "sk-orca-abcdef123456"
        assert "…" in mask_key("sk-orca-abcdef123456")
        assert mask_key("") == "<unset>"


class TestApiKeyAdapter:
    def test_environment_key_wins(self, clean_env, monkeypatch):
        monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-env-key-000001")
        credential = ApiKeyCredentialSource().acquire()
        assert credential is not None
        assert credential.api_key == "sk-orca-env-key-000001"
        assert credential.source == "api_key"
        assert credential.generation == "env"

    def test_stored_key_is_used_without_environment(self, clean_env):
        stored = clean_env.save("sk-orca-stored-key-0001", source="api_key")
        credential = ApiKeyCredentialSource().acquire()
        assert credential is not None
        assert credential.api_key == stored.api_key
        assert credential.generation == stored.generation

    def test_no_credential_returns_none(self, clean_env):
        assert ApiKeyCredentialSource().acquire() is None

    def test_save_rejects_malformed_key(self, clean_env):
        with pytest.raises(OrcaCredentialError):
            ApiKeyCredentialSource().save("sk-openai-not-orca")

    def test_save_refuses_to_shadow_environment_key(self, clean_env, monkeypatch):
        monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-env-key-000001")
        with pytest.raises(OrcaCredentialError):
            ApiKeyCredentialSource().save("sk-orca-other-key-00002")

    def test_clear_removes_file(self, clean_env):
        clean_env.save("sk-orca-stored-key-0001", source="api_key")
        assert ApiKeyCredentialSource().clear() is True
        assert clean_env.current() is None


class TestPkceAdapter:
    def test_reuses_stored_key_instead_of_authorizing_again(self, clean_env):
        stored = clean_env.save("sk-orca-stored-key-0001", source="pkce", account_id="u1")
        source = PkceCredentialSource(store=clean_env)
        credential = source.acquire(flow="loopback")
        assert credential.generation == stored.generation

    def test_loopback_login_persists_the_key(self, clean_env):
        with AuthStub() as stub:
            source = PkceCredentialSource(store=clean_env, auth_base=stub.base)
            credential = source.acquire(
                flow="loopback",
                open_browser=browser_redirect(),
                timeout=10,
                reuse_stored=True,
            )
        assert credential.api_key.startswith("sk-orca-")
        assert credential.source == "pkce"
        assert credential.account_id == "user-42"
        persisted = clean_env.current()
        assert persisted is not None
        assert persisted.api_key == credential.api_key
        assert persisted.generation == credential.generation

    def test_out_of_band_login_persists_the_key(self, clean_env):
        with AuthStub() as stub:
            source = PkceCredentialSource(store=clean_env, auth_base=stub.base)
            credential = source.acquire(
                flow="oob",
                code_prompt=lambda url: "code-from-screen",
                open_browser=lambda url: True,
                reuse_stored=True,
            )
        assert credential.source == "pkce"
        assert stub.requests[0][1]["code"] == "code-from-screen"

    def test_out_of_band_requires_a_code_reader(self, clean_env):
        source = PkceCredentialSource(store=clean_env, auth_base="http://127.0.0.1:9")
        with pytest.raises(OrcaCredentialError):
            source.acquire(flow="oob", reuse_stored=True)

    def test_needs_reauth_forces_a_new_login(self, clean_env):
        stored = clean_env.save("sk-orca-stored-key-0001", source="pkce", account_id="u1")
        clean_env.mark_needs_reauth("u1", stored.generation)
        assert clean_env.current() is None
        with AuthStub() as stub:
            source = PkceCredentialSource(store=clean_env, auth_base=stub.base)
            credential = source.acquire(
                flow="loopback", open_browser=browser_redirect(), timeout=10
            )
        assert credential.generation != stored.generation
        assert clean_env.current() is not None

    def test_unknown_flow_is_rejected(self, clean_env):
        source = PkceCredentialSource(store=clean_env)
        with pytest.raises(OrcaCredentialError):
            source.acquire(flow="device", reuse_stored=False)


class TestDualSourceEquivalence:
    def test_both_adapters_produce_the_same_credential_type(self, clean_env, monkeypatch):
        monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-env-key-000001")
        api_key_credential = ApiKeyCredentialSource().acquire()

        with AuthStub() as stub:
            pkce_credential = PkceCredentialSource(
                store=CredentialStore(str(clean_env.path + ".pkce")), auth_base=stub.base
            ).acquire(flow="loopback", open_browser=browser_redirect(), timeout=10)

        assert isinstance(api_key_credential, OrcaCredential)
        assert isinstance(pkce_credential, OrcaCredential)
        assert api_key_credential.source == "api_key"
        assert pkce_credential.source == "pkce"
        # Downstream consumers use only these two fields.
        assert api_key_credential.api_key.startswith("sk-orca-")
        assert pkce_credential.api_key.startswith("sk-orca-")

    def test_resolve_credential_is_source_agnostic(self, clean_env, monkeypatch):
        monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-env-key-000001")
        credential = resolve_credential(store=clean_env)
        assert credential is not None
        assert credential.api_key == "sk-orca-env-key-000001"


class TestReauthGenerationSafety:
    def test_generation_mismatch_does_not_flag_the_new_credential(self, store):
        old = store.save("sk-orca-old-key-0000001", source="pkce", account_id="u1")
        new = store.save("sk-orca-new-key-0000002", source="pkce", account_id="u1")
        assert store.mark_needs_reauth("u1", old.generation) is False
        current = store.current()
        assert current is not None
        assert current.generation == new.generation

    def test_matching_generation_is_flagged(self, store):
        credential = store.save("sk-orca-key-000000001", source="pkce", account_id="u1")
        assert store.mark_needs_reauth("u1", credential.generation) is True
        assert store.current() is None

    def test_environment_credentials_are_not_written_to_the_store(self, clean_env, monkeypatch):
        monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-env-key-000001")
        credential = ApiKeyCredentialSource().acquire()
        assert credential is not None
        source = PkceCredentialSource(store=clean_env)
        assert source.mark_needs_reauth(credential) is False

    def test_no_refresh_helper_exists(self):
        """A durable key has no refresh grant; nothing here should offer one."""
        paused = [name for name in dir(pkce) if "refresh" in name.lower()]
        assert paused == []
        assert not hasattr(PkceCredentialSource, "refresh")


class TestSecretsStayOutOfLogs:
    def test_exchange_errors_do_not_contain_the_verifier(self, caplog):
        with AuthStub(status=403, payload={"error": "invalid_grant"}) as stub:
            with caplog.at_level(logging.DEBUG):
                with pytest.raises(pkce.OrcaAuthError) as excinfo:
                    pkce.exchange_code(stub.base, "one-time-code", "super-secret-verifier")
        assert "super-secret-verifier" not in str(excinfo.value)
        assert "one-time-code" not in str(excinfo.value)
        assert "super-secret-verifier" not in caplog.text
        assert "one-time-code" not in caplog.text

    def test_successful_flow_does_not_log_the_key(self, caplog):
        with AuthStub() as stub:
            with caplog.at_level(logging.DEBUG):
                pkce.run_loopback_flow(
                    auth_base=stub.base, open_browser=browser_redirect(), timeout=10
                )
        assert "sk-orca-test-1234567890" not in caplog.text
