"""CLI surface tests for the OrcaRouter Cyber Inference provider.

The CLI is this project's user interface; these tests drive the real Typer
commands and a local model/authorization stub rather than calling helpers.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from cli.main import app
from core.llm.orcarouter import catalog
from tests.test_orcarouter_catalog import MIXED_CATALOG, ModelStub
from tests.test_orcarouter_pkce import AuthStub

runner = CliRunner()


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    monkeypatch.delenv("ORCAROUTER_API_KEY", raising=False)
    monkeypatch.delenv("AUTORT_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("AUTORT_LLM_MODEL", raising=False)
    monkeypatch.delenv("AUTORT_LLM_BASE_URL", raising=False)
    path = str(tmp_path / "orcarouter.json")
    monkeypatch.setenv("AUTORT_ORCA_CREDENTIALS", path)
    catalog.reset_catalog_cache()
    yield path
    catalog.reset_catalog_cache()


def _fake_reply(text: str = "ready") -> MagicMock:
    client = MagicMock()
    client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content=text))]
    )
    return client


class TestKeyCommands:
    def test_set_then_status_then_clear(self, cli_env):
        result = runner.invoke(app, ["llm", "key", "set", "--key", "sk-orca-cli-test-0001"])
        assert result.exit_code == 0, result.output
        assert "sk-orca-cli-test-0001" not in result.output

        status = runner.invoke(app, ["llm", "status"])
        assert status.exit_code == 0
        assert "OrcaRouter Cyber Inference" in status.output
        assert "sk-orca-cli-test-0001" not in status.output
        assert "source: api_key" in status.output

        cleared = runner.invoke(app, ["llm", "key", "clear"])
        assert cleared.exit_code == 0
        assert "removed" in cleared.output.lower()

    def test_malformed_key_is_refused(self, cli_env):
        result = runner.invoke(app, ["llm", "key", "set", "--key", "sk-openai-nope"])
        assert result.exit_code == 2
        assert "sk-orca" in result.output

    def test_status_without_credential_points_at_both_entries(self, cli_env):
        result = runner.invoke(app, ["llm", "status"])
        assert result.exit_code == 0
        assert "autort llm connect" in result.output
        assert "key set" in result.output


class TestConnectCommand:
    def test_oob_login_stores_the_key(self, cli_env, monkeypatch):
        with AuthStub() as stub:
            monkeypatch.setenv("ORCA_AUTH_BASE_URL", stub.base)
            result = runner.invoke(
                app,
                ["llm", "connect", "--flow", "oob", "--no-open"],
                input="code-from-consent\n",
            )
        assert result.exit_code == 0, result.output
        assert "is stored" in result.output
        assert "sk-orca-test-1234567890" not in result.output
        assert stub.requests[0][1]["code_challenge_method"] == "S256"

        status = runner.invoke(app, ["llm", "status"])
        assert "source: pkce" in status.output

    def test_second_connect_reuses_the_stored_key(self, cli_env, monkeypatch):
        with AuthStub() as stub:
            monkeypatch.setenv("ORCA_AUTH_BASE_URL", stub.base)
            runner.invoke(
                app,
                ["llm", "connect", "--flow", "oob", "--no-open"],
                input="code-from-consent\n",
            )
            second = runner.invoke(
                app,
                ["llm", "connect", "--flow", "oob", "--no-open"],
                input="",
            )
        assert second.exit_code == 0
        assert len(stub.requests) == 1


class TestModelsCommand:
    def test_live_catalog_is_listed(self, cli_env, monkeypatch):
        with ModelStub(MIXED_CATALOG) as stub:
            monkeypatch.setenv("ORCA_API_BASE_URL", stub.base)
            monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-cli-test-0001")
            result = runner.invoke(app, ["llm", "models"])
        assert result.exit_code == 0, result.output
        assert "orca/orcacyber-ultra-1.0" in result.output
        assert "openai/text-embedding-3" not in result.output
        assert "source: live" in result.output

    def test_image_filter_excludes_text_only_models(self, cli_env, monkeypatch):
        with ModelStub(MIXED_CATALOG) as stub:
            monkeypatch.setenv("ORCA_API_BASE_URL", stub.base)
            monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-cli-test-0001")
            result = runner.invoke(app, ["llm", "models", "--require-input", "image", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output[result.output.index("{") :])
        ids = [model["id"] for model in payload["models"]]
        assert "google/gemini-3.5-flash" in ids
        assert "orcarouter/auto" not in ids

    def test_degraded_catalog_is_labelled(self, cli_env, monkeypatch):
        monkeypatch.setenv("ORCA_API_BASE_URL", "http://127.0.0.1:9/v1")
        monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-cli-test-0001")
        result = runner.invoke(app, ["llm", "models"])
        assert result.exit_code == 0
        assert "degraded" in result.output.lower()
        assert "orcarouter/auto" in result.output

    def test_select_persists_a_compatible_model(self, cli_env, monkeypatch):
        from core.llm.orcarouter import CredentialStore

        CredentialStore(cli_env).save("sk-orca-cli-test-0001", source="api_key")
        with ModelStub(MIXED_CATALOG) as stub:
            monkeypatch.setenv("ORCA_API_BASE_URL", stub.base)
            result = runner.invoke(app, ["llm", "models", "--select"], input="1\n")
        assert result.exit_code == 0, result.output
        assert CredentialStore(cli_env).current().model == "orcarouter/auto"

    def test_use_rejects_an_incompatible_model(self, cli_env, monkeypatch):
        with ModelStub(MIXED_CATALOG) as stub:
            monkeypatch.setenv("ORCA_API_BASE_URL", stub.base)
            monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-cli-test-0001")
            result = runner.invoke(app, ["llm", "use", "openai/text-embedding-3"])
        assert result.exit_code == 2
        assert "not a chat-compatible model" in result.output


class TestPingCommand:
    def test_ping_goes_through_the_provider(self, cli_env, monkeypatch):
        monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-cli-test-0001")
        with patch("openai.OpenAI", return_value=_fake_reply("ready")) as mock_client:
            result = runner.invoke(app, ["llm", "ping"])
        assert result.exit_code == 0, result.output
        assert "ready" in result.output
        assert mock_client.call_args.kwargs["base_url"] == "https://api.orcarouter.ai/v1"
        assert "sk-orca-cli-test-0001" not in result.output

    def test_ping_without_credential_exits_two(self, cli_env):
        result = runner.invoke(app, ["llm", "ping"])
        assert result.exit_code == 2
        assert "not ready" in result.output
