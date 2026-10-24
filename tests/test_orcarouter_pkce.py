"""PKCE protocol tests for the OrcaRouter Cyber Inference provider.

These tests use a local fake authorization server. No real consent is
simulated: the stub only stands in for the exchange endpoint and for the
browser redirect so the flow can be exercised end to end offline.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core.llm.orcarouter import config, pkce


class AuthStub:
    """Local stand-in for the OrcaRouter authorization exchange endpoint."""

    def __init__(self, status: int = 200, payload: dict | None = None) -> None:
        self.status = status
        self.payload = payload or {
            "key": "sk-orca-test-1234567890",
            "user_id": "user-42",
            "scope": "api",
        }
        self.requests: list[tuple[str, dict]] = []
        self.server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "AuthStub":
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:  # noqa: A003
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode("utf-8") if length else ""
                try:
                    body = json.loads(raw) if raw else {}
                except ValueError:
                    body = {"__raw__": raw}
                stub.requests.append((self.path, body))
                encoded = json.dumps(stub.payload).encode("utf-8")
                self.send_response(stub.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        assert self.server is not None
        self.server.shutdown()
        self.server.server_close()

    @property
    def base(self) -> str:
        assert self.server is not None
        return f"http://127.0.0.1:{self.server.server_address[1]}"


def browser_redirect(*, code: str = "code-abc", error: str | None = None, state: str | None = None):
    """Return an 'open browser' callback that performs the consent redirect."""

    def _open(url: str) -> bool:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        callback_url = query["callback_url"][0]
        params = {"state": state if state is not None else query["state"][0]}
        if error:
            params["error"] = error
        else:
            params["code"] = code
        target = f"{callback_url}?{urllib.parse.urlencode(params)}"
        urllib.request.urlopen(target, timeout=5).read()
        return True

    return _open


class TestPkcePrimitives:
    def test_challenge_is_s256_without_padding(self):
        attempt = pkce.new_attempt()
        digest = hashlib.sha256(attempt.verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        assert attempt.challenge == expected
        assert "=" not in attempt.challenge
        assert "=" not in attempt.verifier

    def test_attempt_is_fresh_every_time(self):
        first = pkce.new_attempt()
        second = pkce.new_attempt()
        assert first.verifier != second.verifier
        assert first.state != second.state
        assert first.challenge != second.challenge

    def test_authorize_url_contains_only_the_challenge(self):
        attempt = pkce.new_attempt()
        url = pkce.build_authorize_url(
            "https://www.orcarouter.ai",
            attempt,
            callback_url="http://127.0.0.1:51234/cb",
        )
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        assert urllib.parse.urlsplit(url).path == "/auth"
        assert query["code_challenge_method"] == ["S256"]
        assert query["code_challenge"] == [attempt.challenge]
        assert query["state"] == [attempt.state]
        assert query["callback_url"] == ["http://127.0.0.1:51234/cb"]
        assert query["scope"] == ["api"]
        assert attempt.verifier not in url

    def test_oob_flow_uses_literal_callback(self):
        attempt = pkce.new_attempt()
        url = pkce.build_oob_url("https://www.orcarouter.ai", attempt)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        assert query["callback_url"] == ["oob"]
        assert query["code_challenge_method"] == ["S256"]

    def test_state_comparison(self):
        assert pkce.state_matches("abc", "abc") is True
        assert pkce.state_matches("abc", "abd") is False
        assert pkce.state_matches("abc", None) is False
        assert pkce.state_matches("", "") is False


class TestOrigins:
    def test_public_origins_are_distinct(self, monkeypatch):
        for name in ("ORCA_BASE_URL", "ORCA_AUTH_BASE_URL", "ORCA_API_BASE_URL"):
            monkeypatch.delenv(name, raising=False)
        assert config.auth_base_url() == "https://www.orcarouter.ai"
        assert config.api_base_url() == "https://api.orcarouter.ai/v1"
        assert config.EXCHANGE_PATH == "/api/v1/auth/keys"
        assert not config.EXCHANGE_PATH.startswith("/v1/auth")

    def test_explicit_overrides_win(self, monkeypatch):
        monkeypatch.setenv("ORCA_BASE_URL", "https://shared.example.com")
        monkeypatch.setenv("ORCA_AUTH_BASE_URL", "https://auth.example.com")
        monkeypatch.setenv("ORCA_API_BASE_URL", "https://relay.example.com/v1")
        assert config.auth_base_url() == "https://auth.example.com"
        assert config.api_base_url() == "https://relay.example.com/v1"

    def test_shared_self_hosted_base(self, monkeypatch):
        monkeypatch.setenv("ORCA_BASE_URL", "https://shared.example.com")
        monkeypatch.delenv("ORCA_AUTH_BASE_URL", raising=False)
        monkeypatch.delenv("ORCA_API_BASE_URL", raising=False)
        assert config.auth_base_url() == "https://shared.example.com"
        assert config.api_base_url() == "https://shared.example.com/v1"

    def test_plain_http_only_for_loopback(self, monkeypatch):
        monkeypatch.setenv("ORCA_AUTH_BASE_URL", "http://example.com")
        with pytest.raises(config.OrcaConfigError):
            config.auth_base_url()
        monkeypatch.setenv("ORCA_AUTH_BASE_URL", "http://127.0.0.1:9000")
        assert config.auth_base_url() == "http://127.0.0.1:9000"

    def test_userinfo_rejected(self):
        with pytest.raises(config.OrcaConfigError):
            config.validate_origin("https://user:pass@example.com", setting="ORCA_AUTH_BASE_URL")


class TestLoopbackFlow:
    def test_successful_flow_posts_code_and_verifier_to_auth_origin(self):
        with AuthStub() as stub:
            payload = pkce.run_loopback_flow(
                auth_base=stub.base,
                open_browser=browser_redirect(),
                timeout=10,
            )
        assert payload["key"].startswith("sk-orca-")
        assert payload["scope"] == "api"
        assert len(stub.requests) == 1
        path, body = stub.requests[0]
        assert path == "/api/v1/auth/keys"
        assert body["code"] == "code-abc"
        assert body["code_challenge_method"] == "S256"
        assert body["code_verifier"]

    def test_each_attempt_uses_a_new_verifier(self):
        verifiers = []
        for _ in range(2):
            with AuthStub() as stub:
                pkce.run_loopback_flow(
                    auth_base=stub.base,
                    open_browser=browser_redirect(),
                    timeout=10,
                )
            verifiers.append(stub.requests[0][1]["code_verifier"])
        assert verifiers[0] != verifiers[1]

    def test_state_mismatch_is_rejected(self):
        with AuthStub() as stub:
            with pytest.raises(pkce.OrcaAuthError) as excinfo:
                pkce.run_loopback_flow(
                    auth_base=stub.base,
                    open_browser=browser_redirect(state="wrong-state"),
                    timeout=10,
                )
        assert excinfo.value.reason == "state_mismatch"
        assert stub.requests == []

    def test_denied_authorization(self):
        with AuthStub() as stub:
            with pytest.raises(pkce.OrcaAuthError) as excinfo:
                pkce.run_loopback_flow(
                    auth_base=stub.base,
                    open_browser=browser_redirect(error="access_denied"),
                    timeout=10,
                )
        assert excinfo.value.reason == "access_denied"
        assert stub.requests == []

    def test_timeout_closes_the_listener(self):
        with AuthStub() as stub:
            with pytest.raises(pkce.OrcaAuthError) as excinfo:
                pkce.run_loopback_flow(auth_base=stub.base, timeout=0.4)
        assert excinfo.value.reason == "timeout"

    def test_exchange_403_is_actionable_and_secret_free(self):
        payload = {"error": "invalid_grant", "error_description": "invalid code"}
        with AuthStub(status=403, payload=payload) as stub:
            with pytest.raises(pkce.OrcaAuthError) as excinfo:
                pkce.run_loopback_flow(
                    auth_base=stub.base,
                    open_browser=browser_redirect(code="single-use-code"),
                    timeout=10,
                )
        message = str(excinfo.value)
        assert excinfo.value.status == 403
        assert "expired" in message or "already been used" in message
        assert "single-use-code" not in message
        assert stub.requests[0][1]["code_verifier"] not in message

    def test_exchange_429_explains_the_key_cap(self):
        with AuthStub(status=429, payload={"error": "rate_limited"}) as stub:
            with pytest.raises(pkce.OrcaAuthError) as excinfo:
                pkce.run_loopback_flow(
                    auth_base=stub.base, open_browser=browser_redirect(), timeout=10
                )
        assert excinfo.value.status == 429
        assert "10 PKCE keys" in str(excinfo.value)

    def test_exchange_400_mentions_the_challenge_method(self):
        with AuthStub(status=400, payload={"error": "invalid_request"}) as stub:
            with pytest.raises(pkce.OrcaAuthError) as excinfo:
                pkce.run_loopback_flow(
                    auth_base=stub.base, open_browser=browser_redirect(), timeout=10
                )
        assert excinfo.value.status == 400
        assert "S256" in str(excinfo.value)

    def test_network_failure_is_reported_without_credentials(self):
        with pytest.raises(pkce.OrcaAuthError) as excinfo:
            pkce.exchange_code("http://127.0.0.1:9", "code-x", "verifier-y", timeout=2)
        assert excinfo.value.reason == "network_error"
        assert "code-x" not in str(excinfo.value)
        assert "verifier-y" not in str(excinfo.value)


class TestExchangeValidation:
    def test_scope_downgrade_is_refused(self):
        payload = {"key": "sk-orca-test-1234567890", "user_id": "1", "scope": "connector"}
        with AuthStub(payload=payload) as stub:
            with pytest.raises(pkce.OrcaAuthError) as excinfo:
                pkce.exchange_code(stub.base, "code", "verifier")
        assert excinfo.value.reason == "scope_downgrade"
        assert "connector" in str(excinfo.value)

    def test_non_api_key_response_is_refused(self):
        payload = {"key": "not-a-key", "user_id": "1", "scope": "api"}
        with AuthStub(payload=payload) as stub:
            with pytest.raises(pkce.OrcaAuthError) as excinfo:
                pkce.exchange_code(stub.base, "code", "verifier")
        assert excinfo.value.reason == "unexpected_key_format"

    def test_missing_code_is_refused_before_network(self):
        with pytest.raises(pkce.OrcaAuthError) as excinfo:
            pkce.exchange_code("http://127.0.0.1:9", "", "verifier")
        assert excinfo.value.reason == "missing_code"
