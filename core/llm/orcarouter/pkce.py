"""OAuth 2.0 + PKCE helpers for OrcaRouter (Flow A loopback, Flow B out-of-band).

The verifier is created from a cryptographic RNG for every attempt and never
leaves the process except in the exchange request body.  Only its S256
challenge is placed on the authorize URL.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import logging
import secrets
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlsplit

from . import config

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT = 30.0
_MAX_RESPONSE_BYTES = 64 * 1024
_LOOPBACK_HOST = "127.0.0.1"
_CALLBACK_PATH = "/cb"


class OrcaAuthError(RuntimeError):
    """A user-facing authorization failure.

    Messages never contain the verifier, the authorization code, or a key.
    """

    def __init__(self, message: str, *, status: Optional[int] = None, reason: str = ""):
        super().__init__(message)
        self.status = status
        self.reason = reason


@dataclass(frozen=True)
class PkceAttempt:
    """One authorization attempt's secrets; ``verifier`` stays in-process."""

    verifier: str
    challenge: str
    state: str


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def new_attempt() -> PkceAttempt:
    """Create a fresh verifier/challenge/state triple from a crypto RNG."""
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    state = _b64url(secrets.token_bytes(16))
    return PkceAttempt(verifier=verifier, challenge=challenge, state=state)


def state_matches(expected: str, received: Optional[str]) -> bool:
    """Constant-time state comparison (CSRF defence)."""
    if not expected or not received:
        return False
    return hmac.compare_digest(expected, received)


def build_authorize_url(
    auth_base: str,
    attempt: PkceAttempt,
    *,
    callback_url: str,
    app_name: str = config.APP_NAME,
    scope: str = "api",
) -> str:
    """Build the consent URL. ``S256`` is always sent, even for loopback."""
    query = urlencode(
        {
            "callback_url": callback_url,
            "code_challenge": attempt.challenge,
            "code_challenge_method": "S256",
            "state": attempt.state,
            "app_name": app_name,
            "scope": scope,
        }
    )
    return f"{auth_base}{config.AUTHORIZE_PATH}?{query}"


def _error_body(raw: bytes) -> Dict[str, str]:
    try:
        parsed = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {k: str(v) for k, v in parsed.items() if k in ("error", "error_description", "message")}


def _map_exchange_error(status: int, body: Dict[str, str]) -> OrcaAuthError:
    """Translate an exchange failure into an actionable message."""
    description = (body.get("error_description") or body.get("message") or "").strip()
    # Never relay a body verbatim: only our own wording is guaranteed safe.
    if status == 400:
        return OrcaAuthError(
            "OrcaRouter rejected the authorization request (400). The code "
            "challenge method must be S256 for this client.",
            status=status,
            reason="invalid_request",
        )
    if status == 403:
        return OrcaAuthError(
            "OrcaRouter rejected the authorization code (403). It may have "
            "expired, already been used, or not match this process. Run the "
            "connect command again.",
            status=status,
            reason="invalid_grant",
        )
    if status == 429:
        return OrcaAuthError(
            "OrcaRouter rate-limited key issuance (429). A user may mint at "
            "most 10 PKCE keys per 24 hours; reuse the stored key instead of "
            "authorizing again.",
            status=status,
            reason="rate_limited",
        )
    if status >= 500:
        return OrcaAuthError(
            "OrcaRouter authorization service is unavailable right now. Try "
            "again later or paste an API key.",
            status=status,
            reason="server_error",
        )
    suffix = f" ({description[:120]})" if description else ""
    return OrcaAuthError(
        f"OrcaRouter authorization failed with HTTP {status}{suffix}.",
        status=status,
        reason="exchange_failed",
    )


def exchange_code(
    auth_base: str,
    code: str,
    verifier: str,
    *,
    timeout: float = _REQUEST_TIMEOUT,
    opener: Optional[Callable[..., object]] = None,
) -> Dict[str, str]:
    """Exchange an authorization code for a durable OrcaRouter API key.

    The request goes to ``{auth_base}/api/v1/auth/keys`` — never to the
    inference origin and never with a client secret.
    """
    if not code:
        raise OrcaAuthError("No authorization code was provided.", reason="missing_code")
    if not verifier:
        raise OrcaAuthError(
            "No PKCE verifier is available for this attempt.", reason="missing_verifier"
        )

    payload = json.dumps(
        {
            "code": code,
            "code_verifier": verifier,
            "code_challenge_method": "S256",
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{auth_base}{config.EXCHANGE_PATH}",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )

    open_url = opener or urllib.request.urlopen
    try:
        with open_url(request, timeout=timeout) as response:  # type: ignore[union-attr]
            raw = response.read(_MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        body = _error_body(exc.read(_MAX_RESPONSE_BYTES))
        raise _map_exchange_error(int(exc.code), body) from None
    except urllib.error.URLError as exc:
        raise OrcaAuthError(
            "Could not reach the OrcaRouter authorization service. Check your "
            "network or proxy settings and try again.",
            reason="network_error",
        ) from exc
    except OSError as exc:
        raise OrcaAuthError(
            "Could not reach the OrcaRouter authorization service.",
            reason="network_error",
        ) from exc

    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise OrcaAuthError(
            "OrcaRouter returned an unreadable authorization response.",
            reason="invalid_response",
        ) from None
    if not isinstance(data, dict):
        raise OrcaAuthError(
            "OrcaRouter returned an unexpected authorization response.",
            reason="invalid_response",
        )

    error = str(data.get("error") or "").strip()
    if error:
        raise OrcaAuthError(
            f"OrcaRouter authorization failed: {error}.",
            reason=error,
        )

    key = str(data.get("key") or "").strip()
    if not key:
        raise OrcaAuthError(
            "OrcaRouter authorization response did not contain a key.",
            reason="missing_key",
        )
    if not key.startswith(config.KEY_PREFIX):
        raise OrcaAuthError(
            "OrcaRouter returned a credential that is not an API key.",
            reason="unexpected_key_format",
        )

    granted_scope = str(data.get("scope") or "").strip()
    if granted_scope != "api":
        # The requested scope is not the granted scope; refuse to hand back a
        # credential the inference relay cannot use.
        raise OrcaAuthError(
            f'OrcaRouter granted scope "{granted_scope or "unknown"}", not "api". '
            "Inference requests need the api scope; ask a workspace owner to "
            "approve the wider grant.",
            reason="scope_downgrade",
        )

    return {
        "key": key,
        "scope": granted_scope,
        "user_id": str(data.get("user_id") or ""),
    }


class _LoopbackResult:
    """Thread-safe one-shot holder for the callback outcome."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self.code: Optional[str] = None
        self.error: Optional[str] = None

    def deliver(self, code: Optional[str], error: Optional[str]) -> None:
        if self._event.is_set():
            return
        self.code = code
        self.error = error
        self._event.set()

    def wait(self, timeout: float) -> bool:
        return self._event.wait(timeout)


_PAGE_OK = (
    "<!doctype html><html><head><meta charset='utf-8'><title>OrcaRouter</title></head>"
    "<body style='font-family:system-ui;padding:3rem'>"
    "<h1>Connected to OrcaRouter</h1>"
    "<p>You can close this tab and return to your terminal.</p></body></html>"
)
_PAGE_ERROR = (
    "<!doctype html><html><head><meta charset='utf-8'><title>OrcaRouter</title></head>"
    "<body style='font-family:system-ui;padding:3rem'>"
    "<h1>Authorization did not complete</h1>"
    "<p>{reason}</p><p>You can close this tab.</p></body></html>"
)


def _make_handler(expected_state: str, result: _LoopbackResult):
    class CallbackHandler(BaseHTTPRequestHandler):
        server_version = "AutoRT-Orca-Callback"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            # Keep request lines (which carry the one-time code) out of logs.
            logger.debug("OrcaRouter callback received")

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path != _CALLBACK_PATH:
                self.send_response(404)
                self.end_headers()
                return

            params = parse_qs(parsed.query)
            received_state = (params.get("state") or [None])[0]
            error = (params.get("error") or [None])[0]

            if not state_matches(expected_state, received_state):
                self._respond(400, _PAGE_ERROR.format(reason="State mismatch."))
                result.deliver(None, "state_mismatch")
                return

            if error:
                self._respond(200, _PAGE_ERROR.format(reason=html.escape(error)))
                result.deliver(None, error)
                return

            code = (params.get("code") or [None])[0]
            if not code:
                self._respond(400, _PAGE_ERROR.format(reason="Missing authorization code."))
                result.deliver(None, "missing_code")
                return

            self._respond(200, _PAGE_OK)
            result.deliver(code, None)

        def _respond(self, status: int, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)

    return CallbackHandler


def run_loopback_flow(
    *,
    auth_base: str,
    app_name: str = config.APP_NAME,
    scope: str = "api",
    timeout: float = 180.0,
    open_browser: Optional[Callable[[str], bool]] = None,
    on_authorize_url: Optional[Callable[[str], None]] = None,
    opener: Optional[Callable[..., object]] = None,
) -> Dict[str, str]:
    """Flow A: listen on loopback, open the browser, exchange the code.

    The listener is bound before the URL is handed out so the port is known.
    The server is always closed before this function returns.
    """
    attempt = new_attempt()
    result = _LoopbackResult()
    handler = _make_handler(attempt.state, result)
    server = ThreadingHTTPServer((_LOOPBACK_HOST, 0), handler)
    server.daemon_threads = True

    port = server.server_address[1]
    callback_url = f"http://{_LOOPBACK_HOST}:{port}{_CALLBACK_PATH}"
    authorize_url = build_authorize_url(
        auth_base,
        attempt,
        callback_url=callback_url,
        app_name=app_name,
        scope=scope,
    )

    thread = threading.Thread(target=server.serve_forever, name="orca-pkce-callback", daemon=True)
    thread.start()
    deadline = time.monotonic() + max(1.0, timeout)
    try:
        if on_authorize_url is not None:
            on_authorize_url(authorize_url)
        if open_browser is not None:
            try:
                opened = bool(open_browser(authorize_url))
            except Exception:  # pragma: no cover - browser launch is best effort
                opened = False
            if not opened and on_authorize_url is None:
                logger.info("Could not open a browser; use the printed URL")

        remaining = max(0.0, deadline - time.monotonic())
        if not result.wait(remaining):
            raise OrcaAuthError(
                "Timed out waiting for OrcaRouter authorization. Run the "
                "connect command again, or paste an API key instead.",
                reason="timeout",
            )
        if result.error:
            if result.error == "access_denied":
                raise OrcaAuthError(
                    "Authorization was denied in the browser.", reason="access_denied"
                )
            if result.error == "state_mismatch":
                raise OrcaAuthError(
                    "The authorization response failed its state check and was "
                    "discarded. Run the connect command again.",
                    reason="state_mismatch",
                )
            raise OrcaAuthError(f"Authorization failed: {result.error}.", reason=result.error)
        if not result.code:
            raise OrcaAuthError("Authorization finished without a code.", reason="missing_code")
        return exchange_code(
            auth_base,
            result.code,
            attempt.verifier,
            timeout=min(_REQUEST_TIMEOUT, max(5.0, deadline - time.monotonic())),
            opener=opener,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def build_oob_url(
    auth_base: str,
    attempt: PkceAttempt,
    *,
    app_name: str = config.APP_NAME,
    scope: str = "api",
) -> str:
    """Flow B authorize URL: the consent screen displays the code."""
    return build_authorize_url(
        auth_base,
        attempt,
        callback_url="oob",
        app_name=app_name,
        scope=scope,
    )


def default_browser_opener(url: str) -> bool:
    """Best-effort browser launch that never raises."""
    try:  # pragma: no cover - depends on the host desktop
        import webbrowser

        return bool(webbrowser.open(url))
    except Exception:  # pragma: no cover
        return False


__all__ = [
    "OrcaAuthError",
    "PkceAttempt",
    "build_authorize_url",
    "build_oob_url",
    "default_browser_opener",
    "exchange_code",
    "new_attempt",
    "run_loopback_flow",
    "state_matches",
]
