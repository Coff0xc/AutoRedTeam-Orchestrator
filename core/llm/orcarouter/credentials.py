"""Credential seam for the OrcaRouter Cyber Inference provider.

Two adapters sit on one interface:

* :class:`ApiKeyCredentialSource` — the user's own ``sk-orca-…`` key from the
  environment or the project's user-level credential file;
* :class:`PkceCredentialSource` — OAuth 2.0 + PKCE, which produces the same
  kind of durable API key.

Downstream code (the provider adapter and model discovery) only ever sees
:class:`OrcaCredential`; it never asks where the key came from.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Mapping, Optional, Protocol

from . import config, pkce

logger = logging.getLogger(__name__)

ENV_KEY = "ORCAROUTER_API_KEY"


class OrcaCredentialError(RuntimeError):
    """Raised when no usable OrcaRouter credential can be produced."""


def mask_key(api_key: str) -> str:
    """Return a redacted form safe for logs, status output and errors."""
    key = api_key or ""
    if not key:
        return "<unset>"
    if len(key) <= 10:
        return "****"
    return f"{key[:8]}…{key[-4:]}"


def looks_like_key(api_key: str) -> bool:
    """Lightweight format check only; it is not proof of validity."""
    return bool(api_key) and api_key.startswith(config.KEY_PREFIX) and len(api_key) > 12


@dataclass(frozen=True)
class OrcaCredential:
    """A credential accepted by the inference relay."""

    api_key: str
    source: str  # "api_key" | "pkce"
    account_id: str = ""
    generation: str = ""
    scope: str = "api"
    model: str = ""

    def masked(self) -> str:
        return mask_key(self.api_key)


class CredentialStore:
    """Small JSON credential file next to the project's user config.

    The file is written atomically with mode ``0600``.  It holds a single
    OrcaRouter credential because the relay key is per-user, not per-session.
    """

    _lock = threading.Lock()

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or config.credential_store_path()

    # -- raw record ---------------------------------------------------------
    def load(self) -> Dict[str, Any]:
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            logger.warning("OrcaRouter credential file is unreadable; ignoring it")
            return {}
        return data if isinstance(data, dict) else {}

    def _write(self, data: Dict[str, Any]) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, mode=0o700, exist_ok=True)
        payload = json.dumps(data, indent=2, sort_keys=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".orcarouter-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self.path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # -- lifecycle ----------------------------------------------------------
    def save(
        self,
        api_key: str,
        *,
        source: str,
        account_id: str = "",
        scope: str = "api",
        model: str = "",
    ) -> OrcaCredential:
        if not api_key:
            raise OrcaCredentialError("Refusing to store an empty API key.")
        record = {
            "version": 1,
            "api_key": api_key,
            "source": source,
            "account_id": account_id,
            "generation": uuid.uuid4().hex,
            "scope": scope,
            "model": model,
            "needs_reauth": False,
            "obtained_at": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._write(record)
        return _credential_from_record(record)

    def clear(self) -> bool:
        """Remove the stored credential. Returns True when a file was removed."""
        with self._lock:
            try:
                os.unlink(self.path)
                return True
            except FileNotFoundError:
                return False
            except OSError as exc:
                raise OrcaCredentialError("Could not remove the stored credential.") from exc

    def current(self) -> Optional[OrcaCredential]:
        record = self.load()
        if not record or record.get("needs_reauth"):
            return None
        return _credential_from_record(record)

    def storable_status(self) -> Dict[str, Any]:
        """Redacted status for ``autort llm status``."""
        record = self.load()
        if not record:
            return {"stored": False}
        return {
            "stored": True,
            "source": str(record.get("source") or ""),
            "account_id": str(record.get("account_id") or ""),
            "scope": str(record.get("scope") or ""),
            "model": str(record.get("model") or ""),
            "needs_reauth": bool(record.get("needs_reauth")),
            "key": mask_key(str(record.get("api_key") or "")),
            "generation": str(record.get("generation") or ""),
        }

    def update_model(self, model: str) -> bool:
        record = self.load()
        if not record:
            return False
        record["model"] = model
        record["model_verified_at"] = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._write(record)
        return True

    def mark_needs_reauth(self, account_id: str, generation: str) -> bool:
        """Flag the exact rejected credential generation for reauthentication.

        A late failure from an older request must not poison a newly
        reauthorized credential, so both the account and generation must match.
        """
        with self._lock:
            record = self.load()
            if not record:
                return False
            if str(record.get("generation") or "") != generation:
                return False
            if (
                account_id
                and str(record.get("account_id") or "")
                and (str(record.get("account_id")) != account_id)
            ):
                return False
            record["needs_reauth"] = True
            self._write(record)
            return True


def _credential_from_record(record: Mapping[str, Any]) -> OrcaCredential:
    return OrcaCredential(
        api_key=str(record.get("api_key") or ""),
        source=str(record.get("source") or "api_key"),
        account_id=str(record.get("account_id") or ""),
        generation=str(record.get("generation") or ""),
        scope=str(record.get("scope") or "api"),
        model=str(record.get("model") or ""),
    )


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------
class OrcaCredentialSource(Protocol):
    """Minimal interface shared by the API-key and PKCE adapters."""

    name: str

    def acquire(self, **kwargs: Any) -> Optional[OrcaCredential]:  # pragma: no cover
        ...


class ApiKeyCredentialSource:
    """Adapter 1: a pasted/exported ``sk-orca-…`` key."""

    name = "api_key"

    def __init__(
        self,
        store: Optional[CredentialStore] = None,
        environ: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.store = store or CredentialStore()
        self._environ = environ if environ is not None else os.environ

    def acquire(
        self,
        key: Optional[str] = None,
        *,
        allow_stored: bool = True,
    ) -> Optional[OrcaCredential]:
        candidate = (key or "").strip()
        if candidate:
            return OrcaCredential(api_key=candidate, source=self.name, generation="manual")
        env_key = (self._environ.get(ENV_KEY) or "").strip()
        if env_key:
            return OrcaCredential(api_key=env_key, source=self.name, generation="env")
        if allow_stored:
            stored = self.store.current()
            if stored is not None:
                return OrcaCredential(
                    api_key=stored.api_key,
                    source=stored.source,
                    account_id=stored.account_id,
                    generation=stored.generation,
                    scope=stored.scope,
                    model=stored.model,
                )
        return None

    def save(self, api_key: str, *, model: str = "") -> OrcaCredential:
        """Persist a pasted key using the same store as the PKCE adapter."""
        if not looks_like_key(api_key):
            raise OrcaCredentialError(
                "That does not look like an OrcaRouter key (expected an sk-orca-… value)."
            )
        if not self._environ.get(ENV_KEY):
            return self.store.save(api_key, source=self.name, model=model)
        # An environment key already wins; persisting a different key would be
        # silently ignored, so report that instead of writing a dead file.
        raise OrcaCredentialError(
            f"{ENV_KEY} is set in the environment and takes precedence. Unset it "
            "to store a different key."
        )

    def clear(self) -> bool:
        return self.store.clear()


class PkceCredentialSource:
    """Adapter 2: OAuth 2.0 + PKCE (loopback, or out-of-band for headless hosts)."""

    name = "pkce"

    def __init__(
        self,
        store: Optional[CredentialStore] = None,
        auth_base: Optional[str] = None,
        opener: Optional[Callable[..., object]] = None,
    ) -> None:
        self.store = store or CredentialStore()
        self._auth_base = auth_base
        self._opener = opener

    def auth_base(self) -> str:
        return self._auth_base or config.auth_base_url()

    def acquire(
        self,
        *,
        flow: str = "loopback",
        open_browser: Optional[Callable[[str], bool]] = None,
        on_authorize_url: Optional[Callable[[str], None]] = None,
        code_prompt: Optional[Callable[[str], str]] = None,
        timeout: float = 180.0,
        reuse_stored: bool = True,
    ) -> OrcaCredential:
        if reuse_stored:
            stored = self.store.current()
            if stored is not None:
                return stored

        auth_base = self.auth_base()
        if flow == "oob":
            if code_prompt is None:
                raise OrcaCredentialError(
                    "Out-of-band login needs a way to read the displayed code."
                )
            attempt = pkce.new_attempt()
            url = pkce.build_oob_url(auth_base, attempt)
            if on_authorize_url is not None:
                on_authorize_url(url)
            if open_browser is not None:
                open_browser(url)
            code = (code_prompt(url) or "").strip()
            if not code:
                raise pkce.OrcaAuthError(
                    "No authorization code was entered.", reason="missing_code"
                )
            payload = pkce.exchange_code(auth_base, code, attempt.verifier, opener=self._opener)
        elif flow == "loopback":
            payload = pkce.run_loopback_flow(
                auth_base=auth_base,
                timeout=timeout,
                open_browser=open_browser,
                on_authorize_url=on_authorize_url,
                opener=self._opener,
            )
        else:
            raise OrcaCredentialError(f"Unknown authorization flow: {flow}")

        return self.store.save(
            payload["key"],
            source=self.name,
            account_id=payload.get("user_id", ""),
            scope=payload.get("scope", "api"),
        )

    def clear(self) -> bool:
        return self.store.clear()

    def mark_needs_reauth(
        self, credential: OrcaCredential, store: Optional[CredentialStore] = None
    ) -> bool:
        """Terminal 401 handling: no refresh grant exists, so flag that key."""
        target = store or self.store
        if credential.generation in ("", "env", "manual"):
            return False
        return target.mark_needs_reauth(credential.account_id, credential.generation)


def resolve_credential(
    store: Optional[CredentialStore] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Optional[OrcaCredential]:
    """Return the credential the provider should use, regardless of its source."""
    source = ApiKeyCredentialSource(store=store, environ=environ)
    return source.acquire()


__all__ = [
    "ApiKeyCredentialSource",
    "CredentialStore",
    "ENV_KEY",
    "OrcaCredential",
    "OrcaCredentialError",
    "OrcaCredentialSource",
    "PkceCredentialSource",
    "looks_like_key",
    "mask_key",
    "resolve_credential",
]
