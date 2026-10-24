"""OrcaRouter Cyber Inference provider identity and origin resolution.

The provider is first-class: it has its own id, display name, model namespace and
independent configuration. It is not a generic "custom base URL" passthrough.

Authentication and inference use different public origins.  Never derive one
from the other by swapping a hostname or blindly appending ``/v1``.
"""

from __future__ import annotations

import os
from typing import Optional
from urllib.parse import urlsplit

PROVIDER_ID = "orcarouter"
PROVIDER_LABEL = "OrcaRouter Cyber Inference"
PROVIDER_DESCRIPTION = (
    "Cyber inference provider for authorized red-team and blue-team work. "
    "Routes scoped security reasoning to OrcaCyber models behind one "
    "OpenAI-compatible endpoint."
)

# Model namespace (vendor/model is preserved verbatim).
DEFAULT_MODEL = "orcarouter/auto"
RECOMMENDED_CYBER_MODELS: tuple[str, ...] = (
    "orcacyber-ultra-1.0",
    "orcacyber-zero-1.5",
)
GENERAL_FALLBACK_MODEL = "orcarouter/fusion"

# Public origins. These are intentionally different hosts.
DEFAULT_AUTH_BASE = "https://www.orcarouter.ai"
DEFAULT_API_BASE = "https://api.orcarouter.ai/v1"

AUTHORIZE_PATH = "/auth"
EXCHANGE_PATH = "/api/v1/auth/keys"
DEVICE_CODE_PATH = "/api/v1/auth/device/code"
DEVICE_TOKEN_PATH = "/api/v1/auth/device/token"
MODELS_PATH = "/models"

KEY_PREFIX = "sk-orca-"
APP_NAME = "AutoRedTeam-Orchestrator"

PROVIDER_PAGE_URL = "https://www.orcarouter.ai/cyber"
CYBER_MODEL_CATALOG_URL = "https://www.orcarouter.ai/models?tier=cyber"
KEY_DASHBOARD_URL = "https://www.orcarouter.ai/console/keys"
AUTHORIZED_APPS_URL = "https://www.orcarouter.ai/console/authorized-apps"

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


class OrcaConfigError(ValueError):
    """Raised when an OrcaRouter origin override is unusable."""


def _is_loopback(hostname: Optional[str]) -> bool:
    return bool(hostname) and hostname.lower() in _LOOPBACK_HOSTS


def validate_origin(url: str, *, setting: str) -> str:
    """Validate an origin URL and return it without a trailing slash.

    HTTPS is required for remote origins; plain HTTP is accepted only for
    loopback development hosts. Userinfo, query strings and fragments are
    rejected because they would corrupt the auth endpoints.
    """
    candidate = (url or "").strip().rstrip("/")
    if not candidate:
        raise OrcaConfigError(f"{setting} is empty")
    parts = urlsplit(candidate)
    if parts.scheme not in ("http", "https"):
        raise OrcaConfigError(f"{setting} must use http or https")
    if parts.username or parts.password:
        raise OrcaConfigError(f"{setting} must not contain userinfo")
    if parts.query or parts.fragment:
        raise OrcaConfigError(f"{setting} must not contain a query or fragment")
    if parts.scheme == "http" and not _is_loopback(parts.hostname):
        raise OrcaConfigError(f"{setting} must use https for non-loopback hosts")
    if not parts.hostname:
        raise OrcaConfigError(f"{setting} has no host")
    return candidate


def _shared_base() -> Optional[str]:
    value = (os.environ.get("ORCA_BASE_URL") or "").strip()
    if not value:
        return None
    return validate_origin(value, setting="ORCA_BASE_URL")


def auth_base_url() -> str:
    """Authorization origin (consent screen and code exchange)."""
    explicit = (os.environ.get("ORCA_AUTH_BASE_URL") or "").strip()
    if explicit:
        return validate_origin(explicit, setting="ORCA_AUTH_BASE_URL")
    shared = _shared_base()
    if shared:
        return shared
    return DEFAULT_AUTH_BASE


def api_base_url() -> str:
    """Inference and model-catalog origin, including the ``/v1`` suffix."""
    explicit = (os.environ.get("ORCA_API_BASE_URL") or "").strip()
    if explicit:
        return validate_origin(explicit, setting="ORCA_API_BASE_URL")
    shared = _shared_base()
    if shared:
        # A self-hosted deployment may expose both services on one origin; the
        # operator opted in explicitly, so extend the shared base to the relay.
        return shared if shared.endswith("/v1") else f"{shared}/v1"
    return DEFAULT_API_BASE


def api_origin() -> str:
    """Inference origin without the ``/v1`` suffix."""
    base = api_base_url()
    return base[: -len("/v1")] if base.endswith("/v1") else base


def credential_store_path() -> str:
    """Credential file used when the user has no environment key.

    ``AUTORT_ORCA_CREDENTIALS`` overrides it. The default follows the existing
    user-level config root this project already searches (``utils/config.py``).
    """
    explicit = (os.environ.get("AUTORT_ORCA_CREDENTIALS") or "").strip()
    if explicit:
        return explicit
    return os.path.join(os.path.expanduser("~"), ".config", "autoredt", "orcarouter.json")
