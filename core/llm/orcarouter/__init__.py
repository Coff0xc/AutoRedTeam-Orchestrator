"""OrcaRouter Cyber Inference — first-class provider for authorized security work.

Public surface:

* provider identity and origin resolution (:mod:`.config`);
* the credential seam with API-key and PKCE adapters (:mod:`.credentials`);
* OAuth 2.0 + PKCE flows (:mod:`.pkce`);
* bounded model discovery and capability filters (:mod:`.catalog`).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from . import catalog, config, credentials, pkce
from .catalog import (
    CAPABILITY_ENDPOINT_TYPE,
    SEED_MODELS,
    SUPPORTED_CAPABILITIES,
    CatalogResult,
    ModelInfo,
    OrcaCatalogAuthError,
    OrcaCatalogError,
    fetch_catalog,
    filter_models,
    load_catalog,
    model_is_compatible,
    seed_catalog,
)
from .config import (
    APP_NAME,
    AUTHORIZE_PATH,
    AUTHORIZED_APPS_URL,
    CYBER_MODEL_CATALOG_URL,
    DEFAULT_API_BASE,
    DEFAULT_AUTH_BASE,
    DEFAULT_MODEL,
    EXCHANGE_PATH,
    GENERAL_FALLBACK_MODEL,
    KEY_DASHBOARD_URL,
    PROVIDER_DESCRIPTION,
    PROVIDER_ID,
    PROVIDER_LABEL,
    PROVIDER_PAGE_URL,
    RECOMMENDED_CYBER_MODELS,
    api_base_url,
    auth_base_url,
    validate_origin,
)
from .credentials import (
    ApiKeyCredentialSource,
    CredentialStore,
    OrcaCredential,
    OrcaCredentialError,
    OrcaCredentialSource,
    PkceCredentialSource,
    looks_like_key,
    mask_key,
    resolve_credential,
)
from .pkce import OrcaAuthError, default_browser_opener

# Registry entry mirrored into core.llm.provider's provider tables.
PROVIDER_REGISTRATION: Dict[str, Any] = {
    "id": PROVIDER_ID,
    "name": PROVIDER_LABEL,
    "description": PROVIDER_DESCRIPTION,
    "default_model": DEFAULT_MODEL,
    "recommended_cyber_models": list(RECOMMENDED_CYBER_MODELS),
    "fallback_model": GENERAL_FALLBACK_MODEL,
    "base_url": DEFAULT_API_BASE,
    "auth_base_url": DEFAULT_AUTH_BASE,
    "env_key": "ORCAROUTER_API_KEY",
    "auth_methods": ("api_key", "pkce"),
    "provider_page": PROVIDER_PAGE_URL,
    "cyber_catalog": CYBER_MODEL_CATALOG_URL,
}


def provider_status(store: Optional[CredentialStore] = None) -> Dict[str, Any]:
    """Redacted provider status for the CLI and MCP surfaces."""
    credential = resolve_credential(store=store)
    return {
        "provider": PROVIDER_ID,
        "label": PROVIDER_LABEL,
        "auth_base": auth_base_url(),
        "api_base": api_base_url(),
        "default_model": DEFAULT_MODEL,
        "recommended_cyber_models": list(RECOMMENDED_CYBER_MODELS),
        "fallback_model": GENERAL_FALLBACK_MODEL,
        "credential": (
            {
                "source": credential.source,
                "key": credential.masked(),
                "account_id": credential.account_id,
                "scope": credential.scope,
                "generation": credential.generation,
            }
            if credential is not None
            else None
        ),
        "stored": (store or CredentialStore()).storable_status(),
        "provider_page": PROVIDER_PAGE_URL,
        "cyber_catalog": CYBER_MODEL_CATALOG_URL,
    }


def create_chat_client(credential: Optional[OrcaCredential] = None) -> Any:
    """Return an OpenAI SDK client bound to the OrcaRouter relay.

    The SDK is imported lazily so this module stays importable without the
    optional dependency and so tests can exercise wiring without a network.
    """
    cred = credential or resolve_credential()
    if cred is None:
        raise OrcaCredentialError(
            "No OrcaRouter credential is configured. Set ORCAROUTER_API_KEY or "
            "run `autort llm connect`."
        )
    try:
        import openai
    except ImportError as exc:  # pragma: no cover - dependency is in requirements
        raise OrcaCredentialError(
            "The openai package is required for the OrcaRouter provider."
        ) from exc
    return openai.OpenAI(api_key=cred.api_key, base_url=api_base_url())


__all__ = [
    "APP_NAME",
    "AUTHORIZE_PATH",
    "AUTHORIZED_APPS_URL",
    "ApiKeyCredentialSource",
    "CAPABILITY_ENDPOINT_TYPE",
    "CYBER_MODEL_CATALOG_URL",
    "CatalogResult",
    "CredentialStore",
    "DEFAULT_API_BASE",
    "DEFAULT_AUTH_BASE",
    "DEFAULT_MODEL",
    "EXCHANGE_PATH",
    "GENERAL_FALLBACK_MODEL",
    "KEY_DASHBOARD_URL",
    "ModelInfo",
    "OrcaAuthError",
    "OrcaCatalogAuthError",
    "OrcaCatalogError",
    "OrcaCredential",
    "OrcaCredentialError",
    "OrcaCredentialSource",
    "PROVIDER_DESCRIPTION",
    "PROVIDER_ID",
    "PROVIDER_LABEL",
    "PROVIDER_PAGE_URL",
    "PROVIDER_REGISTRATION",
    "PkceCredentialSource",
    "RECOMMENDED_CYBER_MODELS",
    "SEED_MODELS",
    "SUPPORTED_CAPABILITIES",
    "api_base_url",
    "auth_base_url",
    "catalog",
    "config",
    "create_chat_client",
    "credentials",
    "default_browser_opener",
    "fetch_catalog",
    "filter_models",
    "load_catalog",
    "looks_like_key",
    "mask_key",
    "model_is_compatible",
    "pkce",
    "provider_status",
    "resolve_credential",
    "seed_catalog",
    "validate_origin",
]
