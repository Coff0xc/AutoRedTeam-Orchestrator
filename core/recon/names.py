"""Canonical recon module names and MCP tool aliases.

No recon engines are imported here. capability_manifest and recon_run both
use this table so catalog cards and execution resolve the same names.
"""

from __future__ import annotations

_MODULE_STEMS = (
    "port_scan",
    "fingerprint",
    "subdomain_enum",
    "dir_scan",
    "dns_lookup",
    "tech_detect",
    "waf_detect",
    "passive_subdomain_enum",
    "full_recon",
)

_EXTRA_ALIASES = {
    "port": "port_scan",
    "ports": "port_scan",
    "dns": "dns_lookup",
    "waf": "waf_detect",
    "tech": "tech_detect",
    "technology": "tech_detect",
    "subdomain": "subdomain_enum",
    "subdomains": "subdomain_enum",
    "dir": "dir_scan",
    "directory": "dir_scan",
    "directories": "dir_scan",
    "passive": "passive_subdomain_enum",
    "passive_subdomain": "passive_subdomain_enum",
    "recon": "full_recon",
    "full": "full_recon",
}


def _build_aliases() -> dict[str, str]:
    aliases = {stem: stem for stem in _MODULE_STEMS}
    aliases.update(_EXTRA_ALIASES)
    return aliases


RECON_MODULE_ALIASES = _build_aliases()


def known_recon_modules() -> tuple[str, ...]:
    """Sorted unique recon module names."""
    return tuple(sorted(set(RECON_MODULE_ALIASES.values())))


def canonical_recon_module(raw: str) -> str:
    """Map a tool name or alias to the recon module name."""
    key = str(raw).strip().lower().replace("-", "_")
    if not key:
        raise ValueError("recon module name is empty")
    resolved = RECON_MODULE_ALIASES.get(key)
    if resolved is None:
        available = ", ".join(known_recon_modules())
        raise ValueError(f"unknown recon module {raw!r}; available: {available}")
    return resolved
