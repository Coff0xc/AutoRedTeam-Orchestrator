"""Canonical detector class names and MCP tool aliases.

No detector classes are imported here. capability_manifest and detect_run both
use this table so catalog cards and execution resolve the same names.
"""

from __future__ import annotations

_FACTORY_STEMS = (
    "sqli",
    "xss",
    "ssrf",
    "rce",
    "path_traversal",
    "ssti",
    "xxe",
    "idor",
    "cors",
    "http_smuggling",
    "cache_poisoning",
    "prototype_pollution",
    "crlf_injection",
    "host_header_injection",
    "exposure",
    "ldap",
    "open_redirect",
    "info_disclosure",
    "csrf",
    "auth_bypass",
    "weak_password",
    "session",
    "lfi",
    "jwt",
    "headers",
    "file_upload",
    "deserialize",
)

_EXTRA_ALIASES = {
    "security_headers": "headers",
    "security_headers_scan": "headers",
    "headers_scan": "headers",
    "upload": "file_upload",
    "upload_scan": "file_upload",
    "file_upload_scan": "file_upload",
    "jwt_scan": "jwt",
    "deserialize_scan": "deserialize",
}


def _build_aliases() -> dict[str, str]:
    aliases = {stem: stem for stem in _FACTORY_STEMS}
    aliases.update({f"{stem}_scan": stem for stem in _FACTORY_STEMS})
    aliases.update(_EXTRA_ALIASES)
    return aliases


DETECTOR_CLASS_ALIASES = _build_aliases()


def known_detector_classes() -> tuple[str, ...]:
    """Sorted unique DetectorFactory names plus deserialize."""
    return tuple(sorted(set(DETECTOR_CLASS_ALIASES.values())))


def canonical_detector_class(raw: str) -> str:
    """Map a tool name, alias, or factory stem to the DetectorFactory name."""
    key = str(raw).strip().lower().replace("-", "_")
    if not key:
        raise ValueError("detector class name is empty")
    resolved = DETECTOR_CLASS_ALIASES.get(key)
    if resolved is None:
        available = ", ".join(known_detector_classes())
        raise ValueError(f"unknown detector class {raw!r}; available: {available}")
    return resolved
