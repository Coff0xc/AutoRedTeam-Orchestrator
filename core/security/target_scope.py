"""DNS-aware target allowlist shared by CLI, SDK, and MCP.

Modes (``AUTORT_TARGET_SCOPE``):

- ``off``: no extra gate (default). Format and SSRF checks stay where they already are.
- ``enforce``: every non-empty target must match ``AUTORT_TARGET_ALLOWLIST``.

A non-empty allowlist turns the gate on even when the mode is ``off``.
``enforce`` with an empty list denies every target. Unknown modes fail closed
to ``enforce``. Direct ``core`` imports outside CLI / SDK / MCP stay ungated.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from core.security.mcp_security import InputValidator

logger = logging.getLogger(__name__)

SCOPE_MODE_ENV = "AUTORT_TARGET_SCOPE"
ALLOWLIST_ENV = "AUTORT_TARGET_ALLOWLIST"
DEFAULT_MODE = "off"

_validator = InputValidator()


class ScopeMode(Enum):
    """Whether the shared target allowlist is consulted."""

    OFF = "off"
    ENFORCE = "enforce"


class TargetScopeError(ValueError):
    """Raised when a target is outside the authorized allowlist."""

    def __init__(self, target: str, reason: str):
        self.target = target
        self.reason = reason
        super().__init__("Target %r is outside the authorized allowlist (%s)" % (target, reason))


@dataclass(frozen=True)
class ScopeDecision:
    """Allowlist result for one target string."""

    allowed: bool
    reason: str
    target: str
    hostname: str = ""
    resolved_ips: Tuple[str, ...] = ()

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise TargetScopeError(self.target, self.reason)


@dataclass(frozen=True)
class _AllowlistEntry:
    raw: str
    kind: str
    host: str = ""
    scheme: str = ""
    port: Optional[int] = None
    ip: Optional[ipaddress.IPv4Address | ipaddress.IPv6Address] = None
    network: Optional[ipaddress.IPv4Network | ipaddress.IPv6Network] = None


@dataclass(frozen=True)
class _Identity:
    raw: str
    hostname: str = ""
    scheme: str = ""
    port: Optional[int] = None
    ip: Optional[ipaddress.IPv4Address | ipaddress.IPv6Address] = None
    network: Optional[ipaddress.IPv4Network | ipaddress.IPv6Network] = None


def current_mode() -> ScopeMode:
    raw = os.environ.get(SCOPE_MODE_ENV, DEFAULT_MODE).strip().lower().replace("-", "_")
    for mode in ScopeMode:
        if raw == mode.value:
            return mode
    logger.warning("Unknown %s=%r; failing closed to enforce", SCOPE_MODE_ENV, raw)
    return ScopeMode.ENFORCE


def current_entries() -> Tuple[_AllowlistEntry, ...]:
    return _parse_allowlist(os.environ.get(ALLOWLIST_ENV, ""))


def is_active() -> bool:
    if current_mode() is ScopeMode.ENFORCE:
        return True
    return bool(current_entries())


def check_target(target: Optional[str]) -> ScopeDecision:
    """Decide whether ``target`` is in the configured allowlist."""
    raw = "" if target is None else str(target).strip()
    if not is_active():
        return ScopeDecision(allowed=True, reason="scope_off", target=raw)
    if raw == "":
        return ScopeDecision(allowed=True, reason="empty", target=raw)
    entries = current_entries()
    if not entries:
        return ScopeDecision(allowed=False, reason="empty_allowlist", target=raw)
    if len(raw) > 2048 or _validator.DANGEROUS_CHARS.search(raw):
        return ScopeDecision(allowed=False, reason="unparseable", target=raw)
    identity = _parse_identity(raw)
    if identity is None:
        return ScopeDecision(allowed=False, reason="unparseable", target=raw)

    presented_ok = _presented_matches(identity, entries)
    resolved: List[str] = []
    if identity.network is not None:
        if presented_ok:
            return ScopeDecision(
                allowed=True,
                reason="in_allowlist",
                target=raw,
                hostname=identity.hostname,
            )
        return ScopeDecision(
            allowed=False,
            reason="not_in_allowlist",
            target=raw,
            hostname=identity.hostname,
        )

    if identity.ip is not None:
        resolved = [str(identity.ip)]
    elif identity.hostname:
        resolution = _validator.resolve_hostname(identity.hostname)
        if not resolution.valid:
            return ScopeDecision(
                allowed=False,
                reason="dns_failed",
                target=raw,
                hostname=identity.hostname,
            )
        resolved = list(resolution.resolved_ips)

    ips: List[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for ip_str in resolved:
        try:
            ips.append(ipaddress.ip_address(ip_str))
        except ValueError:
            return ScopeDecision(
                allowed=False,
                reason="dns_failed",
                target=raw,
                hostname=identity.hostname,
                resolved_ips=tuple(resolved),
            )

    all_ips_in = bool(ips) and all(_ip_in_allowlist(ip, entries) for ip in ips)
    if not presented_ok and not all_ips_in:
        return ScopeDecision(
            allowed=False,
            reason="not_in_allowlist",
            target=raw,
            hostname=identity.hostname,
            resolved_ips=tuple(resolved),
        )

    for ip in ips:
        if _validator._is_private_ip(ip) and not _ip_in_allowlist(ip, entries):
            return ScopeDecision(
                allowed=False,
                reason="private_ip_not_allowlisted",
                target=raw,
                hostname=identity.hostname,
                resolved_ips=tuple(resolved),
            )

    return ScopeDecision(
        allowed=True,
        reason="in_allowlist",
        target=raw,
        hostname=identity.hostname,
        resolved_ips=tuple(resolved),
    )


def assert_in_scope(target: Optional[str]) -> None:
    """Raise ``TargetScopeError`` when the gate is on and ``target`` is out of scope."""
    check_target(target).raise_if_denied()


def _parse_allowlist(raw: str) -> Tuple[_AllowlistEntry, ...]:
    entries: List[_AllowlistEntry] = []
    seen = set()
    for token in _split_allowlist(raw):
        if token in seen:
            continue
        seen.add(token)
        entry = _parse_entry(token)
        if entry is not None:
            entries.append(entry)
    return tuple(entries)


def _split_allowlist(raw: str) -> List[str]:
    tokens: List[str] = []
    for line in raw.replace("\r\n", "\n").split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if " #" in stripped:
            stripped = stripped.split(" #", 1)[0].strip()
        for part in re.split(r"[\s,;]+", stripped):
            if part and not part.startswith("#"):
                tokens.append(part)
    return tokens


def _parse_entry(token: str) -> Optional[_AllowlistEntry]:
    value = token.strip()
    if not value or value == "*":
        return None
    if "://" in value:
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return None
        return _AllowlistEntry(
            raw=value,
            kind="origin",
            host=host,
            scheme=parsed.scheme.lower(),
            port=parsed.port,
        )
    if value.startswith("*."):
        host = value[2:].lower().rstrip(".")
        if not host:
            return None
        return _AllowlistEntry(raw=value, kind="wildcard", host=host)
    if value.startswith(".") and len(value) > 1:
        host = value[1:].lower().rstrip(".")
        return _AllowlistEntry(raw=value, kind="suffix", host=host)
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        return _AllowlistEntry(raw=value, kind="cidr", network=network)
    try:
        ip = ipaddress.ip_address(value)
        return _AllowlistEntry(raw=value, kind="ip", ip=ip)
    except ValueError:
        pass
    host, port = _split_host_port(value)
    if not host:
        return None
    return _AllowlistEntry(raw=value, kind="host", host=host, port=port)


def _parse_identity(raw: str) -> Optional[_Identity]:
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return None
        identity = _Identity(raw=raw, hostname=host, scheme=parsed.scheme.lower(), port=parsed.port)
        return _with_literal_ip(identity)
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return None
        return _Identity(raw=raw, network=network, hostname=str(network.network_address))
    host, port = _split_host_port(raw)
    if not host:
        return None
    identity = _Identity(raw=raw, hostname=host, port=port)
    return _with_literal_ip(identity)


def _with_literal_ip(identity: _Identity) -> _Identity:
    try:
        ip = ipaddress.ip_address(identity.hostname)
    except ValueError:
        return identity
    return _Identity(
        raw=identity.raw,
        hostname=identity.hostname,
        scheme=identity.scheme,
        port=identity.port,
        ip=ip,
    )


def _split_host_port(value: str) -> Tuple[str, Optional[int]]:
    text = value.strip().rstrip(".")
    if text.startswith("[") and "]" in text:
        end = text.find("]")
        host = text[1:end].lower()
        rest = text[end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        if rest:
            return "", None
        return host, None
    if text.count(":") == 1:
        host, _, port_text = text.rpartition(":")
        if host and port_text.isdigit():
            return host.lower(), int(port_text)
    try:
        ipaddress.ip_address(text)
        return text.lower(), None
    except ValueError:
        pass
    if "/" in text or " " in text:
        return "", None
    return text.lower(), None


def _presented_matches(identity: _Identity, entries: Sequence[_AllowlistEntry]) -> bool:
    if identity.ip is not None and _ip_in_allowlist(identity.ip, entries):
        return True
    if identity.network is not None and _network_in_allowlist(identity.network, entries):
        return True
    host = identity.hostname
    if not host:
        return False
    for entry in entries:
        if entry.kind in {"host", "wildcard", "suffix", "origin"} and _host_matches(host, entry):
            if entry.kind == "origin":
                if entry.scheme and identity.scheme and entry.scheme != identity.scheme:
                    continue
                if entry.port is not None and identity.port != entry.port:
                    continue
            elif entry.port is not None and identity.port != entry.port:
                continue
            return True
    return False


def _host_matches(hostname: str, entry: _AllowlistEntry) -> bool:
    host = hostname.lower().rstrip(".")
    needle = entry.host.lower().rstrip(".")
    if not needle:
        return False
    if entry.kind in {"wildcard", "suffix"}:
        return host == needle or host.endswith("." + needle)
    return host == needle


def _ip_in_allowlist(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    entries: Sequence[_AllowlistEntry],
) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    for entry in entries:
        if entry.kind == "ip" and entry.ip is not None and ip == entry.ip:
            return True
        if entry.kind == "cidr" and entry.network is not None and ip in entry.network:
            return True
    return False


def _network_in_allowlist(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    entries: Sequence[_AllowlistEntry],
) -> bool:
    for entry in entries:
        if entry.kind == "cidr" and entry.network is not None:
            try:
                if network.subnet_of(entry.network):
                    return True
            except TypeError:
                continue
        if (
            entry.kind == "ip"
            and entry.ip is not None
            and network.prefixlen == network.max_prefixlen
            and network.network_address == entry.ip
        ):
            return True
    return False
