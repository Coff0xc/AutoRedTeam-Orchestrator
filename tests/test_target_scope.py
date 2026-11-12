"""Unified DNS-aware target allowlist."""

from __future__ import annotations

import socket

import pytest

from core.security.target_scope import (
    ScopeMode,
    TargetScopeError,
    assert_in_scope,
    check_target,
    current_mode,
    is_active,
)
from handlers.error_handling import validate_inputs

pytestmark = [pytest.mark.unit, pytest.mark.security]


def _dns(mapping):
    def fake(host, port, *args, **kwargs):
        if host not in mapping:
            raise socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided")
        results = []
        for ip in mapping[host]:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            results.append((family, socket.SOCK_STREAM, 0, "", (ip, 0)))
        return results

    return fake


@pytest.fixture(autouse=True)
def _reset_scope(monkeypatch):
    monkeypatch.delenv("AUTORT_TARGET_SCOPE", raising=False)
    monkeypatch.delenv("AUTORT_TARGET_ALLOWLIST", raising=False)


def test_default_mode_is_off():
    assert current_mode() is ScopeMode.OFF
    assert is_active() is False
    assert check_target("http://evil.example").allowed is True
    assert check_target("http://evil.example").reason == "scope_off"


def test_unknown_mode_fails_closed_to_enforce(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_SCOPE", "open-sesame")
    assert current_mode() is ScopeMode.ENFORCE
    decision = check_target("http://lab.example")
    assert decision.allowed is False
    assert decision.reason == "empty_allowlist"


def test_enforce_with_empty_list_denies(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_SCOPE", "enforce")
    decision = check_target("10.0.0.1")
    assert decision.allowed is False
    assert decision.reason == "empty_allowlist"


def test_empty_target_skips_gate(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_SCOPE", "enforce")
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "10.0.0.0/8")
    assert check_target("").allowed is True
    assert check_target("").reason == "empty"
    assert_in_scope("")
    assert_in_scope(None)


def test_nonempty_allowlist_auto_enforces(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "10.0.0.0/8")
    assert is_active() is True
    assert check_target("10.0.1.5").allowed is True
    assert check_target("8.8.8.8").allowed is False
    assert check_target("8.8.8.8").reason == "not_in_allowlist"


def test_exact_host_and_wildcard(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_SCOPE", "enforce")
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "lab.example,*.corp.example")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        _dns(
            {
                "lab.example": ["1.2.3.4"],
                "app.corp.example": ["1.2.3.5"],
                "corp.example": ["1.2.3.6"],
                "evil.example": ["9.9.9.9"],
            }
        ),
    )
    assert check_target("https://lab.example/path").allowed is True
    assert check_target("https://app.corp.example").allowed is True
    assert check_target("corp.example").allowed is True
    assert check_target("https://evil.example").allowed is False


def test_suffix_and_origin_and_cidr(monkeypatch):
    monkeypatch.setenv(
        "AUTORT_TARGET_ALLOWLIST",
        ".lab.example,https://origin.example:8443,10.0.0.0/8",
    )
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        _dns(
            {
                "app.lab.example": ["1.2.3.4"],
                "origin.example": ["1.2.3.7"],
            }
        ),
    )
    assert check_target("http://app.lab.example").allowed is True
    assert check_target("https://origin.example:8443/api").allowed is True
    assert check_target("https://origin.example/api").allowed is False
    assert check_target("10.0.1.9").allowed is True
    assert check_target("10.0.1.0/24").allowed is True
    assert check_target("11.0.0.1").allowed is False


def test_hostname_match_public_ip_allowed(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "*.lab.example")
    monkeypatch.setattr(socket, "getaddrinfo", _dns({"app.lab.example": ["1.2.3.4"]}))
    decision = check_target("https://app.lab.example")
    assert decision.allowed is True
    assert decision.resolved_ips == ("1.2.3.4",)


def test_hostname_match_private_ip_denied_without_cidr(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "*.lab.example")
    monkeypatch.setattr(socket, "getaddrinfo", _dns({"app.lab.example": ["169.254.169.254"]}))
    decision = check_target("https://app.lab.example")
    assert decision.allowed is False
    assert decision.reason == "private_ip_not_allowlisted"


def test_hostname_match_private_ip_allowed_with_cidr(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "*.lab.example,169.254.0.0/16")
    monkeypatch.setattr(socket, "getaddrinfo", _dns({"app.lab.example": ["169.254.169.254"]}))
    assert check_target("https://app.lab.example").allowed is True


def test_resolved_ips_can_authorize_without_name_match(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "10.0.0.0/8")
    monkeypatch.setattr(socket, "getaddrinfo", _dns({"inside.corp": ["10.0.1.5"]}))
    assert check_target("inside.corp").allowed is True


def test_split_horizon_denied_when_any_ip_out_of_cidr(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "10.0.0.0/8")
    monkeypatch.setattr(socket, "getaddrinfo", _dns({"inside.corp": ["10.0.1.5", "8.8.8.8"]}))
    decision = check_target("inside.corp")
    assert decision.allowed is False
    assert decision.reason == "not_in_allowlist"


def test_dns_failure_denies(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "lab.example")
    monkeypatch.setattr(socket, "getaddrinfo", _dns({}))
    decision = check_target("lab.example")
    assert decision.allowed is False
    assert decision.reason == "dns_failed"


def test_command_injection_unparseable(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "10.0.0.0/8")
    decision = check_target("10.0.0.1; rm -rf /")
    assert decision.allowed is False
    assert decision.reason == "unparseable"


def test_assert_in_scope_raises(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_SCOPE", "enforce")
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "10.0.0.0/8")
    with pytest.raises(TargetScopeError) as exc:
        assert_in_scope("8.8.8.8")
    assert exc.value.reason == "not_in_allowlist"


def test_scanner_constructor_enforces(monkeypatch):
    from autort import Scanner

    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "10.0.0.0/8")
    with pytest.raises(TargetScopeError):
        Scanner("8.8.8.8")
    scanner = Scanner("10.0.1.5")
    assert scanner.target == "10.0.1.5"


def test_exploiter_empty_target_allowed_when_enforcing(monkeypatch):
    from autort import Exploiter

    monkeypatch.setenv("AUTORT_TARGET_SCOPE", "enforce")
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "10.0.0.0/8")
    exploiter = Exploiter("")
    assert exploiter.target == ""


def test_validate_inputs_denies_out_of_scope(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "10.0.0.0/8")

    @validate_inputs(target="target")
    def scan(target: str):
        return {"success": True, "target": target}

    denied = scan(target="8.8.8.8")
    assert denied["success"] is False
    assert denied["error_type"] == "TargetScopeError"
    assert denied["code"] == "not_in_allowlist"
    allowed = scan(target="10.0.1.5")
    assert allowed == {"success": True, "target": "10.0.1.5"}


def test_validate_inputs_url_list(monkeypatch):
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "10.0.0.0/8")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        _dns({"lab.example": ["10.0.1.5"], "evil.example": ["8.8.8.8"]}),
    )

    @validate_inputs(url="url")
    def probe(url: str):
        return {"success": True, "url": url}

    denied = probe(url="https://evil.example")
    assert denied["success"] is False
    assert denied["code"] == "not_in_allowlist"
    allowed = probe(url="http://10.0.1.5/")
    assert allowed["success"] is True
    via_dns = probe(url="https://lab.example")
    assert via_dns["success"] is True


@pytest.mark.asyncio
async def test_secure_tool_denies_out_of_scope(monkeypatch):
    from core.security.mcp_security import MCPSecurityMiddleware

    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "example.com")
    monkeypatch.setattr(socket, "getaddrinfo", _dns({"example.com": ["1.2.3.4"]}))
    security = MCPSecurityMiddleware()

    @security.secure_tool(operation="dns_lookup")
    async def lookup(target: str):
        return {"success": True, "target": target}

    denied = await lookup(target="8.8.8.8")
    assert denied["success"] is False
    assert denied["code"] == "not_in_allowlist"
    allowed = await lookup(target="example.com")
    assert allowed == {"success": True, "target": "example.com"}


def test_multiline_allowlist_and_comments(monkeypatch):
    monkeypatch.setenv(
        "AUTORT_TARGET_ALLOWLIST",
        """
        # lab range
        10.0.0.0/8  # cidr
        192.168.1.10
        """,
    )
    assert check_target("10.1.2.3").allowed is True
    assert check_target("192.168.1.10").allowed is True
    assert check_target("192.168.1.11").allowed is False
