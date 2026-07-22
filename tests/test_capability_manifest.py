"""Capability manifest and MCP profile registration tests."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from core.capability_manifest import (
    CAPABILITIES,
    CAPABILITY_PROFILE_ENV,
    PROFILE_ORDER,
    CapabilityManifestError,
    capability_manifest,
    capability_profiles,
    get_capability,
    normalize_profile,
    resolve_profile,
)
from handlers import register_all_handlers


class Counter:
    def __init__(self):
        self.counts: dict[str, int] = {}
        self.total = 0

    def add(self, category: str, count: int = 1):
        self.counts[category] = self.counts.get(category, 0) + count
        self.total += count

    def summary(self) -> str:
        return str(self.total)


def test_manifest_has_unique_complete_surface_totals():
    keys = {(capability.kind, capability.name) for capability in CAPABILITIES}
    summary = capability_manifest()["summary"]

    assert len(keys) == len(CAPABILITIES) == 141
    assert summary["by_kind"] == {"prompt": 6, "resource": 4, "tool": 131}


def test_profiles_are_monotonic_and_have_stable_counts():
    profiles = capability_profiles()["profiles"]
    counts = {profile["name"]: profile["surface_count"] for profile in profiles}

    assert tuple(counts) == PROFILE_ORDER
    assert counts == {"safe": 23, "scan": 85, "active-lab": 105, "full": 141}

    previous: set[tuple[str, str]] = set()
    for profile in PROFILE_ORDER:
        current = {
            (item["kind"], item["name"]) for item in capability_manifest(profile)["capabilities"]
        }
        assert previous < current
        previous = current


def test_safe_excludes_active_and_post_exploitation_surfaces():
    safe_capabilities = capability_manifest("safe")["capabilities"]
    safe_names = {item["name"] for item in safe_capabilities}
    active_effects = {
        "credential-use",
        "host-exec",
        "internet-egress",
        "network-active",
        "network-probe",
        "provider-egress",
        "target-write",
    }

    assert "ai_surface_scan_handlers" in safe_names
    assert "health_check" in safe_names
    assert "ext_tools_status" not in safe_names
    assert "generate_report" not in safe_names
    assert "c2_beacon_start" not in safe_names
    assert "credential_spray" not in safe_names
    assert "persistence_webshell" not in safe_names
    assert "exfiltrate_file" not in safe_names
    assert all(not active_effects.intersection(item["effects"]) for item in safe_capabilities)


def test_active_capabilities_declare_required_controls():
    active_capabilities = [
        capability
        for capability in CAPABILITIES
        if capability.minimum_profile in {"active-lab", "full"}
    ]

    assert active_capabilities
    assert all(capability.auth_required for capability in active_capabilities)
    assert all(capability.approval_required for capability in active_capabilities)
    assert all(capability.executor == "isolated-required" for capability in active_capabilities)


def test_profile_resolution_precedence_and_normalization():
    environment = {CAPABILITY_PROFILE_ENV: " scan "}

    assert resolve_profile(" FULL ", environ=environment) == "full"
    assert resolve_profile(None, environ=environment) == "scan"
    assert resolve_profile(None, default="active_lab", environ={}) == "active-lab"
    assert normalize_profile("ACTIVE_LAB") == "active-lab"


def test_unknown_profile_and_surface_fail_closed():
    from handlers import _ProfiledMCP

    mcp = MagicMock()
    counter = Counter()

    with pytest.raises(CapabilityManifestError, match="Unknown capability profile"):
        register_all_handlers(mcp, counter, MagicMock(), profile="unknown")
    assert counter.total == 0
    mcp.tool.assert_not_called()

    proxy = _ProfiledMCP(mcp, counter, "safe", "ai")
    with pytest.raises(CapabilityManifestError, match="Unclassified MCP surface"):

        @proxy.tool()
        async def unclassified_surface():
            return {}

    mcp.tool.assert_not_called()
    assert counter.total == 0

    with pytest.raises(AttributeError):
        proxy.add_tool


def test_manifest_drift_aborts_handler_registration():
    def register_unknown(mcp, counter, logger):
        @mcp.tool()
        async def unclassified_surface():
            return {}

    mcp = MagicMock()
    counter = Counter()
    logger = MagicMock()

    with patch(
        "handlers._handler_specs",
        return_value=[("AI辅助工具", "ai", register_unknown)],
    ):
        with pytest.raises(CapabilityManifestError, match="Unclassified MCP surface"):
            register_all_handlers(mcp, counter, logger, profile="safe")

    assert counter.total == 0
    logger.warning.assert_not_called()


@pytest.mark.parametrize(
    ("first_profile", "second_profile"),
    (("safe", "safe"), ("safe", "full"), ("full", "safe")),
)
def test_registration_is_one_shot(first_profile, second_profile):
    mcp = MagicMock()
    mcp.tool.return_value = lambda func: func
    mcp.prompt.return_value = lambda func: func
    mcp.resource.return_value = lambda func: func
    counter = Counter()

    register_all_handlers(mcp, counter, MagicMock(), profile=first_profile)
    original_total = counter.total

    with pytest.raises(CapabilityManifestError, match="already registered"):
        register_all_handlers(mcp, counter, MagicMock(), profile=second_profile)

    assert counter.total == original_total


@pytest.mark.parametrize("profile", PROFILE_ORDER)
@pytest.mark.asyncio
async def test_real_fastmcp_registration_matches_manifest(profile):
    mcp = FastMCP(f"manifest-{profile}")
    counter = Counter()
    register_all_handlers(mcp, counter, logging.getLogger(__name__), profile=profile)

    tools = await mcp.list_tools()
    prompts = await mcp.list_prompts()
    resources = await mcp.list_resources()
    templates = await mcp.list_resource_templates()
    actual = {("tool", item.name) for item in tools}
    actual.update(("prompt", item.name) for item in prompts)
    actual.update(("resource", item.name) for item in resources)
    actual.update(("resource", item.name) for item in templates)
    expected = {
        (item["kind"], item["name"]) for item in capability_manifest(profile)["capabilities"]
    }

    assert actual == expected
    assert counter.total == len(expected)


def test_legacy_registration_default_remains_full():
    mcp = MagicMock()
    mcp.tool.return_value = lambda func: func
    mcp.prompt.return_value = lambda func: func
    mcp.resource.return_value = lambda func: func
    counter = Counter()

    register_all_handlers(mcp, counter, MagicMock())

    assert counter.total == 141


def test_server_default_profile_is_safe(monkeypatch):
    import mcp_stdio_server

    monkeypatch.delenv(CAPABILITY_PROFILE_ENV, raising=False)
    with patch("handlers.register_all_handlers") as register:
        mcp_stdio_server.register_all_tools()

    register.assert_called_once_with(
        mcp_stdio_server.mcp,
        mcp_stdio_server._counter,
        mcp_stdio_server.logger,
        profile="safe",
    )


def test_get_capability_uses_kind_and_public_name():
    payload_resource = get_capability("resource", "payload_library")

    assert payload_resource.locator == "redteam://payloads/{category}"
    assert payload_resource.minimum_profile == "active-lab"


def test_manifest_distinguishes_required_from_enforced_controls():
    payload = get_capability("tool", "port_scan").to_dict()

    assert "auth_required" not in payload
    assert payload["required_controls"]["authentication"] is True
    assert payload["manifest_enforces"] == ["profile-registration"]


def test_production_counter_uses_manifest_categories():
    from mcp_stdio_server import ToolCounter

    mcp = FastMCP("counter-full")
    counter = ToolCounter()

    register_all_handlers(mcp, counter, MagicMock(), profile="full")

    assert counter.total == 141
    assert counter.counts["knowledge"] == 3
    assert counter.counts["mcts"] == 1
    assert "MCP surface" in counter.summary()
