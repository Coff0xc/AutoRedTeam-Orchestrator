"""Capability manifest and MCP profile registration tests."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
from mcp.server import MCPServer

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
    search_surfaces,
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

    assert len(keys) == len(CAPABILITIES) == 145
    assert summary["by_kind"] == {"prompt": 6, "resource": 4, "tool": 135}


def test_profiles_are_monotonic_and_have_stable_counts():
    profiles = capability_profiles()["profiles"]
    counts = {profile["name"]: profile["surface_count"] for profile in profiles}

    assert tuple(counts) == PROFILE_ORDER
    assert counts == {"safe": 24, "scan": 89, "active-lab": 109, "full": 145}
    registered = {profile["name"]: profile["registered_count"] for profile in profiles}
    assert registered == {"safe": 24, "scan": 55, "active-lab": 75, "full": 111}

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


def test_manifest_drift_aborts_handler_registration(monkeypatch):
    import handlers

    def register_unknown(mcp, counter, logger):
        @mcp.tool()
        async def unclassified_surface():
            return {}

    monkeypatch.setattr(
        handlers,
        "_handler_specs",
        lambda: [("AI辅助工具", "ai", "register_unknown_surface")],
    )
    monkeypatch.setattr(handlers, "register_unknown_surface", register_unknown, raising=False)

    mcp = MagicMock()
    counter = Counter()
    logger = MagicMock()

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


@pytest.mark.asyncio
async def test_real_mcp_server_stores_description_keyword():
    mcp = MCPServer("description-probe")
    expected = "Stored from the description keyword."

    @mcp.tool(description=expected)
    def status_clock() -> dict:
        """Docstring that must not replace the keyword."""
        return {}

    @mcp.prompt(description=expected)
    def notes_prompt() -> list:
        """Docstring that must not replace the keyword."""
        return []

    tools = await mcp.list_tools()
    prompts = await mcp.list_prompts()

    assert [(item.name, item.description) for item in tools] == [("status_clock", expected)]
    assert [(item.name, item.description) for item in prompts] == [("notes_prompt", expected)]


@pytest.mark.parametrize("profile", PROFILE_ORDER)
@pytest.mark.asyncio
async def test_real_fastmcp_registration_matches_manifest(profile):
    mcp = MCPServer(f"manifest-{profile}")
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
        (item.kind, item.name)
        for item in CAPABILITIES
        if item.allowed_in(profile) and item.resident
    }

    assert actual == expected
    assert counter.total == len(expected)

    listed = {("tool", item.name): item.description for item in tools}
    listed.update({("prompt", item.name): item.description for item in prompts})
    listed.update({("resource", item.name): item.description for item in resources})
    listed.update({("resource", item.name): item.description for item in templates})
    for kind, name in expected:
        assert listed[(kind, name)] == get_capability(kind, name).public_description()


def test_legacy_registration_default_remains_full():
    mcp = MagicMock()
    mcp.tool.return_value = lambda func: func
    mcp.prompt.return_value = lambda func: func
    mcp.resource.return_value = lambda func: func
    counter = Counter()

    register_all_handlers(mcp, counter, MagicMock())

    assert counter.total == 111


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

    mcp = MCPServer("counter-full")
    counter = ToolCounter()

    register_all_handlers(mcp, counter, MagicMock(), profile="full")

    assert counter.total == 111
    assert counter.counts["knowledge"] == 3
    assert counter.counts["mcts"] == 1
    assert "MCP surface" in counter.summary()


def test_factory_detector_tools_are_catalog_only():
    sqli = get_capability("tool", "sqli_scan")
    detect_run = get_capability("tool", "detect_run")
    tool_search = get_capability("tool", "tool_search")

    assert sqli.resident is False
    assert sqli.allowed_in("scan")
    assert detect_run.resident is True
    assert detect_run.minimum_profile == "scan"
    assert tool_search.resident is True
    assert tool_search.minimum_profile == "safe"
    assert get_capability("tool", "vuln_scan").resident is True
    assert get_capability("tool", "nuclei_scan").resident is True
    assert get_capability("tool", "recon_run").resident is True
    assert get_capability("tool", "full_recon").resident is True
    assert get_capability("tool", "port_scan").resident is False


@pytest.mark.asyncio
async def test_scan_profile_list_tools_hides_factory_detectors():
    mcp = MCPServer("scan-resident")
    register_all_handlers(mcp, Counter(), logging.getLogger(__name__), profile="scan")
    names = {item.name for item in await mcp.list_tools()}

    assert "detect_run" in names
    assert "recon_run" in names
    assert "full_recon" in names
    assert "tool_search" in names
    assert "vuln_scan" in names
    assert "sqli_scan" not in names
    assert "xss_scan" not in names
    assert "port_scan" not in names
    assert "waf_detect" not in names


def test_search_surfaces_empty_query_lists_resident_only():
    result = search_surfaces("", profile="scan", limit=50)

    assert result["profile"] == "scan"
    assert result["matches"]
    assert all(item["resident"] is True for item in result["matches"])
    names = {item["name"] for item in result["matches"]}
    assert "detect_run" in names
    assert "sqli_scan" not in names


def test_search_surfaces_finds_catalog_detector_and_points_at_detect_run():
    result = search_surfaces("sqli", profile="scan", kind="tool", limit=12)
    by_name = {item["name"]: item for item in result["matches"]}

    assert "sqli_scan" in by_name
    card = by_name["sqli_scan"]
    assert card["resident"] is False
    assert card["invoke"] == {"tool": "detect_run", "classes": ["sqli"]}


def test_search_surfaces_finds_catalog_recon_and_points_at_recon_run():
    result = search_surfaces("port_scan", profile="scan", kind="tool", limit=12)
    by_name = {item["name"]: item for item in result["matches"]}

    assert "port_scan" in by_name
    card = by_name["port_scan"]
    assert card["resident"] is False
    assert card["invoke"] == {"tool": "recon_run", "modules": ["port_scan"]}


def test_canonical_recon_module_aliases():
    from core.recon.names import canonical_recon_module, known_recon_modules

    assert canonical_recon_module("port") == "port_scan"
    assert canonical_recon_module("waf") == "waf_detect"
    assert canonical_recon_module("passive") == "passive_subdomain_enum"
    assert "full_recon" in known_recon_modules()


def test_canonical_detector_class_aliases():
    from core.detectors.names import canonical_detector_class, known_detector_classes

    assert canonical_detector_class("sqli_scan") == "sqli"
    assert canonical_detector_class("security_headers") == "headers"
    assert canonical_detector_class("upload_scan") == "file_upload"
    assert "deserialize" in known_detector_classes()
    assert "jwt" in known_detector_classes()


def test_search_surfaces_safe_profile_omits_scan_detectors():
    result = search_surfaces("sqli", profile="safe", kind="tool", limit=12)
    names = {item["name"] for item in result["matches"]}

    assert "sqli_scan" not in names
    assert "detect_run" not in names
    assert "tool_search" in {
        item["name"] for item in search_surfaces("tool_search", profile="safe")["matches"]
    }
