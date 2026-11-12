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
    RESIDENT_SURFACES,
    CapabilityManifestError,
    capability_manifest,
    capability_profiles,
    get_capability,
    mcp_registration_profile,
    normalize_profile,
    resolve_profile,
    search_surfaces,
    surface_enabled_for_mcp,
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

    assert len(keys) == len(CAPABILITIES) == 149
    assert summary["by_kind"] == {"prompt": 6, "resource": 4, "tool": 139}


def test_profiles_are_monotonic_and_have_stable_counts():
    profiles = capability_profiles()["profiles"]
    counts = {profile["name"]: profile["surface_count"] for profile in profiles}

    assert tuple(counts) == PROFILE_ORDER
    assert counts == {"safe": 27, "scan": 92, "active-lab": 113, "full": 149}
    registered = {profile["name"]: profile["registered_count"] for profile in profiles}
    assert registered == {"safe": 18, "scan": 22, "active-lab": 23, "full": 23}


def test_mcp_registration_profile_defaults_full_and_reads_wrapper():
    assert mcp_registration_profile(MagicMock()) == "full"
    wrapper = MagicMock()
    wrapper.capability_profile = "safe"
    assert mcp_registration_profile(wrapper) == "safe"
    assert surface_enabled_for_mcp(wrapper, "tool", "cve_search") is True
    assert surface_enabled_for_mcp(wrapper, "tool", "cve_auto_exploit") is False
    assert RESIDENT_SURFACES <= {(item.kind, item.name) for item in CAPABILITIES}

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

    assert counter.total == 23


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
    assert payload["manifest_enforces"] == ["profile-registration", "authentication"]


def test_production_counter_uses_manifest_categories():
    from mcp_stdio_server import ToolCounter

    mcp = MCPServer("counter-full")
    counter = ToolCounter()

    register_all_handlers(mcp, counter, MagicMock(), profile="full")

    assert counter.total == 23
    assert counter.counts.get("knowledge", 0) == 0
    assert counter.counts.get("mcts", 0) == 0
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
    assert get_capability("tool", "vuln_scan").resident is False
    assert get_capability("tool", "nuclei_scan").resident is True
    assert get_capability("tool", "recon_run").resident is True
    assert get_capability("tool", "full_recon").resident is False
    assert get_capability("tool", "port_scan").resident is False
    assert get_capability("tool", "exploit_run").resident is True
    assert get_capability("tool", "exploit_run").minimum_profile == "active-lab"
    assert get_capability("tool", "tool_enable").resident is True
    assert get_capability("tool", "skill_catalog").resident is True
    assert get_capability("tool", "skill_read").resident is True
    assert get_capability("tool", "session_create").resident is True
    assert get_capability("tool", "session_status").resident is True
    assert get_capability("tool", "session_list").resident is False
    assert get_capability("tool", "session_complete").resident is False
    assert get_capability("tool", "lateral_ssh").resident is False


@pytest.mark.asyncio
async def test_scan_profile_list_tools_hides_factory_detectors():
    mcp = MCPServer("scan-resident")
    register_all_handlers(mcp, Counter(), logging.getLogger(__name__), profile="scan")
    names = {item.name for item in await mcp.list_tools()}

    assert "detect_run" in names
    assert "recon_run" in names
    assert "tool_search" in names
    assert "tool_enable" in names
    assert "nuclei_scan" in names
    assert "verify_finding" in names
    assert "skill_catalog" in names
    assert "skill_read" in names
    assert "session_create" in names
    assert "session_status" in names
    assert "session_list" not in names
    assert "session_complete" not in names
    assert "full_recon" not in names
    assert "vuln_scan" not in names
    assert "sqli_scan" not in names
    assert "xss_scan" not in names
    assert "port_scan" not in names
    assert "waf_detect" not in names
    assert "exploit_run" not in names
    assert "jwt_scan" not in names


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


def test_canonical_exploit_mode_aliases():
    from core.exploit.names import canonical_exploit_mode, known_exploit_modes

    assert canonical_exploit_mode("cve") == "exploit_by_cve"
    assert canonical_exploit_mode("poc_execute") == "poc_execute"
    assert canonical_exploit_mode("retry") == "exploit_with_retry"
    assert "verify_and_exploit" in known_exploit_modes()


def test_search_surfaces_points_catalog_exploit_at_exploit_run():
    result = search_surfaces("exploit_vulnerability", profile="active-lab", kind="tool", limit=12)
    by_name = {item["name"]: item for item in result["matches"]}

    assert "exploit_vulnerability" in by_name
    card = by_name["exploit_vulnerability"]
    assert card["resident"] is False
    assert card["invoke"] == {"tool": "exploit_run", "mode": "exploit_vulnerability"}

    poc = search_surfaces("poc_execute", profile="active-lab", kind="tool", limit=12)
    poc_card = {item["name"]: item for item in poc["matches"]}["poc_execute"]
    assert poc_card["invoke"] == {"tool": "exploit_run", "mode": "poc_execute"}

    pentest = search_surfaces("auto_pentest", profile="full", kind="tool", limit=12)
    pentest_card = {item["name"]: item for item in pentest["matches"]}["auto_pentest"]
    assert pentest_card["invoke"] == {"tool": "tool_enable", "name": "auto_pentest"}


def test_search_surfaces_points_long_tail_at_tool_enable():
    result = search_surfaces("jwt_scan", profile="scan", kind="tool", limit=12)
    by_name = {item["name"]: item for item in result["matches"]}

    assert by_name["jwt_scan"]["invoke"] == {"tool": "tool_enable", "name": "jwt_scan"}

    sessions = search_surfaces("session_list", profile="safe", kind="tool", limit=12)
    session_card = {item["name"]: item for item in sessions["matches"]}["session_list"]
    assert session_card["resident"] is False
    assert session_card["invoke"] == {"tool": "tool_enable", "name": "session_list"}


def test_search_surfaces_points_catalog_prompt_and_resource_at_tool_enable():
    prompts = search_surfaces("plan_pentest", profile="full", kind="prompt", limit=12)
    prompt_card = {item["name"]: item for item in prompts["matches"]}["plan_pentest"]
    assert prompt_card["resident"] is False
    assert prompt_card["invoke"] == {
        "tool": "tool_enable",
        "name": "plan_pentest",
        "kind": "prompt",
    }

    sessions = search_surfaces("active_sessions", profile="scan", kind="resource", limit=12)
    session_card = {item["name"]: item for item in sessions["matches"]}["active_sessions"]
    assert session_card["resident"] is False
    assert session_card["invoke"] == {
        "tool": "tool_enable",
        "name": "active_sessions",
        "kind": "resource",
    }

    resident = search_surfaces("analyze_findings", profile="safe", kind="prompt", limit=12)
    resident_card = {item["name"]: item for item in resident["matches"]}["analyze_findings"]
    assert resident_card["resident"] is True
    assert resident_card["invoke"] == {"prompt": "analyze_findings"}


def test_search_surfaces_points_vuln_scan_at_detect_run():
    result = search_surfaces("vuln_scan", profile="scan", kind="tool", limit=12)
    by_name = {item["name"]: item for item in result["matches"]}

    assert by_name["vuln_scan"]["invoke"] == {"tool": "detect_run"}


@pytest.mark.asyncio
async def test_tool_enable_registers_catalog_detector():
    mcp = MCPServer("enable-scan")
    register_all_handlers(mcp, Counter(), logging.getLogger(__name__), profile="scan")
    names = {item.name for item in await mcp.list_tools()}
    assert "sqli_scan" not in names

    result = await mcp.call_tool("tool_enable", {"name": "sqli_scan"})
    payload = result.structured_content or {}
    inner = payload.get("result", payload)
    data = inner.get("data", inner) if isinstance(inner, dict) else {}
    assert inner.get("success") is True or data.get("enabled") is True

    names = {item.name for item in await mcp.list_tools()}
    assert "sqli_scan" in names


@pytest.mark.asyncio
async def test_tool_enable_registers_session_list():
    mcp = MCPServer("enable-session")
    register_all_handlers(mcp, Counter(), logging.getLogger(__name__), profile="safe")
    names = {item.name for item in await mcp.list_tools()}
    assert "session_list" not in names
    assert "session_complete" not in names
    assert "session_create" in names

    result = await mcp.call_tool("tool_enable", {"name": "session_list"})
    payload = result.structured_content or {}
    inner = payload.get("result", payload)
    data = inner.get("data", inner) if isinstance(inner, dict) else {}
    assert inner.get("success") is True or data.get("enabled") is True

    names = {item.name for item in await mcp.list_tools()}
    assert "session_list" in names
    assert "session_complete" not in names


@pytest.mark.asyncio
async def test_tool_enable_rejects_higher_profile_surface():
    mcp = MCPServer("enable-safe")
    register_all_handlers(mcp, Counter(), logging.getLogger(__name__), profile="safe")

    result = await mcp.call_tool("tool_enable", {"name": "sqli_scan"})
    text = str(result.structured_content or result.content)
    assert "sqli_scan" in text
    assert "scan" in text
    names = {item.name for item in await mcp.list_tools()}
    assert "sqli_scan" not in names


def _enable_payload(result):
    payload = result.structured_content or {}
    inner = payload.get("result", payload)
    data = inner.get("data", inner) if isinstance(inner, dict) else {}
    return inner, data


@pytest.mark.parametrize(
    "profile,kind,name,lister",
    [
        ("full", "prompt", "plan_pentest", "list_prompts"),
        ("scan", "resource", "active_sessions", "list_resources"),
        ("full", "resource", "payload_library", "list_resource_templates"),
    ],
)
@pytest.mark.asyncio
async def test_tool_enable_registers_catalog_prompt_or_resource(profile, kind, name, lister):
    mcp = MCPServer(f"enable-{kind}-{name}")
    register_all_handlers(mcp, Counter(), logging.getLogger(__name__), profile=profile)
    listed = {item.name for item in await getattr(mcp, lister)()}
    assert name not in listed

    result = await mcp.call_tool("tool_enable", {"name": name, "kind": kind})
    inner, data = _enable_payload(result)
    assert inner.get("success") is True or data.get("enabled") is True
    invoke = data.get("invoke") or inner.get("invoke")
    assert invoke[kind] == name
    if kind == "resource":
        assert "locator" in invoke

    listed = {item.name for item in await getattr(mcp, lister)()}
    assert name in listed


@pytest.mark.parametrize(
    "profile,kind,name,required,lister",
    [
        ("safe", "prompt", "plan_pentest", "active-lab", "list_prompts"),
        ("scan", "resource", "payload_library", "active-lab", "list_resource_templates"),
    ],
)
@pytest.mark.asyncio
async def test_tool_enable_rejects_higher_profile_prompt_or_resource(
    profile, kind, name, required, lister
):
    mcp = MCPServer(f"enable-{kind}-{name}-{profile}")
    register_all_handlers(mcp, Counter(), logging.getLogger(__name__), profile=profile)

    result = await mcp.call_tool("tool_enable", {"name": name, "kind": kind})
    text = str(result.structured_content or result.content)
    assert name in text
    assert required in text
    listed = {item.name for item in await getattr(mcp, lister)()}
    assert name not in listed
