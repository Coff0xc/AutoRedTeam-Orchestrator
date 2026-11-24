"""Live MCP initialize / tools/list against an in-process JSON-RPC server."""

from __future__ import annotations

import logging

import pytest
from mcp import Client
from mcp.server import MCPServer

from _version import __version__
from core.capability_manifest import CAPABILITIES, PROFILE_ORDER, get_capability
from handlers import register_all_handlers

_CATALOG_CANARIES = (
    "sqli_scan",
    "session_list",
    "full_recon",
    "poc_execute",
    "cve_auto_exploit",
    "attack_chain_plan",
    "plan_pentest",
    "payload_library",
    "smart_analyze",
    "plan_attack_path",
    "kg_attack_paths",
    "auto_pentest",
)


class _Counter:
    def add(self, category: str, count: int = 1) -> None:
        return None


def _resident(profile: str) -> set[tuple[str, str]]:
    return {
        (item.kind, item.name)
        for item in CAPABILITIES
        if item.allowed_in(profile) and item.resident
    }


@pytest.mark.parametrize("profile", PROFILE_ORDER)
@pytest.mark.asyncio
async def test_live_initialize_and_list_methods_match_resident_surfaces(profile: str):
    mcp = MCPServer("AutoRedTeam", version=__version__)
    register_all_handlers(mcp, _Counter(), logging.getLogger(__name__), profile=profile)

    async with Client(mcp, mode="legacy") as client:
        info = client.server_info
        assert info is not None
        assert info.name == "AutoRedTeam"
        assert info.version == __version__
        assert client.protocol_version
        assert client.server_capabilities.tools is not None

        listed_tools = await client.list_tools()
        listed_prompts = await client.list_prompts()
        listed_resources = await client.list_resources()
        listed_templates = await client.list_resource_templates()

    assert listed_tools.next_cursor is None
    actual = {("tool", item.name) for item in listed_tools.tools}
    actual.update(("prompt", item.name) for item in listed_prompts.prompts)
    actual.update(("resource", item.name) for item in listed_resources.resources)
    actual.update(("resource", item.name) for item in listed_templates.resource_templates)
    expected = _resident(profile)
    assert actual == expected

    listed = {("tool", item.name): item.description for item in listed_tools.tools}
    listed.update({("prompt", item.name): item.description for item in listed_prompts.prompts})
    listed.update(
        {("resource", item.name): item.description for item in listed_resources.resources}
    )
    listed.update(
        {("resource", item.name): item.description for item in listed_templates.resource_templates}
    )
    for kind, name in expected:
        assert listed[(kind, name)] == get_capability(kind, name).public_description()

    listed_names = {name for _kind, name in actual}
    for canary in _CATALOG_CANARIES:
        assert canary not in listed_names
