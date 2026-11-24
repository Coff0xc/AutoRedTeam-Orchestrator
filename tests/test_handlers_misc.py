#!/usr/bin/env python3
"""
杂项工具处理器单元测试
测试 handlers/misc_handlers.py 中的工具注册和执行
"""

import json
from unittest.mock import MagicMock

import pytest


def _register(profile=None):
    from handlers.misc_handlers import register_misc_tools

    mock_mcp = MagicMock()
    mock_counter = MagicMock()
    mock_logger = MagicMock()

    registered_tools = {}

    def capture_tool():
        def decorator(func):
            registered_tools[func.__name__] = func
            return func

        return decorator

    mock_mcp.tool = capture_tool
    if profile:
        mock_mcp.capability_profile = profile
    register_misc_tools(mock_mcp, mock_counter, mock_logger)
    return registered_tools


@pytest.mark.asyncio
async def test_registry_stats_reports_package_version():
    """registry_stats 报出的 version 必须是包版本，不是硬编码的旧值"""
    from core import __version__

    tools = _register()
    result = await tools["registry_stats"]()
    assert result["data"]["version"] == __version__


@pytest.mark.asyncio
async def test_health_check_reports_package_version():
    """health_check 报出的 version 必须是包版本，不是硬编码的旧值"""
    from core import __version__

    tools = _register()
    result = await tools["health_check"]()
    assert result["data"]["version"] == __version__


@pytest.mark.asyncio
async def test_tool_search_lists_resident_and_finds_catalog_detector():
    tools = _register("scan")
    empty = await tools["tool_search"](limit=50)
    names = {item["name"] for item in empty["data"]["matches"]}

    assert empty["success"] is True
    assert "detect_run" in names
    assert all(item["resident"] is True for item in empty["data"]["matches"])
    self_hit = await tools["tool_search"](query="tool_search")
    assert any(item["name"] == "tool_search" for item in self_hit["data"]["matches"])

    found = await tools["tool_search"](query="sqli", kind="tool", limit=12)
    by_name = {item["name"]: item for item in found["data"]["matches"]}
    assert "sqli_scan" in by_name
    assert by_name["sqli_scan"]["invoke"] == {"tool": "detect_run", "classes": ["sqli"]}


@pytest.mark.asyncio
async def test_tool_enable_resident_surface_is_already_listed():
    tools = _register("safe")
    result = await tools["tool_enable"](name="health_check")
    data = result["data"]
    assert result["success"] is True
    assert data["resident"] is True
    assert data["invoke"] == {"tool": "health_check"}


@pytest.mark.asyncio
async def test_tool_enable_resident_prompt_is_already_listed():
    tools = _register("safe")
    result = await tools["tool_enable"](name="analyze_findings", kind="prompt")
    data = result["data"]
    assert result["success"] is True
    assert data["resident"] is True
    assert data["invoke"] == {"prompt": "analyze_findings"}


@pytest.mark.asyncio
async def test_tool_enable_rejects_unknown_kind():
    tools = _register("safe")
    result = await tools["tool_enable"](name="plan_pentest", kind="skill")
    data = result.get("data", result)
    assert result["success"] is False
    assert "kind must be tool, prompt, or resource" in str(data.get("error") or data)


@pytest.mark.asyncio
async def test_tool_enable_records_catalog_grant_and_respects_budget(monkeypatch, tmp_path):
    from core.capability_grants import GRANT_BUDGET_ENV, GRANT_LOG_ENV, GRANT_SCHEMA
    from handlers.misc_handlers import register_misc_tools

    registered_tools = {}
    log_path = tmp_path / "grants.json"
    monkeypatch.setenv(GRANT_LOG_ENV, str(log_path))
    monkeypatch.setenv(GRANT_BUDGET_ENV, "1")

    class StubMCP:
        capability_profile = "scan"
        _autort_catalog = {
            ("tool", "jwt_scan"): (lambda **kwargs: {"ok": True}),
            ("tool", "session_list"): (lambda **kwargs: {"ok": True}),
        }

        def tool(self, **kwargs):
            def decorator(func):
                registered_tools[func.__name__] = func
                if kwargs.get("name"):
                    registered_tools[str(kwargs["name"])] = func
                return func

            return decorator

        def prompt(self, **kwargs):
            def decorator(func):
                return func

            return decorator

    mcp = StubMCP()
    register_misc_tools(mcp, MagicMock(), MagicMock())
    enable = registered_tools["tool_enable"]

    first = await enable(name="jwt_scan")
    data = first["data"]
    assert first["success"] is True
    assert data["grants"]["schema"] == GRANT_SCHEMA
    assert data["grants"]["count"] == 1
    assert data["grants"]["grants"][0]["name"] == "jwt_scan"

    replay = await enable(name="jwt_scan")
    assert replay["success"] is True
    assert replay["data"]["grants"]["count"] == 1

    blocked = await enable(name="session_list")
    assert blocked["success"] is False
    assert GRANT_BUDGET_ENV in str(blocked.get("error") or blocked.get("data"))
    assert "session_list" not in registered_tools
    saved = json.loads(log_path.read_text(encoding="utf-8"))
    assert saved["count"] == 1


@pytest.mark.asyncio
async def test_tool_enable_registers_catalog_prompt_via_inner_factory():
    from handlers.misc_handlers import register_misc_tools

    registered_tools = {}
    registered_prompts = {}

    class StubMCP:
        capability_profile = "full"
        _autort_catalog = {("prompt", "plan_pentest"): (lambda **kwargs: [])}

        def tool(self, **kwargs):
            def decorator(func):
                registered_tools[func.__name__] = func
                return func

            return decorator

        def prompt(self, **kwargs):
            def decorator(func):
                registered_prompts[kwargs.get("name") or func.__name__] = func
                return func

            return decorator

    register_misc_tools(StubMCP(), MagicMock(), MagicMock())

    result = await registered_tools["tool_enable"](name="plan_pentest", kind="prompt")
    data = result["data"]
    assert result["success"] is True
    assert data["resident"] is False
    assert data["invoke"] == {"prompt": "plan_pentest"}
    assert "plan_pentest" in registered_prompts
