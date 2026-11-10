#!/usr/bin/env python3
"""
杂项工具处理器单元测试
测试 handlers/misc_handlers.py 中的工具注册和执行
"""

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
