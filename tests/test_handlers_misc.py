#!/usr/bin/env python3
"""
杂项工具处理器单元测试
测试 handlers/misc_handlers.py 中的工具注册和执行
"""

from unittest.mock import MagicMock

import pytest


def _register():
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
