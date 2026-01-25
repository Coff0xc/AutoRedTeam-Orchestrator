"""
MCP 工具封装器

统一将 handlers 返回值标准化为 ToolResult.to_dict()
"""

from __future__ import annotations

from typing import Any, Callable

from utils.mcp_tooling import build_tool_decorator


def tool(mcp) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """返回包装后的 MCP 工具装饰器"""
    return build_tool_decorator(mcp)
