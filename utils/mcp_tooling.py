"""
MCP tool result normalization helpers.

Use these helpers to wrap legacy MCP tools so they return ToolResult.to_dict().
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable

from core.result import ensure_tool_result


def _wrap_tool_func(func: Callable[..., Any]) -> Callable[..., Any]:
    if inspect.iscoroutinefunction(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            result = await func(*args, **kwargs)
            return ensure_tool_result(result).to_dict()
    else:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            result = func(*args, **kwargs)
            return ensure_tool_result(result).to_dict()

    return wrapper


def build_tool_decorator(mcp) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Return a tool decorator that normalizes results to ToolResult.to_dict()."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        return mcp.tool()(_wrap_tool_func(func))

    return decorator


def patch_mcp_tool(mcp) -> Callable[..., Any]:
    """Patch mcp.tool to normalize all tool outputs. Returns the original tool."""
    if getattr(mcp.tool, "_tool_result_patched", False):
        return getattr(mcp.tool, "_original_tool", mcp.tool)

    original_tool = mcp.tool

    def tool_wrapper(*args, **kwargs):
        decorator = original_tool(*args, **kwargs)

        def apply(func: Callable[..., Any]) -> Any:
            return decorator(_wrap_tool_func(func))

        return apply

    tool_wrapper._tool_result_patched = True  # type: ignore[attr-defined]
    tool_wrapper._original_tool = original_tool  # type: ignore[attr-defined]
    mcp.tool = tool_wrapper
    return original_tool


def restore_mcp_tool(mcp, original_tool: Callable[..., Any]) -> None:
    """Restore the original mcp.tool if it was patched."""
    if original_tool is not None:
        mcp.tool = original_tool
