"""
MCP 工具封装器

统一将 handlers 返回值标准化为 ToolResult.to_dict()
"""

from __future__ import annotations

from typing import Any, Callable

from utils.mcp_tooling import build_tool_decorator


def tool(mcp, **kwargs) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """返回包装后的 MCP 工具装饰器"""
    return build_tool_decorator(mcp, **kwargs)


def no_target_contact(reason: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """声明工具不观测目标，因此没有可核验的证据可返回。

    适用于纯生成器（payload/代码/计划）和只读本地状态的工具：它们的输出是产物或
    本地查询结果，不是对目标的观测，没有 evidence 可言。真正扫描/利用/横向的工具
    不适用——那些必须把证据传给调用方。

    静态契约检查 (``core.tooling.contract``) 据此豁免证据契约要求。豁免是人工判断，
    理由必须写清为什么不需要证据，它会随代码一起被 review。
    """
    if not reason or not reason.strip():
        raise ValueError("no_target_contact 必须给出理由：豁免证据契约是人工判断")

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        func.__no_target_contact__ = reason.strip()  # type: ignore[attr-defined]
        return func

    return decorator
