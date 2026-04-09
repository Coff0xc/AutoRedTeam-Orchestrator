"""
MCP tool result normalization helpers.

Use these helpers to wrap legacy MCP tools so they return ToolResult.to_dict().

Note: 使用延迟导入避免循环依赖 (core.result 在函数调用时才导入)
"""

from __future__ import annotations

import functools
import inspect
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, cast

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 操作审计日志 — 记录每次 MCP 工具调用
# ---------------------------------------------------------------------------

# 通过环境变量控制，默认启用 (AUTORT_AUDIT_LOG=0 关闭)
_AUDIT_ENABLED: bool = os.environ.get("AUTORT_AUDIT_LOG", "1") != "0"

# 审计日志文件路径
_AUDIT_LOG_PATH: Path = Path(os.environ.get(
    "AUTORT_AUDIT_LOG_PATH",
    str(Path(__file__).resolve().parent.parent / "data" / "operation_audit.jsonl"),
))

# 需要脱敏的参数名 (大小写不敏感匹配)
_SENSITIVE_KEYS: frozenset[str] = frozenset({
    "password", "passwd", "api_key", "apikey", "token",
    "secret", "credential", "private_key", "access_key",
    "secret_key", "auth", "authorization",
})


def _sanitize_params(params: dict[str, Any]) -> dict[str, Any]:
    """脱敏敏感参数，返回安全副本"""
    sanitized = {}
    for key, value in params.items():
        if key.lower() in _SENSITIVE_KEYS:
            sanitized[key] = "***REDACTED***"
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_params(value)
        else:
            # 截断过长的值以防日志膨胀
            str_val = str(value)
            sanitized[key] = str_val[:500] if len(str_val) > 500 else value
    return sanitized


def _write_audit_record(record: dict[str, Any]) -> None:
    """追加写入一条审计日志记录到 JSONL 文件"""
    try:
        _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except Exception as e:
        # 审计日志写入失败不应影响工具正常执行
        logger.debug("审计日志写入失败: %s", e)


def _wrap_tool_func(func: Callable[..., Any]) -> Callable[..., Any]:
    """包装工具函数，标准化返回值为 ToolResult.to_dict() 并记录审计日志"""
    tool_name = getattr(func, "__name__", str(func))

    if inspect.iscoroutinefunction(func):

        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            # 延迟导入避免循环依赖
            from core.result import ensure_tool_result

            start_ts = time.time()
            success = True
            error_msg = None
            try:
                result = await func(*args, **kwargs)
                return ensure_tool_result(result).to_dict()
            except Exception as exc:
                success = False
                error_msg = str(exc)
                raise
            finally:
                if _AUDIT_ENABLED:
                    elapsed_ms = round((time.time() - start_ts) * 1000, 2)
                    _write_audit_record({
                        "tool_name": tool_name,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                        "params": _sanitize_params(kwargs),
                        "success": success,
                        "error": error_msg,
                        "execution_time_ms": elapsed_ms,
                    })

    else:

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # 延迟导入避免循环依赖
            from core.result import ensure_tool_result

            start_ts = time.time()
            success = True
            error_msg = None
            try:
                result = func(*args, **kwargs)
                return ensure_tool_result(result).to_dict()
            except Exception as exc:
                success = False
                error_msg = str(exc)
                raise
            finally:
                if _AUDIT_ENABLED:
                    elapsed_ms = round((time.time() - start_ts) * 1000, 2)
                    _write_audit_record({
                        "tool_name": tool_name,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                        "params": _sanitize_params(kwargs),
                        "success": success,
                        "error": error_msg,
                        "execution_time_ms": elapsed_ms,
                    })

    return wrapper


def build_tool_decorator(mcp, **kwargs) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Return a tool decorator that normalizes results to ToolResult.to_dict()."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        return cast(Callable[..., Any], mcp.tool(**kwargs)(_wrap_tool_func(func)))

    return decorator


def patch_mcp_tool(mcp) -> Callable[..., Any]:
    """Patch mcp.tool to normalize all tool outputs. Returns the original tool."""
    if getattr(mcp.tool, "_tool_result_patched", False):
        return cast(Callable[..., Any], getattr(mcp.tool, "_original_tool", mcp.tool))

    original_tool = mcp.tool

    def tool_wrapper(*args, **kwargs):
        decorator = original_tool(*args, **kwargs)

        def apply(func: Callable[..., Any]) -> Any:
            return cast(Callable[..., Any], decorator(_wrap_tool_func(func)))

        return apply

    tool_wrapper._tool_result_patched = True  # type: ignore[attr-defined]
    tool_wrapper._original_tool = original_tool  # type: ignore[attr-defined]
    mcp.tool = tool_wrapper
    return cast(Callable[..., Any], original_tool)


def restore_mcp_tool(mcp, original_tool: Callable[..., Any]) -> None:
    """Restore the original mcp.tool if it was patched."""
    if original_tool is not None:
        mcp.tool = original_tool
