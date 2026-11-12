#!/usr/bin/env python3
"""
MCP 授权中间件 - MCP Tools Authorization Middleware

为MCP工具提供授权检查装饰器，集成AuthManager
仅用于授权渗透测试和安全研究
"""

import functools
import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, cast

logger = logging.getLogger(__name__)

# 尝试导入AuthManager
try:
    from .auth_manager import AuthManager, Permission, ToolLevel

    HAS_AUTH_MANAGER = True
except ImportError:
    HAS_AUTH_MANAGER = False
    logger.warning("AuthManager不可用，授权检查将被跳过")


class AuthMode(Enum):
    """授权模式"""

    STRICT = "strict"  # 严格模式：必须提供有效API Key
    PERMISSIVE = "permissive"  # 宽松模式：无Key时允许访问（记录警告）
    DISABLED = "disabled"  # 禁用模式：不检查授权


# 全局配置
_auth_config = {
    "mode": AuthMode.STRICT,  # 默认严格模式
    "manager": None,
    "audit_enabled": True,
}


def get_auth_manager() -> Optional["AuthManager"]:
    """获取全局AuthManager实例"""
    if _auth_config["manager"] is None and HAS_AUTH_MANAGER:
        try:
            _auth_config["manager"] = AuthManager()
        except Exception as e:
            logger.error("初始化AuthManager失败: %s", e)
    return _auth_config["manager"]


def set_auth_mode(mode: AuthMode):
    """设置授权模式"""
    if mode == AuthMode.DISABLED:
        # 仅在测试环境下允许禁用授权
        is_test = os.getenv("AUTOREDTEAM_ENV") == "test" or os.getenv("PYTEST_CURRENT_TEST")
        if not is_test:
            logger.warning(
                "拒绝设置DISABLED模式：仅允许在测试环境中禁用授权 "
                "(需设置 AUTOREDTEAM_ENV=test 或 PYTEST_CURRENT_TEST)"
            )
            return
    _auth_config["mode"] = mode
    logger.info("授权模式设置为: %s", mode.value)


def set_audit_enabled(enabled: bool):
    """设置是否启用审计"""
    _auth_config["audit_enabled"] = enabled


def get_api_key_from_env() -> Optional[str]:
    """从环境变量获取API Key"""
    return os.getenv("AUTOREDTEAM_API_KEY") or os.getenv("MCP_API_KEY")


_AUTH_RANK = {"none": 0, "safe": 1, "moderate": 2, "dangerous": 3, "critical": 4}
_RISK_TO_RANK = {
    "low": "safe",
    "moderate": "moderate",
    "high": "dangerous",
    "critical": "critical",
}


@dataclass
class AuthDecision:
    """Result of one MCP auth check. ``denial`` is set when ``allowed`` is False."""

    allowed: bool
    denial: Optional[Dict[str, Any]] = None
    api_key: Any = None
    manager: Any = None


def _tool_level_from_rank(rank: str) -> Any:
    if not HAS_AUTH_MANAGER or not rank or rank == "none":
        return rank if rank not in (None, "", "none") else None
    mapping = {
        "safe": ToolLevel.SAFE,
        "moderate": ToolLevel.MODERATE,
        "dangerous": ToolLevel.DANGEROUS,
        "critical": ToolLevel.CRITICAL,
    }
    return mapping.get(rank)


def resolve_wrapper_auth_rank(tool_name: str, func: Any) -> str:
    """Highest of the decorator mark and the manifest ``auth_required`` risk."""
    from core.security.hitl import auth_level_of

    best = auth_level_of(func) or "none"
    try:
        from core.capability_manifest import get_capability

        cap = get_capability("tool", tool_name)
    except Exception:
        return best if best in _AUTH_RANK else "none"
    if cap.auth_required:
        cap_rank = _RISK_TO_RANK.get(str(cap.risk).lower(), "moderate")
        if _AUTH_RANK.get(cap_rank, 0) > _AUTH_RANK.get(best, 0):
            best = cap_rank
    return best if best in _AUTH_RANK else "none"


def evaluate_auth(
    tool_name: str,
    *,
    level: Any = None,
    params: Optional[Dict[str, Any]] = None,
) -> AuthDecision:
    """Return whether an MCP tool call may proceed. None-level still checks STRICT."""
    params = params or {}
    if _auth_config["mode"] == AuthMode.DISABLED:
        return AuthDecision(allowed=True)

    api_key_str = get_api_key_from_env()
    if not api_key_str:
        is_high_level = False
        if HAS_AUTH_MANAGER and level is not None:
            is_high_level = level in (ToolLevel.CRITICAL, ToolLevel.DANGEROUS)
        elif not HAS_AUTH_MANAGER and level is not None:
            is_high_level = True

        if is_high_level:
            logger.warning(
                "CRITICAL/DANGEROUS 工具 %s 需要授权，但未提供API Key",
                tool_name,
            )
            return AuthDecision(
                allowed=False,
                denial={
                    "success": False,
                    "error": (
                        "Authorization required for CRITICAL/DANGEROUS tools. "
                        "Set AUTOREDTEAM_API_KEY environment variable."
                    ),
                    "code": "AUTH_REQUIRED",
                },
            )

        if _auth_config["mode"] == AuthMode.STRICT:
            logger.warning("工具 %s 需要授权，但未提供API Key", tool_name)
            return AuthDecision(
                allowed=False,
                denial={
                    "success": False,
                    "error": (
                        "Authorization required. Set AUTOREDTEAM_API_KEY environment variable."
                    ),
                    "code": "AUTH_REQUIRED",
                },
            )
        logger.warning("工具 %s 未授权访问（宽松模式）", tool_name)
        return AuthDecision(allowed=True)

    auth_mgr = get_auth_manager()
    if not auth_mgr:
        logger.error("AuthManager不可用")
        if _auth_config["mode"] == AuthMode.STRICT:
            return AuthDecision(
                allowed=False,
                denial={
                    "success": False,
                    "error": "Authorization system unavailable",
                    "code": "AUTH_UNAVAILABLE",
                },
            )
        return AuthDecision(allowed=True)

    api_key = auth_mgr.verify_key(api_key_str)
    if not api_key:
        return AuthDecision(
            allowed=False,
            denial={
                "success": False,
                "error": "Invalid or expired API key",
                "code": "INVALID_KEY",
            },
        )

    if not auth_mgr.check_permission(api_key, tool_name):
        if _auth_config["audit_enabled"]:
            auth_mgr.audit(
                api_key.key_id,
                tool_name,
                _sanitize_params(params),
                success=False,
                error="Permission denied",
            )
        return AuthDecision(
            allowed=False,
            denial={
                "success": False,
                "error": f"Insufficient permissions for tool: {tool_name}",
                "code": "PERMISSION_DENIED",
            },
        )

    return AuthDecision(allowed=True, api_key=api_key, manager=auth_mgr)


def evaluate_wrapper_auth(
    tool_name: str,
    func: Any,
    params: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Registration-layer check. Skip tools with no decorator mark and no manifest auth."""
    rank = resolve_wrapper_auth_rank(tool_name, func)
    if rank in ("none", ""):
        return None
    decision = evaluate_auth(tool_name, level=_tool_level_from_rank(rank), params=params)
    if decision.allowed:
        return None
    return decision.denial


def require_auth(
    tool_name: Optional[str] = None,
    level: Optional["ToolLevel"] = None,
    permissions: Optional[List["Permission"]] = None,
):
    """
    MCP工具授权装饰器

    用于检查API Key权限和工具访问级别

    Args:
        tool_name: 工具名称（默认使用函数名）
        level: 工具危险等级（覆盖AuthManager中的默认值）
        permissions: 所需权限列表

    Usage:
        @mcp.tool()
        @require_auth(level=ToolLevel.CRITICAL)
        async def lateral_smb_exec(target: str, ...) -> Dict:
            ...
    """

    def decorator(func: Callable):
        def _audit(
            decision: AuthDecision,
            actual_tool_name: str,
            kwargs: Dict[str, Any],
            success: bool,
            error: Optional[str] = None,
        ) -> None:
            if (
                not _auth_config["audit_enabled"]
                or decision.manager is None
                or decision.api_key is None
            ):
                return
            decision.manager.audit(
                decision.api_key.key_id,
                actual_tool_name,
                _sanitize_params(kwargs),
                success=success,
                error=error,
            )

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Dict[str, Any]:
            actual_tool_name = tool_name or func.__name__
            decision = evaluate_auth(actual_tool_name, level=level, params=kwargs)
            if not decision.allowed:
                return cast(Dict[str, Any], decision.denial)
            try:
                result = await func(*args, **kwargs)
                _audit(decision, actual_tool_name, kwargs, True)
                return cast(Dict[str, Any], result)
            except Exception as exc:
                _audit(decision, actual_tool_name, kwargs, False, str(exc))
                raise

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Dict[str, Any]:
            actual_tool_name = tool_name or func.__name__
            decision = evaluate_auth(actual_tool_name, level=level, params=kwargs)
            if not decision.allowed:
                return cast(Dict[str, Any], decision.denial)
            return cast(Dict[str, Any], func(*args, **kwargs))

        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


def _sanitize_params(params: Dict) -> Dict:
    """
    清理参数中的敏感信息用于审计日志

    Args:
        params: 原始参数

    Returns:
        清理后的参数
    """
    sensitive_keys = {
        "password",
        "secret",
        "key",
        "token",
        "credential",
        "api_key",
        "auth",
        "ntlm_hash",
        "ssh_key",
    }

    sanitized = {}
    for k, v in params.items():
        if any(s in k.lower() for s in sensitive_keys):
            sanitized[k] = "***REDACTED***"
        elif isinstance(v, str) and len(v) > 200:
            sanitized[k] = v[:200] + "...[TRUNCATED]"
        else:
            sanitized[k] = v

    return sanitized


# 便捷装饰器：不同安全级别
def _mark_auth_level(func: Callable, level: str) -> Callable:
    """Record the decorator rank so HITL can see it after functools.wraps."""
    func.__autort_auth_level__ = level  # type: ignore[attr-defined]
    return func


def require_safe_auth(func):
    """安全工具授权（信息收集）"""
    wrapped = require_auth(level=ToolLevel.SAFE if HAS_AUTH_MANAGER else None)(func)
    return _mark_auth_level(wrapped, "safe")


def require_moderate_auth(func):
    """中等风险工具授权（漏洞扫描）"""
    wrapped = require_auth(level=ToolLevel.MODERATE if HAS_AUTH_MANAGER else None)(func)
    return _mark_auth_level(wrapped, "moderate")


def require_dangerous_auth(func):
    """高风险工具授权（漏洞利用）"""
    wrapped = require_auth(level=ToolLevel.DANGEROUS if HAS_AUTH_MANAGER else None)(func)
    return _mark_auth_level(wrapped, "dangerous")


def require_critical_auth(func):
    """极高风险工具授权（后渗透）"""
    wrapped = require_auth(level=ToolLevel.CRITICAL if HAS_AUTH_MANAGER else None)(func)
    return _mark_auth_level(wrapped, "critical")


# 初始化时检查环境变量设置的授权模式
_env_mode = os.getenv("AUTOREDTEAM_AUTH_MODE", "strict").lower()
if _env_mode == "strict":
    _auth_config["mode"] = AuthMode.STRICT
elif _env_mode == "disabled":
    # 与 set_auth_mode() 保持一致：仅测试环境允许 DISABLED
    _is_test = os.getenv("AUTOREDTEAM_ENV") == "test" or os.getenv("PYTEST_CURRENT_TEST")
    if _is_test:
        _auth_config["mode"] = AuthMode.DISABLED
    else:
        logger.warning(
            "拒绝初始化DISABLED模式：仅允许在测试环境中禁用授权 "
            "(需设置 AUTOREDTEAM_ENV=test 或 PYTEST_CURRENT_TEST)"
        )
        _auth_config["mode"] = AuthMode.STRICT
elif _env_mode == "permissive":
    _auth_config["mode"] = AuthMode.PERMISSIVE
else:
    logger.warning("未知授权模式 '%s'，回退到 STRICT", _env_mode)
    _auth_config["mode"] = AuthMode.STRICT

logger.info("MCP授权中间件初始化完成，模式: %s", _auth_config["mode"].value)
