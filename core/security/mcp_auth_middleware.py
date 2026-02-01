#!/usr/bin/env python3
"""
MCP 授权中间件 - MCP Tools Authorization Middleware

为MCP工具提供授权检查装饰器，集成AuthManager
仅用于授权渗透测试和安全研究
"""

import functools
import logging
import os
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

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
    "mode": AuthMode.PERMISSIVE,  # 默认宽松模式
    "manager": None,
    "audit_enabled": True,
}


def get_auth_manager() -> Optional["AuthManager"]:
    """获取全局AuthManager实例"""
    if _auth_config["manager"] is None and HAS_AUTH_MANAGER:
        try:
            _auth_config["manager"] = AuthManager()
        except Exception as e:
            logger.error(f"初始化AuthManager失败: {e}")
    return _auth_config["manager"]


def set_auth_mode(mode: AuthMode):
    """设置授权模式"""
    _auth_config["mode"] = mode
    logger.info(f"授权模式设置为: {mode.value}")


def set_audit_enabled(enabled: bool):
    """设置是否启用审计"""
    _auth_config["audit_enabled"] = enabled


def get_api_key_from_env() -> Optional[str]:
    """从环境变量获取API Key"""
    return os.getenv("AUTOREDTEAM_API_KEY") or os.getenv("MCP_API_KEY")


def require_auth(
    tool_name: str = None, level: "ToolLevel" = None, permissions: List["Permission"] = None
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
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Dict[str, Any]:
            actual_tool_name = tool_name or func.__name__

            # 检查授权模式
            if _auth_config["mode"] == AuthMode.DISABLED:
                return await func(*args, **kwargs)

            # 获取API Key
            api_key_str = get_api_key_from_env()

            # 无Key情况处理
            if not api_key_str:
                if _auth_config["mode"] == AuthMode.STRICT:
                    logger.warning(f"工具 {actual_tool_name} 需要授权，但未提供API Key")
                    return {
                        "success": False,
                        "error": "Authorization required. Set AUTOREDTEAM_API_KEY environment variable.",
                        "code": "AUTH_REQUIRED",
                    }
                else:
                    # 宽松模式：允许但记录警告
                    logger.warning(f"工具 {actual_tool_name} 未授权访问（宽松模式）")
                    return await func(*args, **kwargs)

            # 验证API Key
            auth_mgr = get_auth_manager()
            if not auth_mgr:
                logger.error("AuthManager不可用")
                if _auth_config["mode"] == AuthMode.STRICT:
                    return {
                        "success": False,
                        "error": "Authorization system unavailable",
                        "code": "AUTH_UNAVAILABLE",
                    }
                return await func(*args, **kwargs)

            # 验证Key
            api_key = auth_mgr.verify_key(api_key_str)
            if not api_key:
                return {
                    "success": False,
                    "error": "Invalid or expired API key",
                    "code": "INVALID_KEY",
                }

            # 检查权限
            if not auth_mgr.check_permission(api_key, actual_tool_name):
                # 记录审计日志
                if _auth_config["audit_enabled"]:
                    auth_mgr.audit(
                        api_key.key_id,
                        actual_tool_name,
                        _sanitize_params(kwargs),
                        success=False,
                        error="Permission denied",
                    )
                return {
                    "success": False,
                    "error": f"Insufficient permissions for tool: {actual_tool_name}",
                    "code": "PERMISSION_DENIED",
                }

            # 执行工具
            try:
                result = await func(*args, **kwargs)

                # 记录成功审计
                if _auth_config["audit_enabled"]:
                    auth_mgr.audit(
                        api_key.key_id, actual_tool_name, _sanitize_params(kwargs), success=True
                    )

                return result
            except Exception as e:
                # 记录失败审计
                if _auth_config["audit_enabled"]:
                    auth_mgr.audit(
                        api_key.key_id,
                        actual_tool_name,
                        _sanitize_params(kwargs),
                        success=False,
                        error=str(e),
                    )
                raise

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Dict[str, Any]:
            actual_tool_name = tool_name or func.__name__

            # 检查授权模式
            if _auth_config["mode"] == AuthMode.DISABLED:
                return func(*args, **kwargs)

            # 获取API Key
            api_key_str = get_api_key_from_env()

            if not api_key_str:
                if _auth_config["mode"] == AuthMode.STRICT:
                    return {
                        "success": False,
                        "error": "Authorization required",
                        "code": "AUTH_REQUIRED",
                    }
                return func(*args, **kwargs)

            auth_mgr = get_auth_manager()
            if not auth_mgr:
                if _auth_config["mode"] == AuthMode.STRICT:
                    return {
                        "success": False,
                        "error": "Authorization system unavailable",
                        "code": "AUTH_UNAVAILABLE",
                    }
                return func(*args, **kwargs)

            api_key = auth_mgr.verify_key(api_key_str)
            if not api_key:
                return {
                    "success": False,
                    "error": "Invalid or expired API key",
                    "code": "INVALID_KEY",
                }

            if not auth_mgr.check_permission(api_key, actual_tool_name):
                return {
                    "success": False,
                    "error": f"Insufficient permissions for tool: {actual_tool_name}",
                    "code": "PERMISSION_DENIED",
                }

            return func(*args, **kwargs)

        # 根据函数类型返回对应的wrapper
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
def require_safe_auth(func):
    """安全工具授权（信息收集）"""
    return require_auth(level=ToolLevel.SAFE if HAS_AUTH_MANAGER else None)(func)


def require_moderate_auth(func):
    """中等风险工具授权（漏洞扫描）"""
    return require_auth(level=ToolLevel.MODERATE if HAS_AUTH_MANAGER else None)(func)


def require_dangerous_auth(func):
    """高风险工具授权（漏洞利用）"""
    return require_auth(level=ToolLevel.DANGEROUS if HAS_AUTH_MANAGER else None)(func)


def require_critical_auth(func):
    """极高风险工具授权（后渗透）"""
    return require_auth(level=ToolLevel.CRITICAL if HAS_AUTH_MANAGER else None)(func)


# 初始化时检查环境变量设置的授权模式
_env_mode = os.getenv("AUTOREDTEAM_AUTH_MODE", "permissive").lower()
if _env_mode == "strict":
    _auth_config["mode"] = AuthMode.STRICT
elif _env_mode == "disabled":
    _auth_config["mode"] = AuthMode.DISABLED
else:
    _auth_config["mode"] = AuthMode.PERMISSIVE

logger.info(f"MCP授权中间件初始化完成，模式: {_auth_config['mode'].value}")
