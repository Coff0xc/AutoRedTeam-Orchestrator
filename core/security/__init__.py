#!/usr/bin/env python3
"""
安全加固模块初始化文件

使用 __getattr__ 实现懒加载，避免 import core.security 时
触发所有子模块（auth_manager, secrets_manager, safe_executor 等）的 eager load。
"""

# 轻量导入: 验证器（无重依赖，handlers 需要）
from utils.validators import (
    InputValidator,
    ValidationError,
    require_auth,
    safe_path_join,
    validate_params,
    validate_target,
)

# 轻量导入: MCP auth 装饰器（handlers 的 @require_*_auth 直接依赖）
from .mcp_auth_middleware import (
    AuthMode,
    get_api_key_from_env,
)
from .mcp_auth_middleware import require_auth as mcp_require_auth
from .mcp_auth_middleware import (
    require_critical_auth,
    require_dangerous_auth,
    require_moderate_auth,
    require_safe_auth,
    set_auth_mode,
)

__all__ = [
    # 输入验证
    "InputValidator",
    "ValidationError",
    "validate_params",
    "require_auth",
    "safe_path_join",
    "validate_target",
    # 命令执行 (懒加载)
    "SafeExecutor",
    "SandboxExecutor",
    "SecurityError",
    "ExecutionPolicy",
    "CommandWhitelist",
    "get_safe_executor",
    "safe_execute",
    # 认证授权 (懒加载)
    "AuthManager",
    "APIKey",
    "ToolLevel",
    "Permission",
    "get_auth_manager",
    # 敏感信息管理 (懒加载)
    "SecretsManager",
    "ConfigEncryptor",
    "EnvironmentManager",
    "get_secrets_manager",
    "get_secret",
    "set_secret",
    # MCP授权中间件 (已 eager load)
    "mcp_require_auth",
    "require_safe_auth",
    "require_moderate_auth",
    "require_dangerous_auth",
    "require_critical_auth",
    "set_auth_mode",
    "AuthMode",
    "get_api_key_from_env",
]

# 懒加载映射: 属性名 → (模块路径, 属性名)
_LAZY_IMPORTS = {
    # safe_executor
    "SafeExecutor": (".safe_executor", "SafeExecutor"),
    "SandboxExecutor": (".safe_executor", "SandboxExecutor"),
    "SecurityError": (".safe_executor", "SecurityError"),
    "ExecutionPolicy": (".safe_executor", "ExecutionPolicy"),
    "CommandWhitelist": (".safe_executor", "CommandWhitelist"),
    "get_safe_executor": (".safe_executor", "get_safe_executor"),
    "safe_execute": (".safe_executor", "safe_execute"),
    # auth_manager
    "AuthManager": (".auth_manager", "AuthManager"),
    "APIKey": (".auth_manager", "APIKey"),
    "ToolLevel": (".auth_manager", "ToolLevel"),
    "Permission": (".auth_manager", "Permission"),
    "get_auth_manager": (".auth_manager", "get_auth_manager"),
    # secrets_manager
    "SecretsManager": (".secrets_manager", "SecretsManager"),
    "ConfigEncryptor": (".secrets_manager", "ConfigEncryptor"),
    "EnvironmentManager": (".secrets_manager", "EnvironmentManager"),
    "get_secrets_manager": (".secrets_manager", "get_secrets_manager"),
    "get_secret": (".secrets_manager", "get_secret"),
    "set_secret": (".secrets_manager", "set_secret"),
}


def __getattr__(name: str):
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        import importlib

        module = importlib.import_module(module_path, __package__)
        value = getattr(module, attr_name)
        # 缓存到模块级别，下次直接访问
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
