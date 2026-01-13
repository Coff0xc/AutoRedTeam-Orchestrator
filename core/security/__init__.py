#!/usr/bin/env python3
"""
安全加固模块初始化文件
"""

from .input_validator import (
    InputValidator,
    ValidationError,
    validate_params,
    require_auth,
    safe_path_join,
    validate_target
)

from .safe_executor import (
    SafeExecutor,
    SandboxExecutor,
    SecurityError,
    ExecutionPolicy,
    CommandWhitelist,
    get_safe_executor,
    safe_execute
)

from .auth_manager import (
    AuthManager,
    APIKey,
    ToolLevel,
    Permission,
    get_auth_manager
)

from .secrets_manager import (
    SecretsManager,
    ConfigEncryptor,
    EnvironmentManager,
    get_secrets_manager,
    get_secret,
    set_secret
)

__all__ = [
    # 输入验证
    "InputValidator",
    "ValidationError",
    "validate_params",
    "require_auth",
    "safe_path_join",
    "validate_target",

    # 命令执行
    "SafeExecutor",
    "SandboxExecutor",
    "SecurityError",
    "ExecutionPolicy",
    "CommandWhitelist",
    "get_safe_executor",
    "safe_execute",

    # 认证授权
    "AuthManager",
    "APIKey",
    "ToolLevel",
    "Permission",
    "get_auth_manager",

    # 敏感信息管理
    "SecretsManager",
    "ConfigEncryptor",
    "EnvironmentManager",
    "get_secrets_manager",
    "get_secret",
    "set_secret",
]
