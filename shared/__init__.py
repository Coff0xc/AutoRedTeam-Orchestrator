"""
共享模块 - 提供跨模块复用的公共组件

包含:
- tool_result: 统一工具返回格式
- subprocess_runner: 统一子进程执行
- validators: 统一输入验证
"""

from core.result import ToolResult

from .subprocess_runner import SubprocessRunner, get_subprocess_runner
from .validators import (
    sanitize_command_arg,
    validate_domain,
    validate_ip,
    validate_port,
    validate_url,
)

__all__ = [
    "ToolResult",
    "SubprocessRunner",
    "get_subprocess_runner",
    "validate_domain",
    "validate_ip",
    "validate_url",
    "validate_port",
    "sanitize_command_arg",
]
