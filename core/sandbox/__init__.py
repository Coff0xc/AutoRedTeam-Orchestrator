"""
Docker 沙箱执行器

提供可选的容器隔离环境，用于执行危险操作（扫描、exploit 等）。
docker SDK 为可选依赖，未安装时自动回退到本地执行。

使用示例:
    from core.sandbox import SandboxConfig, get_executor

    config = SandboxConfig(enabled=True)
    executor = get_executor(config)
    result = executor.run_command("nmap -sV target.com")
"""

from core.sandbox.config import CommandResult, SandboxConfig
from core.sandbox.executor import DockerExecutor
from core.sandbox.fallback import LocalExecutor, get_executor

__all__ = [
    "SandboxConfig",
    "CommandResult",
    "DockerExecutor",
    "LocalExecutor",
    "get_executor",
]
