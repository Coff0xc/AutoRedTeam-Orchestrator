"""
本地执行器 (回退方案) 与执行器工厂

当 Docker 不可用或 SandboxConfig.enabled=False 时，使用 LocalExecutor 直接在本地执行。
get_executor() 工厂函数根据配置返回正确的执行器实例。
"""

from __future__ import annotations

import logging
import subprocess
import sys
import time
from typing import List, Optional, Union

from core.sandbox.config import CommandResult, SandboxConfig

logger = logging.getLogger(__name__)


class LocalExecutor:
    """本地命令执行器

    与 DockerExecutor 相同接口，直接在宿主机上执行命令。
    用于未启用沙箱或 Docker 不可用时的回退方案。

    Args:
        config: 沙箱配置（仅使用 timeout 字段）
    """

    def __init__(self, config: SandboxConfig) -> None:
        self._config = config
        logger.info("使用本地执行器 (沙箱未启用)")

    def run_command(self, cmd: str, timeout: Optional[int] = None) -> CommandResult:
        """在本地执行 shell 命令

        Args:
            cmd: shell 命令字符串
            timeout: 超时秒数

        Returns:
            CommandResult
        """
        effective_timeout = timeout if timeout is not None else self._config.timeout
        logger.info("本地执行命令: %s", cmd[:120])
        return self._execute(cmd, timeout=effective_timeout)

    def run_python(self, script: str, timeout: Optional[int] = None) -> CommandResult:
        """在本地执行 Python 脚本

        Args:
            script: Python 脚本内容
            timeout: 超时秒数

        Returns:
            CommandResult
        """
        effective_timeout = timeout if timeout is not None else self._config.timeout
        # 使用当前 Python 解释器路径，保证跨平台兼容
        escaped = script.replace("'", "'\\''")
        cmd = '%s -c "%s"' % (sys.executable, script.replace('"', '\\"'))
        logger.info("本地执行 Python 脚本, 长度=%d", len(script))
        return self._execute(cmd, timeout=effective_timeout)

    def run_tool(
        self,
        tool_name: str,
        args: Optional[List[str]] = None,
        timeout: Optional[int] = None,
    ) -> CommandResult:
        """在本地执行安全工具

        Args:
            tool_name: 工具名称
            args: 命令行参数列表
            timeout: 超时秒数

        Returns:
            CommandResult
        """
        effective_timeout = timeout if timeout is not None else self._config.timeout
        parts = [tool_name]
        if args:
            parts.extend(args)
        cmd = " ".join(parts)
        logger.info("本地执行工具: %s, 参数: %s", tool_name, args)
        return self._execute(cmd, timeout=effective_timeout)

    @staticmethod
    def _execute(cmd: str, timeout: int) -> CommandResult:
        """执行命令的内部方法

        Args:
            cmd: shell 命令字符串
            timeout: 超时秒数

        Returns:
            CommandResult
        """
        start_time = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            duration = time.monotonic() - start_time
            return CommandResult(
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
                duration=duration,
            )
        except subprocess.TimeoutExpired:
            duration = time.monotonic() - start_time
            logger.warning("命令执行超时 (%ds): %s", timeout, cmd[:80])
            return CommandResult(
                stdout="",
                stderr="命令执行超时 (%d 秒)" % timeout,
                exit_code=-1,
                duration=duration,
            )
        except Exception as e:
            duration = time.monotonic() - start_time
            logger.error("命令执行失败: %s", e)
            return CommandResult(
                stdout="",
                stderr=str(e),
                exit_code=-1,
                duration=duration,
            )


def get_executor(config: SandboxConfig) -> Union["DockerExecutor", LocalExecutor]:
    """执行器工厂函数

    根据配置返回正确的执行器：
    - enabled=False → LocalExecutor
    - enabled=True + docker 可用 → DockerExecutor
    - enabled=True + docker 不可用 → 打印警告，回退到 LocalExecutor

    Args:
        config: 沙箱配置

    Returns:
        DockerExecutor 或 LocalExecutor 实例
    """
    if not config.enabled:
        logger.debug("沙箱未启用，使用本地执行器")
        return LocalExecutor(config)

    # 沙箱已启用，尝试创建 Docker 执行器
    try:
        from core.sandbox.executor import DockerExecutor

        return DockerExecutor(config)
    except RuntimeError as e:
        logger.warning("Docker 沙箱不可用，回退到本地执行器: %s", e)
        return LocalExecutor(config)
    except Exception as e:
        logger.warning("Docker 沙箱初始化失败，回退到本地执行器: %s", e)
        return LocalExecutor(config)
