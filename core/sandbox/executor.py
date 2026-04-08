"""
Docker 沙箱执行器

封装 Docker SDK，在容器中隔离执行命令、Python 脚本和安全工具。
docker SDK 为可选依赖，未安装时由 fallback 模块处理。
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, List, Optional

from core.sandbox.config import CommandResult, SandboxConfig

if TYPE_CHECKING:
    import docker  # type: ignore[import-untyped]

# 尝试导入 docker SDK（可选依赖）
try:
    import docker  # type: ignore[import-untyped]
    from docker.errors import (  # type: ignore[import-untyped]
        APIError,
        ContainerError,
        DockerException,
        ImageNotFound,
    )

    DOCKER_AVAILABLE = True
except ImportError:
    docker = None  # type: ignore[assignment]
    DOCKER_AVAILABLE = False

logger = logging.getLogger(__name__)


class DockerExecutor:
    """Docker 容器沙箱执行器

    在 Docker 容器中隔离执行命令，提供资源限制和自动清理。

    Args:
        config: 沙箱配置
    """

    def __init__(self, config: SandboxConfig) -> None:
        self._config = config
        self._client: Optional[docker.DockerClient] = None  # type: ignore[name-defined]
        self._ensure_client()

    def _ensure_client(self) -> None:
        """初始化 Docker 客户端连接"""
        if not DOCKER_AVAILABLE:
            raise RuntimeError(
                "docker SDK 未安装，请执行: pip install docker"
            )
        try:
            self._client = docker.from_env()  # type: ignore[union-attr]
            self._client.ping()  # type: ignore[union-attr]
            logger.info("Docker 客户端连接成功")
        except Exception as e:
            raise RuntimeError("无法连接 Docker 守护进程: %s" % e) from e

    def _pull_image_if_needed(self) -> None:
        """如果本地不存在镜像则拉取"""
        try:
            self._client.images.get(self._config.image)  # type: ignore[union-attr]
            logger.debug("镜像已存在: %s", self._config.image)
        except Exception:
            logger.info("拉取镜像: %s", self._config.image)
            try:
                self._client.images.pull(self._config.image)  # type: ignore[union-attr]
            except Exception as e:
                raise RuntimeError("镜像拉取失败 %s: %s" % (self._config.image, e)) from e

    def _build_container_kwargs(self, command: str) -> dict:
        """构建 docker 容器运行参数

        Args:
            command: 要在容器中执行的命令

        Returns:
            容器运行参数字典
        """
        # 计算 CPU 配额: cpu_limit * 100000 (默认 period)
        nano_cpus = int(self._config.cpu_limit * 1e9)

        kwargs: dict = {
            "image": self._config.image,
            "command": ["sh", "-c", command],
            "detach": True,
            "network_mode": self._config.network_mode,
            "mem_limit": self._config.memory_limit,
            "nano_cpus": nano_cpus,
            "auto_remove": False,  # 先获取日志再手动删除
        }

        # 额外挂载卷
        if self._config.volumes:
            binds = {}
            for vol in self._config.volumes:
                parts = vol.split(":")
                if len(parts) >= 2:
                    binds[parts[0]] = {"bind": parts[1], "mode": parts[2] if len(parts) > 2 else "rw"}
            if binds:
                kwargs["volumes"] = binds

        return kwargs

    def _run_in_container(self, command: str, timeout: Optional[int] = None) -> CommandResult:
        """在容器中执行命令的核心方法

        Args:
            command: shell 命令字符串
            timeout: 超时秒数，None 则使用配置默认值

        Returns:
            CommandResult 包含 stdout/stderr/exit_code/duration
        """
        effective_timeout = timeout if timeout is not None else self._config.timeout
        self._pull_image_if_needed()

        container = None
        start_time = time.monotonic()

        try:
            kwargs = self._build_container_kwargs(command)
            container = self._client.containers.run(**kwargs)  # type: ignore[union-attr]
            logger.info("容器已创建: %s, 执行命令: %s", container.short_id, command[:80])

            # 等待容器执行完成
            result = container.wait(timeout=effective_timeout)
            exit_code = result.get("StatusCode", -1)

            # 获取输出
            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
            duration = time.monotonic() - start_time

            logger.info(
                "容器 %s 执行完成, exit_code=%d, 耗时=%.2fs",
                container.short_id,
                exit_code,
                duration,
            )

            return CommandResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration=duration,
            )

        except Exception as e:
            duration = time.monotonic() - start_time
            logger.error("容器执行异常: %s", e)

            # 尝试获取已有输出
            stdout = ""
            stderr = str(e)
            if container is not None:
                try:
                    stdout = container.logs(stdout=True, stderr=False).decode(
                        "utf-8", errors="replace"
                    )
                    stderr = container.logs(stdout=False, stderr=True).decode(
                        "utf-8", errors="replace"
                    )
                except Exception:
                    pass

            return CommandResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=-1,
                duration=duration,
            )

        finally:
            # 清理容器
            if container is not None:
                try:
                    container.remove(force=True)
                    logger.debug("容器 %s 已清理", container.short_id)
                except Exception:
                    pass

    def run_command(self, cmd: str, timeout: Optional[int] = None) -> CommandResult:
        """在容器中执行 shell 命令

        Args:
            cmd: shell 命令字符串
            timeout: 超时秒数

        Returns:
            CommandResult
        """
        logger.info("沙箱执行命令: %s", cmd[:120])
        return self._run_in_container(cmd, timeout=timeout)

    def run_python(self, script: str, timeout: Optional[int] = None) -> CommandResult:
        """在容器中执行 Python 脚本

        Args:
            script: Python 脚本内容
            timeout: 超时秒数

        Returns:
            CommandResult
        """
        # 用 heredoc 方式传递脚本，避免引号转义问题
        escaped = script.replace("'", "'\\''")
        cmd = "python3 -c '%s'" % escaped
        logger.info("沙箱执行 Python 脚本, 长度=%d", len(script))
        return self._run_in_container(cmd, timeout=timeout)

    def run_tool(
        self,
        tool_name: str,
        args: Optional[List[str]] = None,
        timeout: Optional[int] = None,
    ) -> CommandResult:
        """在容器中执行安全工具

        Args:
            tool_name: 工具名称 (如 nmap, sqlmap, nuclei)
            args: 命令行参数列表
            timeout: 超时秒数

        Returns:
            CommandResult
        """
        parts = [tool_name]
        if args:
            parts.extend(args)
        cmd = " ".join(parts)
        logger.info("沙箱执行工具: %s, 参数: %s", tool_name, args)
        return self._run_in_container(cmd, timeout=timeout)
