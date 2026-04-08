"""
core.sandbox 单元测试

覆盖:
- SandboxConfig 默认值
- CommandResult dataclass
- get_executor 工厂函数 (enabled=False → LocalExecutor)
- LocalExecutor 命令执行
- DockerExecutor (mock docker SDK)
"""

from __future__ import annotations

import subprocess
from dataclasses import asdict
from unittest.mock import MagicMock, patch

import pytest

from core.sandbox.config import CommandResult, SandboxConfig
from core.sandbox.fallback import LocalExecutor, get_executor


# ==================== SandboxConfig 测试 ====================


class TestSandboxConfig:
    """测试沙箱配置模型"""

    def test_defaults(self):
        """验证所有默认值"""
        cfg = SandboxConfig()
        assert cfg.enabled is False
        assert cfg.image == "python:3.12-slim"
        assert cfg.network_mode == "host"
        assert cfg.timeout == 300
        assert cfg.memory_limit == "512m"
        assert cfg.cpu_limit == 1.0
        assert cfg.auto_remove is True
        assert cfg.volumes == []

    def test_custom_values(self):
        """验证自定义值"""
        cfg = SandboxConfig(
            enabled=True,
            image="kalilinux/kali-rolling",
            network_mode="bridge",
            timeout=600,
            memory_limit="1g",
            cpu_limit=2.0,
            auto_remove=False,
            volumes=["/data:/data:ro"],
        )
        assert cfg.enabled is True
        assert cfg.image == "kalilinux/kali-rolling"
        assert cfg.network_mode == "bridge"
        assert cfg.timeout == 600
        assert cfg.memory_limit == "1g"
        assert cfg.cpu_limit == 2.0
        assert cfg.auto_remove is False
        assert cfg.volumes == ["/data:/data:ro"]

    def test_serialization(self):
        """验证 Pydantic 序列化"""
        cfg = SandboxConfig(enabled=True)
        data = cfg.model_dump()
        assert isinstance(data, dict)
        assert data["enabled"] is True
        assert data["image"] == "python:3.12-slim"


# ==================== CommandResult 测试 ====================


class TestCommandResult:
    """测试命令执行结果 dataclass"""

    def test_defaults(self):
        """验证默认值"""
        result = CommandResult()
        assert result.stdout == ""
        assert result.stderr == ""
        assert result.exit_code == 0
        assert result.duration == 0.0

    def test_custom_values(self):
        """验证自定义值"""
        result = CommandResult(
            stdout="output",
            stderr="error",
            exit_code=1,
            duration=2.5,
        )
        assert result.stdout == "output"
        assert result.stderr == "error"
        assert result.exit_code == 1
        assert result.duration == 2.5

    def test_asdict(self):
        """验证 dataclass 字典转换"""
        result = CommandResult(stdout="hello", exit_code=0, duration=1.0)
        d = asdict(result)
        assert d["stdout"] == "hello"
        assert d["exit_code"] == 0


# ==================== get_executor 工厂测试 ====================


class TestGetExecutor:
    """测试执行器工厂函数"""

    def test_returns_local_when_disabled(self):
        """enabled=False 时返回 LocalExecutor"""
        cfg = SandboxConfig(enabled=False)
        executor = get_executor(cfg)
        assert isinstance(executor, LocalExecutor)

    def test_returns_local_when_docker_unavailable(self):
        """enabled=True 但 Docker 不可用时回退到 LocalExecutor"""
        cfg = SandboxConfig(enabled=True)
        with patch(
            "core.sandbox.executor.DockerExecutor.__init__",
            side_effect=RuntimeError("docker not found"),
        ):
            executor = get_executor(cfg)
            assert isinstance(executor, LocalExecutor)


# ==================== LocalExecutor 测试 ====================


class TestLocalExecutor:
    """测试本地执行器"""

    def test_run_command_success(self):
        """测试成功执行命令"""
        cfg = SandboxConfig()
        executor = LocalExecutor(cfg)
        result = executor.run_command("echo hello")
        assert result.exit_code == 0
        assert "hello" in result.stdout
        assert result.duration > 0

    def test_run_command_failure(self):
        """测试命令执行失败"""
        cfg = SandboxConfig()
        executor = LocalExecutor(cfg)
        result = executor.run_command("exit 42")
        assert result.exit_code == 42

    def test_run_command_timeout(self):
        """测试命令超时"""
        cfg = SandboxConfig(timeout=1)
        executor = LocalExecutor(cfg)
        # 用 ping 模拟长时间运行的命令（跨平台）
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 1)):
            result = executor.run_command("sleep 999", timeout=1)
            assert result.exit_code == -1
            assert "超时" in result.stderr

    def test_run_python(self):
        """测试执行 Python 脚本"""
        cfg = SandboxConfig()
        executor = LocalExecutor(cfg)
        result = executor.run_python("print(1+1)")
        assert result.exit_code == 0
        assert "2" in result.stdout

    def test_run_tool(self):
        """测试执行工具"""
        cfg = SandboxConfig()
        executor = LocalExecutor(cfg)
        result = executor.run_tool("echo", args=["tool_test"])
        assert result.exit_code == 0
        assert "tool_test" in result.stdout


# ==================== DockerExecutor Mock 测试 ====================


class TestDockerExecutorMocked:
    """通过 mock docker SDK 测试 DockerExecutor"""

    def _make_mock_docker(self):
        """创建 mock docker 模块和客户端"""
        mock_client = MagicMock()
        mock_client.ping.return_value = True

        # mock 镜像检查
        mock_client.images.get.return_value = MagicMock()

        # mock 容器执行
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.side_effect = [
            b"command output",  # stdout
            b"",  # stderr
        ]
        mock_client.containers.run.return_value = mock_container
        return mock_client, mock_container

    def test_run_command(self):
        """测试 Docker 容器中执行命令"""
        mock_client, mock_container = self._make_mock_docker()

        with patch("core.sandbox.executor.DOCKER_AVAILABLE", True), \
             patch("core.sandbox.executor.docker") as mock_docker_mod:
            mock_docker_mod.from_env.return_value = mock_client

            from core.sandbox.executor import DockerExecutor

            cfg = SandboxConfig(enabled=True)
            executor = DockerExecutor(cfg)
            result = executor.run_command("nmap -sV target.com")

            assert result.exit_code == 0
            assert result.stdout == "command output"
            mock_client.containers.run.assert_called_once()
            mock_container.remove.assert_called_once_with(force=True)

    def test_run_command_container_error(self):
        """测试容器执行异常"""
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_client.images.get.return_value = MagicMock()
        mock_client.containers.run.side_effect = Exception("container failed")

        with patch("core.sandbox.executor.DOCKER_AVAILABLE", True), \
             patch("core.sandbox.executor.docker") as mock_docker_mod:
            mock_docker_mod.from_env.return_value = mock_client

            from core.sandbox.executor import DockerExecutor

            cfg = SandboxConfig(enabled=True)
            executor = DockerExecutor(cfg)
            result = executor.run_command("bad_command")

            assert result.exit_code == -1
            assert "container failed" in result.stderr

    def test_run_tool_with_args(self):
        """测试执行安全工具"""
        mock_client, mock_container = self._make_mock_docker()
        # 重置 logs side_effect 以便多次调用
        mock_container.logs.side_effect = [
            b"scan results",
            b"",
        ]

        with patch("core.sandbox.executor.DOCKER_AVAILABLE", True), \
             patch("core.sandbox.executor.docker") as mock_docker_mod:
            mock_docker_mod.from_env.return_value = mock_client

            from core.sandbox.executor import DockerExecutor

            cfg = SandboxConfig(enabled=True)
            executor = DockerExecutor(cfg)
            result = executor.run_tool("nuclei", args=["-u", "https://target.com"])

            assert result.exit_code == 0
            assert result.stdout == "scan results"


# ==================== AutoRTConfig 集成测试 ====================


class TestAutoRTConfigSandbox:
    """测试 SandboxConfig 已正确集成到 AutoRTConfig"""

    def test_sandbox_in_config(self):
        """验证 AutoRTConfig 包含 sandbox 字段"""
        from core.config.models import AutoRTConfig

        cfg = AutoRTConfig()
        assert hasattr(cfg, "sandbox")
        assert isinstance(cfg.sandbox, SandboxConfig)
        assert cfg.sandbox.enabled is False
