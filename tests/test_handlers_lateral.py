#!/usr/bin/env python3
"""
横向移动工具处理器单元测试
测试 handlers/lateral_handlers.py 中的 9 个工具注册和执行
"""

from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from core.security.mcp_auth_middleware import AuthMode

# ==================== 辅助函数 ====================


def _make_mcp_and_register():
    """创建 mock MCP 并注册 Lateral 工具，返回 (registered_tools, mock_counter, mock_logger)

    通过 patch _wrap_tool_func 为 identity，使注册的工具直接返回 handler 原始 dict。
    同时 mock auth 装饰器为透传，避免 auth 检查阻断测试。
    """
    mock_mcp = MagicMock()
    mock_counter = MagicMock()
    mock_logger = MagicMock()

    registered_tools: Dict[str, Any] = {}

    def capture_tool():
        def decorator(func):
            registered_tools[func.__name__] = func
            return func

        return decorator

    mock_mcp.tool = capture_tool

    def passthrough_decorator(func):
        return func

    with (
        patch("utils.mcp_tooling._wrap_tool_func", side_effect=lambda f: f),
        patch("core.security.require_critical_auth", side_effect=passthrough_decorator),
        patch(
            "core.security.mcp_auth_middleware._auth_config",
            {"mode": AuthMode.DISABLED, "manager": None, "audit_enabled": False},
        ),
    ):
        from handlers.lateral_handlers import register_lateral_tools

        register_lateral_tools(mock_mcp, mock_counter, mock_logger)

    return registered_tools, mock_counter, mock_logger


# ==================== 注册测试 ====================


class TestLateralHandlersRegistration:
    """测试横向移动工具注册"""

    def test_register_lateral_tools(self):
        """测试注册函数是否正确注册 9 个工具"""
        registered_tools, mock_counter, mock_logger = _make_mcp_and_register()

        mock_counter.add.assert_called_once_with("lateral", 9)
        mock_logger.info.assert_called_once()
        assert "9 个横向移动工具" in str(mock_logger.info.call_args)

    def test_all_tools_registered(self):
        """验证所有预期工具均已注册"""
        registered_tools, _, _ = _make_mcp_and_register()

        expected_tools = [
            "lateral_ssh",
            "lateral_ssh_tunnel",
            "lateral_wmi",
            "lateral_wmi_query",
            "lateral_winrm",
            "lateral_winrm_ps",
            "lateral_psexec",
            "lateral_auto",
            "credential_spray",
        ]
        for tool_name in expected_tools:
            assert tool_name in registered_tools, f"工具 {tool_name} 未注册"


# ==================== lateral_ssh 测试 ====================


class TestLateralSSHTool:
    """测试 lateral_ssh SSH横向移动工具"""

    @pytest.mark.asyncio
    async def test_ssh_success_password(self):
        """测试SSH横向移动成功 - 密码认证"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "target": "192.168.1.100",
            "output": "root",
            "command": "whoami",
        }

        with patch("core.lateral.ssh_exec") as mock_ssh:
            mock_ssh.return_value = mock_result

            result = await registered_tools["lateral_ssh"](
                target="192.168.1.100",
                username="root",
                password="P@ssw0rd",
                command="whoami",
                port=22,
            )

            assert result["success"] is True
            mock_ssh.assert_called_once()

    @pytest.mark.asyncio
    async def test_ssh_success_key_file(self):
        """测试SSH横向移动成功 - 私钥认证"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "target": "192.168.1.100",
            "output": "user",
        }

        with patch("core.lateral.ssh_exec") as mock_ssh:
            mock_ssh.return_value = mock_result

            result = await registered_tools["lateral_ssh"](
                target="192.168.1.100",
                username="user",
                key_file="/home/user/.ssh/id_rsa",
                command="id",
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_ssh_connection_error(self):
        """测试SSH连接失败"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.lateral.ssh_exec") as mock_ssh:
            mock_ssh.side_effect = ConnectionError("Connection refused")

            result = await registered_tools["lateral_ssh"](
                target="192.168.1.100",
                username="root",
                password="P@ssw0rd",
            )

            assert result["success"] is False
            assert "error" in result

    @pytest.mark.asyncio
    async def test_ssh_object_result(self):
        """测试SSH返回对象类型结果"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_obj = MagicMock()
        mock_obj.success = True
        mock_obj.output = "root"
        mock_obj.exit_code = 0
        mock_obj.error = None

        with patch("core.lateral.ssh_exec") as mock_ssh:
            mock_ssh.return_value = mock_obj

            result = await registered_tools["lateral_ssh"](
                target="192.168.1.100",
                username="root",
                password="P@ss",
                command="whoami",
            )

            assert result["success"] is True
            assert result["output"] == "root"
            assert result["exit_code"] == 0


# ==================== lateral_ssh_tunnel 测试 ====================


class TestLateralSSHTunnelTool:
    """测试 lateral_ssh_tunnel SSH隧道工具"""

    @pytest.mark.asyncio
    async def test_ssh_tunnel_success(self):
        """测试SSH隧道创建成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "local_bind": "127.0.0.1:8080",
        }

        with patch("core.lateral.ssh_tunnel") as mock_tunnel:
            mock_tunnel.return_value = mock_result

            result = await registered_tools["lateral_ssh_tunnel"](
                target="192.168.1.100",
                username="user",
                password="pass",
                local_port=8080,
                remote_host="10.0.0.1",
                remote_port=80,
            )

            assert result["success"] is True
            assert result["tunnel"]["local_port"] == 8080
            assert result["tunnel"]["remote_host"] == "10.0.0.1"
            assert result["tunnel"]["remote_port"] == 80

    @pytest.mark.asyncio
    async def test_ssh_tunnel_failure(self):
        """测试SSH隧道创建失败"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.lateral.ssh_tunnel") as mock_tunnel:
            mock_tunnel.side_effect = ConnectionError("Cannot establish tunnel")

            result = await registered_tools["lateral_ssh_tunnel"](
                target="192.168.1.100",
                username="user",
                password="pass",
            )

            assert result["success"] is False
            assert "error" in result


# ==================== lateral_wmi 测试 ====================


class TestLateralWMITool:
    """测试 lateral_wmi WMI横向移动工具"""

    @pytest.mark.asyncio
    async def test_wmi_exec_success(self):
        """测试WMI执行成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "target": "192.168.1.100",
            "output": "DOMAIN\\User",
        }

        with patch("core.lateral.wmi_exec") as mock_wmi:
            mock_wmi.return_value = mock_result

            result = await registered_tools["lateral_wmi"](
                target="192.168.1.100",
                username="Admin",
                password="P@ss",
                command="whoami",
                domain="CORP",
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_wmi_exec_exception(self):
        """测试WMI执行异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.lateral.wmi_exec") as mock_wmi:
            mock_wmi.side_effect = RuntimeError("WMI service unavailable")

            result = await registered_tools["lateral_wmi"](
                target="192.168.1.100",
                username="Admin",
                password="P@ss",
            )

            assert result["success"] is False
            assert "error" in result


# ==================== lateral_wmi_query 测试 ====================


class TestLateralWMIQueryTool:
    """测试 lateral_wmi_query WMI查询工具"""

    @pytest.mark.asyncio
    async def test_wmi_query_success(self):
        """测试WMI查询成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "data": [{"Name": "Windows 10", "Version": "10.0.19041"}],
        }

        with patch("core.lateral.wmi_query") as mock_wmi_q:
            mock_wmi_q.return_value = mock_result

            result = await registered_tools["lateral_wmi_query"](
                target="192.168.1.100",
                username="Admin",
                password="P@ss",
                query="SELECT * FROM Win32_OperatingSystem",
            )

            assert result["success"] is True
            assert result["query"] == "SELECT * FROM Win32_OperatingSystem"

    @pytest.mark.asyncio
    async def test_wmi_query_exception(self):
        """测试WMI查询异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.lateral.wmi_query") as mock_wmi_q:
            mock_wmi_q.side_effect = ConnectionError("RPC unavailable")

            result = await registered_tools["lateral_wmi_query"](
                target="192.168.1.100",
                username="Admin",
                password="P@ss",
            )

            assert result["success"] is False


# ==================== lateral_winrm 测试 ====================


class TestLateralWinRMTool:
    """测试 lateral_winrm WinRM横向移动工具"""

    @pytest.mark.asyncio
    async def test_winrm_exec_success(self):
        """测试WinRM执行成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "target": "192.168.1.100",
            "output": "NT AUTHORITY\\SYSTEM",
        }

        with patch("core.lateral.winrm_exec") as mock_winrm:
            mock_winrm.return_value = mock_result

            result = await registered_tools["lateral_winrm"](
                target="192.168.1.100",
                username="Admin",
                password="P@ss",
                command="whoami",
                use_ssl=True,
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_winrm_exec_exception(self):
        """测试WinRM执行异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.lateral.winrm_exec") as mock_winrm:
            mock_winrm.side_effect = TimeoutError("Connection timed out")

            result = await registered_tools["lateral_winrm"](
                target="192.168.1.100",
                username="Admin",
                password="P@ss",
            )

            assert result["success"] is False


# ==================== lateral_winrm_ps 测试 ====================


class TestLateralWinRMPSTool:
    """测试 lateral_winrm_ps PowerShell执行工具"""

    @pytest.mark.asyncio
    async def test_winrm_ps_success(self):
        """测试PowerShell脚本执行成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "target": "192.168.1.100",
            "output": "ProcessName: svchost\nProcessName: explorer",
        }

        with patch("core.lateral.winrm_ps") as mock_ps:
            mock_ps.return_value = mock_result

            result = await registered_tools["lateral_winrm_ps"](
                target="192.168.1.100",
                username="Admin",
                password="P@ss",
                script="Get-Process | Select-Object ProcessName",
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_winrm_ps_exception(self):
        """测试PowerShell执行异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.lateral.winrm_ps") as mock_ps:
            mock_ps.side_effect = PermissionError("Access denied")

            result = await registered_tools["lateral_winrm_ps"](
                target="192.168.1.100",
                username="Admin",
                password="P@ss",
                script="Get-Process",
            )

            assert result["success"] is False


# ==================== lateral_psexec 测试 ====================


class TestLateralPsExecTool:
    """测试 lateral_psexec PsExec横向移动工具"""

    @pytest.mark.asyncio
    async def test_psexec_success_password(self):
        """测试PsExec密码认证成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "target": "192.168.1.100",
            "output": "DOMAIN\\Admin",
        }

        with patch("core.lateral.psexec") as mock_psexec:
            mock_psexec.return_value = mock_result

            result = await registered_tools["lateral_psexec"](
                target="192.168.1.100",
                username="Admin",
                password="P@ss",
                command="whoami",
                domain="CORP",
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_psexec_success_hash(self):
        """测试PsExec Pass-the-Hash成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "target": "192.168.1.100",
            "output": "Admin",
        }

        with patch("core.lateral.psexec") as mock_psexec:
            mock_psexec.return_value = mock_result

            result = await registered_tools["lateral_psexec"](
                target="192.168.1.100",
                username="Admin",
                ntlm_hash="aad3b435b51404ee:8846f7eaee8fb117",
                command="whoami",
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_psexec_exception(self):
        """测试PsExec异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.lateral.psexec") as mock_psexec:
            mock_psexec.side_effect = ImportError("impacket not installed")

            result = await registered_tools["lateral_psexec"](
                target="192.168.1.100",
                username="Admin",
                password="P@ss",
            )

            assert result["success"] is False
            assert "error" in result


# ==================== lateral_auto 测试 ====================


class TestLateralAutoTool:
    """测试 lateral_auto 自动横向移动工具"""

    @pytest.mark.asyncio
    async def test_auto_lateral_success(self):
        """测试自动横向移动成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_exec_result = MagicMock()
        mock_exec_result.success = True
        mock_exec_result.output = "root"

        mock_lateral = MagicMock()
        mock_lateral.execute.return_value = mock_exec_result
        mock_lateral.disconnect.return_value = None
        type(mock_lateral).__name__ = "SSHLateral"

        with (
            patch("core.lateral.auto_lateral") as mock_auto,
            patch("core.lateral.Credentials") as mock_creds,
        ):
            mock_auto.return_value = mock_lateral

            result = await registered_tools["lateral_auto"](
                target="192.168.1.100",
                username="root",
                password="P@ss",
                command="whoami",
            )

            assert result["success"] is True
            assert result["method"] == "SSHLateral"
            assert result["output"] == "root"
            mock_lateral.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_auto_lateral_no_method(self):
        """测试自动横向移动无可用方法"""
        registered_tools, _, _ = _make_mcp_and_register()

        with (
            patch("core.lateral.auto_lateral") as mock_auto,
            patch("core.lateral.Credentials"),
        ):
            mock_auto.return_value = None

            result = await registered_tools["lateral_auto"](
                target="192.168.1.100",
                username="root",
                password="P@ss",
            )

            assert result["success"] is False
            assert "无法找到可用" in result["error"]

    @pytest.mark.asyncio
    async def test_auto_lateral_disconnect_on_error(self):
        """测试自动横向移动异常时也调用 disconnect"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_lateral = MagicMock()
        mock_lateral.execute.side_effect = RuntimeError("Exec failed")
        mock_lateral.disconnect.return_value = None

        with (
            patch("core.lateral.auto_lateral") as mock_auto,
            patch("core.lateral.Credentials"),
        ):
            mock_auto.return_value = mock_lateral

            result = await registered_tools["lateral_auto"](
                target="192.168.1.100",
                username="root",
                password="P@ss",
            )

            # handle_errors 捕获异常
            assert result["success"] is False
            # 关键：disconnect 应在 finally 中被调用
            mock_lateral.disconnect.assert_called_once()


# ==================== credential_spray 测试 ====================


class TestCredentialSprayTool:
    """测试 credential_spray 凭证喷洒工具"""

    @pytest.mark.asyncio
    async def test_spray_found_valid(self):
        """测试凭证喷洒发现有效凭证"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_cred = MagicMock()
        mock_cred.username = "admin"

        mock_results = {
            "192.168.1.100": {"credentials": mock_cred, "method": "smb"},
        }

        with (
            patch("core.lateral.spray_credentials") as mock_spray,
            patch("core.lateral.Credentials"),
        ):
            mock_spray.return_value = mock_results

            result = await registered_tools["credential_spray"](
                targets=["192.168.1.100"],
                usernames=["admin"],
                passwords=["P@ss", "admin"],
                protocol="smb",
            )

            assert result["success"] is True
            assert result["valid_count"] == 1
            assert result["valid_credentials"][0]["target"] == "192.168.1.100"
            assert result["valid_credentials"][0]["username"] == "admin"

    @pytest.mark.asyncio
    async def test_spray_no_valid(self):
        """测试凭证喷洒无有效凭证"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_results = {
            "192.168.1.100": {"credentials": None, "method": None},
        }

        with (
            patch("core.lateral.spray_credentials") as mock_spray,
            patch("core.lateral.Credentials"),
        ):
            mock_spray.return_value = mock_results

            result = await registered_tools["credential_spray"](
                targets=["192.168.1.100"],
                usernames=["admin"],
                passwords=["wrong"],
                protocol="smb",
            )

            assert result["success"] is False
            assert result["valid_count"] == 0

    @pytest.mark.asyncio
    async def test_spray_exception(self):
        """测试凭证喷洒异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with (
            patch("core.lateral.spray_credentials") as mock_spray,
            patch("core.lateral.Credentials"),
        ):
            mock_spray.side_effect = ConnectionError("Network unreachable")

            result = await registered_tools["credential_spray"](
                targets=["192.168.1.100"],
                usernames=["admin"],
                passwords=["P@ss"],
            )

            assert result["success"] is False
            assert "error" in result

    @pytest.mark.asyncio
    async def test_spray_cartesian_product(self):
        """测试凭证喷洒的笛卡尔积计算"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_results = {}

        with (
            patch("core.lateral.spray_credentials") as mock_spray,
            patch("core.lateral.Credentials") as MockCreds,
        ):
            mock_spray.return_value = mock_results

            result = await registered_tools["credential_spray"](
                targets=["10.0.0.1", "10.0.0.2"],
                usernames=["admin", "user"],
                passwords=["pass1", "pass2", "pass3"],
                protocol="ssh",
            )

            # total_attempts = 2 targets * 6 credentials (2 users * 3 passwords)
            assert result["total_attempts"] == 2 * 6
            # Credentials 应被调用 6 次 (笛卡尔积)
            assert MockCreds.call_count == 6
