#!/usr/bin/env python3
"""
外部工具处理器单元测试
测试 handlers/external_tools_handlers.py 中的 8 个工具注册和执行
"""

from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.security.mcp_auth_middleware import AuthMode

# ==================== 辅助函数 ====================


def _make_mcp_and_register():
    """创建 mock MCP 并注册 External Tools 工具

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
        patch("core.security.require_dangerous_auth", side_effect=passthrough_decorator),
        patch(
            "core.security.mcp_auth_middleware._auth_config",
            {"mode": AuthMode.DISABLED, "manager": None, "audit_enabled": False},
        ),
    ):
        from handlers.external_tools_handlers import register_external_tools

        register_external_tools(mock_mcp, mock_counter, mock_logger)

    return registered_tools, mock_counter, mock_logger


# ==================== 注册测试 ====================


class TestExternalToolsRegistration:
    """测试外部工具注册"""

    def test_register_external_tools(self):
        """测试注册函数是否正确注册 8 个工具"""
        registered_tools, mock_counter, mock_logger = _make_mcp_and_register()

        # counter.add 被调用 8 次 (每个工具各调用一次)
        assert mock_counter.add.call_count == 8
        total = sum(c[0][1] for c in mock_counter.add.call_args_list)
        assert total == 8

        mock_logger.info.assert_called_once()
        assert "8 个外部工具" in str(mock_logger.info.call_args)

    def test_all_tools_registered(self):
        """验证所有预期工具均已注册"""
        registered_tools, _, _ = _make_mcp_and_register()

        expected_tools = [
            "ext_nmap_scan",
            "ext_nuclei_scan",
            "ext_sqlmap_scan",
            "ext_ffuf_fuzz",
            "ext_masscan_scan",
            "ext_tool_chain",
            "ext_tools_status",
            "ext_tools_reload",
        ]
        for tool_name in expected_tools:
            assert tool_name in registered_tools, f"工具 {tool_name} 未注册"


# ==================== ext_nmap_scan 测试 ====================


class TestExtNmapScanTool:
    """测试 ext_nmap_scan Nmap扫描工具"""

    @pytest.mark.asyncio
    async def test_nmap_scan_success(self):
        """测试Nmap扫描成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "hosts": [{"ip": "192.168.1.1", "ports": [80, 443]}],
        }

        with (
            patch("core.tools.get_tool_manager") as mock_mgr_fn,
            patch("core.tools.run_nmap", new_callable=AsyncMock) as mock_run,
        ):
            manager = MagicMock()
            manager.is_tool_available.return_value = True
            mock_mgr_fn.return_value = manager
            mock_run.return_value = mock_result

            result = await registered_tools["ext_nmap_scan"](
                target="192.168.1.1", ports="1-1000", preset="quick"
            )

            assert result["success"] is True
            assert "hosts" in result
            mock_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_nmap_not_installed(self):
        """测试Nmap未安装"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.tools.get_tool_manager") as mock_mgr_fn:
            manager = MagicMock()
            manager.is_tool_available.return_value = False
            mock_mgr_fn.return_value = manager

            result = await registered_tools["ext_nmap_scan"](target="192.168.1.1")

            assert result["success"] is False
            assert "Nmap未安装" in result["error"]

    @pytest.mark.asyncio
    async def test_nmap_top100_ports(self):
        """测试Nmap top100端口模式"""
        registered_tools, _, _ = _make_mcp_and_register()

        with (
            patch("core.tools.get_tool_manager") as mock_mgr_fn,
            patch("core.tools.run_nmap", new_callable=AsyncMock) as mock_run,
        ):
            manager = MagicMock()
            manager.is_tool_available.return_value = True
            mock_mgr_fn.return_value = manager
            mock_run.return_value = {"success": True}

            await registered_tools["ext_nmap_scan"](target="192.168.1.1", ports="top100")

            # 验证 top100 被展开为端口列表
            call_args = mock_run.call_args
            assert "21,22,23" in call_args.kwargs.get("ports", call_args[1].get("ports", ""))

    @pytest.mark.asyncio
    async def test_nmap_exception(self):
        """测试Nmap扫描异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with (
            patch("core.tools.get_tool_manager") as mock_mgr_fn,
            patch("core.tools.run_nmap", new_callable=AsyncMock) as mock_run,
        ):
            manager = MagicMock()
            manager.is_tool_available.return_value = True
            mock_mgr_fn.return_value = manager
            mock_run.side_effect = RuntimeError("nmap execution failed")

            result = await registered_tools["ext_nmap_scan"](target="192.168.1.1")

            assert result["success"] is False
            assert "error" in result


# ==================== ext_nuclei_scan 测试 ====================


class TestExtNucleiScanTool:
    """测试 ext_nuclei_scan Nuclei扫描工具"""

    @pytest.mark.asyncio
    async def test_nuclei_scan_success(self):
        """测试Nuclei扫描成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "findings": [{"template": "cve-2021-44228", "severity": "critical"}],
        }

        with (
            patch("core.tools.get_tool_manager") as mock_mgr_fn,
            patch("core.tools.run_nuclei", new_callable=AsyncMock) as mock_run,
        ):
            manager = MagicMock()
            manager.is_tool_available.return_value = True
            mock_mgr_fn.return_value = manager
            mock_run.return_value = mock_result

            result = await registered_tools["ext_nuclei_scan"](
                target="https://example.com", preset="quick"
            )

            assert result["success"] is True
            assert len(result["findings"]) == 1

    @pytest.mark.asyncio
    async def test_nuclei_not_installed(self):
        """测试Nuclei未安装"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.tools.get_tool_manager") as mock_mgr_fn:
            manager = MagicMock()
            manager.is_tool_available.return_value = False
            mock_mgr_fn.return_value = manager

            result = await registered_tools["ext_nuclei_scan"](target="https://example.com")

            assert result["success"] is False
            assert "Nuclei未安装" in result["error"]

    @pytest.mark.asyncio
    async def test_nuclei_with_tags_and_severity(self):
        """测试Nuclei带标签和严重级别过滤"""
        registered_tools, _, _ = _make_mcp_and_register()

        with (
            patch("core.tools.get_tool_manager") as mock_mgr_fn,
            patch("core.tools.run_nuclei", new_callable=AsyncMock) as mock_run,
        ):
            manager = MagicMock()
            manager.is_tool_available.return_value = True
            mock_mgr_fn.return_value = manager
            mock_run.return_value = {"success": True, "findings": []}

            await registered_tools["ext_nuclei_scan"](
                target="https://example.com",
                tags=["cve", "rce"],
                severity="critical,high",
            )

            # 验证 extra_args 包含 tags 和 severity
            call_args = mock_run.call_args
            extra_args = call_args.kwargs.get("extra_args") or call_args[1].get("extra_args")
            assert "-tags" in extra_args
            assert "-severity" in extra_args


# ==================== ext_sqlmap_scan 测试 ====================


class TestExtSqlmapScanTool:
    """测试 ext_sqlmap_scan SQLMap工具"""

    @pytest.mark.asyncio
    async def test_sqlmap_scan_success(self):
        """测试SQLMap扫描成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "vulnerable": True,
            "injection_type": "boolean_blind",
            "dbms": "MySQL",
        }

        with (
            patch("core.tools.get_tool_manager") as mock_mgr_fn,
            patch("core.tools.run_sqlmap", new_callable=AsyncMock) as mock_run,
        ):
            manager = MagicMock()
            manager.is_tool_available.return_value = True
            mock_mgr_fn.return_value = manager
            mock_run.return_value = mock_result

            result = await registered_tools["ext_sqlmap_scan"](
                url="https://example.com/page?id=1", preset="detect"
            )

            assert result["success"] is True
            assert result["vulnerable"] is True

    @pytest.mark.asyncio
    async def test_sqlmap_not_installed(self):
        """测试SQLMap未安装"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.tools.get_tool_manager") as mock_mgr_fn:
            manager = MagicMock()
            manager.is_tool_available.return_value = False
            mock_mgr_fn.return_value = manager

            result = await registered_tools["ext_sqlmap_scan"](
                url="https://example.com/page?id=1"
            )

            assert result["success"] is False
            assert "SQLMap未安装" in result["error"]

    @pytest.mark.asyncio
    async def test_sqlmap_with_data_and_tamper(self):
        """测试SQLMap带POST数据和tamper脚本"""
        registered_tools, _, _ = _make_mcp_and_register()

        with (
            patch("core.tools.get_tool_manager") as mock_mgr_fn,
            patch("core.tools.run_sqlmap", new_callable=AsyncMock) as mock_run,
        ):
            manager = MagicMock()
            manager.is_tool_available.return_value = True
            mock_mgr_fn.return_value = manager
            mock_run.return_value = {"success": True}

            await registered_tools["ext_sqlmap_scan"](
                url="https://example.com/login",
                data="username=admin&password=test",
                tamper=["space2comment", "randomcase"],
            )

            call_args = mock_run.call_args
            extra_args = call_args.kwargs.get("extra_args") or call_args[1].get("extra_args")
            assert "--data" in extra_args
            assert "--tamper" in extra_args


# ==================== ext_ffuf_fuzz 测试 ====================


class TestExtFfufFuzzTool:
    """测试 ext_ffuf_fuzz ffuf模糊测试工具"""

    @pytest.mark.asyncio
    async def test_ffuf_dir_scan_success(self):
        """测试ffuf目录扫描成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "results": [{"url": "/admin", "status": 200}],
        }

        with (
            patch("core.tools.get_tool_manager") as mock_mgr_fn,
            patch("core.tools.run_ffuf", new_callable=AsyncMock) as mock_run,
        ):
            manager = MagicMock()
            manager.is_tool_available.return_value = True
            mock_mgr_fn.return_value = manager
            mock_run.return_value = mock_result

            result = await registered_tools["ext_ffuf_fuzz"](
                url="https://example.com", mode="dir"
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_ffuf_auto_append_fuzz(self):
        """测试ffuf自动追加FUZZ标记"""
        registered_tools, _, _ = _make_mcp_and_register()

        with (
            patch("core.tools.get_tool_manager") as mock_mgr_fn,
            patch("core.tools.run_ffuf", new_callable=AsyncMock) as mock_run,
        ):
            manager = MagicMock()
            manager.is_tool_available.return_value = True
            mock_mgr_fn.return_value = manager
            mock_run.return_value = {"success": True}

            # URL不含FUZZ，dir模式应自动追加
            await registered_tools["ext_ffuf_fuzz"](
                url="https://example.com", mode="dir"
            )

            call_args = mock_run.call_args
            url_arg = call_args.kwargs.get("url") or call_args[1].get("url")
            assert "FUZZ" in url_arg

    @pytest.mark.asyncio
    async def test_ffuf_not_installed(self):
        """测试ffuf未安装"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.tools.get_tool_manager") as mock_mgr_fn:
            manager = MagicMock()
            manager.is_tool_available.return_value = False
            mock_mgr_fn.return_value = manager

            result = await registered_tools["ext_ffuf_fuzz"](url="https://example.com/FUZZ")

            assert result["success"] is False
            assert "ffuf未安装" in result["error"]


# ==================== ext_masscan_scan 测试 ====================


class TestExtMasscanScanTool:
    """测试 ext_masscan_scan Masscan工具"""

    @pytest.mark.asyncio
    async def test_masscan_scan_success(self):
        """测试Masscan扫描成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "hosts": [{"ip": "192.168.1.1", "ports": [80]}],
        }

        with (
            patch("core.tools.get_tool_manager") as mock_mgr_fn,
            patch("core.tools.run_masscan", new_callable=AsyncMock) as mock_run,
        ):
            manager = MagicMock()
            manager.is_tool_available.return_value = True
            mock_mgr_fn.return_value = manager
            mock_run.return_value = mock_result

            result = await registered_tools["ext_masscan_scan"](
                target="192.168.1.0/24", ports="1-10000", rate=10000
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_masscan_invalid_rate(self):
        """测试Masscan无效速率"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.tools.get_tool_manager") as mock_mgr_fn:
            manager = MagicMock()
            manager.is_tool_available.return_value = True
            mock_mgr_fn.return_value = manager

            result = await registered_tools["ext_masscan_scan"](
                target="192.168.1.0/24", rate=-1
            )

            assert result["success"] is False
            assert "rate" in result["error"]

    @pytest.mark.asyncio
    async def test_masscan_not_installed(self):
        """测试Masscan未安装"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.tools.get_tool_manager") as mock_mgr_fn:
            manager = MagicMock()
            manager.is_tool_available.return_value = False
            mock_mgr_fn.return_value = manager

            result = await registered_tools["ext_masscan_scan"](target="192.168.1.0/24")

            assert result["success"] is False
            assert "Masscan未安装" in result["error"]


# ==================== ext_tool_chain 测试 ====================


class TestExtToolChainTool:
    """测试 ext_tool_chain 工具链编排工具"""

    @pytest.mark.asyncio
    async def test_tool_chain_success(self):
        """测试工具链执行成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            "success": True,
            "steps": [
                {"tool": "masscan", "status": "completed"},
                {"tool": "nmap", "status": "completed"},
            ],
        }

        with patch("core.tools.get_tool_manager") as mock_mgr_fn:
            manager = MagicMock()
            manager.run_chain = AsyncMock(return_value=mock_result)
            mock_mgr_fn.return_value = manager

            result = await registered_tools["ext_tool_chain"](
                target="192.168.1.1", chain_name="full_recon"
            )

            assert result["success"] is True
            assert len(result["steps"]) == 2

    @pytest.mark.asyncio
    async def test_tool_chain_invalid_name(self):
        """测试无效的工具链名称"""
        registered_tools, _, _ = _make_mcp_and_register()

        result = await registered_tools["ext_tool_chain"](
            target="192.168.1.1", chain_name="invalid_chain"
        )

        assert result["success"] is False
        assert "无效的工具链名称" in result["error"]

    @pytest.mark.asyncio
    async def test_tool_chain_valid_names(self):
        """测试所有有效的工具链名称"""
        registered_tools, _, _ = _make_mcp_and_register()

        valid_chains = ["full_recon", "vuln_scan", "content_discovery"]

        for chain_name in valid_chains:
            with patch("core.tools.get_tool_manager") as mock_mgr_fn:
                manager = MagicMock()
                manager.run_chain = AsyncMock(return_value={"success": True})
                mock_mgr_fn.return_value = manager

                result = await registered_tools["ext_tool_chain"](
                    target="192.168.1.1", chain_name=chain_name
                )

                assert result["success"] is True, f"工具链 {chain_name} 应该成功"


# ==================== ext_tools_status 测试 ====================


class TestExtToolsStatusTool:
    """测试 ext_tools_status 工具状态查询"""

    @pytest.mark.asyncio
    async def test_tools_status_success(self):
        """测试查询工具状态成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_status = {
            "nmap": {"available": True, "path": "/usr/bin/nmap", "version": "7.94"},
            "nuclei": {"available": True, "path": "/usr/bin/nuclei", "version": "3.1"},
            "sqlmap": {"available": False},
        }

        with patch("core.tools.get_tool_manager") as mock_mgr_fn:
            manager = MagicMock()
            manager.get_all_tools_status.return_value = mock_status
            mock_mgr_fn.return_value = manager

            result = await registered_tools["ext_tools_status"]()

            assert result["success"] is True
            assert result["available_count"] == 2
            assert result["total_count"] == 3
            assert "config_path" in result

    @pytest.mark.asyncio
    async def test_tools_status_exception(self):
        """测试查询工具状态异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.tools.get_tool_manager") as mock_mgr_fn:
            mock_mgr_fn.side_effect = FileNotFoundError("Config not found")

            result = await registered_tools["ext_tools_status"]()

            assert result["success"] is False
            assert "error" in result


# ==================== ext_tools_reload 测试 ====================


class TestExtToolsReloadTool:
    """测试 ext_tools_reload 配置重载工具"""

    @pytest.mark.asyncio
    async def test_tools_reload_success(self):
        """测试配置重载成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_status = {
            "nmap": {"available": True},
            "nuclei": {"available": True},
        }

        with (
            patch("core.tools.tool_manager._manager", None),
            patch("core.tools.get_tool_manager") as mock_mgr_fn,
        ):
            manager = MagicMock()
            manager.get_all_tools_status.return_value = mock_status
            mock_mgr_fn.return_value = manager

            result = await registered_tools["ext_tools_reload"]()

            assert result["success"] is True
            assert result["available_tools"] == 2
            assert result["total_tools"] == 2
            assert "配置已重新加载" in result["message"]

    @pytest.mark.asyncio
    async def test_tools_reload_exception(self):
        """测试配置重载异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch("core.tools.get_tool_manager") as mock_mgr_fn:
            mock_mgr_fn.side_effect = Exception("Config parse error")

            result = await registered_tools["ext_tools_reload"]()

            assert result["success"] is False
            assert "error" in result
