#!/usr/bin/env python3
"""
CVE工具处理器单元测试
测试 handlers/cve_handlers.py 中的 8 个工具注册和执行
"""

from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ==================== 辅助函数 ====================


def _make_mcp_and_register():
    """创建 mock MCP 并注册 CVE 工具，返回 (registered_tools, mock_counter, mock_logger)

    通过 patch _wrap_tool_func 为 identity，使注册的工具直接返回 handler 原始 dict，
    跳过 ToolResult 转换层，方便直接断言 handler 的返回值。
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

    with patch('utils.mcp_tooling._wrap_tool_func', side_effect=lambda f: f):
        from handlers.cve_handlers import register_cve_tools
        register_cve_tools(mock_mcp, mock_counter, mock_logger)

    return registered_tools, mock_counter, mock_logger


# ==================== 注册测试 ====================


class TestCveHandlersRegistration:
    """测试 CVE 工具注册"""

    def test_register_cve_tools(self):
        """测试注册函数是否正确注册 8 个工具"""
        registered_tools, mock_counter, mock_logger = _make_mcp_and_register()

        mock_counter.add.assert_called_once_with('cve', 8)
        mock_logger.info.assert_called_once()
        assert "8 个CVE工具" in str(mock_logger.info.call_args)

    def test_all_tools_registered(self):
        """验证所有预期工具均已注册"""
        registered_tools, _, _ = _make_mcp_and_register()

        expected_tools = [
            'cve_search', 'cve_sync', 'cve_stats',
            'poc_execute', 'poc_list',
            'cve_auto_exploit', 'cve_exploit_with_desc', 'cve_generate_poc',
        ]
        for tool_name in expected_tools:
            assert tool_name in registered_tools, f"工具 {tool_name} 未注册"


# ==================== cve_search 测试 ====================


class TestCveSearchTool:
    """测试 cve_search 搜索工具"""

    @pytest.mark.asyncio
    async def test_cve_search_normal(self):
        """测试正常搜索返回结果"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_cve = MagicMock()
        mock_cve.cve_id = "CVE-2024-1234"
        mock_cve.description = "Test vulnerability" * 20
        mock_cve.severity = "HIGH"
        mock_cve.cvss = 8.5
        mock_cve.poc_available = True
        mock_cve.poc_path = "/path/to/poc.yaml"

        with patch('core.cve.update_manager.CVEUpdateManager') as MockManager:
            MockManager.return_value.search.return_value = [mock_cve]

            result = await registered_tools['cve_search'](
                keyword="apache", severity="HIGH", has_poc=True, limit=10
            )

            assert result['success'] is True
            assert result['keyword'] == 'apache'
            assert result['count'] == 1
            assert result['cves'][0]['cve_id'] == 'CVE-2024-1234'
            assert result['cves'][0]['severity'] == 'HIGH'
            assert result['cves'][0]['poc_available'] is True
            # 验证描述被截断到 200 字符
            assert len(result['cves'][0]['description']) <= 200

    @pytest.mark.asyncio
    async def test_cve_search_empty_results(self):
        """测试搜索无结果"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.cve.update_manager.CVEUpdateManager') as MockManager:
            MockManager.return_value.search.return_value = []

            result = await registered_tools['cve_search'](keyword="nonexistent_cve")

            assert result['success'] is True
            assert result['count'] == 0
            assert result['cves'] == []

    @pytest.mark.asyncio
    async def test_cve_search_exception(self):
        """测试搜索异常处理"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.cve.update_manager.CVEUpdateManager') as MockManager:
            MockManager.return_value.search.side_effect = Exception("Database error")

            result = await registered_tools['cve_search'](keyword="test")

            assert result['success'] is False
            assert 'error' in result
            assert "Database error" in result['error']


# ==================== cve_sync 测试 ====================


class TestCveSyncTool:
    """测试 cve_sync 数据同步工具"""

    @pytest.mark.asyncio
    async def test_cve_sync_normal(self):
        """测试正常同步"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.cve.update_manager.CVEUpdateManager') as MockManager:
            MockManager.return_value.sync_all = AsyncMock(
                return_value={
                    'nvd': (10, 5),
                    'nuclei': (3, 2),
                }
            )

            result = await registered_tools['cve_sync'](days=7)

            assert result['success'] is True
            assert result['days'] == 7
            assert result['results']['nvd']['new'] == 10
            assert result['results']['nvd']['updated'] == 5
            assert result['results']['nuclei']['new'] == 3

    @pytest.mark.asyncio
    async def test_cve_sync_exception(self):
        """测试同步异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.cve.update_manager.CVEUpdateManager') as MockManager:
            MockManager.return_value.sync_all = AsyncMock(
                side_effect=ConnectionError("Network unreachable")
            )

            result = await registered_tools['cve_sync'](days=3)

            assert result['success'] is False
            assert 'error' in result


# ==================== cve_stats 测试 ====================


class TestCveStatsTool:
    """测试 cve_stats 统计工具"""

    @pytest.mark.asyncio
    async def test_cve_stats_normal(self):
        """测试正常获取统计"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_stats = {
            'total': 5000,
            'critical': 200,
            'high': 800,
            'poc_count': 150,
        }

        with patch('core.cve.update_manager.CVEUpdateManager') as MockManager:
            MockManager.return_value.get_stats.return_value = mock_stats

            result = await registered_tools['cve_stats']()

            assert result['success'] is True
            assert result['stats']['total'] == 5000
            assert result['stats']['critical'] == 200


# ==================== poc_execute 测试 ====================


class TestPocExecuteTool:
    """测试 poc_execute PoC 执行工具"""

    @pytest.mark.asyncio
    async def test_poc_execute_success(self):
        """测试 PoC 执行成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_template = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.vulnerable = True
        mock_result.evidence = "Vulnerability confirmed"
        mock_result.extracted = {"version": "1.0"}
        mock_result.execution_time_ms = 150

        with patch('core.cve.poc_engine.get_poc_engine') as mock_engine_fn:
            engine = MagicMock()
            engine.get_template.return_value = mock_template
            engine.execute.return_value = mock_result
            mock_engine_fn.return_value = engine

            result = await registered_tools['poc_execute'](
                target="https://example.com",
                template_id="CVE-2024-1234",
                variables={"path": "/admin"}
            )

            assert result['success'] is True
            assert result['vulnerable'] is True
            assert result['template_id'] == 'CVE-2024-1234'

    @pytest.mark.asyncio
    async def test_poc_execute_template_not_found(self):
        """测试模板不存在"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.cve.poc_engine.get_poc_engine') as mock_engine_fn:
            engine = MagicMock()
            engine.get_template.return_value = None
            engine.list_templates.return_value = ['tmpl-1', 'tmpl-2']
            mock_engine_fn.return_value = engine

            result = await registered_tools['poc_execute'](
                target="https://example.com",
                template_id="nonexistent"
            )

            assert result['success'] is False
            assert '模板不存在' in result['error']
            assert 'available_templates' in result

    @pytest.mark.asyncio
    async def test_poc_execute_exception(self):
        """测试 PoC 执行异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.cve.poc_engine.get_poc_engine') as mock_engine_fn:
            mock_engine_fn.side_effect = ImportError("Module not found")

            result = await registered_tools['poc_execute'](
                target="https://example.com",
                template_id="test"
            )

            assert result['success'] is False
            assert 'error' in result


# ==================== poc_list 测试 ====================


class TestPocListTool:
    """测试 poc_list 模板列表工具"""

    @pytest.mark.asyncio
    async def test_poc_list_all(self):
        """测试列出所有模板"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.cve.poc_engine.get_poc_engine') as mock_engine_fn:
            engine = MagicMock()
            engine.list_templates.return_value = ['tmpl-1', 'tmpl-2', 'tmpl-3']
            mock_engine_fn.return_value = engine

            result = await registered_tools['poc_list']()

            assert result['success'] is True
            assert result['count'] == 3
            assert 'tmpl-1' in result['templates']

    @pytest.mark.asyncio
    async def test_poc_list_with_keyword(self):
        """测试关键词过滤"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.cve.poc_engine.get_poc_engine') as mock_engine_fn:
            engine = MagicMock()
            engine.list_templates.return_value = [
                'apache-rce', 'apache-ssrf', 'nginx-lfi', 'tomcat-rce'
            ]
            mock_engine_fn.return_value = engine

            result = await registered_tools['poc_list'](keyword="apache")

            assert result['success'] is True
            assert result['count'] == 2
            assert all('apache' in t for t in result['templates'])

    @pytest.mark.asyncio
    async def test_poc_list_with_limit(self):
        """测试限制返回数量"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.cve.poc_engine.get_poc_engine') as mock_engine_fn:
            engine = MagicMock()
            engine.list_templates.return_value = [f'tmpl-{i}' for i in range(100)]
            mock_engine_fn.return_value = engine

            result = await registered_tools['poc_list'](limit=5)

            assert result['success'] is True
            assert result['count'] == 5


# ==================== cve_auto_exploit 测试 ====================


class TestCveAutoExploitTool:
    """测试 cve_auto_exploit 自动利用工具"""

    @pytest.mark.asyncio
    async def test_auto_exploit_success(self):
        """测试自动利用成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.status = MagicMock(value='completed')
        mock_result.vulnerable = True
        mock_result.vuln_type = 'rce'
        mock_result.evidence = 'Command executed'
        mock_result.poc_yaml = 'id: test\ninfo:\n  name: test'
        mock_result.poc_template_path = '/path/to/poc.yaml'
        mock_result.exploit_data = {'shell': True}
        mock_result.execution_time_ms = 2500
        mock_result.steps = ['search', 'generate', 'verify', 'exploit']
        mock_result.error = None

        with patch('core.cve.auto_exploit.auto_exploit_cve', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = mock_result

            result = await registered_tools['cve_auto_exploit'](
                target="https://example.com",
                cve_id="CVE-2024-1234"
            )

            assert result['success'] is True
            assert result['vulnerable'] is True
            assert result['cve_id'] == 'CVE-2024-1234'
            assert result['vuln_type'] == 'rce'
            mock_fn.assert_called_once_with("https://example.com", "CVE-2024-1234", None)

    @pytest.mark.asyncio
    async def test_auto_exploit_not_vulnerable(self):
        """测试目标不存在漏洞"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.status = MagicMock(value='not_vulnerable')
        mock_result.vulnerable = False
        mock_result.vuln_type = None
        mock_result.evidence = None
        mock_result.poc_yaml = None
        mock_result.poc_template_path = None
        mock_result.exploit_data = None
        mock_result.execution_time_ms = 1200
        mock_result.steps = ['search', 'generate', 'verify']
        mock_result.error = None

        with patch('core.cve.auto_exploit.auto_exploit_cve', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = mock_result

            result = await registered_tools['cve_auto_exploit'](
                target="https://example.com",
                cve_id="CVE-2024-9999"
            )

            assert result['success'] is True
            assert result['vulnerable'] is False

    @pytest.mark.asyncio
    async def test_auto_exploit_exception(self):
        """测试自动利用异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.cve.auto_exploit.auto_exploit_cve', new_callable=AsyncMock) as mock_fn:
            mock_fn.side_effect = ConnectionError("Target unreachable")

            result = await registered_tools['cve_auto_exploit'](
                target="https://example.com",
                cve_id="CVE-2024-1234"
            )

            assert result['success'] is False
            assert 'error' in result


# ==================== cve_exploit_with_desc 测试 ====================


class TestCveExploitWithDescTool:
    """测试 cve_exploit_with_desc 基于描述的利用工具"""

    @pytest.mark.asyncio
    async def test_exploit_with_desc_success(self):
        """测试基于描述的利用成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.status = MagicMock(value='completed')
        mock_result.vulnerable = True
        mock_result.vuln_type = 'sqli'
        mock_result.evidence = 'SQL injection confirmed'
        mock_result.poc_yaml = 'id: test'
        mock_result.exploit_data = {'dumped': True}
        mock_result.execution_time_ms = 1800
        mock_result.steps = ['generate', 'verify', 'exploit']
        mock_result.error = None

        with patch(
            'core.cve.auto_exploit.exploit_cve_with_description',
            new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = mock_result

            result = await registered_tools['cve_exploit_with_desc'](
                target="https://example.com",
                cve_id="CVE-2024-5678",
                description="SQL injection in login endpoint",
                severity="high"
            )

            assert result['success'] is True
            assert result['vulnerable'] is True
            assert result['cve_id'] == 'CVE-2024-5678'
            mock_fn.assert_called_once_with(
                "https://example.com", "CVE-2024-5678",
                "SQL injection in login endpoint", "high", None
            )


# ==================== cve_generate_poc 测试 ====================


class TestCveGeneratePocTool:
    """测试 cve_generate_poc PoC 生成工具"""

    @pytest.mark.asyncio
    async def test_generate_poc_success(self):
        """测试 PoC 生成成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        poc_yaml = "id: CVE-2024-1234\ninfo:\n  name: Test\n  severity: high"

        with patch('core.cve.auto_exploit.generate_cve_poc') as mock_fn:
            mock_fn.return_value = poc_yaml

            result = await registered_tools['cve_generate_poc'](
                cve_id="CVE-2024-1234",
                description="Test vulnerability",
                severity="high"
            )

            assert result['success'] is True
            assert result['cve_id'] == 'CVE-2024-1234'
            assert result['poc_yaml'] == poc_yaml
            assert result['poc_length'] == len(poc_yaml)

    @pytest.mark.asyncio
    async def test_generate_poc_failure(self):
        """测试 PoC 生成失败"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.cve.auto_exploit.generate_cve_poc') as mock_fn:
            mock_fn.return_value = None

            result = await registered_tools['cve_generate_poc'](
                cve_id="CVE-2024-9999",
                description="Unknown vulnerability"
            )

            assert result['success'] is False
            assert 'PoC生成失败' in result['error']

    @pytest.mark.asyncio
    async def test_generate_poc_exception(self):
        """测试 PoC 生成异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.cve.auto_exploit.generate_cve_poc') as mock_fn:
            mock_fn.side_effect = RuntimeError("AI service unavailable")

            result = await registered_tools['cve_generate_poc'](
                cve_id="CVE-2024-1234",
                description="Test"
            )

            assert result['success'] is False
            assert 'error' in result
