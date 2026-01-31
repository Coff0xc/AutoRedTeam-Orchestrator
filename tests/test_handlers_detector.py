#!/usr/bin/env python3
"""
漏洞检测工具处理器单元测试
测试 handlers/detector_handlers.py 中的工具注册和执行
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from typing import Dict, Any, List


class TestDetectorHandlersRegistration:
    """测试漏洞检测工具注册"""

    def test_register_detector_tools(self):
        """测试注册函数是否正确调用"""
        from handlers.detector_handlers import register_detector_tools

        # 模拟 MCP 实例
        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        # 执行注册
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        # 验证 counter.add 被调用
        mock_counter.add.assert_called_once_with('detector', 11)

        # 验证 logger.info 被调用
        mock_logger.info.assert_called_once()
        assert "11 个漏洞检测工具" in str(mock_logger.info.call_args)

        # 验证 @mcp.tool() 装饰器被调用了 11 次
        assert mock_mcp.tool.call_count == 11


class TestVulnScanTool:
    """测试 vuln_scan 综合漏洞扫描工具"""

    @pytest.mark.asyncio
    async def test_vuln_scan_with_vulnerabilities(self):
        """测试综合扫描发现漏洞"""
        from handlers.detector_handlers import register_detector_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟漏洞结果
        mock_vuln = MagicMock()
        mock_vuln.vulnerable = True
        mock_vuln.vuln_type = 'sqli'
        mock_vuln.severity = MagicMock()
        mock_vuln.severity.value = 'high'
        mock_vuln.param = 'id'
        mock_vuln.payload = "1' OR '1'='1"
        mock_vuln.evidence = "SQL syntax error detected" * 10  # 长证据
        mock_vuln.remediation = "Use parameterized queries"

        # 模拟检测器
        mock_composite = MagicMock()
        mock_composite.async_detect = AsyncMock(return_value=[mock_vuln])

        with patch('core.detectors.DetectorPresets') as mock_presets:
            mock_presets.owasp_top10.return_value = mock_composite

            result = await registered_tools['vuln_scan'](
                url="https://example.com/page?id=1",
                params={"id": "1"}
            )

            assert result['success'] is True
            assert result['data']['total_vulns'] == 1
            assert len(result['data']['vulnerabilities']) == 1
            assert result['data']['vulnerabilities'][0]['type'] == 'sqli'
            assert result['data']['vulnerabilities'][0]['severity'] == 'high'
            assert len(result['data']['vulnerabilities'][0]['evidence']) <= 200  # 截断验证

    @pytest.mark.asyncio
    async def test_vuln_scan_with_custom_detectors(self):
        """测试使用自定义检测器"""
        from handlers.detector_handlers import register_detector_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        mock_composite = MagicMock()
        mock_composite.async_detect = AsyncMock(return_value=[])

        with patch('core.detectors.DetectorFactory') as mock_factory:
            mock_factory.create_composite.return_value = mock_composite

            result = await registered_tools['vuln_scan'](
                url="https://example.com",
                detectors=['sqli', 'xss']
            )

            assert result['success'] is True
            assert result['data']['total_vulns'] == 0
            assert result['data']['detectors_used'] == ['sqli', 'xss']
            mock_factory.create_composite.assert_called_once_with(['sqli', 'xss'])

    @pytest.mark.asyncio
    async def test_vuln_scan_exception(self):
        """测试综合扫描异常处理"""
        from handlers.detector_handlers import register_detector_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        with patch('core.detectors.DetectorPresets') as mock_presets:
            mock_presets.owasp_top10.side_effect = Exception("Network timeout")

            result = await registered_tools['vuln_scan'](
                url="https://example.com"
            )

            assert result['success'] is False
            assert 'error' in result
            assert "Network timeout" in result['error']


class TestSQLiScanTool:
    """测试 sqli_scan SQL注入检测工具"""

    @pytest.mark.asyncio
    async def test_sqli_scan_vulnerable(self):
        """测试SQL注入检测发现漏洞"""
        from handlers.detector_handlers import register_detector_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟SQL注入结果
        mock_result = MagicMock()
        mock_result.vulnerable = True
        mock_result.param = 'id'
        mock_result.payload = "1' OR '1'='1"
        mock_result.injection_type = 'boolean_blind'
        mock_result.evidence = "Different response detected"

        mock_detector = MagicMock()
        mock_detector.async_detect = AsyncMock(return_value=[mock_result])

        with patch('core.detectors.SQLiDetector') as mock_detector_class:
            mock_detector_class.return_value = mock_detector

            result = await registered_tools['sqli_scan'](
                url="https://example.com/page",
                params={"id": "1"},
                method="GET"
            )

            assert result['success'] is True
            assert result['data']['vulnerable'] is True
            assert len(result['data']['findings']) == 1
            assert result['data']['findings'][0]['param'] == 'id'
            assert result['data']['findings'][0]['type'] == 'boolean_blind'

    @pytest.mark.asyncio
    async def test_sqli_scan_not_vulnerable(self):
        """测试SQL注入检测未发现漏洞"""
        from handlers.detector_handlers import register_detector_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        mock_result = MagicMock()
        mock_result.vulnerable = False

        mock_detector = MagicMock()
        mock_detector.async_detect = AsyncMock(return_value=[mock_result])

        with patch('core.detectors.SQLiDetector') as mock_detector_class:
            mock_detector_class.return_value = mock_detector

            result = await registered_tools['sqli_scan'](
                url="https://example.com/page"
            )

            assert result['success'] is True
            assert result['data']['vulnerable'] is False
            assert len(result['data']['findings']) == 0


class TestXSSScanTool:
    """测试 xss_scan XSS检测工具"""

    @pytest.mark.asyncio
    async def test_xss_scan_vulnerable(self):
        """测试XSS检测发现漏洞"""
        from handlers.detector_handlers import register_detector_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        mock_result = MagicMock()
        mock_result.vulnerable = True
        mock_result.param = 'search'
        mock_result.payload = '<script>alert(1)</script>'
        mock_result.context = 'html'
        mock_result.evidence = 'Payload reflected in response'

        mock_detector = MagicMock()
        mock_detector.async_detect = AsyncMock(return_value=[mock_result])

        with patch('core.detectors.XSSDetector') as mock_detector_class:
            mock_detector_class.return_value = mock_detector

            result = await registered_tools['xss_scan'](
                url="https://example.com/search",
                params={"search": "test"}
            )

            assert result['success'] is True
            assert result['data']['vulnerable'] is True
            assert result['data']['findings'][0]['context'] == 'html'


class TestSSRFScanTool:
    """测试 ssrf_scan SSRF检测工具"""

    @pytest.mark.asyncio
    async def test_ssrf_scan_vulnerable(self):
        """测试SSRF检测发现漏洞"""
        from handlers.detector_handlers import register_detector_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        mock_result = MagicMock()
        mock_result.vulnerable = True
        mock_result.to_dict.return_value = {
            'param': 'url',
            'payload': 'http://169.254.169.254/latest/meta-data/',
            'evidence': 'AWS metadata accessible'
        }

        mock_detector = MagicMock()
        mock_detector.async_detect = AsyncMock(return_value=[mock_result])

        with patch('core.detectors.SSRFDetector') as mock_detector_class:
            mock_detector_class.return_value = mock_detector

            result = await registered_tools['ssrf_scan'](
                url="https://example.com/fetch",
                params={"url": "http://example.com"}
            )

            assert result['success'] is True
            assert result['data']['vulnerable'] is True
            assert len(result['data']['findings']) == 1


class TestRCEScanTool:
    """测试 rce_scan 命令注入检测工具"""

    @pytest.mark.asyncio
    async def test_rce_scan_vulnerable(self):
        """测试RCE检测发现漏洞"""
        from handlers.detector_handlers import register_detector_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        mock_result = MagicMock()
        mock_result.vulnerable = True
        mock_result.to_dict.return_value = {
            'param': 'cmd',
            'payload': '; whoami',
            'evidence': 'Command output detected'
        }

        mock_detector = MagicMock()
        mock_detector.async_detect = AsyncMock(return_value=[mock_result])

        with patch('core.detectors.RCEDetector') as mock_detector_class:
            mock_detector_class.return_value = mock_detector

            result = await registered_tools['rce_scan'](
                url="https://example.com/exec"
            )

            assert result['success'] is True
            assert result['data']['vulnerable'] is True


class TestPathTraversalScanTool:
    """测试 path_traversal_scan 路径遍历检测工具"""

    @pytest.mark.asyncio
    async def test_path_traversal_scan_vulnerable(self):
        """测试路径遍历检测发现漏洞"""
        from handlers.detector_handlers import register_detector_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        mock_result = MagicMock()
        mock_result.vulnerable = True
        mock_result.to_dict.return_value = {
            'param': 'file',
            'payload': '../../../etc/passwd',
            'evidence': 'root:x:0:0:root'
        }

        mock_detector = MagicMock()
        mock_detector.async_detect = AsyncMock(return_value=[mock_result])

        with patch('core.detectors.PathTraversalDetector') as mock_detector_class:
            mock_detector_class.return_value = mock_detector

            result = await registered_tools['path_traversal_scan'](
                url="https://example.com/download"
            )

            assert result['success'] is True
            assert result['data']['vulnerable'] is True


class TestSSTIScanTool:
    """测试 ssti_scan 模板注入检测工具"""

    @pytest.mark.asyncio
    async def test_ssti_scan_vulnerable(self):
        """测试SSTI检测发现漏洞"""
        from handlers.detector_handlers import register_detector_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        mock_result = MagicMock()
        mock_result.vulnerable = True
        mock_result.to_dict.return_value = {
            'param': 'template',
            'payload': '{{7*7}}',
            'evidence': '49'
        }

        mock_detector = MagicMock()
        mock_detector.async_detect = AsyncMock(return_value=[mock_result])

        with patch('core.detectors.SSTIDetector') as mock_detector_class:
            mock_detector_class.return_value = mock_detector

            result = await registered_tools['ssti_scan'](
                url="https://example.com/render"
            )

            assert result['success'] is True
            assert result['data']['vulnerable'] is True


class TestXXEScanTool:
    """测试 xxe_scan XXE检测工具"""

    @pytest.mark.asyncio
    async def test_xxe_scan_vulnerable(self):
        """测试XXE检测发现漏洞"""
        from handlers.detector_handlers import register_detector_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        mock_result = MagicMock()
        mock_result.vulnerable = True
        mock_result.to_dict.return_value = {
            'type': 'xxe',
            'evidence': 'External entity processed'
        }

        mock_detector = MagicMock()
        mock_detector.async_detect = AsyncMock(return_value=[mock_result])

        with patch('core.detectors.XXEDetector') as mock_detector_class:
            mock_detector_class.return_value = mock_detector

            result = await registered_tools['xxe_scan'](
                url="https://example.com/xml",
                content_type="application/xml"
            )

            assert result['success'] is True
            assert result['data']['vulnerable'] is True


class TestIDORScanTool:
    """测试 idor_scan IDOR检测工具"""

    @pytest.mark.asyncio
    async def test_idor_scan_vulnerable(self):
        """测试IDOR检测发现漏洞"""
        from handlers.detector_handlers import register_detector_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        mock_result = MagicMock()
        mock_result.vulnerable = True
        mock_result.to_dict.return_value = {
            'param': 'id',
            'test_id': '2',
            'evidence': 'Unauthorized access to user 2 data'
        }

        mock_detector = MagicMock()
        mock_detector.async_detect = AsyncMock(return_value=[mock_result])

        with patch('core.detectors.IDORDetector') as mock_detector_class:
            mock_detector_class.return_value = mock_detector

            result = await registered_tools['idor_scan'](
                url="https://example.com/user/profile",
                id_param="id",
                test_ids=["1", "2", "3"]
            )

            assert result['success'] is True
            assert result['data']['vulnerable'] is True


class TestCORSScanTool:
    """测试 cors_scan CORS检测工具"""

    @pytest.mark.asyncio
    async def test_cors_scan_vulnerable(self):
        """测试CORS检测发现配置问题"""
        from handlers.detector_handlers import register_detector_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        mock_result = MagicMock()
        mock_result.vulnerable = True
        mock_result.to_dict.return_value = {
            'issue': 'wildcard_origin',
            'evidence': 'Access-Control-Allow-Origin: *'
        }

        mock_detector = MagicMock()
        mock_detector.async_detect = AsyncMock(return_value=[mock_result])

        with patch('core.detectors.CORSDetector') as mock_detector_class:
            mock_detector_class.return_value = mock_detector

            result = await registered_tools['cors_scan'](
                url="https://example.com/api"
            )

            assert result['success'] is True
            assert result['data']['vulnerable'] is True


class TestSecurityHeadersScanTool:
    """测试 security_headers_scan 安全头检测工具"""

    @pytest.mark.asyncio
    async def test_security_headers_scan(self):
        """测试安全头检测"""
        from handlers.detector_handlers import register_detector_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_detector_tools(mock_mcp, mock_counter, mock_logger)

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            'header': 'X-Frame-Options',
            'present': False,
            'recommendation': 'Add X-Frame-Options: DENY'
        }

        mock_detector = MagicMock()
        mock_detector.async_detect = AsyncMock(return_value=[mock_result])

        with patch('core.detectors.SecurityHeadersDetector') as mock_detector_class:
            mock_detector_class.return_value = mock_detector

            result = await registered_tools['security_headers_scan'](
                url="https://example.com"
            )

            assert result['success'] is True
            assert 'findings' in result['data']
            assert len(result['data']['findings']) == 1
