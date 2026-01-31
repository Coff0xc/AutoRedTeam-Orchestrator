#!/usr/bin/env python3
"""
侦察工具处理器单元测试
测试 handlers/recon_handlers.py 中的工具注册和执行
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from typing import Dict, Any


class TestReconHandlersRegistration:
    """测试侦察工具注册"""

    def test_register_recon_tools(self):
        """测试注册函数是否正确调用"""
        from handlers.recon_handlers import register_recon_tools

        # 模拟 MCP 实例
        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        # 执行注册
        register_recon_tools(mock_mcp, mock_counter, mock_logger)

        # 验证 counter.add 被调用
        mock_counter.add.assert_called_once_with('recon', 8)

        # 验证 logger.info 被调用
        mock_logger.info.assert_called_once()
        assert "8 个侦察工具" in str(mock_logger.info.call_args)

        # 验证 @mcp.tool() 装饰器被调用了 8 次
        assert mock_mcp.tool.call_count == 8


class TestFullReconTool:
    """测试 full_recon 工具"""

    @pytest.mark.asyncio
    async def test_full_recon_success(self):
        """测试完整侦察成功场景"""
        from handlers.recon_handlers import register_recon_tools

        # 模拟 MCP 和依赖
        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        # 捕获注册的工具函数
        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool

        # 注册工具
        register_recon_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟 StandardReconEngine
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            'dns': {'ip': '1.2.3.4'},
            'ports': [80, 443],
            'fingerprints': ['nginx']
        }

        with patch('core.recon.StandardReconEngine') as mock_engine_class:
            mock_engine = MagicMock()
            mock_engine.run.return_value = mock_result
            mock_engine_class.return_value = mock_engine

            # 调用工具
            result = await registered_tools['full_recon'](
                target="https://example.com",
                quick_mode=True
            )

            # 验证结果
            assert result['success'] is True
            assert result['data']['target'] == "https://example.com"
            assert 'data' in result
            assert result['data']['dns']['ip'] == '1.2.3.4'

            # 验证引擎被正确初始化
            mock_engine_class.assert_called_once()
            mock_engine.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_full_recon_exception(self):
        """测试完整侦察异常处理"""
        from handlers.recon_handlers import register_recon_tools

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
        register_recon_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟异常
        with patch('core.recon.StandardReconEngine') as mock_engine_class:
            mock_engine_class.side_effect = Exception("Network error")

            result = await registered_tools['full_recon'](
                target="https://example.com"
            )

            assert result['success'] is False
            assert 'error' in result
            assert "Network error" in result['error']
            assert result['data']['target'] == "https://example.com"


class TestPortScanTool:
    """测试 port_scan 工具"""

    @pytest.mark.asyncio
    async def test_port_scan_success(self):
        """测试端口扫描成功场景"""
        from handlers.recon_handlers import register_recon_tools

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
        register_recon_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟扫描结果
        mock_port_result = MagicMock()
        mock_port_result.port = 80
        mock_port_result.state = 'open'
        mock_port_result.service = 'http'
        mock_port_result.version = 'nginx 1.18'

        with patch('core.recon.async_scan_ports') as mock_scan:
            mock_scan.return_value = [mock_port_result]

            result = await registered_tools['port_scan'](
                target="192.168.1.1",
                ports="1-1000",
                timeout=2.0
            )

            assert result['success'] is True
            assert result['data']['target'] == "192.168.1.1"
            assert result['data']['total_open'] == 1
            assert len(result['data']['open_ports']) == 1
            assert result['data']['open_ports'][0]['port'] == 80
            assert result['data']['open_ports'][0]['service'] == 'http'

    @pytest.mark.asyncio
    async def test_port_scan_no_open_ports(self):
        """测试端口扫描无开放端口"""
        from handlers.recon_handlers import register_recon_tools

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
        register_recon_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟无开放端口
        mock_port_result = MagicMock()
        mock_port_result.state = 'closed'

        with patch('core.recon.async_scan_ports') as mock_scan:
            mock_scan.return_value = [mock_port_result]

            result = await registered_tools['port_scan'](
                target="192.168.1.1"
            )

            assert result['success'] is True
            assert result['data']['total_open'] == 0
            assert len(result['data']['open_ports']) == 0


class TestFingerprintTool:
    """测试 fingerprint 工具"""

    @pytest.mark.asyncio
    async def test_fingerprint_success(self):
        """测试指纹识别成功"""
        from handlers.recon_handlers import register_recon_tools

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
        register_recon_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟指纹结果
        mock_fingerprint = MagicMock()
        mock_fingerprint.name = 'nginx'
        mock_fingerprint.category = MagicMock()
        mock_fingerprint.category.value = 'web_server'
        mock_fingerprint.version = '1.18.0'
        mock_fingerprint.confidence = 0.95

        with patch('core.recon.identify_fingerprints') as mock_identify:
            mock_identify.return_value = [mock_fingerprint]

            result = await registered_tools['fingerprint'](
                url="https://example.com"
            )

            assert result['success'] is True
            assert result['data']['url'] == "https://example.com"
            assert result['data']['count'] == 1
            assert len(result['data']['fingerprints']) == 1
            assert result['data']['fingerprints'][0]['name'] == 'nginx'
            assert result['data']['fingerprints'][0]['version'] == '1.18.0'


class TestSubdomainEnumTool:
    """测试 subdomain_enum 工具"""

    @pytest.mark.asyncio
    async def test_subdomain_enum_success(self):
        """测试子域名枚举成功"""
        from handlers.recon_handlers import register_recon_tools

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
        register_recon_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟子域名结果
        mock_subdomain = MagicMock()
        mock_subdomain.subdomain = 'www.example.com'
        mock_subdomain.ip = '1.2.3.4'
        mock_subdomain.source = 'dns_brute'

        with patch('core.recon.async_enumerate_subdomains') as mock_enum:
            mock_enum.return_value = [mock_subdomain]

            result = await registered_tools['subdomain_enum'](
                domain="example.com",
                limit=100
            )

            assert result['success'] is True
            assert result['data']['domain'] == "example.com"
            assert result['data']['count'] == 1
            assert result['data']['subdomains'][0]['subdomain'] == 'www.example.com'

    @pytest.mark.asyncio
    async def test_subdomain_enum_with_limit(self):
        """测试子域名枚举限制数量"""
        from handlers.recon_handlers import register_recon_tools

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
        register_recon_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟多个子域名
        mock_subdomains = []
        for i in range(150):
            mock_sub = MagicMock()
            mock_sub.subdomain = f'sub{i}.example.com'
            mock_sub.ip = f'1.2.3.{i % 255}'
            mock_sub.source = 'dns_brute'
            mock_subdomains.append(mock_sub)

        with patch('core.recon.async_enumerate_subdomains') as mock_enum:
            mock_enum.return_value = mock_subdomains

            result = await registered_tools['subdomain_enum'](
                domain="example.com",
                limit=50
            )

            assert result['success'] is True
            assert result['data']['count'] == 50  # 应该被限制到 50


class TestDNSLookupTool:
    """测试 dns_lookup 工具"""

    @pytest.mark.asyncio
    async def test_dns_lookup_success(self):
        """测试DNS查询成功"""
        from handlers.recon_handlers import register_recon_tools

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
        register_recon_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟DNS结果
        mock_dns_result = MagicMock()
        mock_dns_result.to_dict.return_value = {
            'A': ['1.2.3.4'],
            'MX': ['mail.example.com'],
            'NS': ['ns1.example.com']
        }

        with patch('core.recon.get_dns_records') as mock_dns:
            mock_dns.return_value = mock_dns_result

            result = await registered_tools['dns_lookup'](
                domain="example.com"
            )

            assert result['success'] is True
            assert result['data']['domain'] == "example.com"
            assert 'records' in result['data']
            assert result['data']['records']['A'] == ['1.2.3.4']


class TestWAFDetectTool:
    """测试 waf_detect 工具"""

    @pytest.mark.asyncio
    async def test_waf_detect_found(self):
        """测试WAF检测发现WAF"""
        from handlers.recon_handlers import register_recon_tools

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
        register_recon_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟WAF检测结果
        mock_waf_result = MagicMock()
        mock_waf_result.detected = True
        mock_waf_result.name = 'Cloudflare'
        mock_waf_result.confidence = 0.9

        with patch('core.recon.detect_waf') as mock_waf:
            mock_waf.return_value = mock_waf_result

            result = await registered_tools['waf_detect'](
                url="https://example.com"
            )

            assert result['success'] is True
            assert result['data']['waf_detected'] is True
            assert result['data']['waf_name'] == 'Cloudflare'
            assert result['data']['confidence'] == 0.9

    @pytest.mark.asyncio
    async def test_waf_detect_not_found(self):
        """测试WAF检测未发现WAF"""
        from handlers.recon_handlers import register_recon_tools

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
        register_recon_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟未检测到WAF
        mock_waf_result = MagicMock()
        mock_waf_result.detected = False
        mock_waf_result.name = None
        mock_waf_result.confidence = None

        with patch('core.recon.detect_waf') as mock_waf:
            mock_waf.return_value = mock_waf_result

            result = await registered_tools['waf_detect'](
                url="https://example.com"
            )

            assert result['success'] is True
            assert result['data']['waf_detected'] is False
            assert result['data']['waf_name'] is None
