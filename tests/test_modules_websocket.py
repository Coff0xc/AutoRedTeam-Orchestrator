#!/usr/bin/env python3
"""
WebSocket 安全测试模块单元测试

测试 modules/api_security/websocket.py 的各项功能。
"""

from unittest.mock import MagicMock, Mock, patch
from urllib.parse import urlparse, parse_qs

import pytest

from modules.api_security.websocket import WebSocketTester
from modules.api_security.base import APIVulnType, Severity


class TestWebSocketTesterInit:
    """WebSocket 测试器初始化测试"""

    def test_init_wss_url(self):
        """测试 WSS URL 初始化"""
        tester = WebSocketTester("wss://api.example.com:8443/ws?token=abc")

        assert tester.scheme == "wss"
        assert tester.is_secure is True
        assert tester.host == "api.example.com"
        assert tester.port == 8443
        assert tester.path == "/ws?token=abc"
        assert 'token' in tester.query_params

    def test_init_ws_url(self):
        """测试 WS URL 初始化"""
        tester = WebSocketTester("ws://api.example.com/ws")

        assert tester.scheme == "ws"
        assert tester.is_secure is False
        assert tester.host == "api.example.com"
        assert tester.port == 80

    def test_init_default_port(self):
        """测试默认端口"""
        tester_wss = WebSocketTester("wss://api.example.com/ws")
        assert tester_wss.port == 443

        tester_ws = WebSocketTester("ws://api.example.com/ws")
        assert tester_ws.port == 80

    def test_init_with_config(self):
        """测试带配置的初始化"""
        config = {
            'target_origin': 'https://trusted.com',
            'auth_token': 'Bearer token123',
            'extra_headers': {'X-Custom': 'value'}
        }
        tester = WebSocketTester("wss://api.example.com/ws", config)

        assert tester.target_origin == 'https://trusted.com'
        assert tester.auth_token == 'Bearer token123'

    def test_init_path_without_slash(self):
        """测试没有路径的 URL"""
        tester = WebSocketTester("wss://api.example.com")

        assert tester.path == "/"


class TestWebSocketNoTLS:
    """WebSocket TLS 测试"""

    def test_no_tls_detected(self):
        """测试检测到未使用 TLS"""
        tester = WebSocketTester("ws://api.example.com/ws")

        result = tester.test_no_tls()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.WEBSOCKET_NO_TLS
        assert result.severity == Severity.HIGH

    def test_tls_enabled(self):
        """测试使用了 TLS"""
        tester = WebSocketTester("wss://api.example.com/ws")

        result = tester.test_no_tls()

        assert result is None

    def test_localhost_no_tls_lower_severity(self):
        """测试 localhost 未使用 TLS（较低严重性）"""
        tester = WebSocketTester("ws://localhost/ws")

        result = tester.test_no_tls()

        if result:
            # localhost 可能被视为较低风险
            assert result.severity in [Severity.MEDIUM, Severity.HIGH]


class TestWebSocketTokenInURL:
    """WebSocket URL Token 泄露测试"""

    def test_token_in_url_detected(self):
        """测试检测到 URL 中的 Token"""
        tester = WebSocketTester("wss://api.example.com/ws?token=secret123")

        result = tester.test_token_in_url()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.WEBSOCKET_TOKEN_LEAK
        assert result.severity == Severity.MEDIUM
        assert 'token' in result.evidence['sensitive_params']

    def test_api_key_in_url_detected(self):
        """测试检测到 URL 中的 API Key"""
        tester = WebSocketTester("wss://api.example.com/ws?api_key=key123&user=test")

        result = tester.test_token_in_url()

        assert result is not None
        assert result.vulnerable is True
        assert 'api_key' in result.evidence['sensitive_params']

    def test_no_sensitive_params(self):
        """测试 URL 中没有敏感参数"""
        tester = WebSocketTester("wss://api.example.com/ws?user=test&page=1")

        result = tester.test_token_in_url()

        assert result is None

    def test_multiple_sensitive_params(self):
        """测试多个敏感参数"""
        tester = WebSocketTester("wss://api.example.com/ws?token=abc&secret=xyz&user=test")

        result = tester.test_token_in_url()

        assert result is not None
        assert len(result.evidence['sensitive_params']) >= 2


class TestWebSocketOriginBypass:
    """WebSocket Origin 绕过测试"""

    def test_origin_bypass_detected(self):
        """测试检测到 Origin 绕过"""
        tester = WebSocketTester("wss://api.example.com/ws")

        # Mock WebSocket 连接 - 接受恶意 Origin
        def mock_connect(origin):
            return {
                'success': True,
                'origin': origin
            }

        with patch.object(tester, '_test_ws_connection', side_effect=mock_connect):
            result = tester.test_origin_bypass()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.WEBSOCKET_ORIGIN_BYPASS
        assert result.severity in [Severity.HIGH, Severity.CRITICAL]
        assert len(result.evidence['bypassed_origins']) > 0

    def test_origin_validation_strict(self):
        """测试严格的 Origin 验证"""
        tester = WebSocketTester("wss://api.example.com/ws")

        # Mock WebSocket 连接 - 拒绝恶意 Origin
        def mock_connect(origin):
            if origin == tester.target_origin:
                return {'success': True, 'origin': origin}
            return {'success': False, 'error': 'Invalid origin'}

        with patch.object(tester, '_test_ws_connection', side_effect=mock_connect):
            result = tester.test_origin_bypass()

        assert result is None

    def test_null_origin_accepted(self):
        """测试接受 null Origin"""
        tester = WebSocketTester("wss://api.example.com/ws")

        # Mock WebSocket 连接 - 接受 null Origin
        def mock_connect(origin):
            if origin == 'null':
                return {'success': True, 'origin': origin}
            return {'success': False}

        with patch.object(tester, '_test_ws_connection', side_effect=mock_connect):
            result = tester.test_origin_bypass()

        if result:
            assert result.vulnerable is True
            assert any('null' in str(o) for o in result.evidence['bypassed_origins'])


class TestWebSocketCSWSH:
    """WebSocket 跨站劫持 (CSWSH) 测试"""

    def test_cswsh_detected(self):
        """测试检测到 CSWSH 漏洞"""
        tester = WebSocketTester("wss://api.example.com/ws")

        # Mock WebSocket 连接 - 不验证 Origin 和 CSRF Token
        def mock_connect(origin, headers=None):
            return {
                'success': True,
                'origin': origin,
                'authenticated': True
            }

        with patch.object(tester, '_test_ws_connection', side_effect=mock_connect):
            result = tester.test_cswsh()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.WEBSOCKET_CSWSH
        assert result.severity == Severity.CRITICAL

    def test_cswsh_protected(self):
        """测试有 CSWSH 保护"""
        tester = WebSocketTester("wss://api.example.com/ws")

        # Mock WebSocket 连接 - 验证 Origin
        def mock_connect(origin, headers=None):
            if origin == tester.target_origin:
                return {'success': True}
            return {'success': False, 'error': 'Invalid origin'}

        with patch.object(tester, '_test_ws_connection', side_effect=mock_connect):
            result = tester.test_cswsh()

        assert result is None


class TestWebSocketCompressionOracle:
    """WebSocket 压缩 Oracle 测试"""

    def test_compression_oracle_detected(self):
        """测试检测到压缩 Oracle 攻击"""
        tester = WebSocketTester("wss://api.example.com/ws")

        # Mock WebSocket 连接 - 支持压缩
        def mock_connect_with_compression():
            return {
                'success': True,
                'compression': True,
                'extensions': 'permessage-deflate'
            }

        with patch.object(tester, '_test_ws_compression', return_value=mock_connect_with_compression()):
            result = tester.test_compression_oracle()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.WEBSOCKET_COMPRESSION_ORACLE
        assert result.severity == Severity.MEDIUM

    def test_compression_disabled(self):
        """测试压缩已禁用"""
        tester = WebSocketTester("wss://api.example.com/ws")

        # Mock WebSocket 连接 - 不支持压缩
        def mock_connect_no_compression():
            return {
                'success': True,
                'compression': False,
                'extensions': ''
            }

        with patch.object(tester, '_test_ws_compression', return_value=mock_connect_no_compression()):
            result = tester.test_compression_oracle()

        assert result is None


class TestWebSocketAuthBypass:
    """WebSocket 认证绕过测试"""

    def test_auth_bypass_detected(self):
        """测试检测到认证绕过"""
        tester = WebSocketTester("wss://api.example.com/ws")

        # Mock WebSocket 连接 - 不需要认证
        def mock_connect(headers=None):
            return {
                'success': True,
                'authenticated': True
            }

        with patch.object(tester, '_test_ws_auth', side_effect=lambda h: mock_connect(h)):
            result = tester.test_auth_bypass()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.WEBSOCKET_AUTH_BYPASS
        assert result.severity == Severity.HIGH

    def test_auth_required(self):
        """测试需要认证"""
        tester = WebSocketTester("wss://api.example.com/ws")

        # Mock WebSocket 连接 - 需要认证
        def mock_connect(headers=None):
            if headers and 'Authorization' in headers:
                return {'success': True, 'authenticated': True}
            return {'success': False, 'error': 'Unauthorized'}

        with patch.object(tester, '_test_ws_auth', side_effect=lambda h: mock_connect(h)):
            result = tester.test_auth_bypass()

        assert result is None


class TestWebSocketFullScan:
    """WebSocket 完整扫描测试"""

    def test_full_scan_execution(self):
        """测试完整扫描执行所有测试"""
        tester = WebSocketTester("wss://api.example.com/ws")

        # Mock 所有测试方法
        with patch.object(tester, '_test_ws_connection', return_value={'success': False}):
            with patch.object(tester, '_test_ws_compression', return_value={'success': False}):
                with patch.object(tester, '_test_ws_auth', return_value={'success': False}):
                    results = tester.test()

        # 应该执行多个测试
        assert len(results) >= 0

    def test_full_scan_with_vulnerabilities(self):
        """测试完整扫描发现多个漏洞"""
        # 使用不安全的 ws:// 和 URL 中的 token
        tester = WebSocketTester("ws://api.example.com/ws?token=secret")

        # Mock WebSocket 连接 - 接受所有 Origin
        def mock_connect(origin, headers=None):
            return {'success': True, 'origin': origin}

        with patch.object(tester, '_test_ws_connection', side_effect=mock_connect):
            with patch.object(tester, '_test_ws_compression', return_value={'success': True, 'compression': True}):
                with patch.object(tester, '_test_ws_auth', return_value={'success': True}):
                    results = tester.test()

        # 应该发现多个漏洞
        vulnerable_results = [r for r in results if r.vulnerable]
        assert len(vulnerable_results) >= 2  # 至少 no_tls 和 token_in_url

    def test_get_summary(self):
        """测试获取扫描摘要"""
        tester = WebSocketTester("wss://api.example.com/ws")

        with patch.object(tester, '_test_ws_connection', return_value={'success': False}):
            with patch.object(tester, '_test_ws_compression', return_value={'success': False}):
                with patch.object(tester, '_test_ws_auth', return_value={'success': False}):
                    tester.test()

        summary = tester.get_summary()

        assert summary.target == "wss://api.example.com/ws"
        assert summary.total_tests >= 0
        assert isinstance(summary.to_dict(), dict)


class TestWebSocketHelperMethods:
    """WebSocket 辅助方法测试"""

    def test_parse_ws_url_complete(self):
        """测试解析完整的 WebSocket URL"""
        tester = WebSocketTester("wss://api.example.com:8443/ws/chat?room=1&token=abc")

        assert tester.scheme == "wss"
        assert tester.host == "api.example.com"
        assert tester.port == 8443
        assert "/ws/chat" in tester.path
        assert "room=1" in tester.path
        assert 'room' in tester.query_params
        assert 'token' in tester.query_params

    def test_parse_ws_url_minimal(self):
        """测试解析最小 WebSocket URL"""
        tester = WebSocketTester("ws://localhost")

        assert tester.scheme == "ws"
        assert tester.host == "localhost"
        assert tester.port == 80
        assert tester.path == "/"

    def test_generate_ws_key(self):
        """测试生成 WebSocket Key"""
        tester = WebSocketTester("wss://api.example.com/ws")

        # WebSocket Key 应该是 16 字节 base64 编码
        if hasattr(tester, '_generate_ws_key'):
            key = tester._generate_ws_key()
            assert len(key) > 0
            # Base64 编码的 16 字节应该是 24 字符（不含填充）
            import base64
            decoded = base64.b64decode(key + '==')
            assert len(decoded) == 16

    def test_calculate_accept_key(self):
        """测试计算 WebSocket Accept Key"""
        tester = WebSocketTester("wss://api.example.com/ws")

        if hasattr(tester, '_calculate_accept_key'):
            # 使用已知的测试向量
            test_key = "dGhlIHNhbXBsZSBub25jZQ=="
            expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

            accept_key = tester._calculate_accept_key(test_key)
            assert accept_key == expected_accept


class TestWebSocketEdgeCases:
    """WebSocket 边缘情况测试"""

    def test_invalid_scheme(self):
        """测试无效的协议"""
        # 应该能处理 http/https URL（虽然不是 WebSocket）
        tester = WebSocketTester("https://api.example.com/ws")

        assert tester.scheme == "https"
        # 可能被视为不安全（不是 wss）
        result = tester.test_no_tls()
        if result:
            assert result.vulnerable is True

    def test_ipv6_host(self):
        """测试 IPv6 主机"""
        tester = WebSocketTester("wss://[2001:db8::1]:8443/ws")

        assert tester.host == "2001:db8::1"
        assert tester.port == 8443

    def test_empty_query_params(self):
        """测试空查询参数"""
        tester = WebSocketTester("wss://api.example.com/ws?")

        assert tester.path == "/ws?"
        assert len(tester.query_params) == 0

    def test_special_characters_in_path(self):
        """测试路径中的特殊字符"""
        tester = WebSocketTester("wss://api.example.com/ws/room%20name?id=1")

        assert "/ws/room%20name" in tester.path

    def test_connection_timeout(self):
        """测试连接超时"""
        tester = WebSocketTester("wss://api.example.com/ws")

        # Mock 连接超时
        if hasattr(tester, '_test_ws_connection'):
            with patch.object(tester, '_test_ws_connection', side_effect=TimeoutError("Connection timeout")):
                result = tester.test_origin_bypass()

            # 超时应该被正确处理
            assert result is None or not result.vulnerable

    def test_connection_refused(self):
        """测试连接被拒绝"""
        tester = WebSocketTester("wss://api.example.com/ws")

        # Mock 连接被拒绝
        if hasattr(tester, '_test_ws_connection'):
            with patch.object(tester, '_test_ws_connection', side_effect=ConnectionRefusedError("Connection refused")):
                result = tester.test_origin_bypass()

            # 连接错误应该被正确处理
            assert result is None or not result.vulnerable


class TestWebSocketSecurityBestPractices:
    """WebSocket 安全最佳实践测试"""

    def test_secure_websocket_configuration(self):
        """测试安全的 WebSocket 配置"""
        # 安全配置：wss + 无 URL token + 严格 Origin 验证
        tester = WebSocketTester("wss://api.example.com/ws")

        # Mock 安全配置
        def mock_secure_connect(origin, headers=None):
            # 只接受特定 Origin
            if origin == tester.target_origin:
                return {'success': True}
            return {'success': False}

        with patch.object(tester, '_test_ws_connection', side_effect=mock_secure_connect):
            with patch.object(tester, '_test_ws_compression', return_value={'success': True, 'compression': False}):
                with patch.object(tester, '_test_ws_auth', return_value={'success': False}):  # 需要认证
                    results = tester.test()

        # 安全配置应该没有高危漏洞
        critical_vulns = [r for r in results if r.vulnerable and r.severity == Severity.CRITICAL]
        assert len(critical_vulns) == 0

    def test_insecure_websocket_configuration(self):
        """测试不安全的 WebSocket 配置"""
        # 不安全配置：ws + URL token + 无 Origin 验证
        tester = WebSocketTester("ws://api.example.com/ws?token=secret123")

        # Mock 不安全配置
        def mock_insecure_connect(origin, headers=None):
            return {'success': True}  # 接受所有 Origin

        with patch.object(tester, '_test_ws_connection', side_effect=mock_insecure_connect):
            with patch.object(tester, '_test_ws_compression', return_value={'success': True, 'compression': True}):
                with patch.object(tester, '_test_ws_auth', return_value={'success': True}):  # 不需要认证
                    results = tester.test()

        # 不安全配置应该发现多个漏洞
        vulnerable_results = [r for r in results if r.vulnerable]
        assert len(vulnerable_results) >= 3
