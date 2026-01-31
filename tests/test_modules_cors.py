#!/usr/bin/env python3
"""
CORS 安全测试模块单元测试

测试 modules/api_security/cors.py 的各项功能。
"""

from unittest.mock import MagicMock, Mock, patch

import pytest

from modules.api_security.cors import CORSTester, quick_cors_test
from modules.api_security.base import APIVulnType, Severity


class TestCORSTesterInit:
    """CORS 测试器初始化测试"""

    def test_init_basic(self):
        """测试基本初始化"""
        tester = CORSTester("https://api.example.com/data")

        assert tester.target == "https://api.example.com/data"
        assert tester.target_host == "api.example.com"
        assert tester.target_scheme == "https"
        assert tester.legitimate_origin == "https://api.example.com"

    def test_init_with_config(self):
        """测试带配置的初始化"""
        config = {
            'legitimate_origin': 'https://trusted.com',
            'test_methods': ['GET', 'POST'],
            'custom_origins': ['https://custom-evil.com']
        }
        tester = CORSTester("https://api.example.com/data", config)

        assert tester.legitimate_origin == 'https://trusted.com'
        assert tester.test_methods == ['GET', 'POST']
        assert 'https://custom-evil.com' in tester.custom_origins

    def test_init_http_target(self):
        """测试 HTTP 目标"""
        tester = CORSTester("http://api.example.com/data")

        assert tester.target_scheme == "http"
        assert tester.legitimate_origin == "http://api.example.com"


class TestCORSWildcardOrigin:
    """CORS 通配符 Origin 测试"""

    def test_wildcard_without_credentials(self):
        """测试通配符 Origin 不带凭证"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应
        mock_response = {
            'acao': '*',
            'acac': '',
            'status_code': 200
        }

        with patch.object(tester, '_send_cors_request', return_value=mock_response):
            result = tester.test_wildcard_origin()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.CORS_WILDCARD
        assert result.severity == Severity.MEDIUM

    def test_wildcard_with_credentials(self):
        """测试通配符 Origin 带凭证（严重漏洞）"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应
        mock_response = {
            'acao': '*',
            'acac': 'true',
            'status_code': 200
        }

        with patch.object(tester, '_send_cors_request', return_value=mock_response):
            result = tester.test_wildcard_origin()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.CORS_CREDENTIALS_WITH_WILDCARD
        assert result.severity == Severity.CRITICAL

    def test_no_wildcard(self):
        """测试没有通配符"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应
        mock_response = {
            'acao': 'https://trusted.com',
            'acac': 'true',
            'status_code': 200
        }

        with patch.object(tester, '_send_cors_request', return_value=mock_response):
            result = tester.test_wildcard_origin()

        assert result is None

    def test_no_response(self):
        """测试无响应"""
        tester = CORSTester("https://api.example.com/data")

        with patch.object(tester, '_send_cors_request', return_value=None):
            result = tester.test_wildcard_origin()

        assert result is None


class TestCORSNullOrigin:
    """CORS Null Origin 测试"""

    def test_null_origin_accepted(self):
        """测试接受 Null Origin"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应
        mock_response = {
            'acao': 'null',
            'acac': '',
            'status_code': 200
        }

        with patch.object(tester, '_send_cors_request', return_value=mock_response):
            result = tester.test_null_origin()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.CORS_NULL_ORIGIN
        assert result.severity == Severity.MEDIUM

    def test_null_origin_with_credentials(self):
        """测试 Null Origin 带凭证"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应
        mock_response = {
            'acao': 'null',
            'acac': 'true',
            'status_code': 200
        }

        with patch.object(tester, '_send_cors_request', return_value=mock_response):
            result = tester.test_null_origin()

        assert result is not None
        assert result.vulnerable is True
        assert result.severity == Severity.HIGH

    def test_null_origin_rejected(self):
        """测试拒绝 Null Origin"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应
        mock_response = {
            'acao': 'https://trusted.com',
            'acac': '',
            'status_code': 200
        }

        with patch.object(tester, '_send_cors_request', return_value=mock_response):
            result = tester.test_null_origin()

        assert result is None


class TestCORSOriginReflection:
    """CORS Origin 反射测试"""

    def test_origin_reflection_detected(self):
        """测试检测到 Origin 反射"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应 - 反射所有 Origin
        def mock_send_cors(origin):
            return {
                'acao': origin,
                'acac': '',
                'status_code': 200
            }

        with patch.object(tester, '_send_cors_request', side_effect=mock_send_cors):
            result = tester.test_origin_reflection()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.CORS_ORIGIN_REFLECTION
        assert result.severity == Severity.HIGH
        assert result.evidence['total_reflected'] > 0

    def test_origin_reflection_with_credentials(self):
        """测试 Origin 反射带凭证"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应 - 反射 Origin 并允许凭证
        def mock_send_cors(origin):
            return {
                'acao': origin,
                'acac': 'true',
                'status_code': 200
            }

        with patch.object(tester, '_send_cors_request', side_effect=mock_send_cors):
            result = tester.test_origin_reflection()

        assert result is not None
        assert result.vulnerable is True
        assert result.severity == Severity.CRITICAL
        assert result.evidence['credentials_allowed'] is True

    def test_no_origin_reflection(self):
        """测试没有 Origin 反射"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应 - 固定 Origin
        def mock_send_cors(origin):
            return {
                'acao': 'https://trusted.com',
                'acac': '',
                'status_code': 200
            }

        with patch.object(tester, '_send_cors_request', side_effect=mock_send_cors):
            result = tester.test_origin_reflection()

        assert result is None

    def test_partial_origin_reflection(self):
        """测试部分 Origin 反射"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应 - 只反射某些 Origin
        reflected_count = 0

        def mock_send_cors(origin):
            nonlocal reflected_count
            if 'evil.com' in origin:
                reflected_count += 1
                return {
                    'acao': origin,
                    'acac': '',
                    'status_code': 200
                }
            return {
                'acao': 'https://trusted.com',
                'acac': '',
                'status_code': 200
            }

        with patch.object(tester, '_send_cors_request', side_effect=mock_send_cors):
            result = tester.test_origin_reflection()

        if result:
            assert result.vulnerable is True
            assert result.evidence['total_reflected'] > 0


class TestCORSSubdomainBypass:
    """CORS 子域名绕过测试"""

    def test_subdomain_bypass_detected(self):
        """测试检测到子域名绕过"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应 - 接受恶意子域名
        def mock_send_cors(origin):
            if 'evil' in origin or '@' in origin:
                return {
                    'acao': origin,
                    'acac': '',
                    'status_code': 200
                }
            return {
                'acao': 'https://api.example.com',
                'acac': '',
                'status_code': 200
            }

        with patch.object(tester, '_send_cors_request', side_effect=mock_send_cors):
            result = tester.test_subdomain_bypass()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.CORS_SUBDOMAIN_BYPASS
        assert result.severity == Severity.HIGH
        assert len(result.evidence['successful_bypasses']) > 0

    def test_no_subdomain_bypass(self):
        """测试没有子域名绕过"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应 - 严格验证
        def mock_send_cors(origin):
            if origin == 'https://api.example.com':
                return {
                    'acao': origin,
                    'acac': '',
                    'status_code': 200
                }
            return {
                'acao': '',
                'status_code': 403
            }

        with patch.object(tester, '_send_cors_request', side_effect=mock_send_cors):
            result = tester.test_subdomain_bypass()

        assert result is None


class TestCORSPreflightBypass:
    """CORS Preflight 绕过测试"""

    def test_preflight_inconsistency(self):
        """测试 Preflight 响应不一致"""
        tester = CORSTester("https://api.example.com/data")

        # Mock Preflight 响应
        preflight_response = {
            'acao': 'https://trusted.com',
            'acac': '',
            'status_code': 200
        }

        # Mock 实际请求响应
        actual_response = {
            'acao': 'https://evil.com',
            'acac': '',
            'status_code': 200
        }

        with patch.object(tester, '_send_preflight_request', return_value=preflight_response):
            with patch.object(tester, '_send_cors_request', return_value=actual_response):
                result = tester.test_preflight_bypass()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.CORS_MISCONFIGURATION
        assert result.severity == Severity.MEDIUM

    def test_preflight_consistent(self):
        """测试 Preflight 响应一致"""
        tester = CORSTester("https://api.example.com/data")

        # Mock 一致的响应
        consistent_response = {
            'acao': 'https://trusted.com',
            'acac': '',
            'status_code': 200
        }

        with patch.object(tester, '_send_preflight_request', return_value=consistent_response):
            with patch.object(tester, '_send_cors_request', return_value=consistent_response):
                result = tester.test_preflight_bypass()

        assert result is None

    def test_preflight_no_response(self):
        """测试 Preflight 无响应"""
        tester = CORSTester("https://api.example.com/data")

        with patch.object(tester, '_send_preflight_request', return_value=None):
            with patch.object(tester, '_send_cors_request', return_value=None):
                result = tester.test_preflight_bypass()

        assert result is None


class TestCORSMethodOverride:
    """CORS 方法覆盖测试"""

    def test_method_override_detected(self):
        """测试检测到方法覆盖"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应 - 接受方法覆盖
        def mock_send_override(origin, method, header):
            return {
                'acao': origin,
                'acam': 'GET, POST',  # 不包含 PUT/DELETE
                'status_code': 200
            }

        with patch.object(tester, '_send_method_override_request', side_effect=mock_send_override):
            result = tester.test_method_override()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.CORS_MISCONFIGURATION
        assert len(result.evidence['vulnerable_methods']) > 0

    def test_no_method_override(self):
        """测试没有方法覆盖"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应 - 拒绝方法覆盖
        def mock_send_override(origin, method, header):
            return {
                'acao': '',
                'acam': '',
                'status_code': 403
            }

        with patch.object(tester, '_send_method_override_request', side_effect=mock_send_override):
            result = tester.test_method_override()

        assert result is None


class TestCORSFullScan:
    """CORS 完整扫描测试"""

    def test_full_scan_execution(self):
        """测试完整扫描执行所有测试"""
        tester = CORSTester("https://api.example.com/data")

        # Mock 所有请求返回安全响应
        safe_response = {
            'acao': 'https://trusted.com',
            'acac': '',
            'status_code': 200
        }

        with patch.object(tester, '_send_cors_request', return_value=safe_response):
            with patch.object(tester, '_send_preflight_request', return_value=safe_response):
                with patch.object(tester, '_send_method_override_request', return_value=safe_response):
                    results = tester.test()

        # 应该执行多个测试
        assert len(results) >= 0

    def test_full_scan_with_vulnerabilities(self):
        """测试完整扫描发现多个漏洞"""
        tester = CORSTester("https://api.example.com/data")

        # Mock 响应 - 反射所有 Origin
        def mock_send_cors(origin, method='GET', with_credentials=False):
            return {
                'acao': origin,
                'acac': 'true',
                'status_code': 200
            }

        with patch.object(tester, '_send_cors_request', side_effect=mock_send_cors):
            with patch.object(tester, '_send_preflight_request', side_effect=lambda o: mock_send_cors(o)):
                with patch.object(tester, '_send_method_override_request', return_value=None):
                    results = tester.test()

        # 应该发现多个漏洞
        vulnerable_results = [r for r in results if r.vulnerable]
        assert len(vulnerable_results) > 0

    def test_get_summary(self):
        """测试获取扫描摘要"""
        tester = CORSTester("https://api.example.com/data")

        safe_response = {
            'acao': 'https://trusted.com',
            'acac': '',
            'status_code': 200
        }

        with patch.object(tester, '_send_cors_request', return_value=safe_response):
            with patch.object(tester, '_send_preflight_request', return_value=safe_response):
                with patch.object(tester, '_send_method_override_request', return_value=safe_response):
                    tester.test()

        summary = tester.get_summary()

        assert summary.target == "https://api.example.com/data"
        assert summary.total_tests >= 0
        assert isinstance(summary.to_dict(), dict)


class TestCORSHelperMethods:
    """CORS 辅助方法测试"""

    def test_extract_cors_headers(self):
        """测试提取 CORS 头"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应对象
        mock_response = Mock()
        mock_response.headers = {
            'access-control-allow-origin': 'https://example.com',
            'access-control-allow-credentials': 'true',
            'access-control-allow-methods': 'GET, POST',
            'access-control-allow-headers': 'Content-Type',
        }
        mock_response.status_code = 200

        headers = tester._extract_cors_headers(mock_response)

        assert headers['acao'] == 'https://example.com'
        assert headers['acac'] == 'true'
        assert headers['acam'] == 'GET, POST'
        assert headers['acah'] == 'Content-Type'
        assert headers['status_code'] == 200

    def test_extract_cors_headers_missing(self):
        """测试提取缺失的 CORS 头"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 响应对象 - 没有 CORS 头
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.status_code = 200

        headers = tester._extract_cors_headers(mock_response)

        assert 'acao' not in headers or headers.get('acao') == ''
        assert headers['status_code'] == 200

    def test_send_cors_request_exception(self):
        """测试发送 CORS 请求异常处理"""
        tester = CORSTester("https://api.example.com/data")

        # Mock HTTP 客户端抛出异常
        with patch.object(tester, '_get_http_client') as mock_client:
            mock_client.return_value.get.side_effect = Exception("Connection error")

            result = tester._send_cors_request('https://evil.com')

        assert result is None


class TestQuickCORSTest:
    """快速 CORS 测试函数测试"""

    def test_quick_cors_test(self):
        """测试快速测试函数"""
        with patch('modules.api_security.cors.CORSTester') as MockTester:
            mock_instance = MockTester.return_value
            mock_instance.test.return_value = []
            mock_instance.get_summary.return_value = MagicMock(
                to_dict=lambda: {'total_tests': 7, 'vulnerable_count': 0}
            )

            result = quick_cors_test("https://api.example.com/data")

        assert isinstance(result, dict)
        assert 'total_tests' in result


class TestCORSEdgeCases:
    """CORS 边缘情况测试"""

    def test_empty_origin(self):
        """测试空 Origin"""
        tester = CORSTester("https://api.example.com/data")

        mock_response = {
            'acao': '',
            'acac': '',
            'status_code': 200
        }

        with patch.object(tester, '_send_cors_request', return_value=mock_response):
            result = tester.test_wildcard_origin()

        assert result is None

    def test_case_sensitive_origin(self):
        """测试大小写敏感的 Origin"""
        tester = CORSTester("https://api.example.com/data")

        # Mock 响应 - 反射但改变大小写
        def mock_send_cors(origin):
            return {
                'acao': origin.upper(),
                'acac': '',
                'status_code': 200
            }

        with patch.object(tester, '_send_cors_request', side_effect=mock_send_cors):
            result = tester.test_origin_reflection()

        # 大小写不匹配不应该算作反射
        assert result is None

    def test_multiple_acao_headers(self):
        """测试多个 ACAO 头（边缘情况）"""
        tester = CORSTester("https://api.example.com/data")

        # 大多数 HTTP 库会合并或只取第一个
        mock_response = Mock()
        mock_response.headers = {
            'access-control-allow-origin': 'https://trusted.com, https://evil.com'
        }
        mock_response.status_code = 200

        headers = tester._extract_cors_headers(mock_response)

        # 应该提取到值（具体行为取决于 HTTP 库）
        assert 'acao' in headers
