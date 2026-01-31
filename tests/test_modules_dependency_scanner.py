#!/usr/bin/env python3
"""
依赖扫描模块单元测试

测试 modules/supply_chain/dependency_scanner.py 的各项功能。
"""

import json
from unittest.mock import MagicMock, Mock, patch

import pytest

from modules.supply_chain.dependency_scanner import (
    DependencyScanner,
    DependencyVuln,
    VulnSeverity
)


class TestVulnSeverity:
    """漏洞严重性枚举测试"""

    def test_severity_values(self):
        """测试严重性值"""
        assert VulnSeverity.CRITICAL.value == "critical"
        assert VulnSeverity.HIGH.value == "high"
        assert VulnSeverity.MEDIUM.value == "medium"
        assert VulnSeverity.LOW.value == "low"
        assert VulnSeverity.UNKNOWN.value == "unknown"


class TestDependencyVuln:
    """依赖漏洞数据类测试"""

    def test_create_vuln_basic(self):
        """测试创建基本漏洞"""
        vuln = DependencyVuln(
            package_name="requests",
            installed_version="2.25.0",
            vuln_id="CVE-2021-1234",
            severity=VulnSeverity.HIGH,
            title="Test Vulnerability",
            description="Test description"
        )

        assert vuln.package_name == "requests"
        assert vuln.installed_version == "2.25.0"
        assert vuln.vuln_id == "CVE-2021-1234"
        assert vuln.severity == VulnSeverity.HIGH
        assert vuln.fixed_version == ""
        assert vuln.references == []

    def test_create_vuln_complete(self):
        """测试创建完整漏洞"""
        vuln = DependencyVuln(
            package_name="django",
            installed_version="3.0.0",
            vuln_id="CVE-2021-5678",
            severity=VulnSeverity.CRITICAL,
            title="SQL Injection",
            description="SQL injection vulnerability",
            fixed_version="3.0.7",
            references=["https://example.com/advisory"],
            cvss_score=9.8,
            ecosystem="PyPI"
        )

        assert vuln.fixed_version == "3.0.7"
        assert len(vuln.references) == 1
        assert vuln.cvss_score == 9.8
        assert vuln.ecosystem == "PyPI"


class TestDependencyScannerInit:
    """依赖扫描器初始化测试"""

    def test_init_default(self):
        """测试默认初始化"""
        scanner = DependencyScanner()

        assert scanner.timeout == 30.0
        assert scanner._session is not None
        assert scanner._cache == {}

    def test_init_custom_timeout(self):
        """测试自定义超时"""
        scanner = DependencyScanner(timeout=60.0)

        assert scanner.timeout == 60.0

    def test_session_headers(self):
        """测试 Session 头"""
        scanner = DependencyScanner()

        assert "User-Agent" in scanner._session.headers
        assert "AutoRedTeam" in scanner._session.headers["User-Agent"]


class TestCVSSToSeverity:
    """CVSS 分数转换测试"""

    def test_cvss_critical(self):
        """测试 CRITICAL 级别"""
        scanner = DependencyScanner()

        assert scanner._cvss_to_severity(9.0) == VulnSeverity.CRITICAL
        assert scanner._cvss_to_severity(10.0) == VulnSeverity.CRITICAL
        assert scanner._cvss_to_severity(9.5) == VulnSeverity.CRITICAL

    def test_cvss_high(self):
        """测试 HIGH 级别"""
        scanner = DependencyScanner()

        assert scanner._cvss_to_severity(7.0) == VulnSeverity.HIGH
        assert scanner._cvss_to_severity(8.9) == VulnSeverity.HIGH
        assert scanner._cvss_to_severity(7.5) == VulnSeverity.HIGH

    def test_cvss_medium(self):
        """测试 MEDIUM 级别"""
        scanner = DependencyScanner()

        assert scanner._cvss_to_severity(4.0) == VulnSeverity.MEDIUM
        assert scanner._cvss_to_severity(6.9) == VulnSeverity.MEDIUM
        assert scanner._cvss_to_severity(5.0) == VulnSeverity.MEDIUM

    def test_cvss_low(self):
        """测试 LOW 级别"""
        scanner = DependencyScanner()

        assert scanner._cvss_to_severity(0.1) == VulnSeverity.LOW
        assert scanner._cvss_to_severity(3.9) == VulnSeverity.LOW
        assert scanner._cvss_to_severity(2.0) == VulnSeverity.LOW

    def test_cvss_unknown(self):
        """测试 UNKNOWN 级别"""
        scanner = DependencyScanner()

        assert scanner._cvss_to_severity(0.0) == VulnSeverity.UNKNOWN
        assert scanner._cvss_to_severity(-1.0) == VulnSeverity.UNKNOWN


class TestParseOSVResponse:
    """OSV 响应解析测试"""

    def test_parse_single_vuln(self):
        """测试解析单个漏洞"""
        scanner = DependencyScanner()

        osv_data = {
            "vulns": [
                {
                    "id": "CVE-2021-1234",
                    "summary": "Test Vulnerability",
                    "details": "Detailed description of the vulnerability",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": 7.5
                        }
                    ],
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.0.0"}
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [
                        {"url": "https://example.com/advisory"}
                    ]
                }
            ]
        }

        vulns = scanner._parse_osv_response(osv_data, "test-package", "1.0.0", "PyPI")

        assert len(vulns) == 1
        assert vulns[0].vuln_id == "CVE-2021-1234"
        assert vulns[0].severity == VulnSeverity.HIGH
        assert vulns[0].fixed_version == "2.0.0"
        assert len(vulns[0].references) == 1

    def test_parse_multiple_vulns(self):
        """测试解析多个漏洞"""
        scanner = DependencyScanner()

        osv_data = {
            "vulns": [
                {
                    "id": "CVE-2021-1111",
                    "summary": "Vuln 1",
                    "details": "Description 1",
                    "severity": [{"type": "CVSS_V3", "score": 9.0}],
                    "affected": [],
                    "references": []
                },
                {
                    "id": "CVE-2021-2222",
                    "summary": "Vuln 2",
                    "details": "Description 2",
                    "severity": [{"type": "CVSS_V3", "score": 5.0}],
                    "affected": [],
                    "references": []
                }
            ]
        }

        vulns = scanner._parse_osv_response(osv_data, "test-package", "1.0.0", "PyPI")

        assert len(vulns) == 2
        assert vulns[0].severity == VulnSeverity.CRITICAL
        assert vulns[1].severity == VulnSeverity.MEDIUM

    def test_parse_empty_response(self):
        """测试解析空响应"""
        scanner = DependencyScanner()

        osv_data = {"vulns": []}

        vulns = scanner._parse_osv_response(osv_data, "test-package", "1.0.0", "PyPI")

        assert len(vulns) == 0

    def test_parse_missing_fields(self):
        """测试解析缺失字段"""
        scanner = DependencyScanner()

        osv_data = {
            "vulns": [
                {
                    "id": "CVE-2021-1234",
                    # 缺少 summary, details, severity 等
                }
            ]
        }

        vulns = scanner._parse_osv_response(osv_data, "test-package", "1.0.0", "PyPI")

        assert len(vulns) == 1
        assert vulns[0].vuln_id == "CVE-2021-1234"
        assert vulns[0].severity == VulnSeverity.UNKNOWN
        assert vulns[0].cvss_score == 0.0


class TestCheckOSV:
    """OSV 检查测试"""

    def test_check_osv_success(self):
        """测试成功检查 OSV"""
        scanner = DependencyScanner()

        # Mock HTTP 响应
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "CVE-2021-1234",
                    "summary": "Test Vulnerability",
                    "details": "Test description",
                    "severity": [{"type": "CVSS_V3", "score": 7.5}],
                    "affected": [],
                    "references": []
                }
            ]
        }

        with patch.object(scanner._session, 'post', return_value=mock_response):
            vulns = scanner.check_osv("requests", "2.25.0", "PyPI")

        assert len(vulns) == 1
        assert vulns[0].package_name == "requests"
        assert vulns[0].installed_version == "2.25.0"

    def test_check_osv_no_vulns(self):
        """测试没有漏洞"""
        scanner = DependencyScanner()

        # Mock HTTP 响应 - 无漏洞
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}

        with patch.object(scanner._session, 'post', return_value=mock_response):
            vulns = scanner.check_osv("safe-package", "1.0.0", "PyPI")

        assert len(vulns) == 0

    def test_check_osv_cache(self):
        """测试缓存机制"""
        scanner = DependencyScanner()

        # Mock HTTP 响应
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}

        with patch.object(scanner._session, 'post', return_value=mock_response) as mock_post:
            # 第一次调用
            vulns1 = scanner.check_osv("requests", "2.25.0", "PyPI")
            # 第二次调用（应该使用缓存）
            vulns2 = scanner.check_osv("requests", "2.25.0", "PyPI")

        # 应该只调用一次 API
        assert mock_post.call_count == 1
        assert vulns1 == vulns2

    def test_check_osv_http_error(self):
        """测试 HTTP 错误"""
        scanner = DependencyScanner()

        # Mock HTTP 响应 - 错误状态码
        mock_response = Mock()
        mock_response.status_code = 500

        with patch.object(scanner._session, 'post', return_value=mock_response):
            vulns = scanner.check_osv("requests", "2.25.0", "PyPI")

        assert len(vulns) == 0

    def test_check_osv_network_error(self):
        """测试网络错误"""
        scanner = DependencyScanner()

        # Mock 网络异常
        with patch.object(scanner._session, 'post', side_effect=Exception("Network error")):
            vulns = scanner.check_osv("requests", "2.25.0", "PyPI")

        assert len(vulns) == 0

    def test_check_osv_timeout(self):
        """测试超时"""
        scanner = DependencyScanner()

        # Mock 超时异常
        import requests
        with patch.object(scanner._session, 'post', side_effect=requests.Timeout("Timeout")):
            vulns = scanner.check_osv("requests", "2.25.0", "PyPI")

        assert len(vulns) == 0


class TestCheckBatchOSV:
    """批量 OSV 检查测试"""

    def test_check_batch_success(self):
        """测试批量检查成功"""
        scanner = DependencyScanner()

        packages = [
            {"name": "requests", "version": "2.25.0", "ecosystem": "PyPI"},
            {"name": "django", "version": "3.0.0", "ecosystem": "PyPI"}
        ]

        # Mock check_osv 方法
        def mock_check_osv(name, version, ecosystem):
            if name == "requests":
                return [
                    DependencyVuln(
                        package_name=name,
                        installed_version=version,
                        vuln_id="CVE-2021-1111",
                        severity=VulnSeverity.HIGH,
                        title="Test Vuln",
                        description="Test"
                    )
                ]
            return []

        with patch.object(scanner, 'check_osv', side_effect=mock_check_osv):
            results = scanner.check_batch_osv(packages)

        assert "requests" in results
        assert len(results["requests"]) == 1
        assert "django" in results
        assert len(results["django"]) == 0

    def test_check_batch_empty(self):
        """测试批量检查空列表"""
        scanner = DependencyScanner()

        results = scanner.check_batch_osv([])

        assert len(results) == 0


class TestDependencyScannerIntegration:
    """依赖扫描器集成测试"""

    def test_scan_vulnerable_package(self):
        """测试扫描有漏洞的包"""
        scanner = DependencyScanner()

        # Mock OSV API 响应
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "summary": "Critical Security Issue",
                    "details": "This is a critical security vulnerability that affects version 1.0.0",
                    "severity": [{"type": "CVSS_V3", "score": 9.8}],
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "1.0.1"}
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [
                        {"url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"},
                        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234"}
                    ]
                }
            ]
        }

        with patch.object(scanner._session, 'post', return_value=mock_response):
            vulns = scanner.check_osv("vulnerable-package", "1.0.0", "PyPI")

        assert len(vulns) == 1
        vuln = vulns[0]
        assert vuln.severity == VulnSeverity.CRITICAL
        assert vuln.fixed_version == "1.0.1"
        assert len(vuln.references) == 2
        assert vuln.cvss_score == 9.8

    def test_scan_multiple_ecosystems(self):
        """测试扫描多个生态系统"""
        scanner = DependencyScanner()

        ecosystems = ["PyPI", "npm", "Go", "Maven"]

        for ecosystem in ecosystems:
            # Mock 响应
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"vulns": []}

            with patch.object(scanner._session, 'post', return_value=mock_response):
                vulns = scanner.check_osv("test-package", "1.0.0", ecosystem)

            assert isinstance(vulns, list)


class TestDependencyScannerEdgeCases:
    """依赖扫描器边缘情况测试"""

    def test_invalid_json_response(self):
        """测试无效 JSON 响应"""
        scanner = DependencyScanner()

        # Mock 无效 JSON
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)

        with patch.object(scanner._session, 'post', return_value=mock_response):
            vulns = scanner.check_osv("requests", "2.25.0", "PyPI")

        assert len(vulns) == 0

    def test_malformed_vuln_data(self):
        """测试格式错误的漏洞数据"""
        scanner = DependencyScanner()

        osv_data = {
            "vulns": [
                {
                    # 缺少必需的 id 字段
                    "summary": "Test",
                },
                {
                    "id": "CVE-2021-1234",
                    # 有效的漏洞
                    "summary": "Valid Vuln",
                    "details": "Description"
                }
            ]
        }

        vulns = scanner._parse_osv_response(osv_data, "test", "1.0.0", "PyPI")

        # 应该解析出两个漏洞（即使第一个缺少字段）
        assert len(vulns) == 2

    def test_very_long_description(self):
        """测试非常长的描述"""
        scanner = DependencyScanner()

        long_description = "A" * 1000  # 1000 字符

        osv_data = {
            "vulns": [
                {
                    "id": "CVE-2021-1234",
                    "summary": "Test",
                    "details": long_description,
                    "severity": [],
                    "affected": [],
                    "references": []
                }
            ]
        }

        vulns = scanner._parse_osv_response(osv_data, "test", "1.0.0", "PyPI")

        # 描述应该被截断到 500 字符
        assert len(vulns[0].description) == 500

    def test_many_references(self):
        """测试大量引用"""
        scanner = DependencyScanner()

        # 创建 10 个引用
        references = [{"url": f"https://example.com/ref{i}"} for i in range(10)]

        osv_data = {
            "vulns": [
                {
                    "id": "CVE-2021-1234",
                    "summary": "Test",
                    "details": "Description",
                    "severity": [],
                    "affected": [],
                    "references": references
                }
            ]
        }

        vulns = scanner._parse_osv_response(osv_data, "test", "1.0.0", "PyPI")

        # 引用应该被限制到 5 个
        assert len(vulns[0].references) == 5

    def test_special_characters_in_package_name(self):
        """测试包名中的特殊字符"""
        scanner = DependencyScanner()

        # Mock 响应
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}

        with patch.object(scanner._session, 'post', return_value=mock_response):
            vulns = scanner.check_osv("package-with-dash", "1.0.0", "PyPI")

        assert isinstance(vulns, list)

    def test_version_with_prerelease(self):
        """测试预发布版本"""
        scanner = DependencyScanner()

        # Mock 响应
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}

        with patch.object(scanner._session, 'post', return_value=mock_response):
            vulns = scanner.check_osv("package", "1.0.0-alpha.1", "PyPI")

        assert isinstance(vulns, list)
