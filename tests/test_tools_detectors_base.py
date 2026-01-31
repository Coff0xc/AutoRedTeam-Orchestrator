#!/usr/bin/env python3
"""
test_tools_detectors_base.py - tools/detectors/base.py 单元测试

测试覆盖:
- BaseDetector 初始化和配置
- Vulnerability 数据类
- HTTP 请求处理
- Payload 测试逻辑
- 基线响应缓存
- 二次验证机制
- 异常处理
- 失败计数器
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock, PropertyMock
from typing import List, Dict, Any

# 导入被测试的模块
from tools.detectors.base import (
    Vulnerability,
    BaseDetector,
)


# ============== 测试用的具体检测器实现 ==============

class MockDetector(BaseDetector):
    """用于测试的模拟检测器"""

    def get_payloads(self) -> Dict[str, List[str]]:
        """返回测试用的 payload"""
        return {
            "error_based": ["'", "\"", "1' OR '1'='1"],
            "time_based": ["1' AND SLEEP(5)--"],
        }

    def validate_response(
        self,
        response: Dict[str, Any],
        payload: str,
        baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在漏洞"""
        if not response or not response.get("success"):
            return False

        # 简单的验证逻辑：检查响应文本中是否包含错误信息
        response_text = response.get("response_text", "")
        error_keywords = ["error", "syntax", "mysql", "sql"]

        return any(keyword in response_text.lower() for keyword in error_keywords)


class MockDetectorNoVuln(BaseDetector):
    """不会发现漏洞的检测器"""

    def get_payloads(self) -> Dict[str, List[str]]:
        return {"test": ["payload1"]}

    def validate_response(
        self,
        response: Dict[str, Any],
        payload: str,
        baseline: Dict[str, Any] = None
    ) -> bool:
        return False


# ============== Vulnerability 数据类测试 ==============

class TestVulnerability:
    """Vulnerability 数据类测试"""

    def test_init_minimal(self):
        """测试最小化初始化"""
        vuln = Vulnerability(
            type="SQL Injection",
            severity="CRITICAL"
        )

        assert vuln.type == "SQL Injection"
        assert vuln.severity == "CRITICAL"
        assert vuln.param is None
        assert vuln.payload is None
        assert vuln.evidence is None
        assert vuln.url is None
        assert vuln.verified is False
        assert vuln.confidence == 0.0
        assert vuln.details == {}

    def test_init_full(self):
        """测试完整初始化"""
        vuln = Vulnerability(
            type="XSS",
            severity="HIGH",
            param="search",
            payload="<script>alert(1)</script>",
            evidence="Script executed",
            url="https://example.com/search?q=test",
            verified=True,
            confidence=0.95,
            details={"context": "reflected", "waf": "none"}
        )

        assert vuln.type == "XSS"
        assert vuln.severity == "HIGH"
        assert vuln.param == "search"
        assert vuln.payload == "<script>alert(1)</script>"
        assert vuln.evidence == "Script executed"
        assert vuln.url == "https://example.com/search?q=test"
        assert vuln.verified is True
        assert vuln.confidence == 0.95
        assert vuln.details["context"] == "reflected"
        assert vuln.details["waf"] == "none"

    def test_to_dict(self):
        """测试转换为字典"""
        vuln = Vulnerability(
            type="CSRF",
            severity="MEDIUM",
            param="action",
            payload="delete_account",
            evidence="No CSRF token",
            url="https://example.com/account",
            verified=False,
            confidence=0.7,
            details={"method": "POST"}
        )

        result = vuln.to_dict()

        assert isinstance(result, dict)
        assert result["type"] == "CSRF"
        assert result["severity"] == "MEDIUM"
        assert result["param"] == "action"
        assert result["payload"] == "delete_account"
        assert result["evidence"] == "No CSRF token"
        assert result["url"] == "https://example.com/account"
        assert result["verified"] is False
        assert result["confidence"] == 0.7
        assert result["details"]["method"] == "POST"

    def test_to_dict_with_none_values(self):
        """测试包含 None 值的字典转换"""
        vuln = Vulnerability(type="Test", severity="LOW")
        result = vuln.to_dict()

        assert result["param"] is None
        assert result["payload"] is None
        assert result["evidence"] is None


# ============== BaseDetector 初始化测试 ==============

class TestBaseDetectorInit:
    """BaseDetector 初始化测试"""

    @patch('tools.detectors.base.GLOBAL_CONFIG', {"request_timeout": 15})
    @patch('tools.detectors.base.get_verify_ssl', return_value=False)
    def test_init_default_config(self, mock_verify_ssl):
        """测试默认配置初始化"""
        detector = MockDetector()

        assert detector.timeout == 15
        assert detector.verify_ssl is False  # 默认值
        assert detector.max_retries == 2
        assert detector.user_agent is not None
        assert detector._baseline_cache == {}

    def test_init_custom_config(self):
        """测试自定义配置初始化"""
        detector = MockDetector(
            timeout=30,
            verify_ssl=True,
            max_retries=5,
            user_agent="CustomAgent/1.0"
        )

        assert detector.timeout == 30
        assert detector.verify_ssl is True
        assert detector.max_retries == 5
        assert detector.user_agent == "CustomAgent/1.0"

    @patch('tools.detectors.base.HAS_REQUESTS', True)
    @patch('tools.detectors.base.HTTPClientFactory')
    def test_init_with_requests(self, mock_factory):
        """测试有 requests 库时的初始化"""
        mock_client = Mock()
        mock_factory.get_sync_client.return_value = mock_client

        detector = MockDetector()

        assert detector.session is not None
        mock_factory.get_sync_client.assert_called_once()

    @patch('tools.detectors.base.HAS_REQUESTS', False)
    def test_init_without_requests(self):
        """测试没有 requests 库时的初始化"""
        detector = MockDetector()

        assert detector.session is None


# ============== BaseDetector 请求处理测试 ==============

class TestBaseDetectorRequests:
    """BaseDetector HTTP 请求处理测试"""

    @patch('tools.detectors.base.HAS_REQUESTS', True)
    def test_send_request_get_success(self):
        """测试 GET 请求成功"""
        detector = MockDetector()

        # Mock session
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Success response"
        mock_response.headers = {"Content-Type": "text/html"}

        mock_session = Mock()
        mock_session.get.return_value = mock_response
        detector.session = mock_session

        with patch('tools.detectors.base.get_proxies', return_value=None):
            result = detector.send_request(
                "https://example.com",
                payload="test",
                param="id"
            )

        assert result is not None
        assert result["success"] is True
        assert result["status_code"] == 200
        assert result["response_text"] == "Success response"
        assert result["response_length"] == len("Success response")
        assert "response_time" in result

    @patch('tools.detectors.base.HAS_REQUESTS', True)
    def test_send_request_post_success(self):
        """测试 POST 请求成功"""
        detector = MockDetector()

        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.text = "Created"
        mock_response.headers = {}

        mock_session = Mock()
        mock_session.post.return_value = mock_response
        detector.session = mock_session

        with patch('tools.detectors.base.get_proxies', return_value=None):
            result = detector.send_request(
                "https://example.com/api",
                method="POST",
                data='{"key": "value"}'
            )

        assert result["success"] is True
        assert result["status_code"] == 201

    @patch('tools.detectors.base.HAS_REQUESTS', True)
    def test_send_request_with_custom_headers(self):
        """测试带自定义请求头的请求"""
        detector = MockDetector()

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_response.headers = {}

        mock_session = Mock()
        mock_session.get.return_value = mock_response
        detector.session = mock_session

        custom_headers = {"X-Custom-Header": "test"}

        with patch('tools.detectors.base.get_proxies', return_value=None):
            result = detector.send_request(
                "https://example.com",
                headers=custom_headers
            )

        # 验证调用时包含了自定义头
        call_args = mock_session.get.call_args
        assert "headers" in call_args.kwargs
        assert "X-Custom-Header" in call_args.kwargs["headers"]

    @patch('tools.detectors.base.HAS_REQUESTS', True)
    def test_send_request_exception_handling(self):
        """测试请求异常处理"""
        detector = MockDetector()

        mock_session = Mock()
        mock_session.get.side_effect = Exception("Connection timeout")
        detector.session = mock_session

        with patch('tools.detectors.base.get_proxies', return_value=None):
            with patch('tools.detectors.base.record_failure') as mock_record:
                result = detector.send_request("https://example.com")

        assert result is not None
        assert result["success"] is False
        assert "error" in result
        mock_record.assert_called_once_with(is_network_error=True)

    @patch('tools.detectors.base.HAS_REQUESTS', False)
    @patch('tools.detectors.base.make_request')
    def test_send_request_fallback_to_make_request(self, mock_make_request):
        """测试降级到 make_request"""
        detector = MockDetector()
        detector.session = None

        mock_make_request.return_value = {
            "success": True,
            "text": "Fallback response",
            "status_code": 200
        }

        result = detector.send_request("https://example.com")

        assert result is not None
        assert result["success"] is True
        mock_make_request.assert_called_once()


# ============== BaseDetector 基线响应测试 ==============

class TestBaseDetectorBaseline:
    """BaseDetector 基线响应测试"""

    def test_get_baseline_first_call(self):
        """测试首次获取基线响应"""
        detector = MockDetector()

        with patch.object(detector, 'send_request') as mock_send:
            mock_send.return_value = {
                "success": True,
                "status_code": 200,
                "response_text": "Normal response"
            }

            baseline = detector.get_baseline("https://example.com")

        assert baseline is not None
        assert baseline["success"] is True
        assert "https://example.com" in detector._baseline_cache
        mock_send.assert_called_once()

    def test_get_baseline_cached(self):
        """测试基线响应缓存"""
        detector = MockDetector()

        # 预先设置缓存
        cached_baseline = {"success": True, "cached": True}
        detector._baseline_cache["https://example.com"] = cached_baseline

        with patch.object(detector, 'send_request') as mock_send:
            baseline = detector.get_baseline("https://example.com")

        assert baseline == cached_baseline
        mock_send.assert_not_called()  # 不应该发送新请求

    def test_get_baseline_failure(self):
        """测试基线响应获取失败"""
        detector = MockDetector()

        with patch.object(detector, 'send_request') as mock_send:
            mock_send.return_value = None

            baseline = detector.get_baseline("https://example.com")

        assert baseline == {}
        assert "https://example.com" not in detector._baseline_cache


# ============== BaseDetector Payload 测试 ==============

class TestBaseDetectorPayload:
    """BaseDetector Payload 测试逻辑"""

    def test_test_payload_success(self):
        """测试单个 payload 成功检测"""
        detector = MockDetector()

        with patch.object(detector, 'send_request') as mock_send:
            mock_send.return_value = {
                "success": True,
                "status_code": 200,
                "response_text": "MySQL syntax error",
                "url": "https://example.com?id='",
                "response_length": 100,
                "response_time": 0.5
            }

            with patch('tools.detectors.base.should_abort_scan', return_value=False):
                with patch('tools.detectors.base.reset_failure_counter'):
                    vuln = detector.test_payload(
                        "https://example.com",
                        "'",
                        "id"
                    )

        assert vuln is not None
        assert isinstance(vuln, Vulnerability)
        assert vuln.param == "id"
        assert vuln.payload == "'"
        assert vuln.verified is False
        assert vuln.confidence == 0.6

    def test_test_payload_no_vulnerability(self):
        """测试 payload 未发现漏洞"""
        detector = MockDetectorNoVuln()

        with patch.object(detector, 'send_request') as mock_send:
            mock_send.return_value = {
                "success": True,
                "status_code": 200,
                "response_text": "Normal response"
            }

            with patch('tools.detectors.base.should_abort_scan', return_value=False):
                with patch('tools.detectors.base.reset_failure_counter'):
                    vuln = detector.test_payload(
                        "https://example.com",
                        "payload1",
                        "id"
                    )

        assert vuln is None

    def test_test_payload_request_failure(self):
        """测试 payload 请求失败"""
        detector = MockDetector()

        with patch.object(detector, 'send_request') as mock_send:
            mock_send.return_value = {"success": False, "error": "Timeout"}

            with patch('tools.detectors.base.should_abort_scan', return_value=False):
                with patch('tools.detectors.base.record_failure') as mock_record:
                    vuln = detector.test_payload(
                        "https://example.com",
                        "'",
                        "id"
                    )

        assert vuln is None
        mock_record.assert_called_once_with(is_network_error=True)

    def test_test_payload_abort_scan(self):
        """测试扫描中止"""
        detector = MockDetector()

        with patch('tools.detectors.base.should_abort_scan', return_value=True):
            vuln = detector.test_payload(
                "https://example.com",
                "'",
                "id"
            )

        assert vuln is None

    def test_test_payloads_stop_on_first(self):
        """测试批量测试 - 发现第一个漏洞后停止"""
        detector = MockDetector()

        with patch.object(detector, 'send_request') as mock_send:
            mock_send.return_value = {
                "success": True,
                "status_code": 200,
                "response_text": "SQL error detected",
                "url": "https://example.com",
                "response_length": 50,
                "response_time": 0.3
            }

            with patch('tools.detectors.base.should_abort_scan', return_value=False):
                with patch('tools.detectors.base.reset_failure_counter'):
                    vulns = detector.test_payloads(
                        "https://example.com",
                        param="id",
                        stop_on_first=True
                    )

        assert len(vulns) >= 1
        # 应该在发现第一个漏洞后停止

    def test_test_payloads_no_stop(self):
        """测试批量测试 - 不停止"""
        detector = MockDetector()

        with patch.object(detector, 'send_request') as mock_send:
            mock_send.return_value = {
                "success": True,
                "status_code": 200,
                "response_text": "MySQL syntax error",
                "url": "https://example.com",
                "response_length": 50,
                "response_time": 0.3
            }

            with patch('tools.detectors.base.should_abort_scan', return_value=False):
                with patch('tools.detectors.base.reset_failure_counter'):
                    vulns = detector.test_payloads(
                        "https://example.com",
                        param="id",
                        stop_on_first=False
                    )

        # 应该测试所有 payload
        assert len(vulns) >= 1


# ============== BaseDetector 检测入口测试 ==============

class TestBaseDetectorDetect:
    """BaseDetector detect() 方法测试"""

    def test_detect_success(self):
        """测试检测成功"""
        detector = MockDetector()

        with patch.object(detector, 'test_payloads') as mock_test:
            mock_vuln = Vulnerability(
                type="SQL Injection",
                severity="HIGH",
                param="id",
                payload="'",
                url="https://example.com"
            )
            mock_test.return_value = [mock_vuln]

            with patch.object(detector, 'verify_vulnerability', return_value=True):
                with patch('tools.detectors.base.reset_failure_counter'):
                    result = detector.detect("https://example.com")

        assert result["success"] is True
        assert result["url"] == "https://example.com"
        assert result["total"] == 1
        assert result["verified_count"] == 1
        assert len(result["vulnerabilities"]) == 1

    def test_detect_no_vulnerabilities(self):
        """测试未发现漏洞"""
        detector = MockDetectorNoVuln()

        with patch.object(detector, 'test_payloads') as mock_test:
            mock_test.return_value = []

            with patch('tools.detectors.base.reset_failure_counter'):
                result = detector.detect("https://example.com")

        assert result["success"] is True
        assert result["total"] == 0
        assert result["verified_count"] == 0

    def test_detect_exception_handling(self):
        """测试检测异常处理"""
        detector = MockDetector()

        with patch.object(detector, 'test_payloads') as mock_test:
            mock_test.side_effect = Exception("Test exception")

            with patch('tools.detectors.base.reset_failure_counter'):
                result = detector.detect("https://example.com")

        assert result["success"] is False
        assert "error" in result
        assert result["total"] == 0


# ============== BaseDetector 二次验证测试 ==============

class TestBaseDetectorVerify:
    """BaseDetector 二次验证测试"""

    def test_verify_vulnerability_success(self):
        """测试二次验证成功"""
        detector = MockDetector()

        vuln = Vulnerability(
            type="SQL Injection",
            severity="HIGH",
            param="id",
            payload="'",
            url="https://example.com?id='"
        )

        with patch.object(detector, 'send_request') as mock_send:
            # 第一次请求：获取基线
            # 第二次请求：验证漏洞
            mock_send.side_effect = [
                {"success": True, "response_text": "Normal"},
                {"success": True, "response_text": "SQL error"}
            ]

            result = detector.verify_vulnerability(vuln)

        assert result is True

    def test_verify_vulnerability_failure(self):
        """测试二次验证失败"""
        detector = MockDetectorNoVuln()

        vuln = Vulnerability(
            type="Test",
            severity="LOW",
            param="id",
            payload="test",
            url="https://example.com?id=test"
        )

        with patch.object(detector, 'send_request') as mock_send:
            mock_send.side_effect = [
                {"success": True, "response_text": "Normal"},
                {"success": True, "response_text": "Normal"}
            ]

            result = detector.verify_vulnerability(vuln)

        assert result is False

    def test_verify_vulnerability_missing_data(self):
        """测试验证缺少必要数据"""
        detector = MockDetector()

        vuln = Vulnerability(type="Test", severity="LOW")

        result = detector.verify_vulnerability(vuln)

        assert result is False

    def test_verify_vulnerability_request_failure(self):
        """测试验证时请求失败"""
        detector = MockDetector()

        vuln = Vulnerability(
            type="Test",
            severity="LOW",
            param="id",
            payload="test",
            url="https://example.com?id=test"
        )

        with patch.object(detector, 'send_request') as mock_send:
            mock_send.return_value = None

            result = detector.verify_vulnerability(vuln)

        assert result is False


# ============== BaseDetector 资源清理测试 ==============

class TestBaseDetectorCleanup:
    """BaseDetector 资源清理测试"""

    def test_cleanup(self):
        """测试资源清理"""
        detector = MockDetector()

        # 设置一些状态
        detector._baseline_cache["test"] = {"data": "test"}
        mock_session = Mock()
        detector.session = mock_session

        detector.cleanup()

        assert detector._baseline_cache == {}
        assert detector.session is None
        mock_session.close.assert_called_once()

    def test_cleanup_session_exception(self):
        """测试清理时 session 关闭异常"""
        detector = MockDetector()

        mock_session = Mock()
        mock_session.close.side_effect = Exception("Close error")
        detector.session = mock_session

        # 不应该抛出异常
        detector.cleanup()

        assert detector.session is None

    def test_context_manager(self):
        """测试上下文管理器"""
        with patch.object(MockDetector, 'cleanup') as mock_cleanup:
            with MockDetector() as detector:
                assert detector is not None

            mock_cleanup.assert_called_once()


# ============== BaseDetector 辅助方法测试 ==============

class TestBaseDetectorHelpers:
    """BaseDetector 辅助方法测试"""

    def test_get_test_params_with_param(self):
        """测试获取测试参数 - 指定参数"""
        detector = MockDetector()

        params = detector.get_test_params("custom_param")

        assert params == ["custom_param"]

    def test_get_test_params_default(self):
        """测试获取测试参数 - 默认参数"""
        detector = MockDetector()

        params = detector.get_test_params()

        assert len(params) > 0
        assert "id" in params
        assert "page" in params

    def test_extract_evidence(self):
        """测试提取证据"""
        detector = MockDetector()

        response = {
            "status_code": 500,
            "response_length": 1234,
            "response_time": 2.5
        }

        evidence = detector._extract_evidence(response)

        assert "Status: 500" in evidence
        assert "Length: 1234" in evidence
        assert "Time: 2.50s" in evidence

    def test_extract_evidence_empty(self):
        """测试提取证据 - 空响应"""
        detector = MockDetector()

        evidence = detector._extract_evidence({})

        assert evidence == "N/A"


# ============== 边界条件测试 ==============

class TestEdgeCases:
    """边界条件测试"""

    def test_empty_url(self):
        """测试空 URL"""
        detector = MockDetector()

        with patch('tools.detectors.base.reset_failure_counter'):
            result = detector.detect("")

        assert result["success"] is True
        assert result["url"] == ""

    def test_special_characters_in_payload(self):
        """测试 payload 中的特殊字符"""
        detector = MockDetector()

        with patch.object(detector, 'send_request') as mock_send:
            mock_send.return_value = {
                "success": True,
                "status_code": 200,
                "response_text": "Normal",
                "url": "https://example.com",
                "response_length": 10,
                "response_time": 0.1
            }

            with patch('tools.detectors.base.should_abort_scan', return_value=False):
                with patch('tools.detectors.base.reset_failure_counter'):
                    vuln = detector.test_payload(
                        "https://example.com",
                        "<script>alert('XSS')</script>",
                        "search"
                    )

        # 应该正常处理特殊字符

    def test_unicode_in_url(self):
        """测试 URL 中的 Unicode 字符"""
        detector = MockDetector()

        with patch('tools.detectors.base.reset_failure_counter'):
            result = detector.detect("https://example.com/路径/测试")

        assert result["success"] is True


# ============== 集成测试 ==============

class TestIntegration:
    """集成测试"""

    def test_full_detection_workflow(self):
        """测试完整检测工作流"""
        detector = MockDetector()

        with patch.object(detector, 'send_request') as mock_send:
            # 模拟基线请求和漏洞检测请求
            mock_send.side_effect = [
                # 基线请求
                {"success": True, "status_code": 200, "response_text": "Normal"},
                # Payload 测试请求
                {"success": True, "status_code": 500, "response_text": "MySQL error",
                 "url": "https://example.com?id='", "response_length": 100, "response_time": 0.5},
                # 验证请求 1
                {"success": True, "status_code": 200, "response_text": "Normal"},
                # 验证请求 2
                {"success": True, "status_code": 500, "response_text": "MySQL error"}
            ]

            with patch('tools.detectors.base.should_abort_scan', return_value=False):
                with patch('tools.detectors.base.reset_failure_counter'):
                    result = detector.detect("https://example.com", param="id", deep_scan=False)

        assert result["success"] is True
        assert result["total"] >= 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
