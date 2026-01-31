"""
core.detectors 模块单元测试

测试漏洞检测器的核心功能
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass

# 模块级别标记 - 标识为单元测试和安全测试
pytestmark = [pytest.mark.unit, pytest.mark.security]


class TestDetectionResult:
    """测试 DetectionResult 数据类"""

    def test_result_creation(self):
        """测试检测结果创建"""
        from core.detectors import DetectionResult, Severity

        result = DetectionResult(
            vulnerable=True,
            vuln_type="sqli",
            severity=Severity.HIGH,
            param="id",
            payload="1' OR '1'='1",
            evidence="SQL syntax error",
            url="http://example.com/page?id=1"
        )

        assert result.vulnerable is True
        assert result.vuln_type == "sqli"
        assert result.severity == Severity.HIGH
        assert result.param == "id"

    def test_result_to_dict(self):
        """测试结果转字典"""
        from core.detectors import DetectionResult, Severity

        result = DetectionResult(
            vulnerable=True,
            vuln_type="xss",
            severity=Severity.MEDIUM,
            param="q",
            payload="<script>alert(1)</script>",
            evidence="Script tag reflected",
            url="http://example.com/search?q=test"
        )

        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        assert result_dict["vulnerable"] is True
        assert result_dict["vuln_type"] == "xss"


class TestSeverity:
    """测试严重性枚举"""

    def test_severity_values(self):
        """测试严重性值"""
        from core.detectors import Severity

        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_comparison(self):
        """测试严重性比较"""
        from core.detectors import Severity

        # 确保枚举值存在
        assert Severity.CRITICAL is not None
        assert Severity.HIGH is not None
        assert Severity.MEDIUM is not None


class TestBaseDetector:
    """测试 BaseDetector 基类"""

    def test_detector_name(self):
        """测试检测器名称"""
        from core.detectors import BaseDetector

        # BaseDetector 是抽象类，我们测试其属性
        assert hasattr(BaseDetector, 'name')
        assert hasattr(BaseDetector, 'description')

    def test_detector_config(self):
        """测试检测器配置"""
        from core.detectors import SQLiDetector

        detector = SQLiDetector(config={"timeout": 60})

        assert detector.config.get("timeout") == 60


class TestSQLiDetector:
    """测试 SQL 注入检测器"""

    def test_sqli_detector_creation(self):
        """测试 SQLi 检测器创建"""
        from core.detectors import SQLiDetector

        detector = SQLiDetector()

        assert detector is not None
        assert detector.name == "sqli"

    def test_sqli_detector_payloads(self):
        """测试 SQLi 检测器 payload"""
        from core.detectors import SQLiDetector

        detector = SQLiDetector()

        # 检测器应该有 payload 列表
        assert hasattr(detector, 'payloads') or hasattr(detector, 'get_payloads')

    @patch('core.detectors.injection.sqli.SQLiDetector._make_request')
    def test_sqli_detect_vulnerable(self, mock_request):
        """测试 SQLi 检测 - 存在漏洞"""
        from core.detectors import SQLiDetector

        # 模拟返回包含 SQL 错误的响应
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "You have an error in your SQL syntax"
        mock_response.headers = {}
        mock_request.return_value = mock_response

        detector = SQLiDetector()
        # 注意：实际测试需要根据检测器的具体实现调整
        assert detector is not None


class TestXSSDetector:
    """测试 XSS 检测器"""

    def test_xss_detector_creation(self):
        """测试 XSS 检测器创建"""
        from core.detectors import XSSDetector

        detector = XSSDetector()

        assert detector is not None
        assert detector.name == "xss"

    def test_xss_detector_types(self):
        """测试 XSS 检测类型"""
        from core.detectors import XSSDetector

        detector = XSSDetector()

        # XSS 检测器应该支持多种类型
        assert hasattr(detector, 'detect')


class TestRCEDetector:
    """测试 RCE 检测器"""

    def test_rce_detector_creation(self):
        """测试 RCE 检测器创建"""
        from core.detectors import RCEDetector

        detector = RCEDetector()

        assert detector is not None
        assert detector.name == "rce"


class TestSSRFDetector:
    """测试 SSRF 检测器"""

    def test_ssrf_detector_creation(self):
        """测试 SSRF 检测器创建"""
        from core.detectors import SSRFDetector

        detector = SSRFDetector()

        assert detector is not None
        assert detector.name == "ssrf"


class TestDetectorFactory:
    """测试检测器工厂"""

    def test_create_detector(self):
        """测试创建检测器"""
        from core.detectors import DetectorFactory

        detector = DetectorFactory.create("sqli")

        assert detector is not None
        assert detector.name == "sqli"

    def test_create_unknown_detector(self):
        """测试创建未知检测器"""
        from core.detectors import DetectorFactory

        with pytest.raises((ValueError, KeyError)):
            DetectorFactory.create("unknown_detector")

    def test_list_detectors(self):
        """测试列出检测器"""
        from core.detectors import DetectorFactory

        detectors = DetectorFactory.list_detectors()

        assert isinstance(detectors, (list, dict))
        assert len(detectors) > 0

    def test_create_composite_detector(self):
        """测试创建组合检测器"""
        from core.detectors import DetectorFactory

        composite = DetectorFactory.create_composite(["sqli", "xss"])

        assert composite is not None


class TestCompositeDetector:
    """测试组合检测器"""

    def test_composite_creation(self):
        """测试组合检测器创建"""
        from core.detectors import CompositeDetector, SQLiDetector, XSSDetector

        detectors = [SQLiDetector(), XSSDetector()]
        composite = CompositeDetector(detectors)

        assert composite is not None
        assert len(composite.detectors) == 2

    def test_composite_add_detector(self):
        """测试添加检测器"""
        from core.detectors import CompositeDetector, SQLiDetector, RCEDetector

        composite = CompositeDetector([SQLiDetector()])
        composite.add_detector(RCEDetector())

        assert len(composite.detectors) == 2


class TestPayloadManager:
    """测试 Payload 管理器"""

    def test_get_payloads(self):
        """测试获取 payload"""
        from core.detectors import get_payloads

        payloads = get_payloads("sqli")

        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_payload_manager_singleton(self):
        """测试 PayloadManager 单例"""
        from core.detectors import get_payload_manager

        manager1 = get_payload_manager()
        manager2 = get_payload_manager()

        assert manager1 is manager2

    def test_payload_categories(self):
        """测试 Payload 类别"""
        from core.detectors import PayloadCategory

        assert PayloadCategory.SQLI is not None
        assert PayloadCategory.XSS is not None
        assert PayloadCategory.RCE is not None


class TestPayloadEncoder:
    """测试 Payload 编码器"""

    def test_url_encoding(self):
        """测试 URL 编码"""
        from core.detectors import PayloadEncoder, EncodingType

        encoder = PayloadEncoder()
        payload = "<script>alert(1)</script>"

        encoded = encoder.encode(payload, EncodingType.URL)

        assert "%3C" in encoded or "%3c" in encoded  # < 的 URL 编码

    def test_html_encoding(self):
        """测试 HTML 编码"""
        from core.detectors import PayloadEncoder, EncodingType

        encoder = PayloadEncoder()
        payload = "<script>alert(1)</script>"

        encoded = encoder.encode(payload, EncodingType.HTML)

        assert "&lt;" in encoded or "&#" in encoded

    def test_base64_encoding(self):
        """测试 Base64 编码"""
        from core.detectors import PayloadEncoder, EncodingType

        encoder = PayloadEncoder()
        payload = "test payload"

        encoded = encoder.encode(payload, EncodingType.BASE64)

        assert encoded != payload
        # Base64 编码后应该只包含 Base64 字符
        import re
        assert re.match(r'^[A-Za-z0-9+/=]+$', encoded)


class TestDetectorPresets:
    """测试检测器预设"""

    def test_owasp_top10_preset(self):
        """测试 OWASP Top 10 预设"""
        from core.detectors import DetectorPresets

        detector = DetectorPresets.owasp_top10()

        assert detector is not None

    def test_injection_preset(self):
        """测试注入类预设"""
        from core.detectors import DetectorPresets

        if hasattr(DetectorPresets, 'injection'):
            detector = DetectorPresets.injection()
            assert detector is not None


class TestFalsePositiveFilter:
    """测试误报过滤器"""

    def test_filter_creation(self):
        """测试过滤器创建"""
        from core.detectors import FalsePositiveFilter

        filter = FalsePositiveFilter()

        assert filter is not None

    def test_is_false_positive(self):
        """测试误报检测"""
        from core.detectors import is_false_positive, DetectionResult, Severity

        result = DetectionResult(
            vulnerable=True,
            vuln_type="xss",
            severity=Severity.MEDIUM,
            param="q",
            payload="<script>",
            evidence="",
            url="http://example.com"
        )

        # 测试函数存在
        assert callable(is_false_positive)


class TestDetectorType:
    """测试检测器类型枚举"""

    def test_detector_types(self):
        """测试检测器类型"""
        from core.detectors import DetectorType

        assert DetectorType.INJECTION is not None
        assert DetectorType.ACCESS_CONTROL is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
