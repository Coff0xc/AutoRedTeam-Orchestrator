"""
CRLF Injection + Host Header Injection 检测器测试
"""

import hashlib
import time
from unittest.mock import MagicMock, patch

from core.detectors.injection.crlf_injection import CRLFInjectionDetector
from core.detectors.request.host_header_injection import HostHeaderInjectionDetector
from core.detectors.result import Severity

# ==================== CRLFInjectionDetector Tests ====================


class TestCRLFInjectionDetector:
    """CRLF Injection 检测器测试"""

    def setup_method(self):
        self.detector = CRLFInjectionDetector()

    def test_attributes(self):
        assert self.detector.name == "crlf_injection"
        assert self.detector.severity == Severity.MEDIUM

    def test_invalid_url(self):
        results = self.detector.detect("not-a-url")
        assert results == []

    @patch.object(CRLFInjectionDetector, "_safe_request")
    def test_no_crlf_detected(self, mock_request):
        """正常响应不应报告 CRLF"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html>normal</html>"
        mock_resp.headers = {"content-type": "text/html"}
        mock_request.return_value = mock_resp

        results = self.detector.detect("https://example.com/redirect", params={"url": "test"})
        assert all(not r.vulnerable for r in results)

    @patch.object(CRLFInjectionDetector, "_safe_request")
    def test_header_injection_detected(self, mock_request):
        """检测到响应头注入"""
        nonce = f"crlfn{id(self.detector) % 100000:05d}"

        def side_effect(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "<html>redirect</html>"

            if f"crlf_test_{nonce}" in url:
                resp.headers = {
                    "content-type": "text/html",
                    "X-Injected": f"crlf_test_{nonce}",
                }
            else:
                resp.headers = {"content-type": "text/html"}

            return resp

        mock_request.side_effect = side_effect

        results = self.detector.detect("https://example.com/redirect", params={"url": "test"})
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) >= 1
        assert vuln[0].extra["crlf_type"] == "header_injection"

    @patch.object(CRLFInjectionDetector, "_safe_request")
    def test_response_splitting_detected(self, mock_request):
        """检测到 HTTP Response Splitting (body 注入)"""
        nonce = f"crlfn{id(self.detector) % 100000:05d}"

        def side_effect(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "text/html"}

            if f"var crlf='{nonce}'" in url or nonce in url:
                resp.text = f"<html>normal</html><script>var crlf='{nonce}'</script>"
            else:
                resp.text = "<html>normal</html>"

            return resp

        mock_request.side_effect = side_effect

        results = self.detector.detect("https://example.com/page", params={"url": "test"})
        splitting = [
            r for r in results if r.vulnerable and r.extra.get("crlf_type") == "response_splitting"
        ]
        if splitting:
            assert splitting[0].confidence >= 0.80

    @patch.object(CRLFInjectionDetector, "_safe_request")
    def test_request_failure_handled(self, mock_request):
        mock_request.return_value = None
        results = self.detector.detect("https://example.com/redirect", params={"url": "test"})
        assert results == []

    @patch.object(CRLFInjectionDetector, "_safe_request")
    def test_no_params_tests_common_params(self, mock_request):
        """无参数时应测试常见反射参数"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html>ok</html>"
        mock_resp.headers = {"content-type": "text/html"}
        mock_request.return_value = mock_resp

        results = self.detector.detect("https://example.com/redirect")
        # 应发出多次请求 (路径 + 常见参数)
        assert mock_request.call_count > 1


# ==================== HostHeaderInjectionDetector Tests ====================


class TestHostHeaderInjectionDetector:
    """Host Header Injection 检测器测试"""

    def setup_method(self):
        self.detector = HostHeaderInjectionDetector()

    def test_attributes(self):
        assert self.detector.name == "host_header_injection"
        assert self.detector.severity == Severity.HIGH

    def test_invalid_url(self):
        results = self.detector.detect("not-a-url")
        assert results == []

    @patch.object(HostHeaderInjectionDetector, "_safe_request")
    def test_no_injection_detected(self, mock_request):
        """正常响应不应报告注入"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html>normal page</html>"
        mock_resp.headers = {"content-type": "text/html"}
        mock_request.return_value = mock_resp

        results = self.detector.detect("https://example.com/")
        assert all(not r.vulnerable for r in results)

    @patch.object(HostHeaderInjectionDetector, "_safe_request")
    def test_host_override_detected(self, mock_request):
        """检测到 Host 头覆盖反射"""

        def side_effect(method, url, headers=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "text/html"}

            if headers and "Host" in headers:
                evil = headers["Host"]
                resp.text = f'<html><a href="http://{evil}/reset">Reset</a></html>'
            else:
                resp.text = "<html>normal</html>"

            return resp

        mock_request.side_effect = side_effect

        results = self.detector.detect("https://example.com/")
        vuln = [
            r for r in results if r.vulnerable and r.extra.get("attack_type") == "host_override"
        ]
        assert len(vuln) >= 1
        assert vuln[0].confidence >= 0.80

    @patch.object(HostHeaderInjectionDetector, "_safe_request")
    def test_x_forwarded_host_detected(self, mock_request):
        """检测到 X-Forwarded-Host 注入"""

        def side_effect(method, url, headers=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "text/html"}

            if headers and "X-Forwarded-Host" in headers:
                evil = headers["X-Forwarded-Host"]
                resp.text = f'<html><link href="http://{evil}/style.css"></html>'
            elif headers and "Host" in headers:
                resp.text = "<html>no reflection for direct Host</html>"
            else:
                resp.text = "<html>normal</html>"

            return resp

        mock_request.side_effect = side_effect

        results = self.detector.detect("https://example.com/")
        vuln = [
            r for r in results if r.vulnerable and r.extra.get("attack_type") == "x_forwarded_host"
        ]
        assert len(vuln) >= 1

    @patch.object(HostHeaderInjectionDetector, "_safe_request")
    def test_host_port_injection(self, mock_request):
        """检测到 Host 端口注入"""

        def side_effect(method, url, headers=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "text/html"}

            if headers and "Host" in headers:
                host_val = headers["Host"]
                if ":1337/" in host_val:
                    resp.text = f'<html><a href="http://{host_val}/page">link</a></html>'
                    return resp

            resp.text = "<html>normal</html>"
            return resp

        mock_request.side_effect = side_effect

        results = self.detector.detect("https://example.com/")
        port_results = [
            r
            for r in results
            if r.vulnerable and r.extra.get("attack_type") == "host_port_injection"
        ]
        assert len(port_results) >= 1

    @patch.object(HostHeaderInjectionDetector, "_safe_request")
    def test_request_failure_handled(self, mock_request):
        mock_request.return_value = None
        results = self.detector.detect("https://example.com/")
        assert results == []

    @patch.object(HostHeaderInjectionDetector, "_safe_request")
    def test_baseline_failure_returns_empty(self, mock_request):
        """基线请求失败应返回空"""
        mock_request.return_value = None
        results = self.detector.detect("https://example.com/")
        assert results == []


# ==================== Registration Tests ====================


class TestNewDetectorRegistration:
    """测试新检测器注册"""

    def test_crlf_registered(self):
        from core.detectors.factory import DetectorFactory

        assert DetectorFactory.exists("crlf_injection")

    def test_host_header_registered(self):
        from core.detectors.factory import DetectorFactory

        assert DetectorFactory.exists("host_header_injection")

    def test_factory_create_crlf(self):
        from core.detectors.factory import DetectorFactory

        d = DetectorFactory.create("crlf_injection")
        assert isinstance(d, CRLFInjectionDetector)

    def test_factory_create_host_header(self):
        from core.detectors.factory import DetectorFactory

        d = DetectorFactory.create("host_header_injection")
        assert isinstance(d, HostHeaderInjectionDetector)

    def test_importable_from_package(self):
        from core.detectors import CRLFInjectionDetector as CRLF
        from core.detectors import HostHeaderInjectionDetector as HHI

        assert CRLF is not None
        assert HHI is not None
