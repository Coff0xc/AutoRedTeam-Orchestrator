"""
HTTP Request Smuggling & Cache Poisoning 检测器测试

测试 HTTPSmugglingDetector 和 CachePoisoningDetector 的核心逻辑。
使用 mock 模拟网络请求，不发送真实流量。
"""

import socket
from unittest.mock import MagicMock, patch

import pytest

from core.detectors.request.cache_poisoning import CachePoisoningDetector
from core.detectors.request.http_smuggling import HTTPSmugglingDetector
from core.detectors.result import Severity

# ==================== HTTPSmugglingDetector Tests ====================


class TestHTTPSmugglingDetector:
    """HTTP Request Smuggling 检测器测试"""

    def setup_method(self):
        self.detector = HTTPSmugglingDetector()

    def test_attributes(self):
        """测试检测器属性"""
        assert self.detector.name == "http_smuggling"
        assert self.detector.severity == Severity.HIGH
        assert self.detector.version == "1.0.0"

    def test_invalid_url(self):
        """无效 URL 应返回空结果"""
        results = self.detector.detect("not-a-valid-url")
        assert results == []

    @patch.object(HTTPSmugglingDetector, "_raw_request")
    def test_baseline_failure_returns_empty(self, mock_raw):
        """无法建立基线连接时返回空结果"""
        mock_raw.return_value = None
        results = self.detector.detect("https://example.com/test")
        assert results == []

    @patch.object(HTTPSmugglingDetector, "_raw_request")
    def test_no_smuggling_detected(self, mock_raw):
        """正常响应不应报告走私漏洞"""
        # 基线请求 (3次) + 3 种检测各 1 次 + TE.TE 4 变体
        normal_resp = {"status": 200, "raw": "HTTP/1.1 200 OK\r\n\r\n", "time": 0.1}
        mock_raw.return_value = normal_resp
        results = self.detector.detect("https://example.com/")
        # 所有检测的响应时间 (0.1s) 低于基线 (0.1s) + 阈值 (3s)
        assert all(not r.vulnerable for r in results)

    @patch.object(HTTPSmugglingDetector, "_raw_request")
    def test_clte_detection(self, mock_raw):
        """CL.TE 走私检测: 超时响应应触发检测"""
        baseline_resp = {"status": 200, "raw": "HTTP/1.1 200 OK\r\n\r\n", "time": 0.1}
        timeout_resp = {"status": 0, "raw": "", "time": 15.0, "timeout": True}
        normal_resp = {"status": 200, "raw": "HTTP/1.1 200 OK\r\n\r\n", "time": 0.1}

        # 基线 3 次正常 → CL.TE 超时 → TE.CL 正常 → TE.TE 4 变体正常
        mock_raw.side_effect = [
            baseline_resp,
            baseline_resp,
            baseline_resp,
            timeout_resp,  # CL.TE 检测
            normal_resp,  # TE.CL 检测
            normal_resp,  # TE.TE 变体 1
            normal_resp,  # TE.TE 变体 2
            normal_resp,  # TE.TE 变体 3
            normal_resp,  # TE.TE 变体 4
        ]

        results = self.detector.detect("https://example.com/")
        smuggling_results = [r for r in results if r.vulnerable]
        assert len(smuggling_results) >= 1
        assert smuggling_results[0].extra["smuggle_type"] == "CL.TE"

    @patch.object(HTTPSmugglingDetector, "_raw_request")
    def test_tecl_detection(self, mock_raw):
        """TE.CL 走私检测"""
        baseline_resp = {"status": 200, "raw": "HTTP/1.1 200 OK\r\n\r\n", "time": 0.1}
        timeout_resp = {"status": 0, "raw": "", "time": 15.0, "timeout": True}
        normal_resp = {"status": 200, "raw": "HTTP/1.1 200 OK\r\n\r\n", "time": 0.1}

        mock_raw.side_effect = [
            baseline_resp,
            baseline_resp,
            baseline_resp,
            normal_resp,  # CL.TE 正常
            timeout_resp,  # TE.CL 超时
            normal_resp,
            normal_resp,
            normal_resp,
            normal_resp,
        ]

        results = self.detector.detect("https://example.com/")
        tecl_results = [
            r for r in results if r.vulnerable and r.extra.get("smuggle_type") == "TE.CL"
        ]
        assert len(tecl_results) == 1

    @patch.object(HTTPSmugglingDetector, "_raw_request")
    def test_tete_detection(self, mock_raw):
        """TE.TE 走私检测"""
        baseline_resp = {"status": 200, "raw": "HTTP/1.1 200 OK\r\n\r\n", "time": 0.1}
        timeout_resp = {"status": 0, "raw": "", "time": 15.0, "timeout": True}
        normal_resp = {"status": 200, "raw": "HTTP/1.1 200 OK\r\n\r\n", "time": 0.1}

        mock_raw.side_effect = [
            baseline_resp,
            baseline_resp,
            baseline_resp,
            normal_resp,  # CL.TE 正常
            normal_resp,  # TE.CL 正常
            timeout_resp,  # TE.TE 变体 1 超时
        ]

        results = self.detector.detect("https://example.com/")
        tete_results = [
            r for r in results if r.vulnerable and r.extra.get("smuggle_type") == "TE.TE"
        ]
        assert len(tete_results) == 1

    def test_raw_request_timeout(self):
        """测试原始请求超时处理"""
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = socket.timeout("timed out")
            mock_socket_cls.return_value = mock_sock

            result = self.detector._raw_request(
                "example.com", 80, b"GET / HTTP/1.1\r\n\r\n", False, 1.0
            )
            # 超时应返回带 timeout 标记的结果
            assert result is not None
            assert result.get("timeout") is True

    def test_raw_request_connection_error(self):
        """测试原始请求连接错误"""
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = ConnectionRefusedError("refused")
            mock_socket_cls.return_value = mock_sock

            result = self.detector._raw_request(
                "example.com", 80, b"GET / HTTP/1.1\r\n\r\n", False, 1.0
            )
            assert result is not None
            assert result.get("timeout") is True


# ==================== CachePoisoningDetector Tests ====================


class TestCachePoisoningDetector:
    """Cache Poisoning 检测器测试"""

    def setup_method(self):
        self.detector = CachePoisoningDetector()

    def test_attributes(self):
        """测试检测器属性"""
        assert self.detector.name == "cache_poisoning"
        assert self.detector.severity == Severity.HIGH
        assert self.detector.version == "1.0.0"

    def test_invalid_url(self):
        """无效 URL 应返回空结果"""
        results = self.detector.detect("not-a-valid-url")
        assert results == []

    def test_cache_buster_uniqueness(self):
        """cache buster 值应唯一"""
        values = {self.detector._generate_cache_buster() for _ in range(10)}
        # 至少应有多个不同值 (时间精度可能导致少量重复)
        assert len(values) >= 2

    @patch.object(CachePoisoningDetector, "_safe_request")
    def test_no_cache_layer(self, mock_request):
        """无缓存层时仍应继续检测"""
        mock_resp = MagicMock()
        mock_resp.headers = {"content-type": "text/html"}
        mock_resp.text = "<html>no nonce here</html>"
        mock_resp.status_code = 200
        mock_request.return_value = mock_resp

        results = self.detector.detect("https://example.com/")
        # 没有 nonce 反射，应无漏洞
        assert all(not r.vulnerable for r in results)

    @patch.object(CachePoisoningDetector, "_safe_request")
    def test_unkeyed_header_reflection_cached(self, mock_request):
        """Unkeyed Header 反射且被缓存应报告漏洞"""
        nonce_holder = {}

        def side_effect(method, url, headers=None, data=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200

            # 检测缓存层的请求
            if headers is None and data is None:
                # 缓存检测 + 验证请求
                if nonce_holder.get("nonce"):
                    # 验证请求 — 返回含 nonce 的缓存响应
                    resp.text = f"<html>cached {nonce_holder['nonce']}</html>"
                else:
                    resp.text = "<html>normal</html>"
                resp.headers = {"content-type": "text/html"}
                return resp

            # 带 header 的投毒请求
            if headers:
                for k, v in headers.items():
                    if "cache-poison-" in str(v) or "nothttps" in str(v) or "127.0.0.1" in str(v):
                        # 提取 nonce
                        if "cache-poison-" in str(v):
                            nonce = str(v).split("cache-poison-")[1].split(".")[0]
                            nonce_holder["nonce"] = nonce
                            resp.text = f"<html>reflected {nonce}</html>"
                            resp.headers = {"content-type": "text/html"}
                            return resp

            resp.text = "<html>normal</html>"
            resp.headers = {"content-type": "text/html"}
            return resp

        mock_request.side_effect = side_effect

        results = self.detector.detect("https://example.com/")
        vuln_results = [r for r in results if r.vulnerable]
        assert len(vuln_results) >= 1
        assert vuln_results[0].extra["poison_type"] in ("unkeyed_header", "header_reflection")

    @patch.object(CachePoisoningDetector, "_safe_request")
    def test_unkeyed_header_reflection_not_cached(self, mock_request):
        """Header 反射但未缓存应报告低置信度漏洞"""
        nonce_holder = {}

        def side_effect(method, url, headers=None, data=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200

            if headers:
                for k, v in headers.items():
                    if "cache-poison-" in str(v):
                        nonce = str(v).split("cache-poison-")[1].split(".")[0]
                        nonce_holder["nonce"] = nonce
                        resp.text = f"<html>reflected {nonce}</html>"
                        resp.headers = {"content-type": "text/html"}
                        return resp

            # 验证请求 — 不返回 nonce（未缓存）
            resp.text = "<html>normal no nonce</html>"
            resp.headers = {"content-type": "text/html"}
            return resp

        mock_request.side_effect = side_effect

        results = self.detector.detect("https://example.com/")
        vuln_results = [r for r in results if r.vulnerable]
        if vuln_results:
            # 如果有结果，应是低置信度的 header_reflection
            assert vuln_results[0].confidence <= 0.60
            assert vuln_results[0].extra["cached"] is False

    @patch.object(CachePoisoningDetector, "_safe_request")
    def test_cache_layer_detection_via_headers(self, mock_request):
        """通过缓存 header 检测缓存层"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "content-type": "text/html",
            "x-cache": "MISS from cdn",
            "age": "0",
        }
        mock_resp.text = "<html>test</html>"
        mock_request.return_value = mock_resp

        has_cache = self.detector._detect_cache_layer("https://example.com/")
        assert has_cache is True

    @patch.object(CachePoisoningDetector, "_safe_request")
    def test_no_cache_layer_detection(self, mock_request):
        """无缓存 header 时应返回 False"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "text/html"}
        mock_resp.text = "<html>test</html>"
        mock_request.return_value = mock_resp

        has_cache = self.detector._detect_cache_layer("https://example.com/")
        assert has_cache is False

    @patch.object(CachePoisoningDetector, "_safe_request")
    def test_request_failure_handled(self, mock_request):
        """请求失败应优雅处理"""
        mock_request.return_value = None
        results = self.detector.detect("https://example.com/")
        assert results == []

    @patch.object(CachePoisoningDetector, "_safe_request")
    def test_fat_get_detection(self, mock_request):
        """Fat GET 投毒检测"""
        call_count = {"n": 0}

        def side_effect(method, url, headers=None, data=None, **kwargs):
            call_count["n"] += 1
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "text/html"}

            # Fat GET 请求 (带 body 的 GET)
            if data and "callback=" in str(data):
                # 提取 nonce
                parts = str(data).split("callback=")
                if len(parts) > 1:
                    nonce = parts[1].split("&")[0]
                    resp.text = f"<html>callback({nonce})</html>"
                    return resp

            resp.text = "<html>normal</html>"
            return resp

        mock_request.side_effect = side_effect

        # 直接测试 _detect_fat_get
        result = self.detector._detect_fat_get("https://example.com/", "testnonce123")
        # 由于验证请求不包含 nonce（normal response），不应确认缓存投毒
        assert result is None


class TestDetectorRegistration:
    """测试检测器注册"""

    def test_http_smuggling_registered(self):
        """HTTPSmugglingDetector 应已注册到工厂"""
        from core.detectors.factory import DetectorFactory

        assert DetectorFactory.exists("http_smuggling")

    def test_cache_poisoning_registered(self):
        """CachePoisoningDetector 应已注册到工厂"""
        from core.detectors.factory import DetectorFactory

        assert DetectorFactory.exists("cache_poisoning")

    def test_factory_create_http_smuggling(self):
        """工厂应能创建 HTTPSmugglingDetector"""
        from core.detectors.factory import DetectorFactory

        detector = DetectorFactory.create("http_smuggling")
        assert isinstance(detector, HTTPSmugglingDetector)

    def test_factory_create_cache_poisoning(self):
        """工厂应能创建 CachePoisoningDetector"""
        from core.detectors.factory import DetectorFactory

        detector = DetectorFactory.create("cache_poisoning")
        assert isinstance(detector, CachePoisoningDetector)

    def test_importable_from_detectors_package(self):
        """应可从 core.detectors 包直接导入"""
        from core.detectors import CachePoisoningDetector as CP
        from core.detectors import HTTPSmugglingDetector as HS

        assert CP is not None
        assert HS is not None
