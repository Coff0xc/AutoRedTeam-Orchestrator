"""
Prototype Pollution 检测器测试

测试 PrototypePollutionDetector 的核心逻辑。
使用 mock 模拟网络请求，不发送真实流量。
"""

from unittest.mock import MagicMock, patch

from core.detectors.injection.prototype_pollution import (
    PrototypePollutionDetector,
    _random_canary,
)
from core.detectors.result import Severity


class TestPrototypePollutionDetector:
    """Prototype Pollution 检测器测试"""

    def setup_method(self):
        self.detector = PrototypePollutionDetector()

    def test_attributes(self):
        """测试检测器属性"""
        assert self.detector.name == "prototype_pollution"
        assert self.detector.severity == Severity.HIGH
        assert self.detector.version == "1.0.0"

    def test_invalid_url(self):
        """无效 URL 应返回空结果"""
        results = self.detector.detect("not-a-valid-url")
        assert results == []

    def test_random_canary_uniqueness(self):
        """canary key/value 应唯一"""
        pairs = {_random_canary() for _ in range(20)}
        assert len(pairs) >= 15  # 应有大部分唯一

    def test_random_canary_format(self):
        """canary key 应以 pptest 开头"""
        key, value = _random_canary()
        assert key.startswith("pptest")
        assert value.startswith("v")
        assert len(key) > 8
        assert len(value) > 1

    @patch.object(PrototypePollutionDetector, "_safe_request")
    def test_no_pollution_detected(self, mock_request):
        """正常响应不应报告漏洞"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"status": "ok"}'
        mock_resp.headers = {"content-type": "application/json"}
        mock_request.return_value = mock_resp

        results = self.detector.detect("https://example.com/api/settings")
        assert all(not r.vulnerable for r in results)

    @patch.object(PrototypePollutionDetector, "_safe_request")
    def test_server_pp_persistent(self, mock_request):
        """服务端持久原型链污染检测"""
        canary_found = {"key": None}

        def side_effect(method, url, json_data=None, headers=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}

            if json_data and isinstance(json_data, dict):
                # 检查是否包含 __proto__
                proto = json_data.get("__proto__", {})
                if isinstance(proto, dict):
                    for k, v in proto.items():
                        if k.startswith("pptest"):
                            canary_found["key"] = k
                            canary_found["value"] = v
                            # 模拟被污染的响应
                            resp.text = f'{{"status": "ok", "{k}": "{v}"}}'
                            return resp

            # 验证请求 - 返回带 canary 的响应 (模拟持久污染)
            if canary_found["key"] and method == "GET":
                k = canary_found["key"]
                v = canary_found["value"]
                resp.text = f'{{"data": {{}}, "{k}": "{v}"}}'
                return resp

            resp.text = '{"status": "ok"}'
            return resp

        mock_request.side_effect = side_effect

        results = self.detector.detect("https://example.com/api/settings")
        vuln_results = [r for r in results if r.vulnerable]
        assert len(vuln_results) >= 1
        assert vuln_results[0].extra["pp_type"] == "server_persistent"
        assert vuln_results[0].confidence >= 0.85

    @patch.object(PrototypePollutionDetector, "_safe_request")
    def test_server_pp_reflected_only(self, mock_request):
        """服务端非持久反射检测"""
        call_count = {"n": 0}

        def side_effect(method, url, json_data=None, headers=None, **kwargs):
            call_count["n"] += 1
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}

            if json_data and isinstance(json_data, dict):
                proto = json_data.get("__proto__", {})
                if isinstance(proto, dict):
                    for k, v in proto.items():
                        if k.startswith("pptest"):
                            resp.text = f'{{"reflected": "{v}"}}'
                            return resp

            # 验证请求 - 正常响应 (无持久污染)
            resp.text = '{"status": "ok"}'
            return resp

        mock_request.side_effect = side_effect

        results = self.detector.detect("https://example.com/api/settings")
        reflected = [
            r for r in results if r.vulnerable and r.extra.get("pp_type") == "server_reflected"
        ]
        if reflected:
            assert reflected[0].confidence < 0.70  # 应低于持久污染的置信度

    @patch.object(PrototypePollutionDetector, "_safe_request")
    def test_server_pp_error_detection(self, mock_request):
        """__proto__ 导致 500 错误检测"""

        def side_effect(method, url, json_data=None, headers=None, **kwargs):
            resp = MagicMock()
            resp.headers = {"content-type": "application/json"}

            if json_data and isinstance(json_data, dict):
                if "__proto__" in json_data or "constructor" in json_data:
                    resp.status_code = 500
                    resp.text = "Internal Server Error"
                    return resp

            resp.status_code = 200
            resp.text = '{"status": "ok"}'
            return resp

        mock_request.side_effect = side_effect

        results = self.detector.detect("https://example.com/api/settings")
        error_results = [
            r for r in results if r.vulnerable and r.extra.get("pp_type") == "server_error"
        ]
        assert len(error_results) >= 1

    @patch.object(PrototypePollutionDetector, "_safe_request")
    def test_client_pp_detection(self, mock_request):
        """客户端原型链污染检测"""

        def side_effect(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "text/html"}

            if "__proto__" in url or "constructor" in url:
                # 从 URL 中提取 canary value
                for part in url.split("="):
                    if part.startswith("v") and len(part) == 9:
                        resp.text = f"<html><script>var x = '{part}';</script></html>"
                        return resp

            resp.text = "<html><body>normal page</body></html>"
            return resp

        mock_request.side_effect = side_effect

        results = self.detector.detect("https://example.com/page")
        client_results = [r for r in results if r.vulnerable and r.extra.get("pp_type") == "client"]
        assert len(client_results) >= 1

    @patch.object(PrototypePollutionDetector, "_safe_request")
    def test_request_failure_handled(self, mock_request):
        """请求失败应优雅处理"""
        mock_request.return_value = None
        results = self.detector.detect("https://example.com/api")
        assert results == []

    def test_build_payload_dict(self):
        """测试 payload 构建"""
        template = {"__proto__": {"{key}": "{value}"}}
        result = self.detector._build_payload(template, "testkey", "testval")
        assert result == {"__proto__": {"testkey": "testval"}}

    def test_build_payload_nested(self):
        """测试嵌套 payload 构建"""
        template = {"constructor": {"prototype": {"{key}": "{value}"}}}
        result = self.detector._build_payload(template, "k1", "v1")
        assert result == {"constructor": {"prototype": {"k1": "v1"}}}

    def test_build_payload_string_returns_none(self):
        """字符串模板应返回 None"""
        result = self.detector._build_payload("not a dict", "k", "v")
        assert result is None


class TestPrototypePollutionRegistration:
    """测试检测器注册"""

    def test_registered_in_factory(self):
        """应已注册到 DetectorFactory"""
        from core.detectors.factory import DetectorFactory

        assert DetectorFactory.exists("prototype_pollution")

    def test_factory_create(self):
        """工厂应能创建实例"""
        from core.detectors.factory import DetectorFactory

        detector = DetectorFactory.create("prototype_pollution")
        assert isinstance(detector, PrototypePollutionDetector)

    def test_importable_from_package(self):
        """应可从 core.detectors 包直接导入"""
        from core.detectors import PrototypePollutionDetector as PP

        assert PP is not None
