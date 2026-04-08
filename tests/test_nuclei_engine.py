"""Nuclei 模板引擎测试

覆盖:
- YAML 模板解析
- Matcher 逻辑 (status / word / regex / negative)
- 变量替换 ({{BaseURL}}, {{Hostname}}, {{RootURL}}, {{Path}})
- Mock HTTP 响应测试 scan
- Extractor 提取
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.detectors.nuclei_engine import (
    NucleiEngine,
    NucleiMatcher,
    NucleiRequest,
    NucleiTemplate,
    _build_variables,
    _substitute,
    check_matcher,
    check_matchers,
    run_extractors,
)

# ─────────────── fixtures ───────────────

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "nuclei"


@pytest.fixture
def xss_template() -> NucleiTemplate:
    """加载测试用 XSS 模板"""
    return NucleiTemplate.from_yaml(FIXTURES_DIR / "test-xss-reflected.yaml")


@pytest.fixture
def cve_template() -> NucleiTemplate:
    """加载测试用 CVE 模板"""
    return NucleiTemplate.from_yaml(FIXTURES_DIR / "test-cve-2021-44228.yaml")


@pytest.fixture
def engine() -> NucleiEngine:
    """创建指向 fixtures 目录的引擎"""
    return NucleiEngine(template_dir=FIXTURES_DIR)


# ─────────────── 模板解析 ───────────────


class TestTemplateParser:
    """YAML 模板解析测试"""

    def test_parse_xss_template(self, xss_template: NucleiTemplate):
        assert xss_template.id == "test-xss-reflected"
        assert xss_template.severity == "medium"
        assert "xss" in xss_template.tags
        assert "test" in xss_template.tags
        assert len(xss_template.requests) == 1

    def test_parse_cve_template(self, cve_template: NucleiTemplate):
        assert cve_template.id == "test-cve-2021-44228"
        assert cve_template.severity == "critical"
        assert "cve" in cve_template.tags
        assert "rce" in cve_template.tags
        assert cve_template.reference
        assert "CVE-2021-44228" in cve_template.reference[0]

    def test_parse_request_details(self, xss_template: NucleiTemplate):
        req = xss_template.requests[0]
        assert req.method == "GET"
        assert len(req.path) == 1
        assert "{{BaseURL}}" in req.path[0]
        assert req.matchers_condition == "and"
        assert len(req.matchers) == 2

    def test_parse_cve_headers(self, cve_template: NucleiTemplate):
        req = cve_template.requests[0]
        assert "X-Api-Version" in req.headers
        assert "{{Hostname}}" in req.headers["X-Api-Version"]

    def test_parse_extractors(self, cve_template: NucleiTemplate):
        req = cve_template.requests[0]
        assert len(req.extractors) == 1
        ext = req.extractors[0]
        assert ext.type == "regex"
        assert ext.name == "version"
        assert ext.group == 1

    def test_from_dict(self):
        data = {
            "id": "dict-test",
            "info": {
                "name": "Dict Test",
                "severity": "low",
                "tags": "test,dict",
            },
            "http": [
                {
                    "method": "POST",
                    "path": ["/api"],
                    "body": '{"key":"value"}',
                    "matchers": [
                        {"type": "status", "status": [200]},
                    ],
                }
            ],
        }
        tmpl = NucleiTemplate.from_dict(data)
        assert tmpl.id == "dict-test"
        assert tmpl.severity == "low"
        assert tmpl.tags == ["test", "dict"]
        assert tmpl.requests[0].method == "POST"
        assert tmpl.requests[0].body == '{"key":"value"}'

    def test_missing_id_raises(self):
        with pytest.raises(ValueError, match="缺少 'id'"):
            NucleiTemplate.from_dict({"info": {"name": "x", "severity": "low"}})

    def test_missing_info_raises(self):
        with pytest.raises(ValueError, match="缺少 'info'"):
            NucleiTemplate.from_dict({"id": "bad"})


# ─────────────── 变量替换 ───────────────


class TestVariableSubstitution:

    def test_build_variables_basic(self):
        variables = _build_variables("http://example.com/path")
        assert variables["BaseURL"] == "http://example.com/path"
        assert variables["Hostname"] == "example.com"
        assert variables["RootURL"] == "http://example.com"
        assert variables["Path"] == "/path"
        assert variables["Scheme"] == "http"

    def test_build_variables_https_with_port(self):
        variables = _build_variables("https://target.io:8443/app")
        assert variables["RootURL"] == "https://target.io:8443"
        assert variables["Hostname"] == "target.io"
        assert variables["Port"] == "8443"

    def test_build_variables_default_ports(self):
        v_http = _build_variables("http://a.com")
        assert v_http["Port"] == "80"

        v_https = _build_variables("https://a.com")
        assert v_https["Port"] == "443"

    def test_substitute(self):
        variables = _build_variables("http://target.com")
        result = _substitute("{{BaseURL}}/admin?host={{Hostname}}", variables)
        assert result == "http://target.com/admin?host=target.com"

    def test_substitute_unknown_var(self):
        result = _substitute("{{Unknown}}", {"BaseURL": "x"})
        assert result == "{{Unknown}}"

    def test_substitute_none(self):
        result = _substitute(None, {})
        assert result is None

    def test_trailing_slash_stripped(self):
        variables = _build_variables("http://target.com/")
        assert variables["BaseURL"] == "http://target.com"


# ─────────────── Matcher 逻辑 ───────────────


class TestMatchers:

    def test_status_match(self):
        m = NucleiMatcher(type="status", status=[200, 302])
        assert check_matcher(m, 200, {}, "") is True
        assert check_matcher(m, 404, {}, "") is False

    def test_word_match_or(self):
        m = NucleiMatcher(type="word", words=["admin", "root"], condition="or")
        assert check_matcher(m, 200, {}, "welcome admin") is True
        assert check_matcher(m, 200, {}, "no match") is False

    def test_word_match_and(self):
        m = NucleiMatcher(type="word", words=["admin", "root"], condition="and")
        assert check_matcher(m, 200, {}, "admin and root") is True
        assert check_matcher(m, 200, {}, "admin only") is False

    def test_regex_match(self):
        m = NucleiMatcher(type="regex", regex=[r"version[\s:]+\d+\.\d+"])
        assert check_matcher(m, 200, {}, "version: 1.0") is True
        assert check_matcher(m, 200, {}, "no version") is False

    def test_negative_matcher(self):
        m = NucleiMatcher(type="word", words=["error"], negative=True)
        # 不含 error -> negative 使结果为 True
        assert check_matcher(m, 200, {}, "success") is True
        # 含 error -> negative 使结果为 False
        assert check_matcher(m, 200, {}, "error occurred") is False

    def test_size_matcher(self):
        m = NucleiMatcher(type="size", size=[5])
        assert check_matcher(m, 200, {}, "hello") is True
        assert check_matcher(m, 200, {}, "hi") is False

    def test_header_part(self):
        m = NucleiMatcher(type="word", words=["X-Custom"], part="header")
        headers = {"X-Custom": "value"}
        assert check_matcher(m, 200, headers, "") is True

    def test_all_part(self):
        m = NucleiMatcher(type="word", words=["secret"], part="all")
        assert check_matcher(m, 200, {}, "has secret") is True
        assert check_matcher(m, 200, {"X-Secret": "secret"}, "") is True

    def test_check_matchers_and(self):
        matchers = [
            NucleiMatcher(type="status", status=[200]),
            NucleiMatcher(type="word", words=["ok"]),
        ]
        assert check_matchers(matchers, "and", 200, {}, "ok") is True
        assert check_matchers(matchers, "and", 404, {}, "ok") is False

    def test_check_matchers_or(self):
        matchers = [
            NucleiMatcher(type="status", status=[200]),
            NucleiMatcher(type="word", words=["error"]),
        ]
        assert check_matchers(matchers, "or", 200, {}, "no match") is True
        assert check_matchers(matchers, "or", 404, {}, "no match") is False

    def test_check_matchers_empty(self):
        assert check_matchers([], "or", 200, {}, "") is False

    def test_invalid_regex_graceful(self):
        m = NucleiMatcher(type="regex", regex=["[invalid"])
        # 不应抛异常
        assert check_matcher(m, 200, {}, "test") is False


# ─────────────── Extractor 测试 ───────────────


class TestExtractors:

    def test_regex_extractor(self):
        from core.detectors.nuclei_engine import NucleiExtractor

        ext = NucleiExtractor(type="regex", name="version", regex=[r"Server: Apache/([\d.]+)"], group=1)
        result = run_extractors([ext], {}, "Server: Apache/2.4.49")
        assert result["version"] == "2.4.49"

    def test_regex_extractor_no_match(self):
        from core.detectors.nuclei_engine import NucleiExtractor

        ext = NucleiExtractor(type="regex", name="version", regex=[r"Nginx/([\d.]+)"], group=1)
        result = run_extractors([ext], {}, "Server: Apache/2.4.49")
        assert "version" not in result

    def test_regex_extractor_header_part(self):
        from core.detectors.nuclei_engine import NucleiExtractor

        ext = NucleiExtractor(type="regex", name="token", regex=[r"Token: (\w+)"], group=1, part="header")
        result = run_extractors([ext], {"Token": "abc123"}, "")
        assert result["token"] == "abc123"


# ─────────────── Engine 集成 ───────────────


class TestEngine:

    def test_load_templates(self, engine: NucleiEngine):
        count = engine.load_templates()
        assert count == 2  # fixtures 目录有 2 个模板

    def test_load_filter_by_severity(self, engine: NucleiEngine):
        count = engine.load_templates(severity=["critical"])
        assert count == 1
        assert engine.templates[0].id == "test-cve-2021-44228"

    def test_load_filter_by_tag(self, engine: NucleiEngine):
        count = engine.load_templates(tags=["xss"])
        assert count == 1
        assert engine.templates[0].id == "test-xss-reflected"

    def test_load_with_limit(self, engine: NucleiEngine):
        count = engine.load_templates(limit=1)
        assert count == 1

    def test_load_nonexistent_dir(self):
        engine = NucleiEngine(template_dir="/nonexistent/path")
        assert engine.load_templates() == 0

    def test_load_template_from_dict(self, engine: NucleiEngine):
        data = {
            "id": "dynamic-1",
            "info": {"name": "Dynamic", "severity": "info", "tags": "test"},
            "http": [{"method": "GET", "path": ["/"], "matchers": []}],
        }
        tmpl = engine.load_template_from_dict(data)
        assert tmpl.id == "dynamic-1"
        assert tmpl in engine.templates

    def test_execute_template_sync(self, engine: NucleiEngine):
        engine.load_templates(tags=["xss"])
        tmpl = engine.templates[0]

        # 模拟命中: 响应包含 XSS payload + 状态码 200
        result = engine.execute_template_sync(
            template=tmpl,
            target="http://target.com",
            status_code=200,
            headers={},
            body="<html><script>alert(1)</script></html>",
        )
        assert result is not None
        assert result["template_id"] == "test-xss-reflected"
        assert result["severity"] == "medium"

    def test_execute_template_sync_no_match(self, engine: NucleiEngine):
        engine.load_templates(tags=["xss"])
        tmpl = engine.templates[0]

        result = engine.execute_template_sync(
            template=tmpl,
            target="http://target.com",
            status_code=200,
            headers={},
            body="<html>safe</html>",
        )
        assert result is None

    async def test_scan_with_mock(self, engine: NucleiEngine):
        """Mock HTTP 响应测试异步 scan"""
        engine.load_templates(tags=["xss"])

        # 创建模拟响应
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = "<html><script>alert(1)</script></html>"

        # Mock HTTPClient — 延迟导入在 core.http 模块中
        mock_client_instance = MagicMock()
        mock_client_instance.async_request = AsyncMock(return_value=mock_response)
        mock_client_instance.close = MagicMock()

        with patch("core.http.HTTPClient", return_value=mock_client_instance):
            results = await engine.scan("http://target.com", concurrency=5)

        assert len(results) == 1
        assert results[0]["template_id"] == "test-xss-reflected"

    async def test_scan_no_templates(self, engine: NucleiEngine):
        """无模板时应返回空结果"""
        results = await engine.scan("http://target.com")
        assert results == []

    async def test_scan_http_error_graceful(self, engine: NucleiEngine):
        """HTTP 请求异常不应中断整个扫描"""
        engine.load_templates()

        mock_client_instance = MagicMock()
        mock_client_instance.async_request = AsyncMock(side_effect=Exception("connection refused"))
        mock_client_instance.close = MagicMock()

        with patch("core.http.HTTPClient", return_value=mock_client_instance):
            results = await engine.scan("http://target.com")

        # 所有请求失败，应返回空结果
        assert results == []
