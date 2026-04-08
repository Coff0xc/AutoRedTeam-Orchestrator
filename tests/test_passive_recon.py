#!/usr/bin/env python3
"""
被动侦察模块测试

mock 各 HTTP 响应测试每个被动源 + 整体合并逻辑。
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ==================== Fixtures ====================


@pytest.fixture
def passive_recon():
    """创建 PassiveRecon 实例"""
    from core.recon.passive_recon import PassiveRecon

    return PassiveRecon(timeout=5)


def _mock_response(text: str = "", status_code: int = 200):
    """构建 mock HTTP 响应"""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.json = MagicMock(return_value=json.loads(text) if text else {})
    return resp


# ==================== 单源测试 ====================


class TestCrtsh:
    """crt.sh 数据源测试"""

    async def test_crtsh_parses_json(self, passive_recon):
        data = json.dumps([
            {"name_value": "sub1.example.com\nsub2.example.com"},
            {"name_value": "*.example.com"},
        ])
        resp = _mock_response(data)
        with patch.object(passive_recon, "_http_get", return_value=data):
            result = await passive_recon._query_crtsh("example.com")
        # 应该解析出 sub1 和 sub2 (通配符被过滤)
        assert "sub1.example.com" in result
        assert "sub2.example.com" in result

    async def test_crtsh_handles_empty(self, passive_recon):
        with patch.object(passive_recon, "_http_get", return_value=None):
            result = await passive_recon._query_crtsh("example.com")
        assert result == set()

    async def test_crtsh_handles_bad_json(self, passive_recon):
        with patch.object(passive_recon, "_http_get", return_value="not json"):
            result = await passive_recon._query_crtsh("example.com")
        assert result == set()


class TestHackerTarget:
    """HackerTarget 数据源测试"""

    async def test_hackertarget_parses_csv(self, passive_recon):
        csv_text = "sub1.example.com,1.2.3.4\nsub2.example.com,5.6.7.8\n"
        with patch.object(passive_recon, "_http_get", return_value=csv_text):
            result = await passive_recon._query_hackertarget("example.com")
        assert "sub1.example.com" in result
        assert "sub2.example.com" in result

    async def test_hackertarget_handles_error(self, passive_recon):
        with patch.object(
            passive_recon, "_http_get", return_value="error: rate limit"
        ):
            result = await passive_recon._query_hackertarget("example.com")
        assert result == set()

    async def test_hackertarget_handles_none(self, passive_recon):
        with patch.object(passive_recon, "_http_get", return_value=None):
            result = await passive_recon._query_hackertarget("example.com")
        assert result == set()


class TestAlienVault:
    """AlienVault OTX 数据源测试"""

    async def test_alienvault_parses_dns(self, passive_recon):
        data = json.dumps({
            "passive_dns": [
                {"hostname": "api.example.com"},
                {"hostname": "mail.example.com"},
            ]
        })
        with patch.object(passive_recon, "_http_get", return_value=data):
            result = await passive_recon._query_alienvault("example.com")
        assert "api.example.com" in result
        assert "mail.example.com" in result

    async def test_alienvault_handles_empty(self, passive_recon):
        with patch.object(passive_recon, "_http_get", return_value=None):
            result = await passive_recon._query_alienvault("example.com")
        assert result == set()


class TestURLScan:
    """URLScan.io 数据源测试"""

    async def test_urlscan_parses_results(self, passive_recon):
        data = json.dumps({
            "results": [
                {"page": {"domain": "app.example.com"}, "task": {"domain": ""}},
                {"page": {"domain": "www.example.com"}, "task": {"domain": ""}},
            ]
        })
        with patch.object(passive_recon, "_http_get", return_value=data):
            result = await passive_recon._query_urlscan("example.com")
        assert "app.example.com" in result
        assert "www.example.com" in result


class TestRapidDNS:
    """RapidDNS 数据源测试"""

    async def test_rapiddns_parses_html(self, passive_recon):
        html = """
        <table>
        <tr><td>sub1.example.com</td><td>1.2.3.4</td></tr>
        <tr><td>sub2.example.com</td><td>5.6.7.8</td></tr>
        </table>
        """
        with patch.object(passive_recon, "_http_get", return_value=html):
            result = await passive_recon._query_rapiddns("example.com")
        assert "sub1.example.com" in result
        assert "sub2.example.com" in result


class TestWebArchive:
    """Wayback Machine 数据源测试"""

    async def test_webarchive_parses_cdx(self, passive_recon):
        data = json.dumps([
            ["original"],
            ["http://old.example.com/page"],
            ["https://archive.example.com/test"],
        ])
        with patch.object(passive_recon, "_http_get", return_value=data):
            result = await passive_recon._query_webarchive("example.com")
        assert "old.example.com" in result
        assert "archive.example.com" in result


# ==================== 集成测试 ====================


class TestDiscoverSubdomains:
    """discover_subdomains 集成测试"""

    async def test_merges_and_deduplicates(self, passive_recon):
        """验证多源结果合并去重"""
        async def mock_crtsh(domain):
            return {"sub1.example.com", "sub2.example.com"}

        async def mock_hackertarget(domain):
            return {"sub2.example.com", "sub3.example.com"}

        async def mock_empty(domain):
            return set()

        async def mock_fail(domain):
            raise Exception("source down")

        with patch.object(passive_recon, "_query_crtsh", mock_crtsh), \
             patch.object(passive_recon, "_query_hackertarget", mock_hackertarget), \
             patch.object(passive_recon, "_query_alienvault", mock_empty), \
             patch.object(passive_recon, "_query_urlscan", mock_empty), \
             patch.object(passive_recon, "_query_rapiddns", mock_empty), \
             patch.object(passive_recon, "_query_webarchive", mock_fail):
            result = await passive_recon.discover_subdomains("example.com")

        assert "sub1.example.com" in result
        assert "sub2.example.com" in result
        assert "sub3.example.com" in result
        # 去重: 总共3个
        assert len(result) == 3
        # 排序
        assert result == sorted(result)

    async def test_filters_unrelated_domains(self, passive_recon):
        """验证过滤非目标域名"""
        async def mock_crtsh(domain):
            return {"sub.example.com", "sub.other.com", "evil.com"}

        async def mock_empty(domain):
            return set()

        with patch.object(passive_recon, "_query_crtsh", mock_crtsh), \
             patch.object(passive_recon, "_query_hackertarget", mock_empty), \
             patch.object(passive_recon, "_query_alienvault", mock_empty), \
             patch.object(passive_recon, "_query_urlscan", mock_empty), \
             patch.object(passive_recon, "_query_rapiddns", mock_empty), \
             patch.object(passive_recon, "_query_webarchive", mock_empty):
            result = await passive_recon.discover_subdomains("example.com")

        assert "sub.example.com" in result
        assert "sub.other.com" not in result
        assert "evil.com" not in result

    async def test_all_sources_fail(self, passive_recon):
        """验证所有源失败时返回空列表"""
        async def mock_fail(domain):
            raise Exception("down")

        with patch.object(passive_recon, "_query_crtsh", mock_fail), \
             patch.object(passive_recon, "_query_hackertarget", mock_fail), \
             patch.object(passive_recon, "_query_alienvault", mock_fail), \
             patch.object(passive_recon, "_query_urlscan", mock_fail), \
             patch.object(passive_recon, "_query_rapiddns", mock_fail), \
             patch.object(passive_recon, "_query_webarchive", mock_fail):
            result = await passive_recon.discover_subdomains("example.com")

        assert result == []

    async def test_empty_domain(self, passive_recon):
        """验证空域名返回空列表"""
        result = await passive_recon.discover_subdomains("")
        assert result == []


class TestDiscoverWithSources:
    """discover_subdomains_with_sources 测试"""

    async def test_returns_by_source(self, passive_recon):
        async def mock_crtsh(domain):
            return {"api.example.com"}

        async def mock_empty(domain):
            return set()

        with patch.object(passive_recon, "_query_crtsh", mock_crtsh), \
             patch.object(passive_recon, "_query_hackertarget", mock_empty), \
             patch.object(passive_recon, "_query_alienvault", mock_empty), \
             patch.object(passive_recon, "_query_urlscan", mock_empty), \
             patch.object(passive_recon, "_query_rapiddns", mock_empty), \
             patch.object(passive_recon, "_query_webarchive", mock_empty):
            result = await passive_recon.discover_subdomains_with_sources(
                "example.com"
            )

        assert "crt.sh" in result
        assert "api.example.com" in result["crt.sh"]
        assert "HackerTarget" in result
        assert result["HackerTarget"] == []


# ==================== 便捷函数测试 ====================


class TestConvenienceFunction:
    async def test_passive_subdomain_discovery(self):
        from core.recon.passive_recon import passive_subdomain_discovery

        with patch(
            "core.recon.passive_recon.PassiveRecon.discover_subdomains",
            new_callable=AsyncMock,
            return_value=["a.example.com", "b.example.com"],
        ):
            result = await passive_subdomain_discovery("example.com")
        assert len(result) == 2
