#!/usr/bin/env python3
"""
被动侦察引擎 — 通过公开 API 收集子域名和情报

内置替代 subfinder/amass 的被动收集能力。
零主动流量，仅查询公开数据源。

使用:
    from core.recon.passive_recon import PassiveRecon
    recon = PassiveRecon()
    subs = await recon.discover_subdomains("example.com")
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Dict, List, Optional, Set
from urllib.parse import quote, urlparse

logger = logging.getLogger(__name__)


class PassiveRecon:
    """被动侦察引擎 — 6 个公开数据源并发查询

    数据源:
    1. crt.sh (Certificate Transparency)
    2. HackerTarget (DNS 查询)
    3. AlienVault OTX (威胁情报)
    4. URLScan.io (网站快照)
    5. RapidDNS (DNS 聚合)
    6. Web Archive (Wayback Machine CDX)
    """

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    async def discover_subdomains(self, domain: str) -> List[str]:
        """查询所有被动源，合并去重"""
        from utils.async_utils import gather_with_limit

        sources = [
            ("crt.sh", self._query_crtsh),
            ("HackerTarget", self._query_hackertarget),
            ("AlienVault", self._query_alienvault),
            ("URLScan", self._query_urlscan),
            ("RapidDNS", self._query_rapiddns),
            ("WebArchive", self._query_webarchive),
        ]

        coros = [self._safe_query(name, fn, domain) for name, fn in sources]
        results = await gather_with_limit(coros, limit=6, return_exceptions=True)

        all_subs: Set[str] = set()
        for result in results:
            if isinstance(result, set):
                all_subs.update(result)

        domain_lower = domain.lower()
        valid = {
            s.lower().strip().rstrip(".")
            for s in all_subs
            if s.lower().endswith(f".{domain_lower}") or s.lower() == domain_lower
        }

        logger.info("被动侦察完成: %s, 发现 %d 个子域名", domain, len(valid))
        return sorted(valid)

    async def _safe_query(self, name: str, fn, domain: str) -> Set[str]:
        """安全包装: 单个源失败不影响整体"""
        try:
            result = await asyncio.wait_for(fn(domain), timeout=self.timeout)
            logger.info("被动源 %s: 发现 %d 个子域名", name, len(result))
            return result
        except asyncio.TimeoutError:
            logger.warning("被动源 %s 超时", name)
            return set()
        except Exception as e:
            logger.warning("被动源 %s 失败: %s", name, e)
            return set()

    async def _http_get(self, url: str) -> Optional[str]:
        """统一 HTTP 请求"""
        try:
            from core.http.client import get_client

            client = get_client()
            response = await asyncio.to_thread(client.get, url)
            if response and response.status_code == 200:
                return response.text
        except Exception:
            pass
        return None

    async def _query_crtsh(self, domain: str) -> Set[str]:
        """Certificate Transparency — crt.sh"""
        url = f"https://crt.sh/?q=%.{quote(domain)}&output=json"
        text = await self._http_get(url)
        if not text:
            return set()
        subs: Set[str] = set()
        try:
            for entry in json.loads(text):
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name and "*" not in name:
                        subs.add(name)
        except (json.JSONDecodeError, TypeError):
            pass
        return subs

    async def _query_hackertarget(self, domain: str) -> Set[str]:
        """HackerTarget API"""
        url = f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}"
        text = await self._http_get(url)
        if not text or "error" in text.lower()[:50]:
            return set()
        subs: Set[str] = set()
        for line in text.strip().split("\n"):
            parts = line.split(",")
            if parts:
                subs.add(parts[0].strip().lower())
        return subs

    async def _query_alienvault(self, domain: str) -> Set[str]:
        """AlienVault OTX"""
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/passive_dns"
        text = await self._http_get(url)
        if not text:
            return set()
        subs: Set[str] = set()
        try:
            for record in json.loads(text).get("passive_dns", []):
                hostname = record.get("hostname", "").strip().lower()
                if hostname:
                    subs.add(hostname)
        except (json.JSONDecodeError, TypeError):
            pass
        return subs

    async def _query_urlscan(self, domain: str) -> Set[str]:
        """URLScan.io"""
        url = f"https://urlscan.io/api/v1/search/?q=domain:{quote(domain)}&size=100"
        text = await self._http_get(url)
        if not text:
            return set()
        subs: Set[str] = set()
        try:
            for result in json.loads(text).get("results", []):
                page_domain = result.get("page", {}).get("domain", "").strip().lower()
                if page_domain:
                    subs.add(page_domain)
        except (json.JSONDecodeError, TypeError):
            pass
        return subs

    async def _query_rapiddns(self, domain: str) -> Set[str]:
        """RapidDNS"""
        url = f"https://rapiddns.io/subdomain/{quote(domain)}?full=1"
        text = await self._http_get(url)
        if not text:
            return set()
        subs: Set[str] = set()
        pattern = re.compile(r"<td>([a-zA-Z0-9._-]+\." + re.escape(domain) + r")</td>")
        for match in pattern.finditer(text):
            subs.add(match.group(1).lower())
        return subs

    async def _query_webarchive(self, domain: str) -> Set[str]:
        """Wayback Machine CDX API"""
        url = (
            f"https://web.archive.org/cdx/search/cdx?url=*.{quote(domain)}"
            f"&output=json&fl=original&collapse=urlkey&limit=500"
        )
        text = await self._http_get(url)
        if not text:
            return set()
        subs: Set[str] = set()
        try:
            rows = json.loads(text)
            for row in rows[1:]:
                if row:
                    parsed = urlparse(row[0] if isinstance(row, list) else row)
                    if parsed.hostname:
                        subs.add(parsed.hostname.lower())
        except (json.JSONDecodeError, IndexError, TypeError):
            pass
        return subs

    # ==================== 高级接口 ====================

    async def discover_subdomains_with_sources(
        self, domain: str
    ) -> Dict[str, List[str]]:
        """查询所有被动源，按源分类返回

        Args:
            domain: 目标根域名

        Returns:
            字典 {源名称: [子域名列表]}
        """
        from utils.async_utils import gather_with_limit

        sources = [
            ("crt.sh", self._query_crtsh),
            ("HackerTarget", self._query_hackertarget),
            ("AlienVault", self._query_alienvault),
            ("URLScan", self._query_urlscan),
            ("RapidDNS", self._query_rapiddns),
            ("WebArchive", self._query_webarchive),
        ]

        coros = [self._safe_query(name, fn, domain) for name, fn in sources]
        results = await gather_with_limit(coros, limit=6, return_exceptions=True)

        domain_lower = domain.lower()
        source_results: Dict[str, List[str]] = {}
        for i, result in enumerate(results):
            name = sources[i][0]
            if isinstance(result, set):
                filtered = sorted(
                    s.lower().strip().rstrip(".")
                    for s in result
                    if s.lower().endswith(f".{domain_lower}")
                    or s.lower() == domain_lower
                )
                source_results[name] = filtered
            else:
                source_results[name] = []

        return source_results


# 便捷函数
async def passive_subdomain_discovery(
    domain: str, timeout: int = 15
) -> List[str]:
    """便捷函数: 被动子域名发现

    Args:
        domain: 目标根域名
        timeout: HTTP 超时时间

    Returns:
        排序后的子域名列表
    """
    recon = PassiveRecon(timeout=timeout)
    return await recon.discover_subdomains(domain)


# 导出
__all__ = [
    "PassiveRecon",
    "passive_subdomain_discovery",
]
