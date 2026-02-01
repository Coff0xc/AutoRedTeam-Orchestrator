#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE 数据源
支持 NVD、Nuclei Templates、Exploit-DB 等多个数据源

作者: AutoRedTeam-Orchestrator
"""

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from .models import CVSS, CVEEntry, Reference, Severity

logger = logging.getLogger(__name__)

# HTTP 客户端
try:
    from core.http import get_client

    HAS_HTTP_FACTORY = True
except ImportError:
    HAS_HTTP_FACTORY = False

try:
    import aiohttp

    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


class RateLimiter:
    """速率限制器"""

    def __init__(self, requests_per_period: int, period_seconds: int):
        """
        初始化速率限制器

        Args:
            requests_per_period: 时间段内允许的请求数
            period_seconds: 时间段长度 (秒)
        """
        self.requests_per_period = requests_per_period
        self.period_seconds = period_seconds
        self.request_times: List[datetime] = []

    async def acquire(self):
        """获取请求许可"""
        now = datetime.now()

        # 清理过期记录
        cutoff = now - timedelta(seconds=self.period_seconds)
        self.request_times = [t for t in self.request_times if t > cutoff]

        # 检查是否超过限制
        if len(self.request_times) >= self.requests_per_period:
            sleep_time = (self.request_times[0] - cutoff).total_seconds()
            if sleep_time > 0:
                logger.debug(f"速率限制: 等待 {sleep_time:.1f}s")
                await asyncio.sleep(sleep_time)

        # 记录本次请求
        self.request_times.append(now)


class CVESource(ABC):
    """CVE 数据源基类"""

    name: str = "base"

    def __init__(self):
        self._session = None

    @abstractmethod
    async def fetch_recent(self, days: int = 7) -> List[CVEEntry]:
        """
        获取最近的 CVE

        Args:
            days: 获取最近 N 天的 CVE

        Returns:
            CVE 条目列表
        """
        ...

    @abstractmethod
    async def search(self, keyword: str, limit: int = 100) -> List[CVEEntry]:
        """
        搜索 CVE

        Args:
            keyword: 搜索关键词
            limit: 结果数量限制

        Returns:
            CVE 条目列表
        """
        ...

    @abstractmethod
    async def get_detail(self, cve_id: str) -> Optional[CVEEntry]:
        """
        获取 CVE 详情

        Args:
            cve_id: CVE ID

        Returns:
            CVE 条目或 None
        """
        ...

    async def _fetch_json(
        self, url: str, headers: Optional[Dict] = None, timeout: int = 30
    ) -> Optional[Dict[str, Any]]:
        """
        异步获取 JSON 数据

        Args:
            url: 请求地址
            headers: 请求头
            timeout: 超时时间

        Returns:
            JSON 数据或 None
        """
        if HAS_HTTP_FACTORY:
            try:
                client = get_client()
                response = await asyncio.to_thread(
                    lambda: client.get(url, headers=headers, timeout=timeout)
                )
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warning(f"HTTP {response.status_code}: {url}")
                    return None
            except Exception as e:
                logger.error(f"请求失败 [{self.name}]: {url}, 错误: {e}")
                return None

        elif HAS_AIOHTTP:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False,
                    ) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        else:
                            logger.warning(f"HTTP {resp.status}: {url}")
                            return None
            except Exception as e:
                logger.error(f"请求失败 [{self.name}]: {url}, 错误: {e}")
                return None

        else:
            logger.error("没有可用的 HTTP 库")
            return None

    async def _fetch_text(
        self, url: str, headers: Optional[Dict] = None, timeout: int = 60
    ) -> Optional[str]:
        """
        异步获取文本数据

        Args:
            url: 请求地址
            headers: 请求头
            timeout: 超时时间

        Returns:
            文本数据或 None
        """
        if HAS_HTTP_FACTORY:
            try:
                client = get_client()
                response = await asyncio.to_thread(
                    lambda: client.get(url, headers=headers, timeout=timeout)
                )
                if response.status_code == 200:
                    return response.text
                else:
                    logger.warning(f"HTTP {response.status_code}: {url}")
                    return None
            except Exception as e:
                logger.error(f"请求失败 [{self.name}]: {url}, 错误: {e}")
                return None

        elif HAS_AIOHTTP:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False,
                    ) as resp:
                        if resp.status == 200:
                            return await resp.text()
                        else:
                            logger.warning(f"HTTP {resp.status}: {url}")
                            return None
            except Exception as e:
                logger.error(f"请求失败 [{self.name}]: {url}, 错误: {e}")
                return None

        else:
            logger.error("没有可用的 HTTP 库")
            return None

    def close(self):
        """关闭数据源"""
        if self._session:
            self._session = None


class NVDSource(CVESource):
    """NVD 数据源 (National Vulnerability Database)"""

    name = "nvd"
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # 速率限制: 无 API Key 5次/30秒, 有 API Key 50次/30秒
    RATE_LIMIT_NO_KEY = (5, 30)
    RATE_LIMIT_WITH_KEY = (50, 30)

    def __init__(self, api_key: Optional[str] = None):
        """
        初始化 NVD 数据源

        Args:
            api_key: NVD API Key (可提高速率限制)
        """
        super().__init__()
        self.api_key = api_key

        # 设置速率限制
        if api_key:
            self._rate_limiter = RateLimiter(*self.RATE_LIMIT_WITH_KEY)
        else:
            self._rate_limiter = RateLimiter(*self.RATE_LIMIT_NO_KEY)

    async def fetch_recent(self, days: int = 7) -> List[CVEEntry]:
        """获取最近的 CVE"""
        logger.info(f"[NVD] 获取最近 {days} 天的 CVE")

        entries = []
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        # 构建请求参数
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
        }

        # 分页获取
        start_index = 0
        results_per_page = 100

        while True:
            await self._rate_limiter.acquire()

            url = f"{self.BASE_URL}?startIndex={start_index}&resultsPerPage={results_per_page}"
            for key, value in params.items():
                url += f"&{key}={value}"

            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            data = await self._fetch_json(url, headers)
            if not data or "vulnerabilities" not in data:
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            # 解析 CVE 条目
            for vuln in vulns:
                entry = self._parse_nvd_entry(vuln)
                if entry:
                    entries.append(entry)

            # 检查分页
            total_results = data.get("totalResults", 0)
            if start_index + results_per_page >= total_results:
                break

            start_index += results_per_page
            logger.debug(f"[NVD] 进度: {start_index}/{total_results}")

        logger.info(f"[NVD] 获取完成: {len(entries)} 条")
        return entries

    async def search(self, keyword: str, limit: int = 100) -> List[CVEEntry]:
        """搜索 CVE"""
        logger.info(f"[NVD] 搜索: {keyword}")

        entries = []
        await self._rate_limiter.acquire()

        url = f"{self.BASE_URL}?keywordSearch={keyword}&resultsPerPage={min(limit, 100)}"

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        data = await self._fetch_json(url, headers)
        if data and "vulnerabilities" in data:
            for vuln in data["vulnerabilities"][:limit]:
                entry = self._parse_nvd_entry(vuln)
                if entry:
                    entries.append(entry)

        logger.info(f"[NVD] 搜索完成: {len(entries)} 条")
        return entries

    async def get_detail(self, cve_id: str) -> Optional[CVEEntry]:
        """获取 CVE 详情"""
        logger.debug(f"[NVD] 获取详情: {cve_id}")

        await self._rate_limiter.acquire()

        url = f"{self.BASE_URL}?cveId={cve_id}"

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        data = await self._fetch_json(url, headers)
        if data and "vulnerabilities" in data and data["vulnerabilities"]:
            return self._parse_nvd_entry(data["vulnerabilities"][0])

        return None

    def _parse_nvd_entry(self, data: Dict[str, Any]) -> Optional[CVEEntry]:
        """
        解析 NVD CVE 条目

        Args:
            data: NVD API 返回的漏洞数据

        Returns:
            CVEEntry 或 None
        """
        try:
            cve_data = data.get("cve", {})
            cve_id = cve_data.get("id", "")

            if not cve_id:
                return None

            # 提取描述
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available",
            )

            # 提取 CVSS
            metrics = cve_data.get("metrics", {})
            cvss = None
            severity = Severity.UNKNOWN

            # 优先使用 CVSS 3.1
            cvss_v31 = metrics.get("cvssMetricV31", [])
            if cvss_v31:
                cvss_data = cvss_v31[0].get("cvssData", {})
                cvss = CVSS(
                    version="3.1",
                    score=cvss_data.get("baseScore", 0.0),
                    vector=cvss_data.get("vectorString", ""),
                    severity=Severity.from_string(cvss_data.get("baseSeverity", "")),
                )
                severity = cvss.severity
            else:
                # 回退到 CVSS 3.0
                cvss_v30 = metrics.get("cvssMetricV30", [])
                if cvss_v30:
                    cvss_data = cvss_v30[0].get("cvssData", {})
                    cvss = CVSS(
                        version="3.0",
                        score=cvss_data.get("baseScore", 0.0),
                        vector=cvss_data.get("vectorString", ""),
                        severity=Severity.from_string(cvss_data.get("baseSeverity", "")),
                    )
                    severity = cvss.severity
                else:
                    # 回退到 CVSS 2.0
                    cvss_v2 = metrics.get("cvssMetricV2", [])
                    if cvss_v2:
                        cvss_data = cvss_v2[0].get("cvssData", {})
                        cvss = CVSS(
                            version="2.0",
                            score=cvss_data.get("baseScore", 0.0),
                            vector=cvss_data.get("vectorString", ""),
                            severity=Severity.from_cvss(cvss_data.get("baseScore", 0.0)),
                        )
                        severity = cvss.severity

            # 提取受影响产品
            affected_products = []
            affected_versions = []
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe = cpe_match.get("criteria", "")
                        if cpe:
                            # 解析 CPE: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
                            parts = cpe.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
                                affected_products.append(f"{vendor}:{product}")
                                if version:
                                    affected_versions.append(version)

            # 提取 CWE
            weaknesses = cve_data.get("weaknesses", [])
            cwe_ids = []
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    cwe_value = desc.get("value", "")
                    if cwe_value.startswith("CWE-"):
                        cwe_ids.append(cwe_value)

            # 提取参考链接
            refs_data = cve_data.get("references", [])
            references = []
            poc_urls = []
            has_poc = False

            for ref in refs_data:
                url = ref.get("url", "")
                source = ref.get("source", "")
                tags = ref.get("tags", [])

                references.append(Reference(url=url, source=source, tags=tags))

                # 检查是否有 PoC/Exploit
                if any(tag in ["Exploit", "Third Party Advisory"] for tag in tags):
                    has_poc = True
                    poc_urls.append(url)

            # 解析时间
            published = cve_data.get("published", "")
            modified = cve_data.get("lastModified", "")

            published_date = None
            modified_date = None

            if published:
                try:
                    published_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass

            if modified:
                try:
                    modified_date = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass

            return CVEEntry(
                cve_id=cve_id,
                title=f"{cve_id}",
                description=description[:2000],  # 限制长度
                cvss=cvss,
                severity=severity,
                affected_products=list(set(affected_products)),
                affected_versions=list(set(affected_versions)),
                cwe_ids=list(set(cwe_ids)),
                published_date=published_date,
                modified_date=modified_date,
                references=references,
                has_poc=has_poc,
                poc_urls=poc_urls,
                exploit_available=has_poc,
                source="nvd",
                tags=[],
            )

        except Exception as e:
            logger.error(f"[NVD] 解析 CVE 失败: {e}")
            return None


class NucleiSource(CVESource):
    """Nuclei Templates 数据源"""

    name = "nuclei"
    GITHUB_API = "https://api.github.com/repos/projectdiscovery/nuclei-templates"

    # GitHub API 速率限制: 未认证 60次/小时, 认证 5000次/小时
    RATE_LIMIT_NO_TOKEN = (60, 3600)
    RATE_LIMIT_WITH_TOKEN = (5000, 3600)

    def __init__(self, github_token: Optional[str] = None):
        """
        初始化 Nuclei 数据源

        Args:
            github_token: GitHub Token (可提高速率限制)
        """
        super().__init__()
        self.github_token = github_token

        if github_token:
            self._rate_limiter = RateLimiter(*self.RATE_LIMIT_WITH_TOKEN)
        else:
            self._rate_limiter = RateLimiter(*self.RATE_LIMIT_NO_TOKEN)

    async def fetch_recent(self, days: int = 7) -> List[CVEEntry]:
        """获取最近的 CVE 模板"""
        logger.info(f"[Nuclei] 获取最近更新的模板 (days={days})")

        entries = []
        await self._rate_limiter.acquire()

        # 获取 CVE 目录下的文件树
        url = f"{self.GITHUB_API}/git/trees/main?recursive=1"

        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"

        data = await self._fetch_json(url, headers)
        if not data or "tree" not in data:
            logger.warning("[Nuclei] 无法获取文件树")
            return entries

        # 筛选 CVE 相关文件
        cve_files = [
            item
            for item in data["tree"]
            if item.get("path", "").startswith("http/cves/")
            and item.get("path", "").endswith(".yaml")
        ]

        logger.info(f"[Nuclei] 发现 {len(cve_files)} 个 CVE 模板")

        # 解析 CVE ID 和基本信息
        for file_info in cve_files:
            path = file_info.get("path", "")
            filename = path.split("/")[-1].replace(".yaml", "")

            # 提取 CVE ID
            cve_match = re.match(r"(CVE-\d{4}-\d+)", filename, re.IGNORECASE)
            if cve_match:
                cve_id = cve_match.group(1).upper()

                entry = CVEEntry(
                    cve_id=cve_id,
                    title=f"{cve_id} - Nuclei Template",
                    description=f"Nuclei PoC template available for {cve_id}",
                    has_poc=True,
                    poc_urls=[
                        f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{path}"
                    ],
                    exploit_available=True,
                    source="nuclei",
                    tags=["nuclei", "poc"],
                )
                entries.append(entry)

        logger.info(f"[Nuclei] 获取完成: {len(entries)} 条")
        return entries

    async def search(self, keyword: str, limit: int = 100) -> List[CVEEntry]:
        """搜索 Nuclei 模板"""
        logger.info(f"[Nuclei] 搜索: {keyword}")

        entries = []
        await self._rate_limiter.acquire()

        # 使用 GitHub Search API
        url = f"https://api.github.com/search/code?q={keyword}+repo:projectdiscovery/nuclei-templates+path:http/cves&per_page={min(limit, 100)}"

        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"

        data = await self._fetch_json(url, headers)
        if data and "items" in data:
            for item in data["items"][:limit]:
                path = item.get("path", "")
                filename = path.split("/")[-1].replace(".yaml", "")

                cve_match = re.match(r"(CVE-\d{4}-\d+)", filename, re.IGNORECASE)
                if cve_match:
                    cve_id = cve_match.group(1).upper()

                    entry = CVEEntry(
                        cve_id=cve_id,
                        title=f"{cve_id} - Nuclei Template",
                        description=f"Nuclei PoC template available for {cve_id}",
                        has_poc=True,
                        poc_urls=[item.get("html_url", "")],
                        exploit_available=True,
                        source="nuclei",
                        tags=["nuclei", "poc"],
                    )
                    entries.append(entry)

        logger.info(f"[Nuclei] 搜索完成: {len(entries)} 条")
        return entries

    async def get_detail(self, cve_id: str) -> Optional[CVEEntry]:
        """获取 Nuclei 模板详情"""
        # Nuclei 源主要用于标记 PoC 可用性，详情从 NVD 获取
        entries = await self.search(cve_id, limit=1)
        return entries[0] if entries else None


class ExploitDBSource(CVESource):
    """Exploit-DB 数据源"""

    name = "exploitdb"
    CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

    def __init__(self):
        super().__init__()
        self._rate_limiter = RateLimiter(1, 60)  # 1次/分钟
        self._cache: Dict[str, CVEEntry] = {}
        self._cache_loaded = False

    async def _load_cache(self):
        """加载 Exploit-DB CSV 数据到缓存"""
        if self._cache_loaded:
            return

        logger.info("[ExploitDB] 加载数据...")
        await self._rate_limiter.acquire()

        csv_content = await self._fetch_text(self.CSV_URL)
        if not csv_content:
            logger.warning("[ExploitDB] 无法下载数据")
            return

        # 解析 CSV
        lines = csv_content.strip().split("\n")[1:]  # 跳过表头

        for line in lines:
            try:
                # CSV 格式: id,file,description,date_published,author,type,platform,port,codes
                parts = line.split(",")
                if len(parts) < 9:
                    continue

                exploit_id = parts[0]
                file_path = parts[1]
                description = parts[2].strip('"')
                date_published = parts[3]
                author = parts[4]
                exploit_type = parts[5]
                platform = parts[6]
                codes = parts[8] if len(parts) > 8 else ""

                # 提取 CVE ID
                cve_matches = re.findall(r"CVE-\d{4}-\d+", description + " " + codes, re.IGNORECASE)

                for cve_id in set(cve_matches):
                    cve_id = cve_id.upper()

                    if cve_id in self._cache:
                        # 更新已存在的条目
                        existing = self._cache[cve_id]
                        existing.poc_urls.append(
                            f"https://www.exploit-db.com/exploits/{exploit_id}"
                        )
                    else:
                        # 创建新条目
                        entry = CVEEntry(
                            cve_id=cve_id,
                            title=f"{cve_id} - {description[:100]}",
                            description=description[:500],
                            has_poc=True,
                            poc_urls=[f"https://www.exploit-db.com/exploits/{exploit_id}"],
                            exploit_available=True,
                            source="exploitdb",
                            tags=["exploit-db", exploit_type.lower(), platform.lower()],
                        )
                        self._cache[cve_id] = entry

            except Exception as e:
                logger.debug(f"[ExploitDB] 解析行失败: {e}")
                continue

        self._cache_loaded = True
        logger.info(f"[ExploitDB] 加载完成: {len(self._cache)} 条")

    async def fetch_recent(self, days: int = 7) -> List[CVEEntry]:
        """获取最近的 Exploit"""
        await self._load_cache()
        # Exploit-DB 没有精确的时间筛选，返回所有缓存
        return list(self._cache.values())[:500]

    async def search(self, keyword: str, limit: int = 100) -> List[CVEEntry]:
        """搜索 Exploit"""
        await self._load_cache()

        keyword_lower = keyword.lower()
        results = []

        for cve_id, entry in self._cache.items():
            if (
                keyword_lower in cve_id.lower()
                or keyword_lower in entry.description.lower()
                or keyword_lower in entry.title.lower()
            ):
                results.append(entry)
                if len(results) >= limit:
                    break

        return results

    async def get_detail(self, cve_id: str) -> Optional[CVEEntry]:
        """获取 Exploit 详情"""
        await self._load_cache()
        return self._cache.get(cve_id.upper())


class GitHubPoCSource(CVESource):
    """GitHub PoC-in-GitHub 数据源"""

    name = "github-poc"
    SEARCH_URL = "https://api.github.com/search/repositories"

    def __init__(self, github_token: Optional[str] = None):
        super().__init__()
        self.github_token = github_token

        if github_token:
            self._rate_limiter = RateLimiter(30, 60)
        else:
            self._rate_limiter = RateLimiter(10, 60)

    async def fetch_recent(self, days: int = 7) -> List[CVEEntry]:
        """获取最近的 PoC"""
        logger.info(f"[GitHub PoC] 获取最近 {days} 天的 PoC")

        entries = []
        await self._rate_limiter.acquire()

        # 搜索最近创建的 CVE 相关仓库
        since_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        url = f"{self.SEARCH_URL}?q=CVE+in:name+created:>{since_date}&sort=updated&order=desc&per_page=100"

        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"

        data = await self._fetch_json(url, headers)
        if data and "items" in data:
            for item in data["items"]:
                repo_name = item.get("name", "")
                description = item.get("description", "") or ""

                # 提取 CVE ID
                cve_match = re.search(
                    r"CVE-\d{4}-\d+", repo_name + " " + description, re.IGNORECASE
                )
                if cve_match:
                    cve_id = cve_match.group(0).upper()

                    entry = CVEEntry(
                        cve_id=cve_id,
                        title=f"{cve_id} - {repo_name}",
                        description=description[:500] or f"GitHub PoC for {cve_id}",
                        has_poc=True,
                        poc_urls=[item.get("html_url", "")],
                        exploit_available=True,
                        source="github-poc",
                        tags=["github", "poc"],
                    )
                    entries.append(entry)

        logger.info(f"[GitHub PoC] 获取完成: {len(entries)} 条")
        return entries

    async def search(self, keyword: str, limit: int = 100) -> List[CVEEntry]:
        """搜索 GitHub PoC"""
        logger.info(f"[GitHub PoC] 搜索: {keyword}")

        entries = []
        await self._rate_limiter.acquire()

        url = f"{self.SEARCH_URL}?q={keyword}+CVE&sort=stars&order=desc&per_page={min(limit, 100)}"

        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"

        data = await self._fetch_json(url, headers)
        if data and "items" in data:
            for item in data["items"][:limit]:
                repo_name = item.get("name", "")
                description = item.get("description", "") or ""

                cve_match = re.search(
                    r"CVE-\d{4}-\d+", repo_name + " " + description, re.IGNORECASE
                )
                if cve_match:
                    cve_id = cve_match.group(0).upper()

                    entry = CVEEntry(
                        cve_id=cve_id,
                        title=f"{cve_id} - {repo_name}",
                        description=description[:500] or f"GitHub PoC for {cve_id}",
                        has_poc=True,
                        poc_urls=[item.get("html_url", "")],
                        exploit_available=True,
                        source="github-poc",
                        tags=["github", "poc"],
                    )
                    entries.append(entry)

        logger.info(f"[GitHub PoC] 搜索完成: {len(entries)} 条")
        return entries

    async def get_detail(self, cve_id: str) -> Optional[CVEEntry]:
        """获取 PoC 详情"""
        entries = await self.search(cve_id, limit=1)
        return entries[0] if entries else None


class AggregatedSource(CVESource):
    """聚合数据源 - 合并多个数据源的结果"""

    name = "aggregated"

    def __init__(self, sources: List[CVESource]):
        """
        初始化聚合数据源

        Args:
            sources: 数据源列表
        """
        super().__init__()
        self.sources = sources

    async def fetch_recent(self, days: int = 7) -> List[CVEEntry]:
        """从所有源获取最近的 CVE 并去重合并"""
        logger.info(f"[Aggregated] 从 {len(self.sources)} 个源获取数据...")

        tasks = [source.fetch_recent(days) for source in self.sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return self._merge_results(results)

    async def search(self, keyword: str, limit: int = 100) -> List[CVEEntry]:
        """从所有源搜索并去重合并"""
        logger.info(f"[Aggregated] 搜索: {keyword}")

        tasks = [source.search(keyword, limit) for source in self.sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        merged = self._merge_results(results)
        return merged[:limit]

    async def get_detail(self, cve_id: str) -> Optional[CVEEntry]:
        """从所有源获取详情并合并"""
        tasks = [source.get_detail(cve_id) for source in self.sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        entries = [r for r in results if isinstance(r, CVEEntry)]

        if not entries:
            return None

        # 合并所有条目
        merged = entries[0]
        for entry in entries[1:]:
            merged = merged.merge_with(entry)

        return merged

    def _merge_results(self, results: List) -> List[CVEEntry]:
        """
        合并多个数据源的结果

        Args:
            results: 各数据源返回的结果列表

        Returns:
            合并去重后的 CVE 列表
        """
        cve_map: Dict[str, CVEEntry] = {}

        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"[Aggregated] 数据源错误: {result}")
                continue

            if not isinstance(result, list):
                continue

            for entry in result:
                if not isinstance(entry, CVEEntry):
                    continue

                if entry.cve_id in cve_map:
                    # 合并已存在的条目
                    cve_map[entry.cve_id] = cve_map[entry.cve_id].merge_with(entry)
                else:
                    cve_map[entry.cve_id] = entry

        # 按发布时间排序 (最新的在前)
        entries = list(cve_map.values())
        entries.sort(key=lambda x: x.published_date or datetime.min, reverse=True)

        logger.info(f"[Aggregated] 合并完成: {len(entries)} 条 (去重后)")
        return entries


# 便捷函数
def create_nvd_source(api_key: Optional[str] = None) -> NVDSource:
    """创建 NVD 数据源"""
    import os

    api_key = api_key or os.environ.get("NVD_API_KEY")
    return NVDSource(api_key=api_key)


def create_nuclei_source(github_token: Optional[str] = None) -> NucleiSource:
    """创建 Nuclei 数据源"""
    import os

    github_token = github_token or os.environ.get("GITHUB_TOKEN")
    return NucleiSource(github_token=github_token)


def create_exploitdb_source() -> ExploitDBSource:
    """创建 ExploitDB 数据源"""
    return ExploitDBSource()


def create_github_poc_source(github_token: Optional[str] = None) -> GitHubPoCSource:
    """创建 GitHub PoC 数据源"""
    import os

    github_token = github_token or os.environ.get("GITHUB_TOKEN")
    return GitHubPoCSource(github_token=github_token)


def create_aggregated_source(
    include_nvd: bool = True,
    include_nuclei: bool = True,
    include_exploitdb: bool = True,
    include_github_poc: bool = False,
    nvd_api_key: Optional[str] = None,
    github_token: Optional[str] = None,
) -> AggregatedSource:
    """
    创建聚合数据源

    Args:
        include_nvd: 是否包含 NVD
        include_nuclei: 是否包含 Nuclei
        include_exploitdb: 是否包含 ExploitDB
        include_github_poc: 是否包含 GitHub PoC
        nvd_api_key: NVD API Key
        github_token: GitHub Token

    Returns:
        聚合数据源
    """
    sources = []

    if include_nvd:
        sources.append(create_nvd_source(nvd_api_key))

    if include_nuclei:
        sources.append(create_nuclei_source(github_token))

    if include_exploitdb:
        sources.append(create_exploitdb_source())

    if include_github_poc:
        sources.append(create_github_poc_source(github_token))

    return AggregatedSource(sources)
