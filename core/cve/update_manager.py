#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE 多源同步管理器
支持: GitHub (nuclei-templates/PoC-in-GitHub), NVD API 2.0, Exploit-DB
作者: AutoRedTeam-Orchestrator
"""

import os
import sqlite3
import json
import asyncio
import aiohttp
import hashlib
import tempfile
import atexit
import shutil
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import logging

from utils.logger import configure_root_logger

# 统一 HTTP 客户端工厂
try:
    from core.http import get_async_client
    HAS_HTTP_FACTORY = True
except ImportError:
    HAS_HTTP_FACTORY = False

configure_root_logger(level=logging.INFO, log_to_file=True, log_to_console=True)
logger = logging.getLogger(__name__)


class Severity(Enum):
    """漏洞严重性等级"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass
class CVEEntry:
    """CVE条目数据模型"""
    cve_id: str
    description: str
    severity: str
    cvss: float
    affected_products: str  # JSON array string
    poc_available: bool
    poc_path: Optional[str]
    source: str
    last_updated: str

    def to_dict(self) -> Dict:
        return asdict(self)


class CVEUpdateManager:
    """CVE多源同步管理器"""

    # 数据库Schema
    DB_SCHEMA = """
    CREATE TABLE IF NOT EXISTS cve_index (
        cve_id TEXT PRIMARY KEY,
        description TEXT,
        severity TEXT,
        cvss REAL,
        affected_products TEXT,
        poc_available BOOLEAN,
        poc_path TEXT,
        source TEXT,
        last_updated TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_severity ON cve_index(severity);
    CREATE INDEX IF NOT EXISTS idx_cvss ON cve_index(cvss);
    CREATE INDEX IF NOT EXISTS idx_source ON cve_index(source);
    CREATE INDEX IF NOT EXISTS idx_updated ON cve_index(last_updated);

    CREATE TABLE IF NOT EXISTS sync_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT,
        sync_time TEXT,
        new_cves INTEGER,
        updated_cves INTEGER,
        status TEXT
    );

    CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filter_type TEXT,
        filter_value TEXT,
        enabled BOOLEAN DEFAULT 1,
        created_at TEXT
    );
    """

    # API配置
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    GITHUB_API_BASE = "https://api.github.com"
    EXPLOIT_DB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

    # 速率限制配置
    RATE_LIMITS = {
        "nvd": {"requests": 5, "per_seconds": 30},  # NVD: 5 req/30s (无API key)
        "github": {"requests": 60, "per_seconds": 3600},  # GitHub: 60 req/hour (未认证)
        "exploit_db": {"requests": 1, "per_seconds": 60}
    }

    def __init__(self, db_path: Optional[str] = None, cache_dir: Optional[str] = None):
        """
        初始化CVE更新管理器

        Args:
            db_path: 数据库路径 (默认: 项目根目录/data/cve_index.db)
            cache_dir: 缓存目录 (默认: 系统临时目录/cve_cache)
        """
        # 使用跨平台路径处理
        project_root = Path(__file__).parent.parent.parent

        if db_path:
            self.db_path = Path(db_path)
        else:
            data_dir = project_root / "data"
            data_dir.mkdir(exist_ok=True)
            self.db_path = data_dir / "cve_index.db"

        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path(tempfile.gettempdir()) / "cve_cache"

        self.cache_dir.mkdir(exist_ok=True)

        # 初始化数据库
        self._init_database()

        # 速率限制器
        self.rate_limiters = {
            source: {"requests": [], "config": config}
            for source, config in self.RATE_LIMITS.items()
        }

        # GitHub Token (可选,提高速率限制)
        self.github_token = os.getenv("GITHUB_TOKEN")

        # NVD API Key (可选,提高速率限制到50 req/30s)
        self.nvd_api_key = os.getenv("NVD_API_KEY")

        # 清理过期缓存文件
        self._cleanup_old_cache()

        # 注册退出时的清理函数
        atexit.register(self._cleanup_on_exit)

    def _cleanup_old_cache(self, max_age_days: int = 7):
        """清理过期的缓存文件

        Args:
            max_age_days: 最大缓存天数 (默认7天)
        """
        if not self.cache_dir.exists():
            return

        try:
            now = datetime.now()
            cutoff = now - timedelta(days=max_age_days)
            cleaned_count = 0
            cleaned_size = 0

            for cache_file in self.cache_dir.iterdir():
                if cache_file.is_file():
                    # 获取文件修改时间
                    mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
                    if mtime < cutoff:
                        file_size = cache_file.stat().st_size
                        cache_file.unlink()
                        cleaned_count += 1
                        cleaned_size += file_size

            if cleaned_count > 0:
                logger.info(f"清理过期缓存: {cleaned_count} 个文件, {cleaned_size / 1024:.1f} KB")

        except Exception as e:
            logger.warning(f"清理缓存文件失败: {e}")

    def _cleanup_on_exit(self):
        """程序退出时的清理函数"""
        try:
            # 清理空的缓存目录
            if self.cache_dir.exists() and not any(self.cache_dir.iterdir()):
                self.cache_dir.rmdir()
                logger.debug(f"清理空缓存目录: {self.cache_dir}")

            # 清理临时下载文件
            temp_pattern = "cve_temp_*"
            temp_dir = Path(tempfile.gettempdir())
            for temp_file in temp_dir.glob(temp_pattern):
                try:
                    if temp_file.is_file():
                        temp_file.unlink()
                    elif temp_file.is_dir():
                        shutil.rmtree(temp_file)
                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        except Exception as e:
            logger.debug(f"退出清理失败 (可忽略): {e}")

    def _init_database(self):
        """初始化SQLite数据库"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.executescript(self.DB_SCHEMA)
            conn.commit()
            conn.close()
            logger.info(f"数据库初始化成功: {self.db_path}")
        except Exception as e:
            logger.error(f"数据库初始化失败: {e}")
            raise

    async def _rate_limit(self, source: str):
        """速率限制器"""
        limiter = self.rate_limiters[source]
        config = limiter["config"]
        now = datetime.now()

        # 清理过期的请求记录
        cutoff = now - timedelta(seconds=config["per_seconds"])
        limiter["requests"] = [t for t in limiter["requests"] if t > cutoff]

        # 检查是否超过限制
        if len(limiter["requests"]) >= config["requests"]:
            sleep_time = (limiter["requests"][0] - cutoff).total_seconds()
            logger.warning(f"触发速率限制 [{source}], 等待 {sleep_time:.1f}s")
            await asyncio.sleep(sleep_time)

        # 记录本次请求
        limiter["requests"].append(now)

    async def _fetch_json(self, session: aiohttp.ClientSession, url: str,
                          source: str, headers: Optional[Dict] = None) -> Optional[Dict]:
        """异步HTTP请求(带速率限制)"""
        await self._rate_limit(source)

        try:
            async with session.get(url, headers=headers, timeout=30, ssl=False) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 403:
                    logger.warning(f"API访问受限 [{source}]: {url}")
                    return None
                else:
                    logger.error(f"请求失败 [{source}] {resp.status}: {url}")
                    return None
        except asyncio.TimeoutError:
            logger.error(f"请求超时 [{source}]: {url}")
            return None
        except Exception as e:
            logger.error(f"请求异常 [{source}]: {e}")
            return None

    async def sync_nvd(self, days_back: int = 7) -> Tuple[int, int]:
        """
        同步NVD数据库 (CVE官方来源)

        Args:
            days_back: 同步最近N天的CVE (默认7天)

        Returns:
            (新增CVE数, 更新CVE数)
        """
        logger.info(f"开始同步 NVD (最近 {days_back} 天)")

        new_count = 0
        updated_count = 0

        # 计算时间范围
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)

        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999")
        }

        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        # 使用统一 HTTP 客户端工厂或回退到 aiohttp
        if HAS_HTTP_FACTORY:
            client_ctx = get_async_client()
        else:
            client_ctx = aiohttp.ClientSession()

        async with client_ctx as session:
            # NVD API 2.0 使用分页
            start_index = 0
            results_per_page = 100  # 每页100条(最大2000)

            while True:
                url = f"{self.NVD_API_BASE}?startIndex={start_index}&resultsPerPage={results_per_page}"
                for key, value in params.items():
                    url += f"&{key}={value}"

                data = await self._fetch_json(session, url, "nvd", headers)

                if not data or "vulnerabilities" not in data:
                    break

                vulns = data["vulnerabilities"]
                if not vulns:
                    break

                # 处理CVE条目
                for vuln in vulns:
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")

                    if not cve_id:
                        continue

                    # 提取描述
                    descriptions = cve_data.get("descriptions", [])
                    description = next(
                        (d["value"] for d in descriptions if d.get("lang") == "en"),
                        "No description"
                    )

                    # 提取CVSS分数
                    metrics = cve_data.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [])
                    cvss_v2 = metrics.get("cvssMetricV2", [])

                    cvss_score = 0.0
                    severity = "UNKNOWN"

                    if cvss_v3:
                        cvss_score = cvss_v3[0]["cvssData"].get("baseScore", 0.0)
                        severity = cvss_v3[0]["cvssData"].get("baseSeverity", "UNKNOWN")
                    elif cvss_v2:
                        cvss_score = cvss_v2[0]["cvssData"].get("baseScore", 0.0)
                        severity = cvss_v2[0].get("baseSeverity", "UNKNOWN")

                    # 提取受影响产品
                    affected_products = []
                    configurations = cve_data.get("configurations", [])
                    for config in configurations:
                        for node in config.get("nodes", []):
                            for cpe_match in node.get("cpeMatch", []):
                                cpe = cpe_match.get("criteria", "")
                                if cpe:
                                    # 简化CPE格式: cpe:2.3:a:vendor:product:version
                                    parts = cpe.split(":")
                                    if len(parts) >= 5:
                                        affected_products.append(f"{parts[3]}:{parts[4]}")

                    entry = CVEEntry(
                        cve_id=cve_id,
                        description=description[:500],  # 限制长度
                        severity=severity.upper(),
                        cvss=cvss_score,
                        affected_products=json.dumps(list(set(affected_products))),
                        poc_available=False,
                        poc_path=None,
                        source="NVD",
                        last_updated=datetime.now().isoformat()
                    )

                    # 保存到数据库
                    if self._insert_or_update_cve(entry):
                        new_count += 1
                    else:
                        updated_count += 1

                # 检查是否还有更多数据
                total_results = data.get("totalResults", 0)
                if start_index + results_per_page >= total_results:
                    break

                start_index += results_per_page
                logger.info(f"NVD: 已处理 {start_index}/{total_results} 条")

        self._log_sync("NVD", new_count, updated_count, "SUCCESS")
        logger.info(f"NVD同步完成: 新增 {new_count}, 更新 {updated_count}")
        return new_count, updated_count

    async def sync_nuclei_templates(self) -> Tuple[int, int]:
        """
        同步Nuclei Templates (ProjectDiscovery官方PoC库)

        Returns:
            (新增CVE数, 更新CVE数)
        """
        logger.info("开始同步 Nuclei Templates")

        new_count = 0
        updated_count = 0

        # Nuclei Templates目录结构
        base_url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"

        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"

        # 使用统一 HTTP 客户端工厂或回退到 aiohttp
        if HAS_HTTP_FACTORY:
            client_ctx = get_async_client()
        else:
            client_ctx = aiohttp.ClientSession()

        async with client_ctx as session:
            # 获取文件树
            tree_data = await self._fetch_json(session, base_url, "github", headers)

            if not tree_data or "tree" not in tree_data:
                logger.error("Nuclei Templates: 无法获取文件树")
                return 0, 0

            # 筛选CVE相关文件
            cve_files = [
                item for item in tree_data["tree"]
                if item["path"].startswith("cves/") and item["path"].endswith(".yaml")
            ]

            logger.info(f"Nuclei Templates: 发现 {len(cve_files)} 个CVE模板")

            # 批量处理CVE文件 (限制并发)
            semaphore = asyncio.Semaphore(10)

            async def process_template(file_info):
                async with semaphore:
                    # 从文件名提取CVE ID
                    filename = Path(file_info["path"]).stem
                    if not filename.startswith("CVE-"):
                        return False

                    cve_id = filename.split("-")[0] + "-" + filename.split("-")[1]

                    # 获取CVE信息 (从本地数据库或NVD)
                    existing = self._get_cve(cve_id)

                    if existing:
                        # 更新PoC路径
                        existing.poc_available = True
                        existing.poc_path = f"nuclei-templates:{file_info['path']}"
                        existing.last_updated = datetime.now().isoformat()

                        self._insert_or_update_cve(existing)
                        return False
                    else:
                        # 创建新条目
                        entry = CVEEntry(
                            cve_id=cve_id,
                            description=f"Nuclei template available for {cve_id}",
                            severity="UNKNOWN",
                            cvss=0.0,
                            affected_products="[]",
                            poc_available=True,
                            poc_path=f"nuclei-templates:{file_info['path']}",
                            source="Nuclei",
                            last_updated=datetime.now().isoformat()
                        )

                        self._insert_or_update_cve(entry)
                        return True

            results = await asyncio.gather(*[process_template(f) for f in cve_files])
            new_count = sum(results)
            updated_count = len(results) - new_count

        self._log_sync("Nuclei", new_count, updated_count, "SUCCESS")
        logger.info(f"Nuclei同步完成: 新增 {new_count}, 更新 {updated_count}")
        return new_count, updated_count

    async def sync_exploit_db(self) -> Tuple[int, int]:
        """
        同步Exploit-DB (Offensive Security维护)

        Returns:
            (新增CVE数, 更新CVE数)
        """
        logger.info("开始同步 Exploit-DB")

        new_count = 0
        updated_count = 0

        # 使用统一 HTTP 客户端工厂或回退到 aiohttp
        if HAS_HTTP_FACTORY:
            client_ctx = get_async_client()
        else:
            client_ctx = aiohttp.ClientSession()

        async with client_ctx as session:
            await self._rate_limit("exploit_db")

            try:
                async with session.get(self.EXPLOIT_DB_CSV, timeout=60, ssl=False) as resp:
                    if resp.status != 200:
                        logger.error(f"Exploit-DB: 下载失败 {resp.status}")
                        return 0, 0

                    csv_content = await resp.text()

                    # 解析CSV (格式: id,file,description,date,author,type,platform,port,codes)
                    lines = csv_content.strip().split("\n")[1:]  # 跳过表头

                    for line in lines:
                        try:
                            parts = line.split(",")
                            if len(parts) < 3:
                                continue

                            description = parts[2].strip('"')

                            # 提取CVE ID
                            import re
                            cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', description, re.IGNORECASE)

                            if not cve_matches:
                                continue

                            for cve_id in set(cve_matches):
                                cve_id = cve_id.upper()

                                # 获取现有条目
                                existing = self._get_cve(cve_id)

                                exploit_id = parts[0]
                                exploit_path = f"exploit-db:exploits/{parts[1]}"

                                if existing:
                                    existing.poc_available = True
                                    existing.poc_path = exploit_path
                                    existing.last_updated = datetime.now().isoformat()

                                    self._insert_or_update_cve(existing)
                                    updated_count += 1
                                else:
                                    entry = CVEEntry(
                                        cve_id=cve_id,
                                        description=description[:500],
                                        severity="UNKNOWN",
                                        cvss=0.0,
                                        affected_products="[]",
                                        poc_available=True,
                                        poc_path=exploit_path,
                                        source="Exploit-DB",
                                        last_updated=datetime.now().isoformat()
                                    )

                                    self._insert_or_update_cve(entry)
                                    new_count += 1

                        except Exception as e:
                            logger.debug(f"Exploit-DB: 解析行失败 {e}")
                            continue

            except Exception as e:
                logger.error(f"Exploit-DB同步失败: {e}")
                return 0, 0

        self._log_sync("Exploit-DB", new_count, updated_count, "SUCCESS")
        logger.info(f"Exploit-DB同步完成: 新增 {new_count}, 更新 {updated_count}")
        return new_count, updated_count

    def _insert_or_update_cve(self, entry: CVEEntry) -> bool:
        """
        插入或更新CVE条目

        Returns:
            True: 新插入, False: 已更新
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # 检查是否存在
            cursor.execute("SELECT cve_id FROM cve_index WHERE cve_id = ?", (entry.cve_id,))
            exists = cursor.fetchone()

            if exists:
                # 更新
                cursor.execute("""
                    UPDATE cve_index SET
                        description = ?,
                        severity = ?,
                        cvss = ?,
                        affected_products = ?,
                        poc_available = ?,
                        poc_path = ?,
                        source = ?,
                        last_updated = ?
                    WHERE cve_id = ?
                """, (
                    entry.description,
                    entry.severity,
                    entry.cvss,
                    entry.affected_products,
                    entry.poc_available,
                    entry.poc_path,
                    entry.source,
                    entry.last_updated,
                    entry.cve_id
                ))
                conn.commit()
                conn.close()
                return False
            else:
                # 插入
                cursor.execute("""
                    INSERT INTO cve_index VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.cve_id,
                    entry.description,
                    entry.severity,
                    entry.cvss,
                    entry.affected_products,
                    entry.poc_available,
                    entry.poc_path,
                    entry.source,
                    entry.last_updated
                ))
                conn.commit()
                conn.close()
                return True

        except Exception as e:
            logger.error(f"数据库操作失败: {e}")
            return False

    def _get_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """获取CVE条目"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cve_index WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()
            conn.close()

            if row:
                return CVEEntry(*row)
            return None

        except Exception as e:
            logger.error(f"查询CVE失败: {e}")
            return None

    def _log_sync(self, source: str, new_cves: int, updated_cves: int, status: str):
        """记录同步历史"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sync_history (source, sync_time, new_cves, updated_cves, status)
                VALUES (?, ?, ?, ?, ?)
            """, (source, datetime.now().isoformat(), new_cves, updated_cves, status))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"记录同步历史失败: {e}")

    async def sync_all(self, days_back: int = 7) -> Dict[str, Tuple[int, int]]:
        """
        同步所有数据源

        Args:
            days_back: NVD同步最近N天

        Returns:
            {"NVD": (new, updated), "Nuclei": (new, updated), ...}
        """
        logger.info("开始全量同步所有数据源")

        results = {}

        # 并发同步
        tasks = [
            ("NVD", self.sync_nvd(days_back)),
            ("Nuclei", self.sync_nuclei_templates()),
            ("Exploit-DB", self.sync_exploit_db())
        ]

        for source, task in tasks:
            try:
                results[source] = await task
            except Exception as e:
                logger.error(f"{source} 同步失败: {e}")
                results[source] = (0, 0)

        logger.info(f"全量同步完成: {results}")
        return results

    def search(self, keyword: str = "", severity: Optional[str] = None,
               min_cvss: float = 0.0, poc_only: bool = False) -> List[CVEEntry]:
        """
        搜索CVE

        Args:
            keyword: 关键词 (在CVE ID或描述中搜索)
            severity: 严重性过滤 (CRITICAL/HIGH/MEDIUM/LOW)
            min_cvss: 最低CVSS分数
            poc_only: 仅显示有PoC的CVE

        Returns:
            CVE条目列表
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            query = "SELECT * FROM cve_index WHERE 1=1"
            params = []

            if keyword:
                query += " AND (cve_id LIKE ? OR description LIKE ?)"
                params.extend([f"%{keyword}%", f"%{keyword}%"])

            if severity:
                query += " AND severity = ?"
                params.append(severity.upper())

            if min_cvss > 0:
                query += " AND cvss >= ?"
                params.append(min_cvss)

            if poc_only:
                query += " AND poc_available = 1"

            query += " ORDER BY cvss DESC, last_updated DESC"

            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()

            return [CVEEntry(*row) for row in rows]

        except Exception as e:
            logger.error(f"搜索失败: {e}")
            return []

    def get_stats(self) -> Dict:
        """获取数据库统计信息"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            stats = {}

            # 总CVE数
            cursor.execute("SELECT COUNT(*) FROM cve_index")
            stats["total_cves"] = cursor.fetchone()[0]

            # 有PoC的CVE数
            cursor.execute("SELECT COUNT(*) FROM cve_index WHERE poc_available = 1")
            stats["poc_available"] = cursor.fetchone()[0]

            # 按严重性统计
            cursor.execute("SELECT severity, COUNT(*) FROM cve_index GROUP BY severity")
            stats["by_severity"] = dict(cursor.fetchall())

            # 按来源统计
            cursor.execute("SELECT source, COUNT(*) FROM cve_index GROUP BY source")
            stats["by_source"] = dict(cursor.fetchall())

            # 最近同步时间
            cursor.execute("SELECT source, MAX(sync_time) FROM sync_history GROUP BY source")
            stats["last_sync"] = dict(cursor.fetchall())

            conn.close()
            return stats

        except Exception as e:
            logger.error(f"获取统计失败: {e}")
            return {}


# CLI入口 (可选)
async def main():
    """CLI测试入口"""
    import sys

    manager = CVEUpdateManager()

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "sync":
            await manager.sync_all(days_back=7)
        elif command == "search":
            keyword = sys.argv[2] if len(sys.argv) > 2 else ""
            results = manager.search(keyword=keyword, poc_only=True)
            print(f"\n找到 {len(results)} 条结果:\n")
            for cve in results[:10]:
                print(f"[{cve.severity}] {cve.cve_id} (CVSS: {cve.cvss})")
                print(f"  {cve.description[:100]}...")
                if cve.poc_path:
                    print(f"  PoC: {cve.poc_path}")
                print()
        elif command == "stats":
            stats = manager.get_stats()
            print("\n数据库统计:")
            print(f"  总CVE数: {stats.get('total_cves', 0)}")
            print(f"  有PoC: {stats.get('poc_available', 0)}")
            print(f"\n按严重性:")
            for severity, count in stats.get('by_severity', {}).items():
                print(f"    {severity}: {count}")
    else:
        print("用法:")
        print("  python update_manager.py sync       # 同步所有数据源")
        print("  python update_manager.py search <keyword>  # 搜索CVE")
        print("  python update_manager.py stats      # 查看统计")


if __name__ == "__main__":
    asyncio.run(main())
