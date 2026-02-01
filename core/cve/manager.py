#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE 管理器
统一管理 CVE 数据的获取、存储、搜索和同步

作者: AutoRedTeam-Orchestrator
"""

import asyncio
import logging
import os
import threading
from datetime import datetime
from typing import Dict, List, Optional

from .models import CVEEntry, CVEStats, Severity, SyncStatus
from .search import CVESearchEngine, SearchFilter, SearchOptions, SearchResult
from .sources import (
    AggregatedSource,
    CVESource,
    ExploitDBSource,
    NucleiSource,
    NVDSource,
)
from .storage import get_storage

logger = logging.getLogger(__name__)


class CVEManager:
    """
    CVE 管理器 - 单例模式

    功能:
    - 统一管理 CVE 数据
    - 多源数据同步
    - 高级搜索
    - 统计分析
    """

    _instance: Optional["CVEManager"] = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs) -> "CVEManager":
        """单例模式"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(
        self,
        db_path: Optional[str] = None,
        nvd_api_key: Optional[str] = None,
        github_token: Optional[str] = None,
    ):
        """
        初始化 CVE 管理器

        Args:
            db_path: 数据库路径
            nvd_api_key: NVD API Key
            github_token: GitHub Token
        """
        if self._initialized:
            return

        # 从环境变量获取 API Key
        self._nvd_api_key = nvd_api_key or os.environ.get("NVD_API_KEY")
        self._github_token = github_token or os.environ.get("GITHUB_TOKEN")

        # 初始化存储
        self._storage = get_storage(db_path)

        # 初始化数据源
        self._sources: List[CVESource] = []
        self._aggregated_source: Optional[AggregatedSource] = None
        self._init_sources()

        # 初始化搜索引擎
        self._search_engine = CVESearchEngine(self._storage)

        # 同步锁
        self._sync_lock = threading.Lock()

        self._initialized = True
        logger.info("[Manager] CVE 管理器初始化完成")

    def _init_sources(self):
        """初始化数据源"""
        # NVD 数据源
        nvd_source = NVDSource(api_key=self._nvd_api_key)
        self._sources.append(nvd_source)

        # Nuclei 数据源
        nuclei_source = NucleiSource(github_token=self._github_token)
        self._sources.append(nuclei_source)

        # Exploit-DB 数据源
        exploitdb_source = ExploitDBSource()
        self._sources.append(exploitdb_source)

        # 聚合数据源
        self._aggregated_source = AggregatedSource(self._sources)

        logger.info(f"[Manager] 初始化 {len(self._sources)} 个数据源")

    async def sync(
        self, days: int = 7, sources: Optional[List[str]] = None
    ) -> Dict[str, SyncStatus]:
        """
        同步 CVE 数据

        Args:
            days: 同步最近 N 天的数据
            sources: 要同步的数据源列表 (None 表示全部)

        Returns:
            同步状态字典
        """
        with self._sync_lock:
            logger.info(f"[Manager] 开始同步 (days={days})")

            results = {}
            start_time = datetime.now()

            # 确定要同步的数据源
            if sources:
                sources_to_sync = [s for s in self._sources if s.name in sources]
            else:
                sources_to_sync = self._sources

            # 并发同步各数据源
            tasks = []
            for source in sources_to_sync:
                tasks.append(self._sync_source(source, days))

            sync_results = await asyncio.gather(*tasks, return_exceptions=True)

            # 处理同步结果
            for i, result in enumerate(sync_results):
                source = sources_to_sync[i]

                if isinstance(result, Exception):
                    status = SyncStatus(
                        source=source.name,
                        last_sync=datetime.now(),
                        status="failed",
                        message=str(result),
                    )
                    logger.error(f"[Manager] {source.name} 同步失败: {result}")
                else:
                    status = result

                results[source.name] = status
                self._storage.log_sync(status)

            total_time = (datetime.now() - start_time).total_seconds()
            total_new = sum(s.new_count for s in results.values())
            total_updated = sum(s.updated_count for s in results.values())

            logger.info(
                f"[Manager] 同步完成: "
                f"新增 {total_new}, 更新 {total_updated}, "
                f"耗时 {total_time:.1f}s"
            )

            return results

    async def _sync_source(self, source: CVESource, days: int) -> SyncStatus:
        """
        同步单个数据源

        Args:
            source: 数据源
            days: 天数

        Returns:
            同步状态
        """
        status = SyncStatus(source=source.name, last_sync=datetime.now(), status="running")

        try:
            # 获取数据
            entries = await source.fetch_recent(days)

            # 保存到存储
            new_count, updated_count = self._storage.save_batch(entries)

            status.new_count = new_count
            status.updated_count = updated_count
            status.status = "success"
            status.message = f"获取 {len(entries)} 条, 新增 {new_count}, 更新 {updated_count}"

        except Exception as e:
            status.status = "failed"
            status.error_count = 1
            status.message = str(e)
            logger.error(f"[Manager] 同步 {source.name} 失败: {e}")

        return status

    def search(
        self,
        keyword: Optional[str] = None,
        severity: Optional[Severity] = None,
        has_poc: Optional[bool] = None,
        limit: int = 100,
        **kwargs,
    ) -> List[CVEEntry]:
        """
        搜索 CVE

        Args:
            keyword: 关键词
            severity: 严重性
            has_poc: 是否有 PoC
            limit: 结果数量限制
            **kwargs: 其他过滤参数

        Returns:
            CVE 条目列表
        """
        return self._search_engine.search(
            keyword=keyword, severity=severity, has_poc=has_poc, limit=limit, **kwargs
        )

    def advanced_search(
        self, search_filter: SearchFilter, options: Optional[SearchOptions] = None
    ) -> SearchResult:
        """
        高级搜索

        Args:
            search_filter: 搜索过滤器
            options: 搜索选项

        Returns:
            搜索结果
        """
        return self._search_engine.advanced_search(search_filter, options)

    def get(self, cve_id: str) -> Optional[CVEEntry]:
        """
        获取单个 CVE

        Args:
            cve_id: CVE ID

        Returns:
            CVE 条目或 None
        """
        return self._storage.get(cve_id)

    async def get_detail(self, cve_id: str, refresh: bool = False) -> Optional[CVEEntry]:
        """
        获取 CVE 详情 (支持实时刷新)

        Args:
            cve_id: CVE ID
            refresh: 是否从远程刷新

        Returns:
            CVE 条目或 None
        """
        if not refresh:
            # 先从本地获取
            entry = self._storage.get(cve_id)
            if entry:
                return entry

        # 从远程获取
        if self._aggregated_source:
            entry = await self._aggregated_source.get_detail(cve_id)
            if entry:
                self._storage.save(entry)
            return entry

        return None

    def get_recent(self, limit: int = 50) -> List[CVEEntry]:
        """
        获取最近的 CVE

        Args:
            limit: 数量限制

        Returns:
            CVE 条目列表
        """
        return self._storage.get_recent(limit)

    def get_by_severity(self, severity: Severity, limit: int = 100) -> List[CVEEntry]:
        """
        按严重性获取 CVE

        Args:
            severity: 严重性等级
            limit: 数量限制

        Returns:
            CVE 条目列表
        """
        return self._storage.get_by_severity(severity, limit)

    def get_by_product(self, product: str, limit: int = 100) -> List[CVEEntry]:
        """
        按产品获取 CVE

        Args:
            product: 产品名称
            limit: 数量限制

        Returns:
            CVE 条目列表
        """
        return self._search_engine.search_by_product(product, limit)

    def get_with_poc(self, limit: int = 100) -> List[CVEEntry]:
        """
        获取有 PoC 的 CVE

        Args:
            limit: 数量限制

        Returns:
            CVE 条目列表
        """
        return self._storage.get_with_poc(limit)

    def get_exploitable(self, min_cvss: float = 7.0, limit: int = 100) -> List[CVEEntry]:
        """
        获取高危且可利用的 CVE

        Args:
            min_cvss: 最低 CVSS 分数
            limit: 数量限制

        Returns:
            CVE 条目列表
        """
        return self._search_engine.search_exploitable(min_cvss, limit)

    def stats(self) -> CVEStats:
        """
        获取统计信息

        Returns:
            CVE 统计信息
        """
        return self._storage.stats()

    def get_sync_history(self, source: Optional[str] = None, limit: int = 20) -> List[SyncStatus]:
        """
        获取同步历史

        Args:
            source: 数据源名称 (可选)
            limit: 数量限制

        Returns:
            同步状态列表
        """
        return self._storage.get_sync_history(source, limit)

    def suggest(self, prefix: str, limit: int = 10) -> List[str]:
        """
        搜索建议

        Args:
            prefix: 前缀
            limit: 建议数量

        Returns:
            建议列表
        """
        return self._search_engine.suggest(prefix, limit)

    def save(self, entry: CVEEntry) -> bool:
        """
        保存 CVE 条目

        Args:
            entry: CVE 条目

        Returns:
            True 表示新增, False 表示更新
        """
        return self._storage.save(entry)

    def delete(self, cve_id: str) -> bool:
        """
        删除 CVE 条目

        Args:
            cve_id: CVE ID

        Returns:
            是否删除成功
        """
        return self._storage.delete(cve_id)

    def close(self):
        """关闭管理器"""
        if self._storage:
            self._storage.close()

        for source in self._sources:
            source.close()

        logger.info("[Manager] CVE 管理器已关闭")


# 全局管理器实例
_manager: Optional[CVEManager] = None
_manager_lock = threading.Lock()


def get_cve_manager(
    db_path: Optional[str] = None,
    nvd_api_key: Optional[str] = None,
    github_token: Optional[str] = None,
) -> CVEManager:
    """
    获取全局 CVE 管理器

    Args:
        db_path: 数据库路径
        nvd_api_key: NVD API Key
        github_token: GitHub Token

    Returns:
        CVE 管理器实例
    """
    global _manager

    with _manager_lock:
        if _manager is None:
            _manager = CVEManager(
                db_path=db_path, nvd_api_key=nvd_api_key, github_token=github_token
            )

    return _manager


def reset_cve_manager():
    """重置全局 CVE 管理器"""
    global _manager

    with _manager_lock:
        if _manager:
            _manager.close()
            _manager = None


# CLI 入口
async def _cli_main():
    """CLI 入口"""
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 2:
        logger.info("CVE Manager CLI")
        logger.info("=" * 50)
        logger.info("用法:")
        logger.info("  python manager.py sync [days]     # 同步数据 (默认7天)")
        logger.info("  python manager.py search <keyword> # 搜索 CVE")
        logger.info("  python manager.py get <cve_id>    # 获取 CVE 详情")
        logger.info("  python manager.py stats           # 查看统计")
        logger.info("  python manager.py recent [limit]  # 最近的 CVE")
        logger.info("  python manager.py poc [limit]     # 有 PoC 的 CVE")
        return

    manager = get_cve_manager()
    command = sys.argv[1]

    if command == "sync":
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 7
        results = await manager.sync(days=days)
        logger.info("\n同步完成:")
        for source, status in results.items():
            logger.info(
                f"  {source}: {status.status} "
                f"(新增: {status.new_count}, 更新: {status.updated_count})"
            )

    elif command == "search":
        keyword = sys.argv[2] if len(sys.argv) > 2 else ""
        entries = manager.search(keyword=keyword, limit=10)
        logger.info(f"\n搜索结果 ({len(entries)} 条):")
        for entry in entries:
            severity = entry.severity.value.upper()
            cvss = entry.cvss.score if entry.cvss else 0.0
            poc = "✓" if entry.has_poc else "✗"
            logger.info(f"  [{severity}] {entry.cve_id} (CVSS: {cvss:.1f}) PoC: {poc}")
            logger.info(f"    {entry.description[:80]}...")

    elif command == "get":
        cve_id = sys.argv[2] if len(sys.argv) > 2 else ""
        entry = await manager.get_detail(cve_id.upper(), refresh=True)
        if entry:
            logger.info(f"\n{entry.cve_id}")
            logger.info("=" * 50)
            logger.info(f"标题: {entry.title}")
            logger.info(f"严重性: {entry.severity.value.upper()}")
            if entry.cvss:
                logger.info(f"CVSS: {entry.cvss.score} ({entry.cvss.version})")
            logger.info(f"描述: {entry.description[:200]}...")
            logger.info(f"有 PoC: {'是' if entry.has_poc else '否'}")
            if entry.poc_urls:
                logger.info("PoC 链接:")
                for url in entry.poc_urls[:3]:
                    logger.info(f"  - {url}")
        else:
            logger.info(f"未找到: {cve_id}")

    elif command == "stats":
        stats = manager.stats()
        logger.info("\n统计信息:")
        logger.info(f"  总 CVE 数: {stats.total_count}")
        logger.info(f"  有 PoC 的: {stats.poc_available_count}")
        logger.info("\n按严重性:")
        for severity, count in stats.by_severity.items():
            logger.info(f"    {severity}: {count}")
        logger.info("\n按来源:")
        for source, count in stats.by_source.items():
            logger.info(f"    {source}: {count}")

    elif command == "recent":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        entries = manager.get_recent(limit=limit)
        logger.info(f"\n最近的 CVE ({len(entries)} 条):")
        for entry in entries:
            severity = entry.severity.value.upper()
            cvss = entry.cvss.score if entry.cvss else 0.0
            logger.info(f"  [{severity}] {entry.cve_id} (CVSS: {cvss:.1f})")

    elif command == "poc":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        entries = manager.get_with_poc(limit=limit)
        logger.info(f"\n有 PoC 的 CVE ({len(entries)} 条):")
        for entry in entries:
            severity = entry.severity.value.upper()
            cvss = entry.cvss.score if entry.cvss else 0.0
            logger.info(f"  [{severity}] {entry.cve_id} (CVSS: {cvss:.1f})")
            if entry.poc_urls:
                logger.info(f"    PoC: {entry.poc_urls[0]}")

    else:
        logger.warning(f"未知命令: {command}")


if __name__ == "__main__":
    asyncio.run(_cli_main())
