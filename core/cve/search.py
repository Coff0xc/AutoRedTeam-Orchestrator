#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE 搜索引擎
支持全文搜索、高级过滤、排序等功能

作者: AutoRedTeam-Orchestrator
"""

import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from .models import CVEEntry, Severity
from .storage import CVEStorage

logger = logging.getLogger(__name__)


@dataclass
class SearchFilter:
    """搜索过滤器"""

    keyword: Optional[str] = None  # 关键词 (全文搜索)
    cve_id: Optional[str] = None  # CVE ID 匹配
    severity: Optional[Severity] = None  # 严重性过滤
    min_cvss: Optional[float] = None  # 最低 CVSS 分数
    max_cvss: Optional[float] = None  # 最高 CVSS 分数
    has_poc: Optional[bool] = None  # 是否有 PoC
    exploit_available: Optional[bool] = None  # 是否有公开利用
    source: Optional[str] = None  # 数据源
    product: Optional[str] = None  # 产品名称
    vendor: Optional[str] = None  # 厂商名称
    cwe_id: Optional[str] = None  # CWE ID
    tags: Optional[List[str]] = None  # 标签

    # 时间过滤
    published_after: Optional[datetime] = None  # 发布时间起始
    published_before: Optional[datetime] = None  # 发布时间截止
    modified_after: Optional[datetime] = None  # 修改时间起始
    modified_before: Optional[datetime] = None  # 修改时间截止

    # 年份过滤
    year: Optional[int] = None  # 指定年份


@dataclass
class SearchOptions:
    """搜索选项"""

    limit: int = 100  # 结果数量限制
    offset: int = 0  # 偏移量 (分页)
    order_by: str = "relevance"  # 排序字段
    order_desc: bool = True  # 是否降序

    # 排序字段选项: relevance, cvss_score, published_date, modified_date, cve_id
    VALID_ORDER_BY = ["relevance", "cvss_score", "published_date", "modified_date", "cve_id"]


@dataclass
class SearchResult:
    """搜索结果"""

    entries: List[CVEEntry] = field(default_factory=list)
    total_count: int = 0  # 总匹配数量
    returned_count: int = 0  # 返回数量
    offset: int = 0  # 偏移量
    execution_time_ms: float = 0  # 执行时间 (毫秒)
    query: Optional[str] = None  # 原始查询

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "total_count": self.total_count,
            "returned_count": self.returned_count,
            "offset": self.offset,
            "execution_time_ms": self.execution_time_ms,
            "query": self.query,
            "entries": [e.to_dict() for e in self.entries],
        }


class CVESearchEngine:
    """
    CVE 搜索引擎

    特性:
    - 全文搜索 (基于 SQLite FTS5)
    - 高级过滤条件
    - 多字段排序
    - 结果高亮
    - 搜索建议
    """

    def __init__(self, storage: CVEStorage):
        """
        初始化搜索引擎

        Args:
            storage: CVE 存储实例
        """
        self.storage = storage
        logger.info("[Search] 搜索引擎初始化完成")

    def search(
        self,
        keyword: Optional[str] = None,
        severity: Optional[Severity] = None,
        has_poc: Optional[bool] = None,
        limit: int = 100,
        **kwargs,
    ) -> List[CVEEntry]:
        """
        简单搜索接口

        Args:
            keyword: 搜索关键词
            severity: 严重性过滤
            has_poc: 是否有 PoC
            limit: 结果数量限制
            **kwargs: 其他过滤参数

        Returns:
            CVE 条目列表
        """
        search_filter = SearchFilter(keyword=keyword, severity=severity, has_poc=has_poc, **kwargs)

        options = SearchOptions(limit=limit)

        result = self.advanced_search(search_filter, options)
        return result.entries

    def advanced_search(
        self, search_filter: SearchFilter, options: Optional[SearchOptions] = None
    ) -> SearchResult:
        """
        高级搜索接口

        Args:
            search_filter: 搜索过滤器
            options: 搜索选项

        Returns:
            搜索结果
        """
        import time

        start_time = time.time()

        options = options or SearchOptions()

        # 构建 SQL 查询
        query, params = self._build_query(search_filter, options)

        # 执行查询
        conn = self.storage._get_connection()
        cursor = conn.cursor()

        try:
            # 获取总数
            count_query = self._build_count_query(search_filter)
            cursor.execute(count_query, params[:-2] if len(params) >= 2 else params)
            total_count = cursor.fetchone()[0]

            # 执行主查询
            cursor.execute(query, params)
            rows = cursor.fetchall()

            # 转换为 CVEEntry
            entries = [self.storage._row_to_entry(row) for row in rows]

            execution_time_ms = (time.time() - start_time) * 1000

            return SearchResult(
                entries=entries,
                total_count=total_count,
                returned_count=len(entries),
                offset=options.offset,
                execution_time_ms=execution_time_ms,
                query=search_filter.keyword,
            )

        except Exception as e:
            logger.error(f"[Search] 搜索失败: {e}")
            return SearchResult(
                execution_time_ms=(time.time() - start_time) * 1000, query=search_filter.keyword
            )

    def search_by_product(self, product: str, limit: int = 100) -> List[CVEEntry]:
        """
        按产品搜索

        Args:
            product: 产品名称
            limit: 结果数量限制

        Returns:
            CVE 条目列表
        """
        search_filter = SearchFilter(product=product)
        options = SearchOptions(limit=limit, order_by="cvss_score")

        result = self.advanced_search(search_filter, options)
        return result.entries

    def search_by_vendor(self, vendor: str, limit: int = 100) -> List[CVEEntry]:
        """
        按厂商搜索

        Args:
            vendor: 厂商名称
            limit: 结果数量限制

        Returns:
            CVE 条目列表
        """
        search_filter = SearchFilter(vendor=vendor)
        options = SearchOptions(limit=limit, order_by="cvss_score")

        result = self.advanced_search(search_filter, options)
        return result.entries

    def search_by_cwe(self, cwe_id: str, limit: int = 100) -> List[CVEEntry]:
        """
        按 CWE ID 搜索

        Args:
            cwe_id: CWE ID (如 CWE-79)
            limit: 结果数量限制

        Returns:
            CVE 条目列表
        """
        search_filter = SearchFilter(cwe_id=cwe_id)
        options = SearchOptions(limit=limit, order_by="cvss_score")

        result = self.advanced_search(search_filter, options)
        return result.entries

    def search_recent(self, days: int = 7, limit: int = 100) -> List[CVEEntry]:
        """
        搜索最近发布的 CVE

        Args:
            days: 天数
            limit: 结果数量限制

        Returns:
            CVE 条目列表
        """
        since = datetime.now() - timedelta(days=days)
        search_filter = SearchFilter(published_after=since)
        options = SearchOptions(limit=limit, order_by="published_date")

        result = self.advanced_search(search_filter, options)
        return result.entries

    def search_critical(self, limit: int = 100) -> List[CVEEntry]:
        """
        搜索严重级别为 CRITICAL 的 CVE

        Args:
            limit: 结果数量限制

        Returns:
            CVE 条目列表
        """
        search_filter = SearchFilter(severity=Severity.CRITICAL)
        options = SearchOptions(limit=limit, order_by="cvss_score")

        result = self.advanced_search(search_filter, options)
        return result.entries

    def search_exploitable(self, min_cvss: float = 7.0, limit: int = 100) -> List[CVEEntry]:
        """
        搜索高危且有公开利用的 CVE

        Args:
            min_cvss: 最低 CVSS 分数
            limit: 结果数量限制

        Returns:
            CVE 条目列表
        """
        search_filter = SearchFilter(min_cvss=min_cvss, exploit_available=True)
        options = SearchOptions(limit=limit, order_by="cvss_score")

        result = self.advanced_search(search_filter, options)
        return result.entries

    def fulltext_search(self, query: str, limit: int = 100) -> List[CVEEntry]:
        """
        全文搜索

        Args:
            query: 搜索查询
            limit: 结果数量限制

        Returns:
            CVE 条目列表
        """
        conn = self.storage._get_connection()
        cursor = conn.cursor()

        try:
            # 使用 FTS5 全文搜索
            # 转义特殊字符
            escaped_query = self._escape_fts_query(query)

            cursor.execute(
                """
                SELECT cve_entries.*
                FROM cve_fts
                JOIN cve_entries ON cve_fts.cve_id = cve_entries.cve_id
                WHERE cve_fts MATCH ?
                ORDER BY rank
                LIMIT ?
            """,
                (escaped_query, limit),
            )

            return [self.storage._row_to_entry(row) for row in cursor.fetchall()]

        except sqlite3.OperationalError as e:
            logger.warning(f"[Search] FTS 搜索失败，回退到 LIKE: {e}")
            # 回退到 LIKE 搜索
            return self.search(keyword=query, limit=limit)

    def suggest(self, prefix: str, limit: int = 10) -> List[str]:
        """
        搜索建议 (自动补全)

        Args:
            prefix: 前缀
            limit: 建议数量

        Returns:
            建议列表
        """
        conn = self.storage._get_connection()
        cursor = conn.cursor()

        suggestions = []

        # CVE ID 建议
        if prefix.upper().startswith("CVE"):
            cursor.execute(
                """
                SELECT DISTINCT cve_id FROM cve_entries
                WHERE cve_id LIKE ?
                ORDER BY cve_id DESC
                LIMIT ?
            """,
                (f"{prefix.upper()}%", limit),
            )

            suggestions.extend([row[0] for row in cursor.fetchall()])

        # 产品名称建议
        cursor.execute(
            """
            SELECT DISTINCT affected_products FROM cve_entries
            WHERE affected_products LIKE ?
            LIMIT ?
        """,
            (f"%{prefix}%", limit * 2),
        )

        for row in cursor.fetchall():
            try:
                import json

                products = json.loads(row[0] or "[]")
                for product in products:
                    if prefix.lower() in product.lower():
                        suggestions.append(product)
            except (ValueError, TypeError):
                pass

        # 去重并限制数量
        seen = set()
        unique_suggestions = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique_suggestions.append(s)
                if len(unique_suggestions) >= limit:
                    break

        return unique_suggestions

    def _build_query(self, search_filter: SearchFilter, options: SearchOptions) -> Tuple[str, List]:
        """
        构建 SQL 查询

        Args:
            search_filter: 搜索过滤器
            options: 搜索选项

        Returns:
            (SQL 查询, 参数列表)
        """
        conditions = []
        params = []

        # 关键词搜索
        if search_filter.keyword:
            conditions.append("""
                (cve_id LIKE ? OR title LIKE ? OR description LIKE ?
                 OR affected_products LIKE ? OR tags LIKE ?)
            """)
            keyword_pattern = f"%{search_filter.keyword}%"
            params.extend([keyword_pattern] * 5)

        # CVE ID 匹配
        if search_filter.cve_id:
            conditions.append("cve_id LIKE ?")
            params.append(f"%{search_filter.cve_id}%")

        # 严重性过滤
        if search_filter.severity:
            conditions.append("severity = ?")
            params.append(search_filter.severity.value)

        # CVSS 范围
        if search_filter.min_cvss is not None:
            conditions.append("cvss_score >= ?")
            params.append(search_filter.min_cvss)

        if search_filter.max_cvss is not None:
            conditions.append("cvss_score <= ?")
            params.append(search_filter.max_cvss)

        # PoC 过滤
        if search_filter.has_poc is not None:
            conditions.append("has_poc = ?")
            params.append(1 if search_filter.has_poc else 0)

        # 公开利用过滤
        if search_filter.exploit_available is not None:
            conditions.append("exploit_available = ?")
            params.append(1 if search_filter.exploit_available else 0)

        # 数据源过滤
        if search_filter.source:
            conditions.append("source LIKE ?")
            params.append(f"%{search_filter.source}%")

        # 产品过滤
        if search_filter.product:
            conditions.append("affected_products LIKE ?")
            params.append(f"%{search_filter.product}%")

        # 厂商过滤
        if search_filter.vendor:
            conditions.append("affected_products LIKE ?")
            params.append(f"%{search_filter.vendor}%")

        # CWE 过滤
        if search_filter.cwe_id:
            conditions.append("cwe_ids LIKE ?")
            params.append(f"%{search_filter.cwe_id}%")

        # 标签过滤
        if search_filter.tags:
            for tag in search_filter.tags:
                conditions.append("tags LIKE ?")
                params.append(f"%{tag}%")

        # 发布时间过滤
        if search_filter.published_after:
            conditions.append("published_date >= ?")
            params.append(search_filter.published_after.isoformat())

        if search_filter.published_before:
            conditions.append("published_date <= ?")
            params.append(search_filter.published_before.isoformat())

        # 修改时间过滤
        if search_filter.modified_after:
            conditions.append("modified_date >= ?")
            params.append(search_filter.modified_after.isoformat())

        if search_filter.modified_before:
            conditions.append("modified_date <= ?")
            params.append(search_filter.modified_before.isoformat())

        # 年份过滤
        if search_filter.year:
            conditions.append("cve_id LIKE ?")
            params.append(f"CVE-{search_filter.year}-%")

        # 构建 WHERE 子句
        where_clause = " AND ".join(conditions) if conditions else "1=1"

        # 排序
        order_by = self._get_order_clause(options)

        # 构建完整查询
        query = f"""
            SELECT * FROM cve_entries
            WHERE {where_clause}
            {order_by}
            LIMIT ? OFFSET ?
        """

        params.extend([options.limit, options.offset])

        return query, params

    def _build_count_query(self, search_filter: SearchFilter) -> str:
        """构建计数查询"""
        conditions = []

        # 复制 _build_query 中的条件构建逻辑 (简化版)
        if search_filter.keyword:
            conditions.append("""
                (cve_id LIKE ? OR title LIKE ? OR description LIKE ?
                 OR affected_products LIKE ? OR tags LIKE ?)
            """)

        if search_filter.cve_id:
            conditions.append("cve_id LIKE ?")

        if search_filter.severity:
            conditions.append("severity = ?")

        if search_filter.min_cvss is not None:
            conditions.append("cvss_score >= ?")

        if search_filter.max_cvss is not None:
            conditions.append("cvss_score <= ?")

        if search_filter.has_poc is not None:
            conditions.append("has_poc = ?")

        if search_filter.exploit_available is not None:
            conditions.append("exploit_available = ?")

        if search_filter.source:
            conditions.append("source LIKE ?")

        if search_filter.product:
            conditions.append("affected_products LIKE ?")

        if search_filter.vendor:
            conditions.append("affected_products LIKE ?")

        if search_filter.cwe_id:
            conditions.append("cwe_ids LIKE ?")

        if search_filter.tags:
            for _ in search_filter.tags:
                conditions.append("tags LIKE ?")

        if search_filter.published_after:
            conditions.append("published_date >= ?")

        if search_filter.published_before:
            conditions.append("published_date <= ?")

        if search_filter.modified_after:
            conditions.append("modified_date >= ?")

        if search_filter.modified_before:
            conditions.append("modified_date <= ?")

        if search_filter.year:
            conditions.append("cve_id LIKE ?")

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        return f"SELECT COUNT(*) FROM cve_entries WHERE {where_clause}"

    def _get_order_clause(self, options: SearchOptions) -> str:
        """获取排序子句"""
        order_mapping = {
            "relevance": "cvss_score",
            "cvss_score": "cvss_score",
            "published_date": "published_date",
            "modified_date": "modified_date",
            "cve_id": "cve_id",
        }

        order_field = order_mapping.get(options.order_by, "cvss_score")
        order_direction = "DESC" if options.order_desc else "ASC"

        # 添加次要排序条件
        if order_field != "cvss_score":
            return f"ORDER BY {order_field} {order_direction}, cvss_score DESC"
        else:
            return f"ORDER BY {order_field} {order_direction}, published_date DESC"

    def _escape_fts_query(self, query: str) -> str:
        """
        转义 FTS5 查询中的特殊字符

        Args:
            query: 原始查询

        Returns:
            转义后的查询
        """
        # FTS5 特殊字符: " ( ) * - ^
        special_chars = ['"', "(", ")", "*", "-", "^"]

        escaped = query
        for char in special_chars:
            escaped = escaped.replace(char, f'"{char}"')

        # 将多个空格合并为一个
        escaped = " ".join(escaped.split())

        return escaped


# 便捷函数
def create_search_engine(storage: Optional[CVEStorage] = None) -> CVESearchEngine:
    """
    创建搜索引擎

    Args:
        storage: CVE 存储实例 (可选)

    Returns:
        搜索引擎实例
    """
    if storage is None:
        from .storage import get_storage

        storage = get_storage()

    return CVESearchEngine(storage)
