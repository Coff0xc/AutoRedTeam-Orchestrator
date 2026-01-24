#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE 本地存储
基于 SQLite 的高性能本地存储，支持全文搜索和索引

作者: AutoRedTeam-Orchestrator
"""

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Iterator, Tuple
import tempfile

from .models import CVEEntry, CVSS, Reference, Severity, CVEStats, SyncStatus

logger = logging.getLogger(__name__)


class CVEStorage:
    """
    CVE 本地存储 - 基于 SQLite

    特性:
    - 线程安全
    - 支持全文搜索 (FTS5)
    - 自动索引
    - 事务支持
    """

    # 数据库 Schema
    SCHEMA = """
    -- CVE 主表
    CREATE TABLE IF NOT EXISTS cve_entries (
        cve_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,

        -- CVSS 信息
        cvss_version TEXT,
        cvss_score REAL DEFAULT 0.0,
        cvss_vector TEXT,
        severity TEXT DEFAULT 'unknown',

        -- 影响范围
        affected_products TEXT,  -- JSON array
        affected_versions TEXT,  -- JSON array
        cwe_ids TEXT,            -- JSON array

        -- 时间
        published_date TEXT,
        modified_date TEXT,

        -- 参考链接
        ref_links TEXT,          -- JSON array

        -- PoC
        has_poc INTEGER DEFAULT 0,
        poc_urls TEXT,           -- JSON array
        exploit_available INTEGER DEFAULT 0,

        -- 元数据
        source TEXT,
        tags TEXT,               -- JSON array
        raw_data TEXT,           -- JSON object

        -- 存储元数据
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- 索引
    CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_entries(severity);
    CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve_entries(cvss_score);
    CREATE INDEX IF NOT EXISTS idx_cve_source ON cve_entries(source);
    CREATE INDEX IF NOT EXISTS idx_cve_published ON cve_entries(published_date);
    CREATE INDEX IF NOT EXISTS idx_cve_has_poc ON cve_entries(has_poc);
    CREATE INDEX IF NOT EXISTS idx_cve_exploit ON cve_entries(exploit_available);

    -- 全文搜索表 (FTS5)
    CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
        cve_id,
        title,
        description,
        affected_products,
        tags,
        content='cve_entries',
        content_rowid='rowid'
    );

    -- 全文搜索触发器
    CREATE TRIGGER IF NOT EXISTS cve_fts_insert AFTER INSERT ON cve_entries BEGIN
        INSERT INTO cve_fts(rowid, cve_id, title, description, affected_products, tags)
        VALUES (new.rowid, new.cve_id, new.title, new.description, new.affected_products, new.tags);
    END;

    CREATE TRIGGER IF NOT EXISTS cve_fts_delete AFTER DELETE ON cve_entries BEGIN
        INSERT INTO cve_fts(cve_fts, rowid, cve_id, title, description, affected_products, tags)
        VALUES ('delete', old.rowid, old.cve_id, old.title, old.description, old.affected_products, old.tags);
    END;

    CREATE TRIGGER IF NOT EXISTS cve_fts_update AFTER UPDATE ON cve_entries BEGIN
        INSERT INTO cve_fts(cve_fts, rowid, cve_id, title, description, affected_products, tags)
        VALUES ('delete', old.rowid, old.cve_id, old.title, old.description, old.affected_products, old.tags);
        INSERT INTO cve_fts(rowid, cve_id, title, description, affected_products, tags)
        VALUES (new.rowid, new.cve_id, new.title, new.description, new.affected_products, new.tags);
    END;

    -- 同步历史表
    CREATE TABLE IF NOT EXISTS sync_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        sync_time TEXT NOT NULL,
        new_count INTEGER DEFAULT 0,
        updated_count INTEGER DEFAULT 0,
        error_count INTEGER DEFAULT 0,
        status TEXT DEFAULT 'pending',
        message TEXT,
        duration_ms INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_sync_source ON sync_history(source);
    CREATE INDEX IF NOT EXISTS idx_sync_time ON sync_history(sync_time);

    -- PoC 模板表
    CREATE TABLE IF NOT EXISTS poc_templates (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        cve_id TEXT,

        -- 请求配置
        method TEXT DEFAULT 'GET',
        path TEXT,
        paths TEXT,              -- JSON array
        headers TEXT,            -- JSON object
        body TEXT,

        -- 匹配配置
        matchers TEXT,           -- JSON array
        matchers_condition TEXT DEFAULT 'or',
        extractors TEXT,         -- JSON array

        -- 元数据
        severity TEXT DEFAULT 'medium',
        tags TEXT,               -- JSON array
        author TEXT,
        description TEXT,
        reference TEXT,          -- JSON array

        -- 存储元数据
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (cve_id) REFERENCES cve_entries(cve_id)
    );

    CREATE INDEX IF NOT EXISTS idx_poc_cve ON poc_templates(cve_id);
    CREATE INDEX IF NOT EXISTS idx_poc_severity ON poc_templates(severity);
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        初始化存储

        Args:
            db_path: 数据库文件路径，默认为项目 data 目录
        """
        if db_path:
            self.db_path = Path(db_path)
        else:
            # 使用项目根目录下的 data 目录
            project_root = Path(__file__).parent.parent.parent
            data_dir = project_root / 'data'
            data_dir.mkdir(exist_ok=True)
            self.db_path = data_dir / 'cve_storage.db'

        # 线程本地存储
        self._local = threading.local()

        # 初始化数据库
        self._init_database()

        logger.info(f"[Storage] 初始化完成: {self.db_path}")

    def _get_connection(self) -> sqlite3.Connection:
        """获取线程本地的数据库连接"""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False
            )
            self._local.conn.row_factory = sqlite3.Row
            # 启用外键约束
            self._local.conn.execute('PRAGMA foreign_keys = ON')
            # 启用 WAL 模式提高并发性能
            self._local.conn.execute('PRAGMA journal_mode = WAL')

        return self._local.conn

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        """事务上下文管理器"""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e

    def _init_database(self):
        """初始化数据库表结构"""
        try:
            conn = self._get_connection()
            conn.executescript(self.SCHEMA)
            conn.commit()
            logger.debug("[Storage] 数据库表结构初始化完成")
        except Exception as e:
            logger.error(f"[Storage] 数据库初始化失败: {e}")
            raise

    def save(self, entry: CVEEntry) -> bool:
        """
        保存或更新 CVE 条目

        Args:
            entry: CVE 条目

        Returns:
            True 表示新增, False 表示更新
        """
        with self._transaction() as cursor:
            # 检查是否存在
            cursor.execute(
                'SELECT cve_id FROM cve_entries WHERE cve_id = ?',
                (entry.cve_id,)
            )
            exists = cursor.fetchone() is not None

            # 序列化复杂字段
            cvss_version = entry.cvss.version if entry.cvss else None
            cvss_score = entry.cvss.score if entry.cvss else 0.0
            cvss_vector = entry.cvss.vector if entry.cvss else ''

            affected_products = json.dumps(entry.affected_products, ensure_ascii=False)
            affected_versions = json.dumps(entry.affected_versions, ensure_ascii=False)
            cwe_ids = json.dumps(entry.cwe_ids, ensure_ascii=False)
            references = json.dumps([ref.to_dict() for ref in entry.references], ensure_ascii=False)
            poc_urls = json.dumps(entry.poc_urls, ensure_ascii=False)
            tags = json.dumps(entry.tags, ensure_ascii=False)
            raw_data = json.dumps(entry.raw_data, ensure_ascii=False) if entry.raw_data else None

            published_date = entry.published_date.isoformat() if entry.published_date else None
            modified_date = entry.modified_date.isoformat() if entry.modified_date else None

            if exists:
                # 更新
                cursor.execute('''
                    UPDATE cve_entries SET
                        title = ?,
                        description = ?,
                        cvss_version = ?,
                        cvss_score = ?,
                        cvss_vector = ?,
                        severity = ?,
                        affected_products = ?,
                        affected_versions = ?,
                        cwe_ids = ?,
                        published_date = ?,
                        modified_date = ?,
                        ref_links = ?,
                        has_poc = ?,
                        poc_urls = ?,
                        exploit_available = ?,
                        source = ?,
                        tags = ?,
                        raw_data = ?,
                        updated_at = ?
                    WHERE cve_id = ?
                ''', (
                    entry.title,
                    entry.description,
                    cvss_version,
                    cvss_score,
                    cvss_vector,
                    entry.severity.value,
                    affected_products,
                    affected_versions,
                    cwe_ids,
                    published_date,
                    modified_date,
                    references,
                    int(entry.has_poc),
                    poc_urls,
                    int(entry.exploit_available),
                    entry.source,
                    tags,
                    raw_data,
                    datetime.now().isoformat(),
                    entry.cve_id
                ))
                return False
            else:
                # 插入
                cursor.execute('''
                    INSERT INTO cve_entries (
                        cve_id, title, description,
                        cvss_version, cvss_score, cvss_vector, severity,
                        affected_products, affected_versions, cwe_ids,
                        published_date, modified_date,
                        ref_links, has_poc, poc_urls, exploit_available,
                        source, tags, raw_data,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    entry.cve_id,
                    entry.title,
                    entry.description,
                    cvss_version,
                    cvss_score,
                    cvss_vector,
                    entry.severity.value,
                    affected_products,
                    affected_versions,
                    cwe_ids,
                    published_date,
                    modified_date,
                    references,
                    int(entry.has_poc),
                    poc_urls,
                    int(entry.exploit_available),
                    entry.source,
                    tags,
                    raw_data,
                    datetime.now().isoformat(),
                    datetime.now().isoformat()
                ))
                return True

    def save_batch(self, entries: List[CVEEntry]) -> Tuple[int, int]:
        """
        批量保存 CVE 条目

        Args:
            entries: CVE 条目列表

        Returns:
            (新增数量, 更新数量)
        """
        new_count = 0
        updated_count = 0

        for entry in entries:
            try:
                if self.save(entry):
                    new_count += 1
                else:
                    updated_count += 1
            except Exception as e:
                logger.warning(f"[Storage] 保存 {entry.cve_id} 失败: {e}")

        logger.info(f"[Storage] 批量保存完成: 新增 {new_count}, 更新 {updated_count}")
        return new_count, updated_count

    def get(self, cve_id: str) -> Optional[CVEEntry]:
        """
        获取单个 CVE 条目

        Args:
            cve_id: CVE ID

        Returns:
            CVE 条目或 None
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM cve_entries WHERE cve_id = ?', (cve_id,))
        row = cursor.fetchone()

        if row:
            return self._row_to_entry(row)

        return None

    def get_batch(self, cve_ids: List[str]) -> List[CVEEntry]:
        """
        批量获取 CVE 条目

        Args:
            cve_ids: CVE ID 列表

        Returns:
            CVE 条目列表
        """
        if not cve_ids:
            return []

        conn = self._get_connection()
        cursor = conn.cursor()

        placeholders = ','.join(['?' for _ in cve_ids])
        cursor.execute(
            f'SELECT * FROM cve_entries WHERE cve_id IN ({placeholders})',
            cve_ids
        )

        return [self._row_to_entry(row) for row in cursor.fetchall()]

    def get_recent(self, limit: int = 50) -> List[CVEEntry]:
        """
        获取最近的 CVE

        Args:
            limit: 数量限制

        Returns:
            CVE 条目列表
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM cve_entries
            ORDER BY published_date DESC, updated_at DESC
            LIMIT ?
        ''', (limit,))

        return [self._row_to_entry(row) for row in cursor.fetchall()]

    def get_by_severity(self, severity: Severity, limit: int = 100) -> List[CVEEntry]:
        """
        按严重性获取 CVE

        Args:
            severity: 严重性等级
            limit: 数量限制

        Returns:
            CVE 条目列表
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM cve_entries
            WHERE severity = ?
            ORDER BY cvss_score DESC, published_date DESC
            LIMIT ?
        ''', (severity.value, limit))

        return [self._row_to_entry(row) for row in cursor.fetchall()]

    def get_with_poc(self, limit: int = 100) -> List[CVEEntry]:
        """
        获取有 PoC 的 CVE

        Args:
            limit: 数量限制

        Returns:
            CVE 条目列表
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM cve_entries
            WHERE has_poc = 1
            ORDER BY cvss_score DESC, published_date DESC
            LIMIT ?
        ''', (limit,))

        return [self._row_to_entry(row) for row in cursor.fetchall()]

    def get_by_product(self, product: str, limit: int = 100) -> List[CVEEntry]:
        """
        按产品获取 CVE

        Args:
            product: 产品名称 (模糊匹配)
            limit: 数量限制

        Returns:
            CVE 条目列表
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM cve_entries
            WHERE affected_products LIKE ?
            ORDER BY cvss_score DESC, published_date DESC
            LIMIT ?
        ''', (f'%{product}%', limit))

        return [self._row_to_entry(row) for row in cursor.fetchall()]

    def delete(self, cve_id: str) -> bool:
        """
        删除 CVE 条目

        Args:
            cve_id: CVE ID

        Returns:
            是否删除成功
        """
        with self._transaction() as cursor:
            cursor.execute('DELETE FROM cve_entries WHERE cve_id = ?', (cve_id,))
            return cursor.rowcount > 0

    def count(self) -> int:
        """获取 CVE 总数"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM cve_entries')
        return cursor.fetchone()[0]

    def stats(self) -> CVEStats:
        """获取统计信息"""
        conn = self._get_connection()
        cursor = conn.cursor()

        # 总数
        cursor.execute('SELECT COUNT(*) FROM cve_entries')
        total_count = cursor.fetchone()[0]

        # 有 PoC 的数量
        cursor.execute('SELECT COUNT(*) FROM cve_entries WHERE has_poc = 1')
        poc_available_count = cursor.fetchone()[0]

        # 按严重性统计
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM cve_entries
            GROUP BY severity
        ''')
        by_severity = {row[0]: row[1] for row in cursor.fetchall()}

        # 按来源统计
        cursor.execute('''
            SELECT source, COUNT(*) as count
            FROM cve_entries
            GROUP BY source
        ''')
        by_source = {row[0]: row[1] for row in cursor.fetchall()}

        # 按年份统计
        cursor.execute('''
            SELECT
                CAST(substr(cve_id, 5, 4) AS INTEGER) as year,
                COUNT(*) as count
            FROM cve_entries
            WHERE cve_id LIKE 'CVE-%'
            GROUP BY year
            ORDER BY year DESC
        ''')
        by_year = {row[0]: row[1] for row in cursor.fetchall()}

        # 最后更新时间
        cursor.execute('SELECT MAX(updated_at) FROM cve_entries')
        last_updated_str = cursor.fetchone()[0]
        last_updated = None
        if last_updated_str:
            try:
                last_updated = datetime.fromisoformat(last_updated_str)
            except (ValueError, TypeError):
                pass

        return CVEStats(
            total_count=total_count,
            poc_available_count=poc_available_count,
            by_severity=by_severity,
            by_source=by_source,
            by_year=by_year,
            last_updated=last_updated
        )

    def log_sync(self, status: SyncStatus):
        """
        记录同步历史

        Args:
            status: 同步状态
        """
        with self._transaction() as cursor:
            cursor.execute('''
                INSERT INTO sync_history (
                    source, sync_time, new_count, updated_count,
                    error_count, status, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                status.source,
                status.last_sync.isoformat() if status.last_sync else datetime.now().isoformat(),
                status.new_count,
                status.updated_count,
                status.error_count,
                status.status,
                status.message
            ))

    def get_sync_history(self, source: Optional[str] = None, limit: int = 20) -> List[SyncStatus]:
        """
        获取同步历史

        Args:
            source: 数据源名称 (可选)
            limit: 数量限制

        Returns:
            同步状态列表
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        if source:
            cursor.execute('''
                SELECT * FROM sync_history
                WHERE source = ?
                ORDER BY sync_time DESC
                LIMIT ?
            ''', (source, limit))
        else:
            cursor.execute('''
                SELECT * FROM sync_history
                ORDER BY sync_time DESC
                LIMIT ?
            ''', (limit,))

        results = []
        for row in cursor.fetchall():
            sync_time = None
            if row['sync_time']:
                try:
                    sync_time = datetime.fromisoformat(row['sync_time'])
                except (ValueError, TypeError):
                    pass

            results.append(SyncStatus(
                source=row['source'],
                last_sync=sync_time,
                new_count=row['new_count'],
                updated_count=row['updated_count'],
                error_count=row['error_count'],
                status=row['status'],
                message=row['message'] or ''
            ))

        return results

    def get_last_sync(self, source: str) -> Optional[SyncStatus]:
        """
        获取指定源的最后同步状态

        Args:
            source: 数据源名称

        Returns:
            同步状态或 None
        """
        history = self.get_sync_history(source, limit=1)
        return history[0] if history else None

    def _row_to_entry(self, row: sqlite3.Row) -> CVEEntry:
        """
        将数据库行转换为 CVEEntry

        Args:
            row: 数据库行

        Returns:
            CVE 条目
        """
        # 解析 CVSS
        cvss = None
        if row['cvss_version']:
            cvss = CVSS(
                version=row['cvss_version'],
                score=row['cvss_score'] or 0.0,
                vector=row['cvss_vector'] or '',
                severity=Severity.from_string(row['severity'])
            )

        # 解析 JSON 字段
        affected_products = json.loads(row['affected_products'] or '[]')
        affected_versions = json.loads(row['affected_versions'] or '[]')
        cwe_ids = json.loads(row['cwe_ids'] or '[]')
        poc_urls = json.loads(row['poc_urls'] or '[]')
        tags = json.loads(row['tags'] or '[]')

        # 解析参考链接
        refs_data = json.loads(row['ref_links'] or '[]')
        references = [Reference.from_dict(r) for r in refs_data]

        # 解析时间
        published_date = None
        modified_date = None

        if row['published_date']:
            try:
                published_date = datetime.fromisoformat(row['published_date'])
            except (ValueError, TypeError):
                pass

        if row['modified_date']:
            try:
                modified_date = datetime.fromisoformat(row['modified_date'])
            except (ValueError, TypeError):
                pass

        # 解析原始数据
        raw_data = None
        if row['raw_data']:
            try:
                raw_data = json.loads(row['raw_data'])
            except (ValueError, TypeError):
                pass

        return CVEEntry(
            cve_id=row['cve_id'],
            title=row['title'],
            description=row['description'] or '',
            cvss=cvss,
            severity=Severity.from_string(row['severity']),
            affected_products=affected_products,
            affected_versions=affected_versions,
            cwe_ids=cwe_ids,
            published_date=published_date,
            modified_date=modified_date,
            references=references,
            has_poc=bool(row['has_poc']),
            poc_urls=poc_urls,
            exploit_available=bool(row['exploit_available']),
            source=row['source'] or '',
            tags=tags,
            raw_data=raw_data
        )

    def vacuum(self):
        """压缩数据库"""
        conn = self._get_connection()
        conn.execute('VACUUM')
        logger.info("[Storage] 数据库压缩完成")

    def close(self):
        """关闭数据库连接"""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
            logger.debug("[Storage] 数据库连接已关闭")


# 全局存储实例
_storage: Optional[CVEStorage] = None
_storage_lock = threading.Lock()


def get_storage(db_path: Optional[str] = None) -> CVEStorage:
    """
    获取全局存储实例

    Args:
        db_path: 数据库路径 (首次调用时生效)

    Returns:
        存储实例
    """
    global _storage

    with _storage_lock:
        if _storage is None:
            _storage = CVEStorage(db_path)

    return _storage


def reset_storage():
    """重置全局存储实例"""
    global _storage

    with _storage_lock:
        if _storage:
            _storage.close()
            _storage = None
