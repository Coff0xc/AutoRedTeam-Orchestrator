#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE情报订阅管理系统
支持: 关键词/产品/严重性/CVSS范围过滤 + 多种通知方式
作者: AutoRedTeam-Orchestrator
"""

import os
import sqlite3
import json
import asyncio
import aiohttp
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import logging

from utils.logger import configure_root_logger

from .update_manager import CVEUpdateManager, CVEEntry, Severity

# 统一 HTTP 客户端工厂
try:
    from core.http import get_async_client
    HAS_HTTP_FACTORY = True
except ImportError:
    HAS_HTTP_FACTORY = False

configure_root_logger(level=logging.INFO, log_to_file=True, log_to_console=True)
logger = logging.getLogger(__name__)


class FilterType(Enum):
    """订阅过滤类型"""
    KEYWORD = "keyword"          # 关键词匹配 (CVE ID或描述)
    PRODUCT = "product"          # 产品匹配 (如 nginx, MySQL)
    SEVERITY = "severity"        # 严重性匹配 (CRITICAL/HIGH/MEDIUM/LOW)
    CVSS_RANGE = "cvss_range"    # CVSS分数范围 (如 "7.0-10.0")


class NotifyMethod(Enum):
    """通知方式"""
    CONSOLE = "console"          # 控制台输出
    FILE = "file"                # 写入文件
    WEBHOOK = "webhook"          # HTTP回调 (可选)


@dataclass
class Subscription:
    """订阅配置数据模型"""
    id: Optional[int]
    filter_type: str
    filter_value: str
    min_cvss: float
    notify_method: str
    notify_target: Optional[str]  # 文件路径/Webhook URL
    enabled: bool
    created_at: str
    last_notified: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SubscriptionMatch:
    """订阅匹配结果"""
    subscription_id: int
    cve: CVEEntry
    matched_at: str


class SubscriptionManager:
    """CVE情报订阅管理器"""

    # 扩展数据库Schema
    EXTENDED_SCHEMA = """
    CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filter_type TEXT NOT NULL,
        filter_value TEXT NOT NULL,
        min_cvss REAL DEFAULT 0.0,
        notify_method TEXT NOT NULL,
        notify_target TEXT,
        enabled BOOLEAN DEFAULT 1,
        created_at TEXT NOT NULL,
        last_notified TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_sub_enabled ON subscriptions(enabled);
    CREATE INDEX IF NOT EXISTS idx_sub_filter ON subscriptions(filter_type, filter_value);

    CREATE TABLE IF NOT EXISTS notification_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subscription_id INTEGER,
        cve_id TEXT,
        notified_at TEXT,
        status TEXT,
        FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
    );

    CREATE INDEX IF NOT EXISTS idx_notify_sub ON notification_history(subscription_id);
    CREATE INDEX IF NOT EXISTS idx_notify_cve ON notification_history(cve_id);
    """

    def __init__(self, db_path: Optional[str] = None, cache_dir: Optional[str] = None):
        """
        初始化订阅管理器

        Args:
            db_path: 数据库路径 (默认复用CVEUpdateManager的数据库)
            cache_dir: 缓存目录 (默认复用CVEUpdateManager的缓存)
        """
        # 初始化CVE更新管理器 (复用其数据库和缓存)
        self.cve_manager = CVEUpdateManager(db_path=db_path, cache_dir=cache_dir)
        self.db_path = self.cve_manager.db_path

        # 初始化扩展数据库表
        self._init_subscription_tables()

        logger.info(f"订阅管理器初始化成功: {self.db_path}")

    def _init_subscription_tables(self):
        """初始化订阅相关数据库表 (含迁移逻辑)"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # 1. 检查表是否存在
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='subscriptions'
            """)
            table_exists = cursor.fetchone() is not None

            if table_exists:
                # 2. 表已存在,检查是否需要迁移
                cursor.execute('PRAGMA table_info(subscriptions)')
                existing_cols = {col[1] for col in cursor.fetchall()}

                # 需要的列及其定义
                required_cols = {
                    'min_cvss': 'REAL DEFAULT 0.0',
                    'notify_method': 'TEXT DEFAULT "console"',
                    'notify_target': 'TEXT',
                    'last_notified': 'TEXT'
                }

                # 执行ALTER TABLE添加缺失列
                for col_name, col_def in required_cols.items():
                    if col_name not in existing_cols:
                        alter_sql = f'ALTER TABLE subscriptions ADD COLUMN {col_name} {col_def}'
                        cursor.execute(alter_sql)
                        logger.info(f"迁移: 添加列 {col_name}")

                # 3. 确保NOT NULL列有默认值 (仅针对新添加的列)
                # filter_type 和 filter_value 如果是NULL需要更新
                # 但这些是旧数据,我们保持不动

            else:
                # 3. 表不存在,创建新表
                cursor.executescript(self.EXTENDED_SCHEMA)
                logger.info("创建新订阅表")

            # 4. 创建notification_history表 (如果不存在)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notification_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subscription_id INTEGER,
                    cve_id TEXT,
                    notified_at TEXT,
                    status TEXT,
                    FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
                )
            """)

            # 5. 创建索引
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sub_enabled ON subscriptions(enabled)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sub_filter ON subscriptions(filter_type, filter_value)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_notify_sub ON notification_history(subscription_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_notify_cve ON notification_history(cve_id)')

            conn.commit()
            conn.close()
            logger.info("订阅数据库表初始化成功")

        except Exception as e:
            logger.error(f"订阅数据库表初始化失败: {e}")
            raise

    def add_subscription(
        self,
        filter_type: str,
        filter_value: str,
        min_cvss: float = 0.0,
        notify_method: str = "console",
        notify_target: Optional[str] = None
    ) -> int:
        """
        添加订阅

        Args:
            filter_type: 过滤类型 (keyword/product/severity/cvss_range)
            filter_value: 过滤值
            min_cvss: 最低CVSS分数 (默认0.0)
            notify_method: 通知方式 (console/file/webhook)
            notify_target: 通知目标 (文件路径/Webhook URL)

        Returns:
            订阅ID

        Example:
            # 订阅Apache相关的高危CVE
            sub_id = manager.add_subscription(
                filter_type="keyword",
                filter_value="Apache",
                min_cvss=7.0,
                notify_method="file",
                notify_target="/tmp/apache_cves.log"
            )
        """
        try:
            # 验证输入
            if filter_type not in [ft.value for ft in FilterType]:
                raise ValueError(f"无效的过滤类型: {filter_type}")

            if notify_method not in [nm.value for nm in NotifyMethod]:
                raise ValueError(f"无效的通知方式: {notify_method}")

            # CVSS范围验证
            if filter_type == FilterType.CVSS_RANGE.value:
                try:
                    parts = filter_value.split("-")
                    if len(parts) != 2:
                        raise ValueError("CVSS范围格式错误,应为 'min-max' (如 '7.0-10.0')")
                    float(parts[0])
                    float(parts[1])
                except Exception:
                    raise ValueError("CVSS范围格式错误,应为 'min-max' (如 '7.0-10.0')")

            # 严重性验证
            if filter_type == FilterType.SEVERITY.value:
                if filter_value.upper() not in [s.value for s in Severity]:
                    raise ValueError(f"无效的严重性: {filter_value}")

            # 插入订阅
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO subscriptions (
                    filter_type, filter_value, min_cvss,
                    notify_method, notify_target,
                    enabled, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                filter_type,
                filter_value,
                min_cvss,
                notify_method,
                notify_target,
                True,
                datetime.now().isoformat()
            ))

            subscription_id = cursor.lastrowid
            conn.commit()
            conn.close()

            logger.info(f"订阅添加成功: ID={subscription_id}, {filter_type}={filter_value}")
            return subscription_id

        except Exception as e:
            logger.error(f"添加订阅失败: {e}")
            raise

    def remove_subscription(self, subscription_id: int) -> bool:
        """
        删除订阅

        Args:
            subscription_id: 订阅ID

        Returns:
            True: 成功, False: 失败
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # 删除订阅
            cursor.execute("DELETE FROM subscriptions WHERE id = ?", (subscription_id,))

            # 删除相关通知历史
            cursor.execute("DELETE FROM notification_history WHERE subscription_id = ?", (subscription_id,))

            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()

            if deleted:
                logger.info(f"订阅删除成功: ID={subscription_id}")
            else:
                logger.warning(f"订阅不存在: ID={subscription_id}")

            return deleted

        except Exception as e:
            logger.error(f"删除订阅失败: {e}")
            return False

    def enable_subscription(self, subscription_id: int) -> bool:
        """启用订阅"""
        return self._toggle_subscription(subscription_id, True)

    def disable_subscription(self, subscription_id: int) -> bool:
        """禁用订阅"""
        return self._toggle_subscription(subscription_id, False)

    def _toggle_subscription(self, subscription_id: int, enabled: bool) -> bool:
        """切换订阅启用状态"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE subscriptions SET enabled = ? WHERE id = ?",
                (enabled, subscription_id)
            )

            updated = cursor.rowcount > 0
            conn.commit()
            conn.close()

            if updated:
                status = "启用" if enabled else "禁用"
                logger.info(f"订阅{status}成功: ID={subscription_id}")
            else:
                logger.warning(f"订阅不存在: ID={subscription_id}")

            return updated

        except Exception as e:
            logger.error(f"切换订阅状态失败: {e}")
            return False

    def list_subscriptions(self, enabled_only: bool = False) -> List[Subscription]:
        """
        列出所有订阅

        Args:
            enabled_only: 仅显示启用的订阅

        Returns:
            订阅列表
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            query = "SELECT * FROM subscriptions"
            if enabled_only:
                query += " WHERE enabled = 1"
            query += " ORDER BY created_at DESC"

            cursor.execute(query)
            rows = cursor.fetchall()
            conn.close()

            subscriptions = []
            for row in rows:
                sub = Subscription(
                    id=row[0],
                    filter_type=row[1],
                    filter_value=row[2],
                    min_cvss=row[3],
                    notify_method=row[4],
                    notify_target=row[5],
                    enabled=bool(row[6]),
                    created_at=row[7],
                    last_notified=row[8] if len(row) > 8 else None
                )
                subscriptions.append(sub)

            return subscriptions

        except Exception as e:
            logger.error(f"列出订阅失败: {e}")
            return []

    def check_new_cves(self) -> Dict[int, List[CVEEntry]]:
        """
        检查新CVE是否匹配订阅

        Returns:
            {subscription_id: [matched_cves], ...}

        Example:
            matches = manager.check_new_cves()
            for sub_id, cves in matches.items():
                print(f"订阅 {sub_id} 匹配到 {len(cves)} 个CVE")
        """
        try:
            # 获取所有启用的订阅
            subscriptions = self.list_subscriptions(enabled_only=True)

            if not subscriptions:
                logger.info("没有启用的订阅")
                return {}

            matches = {}

            for sub in subscriptions:
                # 获取匹配的CVE
                matched_cves = self._match_subscription(sub)

                # 过滤已通知的CVE
                new_cves = self._filter_notified_cves(sub.id, matched_cves)

                if new_cves:
                    matches[sub.id] = new_cves

                    # 发送通知
                    self._send_notification(sub, new_cves)

                    # 更新最后通知时间
                    self._update_last_notified(sub.id)

            logger.info(f"订阅检查完成: {len(matches)} 个订阅匹配到新CVE")
            return matches

        except Exception as e:
            logger.error(f"检查新CVE失败: {e}")
            return {}

    def _match_subscription(self, subscription: Subscription) -> List[CVEEntry]:
        """
        匹配订阅条件

        Args:
            subscription: 订阅配置

        Returns:
            匹配的CVE列表
        """
        filter_type = subscription.filter_type
        filter_value = subscription.filter_value
        min_cvss = subscription.min_cvss

        if filter_type == FilterType.KEYWORD.value:
            # 关键词匹配 (CVE ID或描述)
            return self.cve_manager.search(
                keyword=filter_value,
                min_cvss=min_cvss
            )

        elif filter_type == FilterType.PRODUCT.value:
            # 产品匹配 (在affected_products中搜索)
            return self._search_by_product(filter_value, min_cvss)

        elif filter_type == FilterType.SEVERITY.value:
            # 严重性匹配
            return self.cve_manager.search(
                severity=filter_value.upper(),
                min_cvss=min_cvss
            )

        elif filter_type == FilterType.CVSS_RANGE.value:
            # CVSS范围匹配
            try:
                min_score, max_score = map(float, filter_value.split("-"))
                return self._search_by_cvss_range(min_score, max_score, min_cvss)
            except Exception as e:
                logger.error(f"CVSS范围解析失败: {e}")
                return []

        else:
            logger.warning(f"未知的过滤类型: {filter_type}")
            return []

    def _search_by_product(self, product: str, min_cvss: float) -> List[CVEEntry]:
        """按产品搜索CVE"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM cve_index
                WHERE affected_products LIKE ?
                AND cvss >= ?
                ORDER BY cvss DESC, last_updated DESC
            """, (f"%{product}%", min_cvss))

            rows = cursor.fetchall()
            conn.close()

            return [CVEEntry(*row) for row in rows]

        except Exception as e:
            logger.error(f"产品搜索失败: {e}")
            return []

    def _search_by_cvss_range(
        self,
        min_score: float,
        max_score: float,
        min_cvss: float
    ) -> List[CVEEntry]:
        """按CVSS范围搜索CVE"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # 应用min_cvss限制
            effective_min = max(min_score, min_cvss)

            cursor.execute("""
                SELECT * FROM cve_index
                WHERE cvss >= ? AND cvss <= ?
                ORDER BY cvss DESC, last_updated DESC
            """, (effective_min, max_score))

            rows = cursor.fetchall()
            conn.close()

            return [CVEEntry(*row) for row in rows]

        except Exception as e:
            logger.error(f"CVSS范围搜索失败: {e}")
            return []

    def _filter_notified_cves(
        self,
        subscription_id: int,
        cves: List[CVEEntry]
    ) -> List[CVEEntry]:
        """
        过滤已通知的CVE

        Args:
            subscription_id: 订阅ID
            cves: CVE列表

        Returns:
            未通知的CVE列表
        """
        try:
            if not cves:
                return []

            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # 获取已通知的CVE ID
            cursor.execute("""
                SELECT cve_id FROM notification_history
                WHERE subscription_id = ?
            """, (subscription_id,))

            notified_ids = {row[0] for row in cursor.fetchall()}
            conn.close()

            # 过滤
            new_cves = [cve for cve in cves if cve.cve_id not in notified_ids]

            return new_cves

        except Exception as e:
            logger.error(f"过滤已通知CVE失败: {e}")
            return cves

    def _send_notification(self, subscription: Subscription, cves: List[CVEEntry]):
        """
        发送通知

        Args:
            subscription: 订阅配置
            cves: 匹配的CVE列表
        """
        notify_method = subscription.notify_method

        try:
            if notify_method == NotifyMethod.CONSOLE.value:
                self._notify_console(subscription, cves)

            elif notify_method == NotifyMethod.FILE.value:
                self._notify_file(subscription, cves)

            elif notify_method == NotifyMethod.WEBHOOK.value:
                self._notify_webhook(subscription, cves)

            else:
                logger.warning(f"未知的通知方式: {notify_method}")

            # 记录通知历史
            self._log_notifications(subscription.id, cves)

        except Exception as e:
            logger.error(f"发送通知失败: {e}")

    def _notify_console(self, subscription: Subscription, cves: List[CVEEntry]):
        """控制台通知"""
        print(f"\n{'='*80}")
        print(f"[订阅通知] ID={subscription.id} | {subscription.filter_type}={subscription.filter_value}")
        print(f"{'='*80}")
        print(f"匹配到 {len(cves)} 个新CVE:\n")

        for cve in cves:
            print(f"[{cve.severity}] {cve.cve_id} (CVSS: {cve.cvss})")
            print(f"  描述: {cve.description[:100]}...")
            if cve.poc_available:
                print(f"  PoC: {cve.poc_path}")
            print(f"  更新: {cve.last_updated}")
            print()

        print(f"{'='*80}\n")

    def _notify_file(self, subscription: Subscription, cves: List[CVEEntry]):
        """文件通知"""
        if not subscription.notify_target:
            logger.error("文件通知未指定目标路径")
            return

        try:
            # 使用跨平台路径处理
            file_path = Path(subscription.notify_target)

            # 创建父目录
            file_path.parent.mkdir(parents=True, exist_ok=True)

            # 追加写入
            with open(file_path, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"[订阅通知] {datetime.now().isoformat()}\n")
                f.write(f"订阅ID: {subscription.id}\n")
                f.write(f"过滤条件: {subscription.filter_type}={subscription.filter_value}\n")
                f.write(f"{'='*80}\n\n")

                for cve in cves:
                    f.write(f"[{cve.severity}] {cve.cve_id} (CVSS: {cve.cvss})\n")
                    f.write(f"描述: {cve.description}\n")
                    f.write(f"产品: {cve.affected_products}\n")
                    if cve.poc_available:
                        f.write(f"PoC: {cve.poc_path}\n")
                    f.write(f"来源: {cve.source}\n")
                    f.write(f"更新: {cve.last_updated}\n")
                    f.write("\n")

            logger.info(f"文件通知已写入: {file_path}")

        except Exception as e:
            logger.error(f"写入文件失败: {e}")

    def _notify_webhook(self, subscription: Subscription, cves: List[CVEEntry]):
        """Webhook通知 (HTTP回调)"""
        if not subscription.notify_target:
            logger.error("Webhook通知未指定目标URL")
            return

        try:
            # 构造Webhook payload
            payload = {
                "subscription_id": subscription.id,
                "filter_type": subscription.filter_type,
                "filter_value": subscription.filter_value,
                "timestamp": datetime.now().isoformat(),
                "cves": [
                    {
                        "cve_id": cve.cve_id,
                        "severity": cve.severity,
                        "cvss": cve.cvss,
                        "description": cve.description,
                        "affected_products": json.loads(cve.affected_products),
                        "poc_available": cve.poc_available,
                        "poc_path": cve.poc_path,
                        "source": cve.source,
                        "last_updated": cve.last_updated
                    }
                    for cve in cves
                ]
            }

            # 异步HTTP POST
            asyncio.create_task(self._post_webhook(subscription.notify_target, payload))

            logger.info(f"Webhook通知已发送: {subscription.notify_target}")

        except Exception as e:
            logger.error(f"Webhook通知失败: {e}")

    async def _post_webhook(self, url: str, payload: Dict):
        """异步POST Webhook"""
        try:
            # 使用统一 HTTP 客户端工厂或回退到 aiohttp
            if HAS_HTTP_FACTORY:
                client_ctx = get_async_client(verify_ssl=False)
            else:
                client_ctx = aiohttp.ClientSession()

            async with client_ctx as session:
                async with session.post(
                    url,
                    json=payload,
                    timeout=10,
                    ssl=False
                ) as resp:
                    if resp.status == 200:
                        logger.info(f"Webhook成功: {url}")
                    else:
                        logger.error(f"Webhook失败 {resp.status}: {url}")

        except Exception as e:
            logger.error(f"Webhook异常: {e}")

    def _log_notifications(self, subscription_id: int, cves: List[CVEEntry]):
        """记录通知历史"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            for cve in cves:
                cursor.execute("""
                    INSERT INTO notification_history (
                        subscription_id, cve_id, notified_at, status
                    ) VALUES (?, ?, ?, ?)
                """, (
                    subscription_id,
                    cve.cve_id,
                    datetime.now().isoformat(),
                    "SUCCESS"
                ))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"记录通知历史失败: {e}")

    def _update_last_notified(self, subscription_id: int):
        """更新最后通知时间"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE subscriptions
                SET last_notified = ?
                WHERE id = ?
            """, (datetime.now().isoformat(), subscription_id))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"更新最后通知时间失败: {e}")

    def get_subscription_stats(self, subscription_id: int) -> Dict:
        """
        获取订阅统计信息

        Args:
            subscription_id: 订阅ID

        Returns:
            统计信息字典
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # 总通知次数
            cursor.execute("""
                SELECT COUNT(*) FROM notification_history
                WHERE subscription_id = ?
            """, (subscription_id,))
            total_notifications = cursor.fetchone()[0]

            # 最近7天通知次数
            cursor.execute("""
                SELECT COUNT(*) FROM notification_history
                WHERE subscription_id = ?
                AND notified_at >= datetime('now', '-7 days')
            """, (subscription_id,))
            recent_notifications = cursor.fetchone()[0]

            # 最后通知时间
            cursor.execute("""
                SELECT MAX(notified_at) FROM notification_history
                WHERE subscription_id = ?
            """, (subscription_id,))
            last_notification = cursor.fetchone()[0]

            conn.close()

            return {
                "subscription_id": subscription_id,
                "total_notifications": total_notifications,
                "recent_notifications_7d": recent_notifications,
                "last_notification": last_notification
            }

        except Exception as e:
            logger.error(f"获取订阅统计失败: {e}")
            return {}


# CLI测试入口
async def main():
    """CLI测试入口"""
    import sys

    manager = SubscriptionManager()

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "add":
            # 添加订阅
            # python subscription_manager.py add keyword "Apache" 7.0 console
            if len(sys.argv) < 6:
                print("用法: add <filter_type> <filter_value> <min_cvss> <notify_method> [notify_target]")
                return

            filter_type = sys.argv[2]
            filter_value = sys.argv[3]
            min_cvss = float(sys.argv[4])
            notify_method = sys.argv[5]
            notify_target = sys.argv[6] if len(sys.argv) > 6 else None

            sub_id = manager.add_subscription(
                filter_type=filter_type,
                filter_value=filter_value,
                min_cvss=min_cvss,
                notify_method=notify_method,
                notify_target=notify_target
            )
            print(f"订阅添加成功: ID={sub_id}")

        elif command == "list":
            # 列出订阅
            subscriptions = manager.list_subscriptions()
            print(f"\n共 {len(subscriptions)} 个订阅:\n")
            for sub in subscriptions:
                status = "✓" if sub.enabled else "✗"
                print(f"[{status}] ID={sub.id} | {sub.filter_type}={sub.filter_value}")
                print(f"    CVSS>={sub.min_cvss} | 通知: {sub.notify_method}")
                if sub.last_notified:
                    print(f"    最后通知: {sub.last_notified}")
                print()

        elif command == "remove":
            # 删除订阅
            if len(sys.argv) < 3:
                print("用法: remove <subscription_id>")
                return

            sub_id = int(sys.argv[2])
            manager.remove_subscription(sub_id)

        elif command == "check":
            # 检查新CVE
            matches = manager.check_new_cves()
            print(f"\n检查完成: {len(matches)} 个订阅匹配到新CVE")

        elif command == "stats":
            # 订阅统计
            if len(sys.argv) < 3:
                print("用法: stats <subscription_id>")
                return

            sub_id = int(sys.argv[2])
            stats = manager.get_subscription_stats(sub_id)
            print(f"\n订阅 {sub_id} 统计:")
            print(f"  总通知次数: {stats.get('total_notifications', 0)}")
            print(f"  最近7天: {stats.get('recent_notifications_7d', 0)}")
            print(f"  最后通知: {stats.get('last_notification', 'N/A')}")

        else:
            print(f"未知命令: {command}")

    else:
        print("CVE情报订阅管理器")
        print("\n用法:")
        print("  add <filter_type> <filter_value> <min_cvss> <notify_method> [notify_target]")
        print("      添加订阅")
        print("      示例: add keyword Apache 7.0 file /tmp/apache_cves.log")
        print("\n  list")
        print("      列出所有订阅")
        print("\n  remove <subscription_id>")
        print("      删除订阅")
        print("\n  check")
        print("      检查新CVE并发送通知")
        print("\n  stats <subscription_id>")
        print("      查看订阅统计")


if __name__ == "__main__":
    asyncio.run(main())
