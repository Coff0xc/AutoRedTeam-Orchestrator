"""Payload 加载器 — 运行时按需加载 + 线程安全缓存

提供两种加载方式:
1. YAML 加载器: 从 data/payloads/ 目录加载 YAML payload 文件
2. PayloadDB: 延迟加载 payloads/complete_payload_db.json
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DATA_DIR = _PROJECT_ROOT / "data" / "payloads"

# 线程安全缓存
_cache_lock = threading.Lock()
_cache: dict | None = None


def load_all_payloads() -> MappingProxyType:
    """加载所有 payload YAML 文件 (线程安全, 只读返回)

    Returns:
        以文件名(不含扩展名)为键的只读字典
    """
    global _cache
    if _cache is not None:
        return MappingProxyType(_cache)
    with _cache_lock:
        if _cache is not None:
            return MappingProxyType(_cache)
        payloads: dict = {}
        if _DATA_DIR.exists():
            for yaml_file in sorted(_DATA_DIR.glob("*.yaml")):
                category = yaml_file.stem
                with open(yaml_file, "r", encoding="utf-8") as f:
                    payloads[category] = yaml.safe_load(f) or {}
        _cache = payloads
    return MappingProxyType(_cache)


def load_payloads(category: str) -> dict:
    """加载指定类别的 payloads

    Args:
        category: payload 类别 (如 "sqli", "xss", "rce" 等)

    Returns:
        该类别的 payload 字典
    """
    all_payloads = load_all_payloads()
    return dict(all_payloads.get(category, {}))


def get_payload_list(category: str, subcategory: Optional[str] = None) -> list[str]:
    """获取扁平化的 payload 列表

    Args:
        category: payload 类别
        subcategory: 子类别 (可选)

    Returns:
        扁平化的 payload 字符串列表
    """
    data = load_payloads(category)
    if subcategory:
        result = data.get(subcategory, [])
        if isinstance(result, list):
            return result
        flat: list[str] = []
        _flatten(result, flat)
        return flat
    result: list[str] = []
    _flatten(data, result)
    return result


def _flatten(obj: object, result: list[str]) -> None:
    """递归展平嵌套结构为列表"""
    if isinstance(obj, list):
        result.extend(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _flatten(v, result)


def reload_payloads() -> None:
    """清除缓存，强制重新加载"""
    global _cache
    with _cache_lock:
        _cache = None


# ---------------------------------------------------------------------------
# PayloadDB — 延迟加载 complete_payload_db.json
# ---------------------------------------------------------------------------

_DEFAULT_DB_PATH = _PROJECT_ROOT / "payloads" / "complete_payload_db.json"


class PayloadDB:
    """延迟加载的 Payload 数据库，按需加载 JSON 文件

    首次访问数据时才从磁盘读取，之后使用内存缓存。
    线程安全，可作为单例使用。

    Usage:
        db = get_payload_db()
        sqli = db.get_category("sqli")
        print(db.categories)
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path: Path = db_path or _DEFAULT_DB_PATH
        self._full_db: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()

    def _ensure_loaded(self) -> Dict[str, Any]:
        """确保 JSON 已加载到内存 (双重检查锁)"""
        if self._full_db is None:
            with self._lock:
                if self._full_db is None:
                    if not self._db_path.exists():
                        logger.warning("Payload DB 文件不存在: %s", self._db_path)
                        self._full_db = {}
                    else:
                        with open(self._db_path, "r", encoding="utf-8") as f:
                            self._full_db = json.load(f)
                        logger.debug(
                            "已加载 Payload DB: %s (%d 个分类)",
                            self._db_path,
                            len(self._full_db),
                        )
        return self._full_db

    def get_category(self, category: str) -> Dict[str, Any]:
        """获取指定分类的 payload 数据

        Args:
            category: 分类名称 (如 "sqli", "xss", "rce" 等)

        Returns:
            该分类的完整数据字典，不存在则返回空字典
        """
        db = self._ensure_loaded()
        return dict(db.get(category, {}))

    def get_payloads(self, category: str, subcategory: Optional[str] = None) -> List[str]:
        """获取扁平化的 payload 字符串列表

        Args:
            category: 分类名称
            subcategory: 子分类 (可选)

        Returns:
            payload 字符串列表
        """
        data = self.get_category(category)
        if subcategory:
            sub = data.get(subcategory, data.get("categories", {}).get(subcategory, []))
            result: List[str] = []
            _flatten(sub, result)
            return result
        # 展平整个分类 (跳过 metadata 字段)
        result = []
        for key, val in data.items():
            if key in ("description", "count", "metadata"):
                continue
            _flatten(val, result)
        return result

    @property
    def categories(self) -> List[str]:
        """获取所有分类名称 (不含 metadata)"""
        db = self._ensure_loaded()
        return [k for k in db if k != "metadata"]

    @property
    def metadata(self) -> Dict[str, Any]:
        """获取数据库元信息"""
        db = self._ensure_loaded()
        return dict(db.get("metadata", {}))

    def __getitem__(self, category: str) -> Dict[str, Any]:
        """支持 db["sqli"] 语法"""
        return self.get_category(category)

    def __contains__(self, category: str) -> bool:
        """支持 "sqli" in db 语法"""
        db = self._ensure_loaded()
        return category in db

    def reload(self) -> None:
        """清除缓存，下次访问时重新加载"""
        with self._lock:
            self._full_db = None


# 全局单例
_payload_db: Optional[PayloadDB] = None
_payload_db_lock = threading.Lock()


def get_payload_db(db_path: Optional[Path] = None) -> PayloadDB:
    """获取全局 PayloadDB 单例

    Args:
        db_path: 自定义 JSON 路径 (仅首次调用时生效)

    Returns:
        PayloadDB 实例
    """
    global _payload_db
    if _payload_db is None:
        with _payload_db_lock:
            if _payload_db is None:
                _payload_db = PayloadDB(db_path=db_path)
    return _payload_db
