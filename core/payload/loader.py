"""Payload YAML 加载器 — 运行时加载 + 线程安全缓存

从 data/payloads/ 目录加载 YAML payload 文件，
替代原 mega_payloads.py 中的硬编码数据。
"""

from __future__ import annotations

import threading
from pathlib import Path
from types import MappingProxyType
from typing import Optional

import yaml

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "payloads"

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
