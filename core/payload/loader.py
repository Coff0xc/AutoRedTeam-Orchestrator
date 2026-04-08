"""Payload YAML 加载器 — 运行时加载 + 内存缓存

从 data/payloads/ 目录加载 YAML payload 文件，
替代原 mega_payloads.py 中的硬编码数据。
"""

from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "payloads"


@lru_cache(maxsize=1)
def load_all_payloads() -> dict:
    """加载所有 payload YAML 文件

    Returns:
        以文件名(不含扩展名)为键的字典，值为对应 YAML 内容
    """
    payloads = {}
    if not _DATA_DIR.exists():
        return payloads
    for yaml_file in sorted(_DATA_DIR.glob("*.yaml")):
        category = yaml_file.stem
        with open(yaml_file, "r", encoding="utf-8") as f:
            payloads[category] = yaml.safe_load(f) or {}
    return payloads


def load_payloads(category: str) -> dict:
    """加载指定类别的 payloads

    Args:
        category: payload 类别 (如 "sqli", "xss", "rce" 等)

    Returns:
        该类别的 payload 字典
    """
    all_payloads = load_all_payloads()
    return all_payloads.get(category, {})


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
        # subcategory 本身可能是嵌套 dict
        flat: list[str] = []
        _flatten(result, flat)
        return flat
    # 递归展平所有 payload
    result: list[str] = []
    _flatten(data, result)
    return result


def _flatten(obj, result: list) -> None:
    """递归展平嵌套结构为列表"""
    if isinstance(obj, list):
        result.extend(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _flatten(v, result)


def reload_payloads() -> None:
    """清除缓存，强制重新加载"""
    load_all_payloads.cache_clear()
