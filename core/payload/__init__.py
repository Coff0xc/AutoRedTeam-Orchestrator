"""Payload 管理模块

提供 YAML 文件加载和向后兼容的 MegaPayloads 接口。
"""

from .loader import (
    get_payload_list,
    load_all_payloads,
    load_payloads,
    reload_payloads,
)

__all__ = [
    "load_all_payloads",
    "load_payloads",
    "get_payload_list",
    "reload_payloads",
]
