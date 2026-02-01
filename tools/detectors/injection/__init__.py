#!/usr/bin/env python3
"""
注入类漏洞检测器模块

包含:
- SQLiDetector: SQL注入检测
- XSSDetector: 跨站脚本检测
- RCEDetector: 命令注入检测
- XXEDetector: XML外部实体注入检测
- SSTIDetector: 服务端模板注入检测
- DeserializeDetector: 反序列化漏洞检测
"""

from .deserialize import DeserializeDetector
from .rce import RCEDetector
from .sqli import SQLiDetector
from .ssti import SSTIDetector
from .xss import XSSDetector
from .xxe import XXEDetector

__all__ = [
    "SQLiDetector",
    "XSSDetector",
    "RCEDetector",
    "XXEDetector",
    "SSTIDetector",
    "DeserializeDetector",
]
