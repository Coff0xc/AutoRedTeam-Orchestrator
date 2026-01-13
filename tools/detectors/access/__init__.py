#!/usr/bin/env python3
"""
访问控制漏洞检测器模块

包含:
- IDORDetector: 不安全的直接对象引用检测
- OpenRedirectDetector: 开放重定向检测
"""

from .idor import IDORDetector
from .open_redirect import OpenRedirectDetector

__all__ = ["IDORDetector", "OpenRedirectDetector"]
