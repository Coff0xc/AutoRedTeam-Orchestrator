"""
访问控制漏洞检测器模块

包含 IDOR、路径遍历、SSRF、开放重定向等检测器
"""

from .idor import IDORDetector
from .open_redirect import OpenRedirectDetector
from .path_traversal import PathTraversalDetector
from .ssrf import SSRFDetector

__all__ = [
    "IDORDetector",
    "PathTraversalDetector",
    "SSRFDetector",
    "OpenRedirectDetector",
]
