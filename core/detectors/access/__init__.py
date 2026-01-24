"""
访问控制漏洞检测器模块

包含 IDOR、路径遍历、SSRF、开放重定向等检测器
"""

from .idor import IDORDetector
from .path_traversal import PathTraversalDetector
from .ssrf import SSRFDetector
from .open_redirect import OpenRedirectDetector

__all__ = [
    'IDORDetector',
    'PathTraversalDetector',
    'SSRFDetector',
    'OpenRedirectDetector',
]
