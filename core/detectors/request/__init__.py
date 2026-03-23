"""
请求层漏洞检测器

包括 HTTP Request Smuggling、Cache Poisoning 等请求层面的漏洞检测。
"""

from .cache_poisoning import CachePoisoningDetector
from .http_smuggling import HTTPSmugglingDetector

__all__ = [
    "HTTPSmugglingDetector",
    "CachePoisoningDetector",
]
