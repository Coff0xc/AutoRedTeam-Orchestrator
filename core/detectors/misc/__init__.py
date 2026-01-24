"""
其他漏洞检测器模块

包含 CORS、CSRF、安全头、信息泄露等检测器
"""

from .cors import CORSDetector
from .csrf import CSRFDetector
from .headers import SecurityHeadersDetector
from .info_disclosure import InfoDisclosureDetector

__all__ = [
    'CORSDetector',
    'CSRFDetector',
    'SecurityHeadersDetector',
    'InfoDisclosureDetector',
]
