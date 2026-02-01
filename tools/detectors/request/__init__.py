#!/usr/bin/env python3
"""
请求类漏洞检测器模块

包含:
- CSRFDetector: 跨站请求伪造检测
- SSRFDetector: 服务端请求伪造检测
- CORSDetector: 跨域资源共享配置检测
"""

from .cors import CORSDetector
from .csrf import CSRFDetector
from .ssrf import SSRFDetector

__all__ = ["CSRFDetector", "SSRFDetector", "CORSDetector"]
