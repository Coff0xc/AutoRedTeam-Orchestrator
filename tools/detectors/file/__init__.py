#!/usr/bin/env python3
"""
文件类漏洞检测器模块

包含:
- LFIDetector: 本地/远程文件包含检测
- FileUploadDetector: 文件上传漏洞检测
"""

from .lfi import LFIDetector
from .upload import FileUploadDetector

__all__ = ["LFIDetector", "FileUploadDetector"]
