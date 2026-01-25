"""
文件类漏洞检测器

包含:
- LFI/RFI (本地/远程文件包含)
- 文件上传漏洞
"""

from .lfi import LFIDetector
from .upload import FileUploadDetector

__all__ = ['LFIDetector', 'FileUploadDetector']
