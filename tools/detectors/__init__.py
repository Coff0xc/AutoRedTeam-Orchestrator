#!/usr/bin/env python3
"""
漏洞检测器统一导出接口

模块结构:
- base: 基类和数据类
- injection: 注入类检测器 (SQLi/XSS/RCE/XXE/SSTI/Deserialize)
- request: 请求类检测器 (SSRF/CSRF/CORS)
- file: 文件类检测器 (LFI/Upload)
- auth: 认证类检测器 (AuthBypass/WeakPassword)
- access: 访问控制检测器 (IDOR/OpenRedirect)

使用示例:
    from tools.detectors import SQLiDetector, XSSDetector

    with SQLiDetector() as detector:
        result = detector.detect("http://example.com/page?id=1", param="id")
"""

# 基类和数据类
from .base import BaseDetector, Vulnerability

# 注入类检测器
from .injection import (
    SQLiDetector, XSSDetector, RCEDetector,
    XXEDetector, SSTIDetector, DeserializeDetector
)

# 请求类检测器
from .request import SSRFDetector, CSRFDetector, CORSDetector

# 文件类检测器
from .file import LFIDetector, FileUploadDetector

# 认证类检测器
from .auth import AuthBypassDetector, WeakPasswordDetector

# 访问控制检测器
from .access import IDORDetector, OpenRedirectDetector

# 便捷函数导入 (兼容旧接口)
from .injection.sqli import sqli_detect
from .injection.xss import xss_detect
from .injection.rce import cmd_inject_detect
from .request.ssrf import ssrf_detect
from .request.csrf import csrf_detect
from .request.cors import cors_deep_check
from .file.lfi import lfi_detect
from .file.upload import file_upload_detect
from .auth.auth_bypass import auth_bypass_detect
from .auth.weak_password import weak_password_detect


__all__ = [
    # 基类
    "BaseDetector",
    "Vulnerability",

    # 检测器类
    "SQLiDetector",
    "XSSDetector",
    "RCEDetector",
    "XXEDetector",
    "SSTIDetector",
    "DeserializeDetector",
    "SSRFDetector",
    "CSRFDetector",
    "CORSDetector",
    "LFIDetector",
    "FileUploadDetector",
    "AuthBypassDetector",
    "WeakPasswordDetector",
    "IDORDetector",
    "OpenRedirectDetector",

    # 便捷函数
    "sqli_detect",
    "xss_detect",
    "cmd_inject_detect",
    "ssrf_detect",
    "csrf_detect",
    "cors_deep_check",
    "lfi_detect",
    "file_upload_detect",
    "auth_bypass_detect",
    "weak_password_detect",
]


# 检测器注册表 (用于动态调用)
DETECTOR_REGISTRY = {
    "sqli": SQLiDetector,
    "xss": XSSDetector,
    "rce": RCEDetector,
    "cmd_inject": RCEDetector,
    "xxe": XXEDetector,
    "ssti": SSTIDetector,
    "deserialize": DeserializeDetector,
    "ssrf": SSRFDetector,
    "csrf": CSRFDetector,
    "cors": CORSDetector,
    "lfi": LFIDetector,
    "file_upload": FileUploadDetector,
    "auth_bypass": AuthBypassDetector,
    "weak_password": WeakPasswordDetector,
    "idor": IDORDetector,
    "open_redirect": OpenRedirectDetector,
}


def get_detector(detector_type: str) -> BaseDetector:
    """
    根据类型获取检测器实例

    Args:
        detector_type: 检测器类型 (sqli/xss/rce/ssrf/csrf/cors/lfi/file_upload/auth_bypass/weak_password)

    Returns:
        检测器实例

    Raises:
        ValueError: 未知的检测器类型
    """
    detector_type = detector_type.lower()
    if detector_type not in DETECTOR_REGISTRY:
        available = ", ".join(DETECTOR_REGISTRY.keys())
        raise ValueError(f"未知的检测器类型: {detector_type}。可用类型: {available}")

    return DETECTOR_REGISTRY[detector_type]()


def list_detectors() -> dict:
    """
    列出所有可用的检测器

    Returns:
        检测器类型和描述的字典
    """
    return {
        "sqli": "SQL 注入检测",
        "xss": "跨站脚本检测",
        "rce": "远程命令执行检测",
        "ssrf": "服务端请求伪造检测",
        "csrf": "跨站请求伪造检测",
        "cors": "跨域资源共享配置检测",
        "lfi": "本地/远程文件包含检测",
        "file_upload": "文件上传漏洞检测",
        "auth_bypass": "认证绕过检测",
        "weak_password": "弱密码检测",
    }
