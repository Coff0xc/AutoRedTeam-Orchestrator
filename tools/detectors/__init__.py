#!/usr/bin/env python3
"""
漏洞检测器统一导出接口 - 已弃用

⚠️ 此模块已弃用，请使用 core.detectors 模块

迁移指南:
    # 旧代码
    from tools.detectors import SQLiDetector, XSSDetector

    # 新代码
    from core.detectors import SQLiDetector, XSSDetector

    # 或使用工厂模式
    from core.detectors import DetectorFactory
    detector = DetectorFactory.create('sqli')

此模块现在作为 core.detectors 的兼容性层，
所有导入都会重定向到 core.detectors。
"""

import warnings
import logging

logger = logging.getLogger(__name__)

# 发出弃用警告
warnings.warn(
    "tools.detectors 模块已弃用，请使用 core.detectors 模块。"
    "此模块将在 v4.0 中移除。",
    DeprecationWarning,
    stacklevel=2
)


# ==================== 从 core.detectors 导入 ====================

try:
    # 基类和数据类
    from core.detectors import (
        BaseDetector,
        CompositeDetector,
        DetectionResult,
        Severity,
    )

    # 注入类检测器
    from core.detectors import (
        SQLiDetector,
        XSSDetector,
        RCEDetector,
        XXEDetector,
        SSTIDetector,
        DeserializeDetector,
    )

    # 访问控制检测器
    from core.detectors import (
        SSRFDetector,
        IDORDetector,
        OpenRedirectDetector,
        PathTraversalDetector,
    )

    # 文件类检测器
    from core.detectors import (
        LFIDetector,
        FileUploadDetector,
    )

    # 认证检测器
    from core.detectors import (
        AuthBypassDetector,
        WeakPasswordDetector,
    )

    # 其他检测器
    from core.detectors import (
        CORSDetector,
        CSRFDetector,
    )

    # 工厂
    from core.detectors import (
        DetectorFactory,
        create_detector,
        list_detectors as _list_detectors,
    )

    # 向后兼容: Vulnerability 别名
    class Vulnerability:
        """
        漏洞数据类 - 已弃用

        ⚠️ 请使用 core.detectors.DetectionResult
        """
        def __init__(self, **kwargs):
            warnings.warn(
                "Vulnerability 类已弃用，请使用 core.detectors.DetectionResult",
                DeprecationWarning,
                stacklevel=2
            )
            self.__dict__.update(kwargs)

    # ==================== 便捷函数 ====================

    def sqli_detect(url: str, param: str = None, **kwargs) -> dict:
        """SQL 注入检测 - 已弃用"""
        warnings.warn(
            "sqli_detect() 已弃用，请使用 SQLiDetector().detect()",
            DeprecationWarning,
            stacklevel=2
        )
        detector = SQLiDetector()
        params = {param: "1"} if param else kwargs.get('params', {})
        results = detector.detect(url, params=params)
        return {
            'vulnerable': len(results) > 0,
            'results': [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]
        }

    def xss_detect(url: str, param: str = None, **kwargs) -> dict:
        """XSS 检测 - 已弃用"""
        warnings.warn(
            "xss_detect() 已弃用，请使用 XSSDetector().detect()",
            DeprecationWarning,
            stacklevel=2
        )
        detector = XSSDetector()
        params = {param: "test"} if param else kwargs.get('params', {})
        results = detector.detect(url, params=params)
        return {
            'vulnerable': len(results) > 0,
            'results': [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]
        }

    def cmd_inject_detect(url: str, param: str = None, **kwargs) -> dict:
        """命令注入检测 - 已弃用"""
        warnings.warn(
            "cmd_inject_detect() 已弃用，请使用 RCEDetector().detect()",
            DeprecationWarning,
            stacklevel=2
        )
        detector = RCEDetector()
        params = {param: "test"} if param else kwargs.get('params', {})
        results = detector.detect(url, params=params)
        return {
            'vulnerable': len(results) > 0,
            'results': [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]
        }

    def ssrf_detect(url: str, param: str = None, **kwargs) -> dict:
        """SSRF 检测 - 已弃用"""
        warnings.warn(
            "ssrf_detect() 已弃用，请使用 SSRFDetector().detect()",
            DeprecationWarning,
            stacklevel=2
        )
        detector = SSRFDetector()
        params = {param: "http://127.0.0.1"} if param else kwargs.get('params', {})
        results = detector.detect(url, params=params)
        return {
            'vulnerable': len(results) > 0,
            'results': [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]
        }

    def csrf_detect(url: str, **kwargs) -> dict:
        """CSRF 检测 - 已弃用"""
        warnings.warn(
            "csrf_detect() 已弃用，请使用 CSRFDetector().detect()",
            DeprecationWarning,
            stacklevel=2
        )
        detector = CSRFDetector()
        results = detector.detect(url)
        return {
            'vulnerable': len(results) > 0,
            'results': [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]
        }

    def cors_deep_check(url: str, **kwargs) -> dict:
        """CORS 检测 - 已弃用"""
        warnings.warn(
            "cors_deep_check() 已弃用，请使用 CORSDetector().detect()",
            DeprecationWarning,
            stacklevel=2
        )
        detector = CORSDetector()
        results = detector.detect(url)
        return {
            'vulnerable': len(results) > 0,
            'results': [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]
        }

    def lfi_detect(url: str, param: str = None, **kwargs) -> dict:
        """LFI 检测 - 已弃用"""
        warnings.warn(
            "lfi_detect() 已弃用，请使用 LFIDetector().detect()",
            DeprecationWarning,
            stacklevel=2
        )
        detector = LFIDetector()
        params = {param: "/etc/passwd"} if param else kwargs.get('params', {})
        results = detector.detect(url, params=params)
        return {
            'vulnerable': len(results) > 0,
            'results': [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]
        }

    def file_upload_detect(url: str, **kwargs) -> dict:
        """文件上传检测 - 已弃用"""
        warnings.warn(
            "file_upload_detect() 已弃用，请使用 FileUploadDetector().detect()",
            DeprecationWarning,
            stacklevel=2
        )
        detector = FileUploadDetector()
        results = detector.detect(url, **kwargs)
        return {
            'vulnerable': len(results) > 0,
            'results': [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]
        }

    def auth_bypass_detect(url: str, **kwargs) -> dict:
        """认证绕过检测 - 已弃用"""
        warnings.warn(
            "auth_bypass_detect() 已弃用，请使用 AuthBypassDetector().detect()",
            DeprecationWarning,
            stacklevel=2
        )
        detector = AuthBypassDetector()
        results = detector.detect(url)
        return {
            'vulnerable': len(results) > 0,
            'results': [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]
        }

    def weak_password_detect(url: str, **kwargs) -> dict:
        """弱密码检测 - 已弃用"""
        warnings.warn(
            "weak_password_detect() 已弃用，请使用 WeakPasswordDetector().detect()",
            DeprecationWarning,
            stacklevel=2
        )
        detector = WeakPasswordDetector()
        results = detector.detect(url)
        return {
            'vulnerable': len(results) > 0,
            'results': [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]
        }

    # ==================== 检测器注册表 ====================

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
        "path_traversal": PathTraversalDetector,
        "file_upload": FileUploadDetector,
        "auth_bypass": AuthBypassDetector,
        "weak_password": WeakPasswordDetector,
        "idor": IDORDetector,
        "open_redirect": OpenRedirectDetector,
    }

    def get_detector(detector_type: str) -> BaseDetector:
        """
        根据类型获取检测器实例 - 已弃用

        请使用 core.detectors.DetectorFactory.create()
        """
        warnings.warn(
            "get_detector() 已弃用，请使用 core.detectors.DetectorFactory.create()",
            DeprecationWarning,
            stacklevel=2
        )
        detector_type = detector_type.lower()
        if detector_type not in DETECTOR_REGISTRY:
            available = ", ".join(DETECTOR_REGISTRY.keys())
            raise ValueError(f"未知的检测器类型: {detector_type}。可用类型: {available}")

        return DETECTOR_REGISTRY[detector_type]()

    def list_detectors() -> dict:
        """
        列出所有可用的检测器 - 已弃用

        请使用 core.detectors.list_detectors()
        """
        warnings.warn(
            "list_detectors() 已弃用，请使用 core.detectors.list_detectors()",
            DeprecationWarning,
            stacklevel=2
        )
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
            "idor": "不安全的直接对象引用检测",
            "open_redirect": "开放重定向检测",
        }

    logger.info("tools.detectors 已重定向到 core.detectors")

except ImportError as e:
    # core.detectors 不可用时，保留原始实现
    logger.warning(f"core.detectors 不可用，使用原始实现: {e}")

    # 从原始模块导入
    from .base import BaseDetector, Vulnerability
    from .injection import (
        SQLiDetector, XSSDetector, RCEDetector,
        XXEDetector, SSTIDetector, DeserializeDetector
    )
    from .request import SSRFDetector, CSRFDetector, CORSDetector
    from .file import LFIDetector, FileUploadDetector
    from .auth import AuthBypassDetector, WeakPasswordDetector
    from .access import IDORDetector, OpenRedirectDetector

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
        detector_type = detector_type.lower()
        if detector_type not in DETECTOR_REGISTRY:
            available = ", ".join(DETECTOR_REGISTRY.keys())
            raise ValueError(f"未知的检测器类型: {detector_type}。可用类型: {available}")
        return DETECTOR_REGISTRY[detector_type]()

    def list_detectors() -> dict:
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

    # 注册表
    "DETECTOR_REGISTRY",
    "get_detector",
    "list_detectors",
]
