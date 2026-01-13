#!/usr/bin/env python3
"""
检测器工厂 - 统一创建和管理检测器实例
应用工厂模式，消除硬编码的检测器创建逻辑
"""

from typing import Dict, Type, Optional, List
import logging

logger = logging.getLogger(__name__)


class DetectorFactory:
    """
    检测器工厂 - 统一创建检测器实例

    特性:
    - 自动注册检测器
    - 支持参数化创建
    - 支持检测器列表查询
    - 支持批量创建
    """

    _registry: Dict[str, Type] = {}
    _aliases: Dict[str, str] = {}

    @classmethod
    def register(cls, name: str, detector_class: Type, aliases: List[str] = None):
        """
        注册检测器

        Args:
            name: 检测器名称
            detector_class: 检测器类
            aliases: 别名列表
        """
        cls._registry[name] = detector_class
        logger.debug(f"注册检测器: {name} -> {detector_class.__name__}")

        # 注册别名
        if aliases:
            for alias in aliases:
                cls._aliases[alias] = name

    @classmethod
    def create(cls, name: str, **kwargs):
        """
        创建检测器实例

        Args:
            name: 检测器名称或别名
            **kwargs: 传递给检测器构造函数的参数

        Returns:
            检测器实例

        Raises:
            ValueError: 检测器不存在
        """
        # 解析别名
        actual_name = cls._aliases.get(name, name)

        detector_class = cls._registry.get(actual_name)
        if not detector_class:
            raise ValueError(
                f"未知的检测器: {name}. "
                f"可用检测器: {', '.join(cls.list_detectors())}"
            )

        try:
            return detector_class(**kwargs)
        except Exception as e:
            logger.error(f"创建检测器失败 {name}: {e}")
            raise

    @classmethod
    def list_detectors(cls) -> List[str]:
        """列出所有已注册的检测器"""
        return sorted(cls._registry.keys())

    @classmethod
    def list_aliases(cls) -> Dict[str, str]:
        """列出所有别名映射"""
        return cls._aliases.copy()

    @classmethod
    def get_detector_info(cls, name: str) -> Dict:
        """
        获取检测器信息

        Args:
            name: 检测器名称

        Returns:
            检测器信息字典
        """
        actual_name = cls._aliases.get(name, name)
        detector_class = cls._registry.get(actual_name)

        if not detector_class:
            return {"error": f"检测器不存在: {name}"}

        return {
            "name": actual_name,
            "class": detector_class.__name__,
            "module": detector_class.__module__,
            "doc": detector_class.__doc__ or "无描述"
        }

    @classmethod
    def create_all(cls, **kwargs) -> Dict[str, object]:
        """
        创建所有检测器实例

        Args:
            **kwargs: 传递给所有检测器的参数

        Returns:
            检测器实例字典 {name: instance}
        """
        instances = {}
        for name in cls._registry.keys():
            try:
                instances[name] = cls.create(name, **kwargs)
            except Exception as e:
                logger.error(f"创建检测器失败 {name}: {e}")
        return instances


# 自动注册所有检测器
def auto_register_detectors():
    """自动注册所有检测器"""
    try:
        # 注入类检测器
        from tools.detectors.injection.sqli import SQLiDetector
        DetectorFactory.register("sqli", SQLiDetector, aliases=["sql", "sql_injection"])

        from tools.detectors.injection.xss import XSSDetector
        DetectorFactory.register("xss", XSSDetector, aliases=["cross_site_scripting"])

        from tools.detectors.injection.rce import RCEDetector
        DetectorFactory.register("rce", RCEDetector, aliases=["command_injection", "cmd_inject"])

        from tools.detectors.injection.ssti import SSTIDetector
        DetectorFactory.register("ssti", SSTIDetector, aliases=["template_injection"])

        from tools.detectors.injection.xxe import XXEDetector
        DetectorFactory.register("xxe", XXEDetector, aliases=["xml_injection"])

        from tools.detectors.injection.deserialize import DeserializeDetector
        DetectorFactory.register("deserialize", DeserializeDetector, aliases=["deserialization"])

        # 请求类检测器
        from tools.detectors.request.ssrf import SSRFDetector
        DetectorFactory.register("ssrf", SSRFDetector, aliases=["server_side_request_forgery"])

        from tools.detectors.request.csrf import CSRFDetector
        DetectorFactory.register("csrf", CSRFDetector, aliases=["cross_site_request_forgery"])

        from tools.detectors.request.cors import CORSDetector
        DetectorFactory.register("cors", CORSDetector, aliases=["cors_misconfiguration"])

        # 文件类检测器
        from tools.detectors.file.lfi import LFIDetector
        DetectorFactory.register("lfi", LFIDetector, aliases=["local_file_inclusion"])

        from tools.detectors.file.upload import FileUploadDetector
        DetectorFactory.register("file_upload", FileUploadDetector, aliases=["upload"])

        # 认证类检测器
        from tools.detectors.auth.weak_password import WeakPasswordDetector
        DetectorFactory.register("weak_password", WeakPasswordDetector, aliases=["weak_pass", "brute_force"])

        from tools.detectors.auth.auth_bypass import AuthBypassDetector
        DetectorFactory.register("auth_bypass", AuthBypassDetector, aliases=["auth_vuln"])

        # 访问控制类检测器
        from tools.detectors.access.idor import IDORDetector
        DetectorFactory.register("idor", IDORDetector, aliases=["insecure_direct_object_reference"])

        from tools.detectors.access.open_redirect import OpenRedirectDetector
        DetectorFactory.register("open_redirect", OpenRedirectDetector, aliases=["redirect"])

        logger.info(f"已注册 {len(DetectorFactory.list_detectors())} 个检测器")

    except ImportError as e:
        logger.warning(f"部分检测器注册失败: {e}")


# 初始化时自动注册
auto_register_detectors()


# 使用示例
if __name__ == "__main__":
    # 创建单个检测器
    sqli_detector = DetectorFactory.create("sqli", timeout=15)
    print(f"创建检测器: {sqli_detector.__class__.__name__}")

    # 使用别名
    xss_detector = DetectorFactory.create("cross_site_scripting")
    print(f"使用别名创建: {xss_detector.__class__.__name__}")

    # 列出所有检测器
    detectors = DetectorFactory.list_detectors()
    print(f"可用检测器 ({len(detectors)}): {', '.join(detectors)}")

    # 获取检测器信息
    info = DetectorFactory.get_detector_info("sqli")
    print(f"检测器信息: {info}")

    # 批量创建
    all_detectors = DetectorFactory.create_all(timeout=10)
    print(f"批量创建: {len(all_detectors)} 个检测器")
