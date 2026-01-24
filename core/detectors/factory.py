"""
检测器工厂

提供检测器的注册、创建和管理功能
"""

from typing import Dict, Type, List, Optional, Any, Callable
import logging

from .base import BaseDetector, CompositeDetector
from .result import DetectorType, Severity

logger = logging.getLogger(__name__)


class DetectorFactory:
    """检测器工厂

    负责检测器的注册、创建和管理

    使用示例:
        # 注册检测器
        DetectorFactory.register('sqli', SQLiDetector)

        # 创建检测器
        detector = DetectorFactory.create('sqli')

        # 创建所有注入类检测器
        detectors = DetectorFactory.create_by_type(DetectorType.INJECTION)
    """

    # 检测器注册表
    _detectors: Dict[str, Type[BaseDetector]] = {}

    # 检测器元信息
    _metadata: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def register(
        cls,
        name: str,
        detector_class: Type[BaseDetector],
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """注册检测器

        Args:
            name: 检测器名称
            detector_class: 检测器类
            metadata: 额外元信息
        """
        if name in cls._detectors:
            logger.warning(f"检测器 '{name}' 已存在，将被覆盖")

        cls._detectors[name] = detector_class
        cls._metadata[name] = metadata or {}
        logger.debug(f"注册检测器: {name}")

    @classmethod
    def unregister(cls, name: str) -> bool:
        """注销检测器

        Args:
            name: 检测器名称

        Returns:
            是否成功注销
        """
        if name in cls._detectors:
            del cls._detectors[name]
            cls._metadata.pop(name, None)
            return True
        return False

    @classmethod
    def create(
        cls,
        name: str,
        config: Optional[Dict[str, Any]] = None
    ) -> BaseDetector:
        """创建检测器实例

        Args:
            name: 检测器名称
            config: 检测器配置

        Returns:
            检测器实例

        Raises:
            ValueError: 检测器不存在
        """
        if name not in cls._detectors:
            raise ValueError(f"未知检测器: {name}，可用: {list(cls._detectors.keys())}")

        return cls._detectors[name](config)

    @classmethod
    def create_all(
        cls,
        config: Optional[Dict[str, Any]] = None
    ) -> List[BaseDetector]:
        """创建所有已注册的检测器

        Args:
            config: 共享配置

        Returns:
            检测器实例列表
        """
        return [
            detector_class(config)
            for detector_class in cls._detectors.values()
        ]

    @classmethod
    def create_by_type(
        cls,
        detector_type: DetectorType,
        config: Optional[Dict[str, Any]] = None
    ) -> List[BaseDetector]:
        """按类型创建检测器

        Args:
            detector_type: 检测器类型
            config: 共享配置

        Returns:
            指定类型的检测器实例列表
        """
        return [
            detector_class(config)
            for detector_class in cls._detectors.values()
            if detector_class.detector_type == detector_type
        ]

    @classmethod
    def create_by_severity(
        cls,
        min_severity: Severity,
        config: Optional[Dict[str, Any]] = None
    ) -> List[BaseDetector]:
        """按最小严重程度创建检测器

        Args:
            min_severity: 最小严重程度
            config: 共享配置

        Returns:
            符合条件的检测器实例列表
        """
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        min_index = severity_order.index(min_severity)

        return [
            detector_class(config)
            for detector_class in cls._detectors.values()
            if severity_order.index(detector_class.severity) >= min_index
        ]

    @classmethod
    def create_composite(
        cls,
        names: List[str],
        config: Optional[Dict[str, Any]] = None
    ) -> CompositeDetector:
        """创建组合检测器

        Args:
            names: 检测器名称列表
            config: 共享配置

        Returns:
            组合检测器实例
        """
        detectors = [cls.create(name, config) for name in names]
        return CompositeDetector(detectors, config)

    @classmethod
    def list_detectors(cls) -> List[str]:
        """列出所有已注册的检测器名称

        Returns:
            检测器名称列表
        """
        return list(cls._detectors.keys())

    @classmethod
    def get_detector_info(cls, name: str) -> Dict[str, Any]:
        """获取检测器信息

        Args:
            name: 检测器名称

        Returns:
            检测器信息字典
        """
        if name not in cls._detectors:
            return {}

        detector_class = cls._detectors[name]
        return {
            'name': detector_class.name,
            'description': detector_class.description,
            'vuln_type': detector_class.vuln_type,
            'severity': detector_class.severity.value,
            'detector_type': detector_class.detector_type.value,
            'version': detector_class.version,
            'metadata': cls._metadata.get(name, {})
        }

    @classmethod
    def get_all_info(cls) -> List[Dict[str, Any]]:
        """获取所有检测器信息

        Returns:
            检测器信息列表
        """
        return [cls.get_detector_info(name) for name in cls._detectors]

    @classmethod
    def exists(cls, name: str) -> bool:
        """检查检测器是否存在

        Args:
            name: 检测器名称

        Returns:
            是否存在
        """
        return name in cls._detectors

    @classmethod
    def clear(cls) -> None:
        """清除所有注册的检测器"""
        cls._detectors.clear()
        cls._metadata.clear()


def register_detector(
    name: str,
    metadata: Optional[Dict[str, Any]] = None
) -> Callable[[Type[BaseDetector]], Type[BaseDetector]]:
    """检测器注册装饰器

    使用示例:
        @register_detector('sqli')
        class SQLiDetector(BaseDetector):
            ...

        @register_detector('xss', metadata={'author': 'team'})
        class XSSDetector(BaseDetector):
            ...

    Args:
        name: 检测器名称
        metadata: 额外元信息

    Returns:
        装饰器函数
    """
    def decorator(cls: Type[BaseDetector]) -> Type[BaseDetector]:
        DetectorFactory.register(name, cls, metadata)
        return cls
    return decorator


# 预定义的检测器组合
class DetectorPresets:
    """预定义的检测器组合"""

    @staticmethod
    def owasp_top10(config: Optional[Dict[str, Any]] = None) -> CompositeDetector:
        """OWASP Top 10 检测器组合"""
        names = [
            'sqli', 'xss', 'xxe', 'idor',
            'security_misconfiguration', 'auth_bypass',
            'xssi', 'csrf', 'ssrf', 'rce'
        ]
        available = [n for n in names if DetectorFactory.exists(n)]
        return DetectorFactory.create_composite(available, config)

    @staticmethod
    def injection_suite(config: Optional[Dict[str, Any]] = None) -> CompositeDetector:
        """注入类漏洞检测器组合"""
        return CompositeDetector(
            DetectorFactory.create_by_type(DetectorType.INJECTION, config),
            config
        )

    @staticmethod
    def auth_suite(config: Optional[Dict[str, Any]] = None) -> CompositeDetector:
        """认证类漏洞检测器组合"""
        return CompositeDetector(
            DetectorFactory.create_by_type(DetectorType.AUTH, config),
            config
        )

    @staticmethod
    def quick_scan(config: Optional[Dict[str, Any]] = None) -> CompositeDetector:
        """快速扫描组合（高危漏洞优先）"""
        return CompositeDetector(
            DetectorFactory.create_by_severity(Severity.HIGH, config),
            config
        )

    @staticmethod
    def full_scan(config: Optional[Dict[str, Any]] = None) -> CompositeDetector:
        """完整扫描组合"""
        return CompositeDetector(
            DetectorFactory.create_all(config),
            config
        )
