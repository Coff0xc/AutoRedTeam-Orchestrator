"""
漏洞检测器模块

提供统一的漏洞检测框架，包括:
- 注入类漏洞检测 (SQL注入、XSS、命令注入、模板注入、XXE、LDAP注入)
- 访问控制漏洞检测 (IDOR、路径遍历、SSRF、开放重定向)
- 认证漏洞检测 (弱密码、认证绕过、会话安全)
- 其他漏洞检测 (CORS、CSRF、安全头、信息泄露)

使用示例:

    # 基础使用
    from core.detectors import DetectorFactory, SQLiDetector

    # 方式1: 直接实例化
    detector = SQLiDetector()
    results = detector.detect("https://example.com/search", params={"q": "test"})

    # 方式2: 使用工厂
    detector = DetectorFactory.create('sqli')
    results = detector.detect("https://example.com/search", params={"q": "test"})

    # 方式3: 创建组合检测器
    composite = DetectorFactory.create_composite(['sqli', 'xss', 'rce'])
    results = composite.detect("https://example.com/search", params={"q": "test"})

    # 方式4: 使用预设
    from core.detectors import DetectorPresets
    owasp_detector = DetectorPresets.owasp_top10()
    results = owasp_detector.detect("https://example.com")

    # 异步检测
    import asyncio
    results = asyncio.run(detector.async_detect("https://example.com/search"))

    # 获取检测结果详情
    for result in results:
        print(f"漏洞类型: {result.vuln_type}")
        print(f"严重程度: {result.severity.value}")
        print(f"参数: {result.param}")
        print(f"Payload: {result.payload}")
        print(f"证据: {result.evidence}")
        print(f"修复建议: {result.remediation}")
"""

# 基础类
from .base import (
    BaseDetector,
    CompositeDetector,
    StreamingDetector,
    ContextAwareDetector,
)

# 检测结果
from .result import (
    DetectionResult,
    DetectionSummary,
    Severity,
    DetectorType,
    RequestInfo,
    ResponseInfo,
)

# 工厂
from .factory import (
    DetectorFactory,
    DetectorPresets,
    register_detector,
)

# Payload 管理
from .payloads import (
    PayloadManager,
    PayloadCategory,
    PayloadEncoder,
    EncodingType,
    Payload,
    get_payloads,
    get_payloads_with_variants,
    get_payload_manager,
)

# ==================== 导入所有检测器以触发注册 ====================

# 注入类检测器
from .injection import (
    SQLiDetector,
    XSSDetector,
    RCEDetector,
    SSTIDetector,
    XXEDetector,
    LDAPiDetector,
)

# 访问控制检测器
from .access import (
    IDORDetector,
    PathTraversalDetector,
    SSRFDetector,
    OpenRedirectDetector,
)

# 认证检测器
from .auth import (
    WeakPasswordDetector,
    AuthBypassDetector,
    SessionDetector,
)

# 其他检测器
from .misc import (
    CORSDetector,
    CSRFDetector,
    SecurityHeadersDetector,
    InfoDisclosureDetector,
)


# ==================== 便捷函数 ====================

def create_detector(name: str, config: dict = None) -> BaseDetector:
    """创建检测器的便捷函数

    Args:
        name: 检测器名称
        config: 配置选项

    Returns:
        检测器实例
    """
    return DetectorFactory.create(name, config)


def list_detectors() -> list:
    """列出所有可用的检测器

    Returns:
        检测器名称列表
    """
    return DetectorFactory.list_detectors()


def get_detector_info(name: str) -> dict:
    """获取检测器信息

    Args:
        name: 检测器名称

    Returns:
        检测器信息字典
    """
    return DetectorFactory.get_detector_info(name)


# ==================== 导出 ====================

__all__ = [
    # 基础类
    'BaseDetector',
    'CompositeDetector',
    'StreamingDetector',
    'ContextAwareDetector',

    # 检测结果
    'DetectionResult',
    'DetectionSummary',
    'Severity',
    'DetectorType',
    'RequestInfo',
    'ResponseInfo',

    # 工厂
    'DetectorFactory',
    'DetectorPresets',
    'register_detector',

    # Payload
    'PayloadManager',
    'PayloadCategory',
    'PayloadEncoder',
    'EncodingType',
    'Payload',
    'get_payloads',
    'get_payloads_with_variants',
    'get_payload_manager',

    # 注入类检测器
    'SQLiDetector',
    'XSSDetector',
    'RCEDetector',
    'SSTIDetector',
    'XXEDetector',
    'LDAPiDetector',

    # 访问控制检测器
    'IDORDetector',
    'PathTraversalDetector',
    'SSRFDetector',
    'OpenRedirectDetector',

    # 认证检测器
    'WeakPasswordDetector',
    'AuthBypassDetector',
    'SessionDetector',

    # 其他检测器
    'CORSDetector',
    'CSRFDetector',
    'SecurityHeadersDetector',
    'InfoDisclosureDetector',

    # 便捷函数
    'create_detector',
    'list_detectors',
    'get_detector_info',
]


# 版本信息
__version__ = '2.0.0'
__author__ = 'AutoRedTeam'
