#!/usr/bin/env python3
"""
AutoRedTeam Recon 引擎模块

统一的侦察引擎接口，提供完整的信息收集能力。

使用方式:
    from core.recon import StandardReconEngine, ReconConfig

    # 基础用法
    engine = StandardReconEngine("https://example.com")
    result = engine.run()
    print(result.to_dict())

    # 自定义配置
    config = ReconConfig(
        timeout=30,
        enable_subdomain=True,
        enable_directory=True,
        quick_mode=False
    )
    engine = StandardReconEngine("https://example.com", config)
    result = engine.run()

    # 使用工厂函数
    from core.recon import create_engine
    engine = create_engine("https://example.com", engine_type="standard")
    result = engine.run()

模块结构:
    - phases.py      - 侦察阶段定义
    - base.py        - 侦察引擎基类
    - engine.py      - 标准侦察引擎
    - fingerprint.py - 指纹识别
    - port_scanner.py- 端口扫描
    - dns_resolver.py- DNS解析
    - subdomain.py   - 子域名枚举
    - directory.py   - 目录扫描
    - tech_detect.py - 技术栈识别
    - waf_detect.py  - WAF检测
"""

# 阶段定义
from .phases import (
    ReconPhase,
    PhaseStatus,
    PhaseResult,
    PhaseConfig,
    PhaseHandler,
    PhaseManager,
    DEFAULT_PHASE_ORDER,
    QUICK_PHASE_ORDER,
    MINIMAL_PHASE_ORDER,
)

# 基类和数据类
from .base import (
    Severity,
    ReconConfig,
    Finding,
    ReconResult,
    BaseReconEngine,
    ProgressCallback,
)

# 标准引擎
from .engine import (
    StandardReconEngine,
    create_recon_engine,
)

# 指纹识别
from .fingerprint import (
    FingerprintCategory,
    Fingerprint,
    FingerprintRule,
    FingerprintEngine,
    identify_fingerprints,
)

# 端口扫描
from .port_scanner import (
    PortInfo,
    PortScanner,
    scan_ports,
    async_scan_ports,
)

# DNS解析
from .dns_resolver import (
    DNSRecordType,
    DNSRecord,
    DNSResult,
    DNSResolver,
    resolve_domain,
    async_resolve_domain,
    get_dns_records,
)

# 子域名枚举
from .subdomain import (
    SubdomainInfo,
    SubdomainEnumerator,
    enumerate_subdomains,
    async_enumerate_subdomains,
)

# 目录扫描
from .directory import (
    DirectoryInfo,
    DirectoryScanner,
    scan_directories,
    async_scan_directories,
)

# 技术栈识别
from .tech_detect import (
    Technology,
    TechDetector,
    detect_technologies,
)

# WAF检测
from .waf_detect import (
    WAFInfo,
    WAFDetector,
    detect_waf,
    is_waf_protected,
)


# 导出列表
__all__ = [
    # 阶段
    "ReconPhase",
    "PhaseStatus",
    "PhaseResult",
    "PhaseConfig",
    "PhaseHandler",
    "PhaseManager",
    "DEFAULT_PHASE_ORDER",
    "QUICK_PHASE_ORDER",
    "MINIMAL_PHASE_ORDER",

    # 基类和配置
    "Severity",
    "ReconConfig",
    "Finding",
    "ReconResult",
    "BaseReconEngine",
    "ProgressCallback",

    # 引擎
    "StandardReconEngine",
    "create_recon_engine",

    # 指纹识别
    "FingerprintCategory",
    "Fingerprint",
    "FingerprintRule",
    "FingerprintEngine",
    "identify_fingerprints",

    # 端口扫描
    "PortInfo",
    "PortScanner",
    "scan_ports",
    "async_scan_ports",

    # DNS解析
    "DNSRecordType",
    "DNSRecord",
    "DNSResult",
    "DNSResolver",
    "resolve_domain",
    "async_resolve_domain",
    "get_dns_records",

    # 子域名枚举
    "SubdomainInfo",
    "SubdomainEnumerator",
    "enumerate_subdomains",
    "async_enumerate_subdomains",

    # 目录扫描
    "DirectoryInfo",
    "DirectoryScanner",
    "scan_directories",
    "async_scan_directories",

    # 技术栈识别
    "Technology",
    "TechDetector",
    "detect_technologies",

    # WAF检测
    "WAFInfo",
    "WAFDetector",
    "detect_waf",
    "is_waf_protected",
]


def create_engine(
    target: str,
    engine_type: str = "standard",
    **kwargs
) -> BaseReconEngine:
    """工厂函数 - 创建侦察引擎实例

    Args:
        target: 目标URL或域名
        engine_type: 引擎类型 ("standard")
        **kwargs: 引擎配置参数

    Returns:
        BaseReconEngine 实例

    Example:
        # 创建标准引擎
        engine = create_engine("https://example.com")

        # 使用快速模式
        engine = create_engine("https://example.com", quick_mode=True)

        # 自定义配置
        engine = create_engine(
            "https://example.com",
            timeout=60,
            enable_subdomain=True,
            max_threads=20
        )
    """
    engines = {
        "standard": StandardReconEngine,
    }

    engine_class = engines.get(engine_type.lower())
    if not engine_class:
        raise ValueError(f"未知引擎类型: {engine_type}，可选: {list(engines.keys())}")

    # 创建配置对象
    if kwargs:
        config = ReconConfig.from_dict(kwargs)
    else:
        config = None

    return engine_class(target, config)


# 版本信息
__version__ = "2.0.0"
__author__ = "AutoRedTeam"
