"""
web_scanner 模块 - Web 扫描核心引擎

提供攻面发现、注入点建模、扫描编排等能力。
"""

from .injection_point import (
    InjectionPoint,
    InjectionPointType,
    InjectionPointSource,
    InjectionPointCollection,
)
from .attack_surface import (
    AttackSurfaceDiscovery,
    DiscoveryResult,
)

__all__ = [
    # 注入点模型
    "InjectionPoint",
    "InjectionPointType",
    "InjectionPointSource",
    "InjectionPointCollection",
    # 攻面发现
    "AttackSurfaceDiscovery",
    "DiscoveryResult",
]
