#!/usr/bin/env python3
"""
AutoRedTeam Recon 引擎模块

统一的侦察引擎接口，替代原有分散的多个实现。

使用方式:
    from core.recon import StandardReconEngine

    engine = StandardReconEngine("https://example.com")
    result = engine.run()
    print(result.to_dict())

引擎类型:
    - StandardReconEngine: 标准侦察引擎，10阶段完整侦察
    - IntelligentReconEngine: 智能侦察引擎 (保留原有实现，待后续整合)
"""

from .base import (
    BaseReconEngine,
    ReconPhase,
    ReconResult,
    Asset,
    Finding,
    Severity
)
from .standard import StandardReconEngine


__all__ = [
    # 基类和数据类
    'BaseReconEngine',
    'ReconPhase',
    'ReconResult',
    'Asset',
    'Finding',
    'Severity',
    # 引擎实现
    'StandardReconEngine',
]


def create_engine(target: str, engine_type: str = "standard", **kwargs) -> BaseReconEngine:
    """工厂函数 - 创建侦察引擎实例

    Args:
        target: 目标URL或域名
        engine_type: 引擎类型 ("standard" | "intelligent")
        **kwargs: 引擎配置参数

    Returns:
        BaseReconEngine 实例
    """
    engines = {
        "standard": StandardReconEngine,
    }

    engine_class = engines.get(engine_type.lower())
    if not engine_class:
        raise ValueError(f"未知引擎类型: {engine_type}，可选: {list(engines.keys())}")

    return engine_class(target, **kwargs)
