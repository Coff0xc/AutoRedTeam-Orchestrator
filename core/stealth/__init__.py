"""
规避控制模块

提供实战级规避检测能力:
- 流量混淆与行为模拟
- User-Agent 智能轮换
- 请求延迟与节流
- 蜜罐/WAF 检测
- 自适应规避策略
"""

from .controller import (
    StealthController,
    StealthLevel,
    RequestContext,
    EvasionTechnique,
    get_stealth_controller,
)

__all__ = [
    'StealthController',
    'StealthLevel',
    'RequestContext',
    'EvasionTechnique',
    'get_stealth_controller',
]
