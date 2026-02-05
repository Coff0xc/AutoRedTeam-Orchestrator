"""
规避控制模块

提供实战级规避检测能力:
- 流量混淆与行为模拟
- User-Agent 智能轮换
- 请求延迟与节流
- 蜜罐/WAF 检测
- 自适应规避策略
- TLS/浏览器指纹伪装
- 代理池管理
"""

from .controller import (
    EvasionTechnique,
    RequestContext,
    StealthController,
    StealthLevel,
    get_stealth_controller,
)

# 指纹伪装
from .fingerprint_spoofer import (
    BrowserProfileFactory,
    BrowserType,
    FingerprintSpoofer,
    TLSFingerprint,
)

# 代理池
from .proxy_pool import (
    ProxyAnonymity,
    ProxyPool,
    ProxyType,
)

# 流量变异
from .traffic_mutator import (
    MutationConfig,
    TrafficMutator,
    UserAgentRotator,
)

__all__ = [
    # 控制器
    "StealthController",
    "StealthLevel",
    "RequestContext",
    "EvasionTechnique",
    "get_stealth_controller",
    # 指纹伪装
    "FingerprintSpoofer",
    "BrowserType",
    "BrowserProfileFactory",
    "TLSFingerprint",
    # 流量变异
    "TrafficMutator",
    "MutationConfig",
    "UserAgentRotator",
    # 代理池
    "ProxyPool",
    "ProxyType",
    "ProxyAnonymity",
]

