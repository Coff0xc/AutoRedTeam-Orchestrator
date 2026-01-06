#!/usr/bin/env python3
"""
隐蔽性模块 - Stealth Module
提供流量伪装、代理轮换、指纹伪装等功能
用于真实攻防对抗场景
"""

from .traffic_mutator import TrafficMutator, RequestHumanizer, MutationConfig
from .proxy_pool import ProxyPool, ProxyValidator, Proxy, ProxyChain as LegacyProxyChain
from .proxy_chain import (
    ProxyChain,
    ProxyChainManager,
    ChainStrategy,
    LoadBalanceMode,
    ChainMetrics,
    create_chain_from_list,
    create_chain_from_pool,
)
from .fingerprint_spoofer import (
    TLSFingerprint,
    JA3Spoofer,
    BrowserProfile,
    FingerprintSpoofer,
    BrowserType,
    BrowserProfileFactory,
)

__all__ = [
    # Traffic Mutation
    'TrafficMutator',
    'RequestHumanizer',
    'MutationConfig',

    # Proxy Pool (Legacy)
    'ProxyPool',
    'ProxyValidator',
    'Proxy',
    'LegacyProxyChain',

    # Proxy Chain (Enhanced)
    'ProxyChain',
    'ProxyChainManager',
    'ChainStrategy',
    'LoadBalanceMode',
    'ChainMetrics',
    'create_chain_from_list',
    'create_chain_from_pool',

    # Fingerprint Spoofing
    'TLSFingerprint',
    'JA3Spoofer',
    'BrowserProfile',
    'FingerprintSpoofer',
    'BrowserType',
    'BrowserProfileFactory',
]
