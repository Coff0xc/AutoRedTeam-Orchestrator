#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE情报管理模块
包含: CVE更新管理器 + PoC引擎 + 订阅管理器
"""

from .update_manager import (
    CVEUpdateManager,
    CVEEntry,
    Severity
)

from .poc_engine import (
    PoCEngine,
    PoCTemplate,
    PoCResult,
    PoCInfo,
    SeverityLevel,
    MatcherType,
    ExtractorType,
    MatcherCondition,
    load_poc,
    execute_poc,
    execute_poc_batch
)

from .subscription_manager import (
    SubscriptionManager,
    Subscription,
    FilterType,
    NotifyMethod,
    SubscriptionMatch
)

__all__ = [
    # CVE更新管理器
    "CVEUpdateManager",
    "CVEEntry",
    "Severity",

    # PoC引擎
    "PoCEngine",
    "PoCTemplate",
    "PoCResult",
    "PoCInfo",
    "SeverityLevel",
    "MatcherType",
    "ExtractorType",
    "MatcherCondition",
    "load_poc",
    "execute_poc",
    "execute_poc_batch",

    # 订阅管理器
    "SubscriptionManager",
    "Subscription",
    "FilterType",
    "NotifyMethod",
    "SubscriptionMatch",
]

__version__ = "2.5.0"
