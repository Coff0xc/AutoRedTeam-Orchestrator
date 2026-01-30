#!/usr/bin/env python3
"""
Payload 统一模块 - 整合的 Payload 生成、选择、变异引擎

本模块整合了原先分散在多个文件中的 Payload 相关功能：
- smart_payload_engine.py
- smart_payload_selector.py
- adaptive_payload_engine.py

提供统一、无重复的 Payload 管理接口。

主要组件:
- AdaptivePayloadEngine: 自适应 Payload 引擎（主入口）
- SmartPayloadSelector: 智能 Payload 选择器
- PayloadMutator: Payload 变异器
- TargetProfile: 目标特征分析

使用示例:
    from modules.payload import (
        get_payload_engine,
        smart_select_payloads,
        mutate_payload,
        TargetProfile,
    )

    # 1. 智能选择 Payload
    payloads = smart_select_payloads("sqli", waf="cloudflare", top_n=10)

    # 2. 变异 Payload
    variants = mutate_payload("' OR '1'='1", waf="modsecurity")

    # 3. 基于目标特征选择
    target = TargetProfile(
        url="https://example.com",
        headers={"Server": "nginx"},
    )
    engine = get_payload_engine()
    scored = engine.get_payloads_for_target(target, "sqli")
"""

# 类型定义
from .types import (
    VulnType,
    PayloadCategory,
    PayloadStats,
    PayloadResult,
    ScoredPayload,
    get_payload_hash,
    get_payload_key,
)

# 特征检测
from .signatures import (
    TargetProfile,
    WAF_SIGNATURES,
    DB_SIGNATURES,
    FRAMEWORK_SIGNATURES,
    LANGUAGE_INDICATORS,
    SERVER_SIGNATURES,
    WAF_BYPASS_STRATEGIES,
    detect_waf_from_dict,
    detect_db_from_dict,
    detect_framework_from_dict,
)

# 变异器
from .mutator import (
    PayloadMutator,
    MutationType,
    MUTATION_DESCRIPTIONS,
    WAF_MUTATION_STRATEGIES,
    mutate_payload,
    mutate_for_waf,
    get_waf_bypass_variants,
)

# 选择器
from .selector import (
    SmartPayloadSelector,
    get_selector,
    smart_select,
)

# 主引擎
from .engine import (
    AdaptivePayloadEngine,
    get_payload_engine,
    smart_select_payloads,
    get_waf_bypass_payloads,
    record_payload_result,
)


__all__ = [
    # 类型
    "VulnType",
    "PayloadCategory",
    "PayloadStats",
    "PayloadResult",
    "ScoredPayload",
    "get_payload_hash",
    "get_payload_key",
    # 特征检测
    "TargetProfile",
    "WAF_SIGNATURES",
    "DB_SIGNATURES",
    "FRAMEWORK_SIGNATURES",
    "LANGUAGE_INDICATORS",
    "SERVER_SIGNATURES",
    "WAF_BYPASS_STRATEGIES",
    "detect_waf_from_dict",
    "detect_db_from_dict",
    "detect_framework_from_dict",
    # 变异器
    "PayloadMutator",
    "MutationType",
    "MUTATION_DESCRIPTIONS",
    "WAF_MUTATION_STRATEGIES",
    "mutate_payload",
    "mutate_for_waf",
    "get_waf_bypass_variants",
    # 选择器
    "SmartPayloadSelector",
    "get_selector",
    "smart_select",
    # 主引擎
    "AdaptivePayloadEngine",
    "get_payload_engine",
    "smart_select_payloads",
    "get_waf_bypass_payloads",
    "record_payload_result",
]

__version__ = "2.0.0"
