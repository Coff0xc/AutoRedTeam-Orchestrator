#!/usr/bin/env python3
"""
核心常量模块

提供项目中共享的常量定义，避免重复定义。

Usage:
    from core.constants import WEAK_SECRETS, KID_INJECTION_PAYLOADS
    from core.constants.security import WEAK_SECRETS
"""

from .security import (
    KID_INJECTION_PAYLOADS,
    NONE_ALGORITHM_VARIANTS,
    WEAK_SECRETS,
)

__all__ = [
    "WEAK_SECRETS",
    "KID_INJECTION_PAYLOADS",
    "NONE_ALGORITHM_VARIANTS",
]
