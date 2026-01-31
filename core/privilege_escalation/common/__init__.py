#!/usr/bin/env python3
"""
权限提升通用模块 - Common Module for Privilege Escalation
"""

from .enumeration import (
    EnumerationResult,
    PrivilegeEnumerator,
    SystemInfo,
)

__all__ = [
    "PrivilegeEnumerator",
    "EnumerationResult",
    "SystemInfo",
]
