#!/usr/bin/env python3
"""
core/patterns/ - 设计模式模块

提供统一的设计模式实现，避免在项目中重复实现。
"""

from .singleton import SingletonMeta, singleton

__all__ = ["SingletonMeta", "singleton"]
