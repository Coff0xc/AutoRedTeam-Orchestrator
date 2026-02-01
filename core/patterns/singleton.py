#!/usr/bin/env python3
"""
core/patterns/singleton.py - 统一单例模式实现

提供两种单例实现方式：
1. SingletonMeta - 元类方式，适用于需要继承的类
2. singleton - 装饰器方式，适用于简单类

使用示例:

    # 方式1: 元类
    class MyManager(metaclass=SingletonMeta):
        def __init__(self, config=None):
            self.config = config

    # 方式2: 装饰器
    @singleton
    class MyService:
        pass

线程安全：两种实现都是线程安全的。

测试注意：
    测试时需要重置单例状态，使用 SingletonMeta.reset(ClassName) 或
    ClassName._instance = None (对于装饰器方式)
"""

import threading
from typing import Any, Dict, Type, TypeVar

T = TypeVar("T")


class SingletonMeta(type):
    """
    线程安全的单例元类

    使用方式:
        class MyClass(metaclass=SingletonMeta):
            pass

    重置单例 (仅用于测试):
        SingletonMeta.reset(MyClass)
    """

    _instances: Dict[Type, Any] = {}
    _lock: threading.Lock = threading.Lock()

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            with cls._lock:
                # 双重检查锁定
                if cls not in cls._instances:
                    instance = super().__call__(*args, **kwargs)
                    cls._instances[cls] = instance
        return cls._instances[cls]

    @classmethod
    def reset(mcs, cls: Type) -> None:
        """
        重置指定类的单例实例 (仅用于测试)

        Args:
            cls: 要重置的类
        """
        with mcs._lock:
            if cls in mcs._instances:
                del mcs._instances[cls]


def singleton(cls: Type[T]) -> Type[T]:
    """
    单例装饰器

    使用方式:
        @singleton
        class MyClass:
            pass

    重置单例 (仅用于测试):
        MyClass._instance = None
    """
    cls._instance = None
    cls._lock = threading.Lock()
    original_new = cls.__new__

    def new_singleton(klass, *args, **kwargs):
        if klass._instance is None:
            with klass._lock:
                if klass._instance is None:
                    if original_new is object.__new__:
                        klass._instance = original_new(klass)
                    else:
                        klass._instance = original_new(klass, *args, **kwargs)
        return klass._instance

    cls.__new__ = new_singleton
    return cls
