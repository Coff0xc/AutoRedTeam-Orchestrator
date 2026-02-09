#!/usr/bin/env python3
"""
服务容器与依赖注入框架

提供轻量级的依赖注入支持，用于解耦核心模块

设计原则：
- 零外部依赖，纯 Python 实现
- 支持单例和工厂模式
- 支持接口（协议）绑定
- 线程安全

Usage:
    from core.container import Container, injectable

    container = Container()

    # 注册服务
    container.register(HTTPClient, AsyncHTTPClient)
    container.register_singleton(KnowledgeManager)
    container.register_factory(SessionManager, lambda c: SessionManager(c.resolve(KnowledgeManager)))

    # 解析服务
    http = container.resolve(HTTPClient)
    km = container.resolve(KnowledgeManager)

    # 使用装饰器
    @injectable
    class MyService:
        def __init__(self, http: HTTPClient, km: KnowledgeManager):
            self.http = http
            self.km = km
"""

import inspect
import logging
import threading
from abc import ABC, abstractmethod
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    Optional,
    Type,
    TypeVar,
    Union,
    get_type_hints,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


class Lifetime(Enum):
    """服务生命周期"""

    TRANSIENT = "transient"  # 每次请求创建新实例
    SINGLETON = "singleton"  # 单例，整个应用生命周期
    SCOPED = "scoped"  # 范围内单例（如每次请求）


class ServiceDescriptor:
    """服务描述符"""

    def __init__(
        self,
        service_type: Type,
        implementation: Union[Type, Callable, Any],
        lifetime: Lifetime,
        instance: Any = None,
    ):
        self.service_type = service_type
        self.implementation = implementation
        self.lifetime = lifetime
        self.instance = instance  # 用于单例

    def __repr__(self):
        return (
            f"ServiceDescriptor({self.service_type.__name__}, "
            f"{self.implementation}, {self.lifetime.value})"
        )


class ServiceNotFoundError(Exception):
    """服务未注册异常"""

    def __init__(self, service_type: Type):
        self.service_type = service_type
        super().__init__(f"Service not registered: {service_type.__name__}")


class CircularDependencyError(Exception):
    """循环依赖异常"""

    def __init__(self, chain: list):
        self.chain = chain
        chain_str = " -> ".join(t.__name__ for t in chain)
        super().__init__(f"Circular dependency detected: {chain_str}")


class Container:
    """依赖注入容器

    Args:
        parent: 父容器（用于范围容器）
    """

    def __init__(self, parent: Optional["Container"] = None):
        self._services: Dict[Type, ServiceDescriptor] = {}
        self._parent = parent
        self._lock = threading.RLock()
        self._resolving: list = []  # 用于检测循环依赖（使用有序列表）

    def register(
        self,
        service_type: Type[T],
        implementation: Optional[Union[Type[T], Callable[["Container"], T]]] = None,
        lifetime: Lifetime = Lifetime.TRANSIENT,
    ) -> "Container":
        """注册服务

        Args:
            service_type: 服务类型（接口或类）
            implementation: 实现类型或工厂函数，None 表示自注册
            lifetime: 生命周期

        Returns:
            self（支持链式调用）
        """
        if implementation is None:
            implementation = service_type

        with self._lock:
            self._services[service_type] = ServiceDescriptor(
                service_type=service_type,
                implementation=implementation,
                lifetime=lifetime,
            )
            logger.debug(
                f"注册服务: {service_type.__name__} -> {implementation}, "
                f"lifetime={lifetime.value}"
            )

        return self

    def register_singleton(
        self,
        service_type: Type[T],
        implementation: Optional[Union[Type[T], Callable[["Container"], T]]] = None,
    ) -> "Container":
        """注册单例服务"""
        return self.register(service_type, implementation, Lifetime.SINGLETON)

    def register_transient(
        self,
        service_type: Type[T],
        implementation: Optional[Union[Type[T], Callable[["Container"], T]]] = None,
    ) -> "Container":
        """注册瞬态服务"""
        return self.register(service_type, implementation, Lifetime.TRANSIENT)

    def register_scoped(
        self,
        service_type: Type[T],
        implementation: Optional[Union[Type[T], Callable[["Container"], T]]] = None,
    ) -> "Container":
        """注册范围服务"""
        return self.register(service_type, implementation, Lifetime.SCOPED)

    def register_instance(
        self,
        service_type: Type[T],
        instance: T,
    ) -> "Container":
        """注册已有实例（作为单例）

        Args:
            service_type: 服务类型
            instance: 实例
        """
        with self._lock:
            self._services[service_type] = ServiceDescriptor(
                service_type=service_type,
                implementation=type(instance),
                lifetime=Lifetime.SINGLETON,
                instance=instance,
            )
        return self

    def register_factory(
        self,
        service_type: Type[T],
        factory: Callable[["Container"], T],
        lifetime: Lifetime = Lifetime.TRANSIENT,
    ) -> "Container":
        """注册工厂函数

        Args:
            service_type: 服务类型
            factory: 工厂函数，接收容器返回实例
            lifetime: 生命周期
        """
        return self.register(service_type, factory, lifetime)

    def resolve(self, service_type: Type[T]) -> T:
        """解析服务

        Args:
            service_type: 服务类型

        Returns:
            服务实例

        Raises:
            ServiceNotFoundError: 服务未注册
            CircularDependencyError: 检测到循环依赖
        """
        with self._lock:
            return self._resolve_internal(service_type)

    def _resolve_internal(self, service_type: Type[T]) -> T:
        """内部解析逻辑"""
        # 检测循环依赖
        if service_type in self._resolving:
            chain = list(self._resolving) + [service_type]
            raise CircularDependencyError(chain)

        # 查找服务描述符
        descriptor = self._services.get(service_type)
        if descriptor is None and self._parent:
            return self._parent.resolve(service_type)
        if descriptor is None:
            raise ServiceNotFoundError(service_type)

        # 单例已有实例
        if descriptor.lifetime == Lifetime.SINGLETON and descriptor.instance is not None:
            return descriptor.instance

        # 创建实例
        self._resolving.append(service_type)
        try:
            instance = self._create_instance(descriptor)
        finally:
            if service_type in self._resolving:
                self._resolving.remove(service_type)

        # 缓存单例
        if descriptor.lifetime == Lifetime.SINGLETON:
            descriptor.instance = instance

        return instance

    def _create_instance(self, descriptor: ServiceDescriptor) -> Any:
        """创建服务实例"""
        impl = descriptor.implementation

        # 如果是工厂函数
        if callable(impl) and not isinstance(impl, type):
            return impl(self)

        # 如果是类，尝试自动注入依赖
        if isinstance(impl, type):
            return self._construct_with_injection(impl)

        raise ValueError(f"无法创建实例: {impl}")

    def _construct_with_injection(self, cls: Type) -> Any:
        """通过构造函数注入创建实例"""
        # 获取 __init__ 的类型提示
        try:
            hints = get_type_hints(cls.__init__)
        except Exception as e:
            logger.warning("获取类型提示失败 (%s): %s", cls.__name__, e)
            hints = {}

        # 获取 __init__ 参数
        sig = inspect.signature(cls.__init__)
        params = list(sig.parameters.values())[1:]  # 跳过 self

        args = []
        kwargs = {}

        for param in params:
            param_type = hints.get(param.name)

            # 有类型注解且已注册
            if param_type and self.is_registered(param_type):
                value = self._resolve_internal(param_type)
            elif param.default is not inspect.Parameter.empty:
                # 有默认值
                value = param.default
            elif param_type is None:
                # 无类型注解且无默认值，跳过
                logger.warning("参数 %s 无类型注解且无默认值，跳过注入", param.name)
                continue
            else:
                # 未注册的依赖
                raise ServiceNotFoundError(param_type)

            if param.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            ):
                args.append(value)
            else:
                kwargs[param.name] = value

        return cls(*args, **kwargs)

    def is_registered(self, service_type: Type) -> bool:
        """检查服务是否已注册"""
        if service_type in self._services:
            return True
        if self._parent:
            return self._parent.is_registered(service_type)
        return False

    def create_scope(self) -> "ScopedContainer":
        """创建范围容器"""
        return ScopedContainer(parent=self)

    def clear(self):
        """清空所有注册"""
        with self._lock:
            self._services.clear()
            self._resolving.clear()

    @property
    def registered_services(self) -> list:
        """获取已注册的服务类型列表"""
        return list(self._services.keys())


class ScopedContainer(Container):
    """范围容器

    用于在特定范围（如 HTTP 请求）内管理服务生命周期
    """

    def __init__(self, parent: Container):
        super().__init__(parent=parent)
        self._scoped_instances: Dict[Type, Any] = {}

    def _resolve_internal(self, service_type: Type[T]) -> T:
        """解析服务，支持范围单例"""
        # 检测循环依赖
        if service_type in self._resolving:
            chain = list(self._resolving) + [service_type]
            raise CircularDependencyError(chain)

        # 先检查父容器的描述符
        descriptor = self._services.get(service_type)
        if descriptor is None and self._parent:
            descriptor = self._parent._services.get(service_type)

        if descriptor is None:
            raise ServiceNotFoundError(service_type)

        # 范围单例
        if descriptor.lifetime == Lifetime.SCOPED:
            if service_type in self._scoped_instances:
                return self._scoped_instances[service_type]

            self._resolving.append(service_type)
            try:
                instance = self._create_instance(descriptor)
            finally:
                if service_type in self._resolving:
                    self._resolving.remove(service_type)
            self._scoped_instances[service_type] = instance
            return instance

        # 其他情况委托给父类
        return super()._resolve_internal(service_type)

    def dispose(self):
        """释放范围内的资源"""
        for instance in self._scoped_instances.values():
            if hasattr(instance, "dispose"):
                try:
                    instance.dispose()
                except Exception as e:
                    logger.warning("释放资源失败: %s", e)
            elif hasattr(instance, "close"):
                try:
                    instance.close()
                except Exception as e:
                    logger.warning("关闭资源失败: %s", e)

        self._scoped_instances.clear()


# 全局默认容器
_default_container: Optional[Container] = None
_container_lock = threading.Lock()


def get_container() -> Container:
    """获取默认容器"""
    global _default_container
    if _default_container is not None:
        return _default_container
    with _container_lock:
        if _default_container is None:
            _default_container = Container()
        return _default_container


def set_container(container: Container):
    """设置默认容器"""
    global _default_container
    with _container_lock:
        _default_container = container


def injectable(cls: Type[T]) -> Type[T]:
    """装饰器：标记类为可注入

    自动将类注册到默认容器

    Usage:
        @injectable
        class MyService:
            def __init__(self, dep: SomeDependency):
                pass
    """
    container = get_container()
    if not container.is_registered(cls):
        container.register(cls)
    return cls


def inject(service_type: Type[T]) -> T:
    """从默认容器解析服务

    Usage:
        http_client = inject(HTTPClient)
    """
    return get_container().resolve(service_type)


# ==================== 服务基类和协议 ====================


class Service(ABC):
    """服务基类

    所有服务可以继承此类以获得统一的生命周期管理
    """

    @abstractmethod
    def initialize(self):
        """初始化服务"""
        pass

    def dispose(self):
        """释放资源"""
        pass


class ServiceProvider(ABC):
    """服务提供者接口

    用于模块化注册服务
    """

    @abstractmethod
    def register_services(self, container: Container):
        """注册服务到容器

        Args:
            container: 目标容器
        """
        pass


def configure_services(
    container: Container,
    providers: list,
):
    """配置服务

    Args:
        container: 目标容器
        providers: ServiceProvider 列表或配置函数列表
    """
    for provider in providers:
        if isinstance(provider, ServiceProvider):
            provider.register_services(container)
        elif callable(provider):
            provider(container)
        else:
            raise TypeError(f"无效的服务提供者: {provider}")


# ==================== 辅助装饰器 ====================


def singleton(cls: Type[T]) -> Type[T]:
    """装饰器：标记类为单例

    Usage:
        @singleton
        class ConfigManager:
            pass
    """
    container = get_container()
    container.register_singleton(cls)
    return cls


def scoped(cls: Type[T]) -> Type[T]:
    """装饰器：标记类为范围单例

    Usage:
        @scoped
        class RequestContext:
            pass
    """
    container = get_container()
    container.register_scoped(cls)
    return cls
