#!/usr/bin/env python3
"""
依赖注入容器测试

测试 core/container.py 的所有核心功能
"""

import pytest
from abc import ABC, abstractmethod
from typing import Optional

from core.container import (
    CircularDependencyError,
    Container,
    Lifetime,
    ScopedContainer,
    Service,
    ServiceDescriptor,
    ServiceNotFoundError,
    ServiceProvider,
    configure_services,
    get_container,
    inject,
    injectable,
    scoped,
    set_container,
    singleton,
)


# ==================== 测试用类 ====================


class ILogger(ABC):
    """日志接口"""

    @abstractmethod
    def log(self, msg: str):
        pass


class ConsoleLogger(ILogger):
    """控制台日志实现"""

    def log(self, msg: str):
        print(msg)


class FileLogger(ILogger):
    """文件日志实现"""

    def __init__(self, path: str = "/tmp/log.txt"):
        self.path = path

    def log(self, msg: str):
        pass  # 模拟写文件


class IDatabase(ABC):
    """数据库接口"""

    @abstractmethod
    def query(self, sql: str):
        pass


class MockDatabase(IDatabase):
    """模拟数据库"""

    def query(self, sql: str):
        return []


class UserService:
    """用户服务 - 依赖注入示例"""

    def __init__(self, logger: ILogger, db: IDatabase):
        self.logger = logger
        self.db = db

    def get_user(self, user_id: int):
        self.logger.log(f"Getting user {user_id}")
        return {"id": user_id, "name": "Test"}


class ConfigManager:
    """配置管理器 - 无依赖"""

    def __init__(self):
        self.settings = {"debug": True}

    def get(self, key: str):
        return self.settings.get(key)


class CircularA:
    """循环依赖测试类 A"""

    def __init__(self, b: "CircularB"):
        self.b = b


class CircularB:
    """循环依赖测试类 B"""

    def __init__(self, a: CircularA):
        self.a = a


class ServiceWithDefault:
    """有默认参数的服务"""

    def __init__(self, logger: ILogger, timeout: int = 30):
        self.logger = logger
        self.timeout = timeout


class DisposableService:
    """可释放的服务"""

    def __init__(self):
        self.disposed = False

    def dispose(self):
        self.disposed = True


class CloseableService:
    """可关闭的服务"""

    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


# ==================== ServiceDescriptor 测试 ====================


class TestServiceDescriptor:
    """ServiceDescriptor 测试"""

    def test_creation(self):
        desc = ServiceDescriptor(
            service_type=ILogger,
            implementation=ConsoleLogger,
            lifetime=Lifetime.SINGLETON,
        )
        assert desc.service_type == ILogger
        assert desc.implementation == ConsoleLogger
        assert desc.lifetime == Lifetime.SINGLETON
        assert desc.instance is None

    def test_repr(self):
        desc = ServiceDescriptor(ILogger, ConsoleLogger, Lifetime.TRANSIENT)
        s = repr(desc)
        assert "ILogger" in s
        assert "transient" in s.lower()


# ==================== Container 基础测试 ====================


class TestContainerBasic:
    """Container 基础功能测试"""

    @pytest.fixture
    def container(self):
        return Container()

    def test_register_and_resolve(self, container):
        container.register(ILogger, ConsoleLogger)
        logger = container.resolve(ILogger)
        assert isinstance(logger, ConsoleLogger)

    def test_register_self(self, container):
        """自注册（类型=实现）"""
        container.register(ConfigManager)
        config = container.resolve(ConfigManager)
        assert isinstance(config, ConfigManager)

    def test_register_chain(self, container):
        """链式注册"""
        container.register(ILogger, ConsoleLogger).register(IDatabase, MockDatabase)

        assert container.is_registered(ILogger)
        assert container.is_registered(IDatabase)

    def test_resolve_not_registered(self, container):
        """解析未注册的服务"""
        with pytest.raises(ServiceNotFoundError) as exc_info:
            container.resolve(ILogger)
        assert exc_info.value.service_type == ILogger

    def test_is_registered(self, container):
        assert not container.is_registered(ILogger)
        container.register(ILogger, ConsoleLogger)
        assert container.is_registered(ILogger)

    def test_registered_services(self, container):
        container.register(ILogger, ConsoleLogger)
        container.register(IDatabase, MockDatabase)
        services = container.registered_services
        assert ILogger in services
        assert IDatabase in services

    def test_clear(self, container):
        container.register(ILogger, ConsoleLogger)
        container.clear()
        assert not container.is_registered(ILogger)


# ==================== 生命周期测试 ====================


class TestLifetime:
    """服务生命周期测试"""

    def test_transient_creates_new_instance(self):
        container = Container()
        container.register_transient(ConfigManager)

        c1 = container.resolve(ConfigManager)
        c2 = container.resolve(ConfigManager)
        assert c1 is not c2

    def test_singleton_same_instance(self):
        container = Container()
        container.register_singleton(ConfigManager)

        c1 = container.resolve(ConfigManager)
        c2 = container.resolve(ConfigManager)
        assert c1 is c2

    def test_register_instance(self):
        container = Container()
        instance = ConfigManager()
        instance.settings["custom"] = True

        container.register_instance(ConfigManager, instance)

        resolved = container.resolve(ConfigManager)
        assert resolved is instance
        assert resolved.settings["custom"] is True

    def test_scoped_in_scope(self):
        container = Container()
        container.register_scoped(ConfigManager)

        scope = container.create_scope()
        c1 = scope.resolve(ConfigManager)
        c2 = scope.resolve(ConfigManager)
        assert c1 is c2

    def test_scoped_different_scopes(self):
        container = Container()
        container.register_scoped(ConfigManager)

        scope1 = container.create_scope()
        scope2 = container.create_scope()

        c1 = scope1.resolve(ConfigManager)
        c2 = scope2.resolve(ConfigManager)
        assert c1 is not c2


# ==================== 依赖注入测试 ====================


class TestDependencyInjection:
    """自动依赖注入测试"""

    @pytest.fixture
    def container(self):
        c = Container()
        c.register(ILogger, ConsoleLogger)
        c.register(IDatabase, MockDatabase)
        return c

    def test_constructor_injection(self, container):
        container.register(UserService)
        service = container.resolve(UserService)

        assert isinstance(service, UserService)
        assert isinstance(service.logger, ConsoleLogger)
        assert isinstance(service.db, MockDatabase)

    def test_nested_injection(self, container):
        """嵌套依赖注入"""
        class OuterService:
            def __init__(self, user_service: UserService):
                self.user_service = user_service

        container.register(UserService)
        container.register(OuterService)

        outer = container.resolve(OuterService)
        assert isinstance(outer.user_service, UserService)
        assert isinstance(outer.user_service.logger, ConsoleLogger)

    def test_injection_with_default_params(self, container):
        """带默认参数的注入"""
        container.register(ServiceWithDefault)
        service = container.resolve(ServiceWithDefault)

        assert isinstance(service.logger, ConsoleLogger)
        assert service.timeout == 30

    def test_missing_dependency(self):
        """缺少依赖"""
        container = Container()
        container.register(UserService)

        with pytest.raises(ServiceNotFoundError):
            container.resolve(UserService)


# ==================== 循环依赖测试 ====================


class TestCircularDependency:
    """循环依赖检测测试"""

    def test_detect_circular(self):
        container = Container()
        container.register(CircularA)
        container.register(CircularB)

        with pytest.raises(CircularDependencyError) as exc_info:
            container.resolve(CircularA)

        assert len(exc_info.value.chain) >= 2


# ==================== 工厂函数测试 ====================


class TestFactory:
    """工厂函数测试"""

    def test_factory_function(self):
        container = Container()
        container.register(ILogger, ConsoleLogger)

        def user_service_factory(c: Container):
            return UserService(
                logger=c.resolve(ILogger),
                db=MockDatabase(),
            )

        container.register_factory(UserService, user_service_factory)

        service = container.resolve(UserService)
        assert isinstance(service, UserService)
        assert isinstance(service.logger, ConsoleLogger)

    def test_factory_with_singleton(self):
        container = Container()
        call_count = [0]

        def factory(c: Container):
            call_count[0] += 1
            return ConfigManager()

        container.register_factory(ConfigManager, factory, Lifetime.SINGLETON)

        container.resolve(ConfigManager)
        container.resolve(ConfigManager)
        assert call_count[0] == 1  # 只调用一次


# ==================== 父子容器测试 ====================


class TestParentChildContainer:
    """父子容器测试"""

    def test_child_inherits_parent(self):
        parent = Container()
        parent.register(ILogger, ConsoleLogger)

        child = Container(parent=parent)
        logger = child.resolve(ILogger)
        assert isinstance(logger, ConsoleLogger)

    def test_child_overrides_parent(self):
        parent = Container()
        parent.register(ILogger, ConsoleLogger)

        child = Container(parent=parent)
        child.register(ILogger, FileLogger)

        logger = child.resolve(ILogger)
        assert isinstance(logger, FileLogger)

    def test_is_registered_checks_parent(self):
        parent = Container()
        parent.register(ILogger, ConsoleLogger)

        child = Container(parent=parent)
        assert child.is_registered(ILogger)


# ==================== ScopedContainer 测试 ====================


class TestScopedContainer:
    """ScopedContainer 测试"""

    def test_dispose_calls_dispose(self):
        container = Container()
        container.register_scoped(DisposableService)

        scope = container.create_scope()
        service = scope.resolve(DisposableService)
        assert not service.disposed

        scope.dispose()
        assert service.disposed

    def test_dispose_calls_close(self):
        container = Container()
        container.register_scoped(CloseableService)

        scope = container.create_scope()
        service = scope.resolve(CloseableService)
        assert not service.closed

        scope.dispose()
        assert service.closed


# ==================== 全局容器和装饰器测试 ====================


class TestGlobalContainerAndDecorators:
    """全局容器和装饰器测试"""

    def setup_method(self):
        """每个测试前重置全局容器"""
        set_container(Container())

    def test_get_container(self):
        c = get_container()
        assert isinstance(c, Container)

    def test_set_container(self):
        custom = Container()
        custom.register(ILogger, FileLogger)

        set_container(custom)
        assert get_container() is custom

    def test_injectable_decorator(self):
        @injectable
        class MyService:
            pass

        c = get_container()
        assert c.is_registered(MyService)

    def test_inject_function(self):
        c = get_container()
        c.register(ConfigManager)

        config = inject(ConfigManager)
        assert isinstance(config, ConfigManager)

    def test_singleton_decorator(self):
        @singleton
        class SingletonService:
            pass

        c = get_container()
        s1 = c.resolve(SingletonService)
        s2 = c.resolve(SingletonService)
        assert s1 is s2

    def test_scoped_decorator(self):
        @scoped
        class ScopedService:
            pass

        c = get_container()
        scope = c.create_scope()
        s1 = scope.resolve(ScopedService)
        s2 = scope.resolve(ScopedService)
        assert s1 is s2


# ==================== ServiceProvider 测试 ====================


class TestServiceProvider:
    """ServiceProvider 测试"""

    def test_configure_with_provider(self):
        class MyProvider(ServiceProvider):
            def register_services(self, container: Container):
                container.register(ILogger, ConsoleLogger)
                container.register(IDatabase, MockDatabase)

        container = Container()
        configure_services(container, [MyProvider()])

        assert container.is_registered(ILogger)
        assert container.is_registered(IDatabase)

    def test_configure_with_function(self):
        def setup(c: Container):
            c.register(ConfigManager)

        container = Container()
        configure_services(container, [setup])

        assert container.is_registered(ConfigManager)

    def test_configure_invalid_provider(self):
        container = Container()
        with pytest.raises(TypeError):
            configure_services(container, ["invalid"])


# ==================== 线程安全测试 ====================


class TestThreadSafety:
    """线程安全测试"""

    def test_concurrent_singleton_resolve(self):
        import threading

        container = Container()
        container.register_singleton(ConfigManager)

        results = []
        errors = []

        def resolve():
            try:
                instance = container.resolve(ConfigManager)
                results.append(instance)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=resolve) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 10
        # 所有结果应该是同一个实例
        assert all(r is results[0] for r in results)


# ==================== 集成测试 ====================


class TestIntegration:
    """集成测试"""

    def test_full_application_setup(self):
        """模拟完整应用程序设置"""
        # 创建容器
        container = Container()

        # 注册基础设施
        container.register_singleton(ConfigManager)
        container.register(ILogger, ConsoleLogger)
        container.register(IDatabase, MockDatabase)

        # 注册业务服务
        container.register(UserService)

        # 解析并使用
        user_service = container.resolve(UserService)
        user = user_service.get_user(1)

        assert user["id"] == 1
        assert isinstance(user_service.logger, ConsoleLogger)

    def test_request_scope_simulation(self):
        """模拟请求范围"""
        # 应用级容器
        app_container = Container()
        app_container.register_singleton(ConfigManager)
        app_container.register(ILogger, ConsoleLogger)

        # 模拟多个请求
        for request_id in range(3):
            # 每个请求创建一个范围
            with_scope = app_container.create_scope()

            # 请求范围内的服务
            with_scope.register(IDatabase, MockDatabase)
            with_scope.register(UserService)

            # 处理请求
            service = with_scope.resolve(UserService)
            user = service.get_user(request_id)
            assert user["id"] == request_id

            # 请求结束，释放资源
            with_scope.dispose()

    def test_service_replacement_for_testing(self):
        """测试时替换服务"""
        # 生产容器
        prod_container = Container()
        prod_container.register(ILogger, ConsoleLogger)
        prod_container.register(IDatabase, MockDatabase)

        # 测试容器（替换部分服务）
        class TestLogger(ILogger):
            messages = []

            def log(self, msg: str):
                self.messages.append(msg)

        test_container = Container(parent=prod_container)
        test_container.register(ILogger, TestLogger)

        # 测试时使用 TestLogger
        logger = test_container.resolve(ILogger)
        assert isinstance(logger, TestLogger)

        # 数据库仍从父容器获取
        db = test_container.resolve(IDatabase)
        assert isinstance(db, MockDatabase)
