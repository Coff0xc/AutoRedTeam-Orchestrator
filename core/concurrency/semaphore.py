"""
信号量管理模块

提供同步和异步信号量，用于控制并发访问资源。
"""

import asyncio
import threading
from typing import Optional, Dict, Any
from contextlib import contextmanager, asynccontextmanager
import logging
import time

logger = logging.getLogger(__name__)


class BoundedSemaphore:
    """
    有界信号量 - 控制并发访问

    特性:
    - 不允许 release 超过初始值
    - 支持超时获取
    - 提供统计信息
    """

    def __init__(self, value: int = 10, name: str = 'default'):
        """
        初始化有界信号量

        Args:
            value: 信号量初始值（最大并发数）
            name: 信号量名称
        """
        if value < 1:
            raise ValueError("value 必须大于等于 1")

        self.value = value
        self.name = name
        self._semaphore = threading.BoundedSemaphore(value)
        self._lock = threading.Lock()

        # 统计信息
        self._acquired_count = 0
        self._released_count = 0
        self._wait_count = 0
        self._timeout_count = 0

    def acquire(self, blocking: bool = True, timeout: Optional[float] = None) -> bool:
        """
        获取信号量

        Args:
            blocking: 是否阻塞等待
            timeout: 超时时间（秒）

        Returns:
            是否成功获取
        """
        with self._lock:
            self._wait_count += 1

        try:
            result = self._semaphore.acquire(blocking=blocking, timeout=timeout)

            with self._lock:
                if result:
                    self._acquired_count += 1
                else:
                    self._timeout_count += 1

            return result
        finally:
            pass

    def release(self) -> None:
        """释放信号量"""
        self._semaphore.release()
        with self._lock:
            self._released_count += 1

    def try_acquire(self) -> bool:
        """
        尝试获取信号量（非阻塞）

        Returns:
            是否成功获取
        """
        return self.acquire(blocking=False)

    @contextmanager
    def context(self, timeout: Optional[float] = None):
        """
        信号量上下文管理器

        Args:
            timeout: 超时时间

        Yields:
            None

        Raises:
            TimeoutError: 超时获取失败
        """
        if not self.acquire(blocking=True, timeout=timeout):
            raise TimeoutError(f"获取信号量 '{self.name}' 超时")

        try:
            yield
        finally:
            self.release()

    @property
    def available(self) -> int:
        """
        当前可用数量

        注意：这是一个近似值，可能在返回后立即变化
        """
        # BoundedSemaphore 没有直接获取当前值的方法
        # 这里返回一个估计值
        with self._lock:
            return max(0, self.value - (self._acquired_count - self._released_count))

    @property
    def stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._lock:
            return {
                'name': self.name,
                'max_value': self.value,
                'acquired_count': self._acquired_count,
                'released_count': self._released_count,
                'wait_count': self._wait_count,
                'timeout_count': self._timeout_count,
                'current_held': self._acquired_count - self._released_count
            }

    def __enter__(self) -> 'BoundedSemaphore':
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()


class AsyncSemaphore:
    """
    异步信号量

    用于异步环境中的并发控制
    """

    def __init__(self, value: int = 10, name: str = 'default'):
        """
        初始化异步信号量

        Args:
            value: 信号量初始值
            name: 信号量名称
        """
        if value < 1:
            raise ValueError("value 必须大于等于 1")

        self.value = value
        self.name = name
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._lock = asyncio.Lock()

        # 统计信息
        self._acquired_count = 0
        self._released_count = 0

    def _get_semaphore(self) -> asyncio.Semaphore:
        """获取或创建信号量"""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.value)
        return self._semaphore

    async def acquire(self) -> bool:
        """
        异步获取信号量

        Returns:
            始终返回 True
        """
        semaphore = self._get_semaphore()
        await semaphore.acquire()
        async with self._lock:
            self._acquired_count += 1
        return True

    async def acquire_with_timeout(self, timeout: float) -> bool:
        """
        带超时的异步获取

        Args:
            timeout: 超时时间（秒）

        Returns:
            是否成功获取
        """
        semaphore = self._get_semaphore()

        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=timeout)
            async with self._lock:
                self._acquired_count += 1
            return True
        except asyncio.TimeoutError:
            return False

    def release(self) -> None:
        """释放信号量"""
        if self._semaphore is not None:
            self._semaphore.release()
            # 使用同步方式更新计数（release 通常不在异步上下文中调用）
            self._released_count += 1

    @asynccontextmanager
    async def context(self, timeout: Optional[float] = None):
        """
        异步信号量上下文管理器

        Args:
            timeout: 超时时间

        Yields:
            None

        Raises:
            TimeoutError: 超时获取失败
        """
        if timeout is not None:
            if not await self.acquire_with_timeout(timeout):
                raise TimeoutError(f"获取异步信号量 '{self.name}' 超时")
        else:
            await self.acquire()

        try:
            yield
        finally:
            self.release()

    @property
    def locked(self) -> bool:
        """是否已锁定（无可用信号量）"""
        if self._semaphore is None:
            return False
        return self._semaphore.locked()

    @property
    def stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'name': self.name,
            'max_value': self.value,
            'acquired_count': self._acquired_count,
            'released_count': self._released_count,
            'current_held': self._acquired_count - self._released_count,
            'locked': self.locked
        }

    async def __aenter__(self) -> 'AsyncSemaphore':
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()


class SemaphoreGroup:
    """
    信号量组 - 管理多个命名信号量

    用于为不同资源或服务分配独立的并发限制
    """

    def __init__(self, default_value: int = 10):
        """
        初始化信号量组

        Args:
            default_value: 默认信号量值
        """
        self.default_value = default_value
        self._semaphores: Dict[str, BoundedSemaphore] = {}
        self._lock = threading.Lock()

    def get(
        self,
        name: str,
        value: Optional[int] = None
    ) -> BoundedSemaphore:
        """
        获取或创建命名信号量

        Args:
            name: 信号量名称
            value: 信号量值（仅创建时有效）

        Returns:
            BoundedSemaphore 实例
        """
        with self._lock:
            if name not in self._semaphores:
                actual_value = value if value is not None else self.default_value
                self._semaphores[name] = BoundedSemaphore(
                    value=actual_value,
                    name=name
                )
            return self._semaphores[name]

    def remove(self, name: str) -> bool:
        """
        移除信号量

        Args:
            name: 信号量名称

        Returns:
            是否成功移除
        """
        with self._lock:
            if name in self._semaphores:
                del self._semaphores[name]
                return True
            return False

    def list_names(self) -> list:
        """列出所有信号量名称"""
        with self._lock:
            return list(self._semaphores.keys())

    def get_all_stats(self) -> Dict[str, Any]:
        """获取所有信号量的统计信息"""
        with self._lock:
            return {
                name: sem.stats
                for name, sem in self._semaphores.items()
            }

    @contextmanager
    def acquire(self, name: str, timeout: Optional[float] = None):
        """
        获取命名信号量的上下文管理器

        Args:
            name: 信号量名称
            timeout: 超时时间

        Yields:
            None
        """
        sem = self.get(name)
        with sem.context(timeout=timeout):
            yield


class AsyncSemaphoreGroup:
    """
    异步信号量组 - 管理多个命名异步信号量
    """

    def __init__(self, default_value: int = 10):
        """
        初始化异步信号量组

        Args:
            default_value: 默认信号量值
        """
        self.default_value = default_value
        self._semaphores: Dict[str, AsyncSemaphore] = {}
        self._lock = asyncio.Lock()

    async def get(
        self,
        name: str,
        value: Optional[int] = None
    ) -> AsyncSemaphore:
        """
        获取或创建命名异步信号量

        Args:
            name: 信号量名称
            value: 信号量值（仅创建时有效）

        Returns:
            AsyncSemaphore 实例
        """
        async with self._lock:
            if name not in self._semaphores:
                actual_value = value if value is not None else self.default_value
                self._semaphores[name] = AsyncSemaphore(
                    value=actual_value,
                    name=name
                )
            return self._semaphores[name]

    async def remove(self, name: str) -> bool:
        """
        移除信号量

        Args:
            name: 信号量名称

        Returns:
            是否成功移除
        """
        async with self._lock:
            if name in self._semaphores:
                del self._semaphores[name]
                return True
            return False

    def list_names(self) -> list:
        """列出所有信号量名称"""
        return list(self._semaphores.keys())

    def get_all_stats(self) -> Dict[str, Any]:
        """获取所有信号量的统计信息"""
        return {
            name: sem.stats
            for name, sem in self._semaphores.items()
        }

    @asynccontextmanager
    async def acquire(
        self,
        name: str,
        timeout: Optional[float] = None
    ):
        """
        获取命名信号量的异步上下文管理器

        Args:
            name: 信号量名称
            timeout: 超时时间

        Yields:
            None
        """
        sem = await self.get(name)
        async with sem.context(timeout=timeout):
            yield


class ResourceLimiter:
    """
    资源限制器 - 基于信号量的资源访问控制

    提供更高级的抽象，用于限制对特定资源的并发访问
    """

    def __init__(
        self,
        max_connections: int = 100,
        max_per_host: int = 10,
        max_per_resource: int = 5
    ):
        """
        初始化资源限制器

        Args:
            max_connections: 最大总连接数
            max_per_host: 每个主机的最大连接数
            max_per_resource: 每个资源的最大并发数
        """
        self._global_sem = BoundedSemaphore(max_connections, name='global')
        self._host_group = SemaphoreGroup(default_value=max_per_host)
        self._resource_group = SemaphoreGroup(default_value=max_per_resource)
        self._lock = threading.Lock()

    @contextmanager
    def acquire_for_host(
        self,
        host: str,
        timeout: Optional[float] = None
    ):
        """
        获取对特定主机的访问许可

        Args:
            host: 主机名
            timeout: 超时时间

        Yields:
            None
        """
        # 先获取全局信号量
        with self._global_sem.context(timeout=timeout):
            # 再获取主机信号量
            with self._host_group.acquire(host, timeout=timeout):
                yield

    @contextmanager
    def acquire_for_resource(
        self,
        resource: str,
        host: Optional[str] = None,
        timeout: Optional[float] = None
    ):
        """
        获取对特定资源的访问许可

        Args:
            resource: 资源标识
            host: 主机名（可选）
            timeout: 超时时间

        Yields:
            None
        """
        with self._global_sem.context(timeout=timeout):
            if host:
                with self._host_group.acquire(host, timeout=timeout):
                    with self._resource_group.acquire(resource, timeout=timeout):
                        yield
            else:
                with self._resource_group.acquire(resource, timeout=timeout):
                    yield

    @property
    def stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'global': self._global_sem.stats,
            'hosts': self._host_group.get_all_stats(),
            'resources': self._resource_group.get_all_stats()
        }


# 全局信号量组
_global_semaphore_group: Optional[SemaphoreGroup] = None
_semaphore_group_lock = threading.Lock()


def get_semaphore_group() -> SemaphoreGroup:
    """获取全局信号量组"""
    global _global_semaphore_group

    with _semaphore_group_lock:
        if _global_semaphore_group is None:
            _global_semaphore_group = SemaphoreGroup()
        return _global_semaphore_group


def get_semaphore(name: str, value: int = 10) -> BoundedSemaphore:
    """
    获取或创建全局命名信号量

    Args:
        name: 信号量名称
        value: 信号量值

    Returns:
        BoundedSemaphore 实例
    """
    return get_semaphore_group().get(name, value)
