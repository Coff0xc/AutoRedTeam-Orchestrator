"""
熔断器模块

实现熔断器模式（Circuit Breaker Pattern），防止级联失败。

状态机:
- CLOSED（关闭）: 正常状态，请求正常通过
- OPEN（打开）: 熔断状态，请求直接失败
- HALF_OPEN（半开）: 试探状态，允许少量请求通过
"""

import functools
import logging
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")


class CircuitState(Enum):
    """熔断器状态"""

    CLOSED = "closed"  # 正常状态
    OPEN = "open"  # 熔断状态
    HALF_OPEN = "half_open"  # 半开状态


class CircuitOpenError(Exception):
    """熔断器打开异常"""

    def __init__(self, message: str = "熔断器已打开", breaker_name: str = "unknown"):
        super().__init__(message)
        self.breaker_name = breaker_name


@dataclass
class CircuitMetrics:
    """熔断器指标"""

    total_calls: int = 0
    success_calls: int = 0
    failure_calls: int = 0
    rejected_calls: int = 0
    last_failure_time: Optional[float] = None
    state_changes: int = 0

    def to_dict(self) -> dict:
        """转换为字典"""
        success_rate = self.success_calls / self.total_calls if self.total_calls > 0 else 1.0
        return {
            "total_calls": self.total_calls,
            "success_calls": self.success_calls,
            "failure_calls": self.failure_calls,
            "rejected_calls": self.rejected_calls,
            "success_rate": success_rate,
            "state_changes": self.state_changes,
            "last_failure_time": self.last_failure_time,
        }


class CircuitBreaker:
    """
    熔断器 - 防止级联失败

    工作原理:
    1. CLOSED 状态下，记录失败次数
    2. 失败次数达到阈值，切换到 OPEN 状态
    3. OPEN 状态下，所有请求直接失败
    4. 超时后切换到 HALF_OPEN 状态
    5. HALF_OPEN 状态下，允许少量请求通过
    6. 如果成功次数达到阈值，切换回 CLOSED
    7. 如果失败，切换回 OPEN
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        success_threshold: int = 2,
        timeout: float = 30.0,
        name: str = "default",
        excluded_exceptions: Optional[tuple] = None,
    ):
        """
        初始化熔断器

        Args:
            failure_threshold: 触发熔断的失败次数阈值
            success_threshold: 从半开恢复需要的成功次数
            timeout: 熔断超时时间（秒）
            name: 熔断器名称
            excluded_exceptions: 不计入失败的异常类型
        """
        if failure_threshold < 1:
            raise ValueError("failure_threshold 必须大于等于 1")
        if success_threshold < 1:
            raise ValueError("success_threshold 必须大于等于 1")
        if timeout <= 0:
            raise ValueError("timeout 必须大于 0")

        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.timeout = timeout
        self.name = name
        self.excluded_exceptions = excluded_exceptions or ()

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._lock = threading.RLock()
        self._metrics = CircuitMetrics()

        logger.debug(
            f"熔断器 '{name}' 已初始化: "
            f"failure_threshold={failure_threshold}, "
            f"timeout={timeout}s"
        )

    @property
    def state(self) -> CircuitState:
        """
        获取当前状态

        Returns:
            当前熔断器状态
        """
        with self._lock:
            # 检查是否应该从 OPEN 转换到 HALF_OPEN
            if self._state == CircuitState.OPEN:
                if self._should_try_reset():
                    self._transition_to(CircuitState.HALF_OPEN)

            return self._state

    def _should_try_reset(self) -> bool:
        """检查是否应该尝试重置"""
        if self._last_failure_time is None:
            return True
        return time.monotonic() - self._last_failure_time >= self.timeout

    def _transition_to(self, new_state: CircuitState) -> None:
        """状态转换"""
        old_state = self._state
        self._state = new_state
        self._metrics.state_changes += 1

        if new_state == CircuitState.CLOSED:
            self._failure_count = 0
            self._success_count = 0
        elif new_state == CircuitState.HALF_OPEN:
            self._success_count = 0

        logger.info(f"熔断器 '{self.name}' 状态变化: {old_state.value} -> {new_state.value}")

    def _is_excluded_exception(self, exc: Exception) -> bool:
        """检查是否是排除的异常类型"""
        return isinstance(exc, self.excluded_exceptions)

    def record_success(self) -> None:
        """
        记录成功调用

        在 HALF_OPEN 状态下，连续成功达到阈值后恢复到 CLOSED
        """
        with self._lock:
            self._metrics.total_calls += 1
            self._metrics.success_calls += 1

            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._transition_to(CircuitState.CLOSED)

            elif self._state == CircuitState.CLOSED:
                # 成功时重置失败计数
                self._failure_count = 0

    def record_failure(self, exception: Optional[Exception] = None) -> None:
        """
        记录失败调用

        在 CLOSED 状态下，失败次数达到阈值后切换到 OPEN
        在 HALF_OPEN 状态下，任何失败都会切换回 OPEN

        Args:
            exception: 导致失败的异常（可选）
        """
        # 检查是否是排除的异常
        if exception is not None and self._is_excluded_exception(exception):
            return

        with self._lock:
            self._metrics.total_calls += 1
            self._metrics.failure_calls += 1
            self._last_failure_time = time.monotonic()
            self._metrics.last_failure_time = self._last_failure_time

            if self._state == CircuitState.HALF_OPEN:
                # 半开状态下失败，立即熔断
                self._transition_to(CircuitState.OPEN)

            elif self._state == CircuitState.CLOSED:
                self._failure_count += 1
                if self._failure_count >= self.failure_threshold:
                    self._transition_to(CircuitState.OPEN)

    def is_call_permitted(self) -> bool:
        """
        检查是否允许调用

        Returns:
            是否允许
        """
        current_state = self.state  # 触发可能的状态转换

        if current_state == CircuitState.OPEN:
            with self._lock:
                self._metrics.rejected_calls += 1
            return False

        return True

    def call(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """
        通过熔断器调用函数

        Args:
            fn: 要调用的函数
            *args: 位置参数
            **kwargs: 关键字参数

        Returns:
            函数返回值

        Raises:
            CircuitOpenError: 熔断器打开时
        """
        if not self.is_call_permitted():
            raise CircuitOpenError(
                f"熔断器 '{self.name}' 已打开，请求被拒绝", breaker_name=self.name
            )

        try:
            result = fn(*args, **kwargs)
            self.record_success()
            return result
        except Exception as e:
            self.record_failure(e)
            raise

    async def async_call(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """
        通过熔断器异步调用函数

        Args:
            fn: 要调用的异步函数
            *args: 位置参数
            **kwargs: 关键字参数

        Returns:
            函数返回值

        Raises:
            CircuitOpenError: 熔断器打开时
        """
        if not self.is_call_permitted():
            raise CircuitOpenError(
                f"熔断器 '{self.name}' 已打开，请求被拒绝", breaker_name=self.name
            )

        try:
            result = await fn(*args, **kwargs)
            self.record_success()
            return result
        except Exception as e:
            self.record_failure(e)
            raise

    def reset(self) -> None:
        """重置熔断器到 CLOSED 状态"""
        with self._lock:
            self._transition_to(CircuitState.CLOSED)
            self._failure_count = 0
            self._success_count = 0
            self._last_failure_time = None
            logger.info(f"熔断器 '{self.name}' 已重置")

    def force_open(self) -> None:
        """强制打开熔断器"""
        with self._lock:
            self._transition_to(CircuitState.OPEN)
            self._last_failure_time = time.monotonic()
            logger.info(f"熔断器 '{self.name}' 被强制打开")

    @property
    def stats(self) -> dict:
        """获取统计信息"""
        with self._lock:
            return {
                "name": self.name,
                "state": self._state.value,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "failure_threshold": self.failure_threshold,
                "success_threshold": self.success_threshold,
                "timeout": self.timeout,
                "metrics": self._metrics.to_dict(),
            }

    def __repr__(self) -> str:
        return f"CircuitBreaker(name='{self.name}', state={self._state.value})"


def circuit_breaker(
    failure_threshold: int = 5,
    success_threshold: int = 2,
    timeout: float = 30.0,
    name: Optional[str] = None,
    excluded_exceptions: Optional[tuple] = None,
) -> Callable:
    """
    熔断器装饰器

    用于自动为函数添加熔断保护。

    Args:
        failure_threshold: 触发熔断的失败次数
        success_threshold: 恢复需要的成功次数
        timeout: 熔断超时时间
        name: 熔断器名称（默认使用函数名）
        excluded_exceptions: 不计入失败的异常类型

    Returns:
        装饰器函数

    Example:
        @circuit_breaker(failure_threshold=3, timeout=60)
        def fetch_data(url: str) -> dict:
            ...
    """

    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        breaker_name = name if name else fn.__name__
        breaker = CircuitBreaker(
            failure_threshold=failure_threshold,
            success_threshold=success_threshold,
            timeout=timeout,
            name=breaker_name,
            excluded_exceptions=excluded_exceptions,
        )

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> T:
            return breaker.call(fn, *args, **kwargs)

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> T:
            return await breaker.async_call(fn, *args, **kwargs)

        # 保存熔断器引用以便外部访问
        wrapper = async_wrapper if asyncio.iscoroutinefunction(fn) else sync_wrapper
        wrapper.circuit_breaker = breaker

        return wrapper

    return decorator


class CircuitBreakerGroup:
    """
    熔断器组 - 管理多个命名熔断器

    用于针对不同服务或资源使用独立的熔断策略
    """

    def __init__(
        self,
        default_failure_threshold: int = 5,
        default_success_threshold: int = 2,
        default_timeout: float = 30.0,
    ):
        """
        初始化熔断器组

        Args:
            default_failure_threshold: 默认失败阈值
            default_success_threshold: 默认成功阈值
            default_timeout: 默认超时时间
        """
        self.default_failure_threshold = default_failure_threshold
        self.default_success_threshold = default_success_threshold
        self.default_timeout = default_timeout

        self._breakers: dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()

    def get(
        self,
        name: str,
        failure_threshold: Optional[int] = None,
        success_threshold: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> CircuitBreaker:
        """
        获取或创建命名熔断器

        Args:
            name: 熔断器名称
            failure_threshold: 失败阈值（仅创建时有效）
            success_threshold: 成功阈值（仅创建时有效）
            timeout: 超时时间（仅创建时有效）

        Returns:
            CircuitBreaker 实例
        """
        with self._lock:
            if name not in self._breakers:
                self._breakers[name] = CircuitBreaker(
                    failure_threshold=failure_threshold or self.default_failure_threshold,
                    success_threshold=success_threshold or self.default_success_threshold,
                    timeout=timeout or self.default_timeout,
                    name=name,
                )
            return self._breakers[name]

    def remove(self, name: str) -> bool:
        """
        移除熔断器

        Args:
            name: 熔断器名称

        Returns:
            是否成功移除
        """
        with self._lock:
            if name in self._breakers:
                del self._breakers[name]
                return True
            return False

    def reset_all(self) -> None:
        """重置所有熔断器"""
        with self._lock:
            for breaker in self._breakers.values():
                breaker.reset()

    def list_names(self) -> list:
        """列出所有熔断器名称"""
        with self._lock:
            return list(self._breakers.keys())

    def get_all_stats(self) -> dict:
        """获取所有熔断器的统计信息"""
        with self._lock:
            return {name: breaker.stats for name, breaker in self._breakers.items()}


# 导入 asyncio 用于装饰器
import asyncio

# 全局熔断器组
_global_breaker_group: Optional[CircuitBreakerGroup] = None
_breaker_group_lock = threading.Lock()


def get_breaker_group() -> CircuitBreakerGroup:
    """获取全局熔断器组"""
    global _global_breaker_group

    with _breaker_group_lock:
        if _global_breaker_group is None:
            _global_breaker_group = CircuitBreakerGroup()
        return _global_breaker_group


def get_circuit_breaker(
    name: str, failure_threshold: int = 5, timeout: float = 30.0
) -> CircuitBreaker:
    """
    获取或创建全局熔断器

    Args:
        name: 熔断器名称
        failure_threshold: 失败阈值
        timeout: 超时时间

    Returns:
        CircuitBreaker 实例
    """
    return get_breaker_group().get(name=name, failure_threshold=failure_threshold, timeout=timeout)
