"""
限流器模块

提供多种限流算法：
- 令牌桶 (Token Bucket)
- 滑动窗口 (Sliding Window)
- 自适应限流 (Adaptive Rate Limiting)
"""

import time
import asyncio
import threading
from typing import Optional
from collections import deque
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


class TokenBucket:
    """
    令牌桶限流器

    算法原理:
    - 令牌以固定速率生成
    - 请求需要消耗令牌才能执行
    - 桶有最大容量，超出的令牌会被丢弃
    - 支持突发流量（桶内有足够令牌时）
    """

    def __init__(
        self,
        rate: float,
        capacity: Optional[float] = None
    ):
        """
        初始化令牌桶

        Args:
            rate: 每秒生成的令牌数
            capacity: 桶容量（默认等于 rate）
        """
        if rate <= 0:
            raise ValueError("rate 必须大于 0")

        self.rate = rate
        self.capacity = capacity if capacity is not None else rate

        if self.capacity < rate:
            raise ValueError("capacity 不能小于 rate")

        self._tokens = self.capacity
        self._last_time = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        """补充令牌"""
        now = time.monotonic()
        elapsed = now - self._last_time
        self._last_time = now

        # 计算新增令牌
        new_tokens = elapsed * self.rate
        self._tokens = min(self._tokens + new_tokens, self.capacity)

    def try_acquire(self, tokens: int = 1) -> bool:
        """
        尝试获取令牌（非阻塞）

        Args:
            tokens: 需要的令牌数

        Returns:
            是否成功获取
        """
        if tokens <= 0:
            raise ValueError("tokens 必须大于 0")

        with self._lock:
            self._refill()

            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def acquire(self, tokens: int = 1, timeout: Optional[float] = None) -> bool:
        """
        获取令牌（阻塞）

        Args:
            tokens: 需要的令牌数
            timeout: 超时时间（秒），None 表示无限等待

        Returns:
            是否成功获取
        """
        if tokens <= 0:
            raise ValueError("tokens 必须大于 0")

        start_time = time.monotonic()

        while True:
            if self.try_acquire(tokens):
                return True

            # 检查超时
            if timeout is not None:
                elapsed = time.monotonic() - start_time
                if elapsed >= timeout:
                    return False

            # 计算需要等待的时间
            with self._lock:
                tokens_needed = tokens - self._tokens
                wait_time = tokens_needed / self.rate

            # 限制单次等待时间
            if timeout is not None:
                remaining = timeout - (time.monotonic() - start_time)
                wait_time = min(wait_time, remaining)

            if wait_time > 0:
                time.sleep(min(wait_time, 0.1))  # 最多等待 0.1 秒后重试

    async def async_acquire(self, tokens: int = 1, timeout: Optional[float] = None) -> bool:
        """
        异步获取令牌

        Args:
            tokens: 需要的令牌数
            timeout: 超时时间

        Returns:
            是否成功获取
        """
        if tokens <= 0:
            raise ValueError("tokens 必须大于 0")

        start_time = time.monotonic()

        while True:
            if self.try_acquire(tokens):
                return True

            # 检查超时
            if timeout is not None:
                elapsed = time.monotonic() - start_time
                if elapsed >= timeout:
                    return False

            # 计算需要等待的时间
            with self._lock:
                tokens_needed = tokens - self._tokens
                wait_time = tokens_needed / self.rate

            if timeout is not None:
                remaining = timeout - (time.monotonic() - start_time)
                wait_time = min(wait_time, remaining)

            if wait_time > 0:
                await asyncio.sleep(min(wait_time, 0.1))

    @property
    def available_tokens(self) -> float:
        """当前可用令牌数"""
        with self._lock:
            self._refill()
            return self._tokens

    def reset(self) -> None:
        """重置令牌桶"""
        with self._lock:
            self._tokens = self.capacity
            self._last_time = time.monotonic()


class SlidingWindowRateLimiter:
    """
    滑动窗口限流器

    算法原理:
    - 维护一个时间窗口内的请求记录
    - 超出窗口的请求会被移除
    - 新请求只有在窗口内请求数未达上限时才允许
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: float
    ):
        """
        初始化滑动窗口限流器

        Args:
            max_requests: 窗口内最大请求数
            window_seconds: 时间窗口大小（秒）
        """
        if max_requests <= 0:
            raise ValueError("max_requests 必须大于 0")
        if window_seconds <= 0:
            raise ValueError("window_seconds 必须大于 0")

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: deque = deque()
        self._lock = threading.Lock()

    def _cleanup(self) -> None:
        """清理过期请求"""
        now = time.monotonic()
        cutoff = now - self.window_seconds

        while self._requests and self._requests[0] < cutoff:
            self._requests.popleft()

    def is_allowed(self) -> bool:
        """
        检查是否允许请求

        Returns:
            是否允许
        """
        with self._lock:
            self._cleanup()
            return len(self._requests) < self.max_requests

    def record_request(self) -> bool:
        """
        记录请求并检查是否允许

        Returns:
            是否允许
        """
        with self._lock:
            self._cleanup()

            if len(self._requests) >= self.max_requests:
                return False

            self._requests.append(time.monotonic())
            return True

    def wait_if_needed(self, timeout: Optional[float] = None) -> bool:
        """
        必要时等待直到可以请求

        Args:
            timeout: 超时时间

        Returns:
            是否成功（超时返回 False）
        """
        start_time = time.monotonic()

        while True:
            if self.record_request():
                return True

            if timeout is not None:
                elapsed = time.monotonic() - start_time
                if elapsed >= timeout:
                    return False

            # 计算需要等待的时间
            with self._lock:
                if self._requests:
                    oldest = self._requests[0]
                    wait_time = oldest + self.window_seconds - time.monotonic()
                else:
                    wait_time = 0.01

            if wait_time > 0:
                time.sleep(min(wait_time, 0.1))

    async def async_wait_if_needed(self, timeout: Optional[float] = None) -> bool:
        """
        异步等待

        Args:
            timeout: 超时时间

        Returns:
            是否成功
        """
        start_time = time.monotonic()

        while True:
            if self.record_request():
                return True

            if timeout is not None:
                elapsed = time.monotonic() - start_time
                if elapsed >= timeout:
                    return False

            with self._lock:
                if self._requests:
                    oldest = self._requests[0]
                    wait_time = oldest + self.window_seconds - time.monotonic()
                else:
                    wait_time = 0.01

            if wait_time > 0:
                await asyncio.sleep(min(wait_time, 0.1))

    @property
    def current_count(self) -> int:
        """当前窗口内请求数"""
        with self._lock:
            self._cleanup()
            return len(self._requests)

    @property
    def remaining(self) -> int:
        """剩余可用请求数"""
        with self._lock:
            self._cleanup()
            return max(0, self.max_requests - len(self._requests))

    def reset(self) -> None:
        """重置限流器"""
        with self._lock:
            self._requests.clear()


@dataclass
class AdaptiveMetrics:
    """自适应限流指标"""
    success_count: int = 0
    failure_count: int = 0
    consecutive_successes: int = 0
    consecutive_failures: int = 0
    last_adjustment_time: float = field(default_factory=time.monotonic)


class AdaptiveRateLimiter:
    """
    自适应限流器 - 根据响应调整速率

    特性:
    - 成功时逐步提高速率
    - 失败时快速降低速率
    - 支持速率边界限制
    """

    def __init__(
        self,
        initial_rate: float = 10.0,
        min_rate: float = 1.0,
        max_rate: float = 100.0,
        increase_factor: float = 1.1,
        decrease_factor: float = 0.5,
        success_threshold: int = 10,
        failure_threshold: int = 3,
        cooldown_seconds: float = 1.0
    ):
        """
        初始化自适应限流器

        Args:
            initial_rate: 初始速率（每秒请求数）
            min_rate: 最小速率
            max_rate: 最大速率
            increase_factor: 速率提升因子
            decrease_factor: 速率下降因子
            success_threshold: 提升速率所需的连续成功次数
            failure_threshold: 降低速率所需的连续失败次数
            cooldown_seconds: 调整冷却时间
        """
        if min_rate <= 0:
            raise ValueError("min_rate 必须大于 0")
        if max_rate < min_rate:
            raise ValueError("max_rate 必须大于等于 min_rate")
        if initial_rate < min_rate or initial_rate > max_rate:
            raise ValueError("initial_rate 必须在 min_rate 和 max_rate 之间")

        self.min_rate = min_rate
        self.max_rate = max_rate
        self.increase_factor = increase_factor
        self.decrease_factor = decrease_factor
        self.success_threshold = success_threshold
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds

        self._current_rate = initial_rate
        self._bucket = TokenBucket(rate=initial_rate, capacity=initial_rate * 2)
        self._metrics = AdaptiveMetrics()
        self._lock = threading.Lock()

        logger.debug(f"自适应限流器已初始化: rate={initial_rate}, range=[{min_rate}, {max_rate}]")

    def _adjust_rate(self, new_rate: float) -> None:
        """调整速率"""
        now = time.monotonic()
        if now - self._metrics.last_adjustment_time < self.cooldown_seconds:
            return

        new_rate = max(self.min_rate, min(self.max_rate, new_rate))

        if abs(new_rate - self._current_rate) > 0.01:
            old_rate = self._current_rate
            self._current_rate = new_rate
            self._bucket = TokenBucket(rate=new_rate, capacity=new_rate * 2)
            self._metrics.last_adjustment_time = now
            logger.debug(f"限流速率调整: {old_rate:.2f} -> {new_rate:.2f}")

    def record_success(self) -> None:
        """记录成功，可能提高速率"""
        with self._lock:
            self._metrics.success_count += 1
            self._metrics.consecutive_successes += 1
            self._metrics.consecutive_failures = 0

            # 检查是否需要提高速率
            if self._metrics.consecutive_successes >= self.success_threshold:
                new_rate = self._current_rate * self.increase_factor
                self._adjust_rate(new_rate)
                self._metrics.consecutive_successes = 0

    def record_failure(self) -> None:
        """记录失败，降低速率"""
        with self._lock:
            self._metrics.failure_count += 1
            self._metrics.consecutive_failures += 1
            self._metrics.consecutive_successes = 0

            # 检查是否需要降低速率
            if self._metrics.consecutive_failures >= self.failure_threshold:
                new_rate = self._current_rate * self.decrease_factor
                self._adjust_rate(new_rate)
                self._metrics.consecutive_failures = 0

    def acquire(self, timeout: Optional[float] = None) -> bool:
        """
        获取执行许可

        Args:
            timeout: 超时时间

        Returns:
            是否获取成功
        """
        return self._bucket.acquire(tokens=1, timeout=timeout)

    def try_acquire(self) -> bool:
        """
        尝试获取执行许可（非阻塞）

        Returns:
            是否获取成功
        """
        return self._bucket.try_acquire(tokens=1)

    async def async_acquire(self, timeout: Optional[float] = None) -> bool:
        """
        异步获取执行许可

        Args:
            timeout: 超时时间

        Returns:
            是否获取成功
        """
        return await self._bucket.async_acquire(tokens=1, timeout=timeout)

    @property
    def current_rate(self) -> float:
        """当前速率"""
        with self._lock:
            return self._current_rate

    @property
    def stats(self) -> dict:
        """统计信息"""
        with self._lock:
            total = self._metrics.success_count + self._metrics.failure_count
            success_rate = (
                self._metrics.success_count / total
                if total > 0 else 1.0
            )

            return {
                'current_rate': self._current_rate,
                'min_rate': self.min_rate,
                'max_rate': self.max_rate,
                'success_count': self._metrics.success_count,
                'failure_count': self._metrics.failure_count,
                'success_rate': success_rate,
                'consecutive_successes': self._metrics.consecutive_successes,
                'consecutive_failures': self._metrics.consecutive_failures
            }

    def reset(self) -> None:
        """重置限流器"""
        with self._lock:
            self._metrics = AdaptiveMetrics()
            self._bucket.reset()


class RateLimiterGroup:
    """
    限流器组 - 管理多个命名限流器

    用于针对不同目标或资源应用不同的限流策略
    """

    def __init__(self, default_rate: float = 10.0):
        """
        初始化限流器组

        Args:
            default_rate: 默认速率
        """
        self.default_rate = default_rate
        self._limiters: dict = {}
        self._lock = threading.Lock()

    def get(
        self,
        name: str,
        rate: Optional[float] = None,
        limiter_type: str = 'token_bucket'
    ) -> TokenBucket:
        """
        获取或创建命名限流器

        Args:
            name: 限流器名称
            rate: 速率（仅创建时有效）
            limiter_type: 限流器类型

        Returns:
            限流器实例
        """
        with self._lock:
            if name not in self._limiters:
                actual_rate = rate if rate is not None else self.default_rate

                if limiter_type == 'token_bucket':
                    self._limiters[name] = TokenBucket(rate=actual_rate)
                elif limiter_type == 'sliding_window':
                    self._limiters[name] = SlidingWindowRateLimiter(
                        max_requests=int(actual_rate),
                        window_seconds=1.0
                    )
                elif limiter_type == 'adaptive':
                    self._limiters[name] = AdaptiveRateLimiter(
                        initial_rate=actual_rate
                    )
                else:
                    raise ValueError(f"未知的限流器类型: {limiter_type}")

            return self._limiters[name]

    def remove(self, name: str) -> bool:
        """
        移除限流器

        Args:
            name: 限流器名称

        Returns:
            是否成功移除
        """
        with self._lock:
            if name in self._limiters:
                del self._limiters[name]
                return True
            return False

    def list_names(self) -> list:
        """列出所有限流器名称"""
        with self._lock:
            return list(self._limiters.keys())

    def clear(self) -> None:
        """清除所有限流器"""
        with self._lock:
            self._limiters.clear()


# 全局限流器组
_global_limiter_group: Optional[RateLimiterGroup] = None
_limiter_group_lock = threading.Lock()


def get_limiter_group() -> RateLimiterGroup:
    """获取全局限流器组"""
    global _global_limiter_group

    with _limiter_group_lock:
        if _global_limiter_group is None:
            _global_limiter_group = RateLimiterGroup()
        return _global_limiter_group


def rate_limit(
    rate: float = 10.0,
    name: Optional[str] = None
):
    """
    限流装饰器

    Args:
        rate: 每秒请求数
        name: 限流器名称（用于共享限流）

    Returns:
        装饰器函数
    """
    limiter_name = name if name else f"decorator_{id(rate)}"
    bucket = TokenBucket(rate=rate)

    def decorator(fn):
        import functools

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            bucket.acquire()
            return fn(*args, **kwargs)

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            await bucket.async_acquire()
            return await fn(*args, **kwargs)

        if asyncio.iscoroutinefunction(fn):
            return async_wrapper
        return wrapper

    return decorator
