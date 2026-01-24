#!/usr/bin/env python3
"""
装饰器集合模块 - AutoRedTeam-Orchestrator

提供通用的装饰器，包括：
- 计时器
- 重试
- 缓存
- 废弃警告
- 同步锁
- 限流
- 日志
- 参数验证

使用示例:
    from utils.decorators import timer, retry, cache, rate_limit

    @timer
    def slow_function():
        ...

    @retry(max_attempts=3)
    def unstable_function():
        ...

    @cache(ttl=3600)
    def expensive_function():
        ...
"""

import time
import functools
import threading
import warnings
import logging
import asyncio
from typing import Callable, Any, Optional, TypeVar, Union, Dict
from collections import OrderedDict

T = TypeVar('T')

# 获取日志器
logger = logging.getLogger(__name__)


def timer(func: Callable[..., T]) -> Callable[..., T]:
    """
    计时装饰器

    记录函数执行时间

    Args:
        func: 被装饰的函数

    Returns:
        包装后的函数

    使用示例:
        @timer
        def slow_function():
            time.sleep(1)
            return "done"
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> T:
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        logger.info(f"{func.__name__} 执行时间: {elapsed:.4f}秒")
        return result

    return wrapper


def async_timer(func: Callable[..., T]) -> Callable[..., T]:
    """
    异步计时装饰器

    Args:
        func: 被装饰的异步函数

    Returns:
        包装后的异步函数
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> T:
        start = time.perf_counter()
        result = await func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        logger.info(f"{func.__name__} 执行时间: {elapsed:.4f}秒")
        return result

    return wrapper


def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
    on_retry: Optional[Callable[[Exception, int], None]] = None
) -> Callable:
    """
    重试装饰器

    在函数失败时自动重试

    Args:
        max_attempts: 最大重试次数
        delay: 初始延迟时间（秒）
        backoff: 延迟倍增因子
        exceptions: 触发重试的异常类型元组
        on_retry: 重试时的回调函数

    Returns:
        装饰器函数

    使用示例:
        @retry(max_attempts=3, delay=1.0, exceptions=(ConnectionError,))
        def fetch_data():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            current_delay = delay
            last_exception = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    logger.warning(
                        f"{func.__name__} 失败 (尝试 {attempt}/{max_attempts}): {e}"
                    )

                    if attempt < max_attempts:
                        if on_retry:
                            on_retry(e, attempt)
                        time.sleep(current_delay)
                        current_delay *= backoff

            logger.error(f"{func.__name__} 重试失败 ({max_attempts}次)")
            raise last_exception  # type: ignore

        return wrapper
    return decorator


def async_retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,)
) -> Callable:
    """
    异步重试装饰器

    Args:
        max_attempts: 最大重试次数
        delay: 初始延迟时间（秒）
        backoff: 延迟倍增因子
        exceptions: 触发重试的异常类型元组

    Returns:
        装饰器函数
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            current_delay = delay
            last_exception = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    logger.warning(
                        f"{func.__name__} 失败 (尝试 {attempt}/{max_attempts}): {e}"
                    )

                    if attempt < max_attempts:
                        await asyncio.sleep(current_delay)
                        current_delay *= backoff

            raise last_exception  # type: ignore

        return wrapper
    return decorator


class LRUCache:
    """LRU缓存实现"""

    def __init__(self, maxsize: int = 128, ttl: int = 0):
        self.maxsize = maxsize
        self.ttl = ttl
        self.cache: OrderedDict = OrderedDict()
        self.timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> tuple:
        """获取缓存值"""
        with self._lock:
            if key not in self.cache:
                return False, None

            # 检查TTL
            if self.ttl > 0:
                if time.time() - self.timestamps.get(key, 0) > self.ttl:
                    del self.cache[key]
                    del self.timestamps[key]
                    return False, None

            # 移动到最近使用
            self.cache.move_to_end(key)
            return True, self.cache[key]

    def set(self, key: str, value: Any) -> None:
        """设置缓存值"""
        with self._lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            else:
                if len(self.cache) >= self.maxsize:
                    # 移除最旧的
                    oldest = next(iter(self.cache))
                    del self.cache[oldest]
                    self.timestamps.pop(oldest, None)

            self.cache[key] = value
            if self.ttl > 0:
                self.timestamps[key] = time.time()

    def clear(self) -> None:
        """清空缓存"""
        with self._lock:
            self.cache.clear()
            self.timestamps.clear()


def cache(
    ttl: int = 3600,
    maxsize: int = 128,
    key_func: Optional[Callable] = None
) -> Callable:
    """
    缓存装饰器

    缓存函数结果，支持TTL过期

    Args:
        ttl: 缓存过期时间（秒），0表示永不过期
        maxsize: 最大缓存数量
        key_func: 自定义缓存键生成函数

    Returns:
        装饰器函数

    使用示例:
        @cache(ttl=300)
        def expensive_computation(x, y):
            ...

        @cache(key_func=lambda args, kwargs: args[0])
        def fetch_user(user_id):
            ...
    """
    cache_store = LRUCache(maxsize=maxsize, ttl=ttl)

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            # 生成缓存键
            if key_func:
                cache_key = str(key_func(args, kwargs))
            else:
                cache_key = str((args, tuple(sorted(kwargs.items()))))

            # 尝试获取缓存
            found, value = cache_store.get(cache_key)
            if found:
                logger.debug(f"{func.__name__} 命中缓存")
                return value

            # 执行函数
            result = func(*args, **kwargs)

            # 存入缓存
            cache_store.set(cache_key, result)

            return result

        # 添加清除缓存的方法
        wrapper.cache_clear = cache_store.clear  # type: ignore

        return wrapper
    return decorator


def deprecated(
    message: str = '',
    version: Optional[str] = None,
    replacement: Optional[str] = None
) -> Callable:
    """
    废弃警告装饰器

    标记函数为废弃，并在调用时发出警告

    Args:
        message: 自定义警告消息
        version: 废弃的版本号
        replacement: 替代函数名

    Returns:
        装饰器函数

    使用示例:
        @deprecated(version="2.0", replacement="new_function")
        def old_function():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            # 构建警告消息
            warn_msg = f"{func.__name__} 已废弃"

            if version:
                warn_msg += f" (自版本 {version})"

            if replacement:
                warn_msg += f"，请使用 {replacement} 代替"

            if message:
                warn_msg += f"。{message}"

            warnings.warn(warn_msg, DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)

        return wrapper
    return decorator


def synchronized(lock: Optional[threading.Lock] = None) -> Callable:
    """
    同步装饰器

    确保函数在多线程环境下的线程安全

    Args:
        lock: 可选的锁对象，为None时创建新锁

    Returns:
        装饰器函数

    使用示例:
        @synchronized()
        def critical_section():
            ...

        # 使用共享锁
        shared_lock = threading.Lock()

        @synchronized(shared_lock)
        def func1():
            ...

        @synchronized(shared_lock)
        def func2():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        actual_lock = lock or threading.Lock()

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            with actual_lock:
                return func(*args, **kwargs)

        return wrapper
    return decorator


def rate_limit(
    calls: int = 10,
    period: float = 1.0,
    raise_on_limit: bool = False
) -> Callable:
    """
    限流装饰器

    限制函数在单位时间内的调用次数

    Args:
        calls: 时间窗口内允许的最大调用次数
        period: 时间窗口（秒）
        raise_on_limit: 达到限制时是否抛出异常

    Returns:
        装饰器函数

    使用示例:
        @rate_limit(calls=10, period=1.0)
        def api_call():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        call_times: list = []
        lock = threading.Lock()

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            with lock:
                now = time.time()

                # 清理过期的调用记录
                nonlocal call_times
                call_times = [t for t in call_times if now - t < period]

                # 检查是否超出限制
                if len(call_times) >= calls:
                    sleep_time = period - (now - call_times[0])
                    if sleep_time > 0:
                        if raise_on_limit:
                            raise RuntimeError(
                                f"速率限制：{func.__name__} 调用过于频繁"
                            )
                        logger.debug(
                            f"{func.__name__} 速率限制，等待 {sleep_time:.2f}秒"
                        )
                        time.sleep(sleep_time)
                        call_times.pop(0)

                # 记录调用时间
                call_times.append(time.time())

            return func(*args, **kwargs)

        return wrapper
    return decorator


def log_execution(
    level: int = logging.INFO,
    include_args: bool = False,
    include_result: bool = False
) -> Callable:
    """
    执行日志装饰器

    记录函数的调用和执行情况

    Args:
        level: 日志级别
        include_args: 是否记录参数
        include_result: 是否记录返回值

    Returns:
        装饰器函数

    使用示例:
        @log_execution(include_args=True)
        def important_function(x, y):
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            # 记录调用
            msg = f"调用 {func.__name__}"
            if include_args:
                msg += f" args={args}, kwargs={kwargs}"
            logger.log(level, msg)

            try:
                result = func(*args, **kwargs)

                # 记录成功
                success_msg = f"{func.__name__} 执行成功"
                if include_result:
                    success_msg += f" 返回: {result}"
                logger.log(level, success_msg)

                return result

            except Exception as e:
                logger.error(f"{func.__name__} 执行失败: {e}")
                raise

        return wrapper
    return decorator


def safe_execute(
    default_return: Any = None,
    exceptions: tuple = (Exception,),
    log_error: bool = True
) -> Callable:
    """
    安全执行装饰器

    捕获异常并返回默认值

    Args:
        default_return: 异常时的默认返回值
        exceptions: 要捕获的异常类型
        log_error: 是否记录错误日志

    Returns:
        装饰器函数

    使用示例:
        @safe_execute(default_return={})
        def risky_function():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., Union[T, Any]]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Union[T, Any]:
            try:
                return func(*args, **kwargs)
            except exceptions as e:
                if log_error:
                    logger.error(f"{func.__name__} 执行异常: {e}")
                return default_return

        return wrapper
    return decorator


def singleton(cls):
    """
    单例装饰器

    确保类只有一个实例

    Args:
        cls: 被装饰的类

    Returns:
        包装后的类

    使用示例:
        @singleton
        class Database:
            ...
    """
    instances: Dict[type, Any] = {}
    lock = threading.Lock()

    @functools.wraps(cls)
    def get_instance(*args, **kwargs):
        if cls not in instances:
            with lock:
                if cls not in instances:
                    instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance


def validate_args(**validators: Callable[[Any], bool]) -> Callable:
    """
    参数验证装饰器

    验证函数参数

    Args:
        **validators: 参数名到验证函数的映射

    Returns:
        装饰器函数

    使用示例:
        @validate_args(
            x=lambda v: isinstance(v, int) and v > 0,
            y=lambda v: isinstance(v, str)
        )
        def process(x, y):
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        import inspect
        sig = inspect.signature(func)

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            # 绑定参数
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()

            # 验证参数
            for name, validator in validators.items():
                if name in bound.arguments:
                    value = bound.arguments[name]
                    if not validator(value):
                        raise ValueError(
                            f"参数 {name} 验证失败: {value}"
                        )

            return func(*args, **kwargs)

        return wrapper
    return decorator


def memoize(func: Callable[..., T]) -> Callable[..., T]:
    """
    记忆化装饰器

    简单的无过期缓存

    Args:
        func: 被装饰的函数

    Returns:
        包装后的函数
    """
    cache_dict: Dict[str, T] = {}

    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> T:
        key = str((args, tuple(sorted(kwargs.items()))))

        if key not in cache_dict:
            cache_dict[key] = func(*args, **kwargs)

        return cache_dict[key]

    wrapper.cache = cache_dict  # type: ignore
    wrapper.cache_clear = cache_dict.clear  # type: ignore

    return wrapper


# 向后兼容
measure_time = timer
cache_result = cache


__all__ = [
    'timer',
    'async_timer',
    'retry',
    'async_retry',
    'cache',
    'deprecated',
    'synchronized',
    'rate_limit',
    'log_execution',
    'safe_execute',
    'singleton',
    'validate_args',
    'memoize',
    # 向后兼容
    'measure_time',
    'cache_result',
]
