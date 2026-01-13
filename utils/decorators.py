#!/usr/bin/env python3
"""
装饰器库 - 提供日志、性能监控、重试等通用装饰器
消除重复的横切关注点代码
"""

import time
import functools
import logging
from typing import Callable, Any, Optional
import asyncio

logger = logging.getLogger(__name__)


def log_execution(func: Callable) -> Callable:
    """
    日志装饰器 - 记录函数执行

    使用:
        @log_execution
        def my_function():
            pass
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        func_name = func.__name__
        logger.info(f"开始执行: {func_name}")
        try:
            result = func(*args, **kwargs)
            logger.info(f"执行成功: {func_name}")
            return result
        except Exception as e:
            logger.error(f"执行失败: {func_name} - {e}")
            raise
    return wrapper


def async_log_execution(func: Callable) -> Callable:
    """异步日志装饰器"""
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        func_name = func.__name__
        logger.info(f"开始执行: {func_name}")
        try:
            result = await func(*args, **kwargs)
            logger.info(f"执行成功: {func_name}")
            return result
        except Exception as e:
            logger.error(f"执行失败: {func_name} - {e}")
            raise
    return wrapper


def measure_time(func: Callable) -> Callable:
    """
    性能监控装饰器 - 测量函数执行时间

    使用:
        @measure_time
        def slow_function():
            time.sleep(1)
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        logger.info(f"{func.__name__} 执行时间: {elapsed:.2f}秒")
        return result
    return wrapper


def async_measure_time(func: Callable) -> Callable:
    """异步性能监控装饰器"""
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        start = time.time()
        result = await func(*args, **kwargs)
        elapsed = time.time() - start
        logger.info(f"{func.__name__} 执行时间: {elapsed:.2f}秒")
        return result
    return wrapper


def retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """
    重试装饰器 - 自动重试失败的函数

    Args:
        max_attempts: 最大重试次数
        delay: 初始延迟时间(秒)
        backoff: 延迟倍增因子

    使用:
        @retry(max_attempts=3, delay=1.0)
        def unstable_function():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_attempts - 1:
                        logger.error(f"{func.__name__} 重试失败 ({max_attempts}次): {e}")
                        raise
                    logger.warning(f"{func.__name__} 失败 (尝试 {attempt + 1}/{max_attempts}): {e}")
                    time.sleep(current_delay)
                    current_delay *= backoff
        return wrapper
    return decorator


def async_retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """异步重试装饰器"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            current_delay = delay
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_attempts - 1:
                        logger.error(f"{func.__name__} 重试失败 ({max_attempts}次): {e}")
                        raise
                    logger.warning(f"{func.__name__} 失败 (尝试 {attempt + 1}/{max_attempts}): {e}")
                    await asyncio.sleep(current_delay)
                    current_delay *= backoff
        return wrapper
    return decorator


def cache_result(ttl: int = 300):
    """
    缓存装饰器 - 缓存函数结果

    Args:
        ttl: 缓存过期时间(秒)

    使用:
        @cache_result(ttl=60)
        def expensive_function(arg):
            return result
    """
    def decorator(func: Callable) -> Callable:
        cache = {}
        cache_time = {}

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # 生成缓存键
            key = str(args) + str(kwargs)

            # 检查缓存
            if key in cache:
                if time.time() - cache_time[key] < ttl:
                    logger.debug(f"{func.__name__} 使用缓存结果")
                    return cache[key]

            # 执行函数
            result = func(*args, **kwargs)

            # 更新缓存
            cache[key] = result
            cache_time[key] = time.time()

            return result
        return wrapper
    return decorator


def rate_limit(calls: int = 10, period: float = 1.0):
    """
    速率限制装饰器 - 限制函数调用频率

    Args:
        calls: 时间窗口内最大调用次数
        period: 时间窗口(秒)

    使用:
        @rate_limit(calls=10, period=1.0)
        def api_call():
            pass
    """
    def decorator(func: Callable) -> Callable:
        call_times = []

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()

            # 清理过期记录
            call_times[:] = [t for t in call_times if now - t < period]

            # 检查速率限制
            if len(call_times) >= calls:
                sleep_time = period - (now - call_times[0])
                if sleep_time > 0:
                    logger.debug(f"{func.__name__} 速率限制，等待 {sleep_time:.2f}秒")
                    time.sleep(sleep_time)
                    call_times.pop(0)

            # 记录调用时间
            call_times.append(time.time())

            return func(*args, **kwargs)
        return wrapper
    return decorator


def safe_execute(default_return: Any = None, log_error: bool = True):
    """
    安全执行装饰器 - 捕获异常并返回默认值

    Args:
        default_return: 异常时返回的默认值
        log_error: 是否记录错误日志

    使用:
        @safe_execute(default_return={})
        def risky_function():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if log_error:
                    logger.error(f"{func.__name__} 执行异常: {e}")
                return default_return
        return wrapper
    return decorator


def timeout(seconds: int):
    """
    超时装饰器 - 限制函数执行时间

    Args:
        seconds: 超时时间(秒)

    使用:
        @timeout(10)
        def long_running_function():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import signal

            def timeout_handler(signum, frame):
                raise TimeoutError(f"{func.__name__} 执行超时 ({seconds}秒)")

            # 设置超时信号
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(seconds)

            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)  # 取消超时

            return result
        return wrapper
    return decorator


# 组合装饰器示例
def robust_api_call(func: Callable) -> Callable:
    """
    健壮的 API 调用装饰器 - 组合多个装饰器

    包含: 日志 + 性能监控 + 重试 + 速率限制
    """
    @log_execution
    @measure_time
    @retry(max_attempts=3, delay=1.0)
    @rate_limit(calls=10, period=1.0)
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


# 使用示例
if __name__ == "__main__":
    @log_execution
    @measure_time
    @retry(max_attempts=3)
    def test_function():
        print("执行测试函数")
        return "success"

    result = test_function()
    print(f"结果: {result}")
