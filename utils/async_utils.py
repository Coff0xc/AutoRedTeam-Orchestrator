#!/usr/bin/env python3
"""
异步工具模块 - AutoRedTeam-Orchestrator

提供异步编程辅助功能，包括：
- 同步/异步互转
- 并发控制
- 超时处理
- 异步重试
- 批量异步执行

使用示例:
    from utils.async_utils import run_sync, gather_with_limit, async_retry

    # 在同步上下文中运行协程
    result = run_sync(some_coroutine())

    # 带并发限制的批量执行
    results = await gather_with_limit(coroutines, limit=10)

    # 异步重试装饰器
    @async_retry(max_attempts=3)
    async def fetch_data():
        ...
"""

import asyncio
import functools
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Awaitable, Callable, Coroutine, List, Optional, Sequence, TypeVar, Union

T = TypeVar("T")


def run_sync(coro: Coroutine[Any, Any, T]) -> T:
    """
    在同步上下文中运行协程

    自动处理事件循环的创建和管理

    Args:
        coro: 要运行的协程

    Returns:
        协程的返回值

    使用示例:
        async def fetch_data():
            return "data"

        # 在同步代码中调用
        result = run_sync(fetch_data())
    """
    try:
        # 尝试获取当前事件循环
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # 没有运行中的事件循环，创建新的
        loop = None

    if loop is not None:
        # 在已有事件循环中，使用线程池执行
        # 这避免了"cannot be called from a running event loop"错误
        pass

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(asyncio.run, coro)
            return future.result()
    else:
        # 没有事件循环，直接运行
        return asyncio.run(coro)


def ensure_async(func: Callable[..., T]) -> Callable[..., Awaitable[T]]:
    """
    确保函数是异步的

    如果是同步函数，将其包装为异步函数

    Args:
        func: 原始函数

    Returns:
        异步函数
    """
    if asyncio.iscoroutinefunction(func):
        return func

    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> T:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, functools.partial(func, *args, **kwargs))

    return wrapper


def ensure_sync(func: Callable[..., Union[T, Awaitable[T]]]) -> Callable[..., T]:
    """
    确保函数是同步的

    如果是异步函数，将其包装为同步函数

    Args:
        func: 原始函数

    Returns:
        同步函数
    """
    if not asyncio.iscoroutinefunction(func):
        return func

    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> T:
        return run_sync(func(*args, **kwargs))

    return wrapper


async def gather_with_limit(
    coros: Sequence[Coroutine[Any, Any, T]], limit: int = 10, return_exceptions: bool = True
) -> List[Union[T, Exception]]:
    """
    带并发限制的 asyncio.gather

    Args:
        coros: 协程列表
        limit: 最大并发数
        return_exceptions: 是否返回异常而不是抛出

    Returns:
        结果列表（顺序与输入一致）

    使用示例:
        async def fetch(url):
            ...

        urls = ["url1", "url2", ...]
        coros = [fetch(url) for url in urls]
        results = await gather_with_limit(coros, limit=5)
    """
    semaphore = asyncio.Semaphore(limit)

    async def limited_coro(coro: Coroutine[Any, Any, T], index: int) -> tuple:
        async with semaphore:
            try:
                result = await coro
                return index, result, None
            except Exception as e:
                if return_exceptions:
                    return index, None, e
                raise

    # 创建带索引的任务
    tasks = [limited_coro(coro, i) for i, coro in enumerate(coros)]

    # 执行所有任务
    completed = await asyncio.gather(*tasks, return_exceptions=return_exceptions)

    # 按原始顺序排列结果
    results = [None] * len(coros)
    for item in completed:
        if isinstance(item, Exception):
            # gather本身的异常（不应该发生，因为我们已经处理了）
            raise item
        index, result, error = item
        results[index] = error if error is not None else result

    return results


async def timeout_wrapper(
    coro: Coroutine[Any, Any, T],
    timeout: float,
    default: Optional[T] = None,
    raise_on_timeout: bool = False,
) -> Optional[T]:
    """
    为协程添加超时处理

    Args:
        coro: 协程
        timeout: 超时时间（秒）
        default: 超时时返回的默认值
        raise_on_timeout: 超时时是否抛出异常

    Returns:
        协程结果或默认值

    Raises:
        asyncio.TimeoutError: 如果 raise_on_timeout=True 且超时
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        if raise_on_timeout:
            raise
        return default


def async_retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
    on_retry: Optional[Callable[[Exception, int], None]] = None,
) -> Callable:
    """
    异步重试装饰器

    Args:
        max_attempts: 最大重试次数
        delay: 初始延迟时间（秒）
        backoff: 延迟倍增因子
        exceptions: 触发重试的异常类型
        on_retry: 重试时的回调函数 (exception, attempt_number)

    Returns:
        装饰器函数

    使用示例:
        @async_retry(max_attempts=3, delay=1.0)
        async def unstable_api_call():
            ...
    """

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            current_delay = delay
            last_exception = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e

                    if attempt < max_attempts:
                        if on_retry:
                            on_retry(e, attempt)
                        await asyncio.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        raise

            # 不应该到达这里，但为了类型安全
            raise last_exception  # type: ignore

        return wrapper

    return decorator


async def run_in_executor(
    func: Callable[..., T], *args, executor: Optional[ThreadPoolExecutor] = None, **kwargs
) -> T:
    """
    在线程池中运行同步函数

    Args:
        func: 同步函数
        *args: 位置参数
        executor: 可选的线程池执行器
        **kwargs: 关键字参数

    Returns:
        函数返回值
    """
    loop = asyncio.get_running_loop()
    partial_func = functools.partial(func, *args, **kwargs)
    return await loop.run_in_executor(executor, partial_func)


async def async_map(
    func: Callable[[T], Awaitable[Any]], items: Sequence[T], limit: int = 10
) -> List[Any]:
    """
    异步 map 函数

    对序列中的每个元素应用异步函数

    Args:
        func: 异步函数
        items: 输入序列
        limit: 并发限制

    Returns:
        结果列表

    使用示例:
        async def process(item):
            ...

        results = await async_map(process, items, limit=5)
    """
    coros = [func(item) for item in items]
    return await gather_with_limit(coros, limit=limit)


async def async_filter(
    func: Callable[[T], Awaitable[bool]], items: Sequence[T], limit: int = 10
) -> List[T]:
    """
    异步 filter 函数

    Args:
        func: 异步谓词函数
        items: 输入序列
        limit: 并发限制

    Returns:
        过滤后的列表
    """

    async def check(item: T) -> tuple:
        result = await func(item)
        return item, result

    results = await async_map(check, items, limit=limit)
    return [item for item, passed in results if passed]


class AsyncThrottle:
    """
    异步节流器

    限制单位时间内的调用次数

    使用示例:
        throttle = AsyncThrottle(calls=10, period=1.0)

        async def make_request():
            async with throttle:
                await do_request()
    """

    def __init__(self, calls: int = 10, period: float = 1.0):
        """
        初始化节流器

        Args:
            calls: 时间窗口内允许的最大调用次数
            period: 时间窗口（秒）
        """
        self.calls = calls
        self.period = period
        self.timestamps: List[float] = []
        self._lock = asyncio.Lock()

    async def __aenter__(self):
        async with self._lock:
            now = asyncio.get_running_loop().time()

            # 清理过期的时间戳
            self.timestamps = [t for t in self.timestamps if now - t < self.period]

            # 如果已达到限制，等待
            if len(self.timestamps) >= self.calls:
                sleep_time = self.period - (now - self.timestamps[0])
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                self.timestamps.pop(0)

            # 记录当前时间
            self.timestamps.append(asyncio.get_running_loop().time())

    async def __aexit__(self, exc_type, _exc_val, _exc_tb):
        pass


class AsyncBatcher:
    """
    异步批处理器

    将多个请求合并为批量处理

    使用示例:
        async def batch_process(items):
            return [process(item) for item in items]

        batcher = AsyncBatcher(batch_process, max_size=100, max_wait=0.5)

        # 多个协程同时调用
        result = await batcher.submit(item)
    """

    def __init__(
        self,
        batch_func: Callable[[List[T]], Awaitable[List[Any]]],
        max_size: int = 100,
        max_wait: float = 0.5,
    ):
        """
        初始化批处理器

        Args:
            batch_func: 批量处理函数
            max_size: 批量最大大小
            max_wait: 最大等待时间（秒）
        """
        self.batch_func = batch_func
        self.max_size = max_size
        self.max_wait = max_wait

        self._queue: List[tuple] = []
        self._lock = asyncio.Lock()
        self._event = asyncio.Event()
        self._task: Optional[asyncio.Task] = None

    async def submit(self, item: T) -> Any:
        """
        提交单个项目

        Args:
            item: 要处理的项目

        Returns:
            处理结果
        """
        future: asyncio.Future = asyncio.Future()

        async with self._lock:
            self._queue.append((item, future))

            # 如果达到批量大小，立即处理
            if len(self._queue) >= self.max_size:
                self._event.set()

            # 启动后台任务
            if self._task is None or self._task.done():
                self._task = asyncio.create_task(self._worker())

        return await future

    async def _worker(self):
        """后台工作任务"""
        while True:
            # 等待批量大小或超时
            try:
                await asyncio.wait_for(self._event.wait(), timeout=self.max_wait)
            except asyncio.TimeoutError:
                pass

            self._event.clear()

            # 获取当前批次
            async with self._lock:
                if not self._queue:
                    return

                batch = self._queue[: self.max_size]
                self._queue = self._queue[self.max_size :]

            # 处理批次
            items = [item for item, _ in batch]
            futures = [future for _, future in batch]

            try:
                results = await self.batch_func(items)
                for future, result in zip(futures, results):
                    if not future.done():
                        future.set_result(result)
            except Exception as e:
                for future in futures:
                    if not future.done():
                        future.set_exception(e)


async def async_first(
    coros: Sequence[Coroutine[Any, Any, T]], predicate: Optional[Callable[[T], bool]] = None
) -> Optional[T]:
    """
    返回第一个完成（或满足条件）的协程结果

    Args:
        coros: 协程序列
        predicate: 可选的过滤函数

    Returns:
        第一个满足条件的结果，或None
    """
    tasks = [asyncio.create_task(coro) for coro in coros]

    try:
        while tasks:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

            for task in done:
                try:
                    result = task.result()
                    if predicate is None or predicate(result):
                        # 取消其他任务
                        for t in pending:
                            t.cancel()
                        return result
                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            tasks = list(pending)

        return None
    finally:
        # 确保清理所有任务
        for task in tasks:
            if not task.done():
                task.cancel()


async def async_race(coros: Sequence[Coroutine[Any, Any, T]]) -> T:
    """
    返回第一个完成的协程结果（不管成功失败）

    类似于 JavaScript 的 Promise.race

    Args:
        coros: 协程序列

    Returns:
        第一个完成的结果

    Raises:
        如果第一个完成的协程抛出异常，则抛出该异常
    """
    tasks = [asyncio.create_task(coro) for coro in coros]

    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        # 取消其他任务
        for task in pending:
            task.cancel()

        # 返回第一个完成的结果
        return list(done)[0].result()

    finally:
        for task in tasks:
            if not task.done():
                task.cancel()


__all__ = [
    "run_sync",
    "ensure_async",
    "ensure_sync",
    "gather_with_limit",
    "timeout_wrapper",
    "async_retry",
    "run_in_executor",
    "async_map",
    "async_filter",
    "AsyncThrottle",
    "AsyncBatcher",
    "async_first",
    "async_race",
]
