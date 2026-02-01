"""
线程池/进程池管理模块

提供动态线程池和异步任务池，支持自动负载调整和批量任务处理。
"""

import asyncio
import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Coroutine,
    Dict,
    Iterator,
    List,
    Optional,
    Tuple,
    TypeVar,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")


@dataclass
class PoolMetrics:
    """线程池指标"""

    submitted_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    total_execution_time: float = 0.0
    peak_workers: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_submit(self) -> None:
        """记录任务提交"""
        with self._lock:
            self.submitted_tasks += 1

    def record_complete(self, execution_time: float, success: bool = True) -> None:
        """记录任务完成"""
        with self._lock:
            self.completed_tasks += 1
            self.total_execution_time += execution_time
            if not success:
                self.failed_tasks += 1

    def update_peak_workers(self, current: int) -> None:
        """更新峰值工作线程数"""
        with self._lock:
            if current > self.peak_workers:
                self.peak_workers = current

    @property
    def success_rate(self) -> float:
        """成功率"""
        with self._lock:
            if self.completed_tasks == 0:
                return 1.0
            return (self.completed_tasks - self.failed_tasks) / self.completed_tasks

    @property
    def avg_execution_time(self) -> float:
        """平均执行时间"""
        with self._lock:
            if self.completed_tasks == 0:
                return 0.0
            return self.total_execution_time / self.completed_tasks

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        with self._lock:
            return {
                "submitted_tasks": self.submitted_tasks,
                "completed_tasks": self.completed_tasks,
                "failed_tasks": self.failed_tasks,
                "pending_tasks": self.submitted_tasks - self.completed_tasks,
                "success_rate": self.success_rate,
                "avg_execution_time": self.avg_execution_time,
                "total_execution_time": self.total_execution_time,
                "peak_workers": self.peak_workers,
            }


class TaskWrapper:
    """任务包装器 - 用于追踪执行时间和状态"""

    def __init__(
        self,
        fn: Callable,
        args: tuple,
        kwargs: dict,
        metrics: PoolMetrics,
        callback: Optional[Callable] = None,
    ):
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.metrics = metrics
        self.callback = callback
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

    def __call__(self) -> Any:
        """执行任务"""
        self.start_time = time.monotonic()
        success = True
        result = None
        error = None

        try:
            result = self.fn(*self.args, **self.kwargs)
            return result
        except Exception as e:
            success = False
            error = e
            raise
        finally:
            self.end_time = time.monotonic()
            execution_time = self.end_time - self.start_time
            self.metrics.record_complete(execution_time, success)

            # 执行回调
            if self.callback is not None:
                try:
                    self.callback(result if success else None, error)
                except Exception as cb_err:
                    logger.warning(f"回调执行失败: {cb_err}")


class DynamicThreadPool:
    """
    动态线程池 - 根据负载自动调整工作线程数

    特性:
    - 自动扩缩容
    - 任务队列管理
    - 性能指标收集
    - 优雅关闭
    """

    def __init__(
        self,
        min_workers: int = 2,
        max_workers: int = 20,
        queue_size: int = 1000,
        name: str = "default",
        scale_up_threshold: float = 0.8,
        scale_down_threshold: float = 0.3,
    ):
        """
        初始化动态线程池

        Args:
            min_workers: 最小工作线程数
            max_workers: 最大工作线程数
            queue_size: 任务队列大小
            name: 线程池名称
            scale_up_threshold: 扩容阈值（队列使用率）
            scale_down_threshold: 缩容阈值
        """
        if min_workers < 1:
            raise ValueError("min_workers 必须大于等于 1")
        if max_workers < min_workers:
            raise ValueError("max_workers 必须大于等于 min_workers")

        self.min_workers = min_workers
        self.max_workers = max_workers
        self.queue_size = queue_size
        self.name = name
        self.scale_up_threshold = scale_up_threshold
        self.scale_down_threshold = scale_down_threshold

        self._executor: Optional[ThreadPoolExecutor] = None
        self._current_workers = min_workers
        self._lock = threading.RLock()
        self._metrics = PoolMetrics()
        self._shutdown = False
        self._pending_count = 0
        self._pending_lock = threading.Lock()

        # 启动线程池
        self._initialize_executor()

        logger.info(f"线程池 '{name}' 已初始化: workers={min_workers}-{max_workers}")

    def _initialize_executor(self) -> None:
        """初始化执行器"""
        with self._lock:
            if self._executor is not None:
                return

            self._executor = ThreadPoolExecutor(
                max_workers=self._current_workers, thread_name_prefix=f"{self.name}-worker"
            )
            self._shutdown = False

    def _adjust_pool_size(self) -> None:
        """根据负载调整线程池大小"""
        with self._pending_lock:
            pending = self._pending_count

        with self._lock:
            if self._shutdown or self._executor is None:
                return

            # 计算负载率
            load_ratio = pending / max(self._current_workers, 1)

            # 扩容条件
            if load_ratio > self.scale_up_threshold and self._current_workers < self.max_workers:
                new_size = min(
                    self._current_workers + max(2, self._current_workers // 4), self.max_workers
                )
                if new_size != self._current_workers:
                    self._resize_pool(new_size)
                    logger.debug(
                        f"线程池 '{self.name}' 扩容: {self._current_workers} -> {new_size}"
                    )

            # 缩容条件
            elif (
                load_ratio < self.scale_down_threshold and self._current_workers > self.min_workers
            ):
                new_size = max(
                    self._current_workers - max(1, self._current_workers // 4), self.min_workers
                )
                if new_size != self._current_workers:
                    self._resize_pool(new_size)
                    logger.debug(
                        f"线程池 '{self.name}' 缩容: {self._current_workers} -> {new_size}"
                    )

    def _resize_pool(self, new_size: int) -> None:
        """调整线程池大小"""
        # ThreadPoolExecutor 不支持动态调整，需要创建新的
        # 这里使用 _max_workers 属性进行软调整
        if self._executor is not None:
            self._executor._max_workers = new_size
            self._current_workers = new_size
            self._metrics.update_peak_workers(new_size)

    def submit(
        self,
        fn: Callable[..., R],
        *args: Any,
        callback: Optional[Callable[[Optional[R], Optional[Exception]], None]] = None,
        **kwargs: Any,
    ) -> Future[R]:
        """
        提交任务到线程池

        Args:
            fn: 要执行的函数
            *args: 位置参数
            callback: 完成回调函数
            **kwargs: 关键字参数

        Returns:
            Future 对象
        """
        with self._lock:
            if self._shutdown:
                raise RuntimeError(f"线程池 '{self.name}' 已关闭")

            if self._executor is None:
                self._initialize_executor()

        # 更新待处理计数
        with self._pending_lock:
            self._pending_count += 1

        # 记录提交
        self._metrics.record_submit()

        # 包装任务
        wrapper = TaskWrapper(fn, args, kwargs, self._metrics, callback)

        # 提交任务
        future = self._executor.submit(wrapper)

        # 添加完成回调以更新计数
        def on_complete(f: Future) -> None:
            with self._pending_lock:
                self._pending_count -= 1
            # 尝试调整池大小
            self._adjust_pool_size()

        future.add_done_callback(on_complete)

        # 检查是否需要扩容
        self._adjust_pool_size()

        return future

    def map(
        self,
        fn: Callable[[T], R],
        items: List[T],
        timeout: Optional[float] = None,
        chunksize: int = 1,
    ) -> Iterator[R]:
        """
        批量映射执行

        Args:
            fn: 映射函数
            items: 输入项列表
            timeout: 超时时间（秒）
            chunksize: 分块大小

        Yields:
            执行结果（按完成顺序）
        """
        with self._lock:
            if self._shutdown:
                raise RuntimeError(f"线程池 '{self.name}' 已关闭")

            if self._executor is None:
                self._initialize_executor()

        # 使用 executor.map
        return self._executor.map(fn, items, timeout=timeout, chunksize=chunksize)

    def map_unordered(
        self, fn: Callable[[T], R], items: List[T], timeout: Optional[float] = None
    ) -> Iterator[R]:
        """
        批量映射执行（按完成顺序返回）

        Args:
            fn: 映射函数
            items: 输入项列表
            timeout: 超时时间

        Yields:
            执行结果（按完成顺序）
        """
        futures = [self.submit(fn, item) for item in items]

        for future in as_completed(futures, timeout=timeout):
            try:
                yield future.result()
            except Exception as e:
                logger.warning(f"任务执行失败: {e}")
                yield None

    def batch_submit(
        self,
        tasks: List[Tuple[Callable, tuple, dict]],
        callback: Optional[Callable[[List[Any]], None]] = None,
    ) -> List[Future]:
        """
        批量提交任务

        Args:
            tasks: 任务列表 [(fn, args, kwargs), ...]
            callback: 所有任务完成后的回调

        Returns:
            Future 列表
        """
        futures: List[Future] = []
        results: List[Any] = []
        results_lock = threading.Lock()
        remaining = len(tasks)
        remaining_lock = threading.Lock()

        def task_callback(result: Any, error: Optional[Exception]) -> None:
            nonlocal remaining
            with results_lock:
                results.append(result if error is None else error)

            with remaining_lock:
                remaining -= 1
                if remaining == 0 and callback is not None:
                    try:
                        callback(results)
                    except Exception as e:
                        logger.warning(f"批量回调执行失败: {e}")

        for task in tasks:
            if len(task) == 2:
                fn, args = task
                kwargs = {}
            else:
                fn, args, kwargs = task

            future = self.submit(fn, *args, callback=task_callback, **kwargs)
            futures.append(future)

        return futures

    def wait_all(
        self, futures: List[Future], timeout: Optional[float] = None
    ) -> Tuple[List[Any], List[Exception]]:
        """
        等待所有任务完成

        Args:
            futures: Future 列表
            timeout: 超时时间

        Returns:
            (结果列表, 异常列表)
        """
        results: List[Any] = []
        errors: List[Exception] = []

        for future in as_completed(futures, timeout=timeout):
            try:
                results.append(future.result())
            except Exception as e:
                errors.append(e)

        return results, errors

    def shutdown(self, wait: bool = True, cancel_pending: bool = False) -> None:
        """
        关闭线程池

        Args:
            wait: 是否等待所有任务完成
            cancel_pending: 是否取消待处理任务
        """
        with self._lock:
            if self._shutdown:
                return

            self._shutdown = True

            if self._executor is not None:
                logger.info(f"正在关闭线程池 '{self.name}'...")
                self._executor.shutdown(wait=wait, cancel_futures=cancel_pending)
                self._executor = None
                logger.info(f"线程池 '{self.name}' 已关闭")

    @property
    def stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._pending_lock:
            pending = self._pending_count

        return {
            "name": self.name,
            "current_workers": self._current_workers,
            "min_workers": self.min_workers,
            "max_workers": self.max_workers,
            "pending_tasks": pending,
            "is_shutdown": self._shutdown,
            "metrics": self._metrics.to_dict(),
        }

    @property
    def is_shutdown(self) -> bool:
        """是否已关闭"""
        return self._shutdown

    def __enter__(self) -> "DynamicThreadPool":
        return self

    def __exit__(self, exc_type, _exc_val, _exc_tb) -> None:
        self.shutdown(wait=True)

    def __del__(self) -> None:
        self.shutdown(wait=False)


class AsyncPool:
    """
    异步任务池

    用于管理和限制并发协程的执行数量
    """

    def __init__(self, concurrency: int = 10):
        """
        初始化异步任务池

        Args:
            concurrency: 最大并发数
        """
        if concurrency < 1:
            raise ValueError("concurrency 必须大于等于 1")

        self.concurrency = concurrency
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._metrics = PoolMetrics()

    def _get_semaphore(self) -> asyncio.Semaphore:
        """获取或创建信号量"""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)
        return self._semaphore

    async def _run_with_semaphore(self, coro: Coroutine, return_exceptions: bool = True) -> Any:
        """使用信号量运行协程"""
        semaphore = self._get_semaphore()
        start_time = time.monotonic()

        async with semaphore:
            self._metrics.record_submit()
            try:
                result = await coro
                self._metrics.record_complete(time.monotonic() - start_time, success=True)
                return result
            except Exception as e:
                self._metrics.record_complete(time.monotonic() - start_time, success=False)
                if return_exceptions:
                    return e
                raise

    async def run(self, coros: List[Coroutine], return_exceptions: bool = True) -> List[Any]:
        """
        并发执行协程列表

        Args:
            coros: 协程列表
            return_exceptions: 是否将异常作为结果返回

        Returns:
            结果列表（保持输入顺序）
        """
        if not coros:
            return []

        tasks = [self._run_with_semaphore(coro, return_exceptions) for coro in coros]

        return await asyncio.gather(*tasks, return_exceptions=return_exceptions)

    async def run_with_timeout(
        self, coros: List[Coroutine], timeout: float, return_exceptions: bool = True
    ) -> List[Any]:
        """
        带超时的并发执行

        Args:
            coros: 协程列表
            timeout: 超时时间（秒）
            return_exceptions: 是否将异常作为结果返回

        Returns:
            结果列表
        """
        try:
            return await asyncio.wait_for(self.run(coros, return_exceptions), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(f"批量任务超时 ({timeout}s)")
            return [asyncio.TimeoutError(f"超时 {timeout}s")] * len(coros)

    async def map(
        self,
        fn: Callable[[T], Coroutine[Any, Any, R]],
        items: List[T],
        return_exceptions: bool = True,
    ) -> List[R]:
        """
        异步批量映射

        Args:
            fn: 异步映射函数
            items: 输入项列表
            return_exceptions: 是否将异常作为结果返回

        Returns:
            结果列表
        """
        coros = [fn(item) for item in items]
        return await self.run(coros, return_exceptions)

    async def map_unordered(
        self, fn: Callable[[T], Coroutine[Any, Any, R]], items: List[T]
    ) -> AsyncIterator[Tuple[T, R]]:
        """
        异步批量映射（按完成顺序返回）

        Args:
            fn: 异步映射函数
            items: 输入项列表

        Yields:
            (输入项, 结果) 元组
        """
        semaphore = self._get_semaphore()

        async def wrapped(item: T) -> Tuple[T, Any]:
            async with semaphore:
                try:
                    result = await fn(item)
                    return (item, result)
                except Exception as e:
                    return (item, e)

        tasks = {asyncio.create_task(wrapped(item)): item for item in items}

        while tasks:
            done, _ = await asyncio.wait(tasks.keys(), return_when=asyncio.FIRST_COMPLETED)

            for task in done:
                del tasks[task]
                yield task.result()

    @property
    def stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {"concurrency": self.concurrency, "metrics": self._metrics.to_dict()}


# 全局线程池
_default_pool: Optional[DynamicThreadPool] = None
_pool_lock = threading.Lock()


def get_pool(min_workers: int = 2, max_workers: int = 20) -> DynamicThreadPool:
    """
    获取默认线程池

    Args:
        min_workers: 最小工作线程数（仅首次创建时有效）
        max_workers: 最大工作线程数（仅首次创建时有效）

    Returns:
        DynamicThreadPool 实例
    """
    global _default_pool

    with _pool_lock:
        if _default_pool is None or _default_pool.is_shutdown:
            _default_pool = DynamicThreadPool(
                min_workers=min_workers, max_workers=max_workers, name="global"
            )
        return _default_pool


def shutdown_default_pool(wait: bool = True) -> None:
    """关闭默认线程池"""
    global _default_pool

    with _pool_lock:
        if _default_pool is not None:
            _default_pool.shutdown(wait=wait)
            _default_pool = None


@contextmanager
def thread_pool(
    min_workers: int = 2, max_workers: int = 20, name: str = "temp"
) -> Iterator[DynamicThreadPool]:
    """
    临时线程池上下文管理器

    Args:
        min_workers: 最小工作线程数
        max_workers: 最大工作线程数
        name: 线程池名称

    Yields:
        DynamicThreadPool 实例
    """
    pool = DynamicThreadPool(min_workers=min_workers, max_workers=max_workers, name=name)

    try:
        yield pool
    finally:
        pool.shutdown(wait=True)


# 便捷函数
def parallel_map(
    fn: Callable[[T], R], items: List[T], workers: int = 10, timeout: Optional[float] = None
) -> List[R]:
    """
    并行映射函数

    Args:
        fn: 映射函数
        items: 输入项列表
        workers: 工作线程数
        timeout: 超时时间

    Returns:
        结果列表
    """
    with thread_pool(min_workers=workers, max_workers=workers, name="parallel_map") as pool:
        return list(pool.map(fn, items, timeout=timeout))


async def async_parallel_map(
    fn: Callable[[T], Coroutine[Any, Any, R]], items: List[T], concurrency: int = 10
) -> List[R]:
    """
    异步并行映射函数

    Args:
        fn: 异步映射函数
        items: 输入项列表
        concurrency: 并发数

    Returns:
        结果列表
    """
    pool = AsyncPool(concurrency=concurrency)
    return await pool.map(fn, items)
