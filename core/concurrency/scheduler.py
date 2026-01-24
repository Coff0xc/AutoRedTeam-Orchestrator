"""
任务调度器模块

提供延迟任务和周期任务的调度功能。
"""

import heapq
import time
import threading
import uuid
import asyncio
from typing import Callable, Optional, Any, List, Dict
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """任务状态"""
    PENDING = 'pending'       # 等待执行
    RUNNING = 'running'       # 正在执行
    COMPLETED = 'completed'   # 已完成
    FAILED = 'failed'         # 失败
    CANCELLED = 'cancelled'   # 已取消


@dataclass(order=True)
class ScheduledTask:
    """
    调度任务

    使用 dataclass 的 order=True 实现基于 run_at 的排序
    """
    run_at: float
    task_id: str = field(compare=False)
    fn: Callable = field(compare=False)
    args: tuple = field(compare=False, default=())
    kwargs: dict = field(compare=False, default_factory=dict)
    interval: Optional[float] = field(compare=False, default=None)
    name: str = field(compare=False, default='')
    status: TaskStatus = field(compare=False, default=TaskStatus.PENDING)
    created_at: float = field(compare=False, default_factory=time.monotonic)
    last_run: Optional[float] = field(compare=False, default=None)
    run_count: int = field(compare=False, default=0)
    error: Optional[str] = field(compare=False, default=None)

    def __post_init__(self):
        if not self.name:
            self.name = f"task_{self.task_id[:8]}"


class TaskScheduler:
    """
    任务调度器 - 支持延迟和周期任务

    特性:
    - 延迟执行
    - 周期执行
    - 任务取消
    - 任务状态追踪
    """

    def __init__(
        self,
        max_workers: int = 4,
        name: str = 'default'
    ):
        """
        初始化任务调度器

        Args:
            max_workers: 最大工作线程数
            name: 调度器名称
        """
        self.max_workers = max_workers
        self.name = name

        self._tasks: List[ScheduledTask] = []
        self._task_map: Dict[str, ScheduledTask] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._executor_pool: List[threading.Thread] = []

        logger.debug(f"调度器 '{name}' 已初始化")

    def schedule(
        self,
        fn: Callable,
        delay: float = 0,
        interval: Optional[float] = None,
        args: tuple = (),
        kwargs: Optional[dict] = None,
        name: Optional[str] = None
    ) -> str:
        """
        调度任务

        Args:
            fn: 要执行的函数
            delay: 延迟时间（秒）
            interval: 周期间隔（秒），None 表示只执行一次
            args: 位置参数
            kwargs: 关键字参数
            name: 任务名称

        Returns:
            任务 ID
        """
        task_id = str(uuid.uuid4())
        run_at = time.monotonic() + delay

        task = ScheduledTask(
            run_at=run_at,
            task_id=task_id,
            fn=fn,
            args=args,
            kwargs=kwargs if kwargs else {},
            interval=interval,
            name=name or f"task_{task_id[:8]}"
        )

        with self._condition:
            heapq.heappush(self._tasks, task)
            self._task_map[task_id] = task
            self._condition.notify()

        logger.debug(f"任务 '{task.name}' (ID: {task_id[:8]}) 已调度, "
                    f"将在 {delay:.2f}s 后执行"
                    + (f", 周期: {interval}s" if interval else ""))

        return task_id

    def schedule_at(
        self,
        fn: Callable,
        run_at: float,
        interval: Optional[float] = None,
        args: tuple = (),
        kwargs: Optional[dict] = None,
        name: Optional[str] = None
    ) -> str:
        """
        在指定时间调度任务

        Args:
            fn: 要执行的函数
            run_at: 执行时间（time.monotonic() 时间戳）
            interval: 周期间隔
            args: 位置参数
            kwargs: 关键字参数
            name: 任务名称

        Returns:
            任务 ID
        """
        delay = max(0, run_at - time.monotonic())
        return self.schedule(fn, delay, interval, args, kwargs, name)

    def cancel(self, task_id: str) -> bool:
        """
        取消任务

        Args:
            task_id: 任务 ID

        Returns:
            是否成功取消
        """
        with self._lock:
            if task_id in self._task_map:
                task = self._task_map[task_id]
                if task.status == TaskStatus.PENDING:
                    task.status = TaskStatus.CANCELLED
                    logger.debug(f"任务 '{task.name}' 已取消")
                    return True
        return False

    def get_task(self, task_id: str) -> Optional[ScheduledTask]:
        """
        获取任务信息

        Args:
            task_id: 任务 ID

        Returns:
            任务对象或 None
        """
        with self._lock:
            return self._task_map.get(task_id)

    def list_tasks(
        self,
        status: Optional[TaskStatus] = None
    ) -> List[Dict[str, Any]]:
        """
        列出任务

        Args:
            status: 按状态过滤

        Returns:
            任务信息列表
        """
        with self._lock:
            tasks = []
            for task in self._task_map.values():
                if status is None or task.status == status:
                    tasks.append({
                        'task_id': task.task_id,
                        'name': task.name,
                        'status': task.status.value,
                        'run_at': task.run_at,
                        'interval': task.interval,
                        'run_count': task.run_count,
                        'last_run': task.last_run,
                        'error': task.error
                    })
            return tasks

    def _execute_task(self, task: ScheduledTask) -> None:
        """执行任务"""
        try:
            task.status = TaskStatus.RUNNING
            task.fn(*task.args, **task.kwargs)
            task.status = TaskStatus.COMPLETED
            task.run_count += 1
            task.last_run = time.monotonic()
            task.error = None

            logger.debug(f"任务 '{task.name}' 执行成功 (第 {task.run_count} 次)")

        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            logger.warning(f"任务 '{task.name}' 执行失败: {e}")

        # 处理周期任务
        if task.interval is not None and task.status != TaskStatus.CANCELLED:
            task.run_at = time.monotonic() + task.interval
            task.status = TaskStatus.PENDING

            with self._condition:
                heapq.heappush(self._tasks, task)
                self._condition.notify()

    def _scheduler_loop(self) -> None:
        """调度器主循环"""
        logger.debug(f"调度器 '{self.name}' 主循环已启动")

        while self._running:
            with self._condition:
                while self._running:
                    # 检查是否有待执行的任务
                    if not self._tasks:
                        self._condition.wait(timeout=1.0)
                        continue

                    # 获取最早的任务
                    next_task = self._tasks[0]

                    # 检查是否被取消
                    if next_task.status == TaskStatus.CANCELLED:
                        heapq.heappop(self._tasks)
                        continue

                    # 计算等待时间
                    now = time.monotonic()
                    wait_time = next_task.run_at - now

                    if wait_time <= 0:
                        # 任务到期，执行
                        task = heapq.heappop(self._tasks)

                        # 在新线程中执行任务
                        executor = threading.Thread(
                            target=self._execute_task,
                            args=(task,),
                            daemon=True
                        )
                        executor.start()
                        self._executor_pool = [
                            t for t in self._executor_pool if t.is_alive()
                        ]
                        self._executor_pool.append(executor)
                    else:
                        # 等待直到任务到期或有新任务
                        self._condition.wait(timeout=min(wait_time, 1.0))

        logger.debug(f"调度器 '{self.name}' 主循环已停止")

    def start(self) -> None:
        """启动调度器"""
        with self._lock:
            if self._running:
                return

            self._running = True
            self._thread = threading.Thread(
                target=self._scheduler_loop,
                name=f"scheduler-{self.name}",
                daemon=True
            )
            self._thread.start()
            logger.info(f"调度器 '{self.name}' 已启动")

    def stop(self, wait: bool = True, timeout: float = 5.0) -> None:
        """
        停止调度器

        Args:
            wait: 是否等待执行中的任务完成
            timeout: 等待超时时间
        """
        with self._condition:
            if not self._running:
                return

            self._running = False
            self._condition.notify_all()

        if self._thread is not None:
            self._thread.join(timeout=timeout)

        # 等待执行中的任务
        if wait:
            for executor in self._executor_pool:
                executor.join(timeout=timeout / max(1, len(self._executor_pool)))

        logger.info(f"调度器 '{self.name}' 已停止")

    def clear(self) -> int:
        """
        清除所有待执行任务

        Returns:
            清除的任务数量
        """
        with self._lock:
            count = 0
            for task in list(self._task_map.values()):
                if task.status == TaskStatus.PENDING:
                    task.status = TaskStatus.CANCELLED
                    count += 1

            self._tasks = [
                t for t in self._tasks
                if t.status != TaskStatus.CANCELLED
            ]
            heapq.heapify(self._tasks)

            return count

    @property
    def is_running(self) -> bool:
        """调度器是否运行中"""
        return self._running

    @property
    def stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._lock:
            status_counts = {}
            for task in self._task_map.values():
                status = task.status.value
                status_counts[status] = status_counts.get(status, 0) + 1

            return {
                'name': self.name,
                'is_running': self._running,
                'total_tasks': len(self._task_map),
                'pending_tasks': len(self._tasks),
                'status_counts': status_counts
            }

    def __enter__(self) -> 'TaskScheduler':
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop(wait=True)

    def __del__(self) -> None:
        if self._running:
            self.stop(wait=False)


class AsyncTaskScheduler:
    """
    异步任务调度器

    用于调度异步任务
    """

    def __init__(self, name: str = 'async_default'):
        """
        初始化异步任务调度器

        Args:
            name: 调度器名称
        """
        self.name = name
        self._tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()

    async def schedule(
        self,
        coro: Any,
        delay: float = 0,
        name: Optional[str] = None
    ) -> str:
        """
        调度异步任务

        Args:
            coro: 协程对象
            delay: 延迟时间
            name: 任务名称

        Returns:
            任务 ID
        """
        task_id = str(uuid.uuid4())
        task_name = name or f"async_task_{task_id[:8]}"

        async def delayed_task():
            if delay > 0:
                await asyncio.sleep(delay)
            return await coro

        async with self._lock:
            task = asyncio.create_task(delayed_task(), name=task_name)
            self._tasks[task_id] = task

            # 任务完成后清理
            task.add_done_callback(
                lambda t: asyncio.create_task(self._cleanup(task_id))
            )

        logger.debug(f"异步任务 '{task_name}' 已调度")
        return task_id

    async def schedule_periodic(
        self,
        fn: Callable,
        interval: float,
        args: tuple = (),
        kwargs: Optional[dict] = None,
        name: Optional[str] = None,
        max_iterations: Optional[int] = None
    ) -> str:
        """
        调度周期异步任务

        Args:
            fn: 异步函数
            interval: 周期间隔
            args: 位置参数
            kwargs: 关键字参数
            name: 任务名称
            max_iterations: 最大执行次数

        Returns:
            任务 ID
        """
        task_id = str(uuid.uuid4())
        task_name = name or f"periodic_{task_id[:8]}"
        kwargs = kwargs or {}

        async def periodic_task():
            iteration = 0
            while True:
                try:
                    if asyncio.iscoroutinefunction(fn):
                        await fn(*args, **kwargs)
                    else:
                        fn(*args, **kwargs)

                    iteration += 1
                    if max_iterations and iteration >= max_iterations:
                        break

                    await asyncio.sleep(interval)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.warning(f"周期任务 '{task_name}' 执行失败: {e}")
                    await asyncio.sleep(interval)

        async with self._lock:
            task = asyncio.create_task(periodic_task(), name=task_name)
            self._tasks[task_id] = task

        logger.debug(f"周期异步任务 '{task_name}' 已调度, 间隔: {interval}s")
        return task_id

    async def _cleanup(self, task_id: str) -> None:
        """清理已完成的任务"""
        async with self._lock:
            if task_id in self._tasks:
                del self._tasks[task_id]

    async def cancel(self, task_id: str) -> bool:
        """
        取消任务

        Args:
            task_id: 任务 ID

        Returns:
            是否成功取消
        """
        async with self._lock:
            if task_id in self._tasks:
                task = self._tasks[task_id]
                task.cancel()
                del self._tasks[task_id]
                return True
        return False

    async def cancel_all(self) -> int:
        """
        取消所有任务

        Returns:
            取消的任务数量
        """
        async with self._lock:
            count = len(self._tasks)
            for task in self._tasks.values():
                task.cancel()
            self._tasks.clear()
            return count

    async def wait_task(
        self,
        task_id: str,
        timeout: Optional[float] = None
    ) -> Any:
        """
        等待任务完成

        Args:
            task_id: 任务 ID
            timeout: 超时时间

        Returns:
            任务结果

        Raises:
            KeyError: 任务不存在
            asyncio.TimeoutError: 超时
        """
        async with self._lock:
            if task_id not in self._tasks:
                raise KeyError(f"任务 {task_id} 不存在")
            task = self._tasks[task_id]

        return await asyncio.wait_for(task, timeout=timeout)

    @property
    def pending_count(self) -> int:
        """待执行任务数"""
        return len(self._tasks)


# 全局调度器
_global_scheduler: Optional[TaskScheduler] = None
_scheduler_lock = threading.Lock()


def get_scheduler() -> TaskScheduler:
    """获取全局调度器"""
    global _global_scheduler

    with _scheduler_lock:
        if _global_scheduler is None:
            _global_scheduler = TaskScheduler(name='global')
            _global_scheduler.start()
        return _global_scheduler


def schedule_task(
    fn: Callable,
    delay: float = 0,
    interval: Optional[float] = None,
    args: tuple = (),
    kwargs: Optional[dict] = None,
    name: Optional[str] = None
) -> str:
    """
    使用全局调度器调度任务

    Args:
        fn: 要执行的函数
        delay: 延迟时间
        interval: 周期间隔
        args: 位置参数
        kwargs: 关键字参数
        name: 任务名称

    Returns:
        任务 ID
    """
    return get_scheduler().schedule(
        fn=fn,
        delay=delay,
        interval=interval,
        args=args,
        kwargs=kwargs,
        name=name
    )


def cancel_task(task_id: str) -> bool:
    """
    取消全局调度器中的任务

    Args:
        task_id: 任务 ID

    Returns:
        是否成功取消
    """
    return get_scheduler().cancel(task_id)
