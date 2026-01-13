#!/usr/bin/env python3
"""
异步执行器 - 统一的异步工具执行框架
支持并发控制、结果聚合、错误处理
"""

import asyncio
from typing import List, Dict, Any, Callable, Optional, Coroutine
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class Task:
    """任务数据类"""
    id: str
    name: str
    func: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    priority: int = 0  # 优先级，数字越大优先级越高
    timeout: int = 300  # 超时时间(秒)
    retry: int = 0  # 重试次数
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class TaskResult:
    """任务结果数据类"""
    task_id: str
    task_name: str
    success: bool
    result: Any = None
    error: Optional[str] = None
    duration: float = 0.0
    retries: int = 0
    completed_at: datetime = field(default_factory=datetime.now)


class AsyncExecutor:
    """
    异步执行器 - 统一的异步工具执行框架

    特性:
    - 并发控制 (Semaphore)
    - 优先级队列
    - 超时控制
    - 自动重试
    - 结果聚合
    - 进度追踪
    """

    def __init__(
        self,
        max_concurrency: int = 50,
        default_timeout: int = 300,
        enable_progress: bool = True
    ):
        """
        初始化异步执行器

        Args:
            max_concurrency: 最大并发数
            default_timeout: 默认超时时间(秒)
            enable_progress: 是否启用进度追踪
        """
        self.max_concurrency = max_concurrency
        self.default_timeout = default_timeout
        self.enable_progress = enable_progress

        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.tasks: List[Task] = []
        self.results: List[TaskResult] = []
        self.running_tasks: Dict[str, asyncio.Task] = {}

        # 统计信息
        self.stats = {
            "total": 0,
            "completed": 0,
            "failed": 0,
            "running": 0
        }

    def add_task(
        self,
        name: str,
        func: Callable,
        *args,
        priority: int = 0,
        timeout: int = None,
        retry: int = 0,
        **kwargs
    ) -> str:
        """
        添加任务

        Args:
            name: 任务名称
            func: 任务函数 (可以是同步或异步)
            *args: 位置参数
            priority: 优先级
            timeout: 超时时间
            retry: 重试次数
            **kwargs: 关键字参数

        Returns:
            任务ID
        """
        task_id = f"task_{len(self.tasks)}_{datetime.now().timestamp()}"

        task = Task(
            id=task_id,
            name=name,
            func=func,
            args=args,
            kwargs=kwargs,
            priority=priority,
            timeout=timeout or self.default_timeout,
            retry=retry
        )

        self.tasks.append(task)
        self.stats["total"] += 1

        logger.debug(f"添加任务: {name} (ID: {task_id})")
        return task_id

    async def _execute_task(self, task: Task) -> TaskResult:
        """
        执行单个任务 (内部方法)

        Args:
            task: 任务对象

        Returns:
            任务结果
        """
        async with self.semaphore:
            self.stats["running"] += 1
            start_time = asyncio.get_event_loop().time()
            retries = 0

            for attempt in range(task.retry + 1):
                try:
                    # 判断是否为协程函数
                    if asyncio.iscoroutinefunction(task.func):
                        result = await asyncio.wait_for(
                            task.func(*task.args, **task.kwargs),
                            timeout=task.timeout
                        )
                    else:
                        # 同步函数在线程池中执行
                        result = await asyncio.wait_for(
                            asyncio.to_thread(task.func, *task.args, **task.kwargs),
                            timeout=task.timeout
                        )

                    duration = asyncio.get_event_loop().time() - start_time
                    self.stats["running"] -= 1
                    self.stats["completed"] += 1

                    return TaskResult(
                        task_id=task.id,
                        task_name=task.name,
                        success=True,
                        result=result,
                        duration=duration,
                        retries=retries
                    )

                except asyncio.TimeoutError:
                    retries += 1
                    if attempt == task.retry:
                        duration = asyncio.get_event_loop().time() - start_time
                        self.stats["running"] -= 1
                        self.stats["failed"] += 1

                        logger.error(f"任务超时: {task.name} ({task.timeout}秒)")
                        return TaskResult(
                            task_id=task.id,
                            task_name=task.name,
                            success=False,
                            error=f"Timeout after {task.timeout}s",
                            duration=duration,
                            retries=retries
                        )
                    logger.warning(f"任务超时，重试 {attempt + 1}/{task.retry}: {task.name}")
                    await asyncio.sleep(1)

                except Exception as e:
                    retries += 1
                    if attempt == task.retry:
                        duration = asyncio.get_event_loop().time() - start_time
                        self.stats["running"] -= 1
                        self.stats["failed"] += 1

                        logger.error(f"任务失败: {task.name} - {e}")
                        return TaskResult(
                            task_id=task.id,
                            task_name=task.name,
                            success=False,
                            error=str(e),
                            duration=duration,
                            retries=retries
                        )
                    logger.warning(f"任务失败，重试 {attempt + 1}/{task.retry}: {task.name} - {e}")
                    await asyncio.sleep(1)

    async def execute_all(self) -> List[TaskResult]:
        """
        执行所有任务

        Returns:
            任务结果列表
        """
        if not self.tasks:
            logger.warning("没有待执行的任务")
            return []

        # 按优先级排序
        sorted_tasks = sorted(self.tasks, key=lambda t: t.priority, reverse=True)

        logger.info(f"开始执行 {len(sorted_tasks)} 个任务 (并发: {self.max_concurrency})")

        # 创建任务协程
        coroutines = [self._execute_task(task) for task in sorted_tasks]

        # 执行所有任务
        if self.enable_progress:
            results = await self._execute_with_progress(coroutines)
        else:
            results = await asyncio.gather(*coroutines, return_exceptions=False)

        self.results = results

        # 输出统计信息
        logger.info(
            f"任务执行完成: 总数={self.stats['total']}, "
            f"成功={self.stats['completed']}, "
            f"失败={self.stats['failed']}"
        )

        return results

    async def _execute_with_progress(self, coroutines: List[Coroutine]) -> List[TaskResult]:
        """带进度追踪的执行"""
        results = []
        total = len(coroutines)

        for i, coro in enumerate(asyncio.as_completed(coroutines), 1):
            result = await coro
            results.append(result)

            # 输出进度
            progress = (i / total) * 100
            logger.info(f"进度: {i}/{total} ({progress:.1f}%)")

        return results

    def get_results(self, success_only: bool = False) -> List[TaskResult]:
        """
        获取任务结果

        Args:
            success_only: 是否只返回成功的结果

        Returns:
            任务结果列表
        """
        if success_only:
            return [r for r in self.results if r.success]
        return self.results

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self.stats,
            "success_rate": (
                self.stats["completed"] / self.stats["total"]
                if self.stats["total"] > 0
                else 0
            )
        }

    def clear(self):
        """清空任务和结果"""
        self.tasks.clear()
        self.results.clear()
        self.running_tasks.clear()
        self.stats = {
            "total": 0,
            "completed": 0,
            "failed": 0,
            "running": 0
        }


# 使用示例
async def example_usage():
    """使用示例"""
    executor = AsyncExecutor(max_concurrency=10)

    # 添加任务
    async def async_task(url: str):
        await asyncio.sleep(1)
        return {"url": url, "status": 200}

    def sync_task(value: int):
        import time
        time.sleep(0.5)
        return value * 2

    # 添加异步任务
    for i in range(20):
        executor.add_task(
            f"async_task_{i}",
            async_task,
            f"https://example.com/{i}",
            priority=i % 3
        )

    # 添加同步任务
    for i in range(10):
        executor.add_task(
            f"sync_task_{i}",
            sync_task,
            i,
            priority=1
        )

    # 执行所有任务
    results = await executor.execute_all()

    # 获取成功的结果
    success_results = executor.get_results(success_only=True)
    print(f"成功: {len(success_results)}/{len(results)}")

    # 统计信息
    stats = executor.get_stats()
    print(f"统计: {stats}")


if __name__ == "__main__":
    asyncio.run(example_usage())
