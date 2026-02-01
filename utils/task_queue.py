#!/usr/bin/env python3
"""
轻量级任务队列 - 支持后台异步任务管理
基于 queue.Queue + threading 实现，无外部依赖
"""

import queue
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class TaskStatus(Enum):
    """任务状态"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Task:
    """任务数据类"""

    id: str
    func: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: str = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    started_at: str = None
    completed_at: str = None


class TaskQueue:
    """
    单例任务队列
    - 3个后台worker处理任务
    - 支持任务提交、状态查询、取消
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self._queue = queue.Queue()
        self._tasks: Dict[str, Task] = {}
        self._workers: List[threading.Thread] = []
        self._running = True
        self._start_workers(3)

    def _start_workers(self, num_workers: int):
        """启动后台worker线程"""
        for i in range(num_workers):
            worker = threading.Thread(target=self._worker_loop, daemon=True, name=f"TaskWorker-{i}")
            worker.start()
            self._workers.append(worker)

    def _worker_loop(self):
        """Worker主循环"""
        while self._running:
            try:
                task = self._queue.get(timeout=1)
                if task is None:
                    continue

                # 检查是否已取消
                if task.status == TaskStatus.CANCELLED:
                    self._queue.task_done()
                    continue

                # 执行任务
                task.status = TaskStatus.RUNNING
                task.started_at = datetime.now().isoformat()

                try:
                    task.result = task.func(*task.args, **task.kwargs)
                    task.status = TaskStatus.COMPLETED
                except Exception as e:
                    task.status = TaskStatus.FAILED
                    task.error = f"{type(e).__name__}: {str(e)}"

                task.completed_at = datetime.now().isoformat()
                self._queue.task_done()

            except queue.Empty:
                continue
            except Exception:
                continue

    def submit(self, func: Callable, *args, **kwargs) -> str:
        """
        提交任务到队列

        Args:
            func: 要执行的函数
            *args: 位置参数
            **kwargs: 关键字参数

        Returns:
            task_id: 任务ID
        """
        task_id = str(uuid.uuid4())[:8]
        task = Task(id=task_id, func=func, args=args, kwargs=kwargs)
        self._tasks[task_id] = task
        self._queue.put(task)
        return task_id

    def get_status(self, task_id: str) -> dict:
        """
        获取任务状态

        Args:
            task_id: 任务ID

        Returns:
            任务状态信息
        """
        task = self._tasks.get(task_id)
        if not task:
            return {"success": False, "error": f"任务不存在: {task_id}"}

        return {
            "success": True,
            "task_id": task.id,
            "status": task.status.value,
            "created_at": task.created_at,
            "started_at": task.started_at,
            "completed_at": task.completed_at,
            "result": task.result if task.status == TaskStatus.COMPLETED else None,
            "error": task.error if task.status == TaskStatus.FAILED else None,
        }

    def cancel(self, task_id: str) -> dict:
        """
        取消任务 (仅限PENDING状态)

        Args:
            task_id: 任务ID

        Returns:
            操作结果
        """
        task = self._tasks.get(task_id)
        if not task:
            return {"success": False, "error": f"任务不存在: {task_id}"}

        if task.status == TaskStatus.PENDING:
            task.status = TaskStatus.CANCELLED
            return {"success": True, "message": f"任务 {task_id} 已取消"}
        elif task.status == TaskStatus.RUNNING:
            return {"success": False, "error": "任务正在执行中，无法取消"}
        else:
            return {"success": False, "error": f"任务已完成，状态: {task.status.value}"}

    def list_tasks(self, limit: int = 20) -> dict:
        """
        列出所有任务

        Args:
            limit: 返回数量限制

        Returns:
            任务列表
        """
        tasks = []
        for task_id, task in list(self._tasks.items())[-limit:]:
            tasks.append(
                {
                    "task_id": task.id,
                    "status": task.status.value,
                    "created_at": task.created_at,
                    "completed_at": task.completed_at,
                }
            )

        # 统计
        stats = {
            "pending": sum(1 for t in self._tasks.values() if t.status == TaskStatus.PENDING),
            "running": sum(1 for t in self._tasks.values() if t.status == TaskStatus.RUNNING),
            "completed": sum(1 for t in self._tasks.values() if t.status == TaskStatus.COMPLETED),
            "failed": sum(1 for t in self._tasks.values() if t.status == TaskStatus.FAILED),
            "cancelled": sum(1 for t in self._tasks.values() if t.status == TaskStatus.CANCELLED),
        }

        return {
            "success": True,
            "total": len(self._tasks),
            "stats": stats,
            "tasks": tasks,
        }

    def clear_completed(self) -> dict:
        """清理已完成的任务"""
        to_remove = [
            tid
            for tid, task in self._tasks.items()
            if task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED)
        ]
        for tid in to_remove:
            del self._tasks[tid]

        return {"success": True, "cleared": len(to_remove)}


# 全局单例
_task_queue: Optional[TaskQueue] = None


def get_task_queue() -> TaskQueue:
    """获取全局任务队列实例"""
    global _task_queue
    if _task_queue is None:
        _task_queue = TaskQueue()
    return _task_queue
