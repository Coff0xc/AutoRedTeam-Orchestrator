#!/usr/bin/env python3
"""
可靠性模块
提供重试机制、断点续传、故障恢复等功能
"""

import os
import json
import time
import asyncio
import threading
import logging
import hashlib
import tempfile
from typing import Any, Dict, List, Optional, Callable, TypeVar, Union
from dataclasses import dataclass, field, asdict
from pathlib import Path
from functools import wraps
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)

T = TypeVar('T')


# ============== 重试策略 ==============

class RetryStrategy(Enum):
    """重试策略"""
    FIXED = "fixed"              # 固定间隔
    EXPONENTIAL = "exponential"  # 指数退避
    LINEAR = "linear"            # 线性增长
    FIBONACCI = "fibonacci"      # 斐波那契


@dataclass
class RetryPolicy:
    """
    重试策略配置

    特性:
    - 多种退避策略
    - 可配置重试条件
    - 支持异步
    - 详细统计
    """
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    jitter: float = 0.1  # 随机抖动比例
    retryable_exceptions: tuple = (Exception,)
    retry_on_result: Optional[Callable[[Any], bool]] = None

    def get_delay(self, attempt: int) -> float:
        """计算重试延迟"""
        import random

        if self.strategy == RetryStrategy.FIXED:
            delay = self.base_delay
        elif self.strategy == RetryStrategy.EXPONENTIAL:
            delay = self.base_delay * (2 ** attempt)
        elif self.strategy == RetryStrategy.LINEAR:
            delay = self.base_delay * (attempt + 1)
        elif self.strategy == RetryStrategy.FIBONACCI:
            a, b = 1, 1
            for _ in range(attempt):
                a, b = b, a + b
            delay = self.base_delay * a
        else:
            delay = self.base_delay

        # 添加抖动
        if self.jitter > 0:
            jitter_range = delay * self.jitter
            delay += random.uniform(-jitter_range, jitter_range)

        return min(delay, self.max_delay)

    def should_retry(self, exception: Optional[Exception], result: Any) -> bool:
        """判断是否应该重试"""
        if exception:
            return isinstance(exception, self.retryable_exceptions)
        if self.retry_on_result:
            return self.retry_on_result(result)
        return False


class RetryExecutor:
    """重试执行器"""

    def __init__(self, policy: Optional[RetryPolicy] = None):
        self.policy = policy or RetryPolicy()
        self._stats = {
            "total_calls": 0,
            "successful_calls": 0,
            "failed_calls": 0,
            "total_retries": 0
        }

    def execute(self, func: Callable, *args, **kwargs) -> Any:
        """同步执行带重试"""
        self._stats["total_calls"] += 1
        last_exception = None

        for attempt in range(self.policy.max_retries + 1):
            try:
                result = func(*args, **kwargs)

                # 检查结果是否需要重试
                if self.policy.should_retry(None, result):
                    if attempt < self.policy.max_retries:
                        delay = self.policy.get_delay(attempt)
                        logger.debug(f"结果触发重试，等待 {delay:.2f}s (尝试 {attempt + 1})")
                        time.sleep(delay)
                        self._stats["total_retries"] += 1
                        continue

                self._stats["successful_calls"] += 1
                return result

            except self.policy.retryable_exceptions as e:
                last_exception = e
                if attempt < self.policy.max_retries:
                    delay = self.policy.get_delay(attempt)
                    logger.warning(f"执行失败: {e}，等待 {delay:.2f}s 后重试 (尝试 {attempt + 1})")
                    time.sleep(delay)
                    self._stats["total_retries"] += 1
                else:
                    logger.error(f"重试次数耗尽: {e}")

        self._stats["failed_calls"] += 1
        if last_exception:
            raise last_exception
        raise RuntimeError("重试次数耗尽")

    async def async_execute(self, func: Callable, *args, **kwargs) -> Any:
        """异步执行带重试"""
        self._stats["total_calls"] += 1
        last_exception = None

        for attempt in range(self.policy.max_retries + 1):
            try:
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

                if self.policy.should_retry(None, result):
                    if attempt < self.policy.max_retries:
                        delay = self.policy.get_delay(attempt)
                        await asyncio.sleep(delay)
                        self._stats["total_retries"] += 1
                        continue

                self._stats["successful_calls"] += 1
                return result

            except self.policy.retryable_exceptions as e:
                last_exception = e
                if attempt < self.policy.max_retries:
                    delay = self.policy.get_delay(attempt)
                    await asyncio.sleep(delay)
                    self._stats["total_retries"] += 1

        self._stats["failed_calls"] += 1
        if last_exception:
            raise last_exception
        raise RuntimeError("重试次数耗尽")

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "retry_rate": self._stats["total_retries"] / max(self._stats["total_calls"], 1)
        }


def retry_with_policy(
    policy: Optional[RetryPolicy] = None,
    max_retries: int = 3,
    base_delay: float = 1.0,
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
):
    """重试装饰器"""
    if policy is None:
        policy = RetryPolicy(
            max_retries=max_retries,
            base_delay=base_delay,
            strategy=strategy
        )
    executor = RetryExecutor(policy)

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            return executor.execute(func, *args, **kwargs)

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await executor.async_execute(func, *args, **kwargs)

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


# ============== 断点续传管理器 ==============

@dataclass
class Checkpoint:
    """检查点数据"""
    task_id: str
    task_type: str
    progress: int
    total: int
    state: Dict[str, Any]
    created_at: str
    updated_at: str
    completed_items: List[str] = field(default_factory=list)
    failed_items: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class CheckpointManager:
    """
    断点续传管理器

    特性:
    - 自动保存进度
    - 支持恢复
    - 多任务管理
    - 过期清理
    """

    def __init__(
        self,
        checkpoint_dir: Optional[str] = None,
        auto_save_interval: int = 100,
        max_checkpoints: int = 100,
        ttl_hours: int = 24
    ):
        self.checkpoint_dir = Path(checkpoint_dir or tempfile.gettempdir()) / "autored_checkpoints"
        self.auto_save_interval = auto_save_interval
        self.max_checkpoints = max_checkpoints
        self.ttl_hours = ttl_hours

        self._checkpoints: Dict[str, Checkpoint] = {}
        self._lock = threading.Lock()
        self._item_count: Dict[str, int] = {}

        # 确保目录存在
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        # 加载现有检查点
        self._load_checkpoints()

    def _get_checkpoint_path(self, task_id: str) -> Path:
        """获取检查点文件路径"""
        return self.checkpoint_dir / f"{task_id}.json"

    def _load_checkpoints(self):
        """加载所有检查点"""
        try:
            for file in self.checkpoint_dir.glob("*.json"):
                try:
                    with open(file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        checkpoint = Checkpoint(**data)
                        self._checkpoints[checkpoint.task_id] = checkpoint
                except Exception as e:
                    logger.warning(f"加载检查点失败 {file}: {e}")
        except Exception as e:
            logger.error(f"扫描检查点目录失败: {e}")

    def create(
        self,
        task_id: str,
        task_type: str,
        total: int,
        metadata: Optional[Dict] = None
    ) -> Checkpoint:
        """创建新检查点"""
        with self._lock:
            now = datetime.now().isoformat()
            checkpoint = Checkpoint(
                task_id=task_id,
                task_type=task_type,
                progress=0,
                total=total,
                state={},
                created_at=now,
                updated_at=now,
                metadata=metadata or {}
            )
            self._checkpoints[task_id] = checkpoint
            self._item_count[task_id] = 0
            self._save_checkpoint(checkpoint)
            return checkpoint

    def update(
        self,
        task_id: str,
        progress: Optional[int] = None,
        state: Optional[Dict] = None,
        completed_item: Optional[str] = None,
        failed_item: Optional[str] = None
    ):
        """更新检查点"""
        with self._lock:
            if task_id not in self._checkpoints:
                raise ValueError(f"检查点不存在: {task_id}")

            checkpoint = self._checkpoints[task_id]

            if progress is not None:
                checkpoint.progress = progress
            if state is not None:
                checkpoint.state.update(state)
            if completed_item:
                checkpoint.completed_items.append(completed_item)
            if failed_item:
                checkpoint.failed_items.append(failed_item)

            checkpoint.updated_at = datetime.now().isoformat()

            # 自动保存
            self._item_count[task_id] = self._item_count.get(task_id, 0) + 1
            if self._item_count[task_id] >= self.auto_save_interval:
                self._save_checkpoint(checkpoint)
                self._item_count[task_id] = 0

    def _save_checkpoint(self, checkpoint: Checkpoint):
        """保存检查点到文件"""
        try:
            path = self._get_checkpoint_path(checkpoint.task_id)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(asdict(checkpoint), f, indent=2, default=str)
        except Exception as e:
            logger.error(f"保存检查点失败: {e}")

    def get(self, task_id: str) -> Optional[Checkpoint]:
        """获取检查点"""
        return self._checkpoints.get(task_id)

    def exists(self, task_id: str) -> bool:
        """检查检查点是否存在"""
        return task_id in self._checkpoints

    def delete(self, task_id: str):
        """删除检查点"""
        with self._lock:
            if task_id in self._checkpoints:
                del self._checkpoints[task_id]
                path = self._get_checkpoint_path(task_id)
                if path.exists():
                    path.unlink()

    def complete(self, task_id: str):
        """标记任务完成并删除检查点"""
        self.delete(task_id)

    def get_resumable_tasks(self, task_type: Optional[str] = None) -> List[Checkpoint]:
        """获取可恢复的任务列表"""
        tasks = []
        for checkpoint in self._checkpoints.values():
            if task_type and checkpoint.task_type != task_type:
                continue
            if checkpoint.progress < checkpoint.total:
                tasks.append(checkpoint)
        return tasks

    def cleanup_expired(self) -> int:
        """清理过期检查点"""
        import datetime as dt
        now = dt.datetime.now()
        expired = []

        for task_id, checkpoint in self._checkpoints.items():
            try:
                created = dt.datetime.fromisoformat(checkpoint.created_at)
                if (now - created).total_seconds() > self.ttl_hours * 3600:
                    expired.append(task_id)
            except Exception:
                continue

        for task_id in expired:
            self.delete(task_id)

        return len(expired)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "total_checkpoints": len(self._checkpoints),
            "by_type": {},
            "resumable": len(self.get_resumable_tasks())
        }


# ============== 故障恢复 ==============

class RecoveryAction(Enum):
    """恢复动作"""
    RETRY = "retry"
    SKIP = "skip"
    FALLBACK = "fallback"
    ABORT = "abort"


@dataclass
class FailureRecord:
    """故障记录"""
    error_type: str
    error_message: str
    timestamp: float
    context: Dict[str, Any]
    recovery_action: Optional[RecoveryAction] = None
    recovered: bool = False


class FaultRecovery:
    """
    故障恢复管理器

    特性:
    - 故障记录
    - 自动恢复策略
    - 降级处理
    - 故障分析
    """

    def __init__(
        self,
        max_failures: int = 100,
        recovery_strategies: Optional[Dict[str, RecoveryAction]] = None,
        fallback_handlers: Optional[Dict[str, Callable]] = None
    ):
        self.max_failures = max_failures
        self.recovery_strategies = recovery_strategies or {}
        self.fallback_handlers = fallback_handlers or {}

        self._failures: List[FailureRecord] = []
        self._lock = threading.Lock()

        # 默认恢复策略
        self._default_strategies = {
            "ConnectionError": RecoveryAction.RETRY,
            "TimeoutError": RecoveryAction.RETRY,
            "ValueError": RecoveryAction.SKIP,
            "KeyError": RecoveryAction.SKIP,
            "PermissionError": RecoveryAction.ABORT,
        }

    def record_failure(
        self,
        error: Exception,
        context: Optional[Dict] = None
    ) -> FailureRecord:
        """记录故障"""
        with self._lock:
            record = FailureRecord(
                error_type=type(error).__name__,
                error_message=str(error),
                timestamp=time.time(),
                context=context or {}
            )
            self._failures.append(record)

            # 限制记录数量
            if len(self._failures) > self.max_failures:
                self._failures = self._failures[-self.max_failures:]

            return record

    def get_recovery_action(self, error: Exception) -> RecoveryAction:
        """获取恢复动作"""
        error_type = type(error).__name__

        # 检查自定义策略
        if error_type in self.recovery_strategies:
            return self.recovery_strategies[error_type]

        # 检查默认策略
        if error_type in self._default_strategies:
            return self._default_strategies[error_type]

        # 默认重试
        return RecoveryAction.RETRY

    def execute_with_recovery(
        self,
        func: Callable,
        *args,
        context: Optional[Dict] = None,
        fallback_value: Any = None,
        **kwargs
    ) -> Any:
        """带故障恢复的执行"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            record = self.record_failure(e, context)
            action = self.get_recovery_action(e)
            record.recovery_action = action

            if action == RecoveryAction.RETRY:
                # 重试由调用者处理
                raise

            elif action == RecoveryAction.SKIP:
                logger.warning(f"跳过故障: {e}")
                record.recovered = True
                return fallback_value

            elif action == RecoveryAction.FALLBACK:
                error_type = type(e).__name__
                if error_type in self.fallback_handlers:
                    try:
                        result = self.fallback_handlers[error_type](*args, **kwargs)
                        record.recovered = True
                        return result
                    except Exception as fallback_error:
                        logger.error(f"降级处理失败: {fallback_error}")
                        raise e
                raise

            elif action == RecoveryAction.ABORT:
                logger.error(f"致命错误，中止执行: {e}")
                raise

            raise

    async def async_execute_with_recovery(
        self,
        func: Callable,
        *args,
        context: Optional[Dict] = None,
        fallback_value: Any = None,
        **kwargs
    ) -> Any:
        """异步带故障恢复的执行"""
        try:
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return func(*args, **kwargs)
        except Exception as e:
            record = self.record_failure(e, context)
            action = self.get_recovery_action(e)
            record.recovery_action = action

            if action == RecoveryAction.SKIP:
                record.recovered = True
                return fallback_value
            elif action == RecoveryAction.FALLBACK:
                error_type = type(e).__name__
                if error_type in self.fallback_handlers:
                    try:
                        handler = self.fallback_handlers[error_type]
                        if asyncio.iscoroutinefunction(handler):
                            result = await handler(*args, **kwargs)
                        else:
                            result = handler(*args, **kwargs)
                        record.recovered = True
                        return result
                    except Exception:
                        raise e
            raise

    def get_failure_summary(self) -> Dict[str, Any]:
        """获取故障摘要"""
        by_type: Dict[str, int] = {}
        by_action: Dict[str, int] = {}
        recovered_count = 0

        for record in self._failures:
            by_type[record.error_type] = by_type.get(record.error_type, 0) + 1
            if record.recovery_action:
                action = record.recovery_action.value
                by_action[action] = by_action.get(action, 0) + 1
            if record.recovered:
                recovered_count += 1

        return {
            "total_failures": len(self._failures),
            "by_type": by_type,
            "by_action": by_action,
            "recovered": recovered_count,
            "recovery_rate": recovered_count / max(len(self._failures), 1)
        }

    def clear_failures(self):
        """清除故障记录"""
        with self._lock:
            self._failures.clear()

    @property
    def recent_failures(self) -> List[Dict]:
        """获取最近的故障"""
        return [
            {
                "type": r.error_type,
                "message": r.error_message,
                "timestamp": r.timestamp,
                "action": r.recovery_action.value if r.recovery_action else None,
                "recovered": r.recovered
            }
            for r in self._failures[-10:]
        ]


# ============== 任务恢复上下文 ==============

class RecoverableTask:
    """
    可恢复任务包装器

    用法:
        async with RecoverableTask("scan_task", checkpoint_mgr) as task:
            for item in items:
                if task.is_completed(item):
                    continue
                result = await process(item)
                task.mark_completed(item, result)
    """

    def __init__(
        self,
        task_id: str,
        checkpoint_manager: CheckpointManager,
        task_type: str = "generic",
        total: int = 0,
        retry_policy: Optional[RetryPolicy] = None,
        fault_recovery: Optional[FaultRecovery] = None
    ):
        self.task_id = task_id
        self.checkpoint_manager = checkpoint_manager
        self.task_type = task_type
        self.total = total
        self.retry_executor = RetryExecutor(retry_policy) if retry_policy else None
        self.fault_recovery = fault_recovery or FaultRecovery()

        self._checkpoint: Optional[Checkpoint] = None
        self._results: Dict[str, Any] = {}

    def __enter__(self):
        return self._setup()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._cleanup(exc_type is None)
        return False

    async def __aenter__(self):
        return self._setup()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._cleanup(exc_type is None)
        return False

    def _setup(self):
        """设置任务"""
        # 检查是否有可恢复的检查点
        existing = self.checkpoint_manager.get(self.task_id)
        if existing:
            self._checkpoint = existing
            logger.info(f"恢复任务 {self.task_id}，进度: {existing.progress}/{existing.total}")
        else:
            self._checkpoint = self.checkpoint_manager.create(
                self.task_id,
                self.task_type,
                self.total
            )
        return self

    def _cleanup(self, success: bool):
        """清理任务"""
        if success and self._checkpoint:
            self.checkpoint_manager.complete(self.task_id)

    def is_completed(self, item_id: str) -> bool:
        """检查项目是否已完成"""
        if self._checkpoint:
            return item_id in self._checkpoint.completed_items
        return False

    def mark_completed(self, item_id: str, result: Any = None):
        """标记项目完成"""
        self._results[item_id] = result
        self.checkpoint_manager.update(
            self.task_id,
            progress=len(self._results),
            completed_item=item_id
        )

    def mark_failed(self, item_id: str, error: Exception):
        """标记项目失败"""
        self.fault_recovery.record_failure(error, {"item_id": item_id})
        self.checkpoint_manager.update(
            self.task_id,
            failed_item=item_id
        )

    def execute_item(self, func: Callable, item_id: str, *args, **kwargs) -> Any:
        """执行单个项目（带重试和恢复）"""
        if self.is_completed(item_id):
            return self._results.get(item_id)

        try:
            if self.retry_executor:
                result = self.retry_executor.execute(func, *args, **kwargs)
            else:
                result = self.fault_recovery.execute_with_recovery(
                    func, *args, context={"item_id": item_id}, **kwargs
                )
            self.mark_completed(item_id, result)
            return result
        except Exception as e:
            self.mark_failed(item_id, e)
            raise

    async def async_execute_item(self, func: Callable, item_id: str, *args, **kwargs) -> Any:
        """异步执行单个项目"""
        if self.is_completed(item_id):
            return self._results.get(item_id)

        try:
            if self.retry_executor:
                result = await self.retry_executor.async_execute(func, *args, **kwargs)
            else:
                result = await self.fault_recovery.async_execute_with_recovery(
                    func, *args, context={"item_id": item_id}, **kwargs
                )
            self.mark_completed(item_id, result)
            return result
        except Exception as e:
            self.mark_failed(item_id, e)
            raise

    @property
    def progress(self) -> Dict[str, Any]:
        """获取进度"""
        if self._checkpoint:
            return {
                "completed": len(self._checkpoint.completed_items),
                "failed": len(self._checkpoint.failed_items),
                "total": self._checkpoint.total,
                "percentage": len(self._checkpoint.completed_items) / max(self._checkpoint.total, 1) * 100
            }
        return {"completed": 0, "failed": 0, "total": 0, "percentage": 0}
