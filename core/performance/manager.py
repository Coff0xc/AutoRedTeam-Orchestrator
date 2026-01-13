#!/usr/bin/env python3
"""
性能优化管理器
统一管理所有性能优化组件
"""

import logging
from typing import Any, Dict, Optional

from .config import PerformanceConfig, get_performance_config
from .memory_optimizer import (
    StreamingResultProcessor,
    ObjectPool,
    ResultPaginator,
    MemoryMonitor,
    CompressedStorage
)
from .concurrency import (
    DynamicThreadPool,
    ConnectionPoolManager,
    RateLimiter,
    CircuitBreaker,
    Bulkhead
)
from .reliability import (
    RetryPolicy,
    RetryExecutor,
    RetryStrategy,
    CheckpointManager,
    FaultRecovery,
    RecoverableTask
)
from .monitoring import (
    MetricsCollector,
    PerformanceMetrics,
    LogController,
    AlertManager
)

logger = logging.getLogger(__name__)


class PerformanceManager:
    """
    性能优化管理器 - 统一入口

    用法:
        # 初始化
        perf = PerformanceManager()
        perf.start()

        # 使用各组件
        with perf.thread_pool.submit(task):
            ...

        # 获取统计
        stats = perf.get_stats()

        # 停止
        perf.stop()
    """

    def __init__(self, config: Optional[PerformanceConfig] = None):
        self.config = config or get_performance_config()
        self._initialized = False

        # 内存优化组件
        self.memory_monitor: Optional[MemoryMonitor] = None
        self.result_processor: Optional[StreamingResultProcessor] = None
        self.compressed_storage: Optional[CompressedStorage] = None

        # 并发控制组件
        self.thread_pool: Optional[DynamicThreadPool] = None
        self.connection_pool: Optional[ConnectionPoolManager] = None
        self.rate_limiter: Optional[RateLimiter] = None
        self.circuit_breaker: Optional[CircuitBreaker] = None
        self.bulkhead: Optional[Bulkhead] = None

        # 可靠性组件
        self.checkpoint_manager: Optional[CheckpointManager] = None
        self.fault_recovery: Optional[FaultRecovery] = None
        self.retry_executor: Optional[RetryExecutor] = None

        # 监控组件
        self.metrics: Optional[PerformanceMetrics] = None
        self.log_controller: Optional[LogController] = None
        self.alert_manager: Optional[AlertManager] = None

    def start(self):
        """启动所有组件"""
        if self._initialized:
            return

        logger.info("正在启动性能优化管理器...")

        # 初始化内存优化
        self._init_memory()

        # 初始化并发控制
        self._init_concurrency()

        # 初始化可靠性
        self._init_reliability()

        # 初始化监控
        self._init_monitoring()

        self._initialized = True
        logger.info("性能优化管理器已启动")

    def _init_memory(self):
        """初始化内存优化组件"""
        cfg = self.config.memory

        self.memory_monitor = MemoryMonitor(
            threshold=cfg.gc_threshold,
            max_memory_mb=cfg.max_memory_mb
        )
        self.memory_monitor.start()

        self.result_processor = StreamingResultProcessor(
            chunk_size=cfg.stream_chunk_size,
            max_buffer_size=cfg.max_result_size
        )

        self.compressed_storage = CompressedStorage()

    def _init_concurrency(self):
        """初始化并发控制组件"""
        cfg = self.config.concurrency

        self.thread_pool = DynamicThreadPool(
            min_threads=cfg.min_threads,
            max_threads=cfg.max_threads,
            initial_threads=cfg.initial_threads,
            queue_size=cfg.queue_size
        )
        self.thread_pool.start()

        self.connection_pool = ConnectionPoolManager(
            max_connections=cfg.connection_pool_size
        )
        self.connection_pool.start()

        self.rate_limiter = RateLimiter(
            rate=cfg.rate_limit_rps,
            burst=cfg.rate_limit_burst
        )

        self.circuit_breaker = CircuitBreaker(
            failure_threshold=cfg.circuit_breaker_threshold,
            timeout=cfg.circuit_breaker_timeout
        )

        self.bulkhead = Bulkhead(
            max_concurrent=cfg.bulkhead_max_concurrent
        )

    def _init_reliability(self):
        """初始化可靠性组件"""
        cfg = self.config.reliability

        strategy = RetryStrategy.EXPONENTIAL if cfg.retry_exponential else RetryStrategy.FIXED
        policy = RetryPolicy(
            max_retries=cfg.max_retries,
            base_delay=cfg.retry_base_delay,
            max_delay=cfg.retry_max_delay,
            strategy=strategy
        )
        self.retry_executor = RetryExecutor(policy)

        if cfg.checkpoint_enabled:
            self.checkpoint_manager = CheckpointManager(
                checkpoint_dir=cfg.checkpoint_dir,
                auto_save_interval=cfg.checkpoint_interval
            )

        self.fault_recovery = FaultRecovery()

    def _init_monitoring(self):
        """初始化监控组件"""
        cfg = self.config.monitoring

        if cfg.metrics_enabled:
            self.metrics = PerformanceMetrics()

        self.log_controller = LogController(
            level=cfg.log_level,
            max_message_size=cfg.log_max_size,
            sampling_rate=cfg.log_sampling_rate
        )

        if cfg.alert_enabled:
            self.alert_manager = AlertManager(
                thresholds=cfg.alert_thresholds,
                webhook_url=cfg.alert_webhook
            )

            # 连接内存监控到告警
            if self.memory_monitor and self.alert_manager:
                self.memory_monitor.add_callback(
                    lambda usage: self.alert_manager.check_threshold(
                        "memory_usage",
                        usage["rss_mb"] / self.config.memory.max_memory_mb
                    )
                )

    def stop(self):
        """停止所有组件"""
        if not self._initialized:
            return

        logger.info("正在停止性能优化管理器...")

        if self.memory_monitor:
            self.memory_monitor.stop()

        if self.thread_pool:
            self.thread_pool.stop()

        if self.connection_pool:
            self.connection_pool.stop()

        self._initialized = False
        logger.info("性能优化管理器已停止")

    def get_stats(self) -> Dict[str, Any]:
        """获取所有组件统计"""
        stats = {"initialized": self._initialized}

        if self.memory_monitor:
            stats["memory"] = self.memory_monitor.get_current()

        if self.thread_pool:
            stats["thread_pool"] = self.thread_pool.stats

        if self.connection_pool:
            stats["connection_pool"] = self.connection_pool.stats

        if self.rate_limiter:
            stats["rate_limiter"] = self.rate_limiter.stats

        if self.circuit_breaker:
            stats["circuit_breaker"] = self.circuit_breaker.stats

        if self.bulkhead:
            stats["bulkhead"] = self.bulkhead.stats

        if self.retry_executor:
            stats["retry"] = self.retry_executor.stats

        if self.checkpoint_manager:
            stats["checkpoint"] = self.checkpoint_manager.stats

        if self.fault_recovery:
            stats["fault_recovery"] = self.fault_recovery.get_failure_summary()

        if self.metrics:
            stats["metrics"] = self.metrics.get_summary()

        if self.log_controller:
            stats["logging"] = self.log_controller.stats

        if self.alert_manager:
            stats["alerts"] = self.alert_manager.stats

        return stats

    def create_recoverable_task(
        self,
        task_id: str,
        task_type: str = "generic",
        total: int = 0
    ) -> RecoverableTask:
        """创建可恢复任务"""
        if not self.checkpoint_manager:
            raise RuntimeError("检查点管理器未启用")

        return RecoverableTask(
            task_id=task_id,
            checkpoint_manager=self.checkpoint_manager,
            task_type=task_type,
            total=total,
            retry_policy=self.retry_executor.policy if self.retry_executor else None,
            fault_recovery=self.fault_recovery
        )

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


# 全局实例
_manager_instance: Optional[PerformanceManager] = None


def get_performance_manager() -> PerformanceManager:
    """获取性能管理器单例"""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = PerformanceManager()
    return _manager_instance


def init_performance(config: Optional[PerformanceConfig] = None) -> PerformanceManager:
    """初始化并启动性能管理器"""
    global _manager_instance
    _manager_instance = PerformanceManager(config)
    _manager_instance.start()
    return _manager_instance
