#!/usr/bin/env python3
"""
性能优化模块 - AutoRedTeam-Orchestrator
提供内存优化、缓存策略、并发控制、可靠性和监控功能
"""

from .memory_optimizer import (
    StreamingResultProcessor,
    ObjectPool,
    ResultPaginator,
    MemoryMonitor,
    memory_efficient
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
    CheckpointManager,
    FaultRecovery,
    retry_with_policy
)

from .monitoring import (
    PerformanceMetrics,
    LogController,
    AlertManager,
    MetricsCollector
)

from .config import PerformanceConfig, get_performance_config

from .manager import (
    PerformanceManager,
    get_performance_manager,
    init_performance
)

__all__ = [
    # 内存优化
    'StreamingResultProcessor',
    'ObjectPool',
    'ResultPaginator',
    'MemoryMonitor',
    'memory_efficient',
    # 并发控制
    'DynamicThreadPool',
    'ConnectionPoolManager',
    'RateLimiter',
    'CircuitBreaker',
    'Bulkhead',
    # 可靠性
    'RetryPolicy',
    'CheckpointManager',
    'FaultRecovery',
    'retry_with_policy',
    # 监控
    'PerformanceMetrics',
    'LogController',
    'AlertManager',
    'MetricsCollector',
    # 配置
    'PerformanceConfig',
    'get_performance_config',
    # 管理器
    'PerformanceManager',
    'get_performance_manager',
    'init_performance'
]
