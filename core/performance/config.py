#!/usr/bin/env python3
"""
性能优化配置模块
集中管理所有性能相关配置
"""

import os
import tempfile
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from pathlib import Path


@dataclass
class MemoryConfig:
    """内存优化配置"""
    max_result_size: int = 10_000          # 单次结果最大条数
    stream_chunk_size: int = 1000          # 流式处理块大小
    object_pool_size: int = 100            # 对象池大小
    gc_threshold: float = 0.8              # 内存使用率触发GC阈值
    max_memory_mb: int = 512               # 最大内存使用(MB)


@dataclass
class CacheConfig:
    """缓存配置"""
    l1_max_size: int = 1000                # L1本地缓存最大条数
    l1_ttl: int = 300                      # L1默认TTL(秒)
    l2_enabled: bool = False               # 是否启用L2 Redis缓存
    l2_url: str = ""                       # Redis URL
    l2_ttl: int = 3600                     # L2默认TTL(秒)
    preload_enabled: bool = True           # 是否启用预加载
    compression_enabled: bool = True       # 是否压缩大对象


@dataclass
class ConcurrencyConfig:
    """并发配置"""
    min_threads: int = 5                   # 最小线程数
    max_threads: int = 100                 # 最大线程数
    initial_threads: int = 20              # 初始线程数
    queue_size: int = 1000                 # 任务队列大小
    connection_pool_size: int = 50         # 连接池大小
    rate_limit_rps: float = 50.0           # 每秒请求限制
    rate_limit_burst: int = 100            # 突发请求容量
    circuit_breaker_threshold: int = 5     # 熔断阈值
    circuit_breaker_timeout: float = 30.0  # 熔断恢复时间(秒)
    bulkhead_max_concurrent: int = 10      # 舱壁隔离最大并发


@dataclass
class ReliabilityConfig:
    """可靠性配置"""
    max_retries: int = 3                   # 最大重试次数
    retry_base_delay: float = 1.0          # 重试基础延迟(秒)
    retry_max_delay: float = 30.0          # 重试最大延迟(秒)
    retry_exponential: bool = True         # 是否指数退避
    checkpoint_enabled: bool = True        # 是否启用断点续传
    checkpoint_interval: int = 100         # 检查点间隔(条数)
    checkpoint_dir: str = ""               # 检查点目录


@dataclass
class MonitoringConfig:
    """监控配置"""
    metrics_enabled: bool = True           # 是否启用指标收集
    metrics_interval: float = 10.0         # 指标收集间隔(秒)
    log_level: str = "INFO"                # 日志级别
    log_max_size: int = 10_000             # 单次日志最大字符数
    log_sampling_rate: float = 1.0         # 日志采样率(0-1)
    alert_enabled: bool = False            # 是否启用告警
    alert_webhook: str = ""                # 告警Webhook URL
    alert_thresholds: Dict[str, float] = field(default_factory=lambda: {
        "error_rate": 0.1,                 # 错误率阈值
        "latency_p99": 10.0,               # P99延迟阈值(秒)
        "memory_usage": 0.9                # 内存使用率阈值
    })


@dataclass
class PerformanceConfig:
    """性能优化总配置"""
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)
    reliability: ReliabilityConfig = field(default_factory=ReliabilityConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)

    def __post_init__(self):
        # 设置默认检查点目录
        if not self.reliability.checkpoint_dir:
            self.reliability.checkpoint_dir = os.path.join(
                tempfile.gettempdir(), "autored_checkpoints"
            )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PerformanceConfig":
        """从字典创建配置"""
        return cls(
            memory=MemoryConfig(**data.get("memory", {})),
            cache=CacheConfig(**data.get("cache", {})),
            concurrency=ConcurrencyConfig(**data.get("concurrency", {})),
            reliability=ReliabilityConfig(**data.get("reliability", {})),
            monitoring=MonitoringConfig(**data.get("monitoring", {}))
        )

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        from dataclasses import asdict
        return asdict(self)


# 全局配置实例
_config_instance: Optional[PerformanceConfig] = None


def get_performance_config() -> PerformanceConfig:
    """获取性能配置单例"""
    global _config_instance
    if _config_instance is None:
        _config_instance = PerformanceConfig()
    return _config_instance


def set_performance_config(config: PerformanceConfig):
    """设置性能配置"""
    global _config_instance
    _config_instance = config
