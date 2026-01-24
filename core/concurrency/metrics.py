"""
性能指标收集模块

提供请求追踪、性能统计和指标导出功能。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
import time
import threading
import statistics
import json
from contextlib import contextmanager
from collections import deque
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """指标类型"""
    COUNTER = 'counter'       # 计数器
    GAUGE = 'gauge'           # 仪表
    HISTOGRAM = 'histogram'   # 直方图
    TIMER = 'timer'           # 计时器


@dataclass
class RequestMetrics:
    """
    请求指标

    收集单个请求类型的性能数据
    """
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_time: float = 0.0
    response_times: List[float] = field(default_factory=list)
    error_counts: Dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    max_samples: int = field(default=10000, repr=False)

    def record(
        self,
        success: bool,
        response_time: float,
        error_type: Optional[str] = None
    ) -> None:
        """
        记录请求

        Args:
            success: 是否成功
            response_time: 响应时间（秒）
            error_type: 错误类型（可选）
        """
        with self._lock:
            self.total_requests += 1
            self.total_time += response_time

            if success:
                self.successful_requests += 1
            else:
                self.failed_requests += 1
                if error_type:
                    self.error_counts[error_type] = (
                        self.error_counts.get(error_type, 0) + 1
                    )

            # 限制样本数量
            if len(self.response_times) >= self.max_samples:
                # 移除前 10% 的样本
                del self.response_times[:self.max_samples // 10]

            self.response_times.append(response_time)

    @property
    def success_rate(self) -> float:
        """成功率"""
        with self._lock:
            if self.total_requests == 0:
                return 0.0
            return self.successful_requests / self.total_requests

    @property
    def failure_rate(self) -> float:
        """失败率"""
        return 1.0 - self.success_rate

    @property
    def avg_response_time(self) -> float:
        """平均响应时间"""
        with self._lock:
            if not self.response_times:
                return 0.0
            return statistics.mean(self.response_times)

    @property
    def min_response_time(self) -> float:
        """最小响应时间"""
        with self._lock:
            if not self.response_times:
                return 0.0
            return min(self.response_times)

    @property
    def max_response_time(self) -> float:
        """最大响应时间"""
        with self._lock:
            if not self.response_times:
                return 0.0
            return max(self.response_times)

    @property
    def median_response_time(self) -> float:
        """中位数响应时间"""
        with self._lock:
            if not self.response_times:
                return 0.0
            return statistics.median(self.response_times)

    @property
    def stddev_response_time(self) -> float:
        """响应时间标准差"""
        with self._lock:
            if len(self.response_times) < 2:
                return 0.0
            return statistics.stdev(self.response_times)

    def percentile(self, p: float) -> float:
        """
        计算百分位数

        Args:
            p: 百分位（0-100）

        Returns:
            响应时间百分位值
        """
        with self._lock:
            if not self.response_times:
                return 0.0

            sorted_times = sorted(self.response_times)
            idx = int(len(sorted_times) * p / 100)
            idx = min(idx, len(sorted_times) - 1)
            return sorted_times[idx]

    @property
    def p50_response_time(self) -> float:
        """P50 响应时间"""
        return self.percentile(50)

    @property
    def p90_response_time(self) -> float:
        """P90 响应时间"""
        return self.percentile(90)

    @property
    def p95_response_time(self) -> float:
        """P95 响应时间"""
        return self.percentile(95)

    @property
    def p99_response_time(self) -> float:
        """P99 响应时间"""
        return self.percentile(99)

    @property
    def requests_per_second(self) -> float:
        """每秒请求数（基于总时间）"""
        with self._lock:
            if self.total_time == 0:
                return 0.0
            return self.total_requests / self.total_time

    def reset(self) -> None:
        """重置指标"""
        with self._lock:
            self.total_requests = 0
            self.successful_requests = 0
            self.failed_requests = 0
            self.total_time = 0.0
            self.response_times.clear()
            self.error_counts.clear()

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        with self._lock:
            return {
                'total_requests': self.total_requests,
                'successful_requests': self.successful_requests,
                'failed_requests': self.failed_requests,
                'success_rate': self.success_rate,
                'total_time': self.total_time,
                'avg_response_time': self.avg_response_time,
                'min_response_time': self.min_response_time,
                'max_response_time': self.max_response_time,
                'median_response_time': self.median_response_time,
                'p50_response_time': self.p50_response_time,
                'p90_response_time': self.p90_response_time,
                'p95_response_time': self.p95_response_time,
                'p99_response_time': self.p99_response_time,
                'requests_per_second': self.requests_per_second,
                'error_counts': dict(self.error_counts),
                'sample_count': len(self.response_times)
            }


class Counter:
    """
    计数器

    用于统计事件发生次数
    """

    def __init__(self, name: str, description: str = ''):
        """
        初始化计数器

        Args:
            name: 计数器名称
            description: 描述
        """
        self.name = name
        self.description = description
        self._value = 0
        self._lock = threading.Lock()

    def inc(self, value: int = 1) -> None:
        """增加计数"""
        with self._lock:
            self._value += value

    def dec(self, value: int = 1) -> None:
        """减少计数"""
        with self._lock:
            self._value -= value

    @property
    def value(self) -> int:
        """当前值"""
        with self._lock:
            return self._value

    def reset(self) -> None:
        """重置计数器"""
        with self._lock:
            self._value = 0


class Gauge:
    """
    仪表

    用于记录可变的数值
    """

    def __init__(self, name: str, description: str = ''):
        """
        初始化仪表

        Args:
            name: 仪表名称
            description: 描述
        """
        self.name = name
        self.description = description
        self._value = 0.0
        self._lock = threading.Lock()

    def set(self, value: float) -> None:
        """设置值"""
        with self._lock:
            self._value = value

    def inc(self, value: float = 1.0) -> None:
        """增加值"""
        with self._lock:
            self._value += value

    def dec(self, value: float = 1.0) -> None:
        """减少值"""
        with self._lock:
            self._value -= value

    @property
    def value(self) -> float:
        """当前值"""
        with self._lock:
            return self._value


class Histogram:
    """
    直方图

    用于统计数值分布
    """

    def __init__(
        self,
        name: str,
        buckets: Optional[List[float]] = None,
        description: str = ''
    ):
        """
        初始化直方图

        Args:
            name: 直方图名称
            buckets: 桶边界
            description: 描述
        """
        self.name = name
        self.description = description
        self.buckets = buckets or [0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        self._values: List[float] = []
        self._bucket_counts: Dict[float, int] = {b: 0 for b in self.buckets}
        self._bucket_counts[float('inf')] = 0
        self._sum = 0.0
        self._count = 0
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        """
        记录观察值

        Args:
            value: 观察值
        """
        with self._lock:
            self._values.append(value)
            self._sum += value
            self._count += 1

            # 更新桶计数
            for bucket in sorted(self.buckets):
                if value <= bucket:
                    self._bucket_counts[bucket] += 1
                    break
            else:
                self._bucket_counts[float('inf')] += 1

    @property
    def sum(self) -> float:
        """总和"""
        with self._lock:
            return self._sum

    @property
    def count(self) -> int:
        """计数"""
        with self._lock:
            return self._count

    @property
    def mean(self) -> float:
        """平均值"""
        with self._lock:
            if self._count == 0:
                return 0.0
            return self._sum / self._count

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        with self._lock:
            return {
                'name': self.name,
                'sum': self._sum,
                'count': self._count,
                'mean': self.mean,
                'buckets': {str(k): v for k, v in self._bucket_counts.items()}
            }


class MetricsCollector:
    """
    指标收集器

    集中管理和收集各类性能指标
    """

    def __init__(self, max_samples: int = 10000):
        """
        初始化指标收集器

        Args:
            max_samples: 每个指标的最大样本数
        """
        self.max_samples = max_samples
        self._metrics: Dict[str, RequestMetrics] = {}
        self._counters: Dict[str, Counter] = {}
        self._gauges: Dict[str, Gauge] = {}
        self._histograms: Dict[str, Histogram] = {}
        self._lock = threading.RLock()
        self._start_time = time.monotonic()

    def record(
        self,
        name: str,
        success: bool,
        response_time: float,
        error_type: Optional[str] = None
    ) -> None:
        """
        记录请求指标

        Args:
            name: 指标名称
            success: 是否成功
            response_time: 响应时间
            error_type: 错误类型
        """
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = RequestMetrics(max_samples=self.max_samples)

        self._metrics[name].record(success, response_time, error_type)

    def get_metrics(self, name: str) -> Optional[RequestMetrics]:
        """
        获取指标

        Args:
            name: 指标名称

        Returns:
            RequestMetrics 或 None
        """
        with self._lock:
            return self._metrics.get(name)

    def get_all_metrics(self) -> Dict[str, RequestMetrics]:
        """获取所有指标"""
        with self._lock:
            return dict(self._metrics)

    def get_counter(self, name: str, description: str = '') -> Counter:
        """
        获取或创建计数器

        Args:
            name: 计数器名称
            description: 描述

        Returns:
            Counter 实例
        """
        with self._lock:
            if name not in self._counters:
                self._counters[name] = Counter(name, description)
            return self._counters[name]

    def get_gauge(self, name: str, description: str = '') -> Gauge:
        """
        获取或创建仪表

        Args:
            name: 仪表名称
            description: 描述

        Returns:
            Gauge 实例
        """
        with self._lock:
            if name not in self._gauges:
                self._gauges[name] = Gauge(name, description)
            return self._gauges[name]

    def get_histogram(
        self,
        name: str,
        buckets: Optional[List[float]] = None,
        description: str = ''
    ) -> Histogram:
        """
        获取或创建直方图

        Args:
            name: 直方图名称
            buckets: 桶边界
            description: 描述

        Returns:
            Histogram 实例
        """
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = Histogram(name, buckets, description)
            return self._histograms[name]

    def reset(self, name: Optional[str] = None) -> None:
        """
        重置指标

        Args:
            name: 指标名称，None 表示重置所有
        """
        with self._lock:
            if name is None:
                for metrics in self._metrics.values():
                    metrics.reset()
                for counter in self._counters.values():
                    counter.reset()
            elif name in self._metrics:
                self._metrics[name].reset()
            elif name in self._counters:
                self._counters[name].reset()

    def remove(self, name: str) -> bool:
        """
        移除指标

        Args:
            name: 指标名称

        Returns:
            是否成功移除
        """
        with self._lock:
            removed = False
            if name in self._metrics:
                del self._metrics[name]
                removed = True
            if name in self._counters:
                del self._counters[name]
                removed = True
            if name in self._gauges:
                del self._gauges[name]
                removed = True
            if name in self._histograms:
                del self._histograms[name]
                removed = True
            return removed

    def to_dict(self) -> Dict[str, Any]:
        """导出为字典"""
        with self._lock:
            uptime = time.monotonic() - self._start_time

            return {
                'uptime_seconds': uptime,
                'request_metrics': {
                    name: metrics.to_dict()
                    for name, metrics in self._metrics.items()
                },
                'counters': {
                    name: counter.value
                    for name, counter in self._counters.items()
                },
                'gauges': {
                    name: gauge.value
                    for name, gauge in self._gauges.items()
                },
                'histograms': {
                    name: hist.to_dict()
                    for name, hist in self._histograms.items()
                }
            }

    def to_json(self, indent: int = 2) -> str:
        """导出为 JSON 字符串"""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def summary(self) -> str:
        """生成摘要报告"""
        with self._lock:
            lines = ["=== 性能指标摘要 ==="]

            if self._metrics:
                lines.append("\n请求指标:")
                for name, metrics in self._metrics.items():
                    lines.append(f"  {name}:")
                    lines.append(f"    总请求: {metrics.total_requests}")
                    lines.append(f"    成功率: {metrics.success_rate:.2%}")
                    lines.append(f"    平均响应: {metrics.avg_response_time*1000:.2f}ms")
                    lines.append(f"    P95响应: {metrics.p95_response_time*1000:.2f}ms")

            if self._counters:
                lines.append("\n计数器:")
                for name, counter in self._counters.items():
                    lines.append(f"  {name}: {counter.value}")

            if self._gauges:
                lines.append("\n仪表:")
                for name, gauge in self._gauges.items():
                    lines.append(f"  {name}: {gauge.value:.2f}")

            return "\n".join(lines)


# 全局收集器
_collector: Optional[MetricsCollector] = None
_collector_lock = threading.Lock()


def get_collector() -> MetricsCollector:
    """获取全局指标收集器"""
    global _collector

    with _collector_lock:
        if _collector is None:
            _collector = MetricsCollector()
        return _collector


@contextmanager
def track_request(
    name: str,
    collector: Optional[MetricsCollector] = None
):
    """
    请求追踪上下文管理器

    自动记录请求的响应时间和成功/失败状态

    Args:
        name: 请求名称
        collector: 指标收集器（默认使用全局收集器）

    Yields:
        None

    Example:
        with track_request('api_call'):
            response = requests.get(url)
    """
    if collector is None:
        collector = get_collector()

    start_time = time.monotonic()
    success = True
    error_type = None

    try:
        yield
    except Exception as e:
        success = False
        error_type = type(e).__name__
        raise
    finally:
        response_time = time.monotonic() - start_time
        collector.record(name, success, response_time, error_type)


def track(name: str) -> Callable:
    """
    请求追踪装饰器

    Args:
        name: 请求名称

    Returns:
        装饰器函数

    Example:
        @track('my_function')
        def my_function():
            ...
    """
    def decorator(fn: Callable) -> Callable:
        import functools
        import asyncio

        @functools.wraps(fn)
        def sync_wrapper(*args, **kwargs):
            with track_request(name):
                return fn(*args, **kwargs)

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            with track_request(name):
                return await fn(*args, **kwargs)

        if asyncio.iscoroutinefunction(fn):
            return async_wrapper
        return sync_wrapper

    return decorator


class RollingMetrics:
    """
    滚动窗口指标

    只保留最近一段时间内的指标数据
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        bucket_count: int = 60
    ):
        """
        初始化滚动窗口指标

        Args:
            window_seconds: 窗口大小（秒）
            bucket_count: 桶数量
        """
        self.window_seconds = window_seconds
        self.bucket_count = bucket_count
        self.bucket_size = window_seconds / bucket_count

        self._buckets: deque = deque(maxlen=bucket_count)
        self._current_bucket: Dict[str, Any] = self._new_bucket()
        self._last_bucket_time = time.monotonic()
        self._lock = threading.Lock()

    def _new_bucket(self) -> Dict[str, Any]:
        """创建新桶"""
        return {
            'count': 0,
            'success': 0,
            'failure': 0,
            'total_time': 0.0,
            'times': []
        }

    def _rotate_if_needed(self) -> None:
        """必要时轮换桶"""
        now = time.monotonic()
        elapsed = now - self._last_bucket_time

        while elapsed >= self.bucket_size:
            self._buckets.append(self._current_bucket)
            self._current_bucket = self._new_bucket()
            self._last_bucket_time += self.bucket_size
            elapsed = now - self._last_bucket_time

    def record(self, success: bool, response_time: float) -> None:
        """记录请求"""
        with self._lock:
            self._rotate_if_needed()

            self._current_bucket['count'] += 1
            self._current_bucket['total_time'] += response_time
            self._current_bucket['times'].append(response_time)

            if success:
                self._current_bucket['success'] += 1
            else:
                self._current_bucket['failure'] += 1

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._lock:
            self._rotate_if_needed()

            total_count = 0
            total_success = 0
            total_failure = 0
            total_time = 0.0
            all_times = []

            # 汇总所有桶
            for bucket in self._buckets:
                total_count += bucket['count']
                total_success += bucket['success']
                total_failure += bucket['failure']
                total_time += bucket['total_time']
                all_times.extend(bucket['times'])

            # 加上当前桶
            total_count += self._current_bucket['count']
            total_success += self._current_bucket['success']
            total_failure += self._current_bucket['failure']
            total_time += self._current_bucket['total_time']
            all_times.extend(self._current_bucket['times'])

            success_rate = total_success / total_count if total_count > 0 else 0.0
            avg_time = total_time / total_count if total_count > 0 else 0.0

            return {
                'window_seconds': self.window_seconds,
                'total_requests': total_count,
                'success_rate': success_rate,
                'avg_response_time': avg_time,
                'requests_per_second': total_count / self.window_seconds
            }
