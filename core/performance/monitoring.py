#!/usr/bin/env python3
"""
监控模块
提供性能指标收集、日志控制、告警机制等功能
"""

import json
import logging
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ============== 性能指标 ==============


class MetricType(Enum):
    """指标类型"""

    COUNTER = "counter"  # 计数器
    GAUGE = "gauge"  # 仪表盘
    HISTOGRAM = "histogram"  # 直方图
    TIMER = "timer"  # 计时器


@dataclass
class Metric:
    """指标数据"""

    name: str
    type: MetricType
    value: float
    timestamp: float
    labels: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """
    指标收集器

    特性:
    - 多种指标类型
    - 标签支持
    - 聚合计算
    - 导出功能
    """

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self._counters: Dict[str, float] = {}
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, deque] = {}
        self._timers: Dict[str, deque] = {}
        self._lock = threading.Lock()

    def increment(self, name: str, value: float = 1.0, labels: Optional[Dict] = None):
        """增加计数器"""
        key = self._make_key(name, labels)
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + value

    def decrement(self, name: str, value: float = 1.0, labels: Optional[Dict] = None):
        """减少计数器"""
        self.increment(name, -value, labels)

    def gauge(self, name: str, value: float, labels: Optional[Dict] = None):
        """设置仪表盘值"""
        key = self._make_key(name, labels)
        with self._lock:
            self._gauges[key] = value

    def histogram(self, name: str, value: float, labels: Optional[Dict] = None):
        """记录直方图值"""
        key = self._make_key(name, labels)
        with self._lock:
            if key not in self._histograms:
                self._histograms[key] = deque(maxlen=self.max_history)
            self._histograms[key].append(value)

    def timer(self, name: str, duration: float, labels: Optional[Dict] = None):
        """记录计时器值"""
        key = self._make_key(name, labels)
        with self._lock:
            if key not in self._timers:
                self._timers[key] = deque(maxlen=self.max_history)
            self._timers[key].append(duration)

    def _make_key(self, name: str, labels: Optional[Dict]) -> str:
        """生成指标键"""
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def get_counter(self, name: str, labels: Optional[Dict] = None) -> float:
        """获取计数器值"""
        key = self._make_key(name, labels)
        return self._counters.get(key, 0)

    def get_gauge(self, name: str, labels: Optional[Dict] = None) -> float:
        """获取仪表盘值"""
        key = self._make_key(name, labels)
        return self._gauges.get(key, 0)

    def get_histogram_stats(self, name: str, labels: Optional[Dict] = None) -> Dict[str, float]:
        """获取直方图统计"""
        key = self._make_key(name, labels)
        values = list(self._histograms.get(key, []))
        if not values:
            return {"count": 0, "min": 0, "max": 0, "avg": 0, "p50": 0, "p95": 0, "p99": 0}

        sorted_values = sorted(values)
        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "avg": statistics.mean(values),
            "p50": self._percentile(sorted_values, 50),
            "p95": self._percentile(sorted_values, 95),
            "p99": self._percentile(sorted_values, 99),
        }

    def get_timer_stats(self, name: str, labels: Optional[Dict] = None) -> Dict[str, float]:
        """获取计时器统计"""
        key = self._make_key(name, labels)
        return self.get_histogram_stats(name, labels)

    def _percentile(self, sorted_values: List[float], percentile: float) -> float:
        """计算百分位数"""
        if not sorted_values:
            return 0
        k = (len(sorted_values) - 1) * percentile / 100
        f = int(k)
        c = f + 1 if f + 1 < len(sorted_values) else f
        return sorted_values[f] + (k - f) * (sorted_values[c] - sorted_values[f])

    def export(self) -> Dict[str, Any]:
        """导出所有指标"""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {k: self.get_histogram_stats(k) for k in self._histograms},
                "timers": {k: self.get_timer_stats(k) for k in self._timers},
                "timestamp": time.time(),
            }

    def reset(self):
        """重置所有指标"""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()
            self._timers.clear()


# ============== 性能指标管理器 ==============


class PerformanceMetrics:
    """
    性能指标管理器 - 高级封装

    特性:
    - 预定义常用指标
    - 自动收集
    - 定时报告
    """

    def __init__(self, collector: Optional[MetricsCollector] = None):
        self.collector = collector or MetricsCollector()
        self._start_time = time.time()

    # 请求指标
    def record_request(self, endpoint: str, method: str, status: int, duration: float):
        """记录HTTP请求"""
        labels = {"endpoint": endpoint, "method": method, "status": str(status)}
        self.collector.increment("http_requests_total", labels=labels)
        self.collector.timer(
            "http_request_duration_seconds", duration, labels={"endpoint": endpoint}
        )

        if status >= 400:
            self.collector.increment("http_errors_total", labels=labels)

    # 扫描指标
    def record_scan(self, scan_type: str, target: str, duration: float, findings: int):
        """记录扫描"""
        labels = {"type": scan_type}
        self.collector.increment("scans_total", labels=labels)
        self.collector.timer("scan_duration_seconds", duration, labels=labels)
        self.collector.histogram("scan_findings", findings, labels=labels)

    # 缓存指标
    def record_cache_hit(self, cache_type: str):
        """记录缓存命中"""
        self.collector.increment("cache_hits_total", labels={"type": cache_type})

    def record_cache_miss(self, cache_type: str):
        """记录缓存未命中"""
        self.collector.increment("cache_misses_total", labels={"type": cache_type})

    # 错误指标
    def record_error(self, error_type: str, component: str):
        """记录错误"""
        self.collector.increment(
            "errors_total", labels={"type": error_type, "component": component}
        )

    # 资源指标
    def record_memory_usage(self, usage_mb: float):
        """记录内存使用"""
        self.collector.gauge("memory_usage_mb", usage_mb)

    def record_cpu_usage(self, usage_percent: float):
        """记录CPU使用"""
        self.collector.gauge("cpu_usage_percent", usage_percent)

    def record_active_connections(self, count: int):
        """记录活跃连接数"""
        self.collector.gauge("active_connections", count)

    def record_queue_size(self, queue_name: str, size: int):
        """记录队列大小"""
        self.collector.gauge("queue_size", size, labels={"queue": queue_name})

    def get_summary(self) -> Dict[str, Any]:
        """获取指标摘要"""
        metrics = self.collector.export()
        uptime = time.time() - self._start_time

        return {
            "uptime_seconds": uptime,
            "requests": {
                "total": sum(v for k, v in metrics["counters"].items() if "http_requests" in k),
                "errors": sum(v for k, v in metrics["counters"].items() if "http_errors" in k),
            },
            "scans": {
                "total": sum(v for k, v in metrics["counters"].items() if "scans_total" in k),
            },
            "cache": {
                "hits": sum(v for k, v in metrics["counters"].items() if "cache_hits" in k),
                "misses": sum(v for k, v in metrics["counters"].items() if "cache_misses" in k),
            },
            "errors": sum(v for k, v in metrics["counters"].items() if "errors_total" in k),
            "resources": {
                "memory_mb": metrics["gauges"].get("memory_usage_mb", 0),
                "cpu_percent": metrics["gauges"].get("cpu_usage_percent", 0),
            },
        }


# ============== 日志控制器 ==============


class LogLevel(Enum):
    """日志级别"""

    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class LogController:
    """
    日志控制器 - 控制日志输出

    特性:
    - 动态日志级别
    - 日志采样
    - 大小限制
    - 敏感信息过滤
    """

    def __init__(
        self,
        level: str = "INFO",
        max_message_size: int = 10000,
        sampling_rate: float = 1.0,
        sensitive_patterns: Optional[List[str]] = None,
    ):
        self.level = getattr(logging, level.upper(), logging.INFO)
        self.max_message_size = max_message_size
        self.sampling_rate = sampling_rate
        self.sensitive_patterns = sensitive_patterns or [
            r'password["\']?\s*[:=]\s*["\']?[^"\']+',
            r'api[_-]?key["\']?\s*[:=]\s*["\']?[^"\']+',
            r'token["\']?\s*[:=]\s*["\']?[^"\']+',
            r'secret["\']?\s*[:=]\s*["\']?[^"\']+',
        ]

        self._log_count = 0
        self._sampled_count = 0
        self._truncated_count = 0
        self._lock = threading.Lock()

        # 编译正则
        import re

        self._patterns = [re.compile(p, re.IGNORECASE) for p in self.sensitive_patterns]

    def set_level(self, level: str):
        """设置日志级别"""
        self.level = getattr(logging, level.upper(), logging.INFO)
        logging.getLogger().setLevel(self.level)

    def should_log(self) -> bool:
        """根据采样率决定是否记录"""
        import random

        with self._lock:
            self._log_count += 1
            if random.random() <= self.sampling_rate:
                self._sampled_count += 1
                return True
        return False

    def filter_sensitive(self, message: str) -> str:
        """过滤敏感信息"""
        for pattern in self._patterns:
            message = pattern.sub("[REDACTED]", message)
        return message

    def truncate(self, message: str) -> str:
        """截断过长消息"""
        if len(message) > self.max_message_size:
            with self._lock:
                self._truncated_count += 1
            return message[: self.max_message_size] + f"... [truncated, total {len(message)} chars]"
        return message

    def process(self, message: str) -> Optional[str]:
        """处理日志消息"""
        if not self.should_log():
            return None
        message = self.filter_sensitive(message)
        message = self.truncate(message)
        return message

    def get_logger(self, name: str) -> logging.Logger:
        """获取配置好的logger"""
        log = logging.getLogger(name)
        log.setLevel(self.level)
        return log

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "total_logs": self._log_count,
            "sampled_logs": self._sampled_count,
            "truncated_logs": self._truncated_count,
            "sampling_rate": self.sampling_rate,
            "current_level": logging.getLevelName(self.level),
        }


# ============== 告警管理器 ==============


class AlertSeverity(Enum):
    """告警级别"""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class Alert:
    """告警数据"""

    name: str
    severity: AlertSeverity
    message: str
    value: float
    threshold: float
    timestamp: float
    resolved: bool = False


class AlertManager:
    """
    告警管理器 - 阈值告警和通知

    特性:
    - 多种告警规则
    - Webhook通知
    - 告警聚合
    - 自动恢复检测
    """

    def __init__(
        self,
        thresholds: Optional[Dict[str, float]] = None,
        webhook_url: str = "",
        cooldown_seconds: float = 300.0,
        max_alerts: int = 100,
    ):
        self.thresholds = thresholds or {
            "error_rate": 0.1,
            "latency_p99": 10.0,
            "memory_usage": 0.9,
            "cpu_usage": 0.9,
            "failure_rate": 0.2,
        }
        self.webhook_url = webhook_url
        self.cooldown_seconds = cooldown_seconds
        self.max_alerts = max_alerts

        self._alerts: List[Alert] = []
        self._last_alert_time: Dict[str, float] = {}
        self._callbacks: List[Callable[[Alert], None]] = []
        self._lock = threading.Lock()

        # 统计
        self._stats = {
            "total_alerts": 0,
            "by_severity": {},
            "notifications_sent": 0,
            "notifications_failed": 0,
        }

    def check_threshold(self, name: str, value: float) -> Optional[Alert]:
        """检查是否超过阈值"""
        if name not in self.thresholds:
            return None

        threshold = self.thresholds[name]
        if value <= threshold:
            return None

        # 检查冷却时间
        now = time.time()
        if name in self._last_alert_time:
            if now - self._last_alert_time[name] < self.cooldown_seconds:
                return None

        # 确定告警级别
        ratio = value / threshold
        if ratio >= 2.0:
            severity = AlertSeverity.CRITICAL
        elif ratio >= 1.5:
            severity = AlertSeverity.ERROR
        elif ratio >= 1.2:
            severity = AlertSeverity.WARNING
        else:
            severity = AlertSeverity.INFO

        alert = Alert(
            name=name,
            severity=severity,
            message=f"{name} 超过阈值: {value:.2f} > {threshold:.2f}",
            value=value,
            threshold=threshold,
            timestamp=now,
        )

        self._record_alert(alert)
        return alert

    def _record_alert(self, alert: Alert):
        """记录告警"""
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > self.max_alerts:
                self._alerts = self._alerts[-self.max_alerts :]

            self._last_alert_time[alert.name] = alert.timestamp
            self._stats["total_alerts"] += 1

            severity = alert.severity.value
            self._stats["by_severity"][severity] = self._stats["by_severity"].get(severity, 0) + 1

        # 触发回调
        for callback in self._callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"告警回调失败: {e}")

        # 发送Webhook
        if self.webhook_url:
            self._send_webhook(alert)

    def _send_webhook(self, alert: Alert):
        """发送Webhook通知"""
        try:
            import urllib.request

            data = json.dumps(
                {
                    "alert": alert.name,
                    "severity": alert.severity.value,
                    "message": alert.message,
                    "value": alert.value,
                    "threshold": alert.threshold,
                    "timestamp": alert.timestamp,
                }
            ).encode("utf-8")

            req = urllib.request.Request(
                self.webhook_url, data=data, headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=10)
            self._stats["notifications_sent"] += 1
        except Exception as e:
            logger.error(f"Webhook发送失败: {e}")
            self._stats["notifications_failed"] += 1

    def add_callback(self, callback: Callable[[Alert], None]):
        """添加告警回调"""
        self._callbacks.append(callback)

    def set_threshold(self, name: str, value: float):
        """设置阈值"""
        self.thresholds[name] = value

    def get_active_alerts(self) -> List[Alert]:
        """获取活跃告警"""
        return [a for a in self._alerts if not a.resolved]

    def resolve_alert(self, name: str):
        """解决告警"""
        with self._lock:
            for alert in self._alerts:
                if alert.name == name and not alert.resolved:
                    alert.resolved = True

    def get_recent_alerts(self, count: int = 10) -> List[Dict]:
        """获取最近告警"""
        return [
            {
                "name": a.name,
                "severity": a.severity.value,
                "message": a.message,
                "value": a.value,
                "threshold": a.threshold,
                "timestamp": a.timestamp,
                "resolved": a.resolved,
            }
            for a in self._alerts[-count:]
        ]

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "active_alerts": len(self.get_active_alerts()),
            "thresholds": self.thresholds,
        }
