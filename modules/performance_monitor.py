#!/usr/bin/env python3
"""
性能监控模块 - 实时监控工具执行性能
支持耗时统计、瓶颈分析、性能报告
"""

import functools
import logging
import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ExecutionMetrics:
    """执行指标"""

    tool_name: str
    start_time: float
    end_time: float = 0.0
    success: bool = True
    error: Optional[str] = None
    result_size: int = 0

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time else 0.0


@dataclass
class ToolStats:
    """工具统计"""

    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    total_time: float = 0.0
    min_time: float = float("inf")
    max_time: float = 0.0
    last_call: Optional[float] = None
    errors: List[str] = field(default_factory=list)

    @property
    def avg_time(self) -> float:
        return self.total_time / max(self.total_calls, 1)

    @property
    def success_rate(self) -> float:
        return self.successful_calls / max(self.total_calls, 1)


class PerformanceMonitor:
    """性能监控器"""

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self._tool_stats: Dict[str, ToolStats] = defaultdict(ToolStats)
        self._execution_history: List[ExecutionMetrics] = []
        self._lock = threading.RLock()
        self._start_time = time.time()
        self._active_executions: Dict[str, ExecutionMetrics] = {}

    def start_execution(self, tool_name: str, execution_id: Optional[str] = None) -> str:
        """开始执行记录"""
        exec_id = execution_id or f"{tool_name}_{time.time()}"
        metrics = ExecutionMetrics(tool_name=tool_name, start_time=time.time())
        with self._lock:
            self._active_executions[exec_id] = metrics
        return exec_id

    def end_execution(
        self,
        execution_id: str,
        success: bool = True,
        error: Optional[str] = None,
        result_size: int = 0,
    ):
        """结束执行记录"""
        with self._lock:
            if execution_id not in self._active_executions:
                return

            metrics = self._active_executions.pop(execution_id)
            metrics.end_time = time.time()
            metrics.success = success
            metrics.error = error
            metrics.result_size = result_size

            # 更新工具统计
            stats = self._tool_stats[metrics.tool_name]
            stats.total_calls += 1
            stats.total_time += metrics.duration
            stats.min_time = min(stats.min_time, metrics.duration)
            stats.max_time = max(stats.max_time, metrics.duration)
            stats.last_call = metrics.end_time

            if success:
                stats.successful_calls += 1
            else:
                stats.failed_calls += 1
                if error:
                    stats.errors.append(error[:200])  # 限制错误长度
                    stats.errors = stats.errors[-10:]  # 只保留最近10个错误

            # 添加到历史
            self._execution_history.append(metrics)
            if len(self._execution_history) > self.max_history:
                self._execution_history = self._execution_history[-self.max_history :]

    @contextmanager
    def track(self, tool_name: str):
        """上下文管理器方式跟踪"""
        exec_id = self.start_execution(tool_name)
        error = None
        success = True
        try:
            yield exec_id
        except Exception as e:
            error = str(e)
            success = False
            raise
        finally:
            self.end_execution(exec_id, success=success, error=error)

    def get_tool_stats(self, tool_name: Optional[str] = None) -> Dict[str, Any]:
        """获取工具统计"""
        with self._lock:
            if tool_name:
                stats = self._tool_stats.get(tool_name)
                if not stats:
                    return {}
                return {
                    "tool": tool_name,
                    "total_calls": stats.total_calls,
                    "success_rate": round(stats.success_rate, 2),
                    "avg_time": round(stats.avg_time, 3),
                    "min_time": round(stats.min_time, 3) if stats.min_time != float("inf") else 0,
                    "max_time": round(stats.max_time, 3),
                    "recent_errors": stats.errors[-3:],
                }

            return {
                name: {
                    "total_calls": s.total_calls,
                    "success_rate": round(s.success_rate, 2),
                    "avg_time": round(s.avg_time, 3),
                    "min_time": round(s.min_time, 3) if s.min_time != float("inf") else 0,
                    "max_time": round(s.max_time, 3),
                }
                for name, s in self._tool_stats.items()
            }

    def get_slowest_tools(self, top_n: int = 5) -> List[Dict[str, Any]]:
        """获取最慢的工具"""
        with self._lock:
            sorted_tools = sorted(
                self._tool_stats.items(), key=lambda x: x[1].avg_time, reverse=True
            )
            return [
                {
                    "tool": name,
                    "avg_time": round(stats.avg_time, 3),
                    "total_calls": stats.total_calls,
                }
                for name, stats in sorted_tools[:top_n]
            ]

    def get_most_failed_tools(self, top_n: int = 5) -> List[Dict[str, Any]]:
        """获取失败率最高的工具"""
        with self._lock:
            sorted_tools = sorted(
                [(n, s) for n, s in self._tool_stats.items() if s.total_calls > 0],
                key=lambda x: 1 - x[1].success_rate,
                reverse=True,
            )
            return [
                {
                    "tool": name,
                    "success_rate": round(stats.success_rate, 2),
                    "failed_calls": stats.failed_calls,
                    "recent_errors": stats.errors[-2:],
                }
                for name, stats in sorted_tools[:top_n]
            ]

    def get_summary(self) -> Dict[str, Any]:
        """获取性能摘要"""
        with self._lock:
            total_calls = sum(s.total_calls for s in self._tool_stats.values())
            total_success = sum(s.successful_calls for s in self._tool_stats.values())
            total_time = sum(s.total_time for s in self._tool_stats.values())

            return {
                "uptime_seconds": round(time.time() - self._start_time, 1),
                "total_tools": len(self._tool_stats),
                "total_calls": total_calls,
                "total_success": total_success,
                "overall_success_rate": round(total_success / max(total_calls, 1), 2),
                "total_execution_time": round(total_time, 2),
                "avg_execution_time": round(total_time / max(total_calls, 1), 3),
                "active_executions": len(self._active_executions),
                "slowest_tools": self.get_slowest_tools(3),
                "most_failed_tools": self.get_most_failed_tools(3),
            }

    def get_recent_executions(self, limit: int = 20) -> List[Dict[str, Any]]:
        """获取最近执行记录"""
        with self._lock:
            recent = self._execution_history[-limit:]
            return [
                {
                    "tool": m.tool_name,
                    "duration": round(m.duration, 3),
                    "success": m.success,
                    "error": m.error[:100] if m.error else None,
                    "time": datetime.fromtimestamp(m.start_time).isoformat(),
                }
                for m in reversed(recent)
            ]

    def identify_bottlenecks(self) -> Dict[str, Any]:
        """识别性能瓶颈"""
        with self._lock:
            bottlenecks = {"slow_tools": [], "unreliable_tools": [], "recommendations": []}

            for name, stats in self._tool_stats.items():
                if stats.total_calls < 3:
                    continue

                # 慢工具（平均超过5秒）
                if stats.avg_time > 5.0:
                    bottlenecks["slow_tools"].append(
                        {
                            "tool": name,
                            "avg_time": round(stats.avg_time, 2),
                            "suggestion": "考虑增加超时或异步执行",
                        }
                    )

                # 不可靠工具（成功率低于70%）
                if stats.success_rate < 0.7:
                    bottlenecks["unreliable_tools"].append(
                        {
                            "tool": name,
                            "success_rate": round(stats.success_rate, 2),
                            "recent_errors": stats.errors[-2:],
                        }
                    )

            # 生成建议
            if bottlenecks["slow_tools"]:
                bottlenecks["recommendations"].append("存在慢速工具，建议使用异步执行或增加并发")
            if bottlenecks["unreliable_tools"]:
                bottlenecks["recommendations"].append("存在不可靠工具，建议检查网络或目标可达性")

            return bottlenecks

    def reset(self):
        """重置所有统计"""
        with self._lock:
            self._tool_stats.clear()
            self._execution_history.clear()
            self._active_executions.clear()
            self._start_time = time.time()


def monitored(monitor: Optional[PerformanceMonitor] = None):
    """性能监控装饰器"""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            mon = monitor or get_performance_monitor()
            tool_name = func.__name__

            exec_id = mon.start_execution(tool_name)
            try:
                result = func(*args, **kwargs)
                result_size = len(str(result)) if result else 0
                mon.end_execution(exec_id, success=True, result_size=result_size)
                return result
            except Exception as e:
                mon.end_execution(exec_id, success=False, error=str(e))
                raise

        return wrapper

    return decorator


def async_monitored(monitor: Optional[PerformanceMonitor] = None):
    """异步性能监控装饰器"""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            mon = monitor or get_performance_monitor()
            tool_name = func.__name__

            exec_id = mon.start_execution(tool_name)
            try:
                result = await func(*args, **kwargs)
                result_size = len(str(result)) if result else 0
                mon.end_execution(exec_id, success=True, result_size=result_size)
                return result
            except Exception as e:
                mon.end_execution(exec_id, success=False, error=str(e))
                raise

        return wrapper

    return decorator


# 全局监控器实例
_monitor_instance: Optional[PerformanceMonitor] = None
_monitor_lock = threading.Lock()


def get_performance_monitor() -> PerformanceMonitor:
    """获取性能监控器单例（线程安全）"""
    global _monitor_instance
    with _monitor_lock:
        if _monitor_instance is None:
            _monitor_instance = PerformanceMonitor()
        return _monitor_instance


def reset_performance_monitor() -> None:
    """重置性能监控器（仅用于测试）"""
    global _monitor_instance
    with _monitor_lock:
        _monitor_instance = None


# 使用示例
"""
# 装饰器方式
@monitored()
def port_scan(target: str, ports: list):
    # 扫描逻辑
    pass

# 上下文管理器方式
monitor = get_performance_monitor()
with monitor.track("sqli_detect"):
    # 检测逻辑
    pass

# 获取统计
print(monitor.get_summary())
print(monitor.identify_bottlenecks())
"""
