#!/usr/bin/env python3
"""
并发控制模块
提供动态线程池、连接池管理、限流器、熔断器、舱壁隔离等功能
"""

import asyncio
import time
import threading
import logging
from typing import Any, Dict, List, Optional, Callable, TypeVar
from dataclasses import dataclass, field
from collections import deque
from concurrent.futures import ThreadPoolExecutor, Future
from contextlib import contextmanager
from enum import Enum
from functools import wraps

logger = logging.getLogger(__name__)

T = TypeVar('T')


# ============== 动态线程池 ==============

class DynamicThreadPool:
    """
    动态线程池 - 根据负载自动调整线程数

    特性:
    - 自适应线程数量
    - 任务队列监控
    - 线程健康检查
    - 优雅关闭
    """

    def __init__(
        self,
        min_threads: int = 5,
        max_threads: int = 100,
        initial_threads: int = 20,
        queue_size: int = 1000,
        scale_up_threshold: float = 0.8,
        scale_down_threshold: float = 0.2,
        adjust_interval: float = 5.0
    ):
        self.min_threads = min_threads
        self.max_threads = max_threads
        self.current_threads = initial_threads
        self.queue_size = queue_size
        self.scale_up_threshold = scale_up_threshold
        self.scale_down_threshold = scale_down_threshold
        self.adjust_interval = adjust_interval

        self._executor: Optional[ThreadPoolExecutor] = None
        self._pending_tasks: deque = deque()
        self._active_count = 0
        self._lock = threading.Lock()
        self._running = False
        self._adjuster_thread: Optional[threading.Thread] = None

        # 统计信息
        self._stats = {
            "submitted": 0,
            "completed": 0,
            "failed": 0,
            "scale_ups": 0,
            "scale_downs": 0
        }

    def start(self):
        """启动线程池"""
        if self._running:
            return

        self._executor = ThreadPoolExecutor(
            max_workers=self.current_threads,
            thread_name_prefix="DynamicPool"
        )
        self._running = True

        # 启动自动调整线程
        self._adjuster_thread = threading.Thread(
            target=self._auto_adjust_loop,
            daemon=True
        )
        self._adjuster_thread.start()
        logger.info(f"动态线程池已启动，初始线程数: {self.current_threads}")

    def stop(self, wait: bool = True):
        """停止线程池"""
        self._running = False
        if self._executor:
            self._executor.shutdown(wait=wait)
            self._executor = None
        logger.info("动态线程池已停止")

    def _auto_adjust_loop(self):
        """自动调整线程数循环"""
        while self._running:
            try:
                self._adjust_pool_size()
                time.sleep(self.adjust_interval)
            except Exception as e:
                logger.error(f"线程池调整错误: {e}")

    def _adjust_pool_size(self):
        """根据负载调整线程池大小"""
        if not self._executor:
            return

        with self._lock:
            # 计算负载率
            load_ratio = self._active_count / max(self.current_threads, 1)

            new_size = self.current_threads

            if load_ratio > self.scale_up_threshold:
                # 扩容
                new_size = min(
                    int(self.current_threads * 1.5),
                    self.max_threads
                )
                if new_size > self.current_threads:
                    self._stats["scale_ups"] += 1
                    logger.debug(f"线程池扩容: {self.current_threads} -> {new_size}")

            elif load_ratio < self.scale_down_threshold:
                # 缩容
                new_size = max(
                    int(self.current_threads * 0.7),
                    self.min_threads
                )
                if new_size < self.current_threads:
                    self._stats["scale_downs"] += 1
                    logger.debug(f"线程池缩容: {self.current_threads} -> {new_size}")

            if new_size != self.current_threads:
                self.current_threads = new_size
                # 重建线程池
                old_executor = self._executor
                self._executor = ThreadPoolExecutor(
                    max_workers=new_size,
                    thread_name_prefix="DynamicPool"
                )
                # 等待旧任务完成后关闭
                threading.Thread(
                    target=lambda: old_executor.shutdown(wait=True),
                    daemon=True
                ).start()

    def submit(self, fn: Callable, *args, **kwargs) -> Future:
        """提交任务"""
        if not self._running or not self._executor:
            raise RuntimeError("线程池未启动")

        with self._lock:
            self._active_count += 1
            self._stats["submitted"] += 1

        def wrapped_fn():
            try:
                return fn(*args, **kwargs)
            finally:
                with self._lock:
                    self._active_count -= 1
                    self._stats["completed"] += 1

        return self._executor.submit(wrapped_fn)

    def map(self, fn: Callable, iterables, timeout: Optional[float] = None):
        """批量执行"""
        if not self._running or not self._executor:
            raise RuntimeError("线程池未启动")
        return self._executor.map(fn, iterables, timeout=timeout)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "current_threads": self.current_threads,
            "active_count": self._active_count,
            "load_ratio": self._active_count / max(self.current_threads, 1)
        }


# ============== 连接池管理器 ==============

@dataclass
class ConnectionInfo:
    """连接信息"""
    connection: Any
    created_at: float
    last_used: float
    use_count: int = 0
    healthy: bool = True


class ConnectionPoolManager:
    """
    连接池管理器 - 管理HTTP/数据库等连接

    特性:
    - 连接复用
    - 健康检查
    - 自动清理过期连接
    - 按域名/主机分组
    """

    def __init__(
        self,
        max_connections: int = 50,
        max_per_host: int = 10,
        connection_ttl: float = 300.0,
        health_check_interval: float = 30.0,
        factory: Optional[Callable[[], Any]] = None,
        health_checker: Optional[Callable[[Any], bool]] = None,
        closer: Optional[Callable[[Any], None]] = None
    ):
        self.max_connections = max_connections
        self.max_per_host = max_per_host
        self.connection_ttl = connection_ttl
        self.health_check_interval = health_check_interval
        self._factory = factory
        self._health_checker = health_checker
        self._closer = closer

        self._pools: Dict[str, deque] = {}
        self._in_use: Dict[str, set] = {}
        self._lock = threading.Lock()
        self._running = False
        self._cleaner_thread: Optional[threading.Thread] = None

        # 统计
        self._stats = {
            "created": 0,
            "reused": 0,
            "closed": 0,
            "health_check_failed": 0
        }

    def start(self):
        """启动连接池"""
        if self._running:
            return
        self._running = True
        self._cleaner_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True
        )
        self._cleaner_thread.start()
        logger.info("连接池管理器已启动")

    def stop(self):
        """停止连接池"""
        self._running = False
        self._close_all()
        logger.info("连接池管理器已停止")

    def _cleanup_loop(self):
        """清理过期连接循环"""
        while self._running:
            try:
                self._cleanup_expired()
                time.sleep(self.health_check_interval)
            except Exception as e:
                logger.error(f"连接池清理错误: {e}")

    def _cleanup_expired(self):
        """清理过期连接"""
        now = time.time()
        with self._lock:
            for host, pool in list(self._pools.items()):
                expired = []
                for conn_info in pool:
                    if now - conn_info.created_at > self.connection_ttl:
                        expired.append(conn_info)
                    elif self._health_checker and not self._health_checker(conn_info.connection):
                        expired.append(conn_info)
                        self._stats["health_check_failed"] += 1

                for conn_info in expired:
                    pool.remove(conn_info)
                    self._close_connection(conn_info.connection)

    def _close_connection(self, conn: Any):
        """关闭连接"""
        try:
            if self._closer:
                self._closer(conn)
            elif hasattr(conn, 'close'):
                conn.close()
            self._stats["closed"] += 1
        except Exception as e:
            logger.warning(f"关闭连接失败: {e}")

    def _close_all(self):
        """关闭所有连接"""
        with self._lock:
            for pool in self._pools.values():
                for conn_info in pool:
                    self._close_connection(conn_info.connection)
            self._pools.clear()
            self._in_use.clear()

    def acquire(self, host: str = "default") -> Any:
        """获取连接"""
        with self._lock:
            if host not in self._pools:
                self._pools[host] = deque()
                self._in_use[host] = set()

            pool = self._pools[host]

            # 尝试复用连接
            while pool:
                conn_info = pool.popleft()
                if self._health_checker and not self._health_checker(conn_info.connection):
                    self._close_connection(conn_info.connection)
                    continue

                conn_info.last_used = time.time()
                conn_info.use_count += 1
                self._in_use[host].add(id(conn_info.connection))
                self._stats["reused"] += 1
                return conn_info.connection

            # 检查是否达到限制
            total_connections = sum(len(p) + len(self._in_use.get(h, set()))
                                   for h, p in self._pools.items())
            if total_connections >= self.max_connections:
                raise RuntimeError("连接池已满")

            if len(self._in_use[host]) >= self.max_per_host:
                raise RuntimeError(f"主机 {host} 连接数已达上限")

            # 创建新连接
            if self._factory:
                conn = self._factory()
            else:
                raise RuntimeError("未设置连接工厂")

            self._in_use[host].add(id(conn))
            self._stats["created"] += 1
            return conn

    def release(self, conn: Any, host: str = "default"):
        """释放连接"""
        with self._lock:
            if host in self._in_use:
                self._in_use[host].discard(id(conn))

            if host not in self._pools:
                self._pools[host] = deque()

            conn_info = ConnectionInfo(
                connection=conn,
                created_at=time.time(),
                last_used=time.time()
            )
            self._pools[host].append(conn_info)

    @contextmanager
    def get_connection(self, host: str = "default"):
        """上下文管理器方式获取连接"""
        conn = self.acquire(host)
        try:
            yield conn
        finally:
            self.release(conn, host)

    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                **self._stats,
                "pool_sizes": {h: len(p) for h, p in self._pools.items()},
                "in_use": {h: len(s) for h, s in self._in_use.items()}
            }


# ============== 令牌桶限流器 ==============

class RateLimiter:
    """
    令牌桶限流器 - 控制请求速率

    特性:
    - 令牌桶算法
    - 支持突发流量
    - 异步/同步双模式
    - 按域名/资源分组限流
    """

    def __init__(
        self,
        rate: float = 10.0,
        burst: int = 20,
        per_key_rate: Optional[float] = None
    ):
        self.rate = rate  # 每秒令牌数
        self.burst = burst  # 桶容量
        self.per_key_rate = per_key_rate or rate

        self._tokens = float(burst)
        self._last_update = time.monotonic()
        self._lock = threading.Lock()
        self._async_lock: Optional[asyncio.Lock] = None

        # 按key分组的限流器
        self._key_limiters: Dict[str, Dict] = {}

        # 统计
        self._stats = {
            "allowed": 0,
            "throttled": 0,
            "wait_time_total": 0.0
        }

    def _refill(self):
        """补充令牌"""
        now = time.monotonic()
        elapsed = now - self._last_update
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last_update = now

    def acquire(self, tokens: int = 1, key: Optional[str] = None) -> bool:
        """同步获取令牌"""
        with self._lock:
            if key:
                return self._acquire_for_key(key, tokens)

            self._refill()

            if self._tokens >= tokens:
                self._tokens -= tokens
                self._stats["allowed"] += 1
                return True

            self._stats["throttled"] += 1
            return False

    def _acquire_for_key(self, key: str, tokens: int) -> bool:
        """按key获取令牌"""
        if key not in self._key_limiters:
            self._key_limiters[key] = {
                "tokens": float(self.burst),
                "last_update": time.monotonic()
            }

        limiter = self._key_limiters[key]
        now = time.monotonic()
        elapsed = now - limiter["last_update"]
        limiter["tokens"] = min(self.burst, limiter["tokens"] + elapsed * self.per_key_rate)
        limiter["last_update"] = now

        if limiter["tokens"] >= tokens:
            limiter["tokens"] -= tokens
            self._stats["allowed"] += 1
            return True

        self._stats["throttled"] += 1
        return False

    def wait(self, tokens: int = 1, key: Optional[str] = None, timeout: float = 30.0) -> bool:
        """等待获取令牌"""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if self.acquire(tokens, key):
                self._stats["wait_time_total"] += time.monotonic() - start
                return True
            time.sleep(0.01)
        return False

    async def async_acquire(self, tokens: int = 1, key: Optional[str] = None) -> bool:
        """异步获取令牌"""
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()

        async with self._async_lock:
            return self.acquire(tokens, key)

    async def async_wait(self, tokens: int = 1, key: Optional[str] = None, timeout: float = 30.0) -> bool:
        """异步等待获取令牌"""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if await self.async_acquire(tokens, key):
                self._stats["wait_time_total"] += time.monotonic() - start
                return True
            await asyncio.sleep(0.01)
        return False

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "current_tokens": self._tokens,
            "rate": self.rate,
            "burst": self.burst,
            "key_count": len(self._key_limiters)
        }


# ============== 熔断器 ==============

class CircuitState(Enum):
    """熔断器状态"""
    CLOSED = "closed"      # 正常
    OPEN = "open"          # 熔断
    HALF_OPEN = "half_open"  # 半开


class CircuitBreaker:
    """
    熔断器 - 防止级联故障

    特性:
    - 三态模型(关闭/打开/半开)
    - 失败计数
    - 自动恢复
    - 按服务分组
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        success_threshold: int = 3,
        timeout: float = 30.0,
        half_open_max_calls: int = 3
    ):
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.timeout = timeout
        self.half_open_max_calls = half_open_max_calls

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._half_open_calls = 0
        self._lock = threading.Lock()

        # 按服务分组
        self._service_breakers: Dict[str, Dict] = {}

        # 统计
        self._stats = {
            "total_calls": 0,
            "successful_calls": 0,
            "failed_calls": 0,
            "rejected_calls": 0,
            "state_changes": 0
        }

    def _get_service_state(self, service: str) -> Dict:
        """获取服务状态"""
        if service not in self._service_breakers:
            self._service_breakers[service] = {
                "state": CircuitState.CLOSED,
                "failure_count": 0,
                "success_count": 0,
                "last_failure_time": None,
                "half_open_calls": 0
            }
        return self._service_breakers[service]

    def can_execute(self, service: Optional[str] = None) -> bool:
        """检查是否可以执行"""
        with self._lock:
            if service:
                state = self._get_service_state(service)
            else:
                state = {
                    "state": self._state,
                    "last_failure_time": self._last_failure_time,
                    "half_open_calls": self._half_open_calls
                }

            self._stats["total_calls"] += 1

            if state["state"] == CircuitState.CLOSED:
                return True

            if state["state"] == CircuitState.OPEN:
                # 检查是否可以转为半开
                if state["last_failure_time"] and \
                   time.time() - state["last_failure_time"] > self.timeout:
                    self._transition_to_half_open(service)
                    return True
                self._stats["rejected_calls"] += 1
                return False

            if state["state"] == CircuitState.HALF_OPEN:
                if state["half_open_calls"] < self.half_open_max_calls:
                    if service:
                        self._service_breakers[service]["half_open_calls"] += 1
                    else:
                        self._half_open_calls += 1
                    return True
                self._stats["rejected_calls"] += 1
                return False

            return False

    def record_success(self, service: Optional[str] = None):
        """记录成功"""
        with self._lock:
            self._stats["successful_calls"] += 1

            if service:
                state = self._get_service_state(service)
                state["failure_count"] = 0
                state["success_count"] += 1

                if state["state"] == CircuitState.HALF_OPEN:
                    if state["success_count"] >= self.success_threshold:
                        self._transition_to_closed(service)
            else:
                self._failure_count = 0
                self._success_count += 1

                if self._state == CircuitState.HALF_OPEN:
                    if self._success_count >= self.success_threshold:
                        self._transition_to_closed()

    def record_failure(self, service: Optional[str] = None):
        """记录失败"""
        with self._lock:
            self._stats["failed_calls"] += 1

            if service:
                state = self._get_service_state(service)
                state["failure_count"] += 1
                state["last_failure_time"] = time.time()

                if state["state"] == CircuitState.HALF_OPEN:
                    self._transition_to_open(service)
                elif state["failure_count"] >= self.failure_threshold:
                    self._transition_to_open(service)
            else:
                self._failure_count += 1
                self._last_failure_time = time.time()

                if self._state == CircuitState.HALF_OPEN:
                    self._transition_to_open()
                elif self._failure_count >= self.failure_threshold:
                    self._transition_to_open()

    def _transition_to_open(self, service: Optional[str] = None):
        """转为打开状态"""
        self._stats["state_changes"] += 1
        if service:
            self._service_breakers[service]["state"] = CircuitState.OPEN
            logger.warning(f"熔断器打开: {service}")
        else:
            self._state = CircuitState.OPEN
            logger.warning("熔断器打开")

    def _transition_to_half_open(self, service: Optional[str] = None):
        """转为半开状态"""
        self._stats["state_changes"] += 1
        if service:
            state = self._service_breakers[service]
            state["state"] = CircuitState.HALF_OPEN
            state["half_open_calls"] = 0
            state["success_count"] = 0
            logger.info(f"熔断器半开: {service}")
        else:
            self._state = CircuitState.HALF_OPEN
            self._half_open_calls = 0
            self._success_count = 0
            logger.info("熔断器半开")

    def _transition_to_closed(self, service: Optional[str] = None):
        """转为关闭状态"""
        self._stats["state_changes"] += 1
        if service:
            state = self._service_breakers[service]
            state["state"] = CircuitState.CLOSED
            state["failure_count"] = 0
            logger.info(f"熔断器关闭: {service}")
        else:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            logger.info("熔断器关闭")

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "current_state": self._state.value,
            "failure_count": self._failure_count,
            "services": {
                s: {"state": d["state"].value, "failures": d["failure_count"]}
                for s, d in self._service_breakers.items()
            }
        }


# ============== 舱壁隔离 ==============

class Bulkhead:
    """
    舱壁隔离 - 限制并发调用数

    特性:
    - 限制最大并发
    - 队列等待
    - 超时控制
    - 按服务分组
    """

    def __init__(
        self,
        max_concurrent: int = 10,
        max_wait_queue: int = 100,
        wait_timeout: float = 30.0
    ):
        self.max_concurrent = max_concurrent
        self.max_wait_queue = max_wait_queue
        self.wait_timeout = wait_timeout

        self._semaphore = threading.Semaphore(max_concurrent)
        self._async_semaphore: Optional[asyncio.Semaphore] = None
        self._current_count = 0
        self._waiting_count = 0
        self._lock = threading.Lock()

        # 按服务分组
        self._service_bulkheads: Dict[str, threading.Semaphore] = {}

        # 统计
        self._stats = {
            "acquired": 0,
            "rejected": 0,
            "timeout": 0
        }

    def acquire(self, service: Optional[str] = None, timeout: Optional[float] = None) -> bool:
        """获取执行许可"""
        timeout = timeout or self.wait_timeout

        with self._lock:
            if self._waiting_count >= self.max_wait_queue:
                self._stats["rejected"] += 1
                return False
            self._waiting_count += 1

        try:
            if service:
                if service not in self._service_bulkheads:
                    self._service_bulkheads[service] = threading.Semaphore(self.max_concurrent)
                semaphore = self._service_bulkheads[service]
            else:
                semaphore = self._semaphore

            acquired = semaphore.acquire(timeout=timeout)

            with self._lock:
                self._waiting_count -= 1
                if acquired:
                    self._current_count += 1
                    self._stats["acquired"] += 1
                else:
                    self._stats["timeout"] += 1

            return acquired
        except Exception:
            with self._lock:
                self._waiting_count -= 1
            return False

    def release(self, service: Optional[str] = None):
        """释放执行许可"""
        if service and service in self._service_bulkheads:
            self._service_bulkheads[service].release()
        else:
            self._semaphore.release()

        with self._lock:
            self._current_count = max(0, self._current_count - 1)

    @contextmanager
    def execute(self, service: Optional[str] = None, timeout: Optional[float] = None):
        """上下文管理器方式执行"""
        if not self.acquire(service, timeout):
            raise RuntimeError("无法获取执行许可")
        try:
            yield
        finally:
            self.release(service)

    async def async_acquire(self, service: Optional[str] = None) -> bool:
        """异步获取执行许可"""
        if self._async_semaphore is None:
            self._async_semaphore = asyncio.Semaphore(self.max_concurrent)

        try:
            await asyncio.wait_for(
                self._async_semaphore.acquire(),
                timeout=self.wait_timeout
            )
            self._stats["acquired"] += 1
            return True
        except asyncio.TimeoutError:
            self._stats["timeout"] += 1
            return False

    async def async_release(self):
        """异步释放执行许可"""
        if self._async_semaphore:
            self._async_semaphore.release()

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "current_count": self._current_count,
            "waiting_count": self._waiting_count,
            "max_concurrent": self.max_concurrent
        }


# ============== 装饰器 ==============

def rate_limited(rate: float = 10.0, burst: int = 20, key_func: Optional[Callable] = None):
    """限流装饰器"""
    limiter = RateLimiter(rate=rate, burst=burst)

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = key_func(*args, **kwargs) if key_func else None
            if not limiter.wait(key=key):
                raise RuntimeError("请求被限流")
            return func(*args, **kwargs)
        return wrapper
    return decorator


def circuit_protected(
    failure_threshold: int = 5,
    timeout: float = 30.0,
    service_func: Optional[Callable] = None
):
    """熔断器装饰器"""
    breaker = CircuitBreaker(failure_threshold=failure_threshold, timeout=timeout)

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            service = service_func(*args, **kwargs) if service_func else None
            if not breaker.can_execute(service):
                raise RuntimeError("服务熔断中")
            try:
                result = func(*args, **kwargs)
                breaker.record_success(service)
                return result
            except Exception as e:
                breaker.record_failure(service)
                raise e
        return wrapper
    return decorator


def bulkhead_isolated(max_concurrent: int = 10, service_func: Optional[Callable] = None):
    """舱壁隔离装饰器"""
    bulkhead = Bulkhead(max_concurrent=max_concurrent)

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            service = service_func(*args, **kwargs) if service_func else None
            with bulkhead.execute(service):
                return func(*args, **kwargs)
        return wrapper
    return decorator
