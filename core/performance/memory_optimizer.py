#!/usr/bin/env python3
"""
内存优化模块
提供流式处理、对象池、结果分页、内存监控等功能
"""

import gc
import logging
import sys
import threading
import time
import weakref
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    Generic,
    Iterable,
    Iterator,
    List,
    Optional,
    TypeVar,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ============== 流式结果处理器 ==============


class StreamingResultProcessor(Generic[T]):
    """
    流式结果处理器 - 避免大结果集内存溢出

    特性:
    - 分块处理大数据集
    - 支持生成器输入
    - 自动内存监控
    - 可配置缓冲区大小
    """

    def __init__(
        self,
        chunk_size: int = 1000,
        max_buffer_size: int = 10000,
        on_chunk: Optional[Callable[[List[T]], None]] = None,
    ):
        self.chunk_size = chunk_size
        self.max_buffer_size = max_buffer_size
        self.on_chunk = on_chunk
        self._buffer: deque = deque(maxlen=max_buffer_size)
        self._processed_count = 0
        self._lock = threading.Lock()

    def process_stream(
        self, data_source: Iterable[T], processor: Callable[[T], Any]
    ) -> Generator[Any, None, None]:
        """流式处理数据源"""
        chunk = []

        for item in data_source:
            try:
                result = processor(item)
                chunk.append(result)
                self._processed_count += 1

                if len(chunk) >= self.chunk_size:
                    if self.on_chunk:
                        self.on_chunk(chunk)
                    yield from chunk
                    chunk = []

                    # 定期触发GC
                    if self._processed_count % (self.chunk_size * 10) == 0:
                        gc.collect()

            except Exception as e:
                logger.warning(f"处理项目失败: {e}")
                continue

        # 处理剩余数据
        if chunk:
            if self.on_chunk:
                self.on_chunk(chunk)
            yield from chunk

    def collect_results(
        self,
        data_source: Iterable[T],
        processor: Callable[[T], Any],
        max_results: Optional[int] = None,
    ) -> List[Any]:
        """收集处理结果(带限制)"""
        results = []
        limit = max_results or self.max_buffer_size

        for result in self.process_stream(data_source, processor):
            results.append(result)
            if len(results) >= limit:
                logger.warning(f"结果数量达到限制 {limit}，停止收集")
                break

        return results

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "processed_count": self._processed_count,
            "buffer_size": len(self._buffer),
            "chunk_size": self.chunk_size,
        }


# ============== 对象池 ==============


class ObjectPool(Generic[T]):
    """
    对象池 - 复用昂贵对象，减少GC压力

    适用场景:
    - HTTP客户端
    - 数据库连接
    - 正则表达式对象
    - 大型数据结构
    """

    def __init__(
        self,
        factory: Callable[[], T],
        max_size: int = 100,
        min_size: int = 5,
        reset_func: Optional[Callable[[T], None]] = None,
        validate_func: Optional[Callable[[T], bool]] = None,
    ):
        self._factory = factory
        self._max_size = max_size
        self._min_size = min_size
        self._reset_func = reset_func
        self._validate_func = validate_func

        self._pool: deque = deque()
        self._in_use: weakref.WeakSet = weakref.WeakSet()
        self._lock = threading.Lock()
        self._created_count = 0
        self._reuse_count = 0

        # 预创建最小数量对象
        self._warm_up()

    def _warm_up(self):
        """预热对象池"""
        for _ in range(self._min_size):
            obj = self._factory()
            self._pool.append(obj)
            self._created_count += 1

    def acquire(self) -> T:
        """获取对象"""
        with self._lock:
            while self._pool:
                obj = self._pool.popleft()

                # 验证对象有效性
                if self._validate_func and not self._validate_func(obj):
                    continue

                self._in_use.add(obj)
                self._reuse_count += 1
                return obj

            # 池为空，创建新对象
            if self._created_count < self._max_size:
                obj = self._factory()
                self._created_count += 1
                self._in_use.add(obj)
                return obj

            # 达到最大限制，等待
            raise RuntimeError("对象池已满，无法获取对象")

    def release(self, obj: T):
        """释放对象回池"""
        with self._lock:
            if obj in self._in_use:
                # 重置对象状态
                if self._reset_func:
                    try:
                        self._reset_func(obj)
                    except (TypeError, AttributeError, RuntimeError):
                        return  # 重置失败，丢弃对象

                if len(self._pool) < self._max_size:
                    self._pool.append(obj)

    @contextmanager
    def get(self):
        """上下文管理器方式获取对象"""
        obj = self.acquire()
        try:
            yield obj
        finally:
            self.release(obj)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "pool_size": len(self._pool),
            "in_use": len(self._in_use),
            "created_count": self._created_count,
            "reuse_count": self._reuse_count,
            "reuse_rate": self._reuse_count / max(self._reuse_count + self._created_count, 1),
        }


# ============== 结果分页器 ==============


@dataclass
class Page(Generic[T]):
    """分页结果"""

    items: List[T]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_prev: bool


class ResultPaginator(Generic[T]):
    """
    结果分页器 - 大结果集分页返回

    特性:
    - 支持懒加载
    - 内存友好
    - 支持游标分页
    """

    def __init__(self, data_source: Iterable[T], page_size: int = 100, max_pages: int = 100):
        self.page_size = page_size
        self.max_pages = max_pages
        self._data_source = data_source
        self._cache: Dict[int, List[T]] = {}
        self._total_items: Optional[int] = None
        self._exhausted = False
        self._iterator: Optional[Iterator[T]] = None

    def _ensure_iterator(self):
        if self._iterator is None:
            self._iterator = iter(self._data_source)

    def _load_page(self, page: int) -> List[T]:
        """加载指定页数据"""
        if page in self._cache:
            return self._cache[page]

        self._ensure_iterator()

        # 加载到目标页
        while not self._exhausted and page not in self._cache:
            items = []
            try:
                for _ in range(self.page_size):
                    items.append(next(self._iterator))
            except StopIteration:
                self._exhausted = True

            if items:
                current_page = len(self._cache)
                self._cache[current_page] = items

        return self._cache.get(page, [])

    def get_page(self, page: int = 0) -> Page[T]:
        """获取指定页"""
        if page < 0:
            page = 0
        if page >= self.max_pages:
            page = self.max_pages - 1

        items = self._load_page(page)

        # 尝试加载下一页以确定是否有更多
        has_next = bool(self._load_page(page + 1)) if not self._exhausted else False

        total_items = sum(len(p) for p in self._cache.values())
        total_pages = len(self._cache)

        return Page(
            items=items,
            page=page,
            page_size=self.page_size,
            total_items=total_items,
            total_pages=total_pages,
            has_next=has_next or not self._exhausted,
            has_prev=page > 0,
        )

    def iter_pages(self) -> Generator[Page[T], None, None]:
        """迭代所有页"""
        page = 0
        while page < self.max_pages:
            result = self.get_page(page)
            if not result.items:
                break
            yield result
            if not result.has_next:
                break
            page += 1


# ============== 内存监控器 ==============


class MemoryMonitor:
    """
    内存监控器 - 实时监控内存使用

    特性:
    - 自动触发GC
    - 内存使用告警
    - 内存泄漏检测
    """

    def __init__(
        self, threshold: float = 0.8, max_memory_mb: int = 512, check_interval: float = 5.0
    ):
        self.threshold = threshold
        self.max_memory_mb = max_memory_mb
        self.check_interval = check_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._history: deque = deque(maxlen=100)
        self._callbacks: List[Callable[[Dict], None]] = []

    def _get_memory_usage(self) -> Dict[str, Any]:
        """获取当前内存使用情况"""
        try:
            import psutil

            process = psutil.Process()
            mem_info = process.memory_info()
            return {
                "rss_mb": mem_info.rss / 1024 / 1024,
                "vms_mb": mem_info.vms / 1024 / 1024,
                "percent": process.memory_percent(),
                "timestamp": time.time(),
            }
        except ImportError:
            # 降级方案
            import resource

            try:
                usage = resource.getrusage(resource.RUSAGE_SELF)
                return {
                    "rss_mb": usage.ru_maxrss / 1024,
                    "vms_mb": 0,
                    "percent": 0,
                    "timestamp": time.time(),
                }
            except (AttributeError, OSError):
                return {
                    "rss_mb": sys.getsizeof(gc.get_objects()) / 1024 / 1024,
                    "vms_mb": 0,
                    "percent": 0,
                    "timestamp": time.time(),
                }

    def _monitor_loop(self):
        """监控循环"""
        while self._running:
            try:
                usage = self._get_memory_usage()
                self._history.append(usage)

                # 检查是否超过阈值
                if usage["rss_mb"] > self.max_memory_mb * self.threshold:
                    logger.warning(
                        f"内存使用率过高: {usage['rss_mb']:.1f}MB "
                        f"(阈值: {self.max_memory_mb * self.threshold:.1f}MB)"
                    )
                    gc.collect()

                    # 触发回调
                    for callback in self._callbacks:
                        try:
                            callback(usage)
                        except Exception as e:
                            logger.error(f"内存告警回调失败: {e}")

                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"内存监控错误: {e}")
                time.sleep(self.check_interval)

    def start(self):
        """启动监控"""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("内存监控已启动")

    def stop(self):
        """停止监控"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        logger.info("内存监控已停止")

    def add_callback(self, callback: Callable[[Dict], None]):
        """添加告警回调"""
        self._callbacks.append(callback)

    def get_current(self) -> Dict[str, Any]:
        """获取当前内存使用"""
        return self._get_memory_usage()

    def get_history(self) -> List[Dict[str, Any]]:
        """获取历史记录"""
        return list(self._history)

    def force_gc(self) -> Dict[str, Any]:
        """强制GC并返回释放情况"""
        before = self._get_memory_usage()
        gc.collect()
        after = self._get_memory_usage()
        return {
            "before_mb": before["rss_mb"],
            "after_mb": after["rss_mb"],
            "freed_mb": before["rss_mb"] - after["rss_mb"],
        }


# ============== 内存高效装饰器 ==============


def memory_efficient(max_items: int = 10000, chunk_size: int = 1000, force_gc: bool = True):
    """
    内存高效装饰器 - 自动限制返回结果数量

    用法:
        @memory_efficient(max_items=5000)
        def scan_ports(target):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            # 处理列表结果
            if isinstance(result, list) and len(result) > max_items:
                logger.warning(f"结果数量 {len(result)} 超过限制 {max_items}，已截断")
                result = result[:max_items]

            # 处理字典中的列表
            elif isinstance(result, dict):
                for key, value in result.items():
                    if isinstance(value, list) and len(value) > max_items:
                        logger.warning(f"字段 {key} 结果数量 {len(value)} 超过限制，已截断")
                        result[key] = value[:max_items]

            # 处理生成器
            elif hasattr(result, "__iter__") and not isinstance(result, (str, bytes, dict)):

                def limited_generator():
                    count = 0
                    for item in result:
                        if count >= max_items:
                            logger.warning(f"生成器结果达到限制 {max_items}")
                            break
                        yield item
                        count += 1
                        if force_gc and count % chunk_size == 0:
                            gc.collect()

                return limited_generator()

            if force_gc:
                gc.collect()

            return result

        return wrapper

    return decorator


# ============== 大对象压缩存储 ==============


class CompressedStorage:
    """
    压缩存储 - 大对象自动压缩

    适用于:
    - 大型扫描结果
    - 历史数据存储
    - 缓存大对象
    """

    def __init__(self, compression_threshold: int = 10240):
        self.compression_threshold = compression_threshold  # 10KB
        self._storage: Dict[str, bytes] = {}
        self._compressed_keys: set = set()

    def _compress(self, data: bytes) -> bytes:
        """压缩数据"""
        import zlib

        return zlib.compress(data, level=6)

    def _decompress(self, data: bytes) -> bytes:
        """解压数据"""
        import zlib

        return zlib.decompress(data)

    def set(self, key: str, value: Any):
        """存储值"""
        import json

        data = json.dumps(value, default=str).encode("utf-8")

        if len(data) > self.compression_threshold:
            data = self._compress(data)
            self._compressed_keys.add(key)
        else:
            self._compressed_keys.discard(key)

        self._storage[key] = data

    def get(self, key: str) -> Optional[Any]:
        """获取值"""
        import json

        if key not in self._storage:
            return None

        data = self._storage[key]
        if key in self._compressed_keys:
            data = self._decompress(data)

        return json.loads(data.decode("utf-8"))

    def delete(self, key: str):
        """删除值"""
        self._storage.pop(key, None)
        self._compressed_keys.discard(key)

    @property
    def stats(self) -> Dict[str, Any]:
        total_size = sum(len(v) for v in self._storage.values())
        return {
            "total_keys": len(self._storage),
            "compressed_keys": len(self._compressed_keys),
            "total_size_kb": total_size / 1024,
            "compression_rate": len(self._compressed_keys) / max(len(self._storage), 1),
        }
