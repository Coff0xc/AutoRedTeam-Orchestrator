#!/usr/bin/env python3
"""
智能缓存系统 - 多层缓存 + TTL + LRU
支持DNS缓存、技术栈缓存、CVE缓存、Payload缓存
"""

import time
import hashlib
import json
import threading
import logging
from typing import Any, Dict, Optional, Callable, TypeVar, Generic
from dataclasses import dataclass, field
from collections import OrderedDict
from pathlib import Path
from functools import wraps

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class CacheEntry(Generic[T]):
    """缓存条目"""
    value: T
    created_at: float
    ttl: float
    hits: int = 0
    last_access: float = field(default_factory=time.time)

    @property
    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl

    def access(self) -> T:
        self.hits += 1
        self.last_access = time.time()
        return self.value


class LRUCache(Generic[T]):
    """LRU缓存实现"""

    def __init__(self, maxsize: int = 1000, default_ttl: float = 300):
        self.maxsize = maxsize
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, CacheEntry[T]] = OrderedDict()
        self._lock = threading.RLock()
        self._stats = {"hits": 0, "misses": 0, "evictions": 0}

    def get(self, key: str) -> Optional[T]:
        """获取缓存值"""
        with self._lock:
            if key not in self._cache:
                self._stats["misses"] += 1
                return None

            entry = self._cache[key]
            if entry.is_expired:
                del self._cache[key]
                self._stats["misses"] += 1
                return None

            # 移到末尾（最近使用）
            self._cache.move_to_end(key)
            self._stats["hits"] += 1
            return entry.access()

    def set(self, key: str, value: T, ttl: Optional[float] = None):
        """设置缓存值"""
        with self._lock:
            if key in self._cache:
                del self._cache[key]

            # 检查容量
            while len(self._cache) >= self.maxsize:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                self._stats["evictions"] += 1

            self._cache[key] = CacheEntry(
                value=value,
                created_at=time.time(),
                ttl=ttl or self.default_ttl
            )

    def delete(self, key: str) -> bool:
        """删除缓存"""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def clear(self):
        """清空缓存"""
        with self._lock:
            self._cache.clear()

    def cleanup(self):
        """清理过期条目"""
        with self._lock:
            expired = [k for k, v in self._cache.items() if v.is_expired]
            for key in expired:
                del self._cache[key]
            return len(expired)

    @property
    def stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._lock:
            total = self._stats["hits"] + self._stats["misses"]
            return {
                "size": len(self._cache),
                "maxsize": self.maxsize,
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "evictions": self._stats["evictions"],
                "hit_rate": self._stats["hits"] / max(total, 1)
            }


class SmartCache:
    """智能多层缓存系统"""

    # 缓存类型配置
    CACHE_CONFIG = {
        "dns": {"maxsize": 1000, "ttl": 300},      # DNS: 5分钟
        "tech": {"maxsize": 500, "ttl": 3600},     # 技术栈: 1小时
        "cve": {"maxsize": 500, "ttl": 7200},      # CVE: 2小时
        "payload": {"maxsize": 200, "ttl": 86400}, # Payload: 24小时
        "recon": {"maxsize": 100, "ttl": 1800},    # 侦察结果: 30分钟
        "vuln": {"maxsize": 200, "ttl": 3600},     # 漏洞结果: 1小时
    }

    def __init__(self, persist_path: Optional[Path] = None):
        self._caches: Dict[str, LRUCache] = {}
        self.persist_path = persist_path
        self._init_caches()
        self._load_persistent()

    def _init_caches(self):
        """初始化各类型缓存"""
        for cache_type, config in self.CACHE_CONFIG.items():
            self._caches[cache_type] = LRUCache(
                maxsize=config["maxsize"],
                default_ttl=config["ttl"]
            )

    def _load_persistent(self):
        """加载持久化缓存"""
        if not self.persist_path or not self.persist_path.exists():
            return

        try:
            with open(self.persist_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for cache_type, entries in data.items():
                if cache_type in self._caches:
                    for key, entry in entries.items():
                        # 检查是否过期
                        if time.time() - entry["created_at"] < entry["ttl"]:
                            self._caches[cache_type].set(
                                key, entry["value"], entry["ttl"]
                            )
            logger.info(f"加载持久化缓存成功")
        except Exception as e:
            logger.warning(f"加载持久化缓存失败: {e}")

    def _save_persistent(self):
        """保存持久化缓存"""
        if not self.persist_path:
            return

        try:
            data = {}
            for cache_type, cache in self._caches.items():
                data[cache_type] = {}
                for key, entry in cache._cache.items():
                    if not entry.is_expired:
                        data[cache_type][key] = {
                            "value": entry.value,
                            "created_at": entry.created_at,
                            "ttl": entry.ttl
                        }

            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.persist_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"保存持久化缓存失败: {e}")

    def get(self, cache_type: str, key: str) -> Optional[Any]:
        """获取缓存"""
        if cache_type not in self._caches:
            return None
        return self._caches[cache_type].get(key)

    def set(self, cache_type: str, key: str, value: Any, ttl: Optional[float] = None):
        """设置缓存"""
        if cache_type not in self._caches:
            # 动态创建缓存
            self._caches[cache_type] = LRUCache(maxsize=500, default_ttl=ttl or 300)
        self._caches[cache_type].set(key, value, ttl)

    def delete(self, cache_type: str, key: str) -> bool:
        """删除缓存"""
        if cache_type not in self._caches:
            return False
        return self._caches[cache_type].delete(key)

    def clear(self, cache_type: Optional[str] = None):
        """清空缓存"""
        if cache_type:
            if cache_type in self._caches:
                self._caches[cache_type].clear()
        else:
            for cache in self._caches.values():
                cache.clear()

    def cleanup(self) -> Dict[str, int]:
        """清理所有过期条目"""
        result = {}
        for cache_type, cache in self._caches.items():
            result[cache_type] = cache.cleanup()
        return result

    def stats(self) -> Dict[str, Any]:
        """获取所有缓存统计"""
        return {
            cache_type: cache.stats
            for cache_type, cache in self._caches.items()
        }

    def save(self):
        """手动保存"""
        self._save_persistent()

    # 便捷方法
    def cache_dns(self, domain: str, records: list):
        self.set("dns", domain, records)

    def get_dns(self, domain: str) -> Optional[list]:
        return self.get("dns", domain)

    def cache_tech(self, url: str, tech_info: dict):
        self.set("tech", url, tech_info)

    def get_tech(self, url: str) -> Optional[dict]:
        return self.get("tech", url)

    def cache_cve(self, keyword: str, cve_list: list):
        self.set("cve", keyword, cve_list)

    def get_cve(self, keyword: str) -> Optional[list]:
        return self.get("cve", keyword)


def cached(cache_type: str, key_func: Optional[Callable] = None, ttl: Optional[float] = None):
    """缓存装饰器"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 生成缓存键
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # 默认使用参数哈希
                key_data = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True, default=str)
                cache_key = hashlib.md5(key_data.encode()).hexdigest()

            # 尝试从缓存获取
            cache = get_smart_cache()
            cached_value = cache.get(cache_type, cache_key)
            if cached_value is not None:
                return cached_value

            # 执行函数
            result = func(*args, **kwargs)

            # 存入缓存
            cache.set(cache_type, cache_key, result, ttl)
            return result

        return wrapper
    return decorator


def async_cached(cache_type: str, key_func: Optional[Callable] = None, ttl: Optional[float] = None):
    """异步缓存装饰器"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                key_data = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True, default=str)
                cache_key = hashlib.md5(key_data.encode()).hexdigest()

            cache = get_smart_cache()
            cached_value = cache.get(cache_type, cache_key)
            if cached_value is not None:
                return cached_value

            result = await func(*args, **kwargs)
            cache.set(cache_type, cache_key, result, ttl)
            return result

        return wrapper
    return decorator


# 全局缓存实例
_cache_instance: Optional[SmartCache] = None

def get_smart_cache() -> SmartCache:
    """获取智能缓存单例"""
    global _cache_instance
    if _cache_instance is None:
        import tempfile
        persist_path = Path(tempfile.gettempdir()) / "autored_cache.json"
        _cache_instance = SmartCache(persist_path=persist_path)
    return _cache_instance


# 使用示例
"""
# 装饰器方式
@cached("dns", key_func=lambda domain, *_: domain, ttl=300)
def resolve_dns(domain: str) -> list:
    # DNS解析逻辑
    pass

# 直接使用
cache = get_smart_cache()
cache.cache_dns("example.com", ["1.2.3.4"])
records = cache.get_dns("example.com")
"""
