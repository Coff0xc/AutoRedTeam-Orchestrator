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
from enum import Enum
from typing import Any, Dict, Optional, Callable, TypeVar, Generic, Union
from dataclasses import dataclass, field
from collections import OrderedDict
from pathlib import Path
from functools import wraps

logger = logging.getLogger(__name__)


class CacheType(str, Enum):
    """缓存类型枚举 - 继承str实现向后兼容"""
    DNS = "dns"
    TECH = "tech"
    CVE = "cve"
    PAYLOAD = "payload"
    RECON = "recon"
    VULN = "vuln"

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
        "fingerprint": {"maxsize": 500, "ttl": 7200}, # 组件指纹: 2小时
        "response": {"maxsize": 300, "ttl": 600},  # 响应缓存: 10分钟
    }
    
    # 预热配置
    PREHEAT_CONFIG = {
        "dns": ["google.com", "cloudflare.com", "github.com"],
        "cve": ["apache", "nginx", "spring", "log4j"],
    }

    def __init__(self, persist_path: Optional[Path] = None, redis_url: Optional[str] = None):
        self._caches: Dict[str, LRUCache] = {}
        self.persist_path = persist_path
        self._redis_client = None
        self._use_redis = False
        self._bloom_filters: Dict[str, set] = {}  # 简化版布隆过滤器
        
        # 初始化Redis分布式缓存
        if redis_url:
            self._init_redis(redis_url)
            
        self._init_caches()
        self._load_persistent()

    def _init_redis(self, redis_url: str):
        """初始化Redis分布式缓存"""
        try:
            import redis
            self._redis_client = redis.from_url(redis_url, decode_responses=True)
            self._redis_client.ping()
            self._use_redis = True
            logger.info("Redis分布式缓存初始化成功")
        except ImportError:
            logger.warning("Redis模块未安装，使用本地缓存")
        except Exception as e:
            logger.warning(f"Redis连接失败: {e}，使用本地缓存")

    def _init_caches(self):
        """初始化各类型缓存"""
        for cache_type, config in self.CACHE_CONFIG.items():
            self._caches[cache_type] = LRUCache(
                maxsize=config["maxsize"],
                default_ttl=config["ttl"]
            )
            self._bloom_filters[cache_type] = set()  # 初始化布隆过滤器

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

    def get(self, cache_type: Union[CacheType, str], key: str) -> Optional[Any]:
        """获取缓存 - 支持L1本地+L2 Redis两级缓存"""
        ct = str(cache_type)
        if ct not in self._caches:
            return None
            
        # 布隆过滤器快速判断（避免无效查询）
        key_hash = hashlib.md5(key.encode()).hexdigest()[:16]
        if key_hash not in self._bloom_filters.get(ct, set()):
            return None
            
        # L1: 本地缓存
        value = self._caches[ct].get(key)
        if value is not None:
            return value
            
        # L2: Redis分布式缓存
        if self._use_redis and self._redis_client:
            try:
                redis_key = f"autored:{ct}:{key}"
                redis_value = self._redis_client.get(redis_key)
                if redis_value:
                    value = json.loads(redis_value)
                    # 回填本地缓存
                    self._caches[ct].set(key, value)
                    return value
            except Exception as e:
                logger.debug(f"Redis读取失败: {e}")
                
        return None

    def set(self, cache_type: Union[CacheType, str], key: str, value: Any, ttl: Optional[float] = None):
        """设置缓存 - 双写L1+L2"""
        ct = str(cache_type)
        if ct not in self._caches:
            self._caches[ct] = LRUCache(maxsize=500, default_ttl=ttl or 300)
            
        # L1: 本地缓存
        self._caches[ct].set(key, value, ttl)
        
        # 更新布隆过滤器
        key_hash = hashlib.md5(key.encode()).hexdigest()[:16]
        self._bloom_filters.setdefault(ct, set()).add(key_hash)
        
        # L2: Redis分布式缓存
        if self._use_redis and self._redis_client:
            try:
                redis_key = f"autored:{ct}:{key}"
                cache_ttl = int(ttl or self.CACHE_CONFIG.get(ct, {}).get("ttl", 300))
                self._redis_client.setex(redis_key, cache_ttl, json.dumps(value, default=str))
            except Exception as e:
                logger.debug(f"Redis写入失败: {e}")

    def delete(self, cache_type: Union[CacheType, str], key: str) -> bool:
        """删除缓存"""
        ct = str(cache_type)
        if ct not in self._caches:
            return False
        return self._caches[ct].delete(key)

    def clear(self, cache_type: Optional[Union[CacheType, str]] = None):
        """清空缓存"""
        if cache_type:
            ct = str(cache_type)
            if ct in self._caches:
                self._caches[ct].clear()
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
    
    def preheat(self, cache_type: Optional[str] = None, data_loader: Optional[Callable] = None):
        """缓存预热 - 提前加载常用数据"""
        if cache_type:
            types_to_preheat = [cache_type]
        else:
            types_to_preheat = list(self.PREHEAT_CONFIG.keys())
            
        preheated = 0
        for ct in types_to_preheat:
            if ct not in self.PREHEAT_CONFIG:
                continue
                
            for key in self.PREHEAT_CONFIG[ct]:
                if self.get(ct, key) is None and data_loader:
                    try:
                        value = data_loader(ct, key)
                        if value:
                            self.set(ct, key, value)
                            preheated += 1
                    except Exception as e:
                        logger.debug(f"预热失败 {ct}:{key}: {e}")
                        
        logger.info(f"缓存预热完成，加载 {preheated} 条数据")
        return preheated
    
    def batch_get(self, cache_type: str, keys: List[str]) -> Dict[str, Any]:
        """批量获取缓存"""
        result = {}
        missing_keys = []
        
        # 本地缓存批量获取
        for key in keys:
            value = self._caches.get(cache_type, LRUCache()).get(key)
            if value is not None:
                result[key] = value
            else:
                missing_keys.append(key)
                
        # Redis批量获取缺失的key
        if missing_keys and self._use_redis and self._redis_client:
            try:
                redis_keys = [f"autored:{cache_type}:{k}" for k in missing_keys]
                redis_values = self._redis_client.mget(redis_keys)
                for key, value in zip(missing_keys, redis_values):
                    if value:
                        parsed = json.loads(value)
                        result[key] = parsed
                        # 回填本地缓存
                        self._caches[cache_type].set(key, parsed)
            except Exception as e:
                logger.debug(f"Redis批量读取失败: {e}")
                
        return result
    
    def batch_set(self, cache_type: str, data: Dict[str, Any], ttl: Optional[float] = None):
        """批量设置缓存"""
        for key, value in data.items():
            self.set(cache_type, key, value, ttl)
            
        # Redis管道批量写入
        if self._use_redis and self._redis_client:
            try:
                pipe = self._redis_client.pipeline()
                cache_ttl = int(ttl or self.CACHE_CONFIG.get(cache_type, {}).get("ttl", 300))
                for key, value in data.items():
                    redis_key = f"autored:{cache_type}:{key}"
                    pipe.setex(redis_key, cache_ttl, json.dumps(value, default=str))
                pipe.execute()
            except Exception as e:
                logger.debug(f"Redis批量写入失败: {e}")
    
    def get_or_set(self, cache_type: str, key: str, loader: Callable, ttl: Optional[float] = None) -> Any:
        """获取缓存，不存在则通过loader加载并设置"""
        value = self.get(cache_type, key)
        if value is not None:
            return value
            
        value = loader()
        if value is not None:
            self.set(cache_type, key, value, ttl)
        return value
    
    async def async_get_or_set(self, cache_type: str, key: str, loader: Callable, ttl: Optional[float] = None) -> Any:
        """异步获取缓存，不存在则通过loader加载并设置"""
        value = self.get(cache_type, key)
        if value is not None:
            return value
            
        value = await loader()
        if value is not None:
            self.set(cache_type, key, value, ttl)
        return value


def cached(cache_type: Union[CacheType, str], key_func: Optional[Callable] = None, ttl: Optional[float] = None):
    """缓存装饰器"""
    ct = str(cache_type)
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                key_data = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True, default=str)
                cache_key = hashlib.md5(key_data.encode()).hexdigest()

            cache = get_smart_cache()
            cached_value = cache.get(ct, cache_key)
            if cached_value is not None:
                return cached_value

            result = func(*args, **kwargs)
            cache.set(ct, cache_key, result, ttl)
            return result

        return wrapper
    return decorator


def async_cached(cache_type: Union[CacheType, str], key_func: Optional[Callable] = None, ttl: Optional[float] = None):
    """异步缓存装饰器"""
    ct = str(cache_type)
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                key_data = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True, default=str)
                cache_key = hashlib.md5(key_data.encode()).hexdigest()

            cache = get_smart_cache()
            cached_value = cache.get(ct, cache_key)
            if cached_value is not None:
                return cached_value

            result = await func(*args, **kwargs)
            cache.set(ct, cache_key, result, ttl)
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
