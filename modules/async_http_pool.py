#!/usr/bin/env python3
"""
异步HTTP客户端池 - 高性能并发请求
支持连接复用、自动重试、速率限制
"""

import asyncio
import logging
import socket
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# 尝试导入httpx，降级到aiohttp或requests
try:
    import httpx

    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import aiohttp

    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


@dataclass
class RequestStats:
    """请求统计"""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_time: float = 0.0
    avg_response_time: float = 0.0


@dataclass
class PoolConfig:
    """连接池配置"""

    max_connections: int = 100
    max_keepalive: int = 20
    timeout: float = 10.0
    connect_timeout: float = 5.0
    retry_count: int = 3
    retry_delay: float = 1.0
    rate_limit: float = 0.1  # 请求间隔(秒)
    verify_ssl: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


class RateLimiter:
    """令牌桶速率限制器"""

    def __init__(self, rate: float = 10.0, burst: int = 20):
        self.rate = rate  # 每秒请求数
        self.burst = burst  # 突发容量
        self.tokens = burst
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        """获取令牌"""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens >= 1:
                self.tokens -= 1
                return True

            # 等待令牌
            wait_time = (1 - self.tokens) / self.rate
            await asyncio.sleep(wait_time)
            self.tokens = 0
            return True


class AsyncHTTPPool:
    """异步HTTP连接池"""

    # 域名统计的最大数量限制
    MAX_DOMAIN_STATS = 500

    def __init__(self, config: Optional[PoolConfig] = None):
        self.config = config or PoolConfig()
        self._client: Optional[Any] = None
        self._stats = RequestStats()
        self._rate_limiter = RateLimiter(rate=1.0 / max(self.config.rate_limit, 0.01), burst=10)
        self._domain_stats: Dict[str, RequestStats] = {}  # 改为普通dict，手动限制大小

    async def __aenter__(self):
        """异步上下文管理器入口"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器退出"""
        await self.close()
        return False

    async def _get_client(self):
        """获取或创建HTTP客户端"""
        if self._client is None:
            if HAS_HTTPX:
                self._client = httpx.AsyncClient(
                    limits=httpx.Limits(
                        max_connections=self.config.max_connections,
                        max_keepalive_connections=self.config.max_keepalive,
                    ),
                    timeout=httpx.Timeout(self.config.timeout, connect=self.config.connect_timeout),
                    verify=self.config.verify_ssl,
                    headers={"User-Agent": self.config.user_agent},
                    follow_redirects=True,
                )
            elif HAS_AIOHTTP:
                connector = aiohttp.TCPConnector(
                    limit=self.config.max_connections,
                    limit_per_host=self.config.max_keepalive,
                    ssl=self.config.verify_ssl,
                )
                timeout = aiohttp.ClientTimeout(
                    total=self.config.timeout, connect=self.config.connect_timeout
                )
                self._client = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout,
                    headers={"User-Agent": self.config.user_agent},
                )
            else:
                raise RuntimeError("需要安装 httpx 或 aiohttp: pip install httpx")

        return self._client

    async def close(self):
        """关闭连接池"""
        if self._client:
            await self._client.aclose() if HAS_HTTPX else await self._client.close()
            self._client = None

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        data: Optional[Any] = None,
        json_data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        timeout: Optional[float] = None,
        retry: bool = True,
    ) -> Dict[str, Any]:
        """发送HTTP请求"""
        await self._rate_limiter.acquire()

        client = await self._get_client()
        domain = urlparse(url).netloc
        start_time = time.monotonic()

        for attempt in range(self.config.retry_count if retry else 1):
            try:
                if HAS_HTTPX:
                    response = await client.request(
                        method=method,
                        url=url,
                        headers=headers,
                        data=data,
                        json=json_data,
                        params=params,
                        timeout=timeout or self.config.timeout,
                    )
                    result = {
                        "success": True,
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "text": response.text,
                        "url": str(response.url),
                        "elapsed": time.monotonic() - start_time,
                    }
                else:  # aiohttp
                    async with client.request(
                        method=method,
                        url=url,
                        headers=headers,
                        data=data,
                        json=json_data,
                        params=params,
                    ) as response:
                        text = await response.text()
                        result = {
                            "success": True,
                            "status_code": response.status,
                            "headers": dict(response.headers),
                            "text": text,
                            "url": str(response.url),
                            "elapsed": time.monotonic() - start_time,
                        }

                self._update_stats(domain, True, result["elapsed"])
                return result

            except Exception as e:
                if attempt < self.config.retry_count - 1:
                    await asyncio.sleep(self.config.retry_delay * (attempt + 1))
                    continue

                elapsed = time.monotonic() - start_time
                self._update_stats(domain, False, elapsed)
                return {"success": False, "error": str(e), "elapsed": elapsed}

    def _update_stats(self, domain: str, success: bool, elapsed: float):
        """更新统计信息"""
        self._stats.total_requests += 1
        self._stats.total_time += elapsed

        if success:
            self._stats.successful_requests += 1
        else:
            self._stats.failed_requests += 1

        self._stats.avg_response_time = self._stats.total_time / self._stats.total_requests

        # 域名级别统计（带大小限制）
        if domain not in self._domain_stats:
            # 如果超过限制，清理最旧的条目
            if len(self._domain_stats) >= self.MAX_DOMAIN_STATS:
                # 删除请求数最少的域名统计
                min_domain = min(
                    self._domain_stats.keys(), key=lambda d: self._domain_stats[d].total_requests
                )
                del self._domain_stats[min_domain]
            self._domain_stats[domain] = RequestStats()

        ds = self._domain_stats[domain]
        ds.total_requests += 1
        ds.total_time += elapsed
        if success:
            ds.successful_requests += 1
        else:
            ds.failed_requests += 1

    async def get(self, url: str, **kwargs) -> Dict[str, Any]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Dict[str, Any]:
        return await self.request("POST", url, **kwargs)

    async def batch_request(
        self, requests: List[Dict[str, Any]], concurrency: int = 10
    ) -> List[Dict[str, Any]]:
        """批量并发请求"""
        semaphore = asyncio.Semaphore(concurrency)

        async def limited_request(req: Dict) -> Dict[str, Any]:
            async with semaphore:
                return await self.request(**req)

        tasks = [limited_request(req) for req in requests]
        return await asyncio.gather(*tasks, return_exceptions=True)

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "global": {
                "total": self._stats.total_requests,
                "success": self._stats.successful_requests,
                "failed": self._stats.failed_requests,
                "avg_time": round(self._stats.avg_response_time, 3),
                "success_rate": round(
                    self._stats.successful_requests / max(self._stats.total_requests, 1), 2
                ),
            },
            "by_domain": {
                domain: {
                    "total": stats.total_requests,
                    "success": stats.successful_requests,
                    "avg_time": round(stats.total_time / max(stats.total_requests, 1), 3),
                }
                for domain, stats in self._domain_stats.items()
            },
        }


class AsyncPortScanner:
    """异步端口扫描器"""

    def __init__(self, concurrency: int = 100, timeout: float = 2.0):
        self.concurrency = concurrency
        self.timeout = timeout

    async def scan_port(self, host: str, port: int) -> Optional[int]:
        """扫描单个端口"""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return port
        except (OSError, asyncio.TimeoutError, ConnectionError):
            return None

    async def scan(self, host: str, ports: List[int]) -> List[int]:
        """扫描多个端口"""
        semaphore = asyncio.Semaphore(self.concurrency)

        async def limited_scan(port: int) -> Optional[int]:
            async with semaphore:
                return await self.scan_port(host, port)

        tasks = [limited_scan(p) for p in ports]
        results = await asyncio.gather(*tasks)
        return [p for p in results if p is not None]


class AsyncDNSResolver:
    """异步DNS解析器"""

    def __init__(self, concurrency: int = 50, timeout: float = 3.0):
        self.concurrency = concurrency
        self.timeout = timeout

    async def resolve(self, domain: str, record_type: str = "A") -> List[str]:
        """解析DNS记录"""
        try:
            import dns.asyncresolver

            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout

            answers = await resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except ImportError:
            # 降级到同步解析
            import socket

            loop = asyncio.get_running_loop()
            try:
                result = await asyncio.wait_for(
                    loop.getaddrinfo(domain, None), timeout=self.timeout
                )
                return list(set(r[4][0] for r in result))
            except (asyncio.TimeoutError, OSError, socket.gaierror):
                return []
        except (ImportError, RuntimeError):
            return []

    async def batch_resolve(
        self, domains: List[str], record_type: str = "A"
    ) -> Dict[str, List[str]]:
        """批量DNS解析"""
        semaphore = asyncio.Semaphore(self.concurrency)

        async def limited_resolve(domain: str) -> tuple:
            async with semaphore:
                result = await self.resolve(domain, record_type)
                return domain, result

        tasks = [limited_resolve(d) for d in domains]
        results = await asyncio.gather(*tasks)
        return {domain: ips for domain, ips in results}


# 全局连接池实例
_pool_instance: Optional[AsyncHTTPPool] = None


def get_http_pool(config: Optional[PoolConfig] = None) -> AsyncHTTPPool:
    """获取HTTP连接池单例"""
    global _pool_instance
    if _pool_instance is None:
        _pool_instance = AsyncHTTPPool(config)
    return _pool_instance


async def async_request(method: str, url: str, **kwargs) -> Dict[str, Any]:
    """便捷异步请求函数"""
    pool = get_http_pool()
    return await pool.request(method, url, **kwargs)


# 同步包装器（兼容现有代码）
def sync_request(method: str, url: str, **kwargs) -> Dict[str, Any]:
    """同步请求包装器 (Python 3.10+ 兼容)"""
    try:
        asyncio.get_running_loop()
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, async_request(method, url, **kwargs)).result()
    except RuntimeError:
        return asyncio.run(async_request(method, url, **kwargs))
