"""
Async Engine - 高性能异步执行引擎
"""

import asyncio
import aiohttp
import logging
import time
import ssl
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    requests_per_second: float = 10.0
    burst_size: int = 20
    per_host_limit: float = 5.0


class TokenBucket:
    """令牌桶限速器"""
    
    def __init__(self, rate: float, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1):
        async with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.last_update) * self.rate)
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return
            
            wait_time = (tokens - self.tokens) / self.rate
            await asyncio.sleep(wait_time)
            self.tokens = 0


class AsyncEngine:
    """高性能异步HTTP引擎"""
    
    def __init__(self, concurrency: int = 50, timeout: int = 30, 
                 rate_limit: RateLimitConfig = None):
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.rate_limit = rate_limit or RateLimitConfig()
        
        self._semaphore = asyncio.Semaphore(concurrency)
        self._limiter = TokenBucket(self.rate_limit.requests_per_second, 
                                    self.rate_limit.burst_size)
        self._session: Optional[aiohttp.ClientSession] = None
        self._stats = {"total": 0, "success": 0, "failed": 0}
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            
            connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=ssl_ctx)
            self._session = aiohttp.ClientSession(
                connector=connector, timeout=self.timeout,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
        return self._session
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        async with self._semaphore:
            await self._limiter.acquire()
            self._stats["total"] += 1
            
            try:
                session = await self._get_session()
                start = time.monotonic()
                
                async with session.request(method, url, **kwargs) as resp:
                    body = await resp.text()
                    self._stats["success"] += 1
                    
                    return {
                        "url": url, "status": resp.status,
                        "headers": dict(resp.headers), "body": body,
                        "duration": time.monotonic() - start
                    }
            except Exception as e:
                self._stats["failed"] += 1
                return {"url": url, "status": 0, "error": str(e)}
    
    async def get(self, url: str, **kwargs) -> Dict:
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Dict:
        return await self.request("POST", url, **kwargs)
    
    async def batch_get(self, urls: List[str], callback: Callable = None) -> List[Dict]:
        async def _req(url):
            result = await self.get(url)
            if callback:
                callback(result)
            return result
        
        return await asyncio.gather(*[_req(u) for u in urls], return_exceptions=True)
    
    def get_stats(self) -> Dict:
        return self._stats.copy()
