#!/usr/bin/env python3
"""
异步 HTTP 客户端 - 支持高并发扫描
提供统一的异步 HTTP 请求接口，替代同步 requests
"""

import asyncio
import aiohttp
import time
from typing import Dict, Optional, Any, List
from dataclasses import dataclass
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)


@dataclass
class AsyncHTTPResponse:
    """异步 HTTP 响应数据类"""
    status: int
    text: str
    headers: Dict[str, str]
    url: str
    elapsed: float
    success: bool = True
    error: Optional[str] = None


class AsyncHTTPClient:
    """
    异步 HTTP 客户端 - 支持高并发扫描

    特性:
    - 连接池复用
    - 并发控制 (Semaphore)
    - 自动重试
    - 超时控制
    - 代理支持
    """

    def __init__(
        self,
        concurrency: int = 50,
        timeout: int = 10,
        max_retries: int = 2,
        user_agent: str = None,
        verify_ssl: bool = True,
        proxy: str = None
    ):
        """
        初始化异步 HTTP 客户端

        Args:
            concurrency: 最大并发数
            timeout: 请求超时时间 (秒)
            max_retries: 最大重试次数
            user_agent: 自定义 User-Agent
            verify_ssl: 是否验证 SSL 证书
            proxy: 代理地址
        """
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.verify_ssl = verify_ssl
        self.proxy = proxy

        self.semaphore = asyncio.Semaphore(concurrency)
        self._session: Optional[aiohttp.ClientSession] = None

        # 统计信息
        self.stats = {
            "total_requests": 0,
            "success_requests": 0,
            "failed_requests": 0,
            "total_time": 0.0
        }

    async def __aenter__(self):
        """上下文管理器入口"""
        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            limit_per_host=20,
            ssl=self.verify_ssl
        )

        self._session = aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers={"User-Agent": self.user_agent}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        if self._session:
            await self._session.close()
        return False

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> AsyncHTTPResponse:
        """
        发送单个 HTTP 请求 (内部方法)

        Args:
            method: HTTP 方法
            url: 目标 URL
            **kwargs: 其他请求参数

        Returns:
            AsyncHTTPResponse 对象
        """
        async with self.semaphore:
            start_time = time.time()

            for attempt in range(self.max_retries + 1):
                try:
                    async with self._session.request(
                        method,
                        url,
                        proxy=self.proxy,
                        **kwargs
                    ) as resp:
                        text = await resp.text()
                        elapsed = time.time() - start_time

                        self.stats["total_requests"] += 1
                        self.stats["success_requests"] += 1
                        self.stats["total_time"] += elapsed

                        return AsyncHTTPResponse(
                            status=resp.status,
                            text=text,
                            headers=dict(resp.headers),
                            url=str(resp.url),
                            elapsed=elapsed,
                            success=True
                        )

                except asyncio.TimeoutError:
                    if attempt == self.max_retries:
                        self.stats["total_requests"] += 1
                        self.stats["failed_requests"] += 1
                        return AsyncHTTPResponse(
                            status=0,
                            text="",
                            headers={},
                            url=url,
                            elapsed=time.time() - start_time,
                            success=False,
                            error="Timeout"
                        )
                    await asyncio.sleep(0.5 * (attempt + 1))

                except Exception as e:
                    if attempt == self.max_retries:
                        self.stats["total_requests"] += 1
                        self.stats["failed_requests"] += 1
                        return AsyncHTTPResponse(
                            status=0,
                            text="",
                            headers={},
                            url=url,
                            elapsed=time.time() - start_time,
                            success=False,
                            error=str(e)
                        )
                    await asyncio.sleep(0.5 * (attempt + 1))

    async def get(self, url: str, **kwargs) -> AsyncHTTPResponse:
        """GET 请求"""
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> AsyncHTTPResponse:
        """POST 请求"""
        return await self._request("POST", url, **kwargs)

    async def batch_get(self, urls: List[str]) -> List[AsyncHTTPResponse]:
        """
        批量 GET 请求

        Args:
            urls: URL 列表

        Returns:
            响应列表
        """
        tasks = [self.get(url) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def batch_request(
        self,
        requests: List[Dict[str, Any]]
    ) -> List[AsyncHTTPResponse]:
        """
        批量混合请求

        Args:
            requests: 请求配置列表，格式: [{"method": "GET", "url": "...", ...}, ...]

        Returns:
            响应列表
        """
        tasks = []
        for req in requests:
            method = req.pop("method", "GET")
            url = req.pop("url")
            tasks.append(self._request(method, url, **req))

        return await asyncio.gather(*tasks, return_exceptions=False)

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        avg_time = (
            self.stats["total_time"] / self.stats["total_requests"]
            if self.stats["total_requests"] > 0
            else 0
        )

        return {
            **self.stats,
            "average_time": avg_time,
            "success_rate": (
                self.stats["success_requests"] / self.stats["total_requests"]
                if self.stats["total_requests"] > 0
                else 0
            )
        }


# 使用示例
async def example_usage():
    """使用示例"""
    async with AsyncHTTPClient(concurrency=100, timeout=10) as client:
        # 单个请求
        response = await client.get("https://example.com")
        print(f"Status: {response.status}, Time: {response.elapsed:.2f}s")

        # 批量请求
        urls = [f"https://example.com/page{i}" for i in range(100)]
        responses = await client.batch_get(urls)

        success_count = sum(1 for r in responses if r.success)
        print(f"Success: {success_count}/{len(responses)}")

        # 统计信息
        stats = client.get_stats()
        print(f"Stats: {stats}")


if __name__ == "__main__":
    asyncio.run(example_usage())
