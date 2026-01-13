#!/usr/bin/env python3
"""
并发控制器 - 统一的并发控制和资源管理
"""

import asyncio
from typing import Optional, Callable, Any, List
from dataclasses import dataclass
import time
import logging

logger = logging.getLogger(__name__)


@dataclass
class ConcurrencyConfig:
    """并发配置"""
    max_concurrency: int = 50
    rate_limit: int = 100  # 每秒最大请求数
    burst_size: int = 10  # 突发请求数
    timeout: int = 300  # 超时时间(秒)


class ConcurrencyController:
    """
    并发控制器 - 统一的并发控制和资源管理

    特性:
    - Semaphore 并发控制
    - Token Bucket 速率限制
    - 动态调整并发数
    - 资源使用监控
    """

    def __init__(self, config: ConcurrencyConfig = None):
        """
        初始化并发控制器

        Args:
            config: 并发配置
        """
        self.config = config or ConcurrencyConfig()

        # 并发控制
        self.semaphore = asyncio.Semaphore(self.config.max_concurrency)

        # 速率限制 (Token Bucket)
        self.tokens = self.config.rate_limit
        self.last_refill = time.time()
        self.token_lock = asyncio.Lock()

        # 统计信息
        self.stats = {
            "total_requests": 0,
            "active_requests": 0,
            "throttled_count": 0,
            "max_active": 0
        }

    async def acquire(self):
        """获取执行权限"""
        # 等待 Semaphore
        await self.semaphore.acquire()

        # 等待 Token
        await self._wait_for_token()

        # 更新统计
        self.stats["total_requests"] += 1
        self.stats["active_requests"] += 1
        self.stats["max_active"] = max(
            self.stats["max_active"],
            self.stats["active_requests"]
        )

    def release(self):
        """释放执行权限"""
        self.semaphore.release()
        self.stats["active_requests"] -= 1

    async def _wait_for_token(self):
        """等待 Token (速率限制)"""
        async with self.token_lock:
            # 补充 Token
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(
                self.config.rate_limit,
                self.tokens + elapsed * self.config.rate_limit
            )
            self.last_refill = now

            # 如果没有 Token，等待
            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.config.rate_limit
                self.stats["throttled_count"] += 1
                logger.debug(f"速率限制，等待 {wait_time:.2f}秒")
                await asyncio.sleep(wait_time)
                self.tokens = 1

            # 消耗 Token
            self.tokens -= 1

    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """
        执行函数（带并发控制）

        Args:
            func: 要执行的函数
            *args: 位置参数
            **kwargs: 关键字参数

        Returns:
            函数执行结果
        """
        await self.acquire()
        try:
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            else:
                return await asyncio.to_thread(func, *args, **kwargs)
        finally:
            self.release()

    async def batch_execute(
        self,
        func: Callable,
        items: List[Any],
        *args,
        **kwargs
    ) -> List[Any]:
        """
        批量执行函数

        Args:
            func: 要执行的函数
            items: 参数列表
            *args: 额外位置参数
            **kwargs: 额外关键字参数

        Returns:
            结果列表
        """
        tasks = [
            self.execute(func, item, *args, **kwargs)
            for item in items
        ]
        return await asyncio.gather(*tasks, return_exceptions=True)

    def adjust_concurrency(self, new_limit: int):
        """动态调整并发数"""
        old_limit = self.config.max_concurrency
        self.config.max_concurrency = new_limit

        # 重新创建 Semaphore
        self.semaphore = asyncio.Semaphore(new_limit)

        logger.info(f"并发数调整: {old_limit} -> {new_limit}")

    def get_stats(self) -> dict:
        """获取统计信息"""
        return {
            **self.stats,
            "config": {
                "max_concurrency": self.config.max_concurrency,
                "rate_limit": self.config.rate_limit
            }
        }


# 使用示例
async def example_usage():
    """使用示例"""
    controller = ConcurrencyController(
        ConcurrencyConfig(max_concurrency=10, rate_limit=50)
    )

    async def task(i: int):
        await asyncio.sleep(0.1)
        return i * 2

    # 批量执行
    results = await controller.batch_execute(task, list(range(100)))
    print(f"完成 {len(results)} 个任务")

    # 统计信息
    stats = controller.get_stats()
    print(f"统计: {stats}")


if __name__ == "__main__":
    asyncio.run(example_usage())
