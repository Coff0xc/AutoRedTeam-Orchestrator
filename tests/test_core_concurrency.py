#!/usr/bin/env python3
"""
test_core_concurrency.py - 并发控制模块单元测试

测试覆盖:
- TokenBucket 令牌桶限流器
- SlidingWindow 滑动窗口限流器
- DynamicThreadPool 动态线程池
- CircuitBreaker 熔断器
- 线程安全
- 性能测试
"""

import pytest
import threading
import time
import asyncio
from unittest.mock import Mock, patch
from typing import List

# 导入被测试的模块
from core.concurrency.rate_limiter import TokenBucket, SlidingWindowRateLimiter, AdaptiveRateLimiter
from core.concurrency.pool import DynamicThreadPool, PoolMetrics, TaskWrapper
from core.concurrency.circuit_breaker import CircuitBreaker, CircuitState
from core.concurrency.semaphore import AsyncSemaphore


# ============== TokenBucket 令牌桶测试 ==============

class TestTokenBucket:
    """TokenBucket 令牌桶限流器测试"""

    def test_init_basic(self):
        """测试基本初始化"""
        bucket = TokenBucket(rate=10.0)

        assert bucket.rate == 10.0
        assert bucket.capacity == 10.0
        assert bucket._tokens == 10.0

    def test_init_with_capacity(self):
        """测试带容量初始化"""
        bucket = TokenBucket(rate=10.0, capacity=20.0)

        assert bucket.rate == 10.0
        assert bucket.capacity == 20.0

    def test_init_invalid_rate(self):
        """测试无效速率"""
        with pytest.raises(ValueError, match='rate 必须大于 0'):
            TokenBucket(rate=0)

        with pytest.raises(ValueError, match='rate 必须大于 0'):
            TokenBucket(rate=-1)

    def test_init_invalid_capacity(self):
        """测试无效容量"""
        with pytest.raises(ValueError, match='capacity 不能小于 rate'):
            TokenBucket(rate=10.0, capacity=5.0)

    def test_try_acquire_success(self):
        """测试成功获取令牌"""
        bucket = TokenBucket(rate=10.0)

        # 初始时桶是满的
        assert bucket.try_acquire(1) is True
        assert bucket.try_acquire(5) is True

    def test_try_acquire_failure(self):
        """测试获取令牌失败"""
        bucket = TokenBucket(rate=10.0, capacity=10.0)

        # 消耗所有令牌
        bucket.try_acquire(10)

        # 应该失败
        assert bucket.try_acquire(1) is False

    def test_acquire_blocking(self):
        """测试阻塞获取令牌"""
        bucket = TokenBucket(rate=10.0)

        # 消耗所有令牌
        bucket.try_acquire(10)

        # 阻塞获取应该等待令牌补充
        start = time.time()
        result = bucket.acquire(1, timeout=0.2)
        elapsed = time.time() - start

        # 应该在超时前获取到令牌
        assert result is True
        assert elapsed >= 0.1  # 至少等待了一段时间

    def test_acquire_timeout(self):
        """测试获取令牌超时"""
        bucket = TokenBucket(rate=1.0)  # 每秒1个令牌

        # 消耗所有令牌
        bucket.try_acquire(1)

        # 超时时间不足以补充令牌
        result = bucket.acquire(1, timeout=0.1)

        assert result is False

    def test_refill_tokens(self):
        """测试令牌补充"""
        bucket = TokenBucket(rate=10.0)

        # 消耗所有令牌
        bucket.try_acquire(10)
        assert bucket.try_acquire(1) is False

        # 等待令牌补充
        time.sleep(0.2)

        # 应该有新令牌
        assert bucket.try_acquire(1) is True

    def test_thread_safety(self):
        """测试线程安全"""
        bucket = TokenBucket(rate=100.0, capacity=100.0)
        success_count = [0]
        lock = threading.Lock()

        def acquire_token():
            if bucket.try_acquire(1):
                with lock:
                    success_count[0] += 1

        threads = [threading.Thread(target=acquire_token) for _ in range(150)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # 应该只有100个成功（初始容量），允许少量误差
        assert success_count[0] <= 105  # 允许5个误差


# ============== SlidingWindowRateLimiter 滑动窗口测试 ==============

class TestSlidingWindowRateLimiter:
    """SlidingWindowRateLimiter 滑动窗口限流器测试"""

    def test_init_basic(self):
        """测试基本初始化"""
        window = SlidingWindowRateLimiter(rate=10, window_size=1.0)

        assert window.rate == 10
        assert window.window_size == 1.0

    def test_try_acquire_success(self):
        """测试成功获取"""
        window = SlidingWindowRateLimiter(rate=10, window_size=1.0)

        # 前10个请求应该成功
        for _ in range(10):
            assert window.try_acquire() is True

    def test_try_acquire_failure(self):
        """测试获取失败"""
        window = SlidingWindowRateLimiter(rate=5, window_size=1.0)

        # 前5个成功
        for _ in range(5):
            assert window.try_acquire() is True

        # 第6个应该失败
        assert window.try_acquire() is False

    def test_window_sliding(self):
        """测试窗口滑动"""
        window = SlidingWindowRateLimiter(rate=5, window_size=0.5)

        # 消耗所有配额
        for _ in range(5):
            window.try_acquire()

        # 应该失败
        assert window.try_acquire() is False

        # 等待窗口滑动
        time.sleep(0.6)

        # 应该成功
        assert window.try_acquire() is True

    def test_thread_safety(self):
        """测试线程安全"""
        window = SlidingWindowRateLimiter(rate=50, window_size=1.0)
        success_count = [0]
        lock = threading.Lock()

        def acquire():
            if window.try_acquire():
                with lock:
                    success_count[0] += 1

        threads = [threading.Thread(target=acquire) for _ in range(100)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # 应该只有50个成功
        assert success_count[0] <= 50


# ============== DynamicThreadPool 动态线程池测试 ==============

class TestDynamicThreadPool:
    """DynamicThreadPool 动态线程池测试"""

    def test_init_basic(self):
        """测试基本初始化"""
        pool = DynamicThreadPool(min_workers=2, max_workers=10)

        assert pool.min_workers == 2
        assert pool.max_workers == 10

    def test_submit_task(self):
        """测试提交任务"""
        pool = DynamicThreadPool(min_workers=2, max_workers=5)

        def simple_task(x):
            return x * 2

        future = pool.submit(simple_task, 5)
        result = future.result(timeout=1.0)

        assert result == 10

    def test_submit_multiple_tasks(self):
        """测试提交多个任务"""
        pool = DynamicThreadPool(min_workers=2, max_workers=5)

        def task(x):
            time.sleep(0.1)
            return x * 2

        futures = [pool.submit(task, i) for i in range(10)]
        results = [f.result(timeout=2.0) for f in futures]

        assert results == [i * 2 for i in range(10)]

    def test_map_function(self):
        """测试 map 函数"""
        pool = DynamicThreadPool(min_workers=2, max_workers=5)

        def task(x):
            return x * 2

        results = list(pool.map(task, range(10)))

        assert results == [i * 2 for i in range(10)]

    def test_context_manager(self):
        """测试上下文管理器"""
        with DynamicThreadPool(min_workers=2, max_workers=5) as pool:
            future = pool.submit(lambda x: x * 2, 5)
            result = future.result()
            assert result == 10

    def test_shutdown(self):
        """测试关闭线程池"""
        pool = DynamicThreadPool(min_workers=2, max_workers=5)

        def task():
            time.sleep(0.1)
            return True

        pool.submit(task)
        pool.shutdown(wait=True)

        # 关闭后不应该能提交新任务
        with pytest.raises(RuntimeError):
            pool.submit(task)

    def test_metrics(self):
        """测试指标收集"""
        pool = DynamicThreadPool(min_workers=2, max_workers=5)

        def task(x):
            time.sleep(0.05)
            return x

        # 提交多个任务
        futures = [pool.submit(task, i) for i in range(10)]
        for f in futures:
            f.result()

        metrics = pool.get_metrics()

        assert metrics['submitted_tasks'] == 10
        assert metrics['completed_tasks'] == 10
        assert metrics['success_rate'] == 1.0

    def test_task_exception_handling(self):
        """测试任务异常处理"""
        pool = DynamicThreadPool(min_workers=2, max_workers=5)

        def failing_task():
            raise ValueError('Task failed')

        future = pool.submit(failing_task)

        with pytest.raises(ValueError, match='Task failed'):
            future.result()

        # 线程池应该继续工作
        future2 = pool.submit(lambda: 42)
        assert future2.result() == 42


# ============== CircuitBreaker 熔断器测试 ==============

class TestCircuitBreaker:
    """CircuitBreaker 熔断器测试"""

    def test_init_basic(self):
        """测试基本初始化"""
        breaker = CircuitBreaker(
            failure_threshold=5,
            timeout=1.0,
        )

        assert breaker.failure_threshold == 5
        assert breaker.timeout == 1.0
        assert breaker.state == CircuitState.CLOSED

    def test_call_success(self):
        """测试成功调用"""
        breaker = CircuitBreaker(failure_threshold=3)

        def success_func():
            return 'success'

        result = breaker.call(success_func)

        assert result == 'success'
        assert breaker.state == CircuitState.CLOSED

    def test_call_failure(self):
        """测试失败调用"""
        breaker = CircuitBreaker(failure_threshold=3)

        def failing_func():
            raise RuntimeError('Failed')

        # 前3次失败应该被记录
        for _ in range(3):
            with pytest.raises(RuntimeError):
                breaker.call(failing_func)

        # 第4次应该触发熔断
        assert breaker.state == CircuitState.OPEN

    def test_open_state_blocks_calls(self):
        """测试开路状态阻止调用"""
        breaker = CircuitBreaker(failure_threshold=2, timeout=1.0)

        def failing_func():
            raise RuntimeError('Failed')

        # 触发熔断
        for _ in range(2):
            with pytest.raises(RuntimeError):
                breaker.call(failing_func)

        assert breaker.state == CircuitState.OPEN

        # 开路状态应该直接拒绝调用
        with pytest.raises(Exception):  # 应该抛出熔断异常
            breaker.call(lambda: 'test')

    def test_half_open_state(self):
        """测试半开状态"""
        breaker = CircuitBreaker(failure_threshold=2, timeout=0.1)

        def failing_func():
            raise RuntimeError('Failed')

        # 触发熔断
        for _ in range(2):
            with pytest.raises(RuntimeError):
                breaker.call(failing_func)

        assert breaker.state == CircuitState.OPEN

        # 等待超时
        time.sleep(0.2)

        # 应该进入半开状态
        # 下一次调用会测试服务是否恢复
        def success_func():
            return 'recovered'

        result = breaker.call(success_func)

        assert result == 'recovered'
        assert breaker.state == CircuitState.CLOSED

    def test_decorator(self):
        """测试装饰器用法"""
        breaker = CircuitBreaker(failure_threshold=3)

        @breaker.decorator
        def protected_func(x):
            if x < 0:
                raise ValueError('Negative value')
            return x * 2

        # 成功调用
        assert protected_func(5) == 10

        # 失败调用
        for _ in range(3):
            with pytest.raises(ValueError):
                protected_func(-1)

        # 应该触发熔断
        assert breaker.state == CircuitState.OPEN


# ============== AsyncSemaphore 异步信号量测试 ==============

class TestAsyncSemaphore:
    """AsyncSemaphore 异步信号量测试"""

    @pytest.mark.asyncio
    async def test_init_basic(self):
        """测试基本初始化"""
        semaphore = AsyncSemaphore(value=5)

        assert semaphore._value == 5

    @pytest.mark.asyncio
    async def test_acquire_release(self):
        """测试获取和释放"""
        semaphore = AsyncSemaphore(value=2)

        # 获取
        await semaphore.acquire()
        assert semaphore._value == 1

        # 释放
        semaphore.release()
        assert semaphore._value == 2

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """测试上下文管理器"""
        semaphore = AsyncSemaphore(value=2)

        async with semaphore:
            assert semaphore._value == 1

        assert semaphore._value == 2

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        """测试并发访问控制"""
        semaphore = AsyncSemaphore(value=2)
        counter = [0]
        max_concurrent = [0]

        async def task():
            async with semaphore:
                counter[0] += 1
                max_concurrent[0] = max(max_concurrent[0], counter[0])
                await asyncio.sleep(0.1)
                counter[0] -= 1

        # 启动5个并发任务
        tasks = [task() for _ in range(5)]
        await asyncio.gather(*tasks)

        # 最大并发数应该不超过信号量值
        assert max_concurrent[0] <= 2

    @pytest.mark.asyncio
    async def test_blocking_behavior(self):
        """测试阻塞行为"""
        semaphore = AsyncSemaphore(value=1)

        # 第一个任务获取信号量
        await semaphore.acquire()

        # 第二个任务应该被阻塞
        acquired = False

        async def try_acquire():
            nonlocal acquired
            await semaphore.acquire()
            acquired = True

        task = asyncio.create_task(try_acquire())

        # 等待一小段时间
        await asyncio.sleep(0.1)

        # 应该还没有获取到
        assert acquired is False

        # 释放信号量
        semaphore.release()

        # 等待任务完成
        await task

        # 现在应该获取到了
        assert acquired is True


# ============== 集成测试 ==============

class TestIntegration:
    """集成测试"""

    def test_rate_limiter_with_thread_pool(self):
        """测试限流器与线程池集成"""
        bucket = TokenBucket(rate=10.0, capacity=10.0)
        pool = DynamicThreadPool(min_workers=2, max_workers=5)

        def rate_limited_task(x):
            if bucket.try_acquire(1):
                return x * 2
            else:
                return None

        futures = [pool.submit(rate_limited_task, i) for i in range(20)]
        results = [f.result() for f in futures]

        # 应该有一些任务被限流
        successful = [r for r in results if r is not None]
        assert len(successful) <= 10

    def test_circuit_breaker_with_thread_pool(self):
        """测试熔断器与线程池集成"""
        breaker = CircuitBreaker(failure_threshold=3)
        pool = DynamicThreadPool(min_workers=2, max_workers=5)

        call_count = [0]

        def protected_task():
            call_count[0] += 1
            if call_count[0] <= 3:
                raise RuntimeError('Service unavailable')
            return 'success'

        # 提交多个任务
        futures = []
        for _ in range(10):
            future = pool.submit(lambda: breaker.call(protected_task))
            futures.append(future)
            time.sleep(0.01)

        # 收集结果
        results = []
        for f in futures:
            try:
                results.append(f.result())
            except Exception:
                results.append(None)

        # 前3个应该失败，之后熔断器应该开路
        assert results.count(None) >= 3

    @pytest.mark.asyncio
    async def test_async_rate_limiting(self):
        """测试异步限流"""
        semaphore = AsyncSemaphore(value=3)
        completed = []

        async def task(task_id):
            async with semaphore:
                await asyncio.sleep(0.1)
                completed.append(task_id)

        # 启动10个任务
        tasks = [task(i) for i in range(10)]
        await asyncio.gather(*tasks)

        # 所有任务都应该完成
        assert len(completed) == 10


# ============== 性能测试 ==============

class TestPerformance:
    """性能测试"""

    def test_token_bucket_performance(self):
        """测试令牌桶性能"""
        bucket = TokenBucket(rate=1000.0)

        start = time.time()
        for _ in range(1000):
            bucket.try_acquire(1)
        elapsed = time.time() - start

        # 应该在合理时间内完成
        assert elapsed < 1.0

    def test_thread_pool_throughput(self):
        """测试线程池吞吐量"""
        pool = DynamicThreadPool(min_workers=5, max_workers=10)

        def quick_task(x):
            return x * 2

        start = time.time()
        futures = [pool.submit(quick_task, i) for i in range(1000)]
        results = [f.result() for f in futures]
        elapsed = time.time() - start

        assert len(results) == 1000
        # 应该在合理时间内完成
        assert elapsed < 5.0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
