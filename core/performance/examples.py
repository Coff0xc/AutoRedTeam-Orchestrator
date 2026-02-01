#!/usr/bin/env python3
"""
性能优化模块使用示例
"""

# 导入性能优化组件
from core.performance import (  # 管理器; 配置; 内存优化; 并发控制; 可靠性; 监控
    CircuitBreaker,
    ObjectPool,
    PerformanceConfig,
    PerformanceManager,
    PerformanceMetrics,
    RateLimiter,
    ResultPaginator,
    RetryPolicy,
    StreamingResultProcessor,
    init_performance,
    memory_efficient,
    retry_with_policy,
)

# ============== 示例1: 使用管理器 ==============


def example_manager():
    """使用性能管理器的完整示例"""
    # 方式1: 上下文管理器
    with PerformanceManager() as perf:
        # 使用线程池
        future = perf.thread_pool.submit(lambda: "task result")
        print(f"任务结果: {future.result()}")

        # 使用限流器
        if perf.rate_limiter.acquire():
            print("请求已通过限流")

        # 获取统计
        stats = perf.get_stats()
        print(f"统计信息: {stats}")

    # 方式2: 手动管理
    perf = PerformanceManager()
    perf.start()
    try:
        # 使用组件...
        pass
    finally:
        perf.stop()


# ============== 示例2: 流式处理大数据 ==============


def example_streaming():
    """流式处理避免内存溢出"""
    processor = StreamingResultProcessor(chunk_size=100, max_buffer_size=1000)

    # 模拟大数据源
    def data_source():
        for i in range(10000):
            yield {"id": i, "data": f"item_{i}"}

    # 流式处理
    def process_item(item):
        return item["id"] * 2

    results = list(processor.process_stream(data_source(), process_item))
    print(f"处理了 {len(results)} 条数据")


# ============== 示例3: 对象池复用 ==============


def example_object_pool():
    """对象池复用昂贵对象"""
    import requests

    # 创建Session池
    session_pool = ObjectPool(
        factory=lambda: requests.Session(), max_size=10, reset_func=lambda s: s.cookies.clear()
    )

    # 使用对象池
    with session_pool.get() as session:
        # response = session.get("https://example.com")
        pass

    print(f"对象池统计: {session_pool.stats}")


# ============== 示例4: 结果分页 ==============


def example_pagination():
    """大结果集分页返回"""
    # 模拟大数据
    data = range(10000)

    paginator = ResultPaginator(data, page_size=100)

    # 获取第一页
    page1 = paginator.get_page(0)
    print(f"第1页: {len(page1.items)} 条, 共 {page1.total_pages} 页")

    # 迭代所有页
    for page in paginator.iter_pages():
        print(f"处理第 {page.page} 页, {len(page.items)} 条")
        if page.page >= 2:  # 只处理前3页
            break


# ============== 示例5: 限流器 ==============


def example_rate_limiter():
    """令牌桶限流"""
    limiter = RateLimiter(rate=10.0, burst=20)

    # 同步获取
    for i in range(30):
        if limiter.acquire():
            print(f"请求 {i} 通过")
        else:
            print(f"请求 {i} 被限流")

    # 等待获取
    if limiter.wait(timeout=5.0):
        print("等待后获取成功")


# ============== 示例6: 熔断器 ==============


def example_circuit_breaker():
    """熔断器防止级联故障"""
    breaker = CircuitBreaker(failure_threshold=3, timeout=10.0)

    def call_service():
        if breaker.can_execute():
            try:
                # 模拟服务调用
                raise ConnectionError("服务不可用")
            except ConnectionError:
                breaker.record_failure()
                raise
        else:
            print("熔断器打开，拒绝请求")

    # 模拟多次失败
    for i in range(5):
        try:
            call_service()
        except ConnectionError:
            print(f"调用 {i} 失败")

    print(f"熔断器状态: {breaker.state}")


# ============== 示例7: 重试装饰器 ==============


@retry_with_policy(max_retries=3, base_delay=1.0)
def unreliable_function():
    """不可靠的函数，会自动重试"""
    import random

    if random.random() < 0.7:
        raise ConnectionError("随机失败")
    return "成功"


def example_retry():
    """重试机制示例"""
    try:
        result = unreliable_function()
        print(f"结果: {result}")
    except ConnectionError:
        print("重试次数耗尽")


# ============== 示例8: 内存高效装饰器 ==============


@memory_efficient(max_items=1000)
def scan_large_target():
    """扫描函数，结果自动限制"""
    return list(range(5000))  # 返回5000条，会被截断到1000


def example_memory_efficient():
    """内存高效装饰器示例"""
    results = scan_large_target()
    print(f"结果数量: {len(results)}")  # 输出1000


# ============== 示例9: 可恢复任务 ==============


def example_recoverable_task():
    """断点续传任务示例"""
    perf = PerformanceManager()
    perf.start()

    try:
        task = perf.create_recoverable_task(
            task_id="scan_task_001", task_type="port_scan", total=1000
        )

        with task:
            for i in range(1000):
                item_id = f"port_{i}"

                # 跳过已完成的
                if task.is_completed(item_id):
                    continue

                # 处理项目
                result = {"port": i, "status": "open" if i % 10 == 0 else "closed"}
                task.mark_completed(item_id, result)

            print(f"任务进度: {task.progress}")
    finally:
        perf.stop()


# ============== 示例10: 性能指标 ==============


def example_metrics():
    """性能指标收集示例"""
    metrics = PerformanceMetrics()

    # 记录请求
    metrics.record_request("/api/scan", "POST", 200, 1.5)
    metrics.record_request("/api/scan", "POST", 500, 2.0)

    # 记录扫描
    metrics.record_scan("port_scan", "192.168.1.1", 30.0, 100)

    # 记录缓存
    metrics.record_cache_hit("dns")
    metrics.record_cache_miss("tech")

    # 获取摘要
    summary = metrics.get_summary()
    print(f"性能摘要: {summary}")


if __name__ == "__main__":
    print("=== 性能优化模块示例 ===\n")

    print("1. 流式处理示例")
    example_streaming()

    print("\n2. 分页示例")
    example_pagination()

    print("\n3. 限流器示例")
    example_rate_limiter()

    print("\n4. 熔断器示例")
    example_circuit_breaker()

    print("\n5. 性能指标示例")
    example_metrics()

    print("\n=== 示例完成 ===")
