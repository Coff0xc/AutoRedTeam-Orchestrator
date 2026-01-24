"""
并发与性能层模块

提供完整的并发控制和性能管理功能：
- 线程池管理
- 限流器
- 熔断器
- 信号量
- 任务调度
- 性能指标

使用示例:

    # 线程池
    from core.concurrency import get_pool, DynamicThreadPool

    pool = get_pool()
    future = pool.submit(some_function, arg1, arg2)
    result = future.result()

    # 异步任务池
    from core.concurrency import AsyncPool

    async_pool = AsyncPool(concurrency=10)
    results = await async_pool.run([coro1, coro2, coro3])

    # 限流器
    from core.concurrency import TokenBucket, rate_limit

    limiter = TokenBucket(rate=10.0)  # 每秒 10 个请求
    if limiter.acquire():
        do_something()

    @rate_limit(rate=5.0)
    def api_call():
        ...

    # 熔断器
    from core.concurrency import CircuitBreaker, circuit_breaker

    breaker = CircuitBreaker(failure_threshold=5, timeout=30.0)
    try:
        result = breaker.call(risky_function)
    except CircuitOpenError:
        handle_circuit_open()

    @circuit_breaker(failure_threshold=3)
    def external_api():
        ...

    # 信号量
    from core.concurrency import BoundedSemaphore, get_semaphore

    sem = get_semaphore('database', value=10)
    with sem:
        query_database()

    # 任务调度
    from core.concurrency import get_scheduler, schedule_task

    task_id = schedule_task(my_function, delay=5.0, interval=60.0)
    cancel_task(task_id)

    # 性能指标
    from core.concurrency import get_collector, track_request, track

    with track_request('api_call'):
        response = requests.get(url)

    @track('my_function')
    def my_function():
        ...

    collector = get_collector()
    print(collector.summary())
"""

# 线程池
from .pool import (
    DynamicThreadPool,
    AsyncPool,
    PoolMetrics,
    get_pool,
    shutdown_default_pool,
    thread_pool,
    parallel_map,
    async_parallel_map
)

# 限流器
from .rate_limiter import (
    TokenBucket,
    SlidingWindowRateLimiter,
    AdaptiveRateLimiter,
    RateLimiterGroup,
    get_limiter_group,
    rate_limit
)

# 熔断器
from .circuit_breaker import (
    CircuitBreaker,
    CircuitState,
    CircuitOpenError,
    CircuitBreakerGroup,
    circuit_breaker,
    get_breaker_group,
    get_circuit_breaker
)

# 信号量
from .semaphore import (
    BoundedSemaphore,
    AsyncSemaphore,
    SemaphoreGroup,
    AsyncSemaphoreGroup,
    ResourceLimiter,
    get_semaphore_group,
    get_semaphore
)

# 任务调度
from .scheduler import (
    TaskScheduler,
    AsyncTaskScheduler,
    ScheduledTask,
    TaskStatus,
    get_scheduler,
    schedule_task,
    cancel_task
)

# 性能指标
from .metrics import (
    RequestMetrics,
    MetricsCollector,
    Counter,
    Gauge,
    Histogram,
    RollingMetrics,
    MetricType,
    get_collector,
    track_request,
    track
)

__all__ = [
    # Pool
    'DynamicThreadPool',
    'AsyncPool',
    'PoolMetrics',
    'get_pool',
    'shutdown_default_pool',
    'thread_pool',
    'parallel_map',
    'async_parallel_map',

    # Rate Limiter
    'TokenBucket',
    'SlidingWindowRateLimiter',
    'AdaptiveRateLimiter',
    'RateLimiterGroup',
    'get_limiter_group',
    'rate_limit',

    # Circuit Breaker
    'CircuitBreaker',
    'CircuitState',
    'CircuitOpenError',
    'CircuitBreakerGroup',
    'circuit_breaker',
    'get_breaker_group',
    'get_circuit_breaker',

    # Semaphore
    'BoundedSemaphore',
    'AsyncSemaphore',
    'SemaphoreGroup',
    'AsyncSemaphoreGroup',
    'ResourceLimiter',
    'get_semaphore_group',
    'get_semaphore',

    # Scheduler
    'TaskScheduler',
    'AsyncTaskScheduler',
    'ScheduledTask',
    'TaskStatus',
    'get_scheduler',
    'schedule_task',
    'cancel_task',

    # Metrics
    'RequestMetrics',
    'MetricsCollector',
    'Counter',
    'Gauge',
    'Histogram',
    'RollingMetrics',
    'MetricType',
    'get_collector',
    'track_request',
    'track',
]

__version__ = '1.0.0'
