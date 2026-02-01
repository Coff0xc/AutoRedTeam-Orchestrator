"""
HTTP 中间件系统

提供可扩展的中间件架构，用于请求/响应处理
支持日志、重试、限流、认证等功能
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Awaitable, Callable, Dict, Generic, List, Optional, TypeVar, Union

logger = logging.getLogger(__name__)

# 泛型类型
RequestT = TypeVar("RequestT")
ResponseT = TypeVar("ResponseT")


@dataclass
class RequestContext:
    """请求上下文 - 在中间件间传递的请求信息"""

    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    params: Optional[Dict[str, Any]] = None
    data: Optional[Any] = None
    json: Optional[Any] = None
    timeout: Optional[float] = None
    extras: Dict[str, Any] = field(default_factory=dict)  # 扩展字段

    # 中间件可修改的元数据
    start_time: Optional[float] = None
    attempt: int = 0
    skip_retry: bool = False


@dataclass
class ResponseContext:
    """响应上下文 - 在中间件间传递的响应信息"""

    status_code: int
    headers: Dict[str, str]
    content: bytes
    elapsed: float
    url: str
    request: Optional[RequestContext] = None
    extras: Dict[str, Any] = field(default_factory=dict)


class Middleware(ABC):
    """中间件基类"""

    @property
    def name(self) -> str:
        """中间件名称"""
        return self.__class__.__name__

    @abstractmethod
    def process_request(self, request: RequestContext) -> RequestContext:
        """
        处理请求 (同步)

        Args:
            request: 请求上下文

        Returns:
            处理后的请求上下文
        """
        pass

    @abstractmethod
    def process_response(
        self, response: ResponseContext, request: RequestContext
    ) -> ResponseContext:
        """
        处理响应 (同步)

        Args:
            response: 响应上下文
            request: 原始请求上下文

        Returns:
            处理后的响应上下文
        """
        pass

    def process_exception(
        self, exception: Exception, request: RequestContext
    ) -> Optional[ResponseContext]:
        """
        处理异常 (可选实现)

        Args:
            exception: 捕获的异常
            request: 原始请求上下文

        Returns:
            如果能处理异常，返回替代响应；否则返回 None
        """
        return None


class AsyncMiddleware(ABC):
    """异步中间件基类"""

    @property
    def name(self) -> str:
        """中间件名称"""
        return self.__class__.__name__

    @abstractmethod
    async def process_request(self, request: RequestContext) -> RequestContext:
        """处理请求 (异步)"""
        pass

    @abstractmethod
    async def process_response(
        self, response: ResponseContext, request: RequestContext
    ) -> ResponseContext:
        """处理响应 (异步)"""
        pass

    async def process_exception(
        self, exception: Exception, request: RequestContext
    ) -> Optional[ResponseContext]:
        """处理异常 (可选)"""
        return None


class LoggingMiddleware(Middleware):
    """日志中间件 - 记录请求和响应"""

    def __init__(
        self,
        log_requests: bool = True,
        log_responses: bool = True,
        log_headers: bool = False,
        log_body: bool = False,
        logger_instance: Optional[logging.Logger] = None,
    ):
        """
        初始化日志中间件

        Args:
            log_requests: 是否记录请求
            log_responses: 是否记录响应
            log_headers: 是否记录请求头
            log_body: 是否记录请求体
            logger_instance: 自定义日志记录器
        """
        self.log_requests = log_requests
        self.log_responses = log_responses
        self.log_headers = log_headers
        self.log_body = log_body
        self._logger = logger_instance or logger

    def process_request(self, request: RequestContext) -> RequestContext:
        if self.log_requests:
            msg = f"[HTTP] {request.method} {request.url}"
            if self.log_headers:
                msg += f" Headers: {request.headers}"
            if self.log_body and request.data:
                body_preview = str(request.data)[:200]
                msg += f" Body: {body_preview}..."
            self._logger.info(msg)

        request.start_time = time.time()
        return request

    def process_response(
        self, response: ResponseContext, request: RequestContext
    ) -> ResponseContext:
        if self.log_responses:
            elapsed_ms = response.elapsed * 1000
            content_length = len(response.content)
            self._logger.info(
                f"[HTTP] {response.status_code} {request.method} {request.url} "
                f"({elapsed_ms:.2f}ms, {content_length} bytes)"
            )
        return response


class RetryMiddleware(Middleware):
    """重试中间件 - 自动重试失败的请求"""

    def __init__(
        self,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        backoff_factor: float = 2.0,
        retry_status_codes: tuple = (429, 500, 502, 503, 504),
        retry_exceptions: tuple = (),
    ):
        """
        初始化重试中间件

        Args:
            max_retries: 最大重试次数
            retry_delay: 基础重试延迟 (秒)
            backoff_factor: 指数退避因子
            retry_status_codes: 需要重试的状态码
            retry_exceptions: 需要重试的异常类型
        """
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.backoff_factor = backoff_factor
        self.retry_status_codes = retry_status_codes
        self.retry_exceptions = retry_exceptions

    def process_request(self, request: RequestContext) -> RequestContext:
        if request.attempt == 0:
            request.attempt = 1
        return request

    def process_response(
        self, response: ResponseContext, request: RequestContext
    ) -> ResponseContext:
        # 检查是否需要重试
        if (
            response.status_code in self.retry_status_codes
            and request.attempt < self.max_retries
            and not request.skip_retry
        ):
            delay = self.retry_delay * (self.backoff_factor ** (request.attempt - 1))

            # 检查 Retry-After 头
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    delay = max(delay, float(retry_after))
                except ValueError:
                    pass

            logger.info(
                f"[Retry] {request.method} {request.url} "
                f"(状态码 {response.status_code}, 第 {request.attempt} 次重试, "
                f"等待 {delay:.2f}s)"
            )

            time.sleep(delay)
            request.attempt += 1
            response.extras["should_retry"] = True

        return response

    def process_exception(
        self, exception: Exception, request: RequestContext
    ) -> Optional[ResponseContext]:
        # 检查是否是需要重试的异常
        exc_type = type(exception).__name__
        should_retry = any(
            isinstance(exception, exc) for exc in self.retry_exceptions
        ) or exc_type in ("TimeoutException", "ConnectError", "ReadTimeout")

        if should_retry and request.attempt < self.max_retries:
            delay = self.retry_delay * (self.backoff_factor ** (request.attempt - 1))
            logger.info(
                f"[Retry] {request.method} {request.url} "
                f"(异常 {exc_type}, 第 {request.attempt} 次重试, 等待 {delay:.2f}s)"
            )
            time.sleep(delay)
            request.attempt += 1
            # 返回 None 表示应该重试
            request.extras["should_retry"] = True

        return None


class RateLimitMiddleware(Middleware):
    """限流中间件 - 控制请求速率"""

    def __init__(self, requests_per_second: float = 10.0, per_host: bool = True, burst: int = 5):
        """
        初始化限流中间件

        Args:
            requests_per_second: 每秒允许的请求数
            per_host: 是否按主机限流
            burst: 突发请求数量
        """
        self.requests_per_second = requests_per_second
        self.per_host = per_host
        self.burst = burst
        self._interval = 1.0 / requests_per_second
        self._last_request: Dict[str, float] = defaultdict(float)
        self._tokens: Dict[str, float] = defaultdict(lambda: burst)
        # 同步中间件不需要异步锁
        self._lock = None

    def _get_key(self, url: str) -> str:
        """获取限流键"""
        if self.per_host:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            return parsed.netloc
        return "__global__"

    def process_request(self, request: RequestContext) -> RequestContext:
        key = self._get_key(request.url)
        now = time.time()

        # 令牌桶算法
        elapsed = now - self._last_request[key]
        self._tokens[key] = min(self.burst, self._tokens[key] + elapsed * self.requests_per_second)
        self._last_request[key] = now

        if self._tokens[key] < 1.0:
            # 需要等待
            wait_time = (1.0 - self._tokens[key]) / self.requests_per_second
            logger.debug(f"[RateLimit] 等待 {wait_time:.3f}s ({key})")
            time.sleep(wait_time)
            self._tokens[key] = 0
        else:
            self._tokens[key] -= 1.0

        return request

    def process_response(
        self, response: ResponseContext, request: RequestContext
    ) -> ResponseContext:
        # 如果收到 429，增加等待时间
        if response.status_code == 429:
            key = self._get_key(request.url)
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    wait_time = float(retry_after)
                    logger.info(f"[RateLimit] 收到 429, 等待 {wait_time}s ({key})")
                    time.sleep(wait_time)
                except ValueError:
                    pass
        return response


class AsyncRetryMiddleware(AsyncMiddleware):
    """异步重试中间件 - 自动重试失败的请求（异步版本）"""

    def __init__(
        self,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        backoff_factor: float = 2.0,
        retry_status_codes: tuple = (429, 500, 502, 503, 504),
        retry_exceptions: tuple = (),
    ):
        """
        初始化异步重试中间件

        Args:
            max_retries: 最大重试次数
            retry_delay: 基础重试延迟 (秒)
            backoff_factor: 指数退避因子
            retry_status_codes: 需要重试的状态码
            retry_exceptions: 需要重试的异常类型
        """
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.backoff_factor = backoff_factor
        self.retry_status_codes = retry_status_codes
        self.retry_exceptions = retry_exceptions

    async def process_request(self, request: RequestContext) -> RequestContext:
        if request.attempt == 0:
            request.attempt = 1
        return request

    async def process_response(
        self, response: ResponseContext, request: RequestContext
    ) -> ResponseContext:
        # 检查是否需要重试
        if (
            response.status_code in self.retry_status_codes
            and request.attempt < self.max_retries
            and not request.skip_retry
        ):
            delay = self.retry_delay * (self.backoff_factor ** (request.attempt - 1))

            # 检查 Retry-After 头
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    delay = max(delay, float(retry_after))
                except ValueError:
                    pass

            logger.info(
                f"[Retry] {request.method} {request.url} "
                f"(状态码 {response.status_code}, 第 {request.attempt} 次重试, "
                f"等待 {delay:.2f}s)"
            )

            await asyncio.sleep(delay)
            request.attempt += 1
            response.extras["should_retry"] = True

        return response

    async def process_exception(
        self, exception: Exception, request: RequestContext
    ) -> Optional[ResponseContext]:
        # 检查是否是需要重试的异常
        exc_type = type(exception).__name__
        should_retry = any(
            isinstance(exception, exc) for exc in self.retry_exceptions
        ) or exc_type in ("TimeoutException", "ConnectError", "ReadTimeout")

        if should_retry and request.attempt < self.max_retries:
            delay = self.retry_delay * (self.backoff_factor ** (request.attempt - 1))
            logger.info(
                f"[Retry] {request.method} {request.url} "
                f"(异常 {exc_type}, 第 {request.attempt} 次重试, 等待 {delay:.2f}s)"
            )
            await asyncio.sleep(delay)
            request.attempt += 1
            # 返回 None 表示应该重试
            request.extras["should_retry"] = True

        return None


class AsyncRateLimitMiddleware(AsyncMiddleware):
    """异步限流中间件"""

    def __init__(self, requests_per_second: float = 10.0, per_host: bool = True, burst: int = 5):
        self.requests_per_second = requests_per_second
        self.per_host = per_host
        self.burst = burst
        self._interval = 1.0 / requests_per_second
        self._last_request: Dict[str, float] = defaultdict(float)
        self._tokens: Dict[str, float] = defaultdict(lambda: burst)
        self._lock = asyncio.Lock()

    def _get_key(self, url: str) -> str:
        if self.per_host:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            return parsed.netloc
        return "__global__"

    async def process_request(self, request: RequestContext) -> RequestContext:
        key = self._get_key(request.url)

        async with self._lock:
            now = time.time()
            elapsed = now - self._last_request[key]
            self._tokens[key] = min(
                self.burst, self._tokens[key] + elapsed * self.requests_per_second
            )
            self._last_request[key] = now

            if self._tokens[key] < 1.0:
                wait_time = (1.0 - self._tokens[key]) / self.requests_per_second
                logger.debug(f"[RateLimit] 等待 {wait_time:.3f}s ({key})")
                await asyncio.sleep(wait_time)
                self._tokens[key] = 0
            else:
                self._tokens[key] -= 1.0

        return request

    async def process_response(
        self, response: ResponseContext, request: RequestContext
    ) -> ResponseContext:
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    wait_time = float(retry_after)
                    key = self._get_key(request.url)
                    logger.info(f"[RateLimit] 收到 429, 等待 {wait_time}s ({key})")
                    await asyncio.sleep(wait_time)
                except ValueError:
                    pass
        return response


class HeadersMiddleware(Middleware):
    """请求头中间件 - 自动添加公共请求头"""

    def __init__(self, headers: Dict[str, str]):
        """
        初始化请求头中间件

        Args:
            headers: 要添加的请求头
        """
        self.headers = headers

    def process_request(self, request: RequestContext) -> RequestContext:
        for key, value in self.headers.items():
            if key not in request.headers:
                request.headers[key] = value
        return request

    def process_response(
        self, response: ResponseContext, request: RequestContext
    ) -> ResponseContext:
        return response


class AuthMiddleware(Middleware):
    """认证中间件 - 自动添加认证信息"""

    def __init__(
        self,
        auth_type: str = "Bearer",
        token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        api_key_header: str = "X-API-Key",
    ):
        """
        初始化认证中间件

        Args:
            auth_type: 认证类型 (Bearer/Basic/ApiKey)
            token: Bearer token
            username: Basic 认证用户名
            password: Basic 认证密码
            api_key: API Key
            api_key_header: API Key 的请求头名称
        """
        self.auth_type = auth_type.lower()
        self.token = token
        self.username = username
        self.password = password
        self.api_key = api_key
        self.api_key_header = api_key_header

    def process_request(self, request: RequestContext) -> RequestContext:
        if self.auth_type == "bearer" and self.token:
            request.headers["Authorization"] = f"Bearer {self.token}"

        elif self.auth_type == "basic" and self.username and self.password:
            import base64

            credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            request.headers["Authorization"] = f"Basic {credentials}"

        elif self.auth_type == "apikey" and self.api_key:
            request.headers[self.api_key_header] = self.api_key

        return request

    def process_response(
        self, response: ResponseContext, request: RequestContext
    ) -> ResponseContext:
        return response


class MetricsMiddleware(Middleware):
    """指标收集中间件 - 收集请求统计信息"""

    def __init__(self):
        self.total_requests: int = 0
        self.successful_requests: int = 0
        self.failed_requests: int = 0
        self.total_bytes: int = 0
        self.total_time: float = 0.0
        self._by_status: Dict[int, int] = defaultdict(int)
        self._by_host: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"requests": 0, "bytes": 0, "time": 0.0}
        )

    def process_request(self, request: RequestContext) -> RequestContext:
        request.start_time = time.time()
        self.total_requests += 1
        return request

    def process_response(
        self, response: ResponseContext, request: RequestContext
    ) -> ResponseContext:
        elapsed = response.elapsed
        content_length = len(response.content)

        # 更新统计
        self._by_status[response.status_code] += 1

        if 200 <= response.status_code < 400:
            self.successful_requests += 1
        else:
            self.failed_requests += 1

        self.total_bytes += content_length
        self.total_time += elapsed

        # 按主机统计
        from urllib.parse import urlparse

        host = urlparse(request.url).netloc
        self._by_host[host]["requests"] += 1
        self._by_host[host]["bytes"] += content_length
        self._by_host[host]["time"] += elapsed

        return response

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": (
                self.successful_requests / self.total_requests * 100
                if self.total_requests > 0
                else 0
            ),
            "total_bytes": self.total_bytes,
            "total_time": self.total_time,
            "avg_time": (self.total_time / self.total_requests if self.total_requests > 0 else 0),
            "by_status": dict(self._by_status),
            "by_host": dict(self._by_host),
        }

    def reset(self) -> None:
        """重置统计"""
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.total_bytes = 0
        self.total_time = 0.0
        self._by_status.clear()
        self._by_host.clear()


class MiddlewareChain:
    """中间件链 - 管理和执行中间件"""

    def __init__(self):
        self._middlewares: List[Middleware] = []
        self._async_middlewares: List[AsyncMiddleware] = []

    def add(self, middleware: Union[Middleware, AsyncMiddleware]) -> "MiddlewareChain":
        """添加中间件"""
        if isinstance(middleware, AsyncMiddleware):
            self._async_middlewares.append(middleware)
        else:
            self._middlewares.append(middleware)
        return self

    def remove(self, middleware_name: str) -> bool:
        """移除中间件"""
        for i, m in enumerate(self._middlewares):
            if m.name == middleware_name:
                self._middlewares.pop(i)
                return True
        for i, m in enumerate(self._async_middlewares):
            if m.name == middleware_name:
                self._async_middlewares.pop(i)
                return True
        return False

    def clear(self) -> None:
        """清空所有中间件"""
        self._middlewares.clear()
        self._async_middlewares.clear()

    def process_request(self, request: RequestContext) -> RequestContext:
        """执行所有中间件的请求处理"""
        for middleware in self._middlewares:
            request = middleware.process_request(request)
        return request

    def process_response(
        self, response: ResponseContext, request: RequestContext
    ) -> ResponseContext:
        """执行所有中间件的响应处理 (逆序)"""
        for middleware in reversed(self._middlewares):
            response = middleware.process_response(response, request)
        return response

    def process_exception(
        self, exception: Exception, request: RequestContext
    ) -> Optional[ResponseContext]:
        """执行所有中间件的异常处理"""
        for middleware in reversed(self._middlewares):
            result = middleware.process_exception(exception, request)
            if result is not None:
                return result
        return None

    async def async_process_request(self, request: RequestContext) -> RequestContext:
        """异步执行所有中间件的请求处理"""
        # 先执行同步中间件（用 to_thread 包装避免阻塞事件循环）
        for middleware in self._middlewares:
            request = await asyncio.to_thread(middleware.process_request, request)
        # 再执行异步中间件
        for middleware in self._async_middlewares:
            request = await middleware.process_request(request)
        return request

    async def async_process_response(
        self, response: ResponseContext, request: RequestContext
    ) -> ResponseContext:
        """异步执行所有中间件的响应处理 (逆序)"""
        for middleware in reversed(self._async_middlewares):
            response = await middleware.process_response(response, request)
        # 同步中间件用 to_thread 包装
        for middleware in reversed(self._middlewares):
            response = await asyncio.to_thread(middleware.process_response, response, request)
        return response

    async def async_process_exception(
        self, exception: Exception, request: RequestContext
    ) -> Optional[ResponseContext]:
        """异步执行所有中间件的异常处理"""
        for middleware in reversed(self._async_middlewares):
            result = await middleware.process_exception(exception, request)
            if result is not None:
                return result
        # 同步中间件用 to_thread 包装
        for middleware in reversed(self._middlewares):
            result = await asyncio.to_thread(middleware.process_exception, exception, request)
            if result is not None:
                return result
        return None


__all__ = [
    "Middleware",
    "AsyncMiddleware",
    "RequestContext",
    "ResponseContext",
    "LoggingMiddleware",
    "RetryMiddleware",
    "AsyncRetryMiddleware",
    "RateLimitMiddleware",
    "AsyncRateLimitMiddleware",
    "HeadersMiddleware",
    "AuthMiddleware",
    "MetricsMiddleware",
    "MiddlewareChain",
]
