"""
统一 HTTP 客户端模块

提供同步和异步 HTTP 客户端的统一接口
支持中间件、会话管理、配置管理等功能

使用示例:
    # 基础用法
    from core.http import get_client, HTTPConfig

    client = get_client()
    response = client.get("https://example.com")
    print(response.status_code, response.text)

    # 自定义配置
    config = HTTPConfig()
    config.timeout = 60
    config.verify_ssl = False
    client = HTTPClient(config=config)

    # 异步用法
    async with async_client_context() as client:
        response = await client.async_get("https://example.com")

    # 会话用法 (保持 Cookie 和认证)
    session = HTTPSession(base_url="https://api.example.com")
    session.set_bearer_token("your-token")
    response = session.get("/users/me")

    # 中间件
    from core.http import HTTPClient, LoggingMiddleware, RateLimitMiddleware

    client = HTTPClient()
    client.middleware_chain.add(LoggingMiddleware())
    client.middleware_chain.add(RateLimitMiddleware(requests_per_second=5))
"""

# 核心客户端
from .client import (
    HTTPClient,
    HTTPResponse,
    get_client,
    reset_client,
    client_context,
    async_client_context,
)

# 配置
from .config import (
    HTTPConfig,
    RetryConfig,
    RetryStrategy,
    ProxyConfig,
    PoolConfig,
    ConfigPresets,
)

# 会话管理
from .session import (
    HTTPSession,
    AuthType,
    AuthConfig,
    Cookie,
    CookieJar,
)

# 中间件
from .middleware import (
    Middleware,
    AsyncMiddleware,
    RequestContext,
    ResponseContext,
    LoggingMiddleware,
    RetryMiddleware,
    RateLimitMiddleware,
    AsyncRateLimitMiddleware,
    HeadersMiddleware,
    AuthMiddleware,
    MetricsMiddleware,
    MiddlewareChain,
)

# 异常
from .exceptions import (
    HTTPError,
    TimeoutError,
    ConnectionError,
    SSLError,
    ProxyError,
    RedirectError,
    RequestError,
    ResponseError,
    RateLimitError,
    AuthenticationError,
    ServerError,
    ClientError,
    exception_from_status_code,
)

# 向后兼容 - 保留旧的工厂接口
from .client_factory import (
    HTTPClientFactory,
    ClientType,
    get_sync_client,
    get_async_client,
)


__all__ = [
    # 客户端
    "HTTPClient",
    "HTTPResponse",
    "get_client",
    "reset_client",
    "client_context",
    "async_client_context",

    # 配置
    "HTTPConfig",
    "RetryConfig",
    "RetryStrategy",
    "ProxyConfig",
    "PoolConfig",
    "ConfigPresets",

    # 会话
    "HTTPSession",
    "AuthType",
    "AuthConfig",
    "Cookie",
    "CookieJar",

    # 中间件
    "Middleware",
    "AsyncMiddleware",
    "RequestContext",
    "ResponseContext",
    "LoggingMiddleware",
    "RetryMiddleware",
    "RateLimitMiddleware",
    "AsyncRateLimitMiddleware",
    "HeadersMiddleware",
    "AuthMiddleware",
    "MetricsMiddleware",
    "MiddlewareChain",

    # 异常
    "HTTPError",
    "TimeoutError",
    "ConnectionError",
    "SSLError",
    "ProxyError",
    "RedirectError",
    "RequestError",
    "ResponseError",
    "RateLimitError",
    "AuthenticationError",
    "ServerError",
    "ClientError",
    "exception_from_status_code",

    # 向后兼容
    "HTTPClientFactory",
    "ClientType",
    "get_sync_client",
    "get_async_client",
]


# 版本信息
__version__ = "3.0.0"
__author__ = "AutoRedTeam"
