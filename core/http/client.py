"""
统一 HTTP 客户端

提供同步和异步两种模式的 HTTP 客户端
基于 httpx 实现，支持连接池、重试、中间件等功能
"""

import asyncio
import json as json_module
import logging
import time
import warnings
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Union,
)

logger = logging.getLogger(__name__)

# 尝试导入 httpx
try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    httpx = None  # type: ignore

# 回退到 requests（同步）和 aiohttp（异步）
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    requests = None  # type: ignore

try:
    import aiohttp

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None  # type: ignore


from .config import HTTPConfig
from .exceptions import (
    ConnectionError,
    HTTPError,
    ProxyError,
    RequestError,
    SSLError,
    TimeoutError,
    exception_from_status_code,
)
from .middleware import MiddlewareChain, RequestContext, ResponseContext


@dataclass
class HTTPResponse:
    """统一响应对象"""

    status_code: int
    headers: Dict[str, str]
    text: str
    content: bytes
    elapsed: float
    url: str
    encoding: str = "utf-8"
    history: List["HTTPResponse"] = field(default_factory=list)

    @property
    def json(self) -> Any:
        """
        解析 JSON 响应

        Returns:
            解析后的 JSON 对象

        Raises:
            ValueError: JSON 解析失败
        """
        try:
            return json_module.loads(self.text)
        except json_module.JSONDecodeError as e:
            raise ValueError(f"JSON 解析失败: {e}")

    @property
    def ok(self) -> bool:
        """检查响应是否成功 (2xx 或 3xx)"""
        return 200 <= self.status_code < 400

    @property
    def is_success(self) -> bool:
        """检查响应是否为成功状态 (2xx)"""
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        """检查是否为重定向响应"""
        return 300 <= self.status_code < 400

    @property
    def is_client_error(self) -> bool:
        """检查是否为客户端错误 (4xx)"""
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        """检查是否为服务器错误 (5xx)"""
        return self.status_code >= 500

    def raise_for_status(self) -> None:
        """
        如果响应状态码表示错误，则抛出异常

        Raises:
            HTTPError: 响应状态码 >= 400
        """
        if self.status_code >= 400:
            raise exception_from_status_code(
                self.status_code,
                url=self.url,
                details={"text": self.text[:500] if self.text else None},
            )

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "text": self.text,
            "url": self.url,
            "elapsed": self.elapsed,
            "ok": self.ok,
        }

    def __repr__(self) -> str:
        return f"HTTPResponse({self.status_code}, url={self.url!r})"


class HTTPClient:
    """统一 HTTP 客户端 - 支持同步和异步"""

    def __init__(
        self, config: Optional[HTTPConfig] = None, middlewares: Optional[List[Any]] = None
    ):
        """
        初始化 HTTP 客户端

        Args:
            config: HTTP 配置
            middlewares: 中间件列表
        """
        self.config = config or HTTPConfig()
        self.middleware_chain = MiddlewareChain()

        # 添加中间件
        if middlewares:
            for mw in middlewares:
                self.middleware_chain.add(mw)

        # 客户端实例 (延迟初始化)
        self._sync_client: Optional[Any] = None
        self._async_client: Optional[Any] = None

        # SSL 警告标志
        self._ssl_warning_shown = False

    def _warn_ssl_disabled(self) -> None:
        """发出 SSL 禁用警告"""
        if not self._ssl_warning_shown and not self.config.verify_ssl:
            warnings.warn(
                "SSL 验证已禁用！可能存在中间人攻击风险。" "仅在测试环境或明确信任的网络中使用。",
                UserWarning,
                stacklevel=4,
            )
            logger.warning("SSL 验证已禁用")
            self._ssl_warning_shown = True

            # 禁用 urllib3 的 SSL 警告
            try:
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

    def _get_sync_client(self):
        """获取或创建同步客户端"""
        if self._sync_client is not None:
            return self._sync_client

        self._warn_ssl_disabled()

        if HTTPX_AVAILABLE:
            # 使用 httpx
            timeout = httpx.Timeout(
                connect=self.config.connect_timeout,
                read=self.config.read_timeout,
                write=self.config.write_timeout,
                pool=self.config.timeout,
            )
            limits = httpx.Limits(
                max_connections=self.config.pool.max_connections,
                max_keepalive_connections=self.config.pool.max_keepalive,
            )
            # httpx 0.24+ 使用 proxy 而不是 proxies
            proxy_config = self.config.proxy.to_dict()
            proxy_url = (
                proxy_config.get("https://") or proxy_config.get("http://")
                if proxy_config
                else None
            )
            self._sync_client = httpx.Client(
                timeout=timeout,
                limits=limits,
                verify=self.config.verify_ssl,
                follow_redirects=self.config.follow_redirects,
                max_redirects=self.config.max_redirects,
                headers=self.config.default_headers,
                proxy=proxy_url,
                http2=self.config.pool.http2,
            )
        elif REQUESTS_AVAILABLE:
            # 回退到 requests
            session = requests.Session()
            session.verify = self.config.verify_ssl
            session.headers.update(self.config.default_headers)

            # 配置重试
            retry_strategy = Retry(
                total=self.config.retry.max_retries,
                backoff_factor=self.config.retry.backoff_factor,
                status_forcelist=list(self.config.retry.retry_status_codes),
                allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"],
            )
            adapter = HTTPAdapter(
                max_retries=retry_strategy, pool_maxsize=self.config.pool.max_connections
            )
            session.mount("http://", adapter)
            session.mount("https://", adapter)

            # 代理
            if self.config.proxy.http_proxy or self.config.proxy.https_proxy:
                session.proxies = {
                    "http": self.config.proxy.http_proxy,
                    "https": self.config.proxy.https_proxy,
                }

            self._sync_client = session
        else:
            raise ImportError("需要安装 httpx 或 requests: pip install httpx")

        return self._sync_client

    async def _get_async_client(self):
        """获取或创建异步客户端"""
        if self._async_client is not None:
            return self._async_client

        self._warn_ssl_disabled()

        if HTTPX_AVAILABLE:
            # 使用 httpx
            timeout = httpx.Timeout(
                connect=self.config.connect_timeout,
                read=self.config.read_timeout,
                write=self.config.write_timeout,
                pool=self.config.timeout,
            )
            limits = httpx.Limits(
                max_connections=self.config.pool.max_connections,
                max_keepalive_connections=self.config.pool.max_keepalive,
            )
            # httpx 0.24+ 使用 proxy 而不是 proxies
            proxy_config = self.config.proxy.to_dict()
            proxy_url = (
                proxy_config.get("https://") or proxy_config.get("http://")
                if proxy_config
                else None
            )
            self._async_client = httpx.AsyncClient(
                timeout=timeout,
                limits=limits,
                verify=self.config.verify_ssl,
                follow_redirects=self.config.follow_redirects,
                max_redirects=self.config.max_redirects,
                headers=self.config.default_headers,
                proxy=proxy_url,
                http2=self.config.pool.http2,
            )
        elif AIOHTTP_AVAILABLE:
            # 回退到 aiohttp
            timeout = aiohttp.ClientTimeout(
                total=self.config.timeout,
                connect=self.config.connect_timeout,
                sock_read=self.config.read_timeout,
            )
            connector = aiohttp.TCPConnector(
                limit=self.config.pool.max_connections,
                ssl=self.config.verify_ssl if self.config.verify_ssl else False,
            )
            self._async_client = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers=self.config.default_headers,
            )
        else:
            raise ImportError("需要安装 httpx 或 aiohttp: pip install httpx")

        return self._async_client

    def _convert_exception(self, e: Exception, url: str) -> HTTPError:
        """转换原生异常为统一异常"""
        exc_type = type(e).__name__

        if "Timeout" in exc_type or "timeout" in str(e).lower():
            return TimeoutError(str(e), url=url)
        elif "Connect" in exc_type or "connect" in str(e).lower():
            return ConnectionError(str(e), url=url)
        elif "SSL" in exc_type or "ssl" in str(e).lower():
            return SSLError(str(e), url=url)
        elif "Proxy" in exc_type or "proxy" in str(e).lower():
            return ProxyError(str(e), url=url)
        else:
            return RequestError(str(e), url=url)

    def _build_response(
        self, raw_response: Any, elapsed: float, backend: str = "httpx"
    ) -> HTTPResponse:
        """构建统一响应对象"""
        if backend == "httpx":
            return HTTPResponse(
                status_code=raw_response.status_code,
                headers=dict(raw_response.headers),
                text=raw_response.text,
                content=raw_response.content,
                elapsed=elapsed,
                url=str(raw_response.url),
                encoding=raw_response.encoding or "utf-8",
            )
        elif backend == "requests":
            return HTTPResponse(
                status_code=raw_response.status_code,
                headers=dict(raw_response.headers),
                text=raw_response.text,
                content=raw_response.content,
                elapsed=elapsed,
                url=raw_response.url,
                encoding=raw_response.encoding or "utf-8",
            )
        else:
            raise ValueError(f"未知的后端: {backend}")

    async def _build_response_async(
        self, raw_response: Any, elapsed: float, backend: str = "httpx"
    ) -> HTTPResponse:
        """异步构建统一响应对象"""
        if backend == "httpx":
            return HTTPResponse(
                status_code=raw_response.status_code,
                headers=dict(raw_response.headers),
                text=raw_response.text,
                content=raw_response.content,
                elapsed=elapsed,
                url=str(raw_response.url),
                encoding=raw_response.encoding or "utf-8",
            )
        elif backend == "aiohttp":
            content = await raw_response.read()
            text = content.decode("utf-8", errors="replace")
            return HTTPResponse(
                status_code=raw_response.status,
                headers=dict(raw_response.headers),
                text=text,
                content=content,
                elapsed=elapsed,
                url=str(raw_response.url),
            )
        else:
            raise ValueError(f"未知的后端: {backend}")

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        timeout: Optional[float] = None,
        **kwargs,
    ) -> HTTPResponse:
        """
        发送同步 HTTP 请求

        Args:
            method: HTTP 方法 (GET, POST, PUT, DELETE 等)
            url: 请求 URL
            headers: 请求头
            params: 查询参数
            data: 表单数据
            json: JSON 数据
            timeout: 超时时间 (覆盖默认值)
            **kwargs: 其他参数

        Returns:
            HTTPResponse 对象

        Raises:
            HTTPError: 请求失败
        """
        # 构建请求上下文
        request_ctx = RequestContext(
            method=method.upper(),
            url=url,
            headers=self.config.merge_headers(headers),
            params=params,
            data=data,
            json=json,
            timeout=timeout or self.config.timeout,
        )

        # 执行请求中间件
        request_ctx = self.middleware_chain.process_request(request_ctx)

        # 重试循环
        max_attempts = self.config.retry.max_retries + 1
        last_exception: Optional[Exception] = None

        for attempt in range(1, max_attempts + 1):
            request_ctx.attempt = attempt
            start_time = time.time()

            try:
                client = self._get_sync_client()

                if HTTPX_AVAILABLE and isinstance(client, httpx.Client):
                    raw_response = client.request(
                        method=request_ctx.method,
                        url=request_ctx.url,
                        headers=request_ctx.headers,
                        params=request_ctx.params,
                        data=request_ctx.data,
                        json=request_ctx.json,
                        timeout=request_ctx.timeout,
                        **kwargs,
                    )
                    elapsed = time.time() - start_time
                    response = self._build_response(raw_response, elapsed, "httpx")

                elif REQUESTS_AVAILABLE:
                    raw_response = client.request(
                        method=request_ctx.method,
                        url=request_ctx.url,
                        headers=request_ctx.headers,
                        params=request_ctx.params,
                        data=request_ctx.data,
                        json=request_ctx.json,
                        timeout=request_ctx.timeout,
                        **kwargs,
                    )
                    elapsed = time.time() - start_time
                    response = self._build_response(raw_response, elapsed, "requests")

                else:
                    raise ImportError("需要安装 httpx 或 requests")

                # 构建响应上下文
                response_ctx = ResponseContext(
                    status_code=response.status_code,
                    headers=response.headers,
                    content=response.content,
                    elapsed=elapsed,
                    url=response.url,
                    request=request_ctx,
                )

                # 执行响应中间件
                response_ctx = self.middleware_chain.process_response(response_ctx, request_ctx)

                # 检查是否需要重试
                if response_ctx.extras.get("should_retry") and attempt < max_attempts:
                    continue

                # 日志
                if self.config.log_responses:
                    logger.info(
                        f"[HTTP] {response.status_code} {method} {url} " f"({elapsed*1000:.2f}ms)"
                    )

                return response

            except Exception as e:
                last_exception = e
                elapsed = time.time() - start_time

                # 尝试通过中间件处理异常
                fallback = self.middleware_chain.process_exception(e, request_ctx)
                if fallback:
                    return HTTPResponse(
                        status_code=fallback.status_code,
                        headers=fallback.headers,
                        text=fallback.content.decode("utf-8", errors="replace"),
                        content=fallback.content,
                        elapsed=elapsed,
                        url=url,
                    )

                # 检查是否应该重试
                exc_type = type(e).__name__
                should_retry = (
                    attempt < max_attempts and exc_type in self.config.retry.retry_exceptions
                )

                if should_retry:
                    delay = self.config.retry.calculate_delay(attempt)
                    logger.info(
                        f"[Retry] {method} {url} (异常: {exc_type}, "
                        f"第 {attempt} 次, 等待 {delay:.2f}s)"
                    )
                    time.sleep(delay)
                    continue

                # 无法重试，转换并抛出异常
                raise self._convert_exception(e, url) from e

        # 所有重试都失败
        if last_exception:
            raise self._convert_exception(last_exception, url) from last_exception
        raise RequestError("请求失败", url=url)

    async def async_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        timeout: Optional[float] = None,
        **kwargs,
    ) -> HTTPResponse:
        """
        发送异步 HTTP 请求

        Args:
            method: HTTP 方法
            url: 请求 URL
            headers: 请求头
            params: 查询参数
            data: 表单数据
            json: JSON 数据
            timeout: 超时时间
            **kwargs: 其他参数

        Returns:
            HTTPResponse 对象

        Raises:
            HTTPError: 请求失败
        """
        # 构建请求上下文
        request_ctx = RequestContext(
            method=method.upper(),
            url=url,
            headers=self.config.merge_headers(headers),
            params=params,
            data=data,
            json=json,
            timeout=timeout or self.config.timeout,
        )

        # 执行请求中间件 (异步)
        request_ctx = await self.middleware_chain.async_process_request(request_ctx)

        # 重试循环
        max_attempts = self.config.retry.max_retries + 1
        last_exception: Optional[Exception] = None

        for attempt in range(1, max_attempts + 1):
            request_ctx.attempt = attempt
            start_time = time.time()

            try:
                client = await self._get_async_client()

                if HTTPX_AVAILABLE and isinstance(client, httpx.AsyncClient):
                    raw_response = await client.request(
                        method=request_ctx.method,
                        url=request_ctx.url,
                        headers=request_ctx.headers,
                        params=request_ctx.params,
                        data=request_ctx.data,
                        json=request_ctx.json,
                        timeout=request_ctx.timeout,
                        **kwargs,
                    )
                    elapsed = time.time() - start_time
                    response = await self._build_response_async(raw_response, elapsed, "httpx")

                elif AIOHTTP_AVAILABLE:
                    async with client.request(
                        method=request_ctx.method,
                        url=request_ctx.url,
                        headers=request_ctx.headers,
                        params=request_ctx.params,
                        data=request_ctx.data,
                        json=request_ctx.json,
                        timeout=aiohttp.ClientTimeout(total=request_ctx.timeout),
                        **kwargs,
                    ) as raw_response:
                        elapsed = time.time() - start_time
                        response = await self._build_response_async(
                            raw_response, elapsed, "aiohttp"
                        )

                else:
                    raise ImportError("需要安装 httpx 或 aiohttp")

                # 构建响应上下文
                response_ctx = ResponseContext(
                    status_code=response.status_code,
                    headers=response.headers,
                    content=response.content,
                    elapsed=elapsed,
                    url=response.url,
                    request=request_ctx,
                )

                # 执行响应中间件 (异步)
                response_ctx = await self.middleware_chain.async_process_response(
                    response_ctx, request_ctx
                )

                # 检查是否需要重试
                if response_ctx.extras.get("should_retry") and attempt < max_attempts:
                    continue

                # 日志
                if self.config.log_responses:
                    logger.info(
                        f"[HTTP] {response.status_code} {method} {url} " f"({elapsed*1000:.2f}ms)"
                    )

                return response

            except Exception as e:
                last_exception = e
                elapsed = time.time() - start_time

                # 尝试通过中间件处理异常
                fallback = await self.middleware_chain.async_process_exception(e, request_ctx)
                if fallback:
                    return HTTPResponse(
                        status_code=fallback.status_code,
                        headers=fallback.headers,
                        text=fallback.content.decode("utf-8", errors="replace"),
                        content=fallback.content,
                        elapsed=elapsed,
                        url=url,
                    )

                # 检查是否应该重试
                exc_type = type(e).__name__
                should_retry = (
                    attempt < max_attempts and exc_type in self.config.retry.retry_exceptions
                )

                if should_retry:
                    delay = self.config.retry.calculate_delay(attempt)
                    logger.info(
                        f"[Retry] {method} {url} (异常: {exc_type}, "
                        f"第 {attempt} 次, 等待 {delay:.2f}s)"
                    )
                    await asyncio.sleep(delay)
                    continue

                raise self._convert_exception(e, url) from e

        if last_exception:
            raise self._convert_exception(last_exception, url) from last_exception
        raise RequestError("请求失败", url=url)

    # 同步便捷方法
    def get(self, url: str, **kwargs) -> HTTPResponse:
        """发送 GET 请求"""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> HTTPResponse:
        """发送 POST 请求"""
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> HTTPResponse:
        """发送 PUT 请求"""
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs) -> HTTPResponse:
        """发送 PATCH 请求"""
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs) -> HTTPResponse:
        """发送 DELETE 请求"""
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs) -> HTTPResponse:
        """发送 HEAD 请求"""
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> HTTPResponse:
        """发送 OPTIONS 请求"""
        return self.request("OPTIONS", url, **kwargs)

    # 异步便捷方法
    async def async_get(self, url: str, **kwargs) -> HTTPResponse:
        """发送异步 GET 请求"""
        return await self.async_request("GET", url, **kwargs)

    async def async_post(self, url: str, **kwargs) -> HTTPResponse:
        """发送异步 POST 请求"""
        return await self.async_request("POST", url, **kwargs)

    async def async_put(self, url: str, **kwargs) -> HTTPResponse:
        """发送异步 PUT 请求"""
        return await self.async_request("PUT", url, **kwargs)

    async def async_patch(self, url: str, **kwargs) -> HTTPResponse:
        """发送异步 PATCH 请求"""
        return await self.async_request("PATCH", url, **kwargs)

    async def async_delete(self, url: str, **kwargs) -> HTTPResponse:
        """发送异步 DELETE 请求"""
        return await self.async_request("DELETE", url, **kwargs)

    async def async_head(self, url: str, **kwargs) -> HTTPResponse:
        """发送异步 HEAD 请求"""
        return await self.async_request("HEAD", url, **kwargs)

    async def async_options(self, url: str, **kwargs) -> HTTPResponse:
        """发送异步 OPTIONS 请求"""
        return await self.async_request("OPTIONS", url, **kwargs)

    # 批量请求
    async def async_batch(
        self,
        requests_list: List[Dict[str, Any]],
        concurrency: int = 10,
        raise_on_error: bool = False,
    ) -> List[Union[HTTPResponse, Exception]]:
        """
        批量发送异步请求

        Args:
            requests_list: 请求列表，每个元素包含 method, url 及其他参数
            concurrency: 最大并发数
            raise_on_error: 是否在遇到错误时抛出异常

        Returns:
            响应列表，失败的请求返回异常对象

        Example:
            responses = await client.async_batch([
                {"method": "GET", "url": "https://example.com/1"},
                {"method": "POST", "url": "https://example.com/2", "json": {"key": "value"}},
            ])
        """
        semaphore = asyncio.Semaphore(concurrency)
        results: List[Union[HTTPResponse, Exception]] = [None] * len(requests_list)  # type: ignore

        async def fetch(index: int, req: Dict[str, Any]):
            async with semaphore:
                try:
                    method = req.pop("method", "GET")
                    url = req.pop("url")
                    response = await self.async_request(method, url, **req)
                    results[index] = response
                except Exception as e:
                    if raise_on_error:
                        raise
                    results[index] = e

        tasks = [fetch(i, req.copy()) for i, req in enumerate(requests_list)]
        await asyncio.gather(*tasks, return_exceptions=not raise_on_error)

        return results

    def batch(
        self, requests_list: List[Dict[str, Any]], raise_on_error: bool = False
    ) -> List[Union[HTTPResponse, Exception]]:
        """
        批量发送同步请求

        Args:
            requests_list: 请求列表
            raise_on_error: 是否在遇到错误时抛出异常

        Returns:
            响应列表
        """
        results: List[Union[HTTPResponse, Exception]] = []

        for req in requests_list:
            try:
                method = req.pop("method", "GET")
                url = req.pop("url")
                response = self.request(method, url, **req)
                results.append(response)
            except Exception as e:
                if raise_on_error:
                    raise
                results.append(e)

        return results

    # 资源管理
    def close(self) -> None:
        """关闭同步客户端"""
        if self._sync_client is not None:
            try:
                if hasattr(self._sync_client, "close"):
                    self._sync_client.close()
            except Exception as e:
                logger.warning(f"关闭同步客户端失败: {e}")
            finally:
                self._sync_client = None

    async def aclose(self) -> None:
        """关闭异步客户端"""
        if self._async_client is not None:
            try:
                if hasattr(self._async_client, "aclose"):
                    await self._async_client.aclose()
                elif hasattr(self._async_client, "close"):
                    await self._async_client.close()
            except Exception as e:
                logger.warning(f"关闭异步客户端失败: {e}")
            finally:
                self._async_client = None

    def __enter__(self) -> "HTTPClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    async def __aenter__(self) -> "HTTPClient":
        return self

    async def __aexit__(self, *args) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        return f"HTTPClient(timeout={self.config.timeout}, " f"verify_ssl={self.config.verify_ssl})"


# 全局单例
_default_client: Optional[HTTPClient] = None


def get_client(config: Optional[HTTPConfig] = None) -> HTTPClient:
    """
    获取默认 HTTP 客户端 (单例)

    Args:
        config: HTTP 配置 (仅在首次调用时生效)

    Returns:
        HTTPClient 实例
    """
    global _default_client
    if _default_client is None:
        _default_client = HTTPClient(config=config)
    return _default_client


def reset_client() -> None:
    """重置默认客户端"""
    global _default_client
    if _default_client is not None:
        _default_client.close()
        _default_client = None


@contextmanager
def client_context(config: Optional[HTTPConfig] = None):
    """
    HTTP 客户端上下文管理器 (同步)

    Usage:
        with client_context() as client:
            response = client.get("https://example.com")
    """
    client = HTTPClient(config=config)
    try:
        yield client
    finally:
        client.close()


@asynccontextmanager
async def async_client_context(config: Optional[HTTPConfig] = None):
    """
    HTTP 客户端上下文管理器 (异步)

    Usage:
        async with async_client_context() as client:
            response = await client.async_get("https://example.com")
    """
    client = HTTPClient(config=config)
    try:
        yield client
    finally:
        await client.aclose()


__all__ = [
    "HTTPClient",
    "HTTPResponse",
    "get_client",
    "reset_client",
    "client_context",
    "async_client_context",
]
