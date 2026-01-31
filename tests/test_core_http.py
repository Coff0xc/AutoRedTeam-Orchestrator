"""
core.http 模块单元测试

测试 HTTP 客户端的核心功能
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import asyncio


class TestHTTPConfig:
    """测试 HTTPConfig 配置类"""

    def test_default_config(self):
        """测试默认配置"""
        from core.http import HTTPConfig
        config = HTTPConfig()

        assert config.timeout == 30
        assert config.verify_ssl is True
        assert config.max_retries == 3
        assert config.user_agent is not None

    def test_custom_config(self):
        """测试自定义配置"""
        from core.http import HTTPConfig
        config = HTTPConfig()
        config.timeout = 60
        config.verify_ssl = False
        config.max_retries = 5

        assert config.timeout == 60
        assert config.verify_ssl is False
        assert config.max_retries == 5


class TestHTTPClient:
    """测试 HTTPClient 类"""

    def test_client_creation(self):
        """测试客户端创建"""
        from core.http import HTTPClient, HTTPConfig
        config = HTTPConfig()
        client = HTTPClient(config=config)

        assert client is not None
        assert client.config == config

    def test_get_client_singleton(self):
        """测试 get_client 单例模式"""
        from core.http import get_client, reset_client

        # 重置以确保干净状态
        reset_client()

        client1 = get_client()
        client2 = get_client()

        assert client1 is client2

        # 清理
        reset_client()

    @patch('core.http.client.httpx')
    def test_get_request(self, mock_httpx):
        """测试 GET 请求"""
        from core.http import HTTPClient, HTTPConfig

        # 模拟响应
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_response.headers = {}
        mock_response.content = b"OK"

        mock_client = Mock()
        mock_client.get.return_value = mock_response
        mock_httpx.Client.return_value.__enter__ = Mock(return_value=mock_client)
        mock_httpx.Client.return_value.__exit__ = Mock(return_value=False)

        config = HTTPConfig()
        client = HTTPClient(config=config)

        # 这里我们测试客户端是否正确初始化
        assert client is not None

    def test_context_manager(self):
        """测试上下文管理器"""
        from core.http import client_context

        with client_context() as client:
            assert client is not None


class TestHTTPResponse:
    """测试 HTTPResponse 类"""

    def test_response_creation(self):
        """测试响应对象创建"""
        from core.http import HTTPResponse

        response = HTTPResponse(
            status_code=200,
            text="OK",
            headers={"Content-Type": "text/html"},
            content=b"OK"
        )

        assert response.status_code == 200
        assert response.text == "OK"
        assert response.headers["Content-Type"] == "text/html"

    def test_response_ok_property(self):
        """测试 ok 属性"""
        from core.http import HTTPResponse

        response_ok = HTTPResponse(status_code=200, text="", headers={}, content=b"")
        response_error = HTTPResponse(status_code=500, text="", headers={}, content=b"")

        assert response_ok.ok is True
        assert response_error.ok is False

    def test_response_json(self):
        """测试 JSON 解析"""
        from core.http import HTTPResponse

        response = HTTPResponse(
            status_code=200,
            text='{"key": "value"}',
            headers={"Content-Type": "application/json"},
            content=b'{"key": "value"}'
        )

        json_data = response.json()
        assert json_data == {"key": "value"}


class TestRetryConfig:
    """测试重试配置"""

    def test_retry_config_defaults(self):
        """测试重试配置默认值"""
        from core.http import RetryConfig

        config = RetryConfig()

        assert config.max_retries >= 0
        assert config.backoff_factor >= 0

    def test_retry_config_custom(self):
        """测试自定义重试配置"""
        from core.http import RetryConfig

        config = RetryConfig()
        config.max_retries = 5
        config.backoff_factor = 2.0

        assert config.max_retries == 5
        assert config.backoff_factor == 2.0


class TestHTTPExceptions:
    """测试 HTTP 异常"""

    def test_http_error(self):
        """测试 HTTPError"""
        from core.http import HTTPError

        error = HTTPError("Test error")
        assert str(error) == "Test error"

    def test_timeout_error(self):
        """测试 TimeoutError"""
        from core.http import TimeoutError

        error = TimeoutError("Request timed out")
        assert "timed out" in str(error).lower()

    def test_connection_error(self):
        """测试 ConnectionError"""
        from core.http import ConnectionError

        error = ConnectionError("Connection failed")
        assert "failed" in str(error).lower()

    def test_ssl_error(self):
        """测试 SSLError"""
        from core.http import SSLError

        error = SSLError("SSL verification failed")
        assert "SSL" in str(error)

    def test_exception_from_status_code(self):
        """测试状态码异常映射"""
        from core.http import exception_from_status_code, ClientError, ServerError

        # 4xx 应该返回 ClientError
        error_400 = exception_from_status_code(400)
        assert isinstance(error_400, ClientError)

        # 5xx 应该返回 ServerError
        error_500 = exception_from_status_code(500)
        assert isinstance(error_500, ServerError)


class TestMiddleware:
    """测试中间件"""

    def test_logging_middleware(self):
        """测试日志中间件"""
        from core.http import LoggingMiddleware

        middleware = LoggingMiddleware()
        assert middleware is not None

    def test_rate_limit_middleware(self):
        """测试速率限制中间件"""
        from core.http import RateLimitMiddleware

        middleware = RateLimitMiddleware(requests_per_second=10)
        assert middleware is not None

    def test_middleware_chain(self):
        """测试中间件链"""
        from core.http import MiddlewareChain, LoggingMiddleware

        chain = MiddlewareChain()
        chain.add(LoggingMiddleware())

        assert len(chain.middlewares) == 1


class TestHTTPSession:
    """测试 HTTP 会话"""

    def test_session_creation(self):
        """测试会话创建"""
        from core.http import HTTPSession

        session = HTTPSession(base_url="https://api.example.com")
        assert session is not None
        assert session.base_url == "https://api.example.com"

    def test_session_headers(self):
        """测试会话头设置"""
        from core.http import HTTPSession

        session = HTTPSession(base_url="https://api.example.com")
        session.set_header("X-Custom-Header", "value")

        assert "X-Custom-Header" in session.headers

    def test_session_bearer_token(self):
        """测试 Bearer Token 设置"""
        from core.http import HTTPSession

        session = HTTPSession(base_url="https://api.example.com")
        session.set_bearer_token("test-token")

        assert "Authorization" in session.headers
        assert "Bearer test-token" in session.headers["Authorization"]


class TestClientFactory:
    """测试客户端工厂"""

    def test_get_sync_client(self):
        """测试获取同步客户端"""
        from core.http import get_sync_client

        client = get_sync_client()
        assert client is not None

    def test_client_type_enum(self):
        """测试客户端类型枚举"""
        from core.http import ClientType

        assert ClientType.SYNC is not None
        assert ClientType.ASYNC is not None


# ==================== 异步测试 ====================

class TestAsyncHTTPClient:
    """测试异步 HTTP 客户端"""

    @pytest.mark.asyncio
    async def test_async_client_context(self):
        """测试异步客户端上下文"""
        from core.http import async_client_context

        async with async_client_context() as client:
            assert client is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
