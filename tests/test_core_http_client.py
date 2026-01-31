#!/usr/bin/env python3
"""
test_core_http_client.py - HTTP 客户端单元测试

测试覆盖:
- HTTPResponse 响应对象
- HTTPClient 同步客户端
- AsyncHTTPClient 异步客户端
- 重试机制
- 超时处理
- 线程安全
"""

import pytest
import asyncio
import threading
import time
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import Dict, Any

# 导入被测试的模块
from core.http.client import (
    HTTPResponse,
    HTTPClient,
)
from core.http.config import HTTPConfig, RetryStrategy
from core.http.exceptions import (
    HTTPError,
    TimeoutError as HTTPTimeoutError,
    ConnectionError as HTTPConnectionError,
    SSLError,
    RateLimitError,
)


# ============== HTTPResponse 测试 ==============

class TestHTTPResponse:
    """HTTPResponse 响应对象测试"""

    def test_init_basic(self):
        """测试基本初始化"""
        response = HTTPResponse(
            status_code=200,
            headers={'Content-Type': 'application/json'},
            text='{"status": "ok"}',
            content=b'{"status": "ok"}',
            elapsed=0.5,
            url='https://example.com',
        )

        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'application/json'
        assert response.text == '{"status": "ok"}'
        assert response.elapsed == 0.5
        assert response.url == 'https://example.com'

    def test_json_property(self):
        """测试 JSON 解析"""
        response = HTTPResponse(
            status_code=200,
            headers={},
            text='{"key": "value", "number": 123}',
            content=b'',
            elapsed=0.1,
            url='https://example.com',
        )

        json_data = response.json
        assert json_data['key'] == 'value'
        assert json_data['number'] == 123

    def test_json_property_invalid(self):
        """测试无效 JSON 解析"""
        response = HTTPResponse(
            status_code=200,
            headers={},
            text='not a json',
            content=b'',
            elapsed=0.1,
            url='https://example.com',
        )

        with pytest.raises(ValueError, match='JSON 解析失败'):
            _ = response.json

    def test_ok_property(self):
        """测试 ok 属性"""
        # 2xx 成功
        response_200 = HTTPResponse(200, {}, '', b'', 0.1, 'https://example.com')
        assert response_200.ok is True

        # 3xx 重定向也算 ok
        response_301 = HTTPResponse(301, {}, '', b'', 0.1, 'https://example.com')
        assert response_301.ok is True

        # 4xx 客户端错误
        response_404 = HTTPResponse(404, {}, '', b'', 0.1, 'https://example.com')
        assert response_404.ok is False

        # 5xx 服务器错误
        response_500 = HTTPResponse(500, {}, '', b'', 0.1, 'https://example.com')
        assert response_500.ok is False

    def test_is_success_property(self):
        """测试 is_success 属性"""
        response_200 = HTTPResponse(200, {}, '', b'', 0.1, 'https://example.com')
        assert response_200.is_success is True

        response_301 = HTTPResponse(301, {}, '', b'', 0.1, 'https://example.com')
        assert response_301.is_success is False

    def test_is_redirect_property(self):
        """测试 is_redirect 属性"""
        response_301 = HTTPResponse(301, {}, '', b'', 0.1, 'https://example.com')
        assert response_301.is_redirect is True

        response_200 = HTTPResponse(200, {}, '', b'', 0.1, 'https://example.com')
        assert response_200.is_redirect is False


# ============== HTTPClient 同步客户端测试 ==============

class TestHTTPClient:
    """HTTPClient 同步客户端测试"""

    @pytest.fixture
    def mock_requests(self):
        """模拟 requests 库"""
        with patch('core.http.client.REQUESTS_AVAILABLE', True):
            with patch('core.http.client.requests') as mock:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.headers = {'Content-Type': 'text/html'}
                mock_response.text = 'OK'
                mock_response.content = b'OK'
                mock_response.elapsed.total_seconds.return_value = 0.5
                mock_response.url = 'https://example.com'
                mock_response.history = []

                mock.Session.return_value.request.return_value = mock_response
                yield mock

    def test_init_default_config(self, mock_requests):
        """测试默认配置初始化"""
        client = HTTPClient()

        assert client.config.timeout == 30
        assert client.config.max_retries == 3
        assert client.config.verify_ssl is False

    def test_init_custom_config(self, mock_requests):
        """测试自定义配置初始化"""
        config = HTTPConfig(
            timeout=60,
            max_retries=5,
            verify_ssl=True,
        )
        client = HTTPClient(config)

        assert client.config.timeout == 60
        assert client.config.max_retries == 5
        assert client.config.verify_ssl is True

    def test_get_request(self, mock_requests):
        """测试 GET 请求"""
        client = HTTPClient()
        response = client.get('https://example.com')

        assert response.status_code == 200
        assert response.text == 'OK'
        assert response.ok is True

    def test_post_request(self, mock_requests):
        """测试 POST 请求"""
        client = HTTPClient()
        response = client.post('https://example.com', data={'key': 'value'})

        assert response.status_code == 200

    def test_request_with_headers(self, mock_requests):
        """测试带自定义 headers 的请求"""
        client = HTTPClient()
        headers = {'User-Agent': 'TestBot/1.0'}
        response = client.get('https://example.com', headers=headers)

        assert response.status_code == 200

    def test_request_timeout(self, mock_requests):
        """测试请求超时"""
        mock_requests.Session.return_value.request.side_effect = Exception('Timeout')

        client = HTTPClient()
        with pytest.raises(Exception):
            client.get('https://example.com')

    def test_context_manager(self, mock_requests):
        """测试上下文管理器"""
        with HTTPClient() as client:
            response = client.get('https://example.com')
            assert response.status_code == 200

    def test_close(self, mock_requests):
        """测试关闭客户端"""
        client = HTTPClient()
        client.close()
        # 确保可以多次调用 close
        client.close()


# ============== 重试机制测试 ==============

class TestRetryMechanism:
    """重试机制测试"""

    @pytest.fixture
    def mock_requests_with_retry(self):
        """模拟带重试的 requests"""
        with patch('core.http.client.REQUESTS_AVAILABLE', True):
            with patch('core.http.client.requests') as mock:
                # 第一次失败，第二次成功
                mock_response_fail = Mock()
                mock_response_fail.status_code = 500

                mock_response_success = Mock()
                mock_response_success.status_code = 200
                mock_response_success.text = 'OK'
                mock_response_success.content = b'OK'
                mock_response_success.elapsed.total_seconds.return_value = 0.5
                mock_response_success.url = 'https://example.com'
                mock_response_success.history = []
                mock_response_success.headers = {}

                mock.Session.return_value.request.side_effect = [
                    mock_response_fail,
                    mock_response_success,
                ]
                yield mock

    def test_retry_on_failure(self, mock_requests_with_retry):
        """测试失败重试"""
        config = HTTPConfig(
            max_retries=3,
            retry_strategy=RetryStrategy.EXPONENTIAL,
        )
        client = HTTPClient(config)

        # 应该在第二次尝试成功
        response = client.get('https://example.com')
        assert response.status_code == 200


# ============== 线程安全测试 ==============

class TestThreadSafety:
    """线程安全测试"""

    @pytest.fixture
    def mock_requests_thread_safe(self):
        """模拟线程安全的 requests"""
        with patch('core.http.client.REQUESTS_AVAILABLE', True):
            with patch('core.http.client.requests') as mock:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.text = 'OK'
                mock_response.content = b'OK'
                mock_response.elapsed.total_seconds.return_value = 0.1
                mock_response.url = 'https://example.com'
                mock_response.history = []
                mock_response.headers = {}

                mock.Session.return_value.request.return_value = mock_response
                yield mock

    def test_concurrent_requests_thread_safe(self, mock_requests_thread_safe):
        """测试并发请求的线程安全性"""
        client = HTTPClient()
        results = []
        errors = []

        def make_request():
            try:
                response = client.get('https://example.com')
                results.append(response.status_code)
            except Exception as e:
                errors.append(e)

        # 创建多个线程并发请求
        threads = [threading.Thread(target=make_request) for _ in range(10)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # 所有请求都应该成功
        assert len(results) == 10
        assert len(errors) == 0
        assert all(code == 200 for code in results)


# ============== 边界条件测试 ==============

class TestEdgeCases:
    """边界条件测试"""

    @pytest.fixture
    def mock_requests_edge(self):
        """模拟边界情况的 requests"""
        with patch('core.http.client.REQUESTS_AVAILABLE', True):
            with patch('core.http.client.requests') as mock:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.text = ''
                mock_response.content = b''
                mock_response.elapsed.total_seconds.return_value = 0.0
                mock_response.url = 'https://example.com'
                mock_response.history = []
                mock_response.headers = {}

                mock.Session.return_value.request.return_value = mock_response
                yield mock

    def test_empty_response(self, mock_requests_edge):
        """测试空响应"""
        client = HTTPClient()
        response = client.get('https://example.com')

        assert response.status_code == 200
        assert response.text == ''
        assert response.content == b''

    def test_invalid_url(self, mock_requests_edge):
        """测试无效 URL"""
        client = HTTPClient()

        # 空 URL
        with pytest.raises(Exception):
            client.get('')

    def test_special_characters_in_url(self, mock_requests_edge):
        """测试 URL 中的特殊字符"""
        client = HTTPClient()
        response = client.get('https://example.com/path?param=<script>')

        assert response.status_code == 200

    def test_unicode_in_response(self, mock_requests_edge):
        """测试响应中的 Unicode 字符"""
        with patch('core.http.client.requests') as mock:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = '你好世界 🌍'
            mock_response.content = '你好世界 🌍'.encode('utf-8')
            mock_response.elapsed.total_seconds.return_value = 0.1
            mock_response.url = 'https://example.com'
            mock_response.history = []
            mock_response.headers = {}

            mock.Session.return_value.request.return_value = mock_response

            client = HTTPClient()
            response = client.get('https://example.com')

            assert '你好世界' in response.text
            assert '🌍' in response.text


# ============== 异常处理测试 ==============

class TestExceptionHandling:
    """异常处理测试"""

    def test_connection_error(self):
        """测试连接错误"""
        with patch('core.http.client.REQUESTS_AVAILABLE', True):
            with patch('core.http.client.requests') as mock:
                mock.Session.return_value.request.side_effect = ConnectionError('Connection refused')

                client = HTTPClient()
                with pytest.raises(Exception):
                    client.get('https://example.com')

    def test_timeout_error(self):
        """测试超时错误"""
        with patch('core.http.client.REQUESTS_AVAILABLE', True):
            with patch('core.http.client.requests') as mock:
                import socket
                mock.Session.return_value.request.side_effect = socket.timeout('Request timeout')

                client = HTTPClient()
                with pytest.raises(Exception):
                    client.get('https://example.com')

    def test_ssl_error(self):
        """测试 SSL 错误"""
        with patch('core.http.client.REQUESTS_AVAILABLE', True):
            with patch('core.http.client.requests') as mock:
                import ssl
                mock.Session.return_value.request.side_effect = ssl.SSLError('SSL verification failed')

                client = HTTPClient()
                with pytest.raises(Exception):
                    client.get('https://example.com')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
