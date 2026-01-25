"""
统一 HTTP 客户端 - 已弃用

⚠️ 此模块已弃用，请使用 core.http 模块

迁移指南:
    # 旧代码
    from utils.http_client import SecureHTTPClient
    client = SecureHTTPClient()

    # 新代码
    from core.http import HTTPClient, HTTPConfig
    config = HTTPConfig()
    client = HTTPClient(config=config)

    # 或使用便捷函数
    from core.http import get_client
    client = get_client()
"""

import warnings
import logging

logger = logging.getLogger(__name__)

# 发出弃用警告
warnings.warn(
    "utils.http_client 模块已弃用，请使用 core.http 模块。"
    "此模块将在 v4.0 中移除。",
    DeprecationWarning,
    stacklevel=2
)


class SecurityWarning(UserWarning):
    """安全警告 - 已弃用，使用 core.http.exceptions"""
    pass


# 向后兼容：重定向到 core.http
try:
    from core.http import (
        HTTPClient as _HTTPClient,
        HTTPConfig,
        get_client,
    )

    class SecureHTTPClient:
        """
        安全的 HTTP 客户端 - 已弃用

        ⚠️ 此类已弃用，请使用 core.http.HTTPClient

        向后兼容包装器，内部使用 core.http.HTTPClient
        """

        def __init__(
            self,
            verify_ssl=None,
            timeout=30,
            max_retries=3,
            user_agent="AutoRedTeam/3.0",
            proxy=None
        ):
            warnings.warn(
                "SecureHTTPClient 已弃用，请使用 core.http.HTTPClient",
                DeprecationWarning,
                stacklevel=2
            )

            # 创建配置
            config = HTTPConfig()
            config.timeout = timeout
            config.verify_ssl = verify_ssl if verify_ssl is not None else True
            config.user_agent = user_agent

            if proxy:
                config.proxy_url = proxy.get('https') or proxy.get('http')

            # 使用 core.http.HTTPClient
            self._client = _HTTPClient(config=config)
            self.timeout = timeout
            self.verify_ssl = config.verify_ssl

        def get(self, url, **kwargs):
            """GET 请求"""
            kwargs.setdefault('timeout', self.timeout)
            return self._client.get(url, **kwargs)

        def post(self, url, **kwargs):
            """POST 请求"""
            kwargs.setdefault('timeout', self.timeout)
            return self._client.post(url, **kwargs)

        def put(self, url, **kwargs):
            """PUT 请求"""
            kwargs.setdefault('timeout', self.timeout)
            return self._client.put(url, **kwargs)

        def delete(self, url, **kwargs):
            """DELETE 请求"""
            kwargs.setdefault('timeout', self.timeout)
            return self._client.delete(url, **kwargs)

        def head(self, url, **kwargs):
            """HEAD 请求"""
            kwargs.setdefault('timeout', self.timeout)
            return self._client.head(url, **kwargs)

        def options(self, url, **kwargs):
            """OPTIONS 请求"""
            kwargs.setdefault('timeout', self.timeout)
            return self._client.options(url, **kwargs)

        def request(self, method, url, **kwargs):
            """通用请求方法"""
            kwargs.setdefault('timeout', self.timeout)
            return self._client.request(method, url, **kwargs)

        def close(self):
            """关闭会话"""
            if hasattr(self._client, 'close'):
                self._client.close()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.close()


    # 便捷函数 - 已弃用
    def get(url, **kwargs):
        """便捷的 GET 请求 - 已弃用，使用 core.http.get_client()"""
        warnings.warn(
            "utils.http_client.get() 已弃用，请使用 core.http.get_client().get()",
            DeprecationWarning,
            stacklevel=2
        )
        client = get_client()
        return client.get(url, **kwargs)


    def post(url, **kwargs):
        """便捷的 POST 请求 - 已弃用，使用 core.http.get_client()"""
        warnings.warn(
            "utils.http_client.post() 已弃用，请使用 core.http.get_client().post()",
            DeprecationWarning,
            stacklevel=2
        )
        client = get_client()
        return client.post(url, **kwargs)

except ImportError:
    # core.http 不可用时，保留原始实现
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    logger.warning("core.http 不可用，使用原始 SecureHTTPClient 实现")

    class SecureHTTPClient:
        """安全的 HTTP 客户端 (回退实现)"""

        def __init__(
            self,
            verify_ssl=None,
            timeout=30,
            max_retries=3,
            user_agent="AutoRedTeam/3.0",
            proxy=None
        ):
            self.session = requests.Session()
            self.timeout = timeout

            if verify_ssl is None:
                verify_ssl = True

            self.verify_ssl = verify_ssl

            if not verify_ssl:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            retry_strategy = Retry(
                total=max_retries,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)

            self.session.headers.update({
                "User-Agent": user_agent,
                "Accept": "*/*",
            })

            if proxy:
                self.session.proxies.update(proxy)

        def get(self, url, **kwargs):
            kwargs.setdefault('verify', self.verify_ssl)
            kwargs.setdefault('timeout', self.timeout)
            return self.session.get(url, **kwargs)

        def post(self, url, **kwargs):
            kwargs.setdefault('verify', self.verify_ssl)
            kwargs.setdefault('timeout', self.timeout)
            return self.session.post(url, **kwargs)

        def put(self, url, **kwargs):
            kwargs.setdefault('verify', self.verify_ssl)
            kwargs.setdefault('timeout', self.timeout)
            return self.session.put(url, **kwargs)

        def delete(self, url, **kwargs):
            kwargs.setdefault('verify', self.verify_ssl)
            kwargs.setdefault('timeout', self.timeout)
            return self.session.delete(url, **kwargs)

        def head(self, url, **kwargs):
            kwargs.setdefault('verify', self.verify_ssl)
            kwargs.setdefault('timeout', self.timeout)
            return self.session.head(url, **kwargs)

        def options(self, url, **kwargs):
            kwargs.setdefault('verify', self.verify_ssl)
            kwargs.setdefault('timeout', self.timeout)
            return self.session.options(url, **kwargs)

        def request(self, method, url, **kwargs):
            kwargs.setdefault('verify', self.verify_ssl)
            kwargs.setdefault('timeout', self.timeout)
            return self.session.request(method, url, **kwargs)

        def close(self):
            self.session.close()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.close()


    def get(url, **kwargs):
        with SecureHTTPClient() as client:
            return client.get(url, **kwargs)


    def post(url, **kwargs):
        with SecureHTTPClient() as client:
            return client.post(url, **kwargs)
