"""
统一 HTTP 客户端 - 安全的 HTTP 请求封装
解决 SSL 验证禁用、重复代码等问题

使用示例:
    from utils.http_client import SecureHTTPClient

    client = SecureHTTPClient()  # 默认启用 SSL
    resp = client.get("https://example.com")

    # 特殊情况禁用 SSL（会发出警告）
    client_insecure = SecureHTTPClient(verify_ssl=False)
"""

import requests
import warnings
import logging
from typing import Optional, Dict, Any
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class SecurityWarning(UserWarning):
    """安全警告"""
    pass


class SecureHTTPClient:
    """安全的 HTTP 客户端

    特性:
    - 默认启用 SSL 验证
    - 自动重试机制
    - 统一的超时控制
    - 自定义 User-Agent
    - 代理支持
    """

    def __init__(
        self,
        verify_ssl: Optional[bool] = None,
        timeout: int = 30,
        max_retries: int = 3,
        user_agent: str = "AutoRedTeam/3.0",
        proxy: Optional[Dict[str, str]] = None
    ):
        """初始化 HTTP 客户端

        Args:
            verify_ssl: 是否验证 SSL（None 时从配置读取，默认 True）
            timeout: 默认超时时间（秒）
            max_retries: 最大重试次数
            user_agent: User-Agent 字符串
            proxy: 代理配置 {"http": "...", "https": "..."}
        """
        self.session = requests.Session()
        self.timeout = timeout

        # SSL 验证配置
        if verify_ssl is None:
            # 从配置读取（默认 True）
            try:
                from utils.config_manager import get_config
                verify_ssl = get_config().security.verify_ssl
            except Exception:
                verify_ssl = True  # 默认启用

        self.verify_ssl = verify_ssl

        # 禁用 SSL 时发出警告
        if not verify_ssl:
            warnings.warn(
                "SSL 验证已禁用！可能存在中间人攻击风险。"
                "仅在测试环境或明确信任的网络中使用。",
                SecurityWarning,
                stacklevel=2
            )
            logger.warning("SSL 验证已禁用")

            # 禁用 urllib3 的 SSL 警告（避免噪音）
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # 配置重试策略
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # 设置默认 headers
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "*/*",
        })

        # 代理配置
        if proxy:
            self.session.proxies.update(proxy)

    def get(self, url: str, **kwargs) -> requests.Response:
        """GET 请求"""
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('timeout', self.timeout)
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """POST 请求"""
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('timeout', self.timeout)
        return self.session.post(url, **kwargs)

    def put(self, url: str, **kwargs) -> requests.Response:
        """PUT 请求"""
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('timeout', self.timeout)
        return self.session.put(url, **kwargs)

    def delete(self, url: str, **kwargs) -> requests.Response:
        """DELETE 请求"""
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('timeout', self.timeout)
        return self.session.delete(url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        """HEAD 请求"""
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('timeout', self.timeout)
        return self.session.head(url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response:
        """OPTIONS 请求"""
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('timeout', self.timeout)
        return self.session.options(url, **kwargs)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """通用请求方法"""
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('timeout', self.timeout)
        return self.session.request(method, url, **kwargs)

    def close(self):
        """关闭会话"""
        self.session.close()

    def __enter__(self):
        """上下文管理器支持"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器支持"""
        self.close()


# 便捷函数
def get(url: str, **kwargs) -> requests.Response:
    """便捷的 GET 请求（使用默认安全配置）"""
    with SecureHTTPClient() as client:
        return client.get(url, **kwargs)


def post(url: str, **kwargs) -> requests.Response:
    """便捷的 POST 请求（使用默认安全配置）"""
    with SecureHTTPClient() as client:
        return client.post(url, **kwargs)
