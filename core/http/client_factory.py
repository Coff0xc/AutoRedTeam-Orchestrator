"""
统一 HTTP 客户端工厂

解决项目中 20+ 处重复创建 requests.Session() 和 aiohttp.ClientSession() 的问题
提供单例复用、连接池管理、统一配置

使用示例:
    # 同步客户端
    from core.http import get_sync_client
    client = get_sync_client()
    resp = client.get("https://example.com")

    # 异步客户端
    from core.http import get_async_client
    async with get_async_client() as client:
        resp = await client.get("https://example.com")
"""

import logging
import warnings
from typing import Optional, Dict, Any
from enum import Enum
from contextlib import asynccontextmanager

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class ClientType(Enum):
    """客户端类型"""
    SYNC = "sync"
    ASYNC = "async"


class SecurityWarning(UserWarning):
    """安全警告"""
    pass


class HTTPClientFactory:
    """统一的 HTTP 客户端工厂

    特性:
    - 同步客户端单例复用，减少连接开销
    - 异步客户端上下文管理，自动清理
    - 统一的 SSL 验证策略（默认启用）
    - 统一的重试机制和超时配置
    - 统一的 User-Agent
    """

    _sync_session: Optional[requests.Session] = None
    _default_timeout: int = 30
    _default_user_agent: str = "AutoRedTeam/3.0"
    _default_max_retries: int = 3

    @classmethod
    def get_sync_client(
        cls,
        timeout: Optional[int] = None,
        verify_ssl: bool = True,
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        max_retries: Optional[int] = None,
        force_new: bool = False
    ) -> requests.Session:
        """获取同步 HTTP 客户端 (单例复用)

        Args:
            timeout: 超时时间（秒），默认 30
            verify_ssl: 是否验证 SSL，默认 True
            proxy: 代理地址，如 "http://127.0.0.1:8080"
            headers: 额外的请求头
            max_retries: 最大重试次数，默认 3
            force_new: 强制创建新实例（不使用单例）

        Returns:
            requests.Session 实例
        """
        if force_new or cls._sync_session is None:
            session = cls._create_sync_session(
                timeout=timeout or cls._default_timeout,
                verify_ssl=verify_ssl,
                proxy=proxy,
                headers=headers,
                max_retries=max_retries or cls._default_max_retries
            )
            if not force_new:
                cls._sync_session = session
            return session

        return cls._sync_session

    @classmethod
    def _create_sync_session(
        cls,
        timeout: int,
        verify_ssl: bool,
        proxy: Optional[str],
        headers: Optional[Dict[str, str]],
        max_retries: int
    ) -> requests.Session:
        """创建同步 Session"""
        session = requests.Session()

        # SSL 验证配置
        session.verify = verify_ssl
        if not verify_ssl:
            cls._warn_ssl_disabled()

        # 配置重试策略
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_maxsize=50)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # 设置默认 headers
        session.headers.update({
            "User-Agent": cls._default_user_agent,
            "Accept": "*/*",
            **(headers or {})
        })

        # 代理配置
        if proxy:
            session.proxies.update({
                "http": proxy,
                "https": proxy
            })

        return session

    @classmethod
    @asynccontextmanager
    async def get_async_client(
        cls,
        timeout: Optional[int] = None,
        verify_ssl: bool = True,
        concurrency: int = 50,
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ):
        """获取异步 HTTP 客户端 (上下文管理)

        Args:
            timeout: 超时时间（秒），默认 30
            verify_ssl: 是否验证 SSL，默认 True
            concurrency: 最大并发连接数，默认 50
            proxy: 代理地址
            headers: 额外的请求头

        Yields:
            aiohttp.ClientSession 实例

        Usage:
            async with HTTPClientFactory.get_async_client() as client:
                resp = await client.get("https://example.com")
        """
        try:
            import aiohttp
        except ImportError:
            raise ImportError("异步客户端需要安装 aiohttp: pip install aiohttp")

        if not verify_ssl:
            cls._warn_ssl_disabled()

        timeout_obj = aiohttp.ClientTimeout(total=timeout or cls._default_timeout)
        connector = aiohttp.TCPConnector(
            limit=concurrency,
            ssl=verify_ssl
        )

        default_headers = {
            "User-Agent": cls._default_user_agent,
            **(headers or {})
        }

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_obj,
            headers=default_headers
        ) as session:
            yield session

    @classmethod
    def _warn_ssl_disabled(cls):
        """发出 SSL 禁用警告"""
        warnings.warn(
            "SSL 验证已禁用！可能存在中间人攻击风险。"
            "仅在测试环境或明确信任的网络中使用。",
            SecurityWarning,
            stacklevel=4
        )
        logger.warning("SSL 验证已禁用")

        # 禁用 urllib3 的 SSL 警告（避免噪音）
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    @classmethod
    def cleanup(cls):
        """清理所有客户端连接"""
        if cls._sync_session:
            try:
                cls._sync_session.close()
            except Exception as e:
                logger.warning(f"关闭同步 Session 失败: {e}")
            cls._sync_session = None
        logger.debug("HTTP 客户端已清理")

    @classmethod
    def configure(
        cls,
        default_timeout: Optional[int] = None,
        default_user_agent: Optional[str] = None,
        default_max_retries: Optional[int] = None
    ):
        """配置工厂默认参数

        Args:
            default_timeout: 默认超时时间
            default_user_agent: 默认 User-Agent
            default_max_retries: 默认最大重试次数
        """
        if default_timeout is not None:
            cls._default_timeout = default_timeout
        if default_user_agent is not None:
            cls._default_user_agent = default_user_agent
        if default_max_retries is not None:
            cls._default_max_retries = default_max_retries


# 便捷函数
def get_sync_client(**kwargs) -> requests.Session:
    """获取同步 HTTP 客户端的便捷函数"""
    return HTTPClientFactory.get_sync_client(**kwargs)


def get_async_client(**kwargs):
    """获取异步 HTTP 客户端的便捷函数"""
    return HTTPClientFactory.get_async_client(**kwargs)
