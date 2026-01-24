"""
HTTP 客户端配置

提供灵活的配置选项，支持超时、重试、代理、连接池等设置
支持从环境变量和配置文件加载
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple, Any, List
from enum import Enum

logger = logging.getLogger(__name__)


class RetryStrategy(Enum):
    """重试策略"""
    NONE = "none"           # 不重试
    FIXED = "fixed"         # 固定间隔重试
    EXPONENTIAL = "exponential"  # 指数退避重试
    JITTER = "jitter"       # 带抖动的指数退避


@dataclass
class RetryConfig:
    """重试配置"""
    max_retries: int = 3
    retry_delay: float = 1.0  # 基础重试延迟 (秒)
    max_delay: float = 30.0   # 最大重试延迟 (秒)
    backoff_factor: float = 2.0  # 指数退避因子
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL

    # 需要重试的状态码
    retry_status_codes: Tuple[int, ...] = (
        408,  # Request Timeout
        429,  # Too Many Requests
        500,  # Internal Server Error
        502,  # Bad Gateway
        503,  # Service Unavailable
        504,  # Gateway Timeout
    )

    # 需要重试的异常类型名称
    retry_exceptions: Tuple[str, ...] = (
        "TimeoutException",
        "ConnectError",
        "ReadTimeout",
        "ConnectTimeout",
    )

    def calculate_delay(self, attempt: int) -> float:
        """
        计算第 N 次重试的延迟时间

        Args:
            attempt: 当前重试次数 (从 1 开始)

        Returns:
            延迟时间 (秒)
        """
        if self.strategy == RetryStrategy.NONE:
            return 0

        if self.strategy == RetryStrategy.FIXED:
            return self.retry_delay

        # 指数退避
        delay = self.retry_delay * (self.backoff_factor ** (attempt - 1))

        # 添加抖动
        if self.strategy == RetryStrategy.JITTER:
            import random
            delay = delay * (0.5 + random.random())

        return min(delay, self.max_delay)


@dataclass
class ProxyConfig:
    """代理配置"""
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    socks_proxy: Optional[str] = None
    no_proxy: List[str] = field(default_factory=list)

    # 代理认证
    proxy_auth: Optional[Tuple[str, str]] = None  # (username, password)

    @classmethod
    def from_env(cls) -> "ProxyConfig":
        """从环境变量加载代理配置"""
        return cls(
            http_proxy=os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"),
            https_proxy=os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy"),
            socks_proxy=os.environ.get("SOCKS_PROXY") or os.environ.get("socks_proxy"),
            no_proxy=[
                x.strip()
                for x in (
                    os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
                ).split(",")
                if x.strip()
            ],
        )

    def to_dict(self) -> Dict[str, str]:
        """转换为 httpx 代理配置格式"""
        proxies: Dict[str, str] = {}
        if self.http_proxy:
            proxies["http://"] = self.http_proxy
        if self.https_proxy:
            proxies["https://"] = self.https_proxy
        if self.socks_proxy:
            # SOCKS 代理同时用于 HTTP 和 HTTPS
            if not self.http_proxy:
                proxies["http://"] = self.socks_proxy
            if not self.https_proxy:
                proxies["https://"] = self.socks_proxy
        return proxies


@dataclass
class PoolConfig:
    """连接池配置"""
    max_connections: int = 100       # 最大连接数
    max_keepalive: int = 20          # 最大保持连接数
    keepalive_timeout: float = 5.0   # 保持连接超时 (秒)
    http2: bool = False              # 是否启用 HTTP/2


@dataclass
class HTTPConfig:
    """HTTP 客户端统一配置"""

    # 超时配置 (秒)
    timeout: float = 30.0            # 总超时
    connect_timeout: float = 10.0    # 连接超时
    read_timeout: float = 30.0       # 读取超时
    write_timeout: float = 30.0      # 写入超时

    # SSL 配置
    verify_ssl: bool = True          # 是否验证 SSL 证书
    ssl_cert: Optional[str] = None   # 客户端证书路径
    ssl_key: Optional[str] = None    # 客户端私钥路径

    # 重定向配置
    follow_redirects: bool = True    # 是否跟随重定向
    max_redirects: int = 10          # 最大重定向次数

    # 默认请求头
    default_headers: Dict[str, str] = field(default_factory=lambda: {
        "User-Agent": "AutoRedTeam/3.0",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })

    # 子配置
    retry: RetryConfig = field(default_factory=RetryConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    pool: PoolConfig = field(default_factory=PoolConfig)

    # 调试选项
    debug: bool = False              # 调试模式
    log_requests: bool = False       # 记录请求日志
    log_responses: bool = False      # 记录响应日志

    def get_timeout_tuple(self) -> Tuple[float, float, float, float]:
        """
        获取超时配置元组

        Returns:
            (connect_timeout, read_timeout, write_timeout, pool_timeout)
        """
        return (
            self.connect_timeout,
            self.read_timeout,
            self.write_timeout,
            self.timeout,
        )

    def merge_headers(self, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        合并默认请求头和自定义请求头

        Args:
            headers: 自定义请求头

        Returns:
            合并后的请求头
        """
        merged = self.default_headers.copy()
        if headers:
            merged.update(headers)
        return merged

    def set_user_agent(self, user_agent: str) -> None:
        """设置 User-Agent"""
        self.default_headers["User-Agent"] = user_agent

    def set_proxy(self, proxy: str) -> None:
        """
        设置统一代理

        Args:
            proxy: 代理地址 (如 http://127.0.0.1:8080)
        """
        if proxy.startswith("socks"):
            self.proxy.socks_proxy = proxy
        else:
            self.proxy.http_proxy = proxy
            self.proxy.https_proxy = proxy

    @classmethod
    def from_env(cls) -> "HTTPConfig":
        """
        从环境变量加载配置

        支持的环境变量:
        - HTTP_TIMEOUT: 总超时时间
        - HTTP_CONNECT_TIMEOUT: 连接超时
        - HTTP_READ_TIMEOUT: 读取超时
        - HTTP_VERIFY_SSL: 是否验证 SSL (true/false)
        - HTTP_MAX_RETRIES: 最大重试次数
        - HTTP_USER_AGENT: User-Agent
        - HTTP_DEBUG: 调试模式 (true/false)
        - HTTP_PROXY / HTTPS_PROXY: 代理配置
        """
        config = cls()

        # 超时配置
        if timeout := os.environ.get("HTTP_TIMEOUT"):
            config.timeout = float(timeout)
        if connect_timeout := os.environ.get("HTTP_CONNECT_TIMEOUT"):
            config.connect_timeout = float(connect_timeout)
        if read_timeout := os.environ.get("HTTP_READ_TIMEOUT"):
            config.read_timeout = float(read_timeout)

        # SSL 配置
        if verify_ssl := os.environ.get("HTTP_VERIFY_SSL"):
            config.verify_ssl = verify_ssl.lower() in ("true", "1", "yes")

        # 重试配置
        if max_retries := os.environ.get("HTTP_MAX_RETRIES"):
            config.retry.max_retries = int(max_retries)

        # User-Agent
        if user_agent := os.environ.get("HTTP_USER_AGENT"):
            config.set_user_agent(user_agent)

        # 调试模式
        if debug := os.environ.get("HTTP_DEBUG"):
            config.debug = debug.lower() in ("true", "1", "yes")
            config.log_requests = config.debug
            config.log_responses = config.debug

        # 代理配置
        config.proxy = ProxyConfig.from_env()

        logger.debug(f"从环境变量加载 HTTP 配置: timeout={config.timeout}, "
                     f"verify_ssl={config.verify_ssl}, debug={config.debug}")

        return config

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HTTPConfig":
        """
        从字典加载配置

        Args:
            data: 配置字典

        Returns:
            HTTPConfig 实例
        """
        config = cls()

        # 基础配置
        if "timeout" in data:
            config.timeout = float(data["timeout"])
        if "connect_timeout" in data:
            config.connect_timeout = float(data["connect_timeout"])
        if "read_timeout" in data:
            config.read_timeout = float(data["read_timeout"])
        if "write_timeout" in data:
            config.write_timeout = float(data["write_timeout"])
        if "verify_ssl" in data:
            config.verify_ssl = bool(data["verify_ssl"])
        if "follow_redirects" in data:
            config.follow_redirects = bool(data["follow_redirects"])
        if "max_redirects" in data:
            config.max_redirects = int(data["max_redirects"])

        # 请求头
        if "headers" in data:
            config.default_headers.update(data["headers"])

        # 重试配置
        if "retry" in data:
            retry_data = data["retry"]
            if "max_retries" in retry_data:
                config.retry.max_retries = int(retry_data["max_retries"])
            if "retry_delay" in retry_data:
                config.retry.retry_delay = float(retry_data["retry_delay"])
            if "strategy" in retry_data:
                config.retry.strategy = RetryStrategy(retry_data["strategy"])

        # 代理配置
        if "proxy" in data:
            proxy_data = data["proxy"]
            if isinstance(proxy_data, str):
                config.set_proxy(proxy_data)
            elif isinstance(proxy_data, dict):
                config.proxy.http_proxy = proxy_data.get("http")
                config.proxy.https_proxy = proxy_data.get("https")
                config.proxy.socks_proxy = proxy_data.get("socks")

        # 连接池配置
        if "pool" in data:
            pool_data = data["pool"]
            if "max_connections" in pool_data:
                config.pool.max_connections = int(pool_data["max_connections"])
            if "max_keepalive" in pool_data:
                config.pool.max_keepalive = int(pool_data["max_keepalive"])

        return config

    def to_dict(self) -> Dict[str, Any]:
        """导出为字典"""
        return {
            "timeout": self.timeout,
            "connect_timeout": self.connect_timeout,
            "read_timeout": self.read_timeout,
            "write_timeout": self.write_timeout,
            "verify_ssl": self.verify_ssl,
            "follow_redirects": self.follow_redirects,
            "max_redirects": self.max_redirects,
            "headers": self.default_headers.copy(),
            "retry": {
                "max_retries": self.retry.max_retries,
                "retry_delay": self.retry.retry_delay,
                "strategy": self.retry.strategy.value,
            },
            "proxy": {
                "http": self.proxy.http_proxy,
                "https": self.proxy.https_proxy,
                "socks": self.proxy.socks_proxy,
            },
            "pool": {
                "max_connections": self.pool.max_connections,
                "max_keepalive": self.pool.max_keepalive,
            },
            "debug": self.debug,
        }

    def copy(self) -> "HTTPConfig":
        """创建配置副本"""
        import copy
        return copy.deepcopy(self)


# 预定义配置模板
class ConfigPresets:
    """预定义配置模板"""

    @staticmethod
    def fast() -> HTTPConfig:
        """快速请求配置 - 短超时，少重试"""
        config = HTTPConfig()
        config.timeout = 10.0
        config.connect_timeout = 5.0
        config.read_timeout = 10.0
        config.retry.max_retries = 1
        return config

    @staticmethod
    def robust() -> HTTPConfig:
        """健壮请求配置 - 长超时，多重试"""
        config = HTTPConfig()
        config.timeout = 60.0
        config.connect_timeout = 15.0
        config.read_timeout = 60.0
        config.retry.max_retries = 5
        config.retry.strategy = RetryStrategy.EXPONENTIAL
        return config

    @staticmethod
    def stealth() -> HTTPConfig:
        """隐蔽请求配置 - 模拟真实浏览器"""
        config = HTTPConfig()
        config.default_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;"
                "q=0.9,image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }
        return config

    @staticmethod
    def api() -> HTTPConfig:
        """API 请求配置"""
        config = HTTPConfig()
        config.default_headers = {
            "User-Agent": "AutoRedTeam/3.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip, deflate",
        }
        return config

    @staticmethod
    def debug() -> HTTPConfig:
        """调试配置"""
        config = HTTPConfig()
        config.debug = True
        config.log_requests = True
        config.log_responses = True
        config.verify_ssl = False
        return config


__all__ = [
    "HTTPConfig",
    "RetryConfig",
    "RetryStrategy",
    "ProxyConfig",
    "PoolConfig",
    "ConfigPresets",
]
