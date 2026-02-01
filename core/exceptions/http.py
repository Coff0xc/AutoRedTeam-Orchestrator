"""
AutoRedTeam-Orchestrator HTTP 异常

HTTP 请求相关的错误类型定义。
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import AutoRedTeamError


class HTTPError(AutoRedTeamError):
    """
    HTTP请求错误基类

    所有HTTP相关错误的父类，提供状态码和URL信息。

    属性:
        status_code: HTTP状态码（可选）
        url: 请求的URL（可选）
        method: HTTP方法（可选）
        response_body: 响应体片段（可选）
    """

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        url: Optional[str] = None,
        method: Optional[str] = None,
        response_body: Optional[str] = None,
        **kwargs: Any,
    ):
        """
        初始化HTTP错误

        参数:
            message: 错误消息
            status_code: HTTP响应状态码
            url: 请求的目标URL
            method: HTTP请求方法 (GET, POST等)
            response_body: 响应体的前N个字符（用于调试）
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.status_code = status_code
        self.url = url
        self.method = method
        self.response_body = response_body

        # 将HTTP特定信息添加到details
        if status_code is not None:
            self.details["status_code"] = status_code
        if url:
            self.details["url"] = url
        if method:
            self.details["method"] = method

    def to_dict(self) -> Dict[str, Any]:
        """扩展父类方法，添加HTTP特定字段"""
        result = super().to_dict()
        if self.status_code is not None:
            result["status_code"] = self.status_code
        if self.url:
            result["url"] = self.url
        return result


class ConnectionError(HTTPError):
    """
    连接错误

    当无法建立TCP连接、DNS解析失败、网络不可达时抛出。

    示例:
        >>> raise ConnectionError("无法连接到目标服务器", url="https://target.com")
        >>> raise ConnectionError("DNS解析失败", details={"hostname": "unknown.local"})
    """


class TimeoutError(HTTPError):
    """
    超时错误

    当请求超过预定时间未响应时抛出。

    属性:
        timeout: 超时时间设置（秒）
    """

    def __init__(self, message: str, timeout: Optional[float] = None, **kwargs: Any):
        """
        初始化超时错误

        参数:
            message: 错误消息
            timeout: 超时时间设置（秒）
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.timeout = timeout
        if timeout is not None:
            self.details["timeout"] = timeout


class SSLError(HTTPError):
    """
    SSL/TLS错误

    当SSL证书验证失败、TLS握手失败时抛出。

    示例:
        >>> raise SSLError("证书验证失败", url="https://self-signed.example.com")
        >>> raise SSLError("TLS版本不兼容", details={"supported": "TLSv1.2", "required": "TLSv1.3"})
    """


class ProxyError(HTTPError):
    """
    代理错误

    当代理连接失败、代理认证失败时抛出。

    属性:
        proxy_url: 代理服务器地址
    """

    def __init__(self, message: str, proxy_url: Optional[str] = None, **kwargs: Any):
        """
        初始化代理错误

        参数:
            message: 错误消息
            proxy_url: 代理服务器地址
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.proxy_url = proxy_url
        if proxy_url:
            self.details["proxy_url"] = proxy_url


# 向后兼容别名
NetworkError = HTTPError


__all__ = [
    "HTTPError",
    "ConnectionError",
    "TimeoutError",
    "SSLError",
    "ProxyError",
    # 向后兼容
    "NetworkError",
]
