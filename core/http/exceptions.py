"""
HTTP 相关异常定义

提供统一的 HTTP 层异常类型，便于精确捕获和处理网络错误
"""

from typing import Optional, Dict, Any


class HTTPError(Exception):
    """HTTP 基础异常类"""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        url: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        初始化 HTTP 异常

        Args:
            message: 错误消息
            status_code: HTTP 状态码 (可选)
            url: 请求的 URL (可选)
            details: 额外的错误详情 (可选)
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.url = url
        self.details = details or {}

    def __str__(self) -> str:
        parts = [self.message]
        if self.status_code:
            parts.insert(0, f"[{self.status_code}]")
        if self.url:
            parts.append(f"(URL: {self.url})")
        return " ".join(parts)

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"status_code={self.status_code}, "
            f"url={self.url!r})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式，便于 JSON 序列化"""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "status_code": self.status_code,
            "url": self.url,
            "details": self.details
        }


class TimeoutError(HTTPError):
    """请求超时异常"""

    def __init__(
        self,
        message: str = "请求超时",
        url: Optional[str] = None,
        timeout: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        初始化超时异常

        Args:
            message: 错误消息
            url: 请求的 URL
            timeout: 超时时间 (秒)
            details: 额外详情
        """
        _details = details or {}
        if timeout is not None:
            _details["timeout"] = timeout
        super().__init__(message=message, url=url, details=_details)
        self.timeout = timeout


class ConnectionError(HTTPError):
    """连接错误异常 - 无法建立连接"""

    def __init__(
        self,
        message: str = "连接失败",
        url: Optional[str] = None,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        初始化连接异常

        Args:
            message: 错误消息
            url: 请求的 URL
            reason: 失败原因
            details: 额外详情
        """
        _details = details or {}
        if reason:
            _details["reason"] = reason
        super().__init__(message=message, url=url, details=_details)
        self.reason = reason


class SSLError(HTTPError):
    """SSL/TLS 相关错误"""

    def __init__(
        self,
        message: str = "SSL 验证失败",
        url: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message=message, url=url, details=details)


class ProxyError(HTTPError):
    """代理相关错误"""

    def __init__(
        self,
        message: str = "代理连接失败",
        url: Optional[str] = None,
        proxy: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        初始化代理异常

        Args:
            message: 错误消息
            url: 请求的 URL
            proxy: 代理地址
            details: 额外详情
        """
        _details = details or {}
        if proxy:
            _details["proxy"] = proxy
        super().__init__(message=message, url=url, details=_details)
        self.proxy = proxy


class RedirectError(HTTPError):
    """重定向相关错误 - 超过最大重定向次数或循环重定向"""

    def __init__(
        self,
        message: str = "重定向错误",
        url: Optional[str] = None,
        redirect_count: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        _details = details or {}
        if redirect_count is not None:
            _details["redirect_count"] = redirect_count
        super().__init__(message=message, url=url, details=_details)
        self.redirect_count = redirect_count


class RequestError(HTTPError):
    """通用请求错误 - 请求构建或发送失败"""

    def __init__(
        self,
        message: str = "请求失败",
        url: Optional[str] = None,
        method: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        _details = details or {}
        if method:
            _details["method"] = method
        super().__init__(message=message, url=url, details=_details)
        self.method = method


class ResponseError(HTTPError):
    """响应处理错误 - 响应解析失败、格式错误等"""

    def __init__(
        self,
        message: str = "响应处理失败",
        status_code: Optional[int] = None,
        url: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            status_code=status_code,
            url=url,
            details=details
        )


class RateLimitError(HTTPError):
    """速率限制错误 - 请求被限流"""

    def __init__(
        self,
        message: str = "请求被限流",
        url: Optional[str] = None,
        retry_after: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        初始化限流异常

        Args:
            message: 错误消息
            url: 请求的 URL
            retry_after: 建议的重试等待时间 (秒)
            details: 额外详情
        """
        _details = details or {}
        if retry_after is not None:
            _details["retry_after"] = retry_after
        super().__init__(message=message, status_code=429, url=url, details=_details)
        self.retry_after = retry_after


class AuthenticationError(HTTPError):
    """认证错误 - 401/403 等认证相关失败"""

    def __init__(
        self,
        message: str = "认证失败",
        status_code: Optional[int] = None,
        url: Optional[str] = None,
        auth_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        初始化认证异常

        Args:
            message: 错误消息
            status_code: HTTP 状态码 (通常为 401 或 403)
            url: 请求的 URL
            auth_type: 认证类型 (如 Bearer, Basic)
            details: 额外详情
        """
        _details = details or {}
        if auth_type:
            _details["auth_type"] = auth_type
        super().__init__(
            message=message,
            status_code=status_code or 401,
            url=url,
            details=_details
        )
        self.auth_type = auth_type


class ServerError(HTTPError):
    """服务器错误 - 5xx 系列错误"""

    def __init__(
        self,
        message: str = "服务器错误",
        status_code: Optional[int] = None,
        url: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            status_code=status_code or 500,
            url=url,
            details=details
        )


class ClientError(HTTPError):
    """客户端错误 - 4xx 系列错误 (除 401/403/429)"""

    def __init__(
        self,
        message: str = "客户端错误",
        status_code: Optional[int] = None,
        url: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            status_code=status_code or 400,
            url=url,
            details=details
        )


# 异常类型映射 - 用于从状态码创建对应的异常
STATUS_CODE_EXCEPTIONS: Dict[int, type] = {
    401: AuthenticationError,
    403: AuthenticationError,
    429: RateLimitError,
    500: ServerError,
    502: ServerError,
    503: ServerError,
    504: ServerError,
}


def exception_from_status_code(
    status_code: int,
    message: Optional[str] = None,
    url: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> HTTPError:
    """
    根据 HTTP 状态码创建对应的异常

    Args:
        status_code: HTTP 状态码
        message: 自定义错误消息
        url: 请求的 URL
        details: 额外详情

    Returns:
        对应的 HTTPError 子类实例
    """
    # 检查特定状态码
    exc_class = STATUS_CODE_EXCEPTIONS.get(status_code)

    if exc_class:
        # RateLimitError 不接受 status_code 参数（固定为 429）
        if exc_class == RateLimitError:
            return exc_class(
                message=message or f"HTTP {status_code}",
                url=url,
                details=details
            )
        # 其他异常类正常传递 status_code
        return exc_class(
            message=message or f"HTTP {status_code}",
            status_code=status_code,
            url=url,
            details=details
        )

    # 按状态码范围判断
    if 400 <= status_code < 500:
        return ClientError(
            message=message or f"客户端错误 {status_code}",
            status_code=status_code,
            url=url,
            details=details
        )
    elif status_code >= 500:
        return ServerError(
            message=message or f"服务器错误 {status_code}",
            status_code=status_code,
            url=url,
            details=details
        )

    # 默认返回基础异常
    return HTTPError(
        message=message or f"HTTP 错误 {status_code}",
        status_code=status_code,
        url=url,
        details=details
    )


__all__ = [
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
]
