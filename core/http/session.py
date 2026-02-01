"""
HTTP 会话管理

提供会话级别的状态管理，包括 Cookie、认证、请求头等
支持同步和异步操作
"""

import base64
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


class AuthType(Enum):
    """认证类型"""

    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    API_KEY = "api_key"
    DIGEST = "digest"
    CUSTOM = "custom"


@dataclass
class AuthConfig:
    """认证配置"""

    auth_type: AuthType = AuthType.NONE

    # Basic 认证
    username: Optional[str] = None
    password: Optional[str] = None

    # Bearer Token
    token: Optional[str] = None
    token_prefix: str = "Bearer"

    # API Key
    api_key: Optional[str] = None
    api_key_header: str = "X-API-Key"
    api_key_query: Optional[str] = None  # 如果设置，则通过查询参数传递

    # 自定义认证头
    custom_header: Optional[str] = None
    custom_value: Optional[str] = None

    def get_auth_header(self) -> Optional[Dict[str, str]]:
        """
        获取认证请求头

        Returns:
            认证请求头字典，如果没有认证则返回 None
        """
        if self.auth_type == AuthType.NONE:
            return None

        if self.auth_type == AuthType.BASIC:
            if self.username and self.password:
                credentials = base64.b64encode(
                    f"{self.username}:{self.password}".encode("utf-8")
                ).decode("utf-8")
                return {"Authorization": f"Basic {credentials}"}

        elif self.auth_type == AuthType.BEARER:
            if self.token:
                return {"Authorization": f"{self.token_prefix} {self.token}"}

        elif self.auth_type == AuthType.API_KEY:
            if self.api_key and not self.api_key_query:
                return {self.api_key_header: self.api_key}

        elif self.auth_type == AuthType.CUSTOM:
            if self.custom_header and self.custom_value:
                return {self.custom_header: self.custom_value}

        return None

    def get_auth_params(self) -> Optional[Dict[str, str]]:
        """
        获取认证查询参数

        Returns:
            认证查询参数字典
        """
        if self.auth_type == AuthType.API_KEY and self.api_key_query and self.api_key:
            return {self.api_key_query: self.api_key}
        return None


@dataclass
class Cookie:
    """Cookie 对象"""

    name: str
    value: str
    domain: Optional[str] = None
    path: str = "/"
    expires: Optional[float] = None  # Unix 时间戳
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None

    def is_expired(self) -> bool:
        """检查 Cookie 是否已过期"""
        if self.expires is None:
            return False
        return time.time() > self.expires

    def to_header_value(self) -> str:
        """转换为请求头格式"""
        return f"{self.name}={self.value}"

    @classmethod
    def from_set_cookie(cls, header_value: str, domain: str = "") -> "Cookie":
        """
        从 Set-Cookie 头解析 Cookie

        Args:
            header_value: Set-Cookie 头的值
            domain: 默认域名

        Returns:
            Cookie 对象
        """
        parts = header_value.split(";")
        if not parts:
            raise ValueError("Invalid Set-Cookie header")

        # 解析名称和值
        name_value = parts[0].strip()
        if "=" not in name_value:
            raise ValueError("Invalid cookie name=value")

        name, value = name_value.split("=", 1)

        cookie = cls(name=name.strip(), value=value.strip(), domain=domain)

        # 解析其他属性
        for part in parts[1:]:
            part = part.strip().lower()
            if part.startswith("domain="):
                cookie.domain = part[7:]
            elif part.startswith("path="):
                cookie.path = part[5:]
            elif part.startswith("expires="):
                # 简化处理，实际应该解析日期
                pass
            elif part.startswith("max-age="):
                try:
                    max_age = int(part[8:])
                    cookie.expires = time.time() + max_age
                except ValueError:
                    pass
            elif part == "secure":
                cookie.secure = True
            elif part == "httponly":
                cookie.http_only = True
            elif part.startswith("samesite="):
                cookie.same_site = part[9:]

        return cookie


class CookieJar:
    """Cookie 容器"""

    def __init__(self):
        self._cookies: Dict[str, Dict[str, Cookie]] = {}  # domain -> {name: Cookie}

    def set(self, cookie: Cookie) -> None:
        """添加或更新 Cookie"""
        domain = cookie.domain or ""
        if domain not in self._cookies:
            self._cookies[domain] = {}
        self._cookies[domain][cookie.name] = cookie

    def get(self, name: str, domain: Optional[str] = None) -> Optional[Cookie]:
        """获取 Cookie"""
        if domain:
            return self._cookies.get(domain, {}).get(name)
        # 搜索所有域名
        for cookies in self._cookies.values():
            if name in cookies:
                return cookies[name]
        return None

    def delete(self, name: str, domain: Optional[str] = None) -> bool:
        """删除 Cookie"""
        if domain:
            if domain in self._cookies and name in self._cookies[domain]:
                del self._cookies[domain][name]
                return True
            return False
        # 从所有域名删除
        deleted = False
        for cookies in self._cookies.values():
            if name in cookies:
                del cookies[name]
                deleted = True
        return deleted

    def clear(self, domain: Optional[str] = None) -> None:
        """清空 Cookie"""
        if domain:
            self._cookies.pop(domain, None)
        else:
            self._cookies.clear()

    def get_for_url(self, url: str) -> Dict[str, str]:
        """
        获取适用于指定 URL 的所有 Cookie

        Args:
            url: 请求的 URL

        Returns:
            Cookie 字典 {name: value}
        """
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path or "/"
        is_secure = parsed.scheme == "https"

        result: Dict[str, str] = {}

        for cookie_domain, cookies in self._cookies.items():
            # 检查域名匹配
            if cookie_domain and not (
                domain == cookie_domain or domain.endswith("." + cookie_domain)
            ):
                continue

            for cookie in cookies.values():
                # 检查过期
                if cookie.is_expired():
                    continue

                # 检查路径
                if not path.startswith(cookie.path):
                    continue

                # 检查 Secure
                if cookie.secure and not is_secure:
                    continue

                result[cookie.name] = cookie.value

        return result

    def get_header_value(self, url: str) -> Optional[str]:
        """
        获取 Cookie 请求头值

        Args:
            url: 请求的 URL

        Returns:
            Cookie 请求头值，如 "name1=value1; name2=value2"
        """
        cookies = self.get_for_url(url)
        if not cookies:
            return None
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    def update_from_response(self, url: str, headers: Dict[str, str]) -> None:
        """
        从响应头更新 Cookie

        Args:
            url: 请求的 URL
            headers: 响应头
        """
        parsed = urlparse(url)
        domain = parsed.netloc

        # 处理 Set-Cookie 头
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                try:
                    cookie = Cookie.from_set_cookie(value, domain)
                    self.set(cookie)
                except ValueError as e:
                    logger.debug(f"解析 Cookie 失败: {e}")

    def to_dict(self) -> Dict[str, str]:
        """导出所有 Cookie 为字典"""
        result: Dict[str, str] = {}
        for cookies in self._cookies.values():
            for cookie in cookies.values():
                if not cookie.is_expired():
                    result[cookie.name] = cookie.value
        return result

    def __len__(self) -> int:
        return sum(len(cookies) for cookies in self._cookies.values())

    def __repr__(self) -> str:
        return f"CookieJar({len(self)} cookies)"


class HTTPSession:
    """HTTP 会话 - 保持 Cookie 和认证状态"""

    def __init__(
        self,
        base_url: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[AuthConfig] = None,
        timeout: float = 30.0,
    ):
        """
        初始化 HTTP 会话

        Args:
            base_url: 基础 URL，后续请求可以使用相对路径
            headers: 默认请求头
            auth: 认证配置
            timeout: 默认超时时间
        """
        self.base_url = base_url.rstrip("/") if base_url else None
        self.headers: Dict[str, str] = headers or {}
        self.auth = auth or AuthConfig()
        self.timeout = timeout
        self.cookies = CookieJar()

        # 会话元数据
        self._created_at = time.time()
        self._request_count = 0

        # 延迟导入客户端
        self._client: Optional[Any] = None
        self._async_client: Optional[Any] = None

    def set_auth(self, auth_type: str, **kwargs) -> None:
        """
        设置认证方式

        Args:
            auth_type: 认证类型 (basic/bearer/api_key/custom)
            **kwargs: 认证参数

        Examples:
            session.set_auth("basic", username="user", password="pass")
            session.set_auth("bearer", token="xxx")
            session.set_auth("api_key", api_key="xxx", header="X-API-Key")
        """
        auth_type_enum = AuthType(auth_type.lower())
        self.auth = AuthConfig(auth_type=auth_type_enum, **kwargs)

    def set_bearer_token(self, token: str, prefix: str = "Bearer") -> None:
        """设置 Bearer Token"""
        self.auth = AuthConfig(auth_type=AuthType.BEARER, token=token, token_prefix=prefix)

    def set_basic_auth(self, username: str, password: str) -> None:
        """设置 Basic 认证"""
        self.auth = AuthConfig(auth_type=AuthType.BASIC, username=username, password=password)

    def set_api_key(
        self, api_key: str, header: str = "X-API-Key", query_param: Optional[str] = None
    ) -> None:
        """设置 API Key 认证"""
        self.auth = AuthConfig(
            auth_type=AuthType.API_KEY,
            api_key=api_key,
            api_key_header=header,
            api_key_query=query_param,
        )

    def set_header(self, name: str, value: str) -> None:
        """设置请求头"""
        self.headers[name] = value

    def set_cookie(self, name: str, value: str, domain: Optional[str] = None) -> None:
        """设置 Cookie"""
        cookie = Cookie(name=name, value=value, domain=domain)
        self.cookies.set(cookie)

    def get_cookie(self, name: str) -> Optional[str]:
        """获取 Cookie 值"""
        cookie = self.cookies.get(name)
        return cookie.value if cookie else None

    def clear_cookies(self) -> None:
        """清空所有 Cookie"""
        self.cookies.clear()

    def build_url(self, path: str) -> str:
        """
        构建完整 URL

        Args:
            path: 路径或完整 URL

        Returns:
            完整 URL
        """
        if path.startswith(("http://", "https://")):
            return path
        if self.base_url:
            return urljoin(self.base_url + "/", path.lstrip("/"))
        return path

    def build_headers(self, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        构建完整请求头

        Args:
            extra_headers: 额外的请求头

        Returns:
            合并后的请求头
        """
        headers = self.headers.copy()

        # 添加认证头
        auth_headers = self.auth.get_auth_header()
        if auth_headers:
            headers.update(auth_headers)

        # 添加额外请求头
        if extra_headers:
            headers.update(extra_headers)

        return headers

    def build_params(self, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        构建查询参数

        Args:
            params: 请求参数

        Returns:
            合并后的参数
        """
        result = params.copy() if params else {}

        # 添加 API Key 查询参数
        auth_params = self.auth.get_auth_params()
        if auth_params:
            result.update(auth_params)

        return result if result else None

    def _get_client(self):
        """获取或创建 HTTP 客户端"""
        if self._client is None:
            from .client import HTTPClient
            from .config import HTTPConfig

            config = HTTPConfig()
            config.timeout = self.timeout
            self._client = HTTPClient(config=config)
        return self._client

    async def _get_async_client(self):
        """获取或创建异步 HTTP 客户端"""
        if self._async_client is None:
            from .client import HTTPClient
            from .config import HTTPConfig

            config = HTTPConfig()
            config.timeout = self.timeout
            self._async_client = HTTPClient(config=config)
        return self._async_client

    def request(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        **kwargs,
    ):
        """
        发送同步请求

        Args:
            method: HTTP 方法
            path: 请求路径或完整 URL
            headers: 额外请求头
            params: 查询参数
            data: 表单数据
            json: JSON 数据
            **kwargs: 其他参数

        Returns:
            HTTPResponse 对象
        """
        url = self.build_url(path)
        merged_headers = self.build_headers(headers)
        merged_params = self.build_params(params)

        # 添加 Cookie
        cookie_header = self.cookies.get_header_value(url)
        if cookie_header:
            merged_headers["Cookie"] = cookie_header

        client = self._get_client()
        response = client.request(
            method=method,
            url=url,
            headers=merged_headers,
            params=merged_params,
            data=data,
            json=json,
            **kwargs,
        )

        # 更新 Cookie
        self.cookies.update_from_response(url, response.headers)
        self._request_count += 1

        return response

    async def async_request(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        **kwargs,
    ):
        """
        发送异步请求

        Args:
            method: HTTP 方法
            path: 请求路径或完整 URL
            headers: 额外请求头
            params: 查询参数
            data: 表单数据
            json: JSON 数据
            **kwargs: 其他参数

        Returns:
            HTTPResponse 对象
        """
        url = self.build_url(path)
        merged_headers = self.build_headers(headers)
        merged_params = self.build_params(params)

        # 添加 Cookie
        cookie_header = self.cookies.get_header_value(url)
        if cookie_header:
            merged_headers["Cookie"] = cookie_header

        client = await self._get_async_client()
        response = await client.async_request(
            method=method,
            url=url,
            headers=merged_headers,
            params=merged_params,
            data=data,
            json=json,
            **kwargs,
        )

        # 更新 Cookie
        self.cookies.update_from_response(url, response.headers)
        self._request_count += 1

        return response

    # 便捷方法
    def get(self, path: str, **kwargs):
        """发送 GET 请求"""
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs):
        """发送 POST 请求"""
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs):
        """发送 PUT 请求"""
        return self.request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs):
        """发送 PATCH 请求"""
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs):
        """发送 DELETE 请求"""
        return self.request("DELETE", path, **kwargs)

    def head(self, path: str, **kwargs):
        """发送 HEAD 请求"""
        return self.request("HEAD", path, **kwargs)

    def options(self, path: str, **kwargs):
        """发送 OPTIONS 请求"""
        return self.request("OPTIONS", path, **kwargs)

    # 异步便捷方法
    async def async_get(self, path: str, **kwargs):
        """发送异步 GET 请求"""
        return await self.async_request("GET", path, **kwargs)

    async def async_post(self, path: str, **kwargs):
        """发送异步 POST 请求"""
        return await self.async_request("POST", path, **kwargs)

    async def async_put(self, path: str, **kwargs):
        """发送异步 PUT 请求"""
        return await self.async_request("PUT", path, **kwargs)

    async def async_patch(self, path: str, **kwargs):
        """发送异步 PATCH 请求"""
        return await self.async_request("PATCH", path, **kwargs)

    async def async_delete(self, path: str, **kwargs):
        """发送异步 DELETE 请求"""
        return await self.async_request("DELETE", path, **kwargs)

    def close(self) -> None:
        """关闭会话"""
        if self._client:
            self._client.close()
            self._client = None

    async def aclose(self) -> None:
        """异步关闭会话"""
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.aclose()

    def get_stats(self) -> Dict[str, Any]:
        """获取会话统计信息"""
        return {
            "base_url": self.base_url,
            "created_at": self._created_at,
            "request_count": self._request_count,
            "cookie_count": len(self.cookies),
            "auth_type": self.auth.auth_type.value,
            "uptime": time.time() - self._created_at,
        }

    def __repr__(self) -> str:
        return (
            f"HTTPSession(base_url={self.base_url!r}, "
            f"requests={self._request_count}, "
            f"cookies={len(self.cookies)})"
        )


__all__ = [
    "HTTPSession",
    "AuthType",
    "AuthConfig",
    "Cookie",
    "CookieJar",
]
