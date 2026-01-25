#!/usr/bin/env python3
"""
HTTP 会话管理器 - 支持登录态测试

迁移自 core/session_manager.py，用于集中管理 HTTP 认证会话。
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import requests
    from core.http.client_factory import HTTPClientFactory
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger(__name__)


@dataclass
class AuthContext:
    """认证上下文"""

    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)
    login_url: str = ""
    is_authenticated: bool = False


class HTTPSessionManager:
    """
    HTTP 会话管理器 - 支持登录态测试
    管理 Cookie、Token、认证状态
    """

    # 常见 CSRF Token 字段名
    CSRF_PATTERNS = [
        r'name=["\']?csrf[_-]?token["\']?\s+value=["\']([^"\']+)["\']',
        r'name=["\']?_token["\']?\s+value=["\']([^"\']+)["\']',
        r'name=["\']?csrfmiddlewaretoken["\']?\s+value=["\']([^"\']+)["\']',
        r'name=["\']?authenticity_token["\']?\s+value=["\']([^"\']+)["\']',
        r'name=["\']?__RequestVerificationToken["\']?\s+value=["\']([^"\']+)["\']',
    ]

    def __init__(self):
        self._sessions: Dict[str, "requests.Session"] = {}
        self._auth_contexts: Dict[str, AuthContext] = {}
        self._request_count: Dict[str, int] = {}

    def create_session(self, session_id: str = None, verify_ssl: bool = True) -> str:
        """
        创建 HTTP 会话

        Args:
            session_id: 会话 ID（可选，自动生成）
            verify_ssl: 是否验证 SSL 证书（默认启用）

        Returns:
            session_id
        """
        if not HAS_REQUESTS:
            raise RuntimeError("requests 库未安装")

        session_id = session_id or str(uuid.uuid4())[:8]

        sess = HTTPClientFactory.get_sync_client(
            verify_ssl=verify_ssl,
            force_new=True  # 每个会话独立
        )
        sess.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })

        self._sessions[session_id] = sess
        self._auth_contexts[session_id] = AuthContext()
        self._request_count[session_id] = 0

        logger.info("HTTP 会话已创建: %s", session_id)
        return session_id

    def get_session(self, session_id: str) -> Optional["requests.Session"]:
        """获取 HTTP 会话"""
        return self._sessions.get(session_id)

    def login(
        self,
        session_id: str,
        login_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        extra_data: Dict = None
    ) -> Dict:
        """
        执行登录

        Args:
            session_id: 会话 ID
            login_url: 登录 URL
            username: 用户名
            password: 密码
            username_field: 用户名字段名
            password_field: 密码字段名
            extra_data: 额外表单数据

        Returns:
            登录结果
        """
        sess = self._sessions.get(session_id)
        if not sess:
            return {"success": False, "error": f"会话不存在: {session_id}"}

        auth_ctx = self._auth_contexts[session_id]

        try:
            # 1. 先 GET 登录页面获取 CSRF Token
            resp = sess.get(login_url, timeout=10)
            csrf_token = self._extract_csrf_token(resp.text)

            # 2. 构建登录数据
            login_data = {
                username_field: username,
                password_field: password,
            }

            if csrf_token:
                # 尝试常见的 CSRF 字段名
                for field_name in ["csrf_token", "_token", "csrfmiddlewaretoken", "authenticity_token"]:
                    if field_name in resp.text:
                        login_data[field_name] = csrf_token
                        break
                else:
                    login_data["csrf_token"] = csrf_token

            if extra_data:
                login_data.update(extra_data)

            # 3. 发送登录请求
            login_resp = sess.post(login_url, data=login_data, timeout=10, allow_redirects=True)

            # 4. 判断登录是否成功
            is_success = self._check_login_success(login_resp, sess)

            if is_success:
                auth_ctx.is_authenticated = True
                auth_ctx.login_url = login_url
                auth_ctx.cookies = dict(sess.cookies)

                # 提取可能的 Token
                self._extract_tokens(session_id, login_resp)

                logger.info("会话 %s 登录成功", session_id)
                return {
                    "success": True,
                    "session_id": session_id,
                    "cookies": dict(sess.cookies),
                    "tokens": auth_ctx.tokens,
                }
            return {
                "success": False,
                "error": "登录失败，请检查凭据",
                "status_code": login_resp.status_code,
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def _extract_csrf_token(self, html: str) -> Optional[str]:
        """从 HTML 中提取 CSRF Token"""
        for pattern in self.CSRF_PATTERNS:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _extract_tokens(self, session_id: str, resp: "requests.Response") -> None:
        """提取各种 Token"""
        auth_ctx = self._auth_contexts[session_id]

        # 从响应头提取
        for header in ["Authorization", "X-CSRF-Token", "X-Auth-Token"]:
            if header in resp.headers:
                auth_ctx.tokens[header] = resp.headers[header]
                auth_ctx.headers[header] = resp.headers[header]

        # 从 Cookie 提取 JWT
        for cookie_name in ["jwt", "token", "access_token", "auth_token"]:
            if cookie_name in resp.cookies:
                auth_ctx.tokens[cookie_name] = resp.cookies[cookie_name]

    def _check_login_success(self, resp: "requests.Response", sess: "requests.Session") -> bool:
        """判断登录是否成功"""
        # 检查常见的失败标志
        fail_indicators = [
            "登录失败", "login failed", "invalid", "incorrect",
            "wrong password", "用户名或密码错误", "authentication failed"
        ]
        for indicator in fail_indicators:
            if indicator.lower() in resp.text.lower():
                return False

        # 检查是否有认证 Cookie
        auth_cookies = ["session", "sessionid", "PHPSESSID", "JSESSIONID", "token", "auth"]
        for cookie_name in auth_cookies:
            if any(cookie_name.lower() in c.lower() for c in sess.cookies.keys()):
                return True

        # 检查状态码
        if resp.status_code in (200, 302) and len(sess.cookies) > 0:
            return True

        return False

    def request(
        self,
        session_id: str,
        url: str,
        method: str = "GET",
        data: Dict = None,
        headers: Dict = None,
        **kwargs
    ) -> Dict:
        """
        发送带会话的 HTTP 请求

        Args:
            session_id: 会话 ID
            url: 请求 URL
            method: HTTP 方法
            data: 请求数据
            headers: 额外请求头

        Returns:
            响应结果
        """
        sess = self._sessions.get(session_id)
        if not sess:
            return {"success": False, "error": f"会话不存在: {session_id}"}

        auth_ctx = self._auth_contexts[session_id]

        try:
            # 合并认证头
            req_headers = {**auth_ctx.headers}
            if headers:
                req_headers.update(headers)

            # 发送请求
            resp = sess.request(
                method=method.upper(),
                url=url,
                data=data,
                headers=req_headers,
                timeout=kwargs.get("timeout", 10),
                allow_redirects=kwargs.get("allow_redirects", True)
            )

            self._request_count[session_id] = self._request_count.get(session_id, 0) + 1

            return {
                "success": True,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "cookies": dict(resp.cookies),
                "content_length": len(resp.content),
                "content_preview": resp.text[:500] if resp.text else "",
                "url": resp.url,
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def get_context(self, session_id: str) -> Dict:
        """获取会话上下文"""
        sess = self._sessions.get(session_id)
        auth_ctx = self._auth_contexts.get(session_id)

        if not sess or not auth_ctx:
            return {"error": f"会话不存在: {session_id}"}

        return {
            "session_id": session_id,
            "is_authenticated": auth_ctx.is_authenticated,
            "cookies": dict(sess.cookies),
            "headers": auth_ctx.headers,
            "tokens": auth_ctx.tokens,
            "request_count": self._request_count.get(session_id, 0),
        }

    def close_session(self, session_id: str) -> None:
        """关闭会话"""
        if session_id in self._sessions:
            self._sessions[session_id].close()
            del self._sessions[session_id]
            del self._auth_contexts[session_id]
            logger.info("HTTP 会话已关闭: %s", session_id)

    def list_sessions(self) -> List[Dict]:
        """列出所有 HTTP 会话"""
        return [
            {
                "session_id": sid,
                "is_authenticated": self._auth_contexts[sid].is_authenticated,
                "request_count": self._request_count.get(sid, 0),
            }
            for sid in self._sessions.keys()
        ]


# 全局 HTTP 会话管理器实例
_http_session_manager: Optional[HTTPSessionManager] = None


def get_http_session_manager() -> HTTPSessionManager:
    """获取全局 HTTP 会话管理器"""
    global _http_session_manager
    if _http_session_manager is None:
        _http_session_manager = HTTPSessionManager()
    return _http_session_manager


__all__ = [
    "AuthContext",
    "HTTPSessionManager",
    "get_http_session_manager",
]
