#!/usr/bin/env python3
"""
会话管理器 - 管理渗透测试会话
"""

import json
import logging
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class SessionStatus(Enum):
    """会话状态"""
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Target:
    """目标信息"""
    value: str  # IP, 域名, URL等
    type: str   # ip, domain, url, network
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """执行结果"""
    tool_name: str
    params: Dict[str, Any]
    result: Dict[str, Any]
    timestamp: datetime
    duration: float  # 秒
    success: bool
    error: str = None


@dataclass
class Session:
    """渗透测试会话"""
    id: str
    name: str
    created_at: datetime
    status: SessionStatus = SessionStatus.ACTIVE
    targets: List[Target] = field(default_factory=list)
    results: List[ExecutionResult] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_target(self, value: str, target_type: str, metadata: Dict = None):
        """添加目标"""
        target = Target(
            value=value,
            type=target_type,
            metadata=metadata or {}
        )
        self.targets.append(target)
        logger.info(f"会话 {self.id}: 添加目标 {value}")
    
    def add_result(self, tool_name: str, params: Dict, result: Dict,
                   duration: float, success: bool, error: str = None):
        """添加执行结果"""
        exec_result = ExecutionResult(
            tool_name=tool_name,
            params=params,
            result=result,
            timestamp=datetime.now(),
            duration=duration,
            success=success,
            error=error
        )
        self.results.append(exec_result)
    
    def add_finding(self, title: str, severity: str, description: str,
                    evidence: Dict = None, recommendations: List[str] = None):
        """添加发现"""
        finding = {
            "id": str(uuid.uuid4())[:8],
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence or {},
            "recommendations": recommendations or [],
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        logger.info(f"会话 {self.id}: 添加发现 - {title} [{severity}]")
    
    def add_note(self, note: str):
        """添加备注"""
        self.notes.append({
            "content": note,
            "timestamp": datetime.now().isoformat()
        })
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "status": self.status.value,
            "targets": [
                {"value": t.value, "type": t.type, "metadata": t.metadata}
                for t in self.targets
            ],
            "results_count": len(self.results),
            "findings_count": len(self.findings),
            "findings": self.findings,
            "notes": self.notes,
            "metadata": self.metadata
        }
    
    def export_results(self) -> List[Dict[str, Any]]:
        """导出结果"""
        return [
            {
                "tool_name": r.tool_name,
                "params": r.params,
                "result": r.result,
                "timestamp": r.timestamp.isoformat(),
                "duration": r.duration,
                "success": r.success,
                "error": r.error
            }
            for r in self.results
        ]


class SessionManager:
    """会话管理器"""
    
    def __init__(self, storage_path: str = None):
        self._sessions: Dict[str, Session] = {}
        self._storage_path = storage_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data", "sessions"
        )
        os.makedirs(self._storage_path, exist_ok=True)
        logger.info("会话管理器初始化完成")
    
    def create_session(self, name: str = None) -> Session:
        """创建会话"""
        session_id = str(uuid.uuid4())[:12]
        name = name or f"session_{session_id}"
        
        session = Session(
            id=session_id,
            name=name,
            created_at=datetime.now()
        )
        self._sessions[session_id] = session
        
        logger.info(f"创建会话: {session_id} ({name})")
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """获取会话"""
        return self._sessions.get(session_id)
    
    def list_sessions(self, status: SessionStatus = None) -> List[Dict[str, Any]]:
        """列出会话"""
        sessions = self._sessions.values()
        if status:
            sessions = [s for s in sessions if s.status == status]
        return [s.to_dict() for s in sessions]
    
    def update_session_status(self, session_id: str, status: SessionStatus):
        """更新会话状态"""
        session = self.get_session(session_id)
        if session:
            session.status = status
            logger.info(f"会话 {session_id} 状态更新为: {status.value}")
    
    def delete_session(self, session_id: str):
        """删除会话"""
        if session_id in self._sessions:
            del self._sessions[session_id]
            logger.info(f"会话已删除: {session_id}")
    
    def get_results(self, session_id: str) -> List[Dict[str, Any]]:
        """获取会话结果"""
        session = self.get_session(session_id)
        if session:
            return session.export_results()
        return []
    
    def save_session(self, session_id: str):
        """保存会话到文件"""
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"会话不存在: {session_id}")
        
        filepath = os.path.join(self._storage_path, f"{session_id}.json")
        data = {
            **session.to_dict(),
            "results": session.export_results()
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        logger.info(f"会话已保存: {filepath}")
    
    def load_session(self, session_id: str) -> Session:
        """从文件加载会话"""
        filepath = os.path.join(self._storage_path, f"{session_id}.json")
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"会话文件不存在: {filepath}")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        session = Session(
            id=data["id"],
            name=data["name"],
            created_at=datetime.fromisoformat(data["created_at"]),
            status=SessionStatus(data["status"]),
            metadata=data.get("metadata", {})
        )
        
        # 恢复目标
        for t in data.get("targets", []):
            session.add_target(t["value"], t["type"], t.get("metadata"))
        
        # 恢复发现
        session.findings = data.get("findings", [])
        session.notes = data.get("notes", [])
        
        self._sessions[session_id] = session
        logger.info(f"会话已加载: {session_id}")
        
        return session
    
    def get_active_session_count(self) -> int:
        """获取活动会话数"""
        return sum(
            1 for s in self._sessions.values()
            if s.status == SessionStatus.ACTIVE
        )


# ========== HTTP会话管理器 (新增) ==========

try:
    import requests
    from requests.cookies import RequestsCookieJar
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

import re
from urllib.parse import urljoin


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
    HTTP会话管理器 - 支持登录态测试
    管理Cookie、Token、认证状态
    """

    # 常见CSRF Token字段名
    CSRF_PATTERNS = [
        r'name=["\']?csrf[_-]?token["\']?\s+value=["\']([^"\']+)["\']',
        r'name=["\']?_token["\']?\s+value=["\']([^"\']+)["\']',
        r'name=["\']?csrfmiddlewaretoken["\']?\s+value=["\']([^"\']+)["\']',
        r'name=["\']?authenticity_token["\']?\s+value=["\']([^"\']+)["\']',
        r'name=["\']?__RequestVerificationToken["\']?\s+value=["\']([^"\']+)["\']',
    ]

    def __init__(self):
        self._sessions: Dict[str, 'requests.Session'] = {}
        self._auth_contexts: Dict[str, AuthContext] = {}
        self._request_count: Dict[str, int] = {}

    def create_session(self, session_id: str = None) -> str:
        """
        创建HTTP会话

        Args:
            session_id: 会话ID (可选，自动生成)

        Returns:
            session_id
        """
        if not HAS_REQUESTS:
            raise RuntimeError("requests库未安装")

        session_id = session_id or str(uuid.uuid4())[:8]

        sess = requests.Session()
        sess.verify = False
        sess.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })

        self._sessions[session_id] = sess
        self._auth_contexts[session_id] = AuthContext()
        self._request_count[session_id] = 0

        logger.info(f"HTTP会话已创建: {session_id}")
        return session_id

    def get_session(self, session_id: str) -> Optional['requests.Session']:
        """获取HTTP会话"""
        return self._sessions.get(session_id)

    def login(self, session_id: str, login_url: str,
              username: str, password: str,
              username_field: str = "username",
              password_field: str = "password",
              extra_data: Dict = None) -> Dict:
        """
        执行登录

        Args:
            session_id: 会话ID
            login_url: 登录URL
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
            # 1. 先GET登录页面获取CSRF Token
            resp = sess.get(login_url, timeout=10)
            csrf_token = self._extract_csrf_token(resp.text)

            # 2. 构建登录数据
            login_data = {
                username_field: username,
                password_field: password,
            }

            if csrf_token:
                # 尝试常见的CSRF字段名
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

                # 提取可能的Token
                self._extract_tokens(session_id, login_resp)

                logger.info(f"会话 {session_id} 登录成功")
                return {
                    "success": True,
                    "session_id": session_id,
                    "cookies": dict(sess.cookies),
                    "tokens": auth_ctx.tokens,
                }
            else:
                return {
                    "success": False,
                    "error": "登录失败，请检查凭据",
                    "status_code": login_resp.status_code,
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _extract_csrf_token(self, html: str) -> Optional[str]:
        """从HTML中提取CSRF Token"""
        for pattern in self.CSRF_PATTERNS:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _extract_tokens(self, session_id: str, resp: 'requests.Response'):
        """提取各种Token"""
        auth_ctx = self._auth_contexts[session_id]

        # 从响应头提取
        for header in ["Authorization", "X-CSRF-Token", "X-Auth-Token"]:
            if header in resp.headers:
                auth_ctx.tokens[header] = resp.headers[header]
                auth_ctx.headers[header] = resp.headers[header]

        # 从Cookie提取JWT
        for cookie_name in ["jwt", "token", "access_token", "auth_token"]:
            if cookie_name in resp.cookies:
                auth_ctx.tokens[cookie_name] = resp.cookies[cookie_name]

    def _check_login_success(self, resp: 'requests.Response', sess: 'requests.Session') -> bool:
        """判断登录是否成功"""
        # 检查常见的失败标志
        fail_indicators = [
            "登录失败", "login failed", "invalid", "incorrect",
            "wrong password", "用户名或密码错误", "authentication failed"
        ]
        for indicator in fail_indicators:
            if indicator.lower() in resp.text.lower():
                return False

        # 检查是否有认证Cookie
        auth_cookies = ["session", "sessionid", "PHPSESSID", "JSESSIONID", "token", "auth"]
        for cookie_name in auth_cookies:
            if any(cookie_name.lower() in c.lower() for c in sess.cookies.keys()):
                return True

        # 检查状态码
        if resp.status_code in [200, 302] and len(sess.cookies) > 0:
            return True

        return False

    def request(self, session_id: str, url: str, method: str = "GET",
                data: Dict = None, headers: Dict = None, **kwargs) -> Dict:
        """
        发送带会话的HTTP请求

        Args:
            session_id: 会话ID
            url: 请求URL
            method: HTTP方法
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

        except Exception as e:
            return {"success": False, "error": str(e)}

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

    def close_session(self, session_id: str):
        """关闭会话"""
        if session_id in self._sessions:
            self._sessions[session_id].close()
            del self._sessions[session_id]
            del self._auth_contexts[session_id]
            logger.info(f"HTTP会话已关闭: {session_id}")

    def list_sessions(self) -> List[Dict]:
        """列出所有HTTP会话"""
        return [
            {
                "session_id": sid,
                "is_authenticated": self._auth_contexts[sid].is_authenticated,
                "request_count": self._request_count.get(sid, 0),
            }
            for sid in self._sessions.keys()
        ]


# 全局HTTP会话管理器实例
_http_session_manager: Optional[HTTPSessionManager] = None


def get_http_session_manager() -> HTTPSessionManager:
    """获取全局HTTP会话管理器"""
    global _http_session_manager
    if _http_session_manager is None:
        _http_session_manager = HTTPSessionManager()
    return _http_session_manager
