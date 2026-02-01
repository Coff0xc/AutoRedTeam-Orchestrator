#!/usr/bin/env python3
"""
弱密码检测器 - 基于 BaseDetector 重构

支持检测类型:
- 登录页面发现
- 默认凭证检测
- 管理面板检测
- 弱密码测试
"""

import os
import sys
from typing import Any, Dict, List, Optional, Tuple

# 导入 requests 用于异常处理
try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
)

from tools.detectors.base import BaseDetector, Vulnerability


class WeakPasswordDetector(BaseDetector):
    """弱密码检测器"""

    # 默认凭证列表
    DEFAULT_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "123456"),
        ("admin", "password"),
        ("admin", "admin123"),
        ("admin", ""),
        ("root", "root"),
        ("root", "123456"),
        ("root", "toor"),
        ("root", ""),
        ("test", "test"),
        ("guest", "guest"),
        ("user", "user"),
        ("demo", "demo"),
        ("administrator", "administrator"),
        ("administrator", "admin"),
    ]

    # 常见登录端点
    LOGIN_ENDPOINTS = [
        "/login",
        "/admin/login",
        "/user/login",
        "/signin",
        "/auth/login",
        "/account/login",
        "/wp-login.php",
        "/administrator",
        "/admin",
        "/manage",
        "/backend",
    ]

    # 管理面板及其默认凭证
    ADMIN_PANELS = {
        "/phpmyadmin/": [("root", ""), ("root", "root"), ("root", "mysql")],
        "/adminer.php": [("root", ""), ("root", "root")],
        "/manager/html": [("tomcat", "tomcat"), ("admin", "admin"), ("tomcat", "s3cret")],
        "/jenkins/": [("admin", "admin"), ("jenkins", "jenkins")],
        "/wp-admin/": [("admin", "admin"), ("admin", "password")],
        "/admin/": [("admin", "admin"), ("admin", "123456")],
    }

    # 表单字段名称
    USERNAME_FIELDS = ["username", "user", "login", "email", "account", "name", "uname"]
    PASSWORD_FIELDS = ["password", "pass", "pwd", "passwd", "secret"]

    # 登录成功指示器
    SUCCESS_INDICATORS = [
        "logout",
        "dashboard",
        "welcome",
        "profile",
        "注销",
        "退出",
        "控制台",
        "欢迎",
        "个人中心",
        "my account",
        "settings",
        "admin panel",
    ]

    # 登录失败指示器
    FAILURE_INDICATORS = [
        "invalid",
        "incorrect",
        "wrong",
        "failed",
        "error",
        "密码错误",
        "用户名或密码",
        "登录失败",
        "认证失败",
    ]

    def get_payloads(self) -> Dict[str, List]:
        """获取 Payload 库"""
        return {
            "Default Credentials": self.DEFAULT_CREDENTIALS,
            "Login Endpoints": self.LOGIN_ENDPOINTS,
            "Admin Panels": list(self.ADMIN_PANELS.keys()),
        }

    def validate_response(
        self, response: Dict[str, Any], payload: str, baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明登录成功"""
        if not response or not response.get("success"):
            return False

        resp_text = response.get("response_text", "").lower()
        status_code = response.get("status_code", 0)

        # 检查重定向 (通常登录成功会重定向)
        if status_code in [302, 303]:
            return True

        # 检查成功指示器
        for indicator in self.SUCCESS_INDICATORS:
            if indicator in resp_text:
                return True

        return False

    def _find_login_pages(self, url: str) -> List[Dict[str, Any]]:
        """查找登录页面"""
        login_pages = []
        base_url = url.rstrip("/")

        for endpoint in self.LOGIN_ENDPOINTS:
            test_url = base_url + endpoint

            try:
                response = self.send_request(test_url)
                if not response or not response.get("success"):
                    continue

                status_code = response.get("status_code", 0)
                if status_code != 200:
                    continue

                html = response.get("response_text", "").lower()

                # 检查是否是登录页面
                has_password_field = any(
                    f'type="password"' in html or f"type='password'" in html for _ in [1]
                )
                has_login_form = "login" in html or "登录" in html or "signin" in html

                if has_password_field or has_login_form:
                    login_pages.append(
                        {
                            "url": test_url,
                            "endpoint": endpoint,
                            "has_password_field": has_password_field,
                            "has_login_form": has_login_form,
                        }
                    )

            except (requests.RequestException, OSError) if HAS_REQUESTS else OSError:
                continue

        return login_pages

    def _test_credentials(
        self,
        login_url: str,
        credentials: List[Tuple[str, str]],
        username_override: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """测试凭证"""
        successful = []

        for username, password in credentials[:10]:  # 限制测试数量
            if username_override:
                username = username_override

            for user_field in self.USERNAME_FIELDS[:3]:
                for pass_field in self.PASSWORD_FIELDS[:2]:
                    try:
                        if not self.session:
                            continue

                        data = {user_field: username, pass_field: password}
                        resp = self.session.post(
                            login_url,
                            data=data,
                            timeout=self.timeout,
                            verify=self.verify_ssl,
                            allow_redirects=False,
                        )

                        # 检查登录成功
                        is_success = False
                        resp_text = resp.text.lower()

                        # 重定向通常表示成功
                        if resp.status_code in [302, 303]:
                            is_success = True

                        # 检查成功指示器
                        if any(ind in resp_text for ind in self.SUCCESS_INDICATORS):
                            is_success = True

                        # 排除失败指示器
                        if any(ind in resp_text for ind in self.FAILURE_INDICATORS):
                            is_success = False

                        if is_success:
                            successful.append(
                                {
                                    "username": username,
                                    "password": password,
                                    "user_field": user_field,
                                    "pass_field": pass_field,
                                    "status_code": resp.status_code,
                                }
                            )
                            return successful  # 找到一个就返回

                    except (requests.RequestException, OSError) if HAS_REQUESTS else OSError:
                        continue

        return successful

    def detect_admin_panels(self, url: str) -> List[Vulnerability]:
        """检测管理面板及其默认凭证"""
        vulnerabilities = []
        base_url = url.rstrip("/")

        for panel_path, credentials in self.ADMIN_PANELS.items():
            panel_url = base_url + panel_path

            try:
                response = self.send_request(panel_url)
                if not response or not response.get("success"):
                    continue

                status_code = response.get("status_code", 0)
                if status_code not in [200, 401, 403]:
                    continue

                html = response.get("response_text", "").lower()

                # 检查是否是管理面板
                is_admin_panel = status_code == 200 and (
                    'type="password"' in html
                    or "type='password'" in html
                    or "login" in html
                    or "登录" in html
                    or "authentication" in html
                )

                # 需要认证的面板
                needs_auth = status_code in [401, 403]

                if is_admin_panel or needs_auth:
                    # 记录发现的面板
                    vulnerabilities.append(
                        Vulnerability(
                            type="Admin Panel Found",
                            severity="INFO",
                            url=panel_url,
                            evidence=f"发现管理面板: {panel_path}",
                            verified=True,
                            confidence=0.9,
                            details={
                                "panel_path": panel_path,
                                "status_code": status_code,
                                "needs_auth": needs_auth,
                                "default_credentials": [f"{u}:{p}" for u, p in credentials],
                            },
                        )
                    )

                    # 如果是 200 状态，尝试测试默认凭证
                    if is_admin_panel:
                        successful = self._test_credentials(panel_url, credentials)
                        if successful:
                            for cred in successful:
                                vulnerabilities.append(
                                    Vulnerability(
                                        type="Default Credentials",
                                        severity="CRITICAL",
                                        url=panel_url,
                                        payload=f"{cred['username']}:{cred['password']}",
                                        evidence=f"默认凭证有效: {cred['username']}:{cred['password']}",
                                        verified=True,
                                        confidence=0.95,
                                        details={
                                            "panel_path": panel_path,
                                            "username": cred["username"],
                                            "password": cred["password"],
                                            "user_field": cred.get("user_field"),
                                            "pass_field": cred.get("pass_field"),
                                            "status_code": cred.get("status_code"),
                                        },
                                    )
                                )

            except (requests.RequestException, OSError) if HAS_REQUESTS else OSError:
                continue

        return vulnerabilities

    def detect_login_pages(self, url: str) -> List[Vulnerability]:
        """检测登录页面"""
        vulnerabilities = []
        login_pages = self._find_login_pages(url)

        for page in login_pages:
            vulnerabilities.append(
                Vulnerability(
                    type="Login Page Found",
                    severity="INFO",
                    url=page["url"],
                    evidence=f"发现登录页面: {page['endpoint']}",
                    verified=True,
                    confidence=0.85,
                    details={
                        "endpoint": page["endpoint"],
                        "has_password_field": page["has_password_field"],
                        "has_login_form": page["has_login_form"],
                    },
                )
            )

        return vulnerabilities

    def detect_weak_credentials(
        self, url: str, username: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测弱密码"""
        vulnerabilities = []
        login_pages = self._find_login_pages(url)

        for page in login_pages:
            successful = self._test_credentials(
                page["url"], self.DEFAULT_CREDENTIALS, username_override=username
            )

            for cred in successful:
                vulnerabilities.append(
                    Vulnerability(
                        type="Weak Password",
                        severity="CRITICAL",
                        url=page["url"],
                        payload=f"{cred['username']}:{cred['password']}",
                        evidence=f"弱密码: {cred['username']}:{cred['password']}",
                        verified=True,
                        confidence=0.9,
                        details={
                            "login_url": page["url"],
                            "username": cred["username"],
                            "password": cred["password"],
                            "user_field": cred.get("user_field"),
                            "pass_field": cred.get("pass_field"),
                            "status_code": cred.get("status_code"),
                        },
                    )
                )

        return vulnerabilities

    def detect(
        self, url: str, param: Optional[str] = None, deep_scan: bool = True
    ) -> Dict[str, Any]:
        """
        弱密码检测入口

        Args:
            url: 目标 URL
            param: 指定用户名 (可选)
            deep_scan: 是否深度扫描 (包含管理面板检测)

        Returns:
            检测结果字典
        """
        all_vulnerabilities = []

        # 1. 检测登录页面
        login_vulns = self.detect_login_pages(url)
        all_vulnerabilities.extend(login_vulns)

        # 2. 检测弱密码
        weak_vulns = self.detect_weak_credentials(url, username=param)
        all_vulnerabilities.extend(weak_vulns)

        if deep_scan:
            # 3. 检测管理面板
            admin_vulns = self.detect_admin_panels(url)
            all_vulnerabilities.extend(admin_vulns)

        # 统计结果
        login_pages_found = sum(1 for v in all_vulnerabilities if "Login Page" in v.type)
        admin_panels_found = sum(1 for v in all_vulnerabilities if "Admin Panel" in v.type)
        weak_passwords_found = sum(
            1
            for v in all_vulnerabilities
            if "Weak Password" in v.type or "Default Credentials" in v.type
        )

        return {
            "success": True,
            "url": url,
            "detector": self.__class__.__name__,
            "vulnerabilities": [v.to_dict() for v in all_vulnerabilities],
            "total": len(all_vulnerabilities),
            "verified_count": sum(1 for v in all_vulnerabilities if v.verified),
            "summary": {
                "login_pages_found": login_pages_found,
                "admin_panels_found": admin_panels_found,
                "weak_passwords_found": weak_passwords_found,
            },
            "by_severity": {
                "critical": sum(1 for v in all_vulnerabilities if v.severity == "CRITICAL"),
                "high": sum(1 for v in all_vulnerabilities if v.severity == "HIGH"),
                "medium": sum(1 for v in all_vulnerabilities if v.severity == "MEDIUM"),
                "info": sum(1 for v in all_vulnerabilities if v.severity == "INFO"),
            },
            "note": "弱密码检测可能触发账户锁定，请谨慎使用",
        }


# 便捷函数 - 兼容旧接口
def weak_password_detect(url: str, username: str = None, deep_scan: bool = True) -> Dict[str, Any]:
    """弱密码检测 (兼容旧接口)"""
    with WeakPasswordDetector() as detector:
        return detector.detect(url, param=username, deep_scan=deep_scan)
