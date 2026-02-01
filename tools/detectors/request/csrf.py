#!/usr/bin/env python3
"""
CSRF 检测器 - 基于 BaseDetector 重构

支持检测类型:
- CSRF Token 缺失检测
- SameSite Cookie 配置检测
- Referer 验证检测
"""

import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
)

from tools.detectors.base import BaseDetector, Vulnerability


class CSRFDetector(BaseDetector):
    """CSRF 跨站请求伪造检测器"""

    # CSRF Token 常见名称
    CSRF_TOKEN_NAMES = [
        "csrf",
        "csrf_token",
        "csrftoken",
        "_csrf",
        "_token",
        "authenticity_token",
        "csrfmiddlewaretoken",
        "__requestverificationtoken",
        "antiforgery",
        "xsrf",
        "xsrf_token",
        "__csrf_magic",
    ]

    # 表单相关正则
    FORM_PATTERN = re.compile(r"<form[^>]*>(.*?)</form>", re.DOTALL | re.IGNORECASE)
    INPUT_PATTERN = re.compile(r"<input[^>]*>", re.IGNORECASE)
    META_CSRF_PATTERN = re.compile(r'<meta[^>]*name=["\']?csrf[^"\']*["\']?[^>]*>', re.IGNORECASE)

    def get_payloads(self) -> Dict[str, List[str]]:
        """获取 Payload 库 - CSRF 检测不需要传统 Payload"""
        return {
            "CSRF Token Check": [],
            "SameSite Cookie Check": [],
            "Referer Validation Check": [],
        }

    def validate_response(
        self, response: Dict[str, Any], payload: str, baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在 CSRF 漏洞"""
        # CSRF 检测使用专门的检测方法，此方法仅作为接口实现
        return False

    def _check_csrf_token_in_html(self, html: str) -> Dict[str, Any]:
        """检查 HTML 中是否存在 CSRF Token"""
        html_lower = html.lower()

        # 检查 meta 标签中的 CSRF Token
        has_meta_csrf = bool(self.META_CSRF_PATTERN.search(html))

        # 检查是否存在任何 CSRF Token 相关字符串
        has_csrf_string = any(token in html_lower for token in self.CSRF_TOKEN_NAMES)

        # 查找所有表单
        forms = self.FORM_PATTERN.findall(html)
        forms_without_csrf = []
        forms_with_csrf = []

        for i, form_content in enumerate(forms):
            form_lower = form_content.lower()
            has_token = any(token in form_lower for token in self.CSRF_TOKEN_NAMES)

            if has_token:
                forms_with_csrf.append(i)
            else:
                # 检查是否是需要保护的表单 (POST 表单)
                forms_without_csrf.append(i)

        return {
            "has_meta_csrf": has_meta_csrf,
            "has_csrf_string": has_csrf_string,
            "total_forms": len(forms),
            "forms_with_csrf": len(forms_with_csrf),
            "forms_without_csrf": len(forms_without_csrf),
        }

    def _check_samesite_cookies(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """检查 Cookie 的 SameSite 属性"""
        issues = []

        # 获取 Set-Cookie 头
        set_cookie = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")

        if not set_cookie:
            return issues

        # 可能有多个 Set-Cookie
        cookies = set_cookie.split(",") if "," in set_cookie else [set_cookie]

        for cookie in cookies:
            cookie_lower = cookie.lower()

            # 提取 cookie 名称
            cookie_name = cookie.split("=")[0].strip() if "=" in cookie else "unknown"

            # 检查 SameSite 属性
            if "samesite" not in cookie_lower:
                issues.append(
                    {
                        "cookie": cookie_name,
                        "issue": "Missing SameSite attribute",
                        "severity": "MEDIUM",
                    }
                )
            elif "samesite=none" in cookie_lower:
                # SameSite=None 需要 Secure 属性
                if "secure" not in cookie_lower:
                    issues.append(
                        {
                            "cookie": cookie_name,
                            "issue": "SameSite=None without Secure flag",
                            "severity": "HIGH",
                        }
                    )

            # 检查敏感 Cookie 是否有 HttpOnly
            sensitive_names = ["session", "auth", "token", "jwt", "sid"]
            if any(name in cookie_name.lower() for name in sensitive_names):
                if "httponly" not in cookie_lower:
                    issues.append(
                        {
                            "cookie": cookie_name,
                            "issue": "Sensitive cookie missing HttpOnly flag",
                            "severity": "MEDIUM",
                        }
                    )

        return issues

    def _check_referer_validation(self, url: str) -> Dict[str, Any]:
        """检查服务器是否验证 Referer 头"""
        # 正常请求
        normal_response = self.send_request(url)
        if not normal_response or not normal_response.get("success"):
            return {"checked": False, "error": "Failed to get normal response"}

        normal_status = normal_response.get("status_code")
        normal_length = normal_response.get("response_length", 0)

        # 使用恶意 Referer 请求
        evil_headers = {"Referer": "https://evil-attacker.com/csrf-attack"}

        # 需要直接使用 session 发送带自定义头的请求
        try:
            if self.session:
                resp = self.session.get(
                    url,
                    headers={**{"User-Agent": self.user_agent}, **evil_headers},
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                evil_status = resp.status_code
                evil_length = len(resp.text)
            else:
                # 降级处理
                return {"checked": False, "error": "No session available"}
        except Exception as e:
            return {"checked": False, "error": str(e)}

        # 无 Referer 请求
        no_referer_headers = {"Referer": ""}
        try:
            if self.session:
                resp = self.session.get(
                    url,
                    headers={**{"User-Agent": self.user_agent}, **no_referer_headers},
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                no_referer_status = resp.status_code
                no_referer_length = len(resp.text)
            else:
                no_referer_status = None
                no_referer_length = None
        except Exception:
            no_referer_status = None
            no_referer_length = None

        # 分析结果
        validates_referer = False

        # 如果恶意 Referer 导致不同的状态码或显著不同的响应长度
        if evil_status != normal_status:
            validates_referer = True
        elif abs(evil_length - normal_length) > 100:
            validates_referer = True

        return {
            "checked": True,
            "validates_referer": validates_referer,
            "normal_status": normal_status,
            "evil_referer_status": evil_status,
            "no_referer_status": no_referer_status,
            "response_length_diff": abs(evil_length - normal_length),
        }

    def detect(
        self, url: str, param: Optional[str] = None, deep_scan: bool = True
    ) -> Dict[str, Any]:
        """
        CSRF 检测入口

        Args:
            url: 目标 URL
            param: 未使用 (保持接口一致)
            deep_scan: 是否深度扫描 (包含 Referer 验证检测)

        Returns:
            检测结果字典
        """
        vulnerabilities = []

        # 获取页面响应
        response = self.send_request(url)
        if not response or not response.get("success"):
            return {
                "success": False,
                "url": url,
                "error": "Failed to fetch page",
                "vulnerabilities": [],
                "total": 0,
            }

        html = response.get("response_text", "")
        headers = response.get("headers", {})

        # 1. 检查 CSRF Token
        token_check = self._check_csrf_token_in_html(html)

        if token_check["forms_without_csrf"] > 0 and not token_check["has_meta_csrf"]:
            vulnerabilities.append(
                Vulnerability(
                    type="Missing CSRF Token",
                    severity="HIGH",
                    url=url,
                    evidence=f"发现 {token_check['forms_without_csrf']} 个表单缺少 CSRF Token",
                    verified=True,
                    confidence=0.8,
                    details={
                        "total_forms": token_check["total_forms"],
                        "forms_without_csrf": token_check["forms_without_csrf"],
                        "has_meta_csrf": token_check["has_meta_csrf"],
                    },
                )
            )

        # 2. 检查 SameSite Cookie
        cookie_issues = self._check_samesite_cookies(headers)

        for issue in cookie_issues:
            vulnerabilities.append(
                Vulnerability(
                    type=f"Cookie Security: {issue['issue']}",
                    severity=issue["severity"],
                    url=url,
                    evidence=f"Cookie '{issue['cookie']}' - {issue['issue']}",
                    verified=True,
                    confidence=0.9,
                    details=issue,
                )
            )

        # 3. 检查 Referer 验证 (深度扫描)
        if deep_scan:
            referer_check = self._check_referer_validation(url)

            if referer_check.get("checked") and not referer_check.get("validates_referer"):
                vulnerabilities.append(
                    Vulnerability(
                        type="No Referer Validation",
                        severity="LOW",
                        url=url,
                        evidence="服务器未验证 Referer 头，可能允许跨站请求",
                        verified=True,
                        confidence=0.6,
                        details=referer_check,
                    )
                )

        return {
            "success": True,
            "url": url,
            "detector": self.__class__.__name__,
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
            "total": len(vulnerabilities),
            "verified_count": sum(1 for v in vulnerabilities if v.verified),
            "by_severity": {
                "high": sum(1 for v in vulnerabilities if v.severity == "HIGH"),
                "medium": sum(1 for v in vulnerabilities if v.severity == "MEDIUM"),
                "low": sum(1 for v in vulnerabilities if v.severity == "LOW"),
            },
            "token_check": token_check,
        }


# 便捷函数 - 兼容旧接口
def csrf_detect(url: str, deep_scan: bool = True) -> Dict[str, Any]:
    """CSRF 检测 (兼容旧接口)"""
    with CSRFDetector() as detector:
        return detector.detect(url, deep_scan=deep_scan)
