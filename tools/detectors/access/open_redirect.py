#!/usr/bin/env python3
"""
Open Redirect (开放重定向) 检测器

检测开放重定向漏洞，包括:
- URL 参数重定向
- Header 注入重定向
- JavaScript 重定向
- Meta 标签重定向
"""

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..base import BaseDetector, Vulnerability


class OpenRedirectDetector(BaseDetector):
    """
    开放重定向漏洞检测器

    通过注入外部 URL 检测开放重定向漏洞。
    """

    # 重定向专用测试参数
    DEFAULT_PARAMS = [
        "url",
        "redirect",
        "redirect_url",
        "redirect_uri",
        "redir",
        "return",
        "return_url",
        "returnUrl",
        "returnTo",
        "return_to",
        "next",
        "next_url",
        "nextUrl",
        "goto",
        "go",
        "target",
        "dest",
        "destination",
        "link",
        "to",
        "out",
        "view",
        "continue",
        "continueTo",
        "forward",
        "forward_url",
        "callback",
        "callback_url",
        "fallback",
        "checkout_url",
        "image_url",
        "load_url",
        "file",
        "reference",
        "site",
        "host",
    ]

    # 测试域名 (使用安全的测试域名)
    TEST_DOMAINS = [
        "evil.com",
        "attacker.com",
        "example.com",
        "burpcollaborator.net",
    ]

    def get_payloads(self) -> Dict[str, List[str]]:
        """获取开放重定向 Payload 库"""
        base_domain = self.TEST_DOMAINS[0]

        return {
            "basic": [
                f"https://{base_domain}",
                f"http://{base_domain}",
                f"//{base_domain}",
            ],
            "bypass_filter": [
                f"https://{base_domain}%2f%2f",
                f"https://{base_domain}/%2f..",
                f"/\\{base_domain}",
                f"\\{base_domain}",
                f"/{base_domain}",
                f"https:/{base_domain}",
                f"https:/\\{base_domain}",
            ],
            "encoded": [
                f"https%3A%2F%2F{base_domain}",
                f"https%3A//{base_domain}",
                f"//%2F{base_domain}",
                f"https://{base_domain}%00",
                f"https://{base_domain}%0d%0a",
            ],
            "subdomain_bypass": [
                f"https://{base_domain}@legitimate.com",
                f"https://legitimate.com@{base_domain}",
                f"https://legitimate.com.{base_domain}",
                f"https://{base_domain}#legitimate.com",
                f"https://{base_domain}?legitimate.com",
            ],
            "protocol_bypass": [
                f"javascript:alert(document.domain)//",
                f"data:text/html,<script>alert(1)</script>",
                f"///{base_domain}",
            ],
        }

    def validate_response(
        self, response: Dict[str, Any], payload: str, baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在开放重定向漏洞"""
        if not response.get("success"):
            return False

        status = response.get("status_code", 0)
        headers = response.get("headers", {})
        text = response.get("response_text", "")
        final_url = response.get("url", "")

        # 检查 3xx 重定向
        if 300 <= status < 400:
            location = headers.get("Location", headers.get("location", ""))
            for domain in self.TEST_DOMAINS:
                if domain in location:
                    return True

        # 检查最终 URL (跟随重定向后)
        for domain in self.TEST_DOMAINS:
            if domain in final_url:
                return True

        # 检查 JavaScript 重定向
        js_redirect_patterns = [
            r"window\.location\s*=\s*['\"]([^'\"]+)['\"]",
            r"location\.href\s*=\s*['\"]([^'\"]+)['\"]",
            r"location\.replace\s*\(['\"]([^'\"]+)['\"]\)",
        ]
        for pattern in js_redirect_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                redirect_url = match.group(1)
                for domain in self.TEST_DOMAINS:
                    if domain in redirect_url:
                        return True

        # 检查 Meta 标签重定向
        meta_pattern = (
            r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?\d+;\s*url=([^"\'>\s]+)'
        )
        match = re.search(meta_pattern, text, re.IGNORECASE)
        if match:
            redirect_url = match.group(1)
            for domain in self.TEST_DOMAINS:
                if domain in redirect_url:
                    return True

        return False

    def detect(
        self, url: str, param: Optional[str] = None, deep_scan: bool = False
    ) -> Dict[str, Any]:
        """执行开放重定向检测"""
        from tools._common import reset_failure_counter

        reset_failure_counter()

        vulnerabilities = []
        test_params = self.get_test_params(param)
        baseline = self.get_baseline(url)
        payloads = self.get_payloads()

        for test_param in test_params[:10]:  # 限制参数数量
            for payload_type, payload_list in payloads.items():
                for payload in payload_list:
                    try:
                        # 构建测试 URL
                        test_url = self._build_test_url(url, test_param, payload)

                        # 发送请求，不跟随重定向以检查 Location 头
                        response = self.send_request(test_url, allow_redirects=False)

                        if not response or not response.get("success"):
                            continue

                        status = response.get("status_code", 0)
                        headers = response.get("headers", {})

                        # 检查 3xx 重定向
                        if 300 <= status < 400:
                            location = headers.get("Location", headers.get("location", ""))

                            for domain in self.TEST_DOMAINS:
                                if domain in location:
                                    severity = self._get_severity(payload_type)
                                    vuln = Vulnerability(
                                        type=f"Open Redirect ({payload_type})",
                                        severity=severity,
                                        param=test_param,
                                        payload=payload,
                                        url=test_url,
                                        evidence=f"Redirects to: {location[:100]}",
                                        verified=False,
                                        confidence=0.85,
                                        details={
                                            "payload_type": payload_type,
                                            "redirect_location": location,
                                            "status_code": status,
                                        },
                                    )
                                    vulnerabilities.append(vuln)

                                    if not deep_scan:
                                        break

                        # 检查响应内容中的重定向
                        if self.validate_response(response, payload, baseline):
                            if not any(
                                v.param == test_param and v.payload == payload
                                for v in vulnerabilities
                            ):
                                vuln = Vulnerability(
                                    type=f"Open Redirect ({payload_type})",
                                    severity="MEDIUM",
                                    param=test_param,
                                    payload=payload,
                                    url=test_url,
                                    evidence="Redirect found in response content",
                                    verified=False,
                                    confidence=0.6,
                                    details={"payload_type": payload_type},
                                )
                                vulnerabilities.append(vuln)

                    except Exception as exc:
                        logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

                if vulnerabilities and not deep_scan:
                    break
            if vulnerabilities and not deep_scan:
                break

        # 二次验证
        verified_vulns = []
        for vuln in vulnerabilities:
            if self._verify_redirect(url, vuln):
                vuln.verified = True
                vuln.confidence = min(1.0, vuln.confidence + 0.1)
            verified_vulns.append(vuln)

        return {
            "success": True,
            "url": url,
            "detector": "OpenRedirectDetector",
            "vulnerabilities": [v.to_dict() for v in verified_vulns],
            "total": len(verified_vulns),
            "verified_count": sum(1 for v in verified_vulns if v.verified),
            "recommendations": self._get_recommendations() if verified_vulns else [],
        }

    def _build_test_url(self, url: str, param: str, value: str) -> str:
        """构建测试 URL"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        query_params[param] = [value]
        new_query = urlencode(query_params, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)

    def _get_severity(self, payload_type: str) -> str:
        """根据 payload 类型确定严重程度"""
        if payload_type in ["basic", "subdomain_bypass"]:
            return "MEDIUM"
        elif payload_type == "protocol_bypass":
            return "HIGH"
        else:
            return "MEDIUM"

    def _verify_redirect(self, url: str, vuln: Vulnerability) -> bool:
        """二次验证开放重定向漏洞"""
        if not vuln.param:
            return False

        # 使用不同的测试域名重新验证
        verify_domain = self.TEST_DOMAINS[1] if len(self.TEST_DOMAINS) > 1 else "verify-test.com"
        verify_payload = f"https://{verify_domain}/verify"

        try:
            test_url = self._build_test_url(url, vuln.param, verify_payload)
            response = self.send_request(test_url, allow_redirects=False)

            if response and response.get("success"):
                status = response.get("status_code", 0)
                if 300 <= status < 400:
                    location = response.get("headers", {}).get("Location", "")
                    location = location or response.get("headers", {}).get("location", "")
                    if verify_domain in location:
                        return True
        except Exception as exc:
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        return False

    def _get_recommendations(self) -> List[str]:
        """获取修复建议"""
        return [
            "使用白名单验证重定向目标 URL",
            "避免使用用户输入直接构建重定向 URL",
            "使用相对路径而非完整 URL 进行重定向",
            "实施严格的 URL 解析和验证",
            "对重定向参数进行签名验证",
            "使用间接引用映射替代直接 URL 参数",
            "记录并监控异常的重定向请求",
        ]
