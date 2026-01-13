#!/usr/bin/env python3
"""
XSS 检测器 - 基于 BaseDetector 重构

支持检测类型:
- 反射型 XSS (Reflected XSS)
- 存储型 XSS (Stored XSS) - 需要配合其他检测
- DOM 型 XSS (DOM-based XSS) - 基础检测
"""

import re
import html
from typing import Dict, List, Any, Optional
from urllib.parse import quote

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tools.detectors.base import BaseDetector, Vulnerability


class XSSDetector(BaseDetector):
    """XSS 跨站脚本检测器"""

    # 覆盖默认测试参数
    DEFAULT_PARAMS = [
        "search", "q", "query", "keyword", "name", "input",
        "text", "msg", "message", "content", "title", "comment",
        "value", "data", "body", "description", "callback"
    ]

    # 反射型 XSS Payload
    REFLECTED_PAYLOADS = [
        # 基础 Script 标签
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<script>alert(document.domain)</script>",
        # 事件处理器
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror='alert(1)'>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        # 闭合标签
        "'\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "</title><script>alert(1)</script>",
        "</textarea><script>alert(1)</script>",
        # JavaScript 协议
        "javascript:alert(1)",
        "javascript:alert(document.domain)",
        # 编码绕过
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
    ]

    # DOM XSS 检测 Payload
    DOM_PAYLOADS = [
        "#<script>alert(1)</script>",
        "#javascript:alert(1)",
        "?default=<script>alert(1)</script>",
    ]

    # XSS 上下文检测模式
    CONTEXT_PATTERNS = {
        "html_tag": r"<[^>]*{payload}[^>]*>",
        "html_attr": r'["\'][^"\']*{payload}[^"\']*["\']',
        "script_block": r"<script[^>]*>[^<]*{payload}[^<]*</script>",
        "event_handler": r"on\w+\s*=\s*[\"'][^\"']*{payload}",
    }

    # 危险 HTML 标签和属性
    DANGEROUS_TAGS = [
        "script", "iframe", "object", "embed", "applet",
        "form", "input", "button", "select", "textarea"
    ]

    DANGEROUS_ATTRS = [
        "onerror", "onload", "onclick", "onmouseover", "onfocus",
        "onblur", "onchange", "onsubmit", "onkeydown", "onkeyup",
        "onmouseenter", "onmouseleave", "ondblclick", "oncontextmenu"
    ]

    def get_payloads(self) -> Dict[str, List[str]]:
        """获取 Payload 库"""
        return {
            "Reflected XSS": self.REFLECTED_PAYLOADS,
            "DOM-based XSS": self.DOM_PAYLOADS,
        }

    def validate_response(
        self,
        response: Dict[str, Any],
        payload: str,
        baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在 XSS"""
        if not response or not response.get("success"):
            return False

        resp_text = response.get("response_text", "")

        # 检查 payload 是否在响应中反射
        if self._check_reflection(resp_text, payload):
            return True

        return False

    def _check_reflection(self, response_text: str, payload: str) -> bool:
        """检查 payload 是否在响应中反射"""
        # 直接匹配
        if payload in response_text:
            return True

        # HTML 实体编码匹配
        encoded_payload = html.escape(payload)
        if encoded_payload in response_text:
            # 如果只是被编码了，可能不是漏洞
            # 但如果关键字符没被编码，仍可能有风险
            if payload.replace('"', '&quot;') in response_text:
                return True

        # 部分编码匹配
        partial_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        if partial_encoded != payload and partial_encoded not in response_text:
            # 如果 < > 被编码了，检查其他危险字符
            if 'onerror' in payload.lower() and 'onerror' in response_text.lower():
                return True

        return False

    def _analyze_context(
        self,
        response_text: str,
        payload: str
    ) -> Optional[str]:
        """分析 payload 在响应中的上下文"""
        for context_name, pattern in self.CONTEXT_PATTERNS.items():
            regex = pattern.replace("{payload}", re.escape(payload))
            if re.search(regex, response_text, re.IGNORECASE):
                return context_name
        return None

    def detect_reflected(
        self,
        url: str,
        param: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测反射型 XSS"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        for test_param in test_params:
            for payload in self.REFLECTED_PAYLOADS:
                # URL 编码 payload
                encoded_payload = quote(payload, safe='')

                response = self.send_request(url, encoded_payload, test_param)

                if not response or not response.get("success"):
                    continue

                resp_text = response.get("response_text", "")

                # 检查反射
                if self._check_reflection(resp_text, payload):
                    # 分析上下文
                    context = self._analyze_context(resp_text, payload)

                    vulnerabilities.append(Vulnerability(
                        type="Reflected XSS",
                        severity="HIGH",
                        param=test_param,
                        payload=payload,
                        url=response.get("url", url),
                        evidence=f"Payload 在响应中反射, 上下文: {context or 'unknown'}",
                        verified=False,
                        confidence=0.75 if context else 0.6,
                        details={
                            "context": context,
                            "response_length": len(resp_text)
                        }
                    ))
                    break  # 找到一个就停止该参数的测试

        return vulnerabilities

    def detect_dom_based(
        self,
        url: str,
        param: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测 DOM 型 XSS (基础检测)"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        # DOM XSS 检测需要检查响应中的危险 JS 模式
        dom_sink_patterns = [
            r"document\.write\s*\(",
            r"\.innerHTML\s*=",
            r"\.outerHTML\s*=",
            r"eval\s*\(",
            r"setTimeout\s*\([^,]*\+",
            r"setInterval\s*\([^,]*\+",
            r"location\s*=",
            r"location\.href\s*=",
            r"location\.replace\s*\(",
            r"document\.location\s*=",
        ]

        dom_source_patterns = [
            r"location\.hash",
            r"location\.search",
            r"location\.href",
            r"document\.URL",
            r"document\.referrer",
            r"window\.name",
        ]

        for test_param in test_params:
            for payload in self.DOM_PAYLOADS:
                encoded_payload = quote(payload, safe='')
                response = self.send_request(url, encoded_payload, test_param)

                if not response or not response.get("success"):
                    continue

                resp_text = response.get("response_text", "")

                # 检查是否存在 DOM sink 和 source 组合
                has_sink = any(re.search(p, resp_text) for p in dom_sink_patterns)
                has_source = any(re.search(p, resp_text) for p in dom_source_patterns)

                # 检查 payload 是否反射
                if self._check_reflection(resp_text, payload):
                    vulnerabilities.append(Vulnerability(
                        type="DOM-based XSS",
                        severity="HIGH",
                        param=test_param,
                        payload=payload,
                        url=response.get("url", url),
                        evidence=f"DOM sink: {has_sink}, DOM source: {has_source}",
                        verified=False,
                        confidence=0.7 if (has_sink and has_source) else 0.5,
                        details={
                            "has_dom_sink": has_sink,
                            "has_dom_source": has_source,
                            "response_length": len(resp_text)
                        }
                    ))
                    break

        return vulnerabilities

    def detect(
        self,
        url: str,
        param: Optional[str] = None,
        deep_scan: bool = True
    ) -> Dict[str, Any]:
        """
        XSS 检测入口

        Args:
            url: 目标 URL
            param: 指定参数 (可选)
            deep_scan: 是否深度扫描 (包含 DOM XSS 检测)

        Returns:
            检测结果字典
        """
        all_vulnerabilities = []

        # 1. 反射型 XSS 检测
        reflected_vulns = self.detect_reflected(url, param)
        all_vulnerabilities.extend(reflected_vulns)

        if deep_scan:
            # 2. DOM 型 XSS 检测
            dom_vulns = self.detect_dom_based(url, param)
            all_vulnerabilities.extend(dom_vulns)

        # 二次验证
        verified_vulns = []
        for vuln in all_vulnerabilities:
            if not vuln.verified:
                if self.verify_vulnerability(vuln):
                    vuln.verified = True
                    vuln.confidence = min(1.0, vuln.confidence + 0.2)
            verified_vulns.append(vuln)

        return {
            "success": True,
            "url": url,
            "detector": self.__class__.__name__,
            "vulnerabilities": [v.to_dict() for v in verified_vulns],
            "total": len(verified_vulns),
            "verified_count": sum(1 for v in verified_vulns if v.verified),
            "by_type": {
                "reflected": sum(1 for v in verified_vulns if "Reflected" in v.type),
                "dom_based": sum(1 for v in verified_vulns if "DOM" in v.type),
            }
        }


# 便捷函数 - 兼容旧接口
def xss_detect(url: str, param: str = None, deep_scan: bool = True) -> Dict[str, Any]:
    """XSS 检测 (兼容旧接口)"""
    with XSSDetector() as detector:
        return detector.detect(url, param, deep_scan)
