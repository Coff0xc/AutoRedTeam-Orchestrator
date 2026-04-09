"""
CRLF Injection 检测器

检测 HTTP 响应头注入 (CRLF Injection / HTTP Response Splitting)，包括:
- 响应头注入: 通过 \\r\\n 在响应头中注入额外 header
- HTTP Response Splitting: 注入完整的 HTTP 响应
- Set-Cookie 注入: 通过 CRLF 注入恶意 Cookie
- XSS via CRLF: 通过响应拆分注入 HTML 内容

技术原理:
1. 用户输入被直接拼接到 HTTP 响应头 (如 Location, Set-Cookie)
2. 注入 \\r\\n 可以终止当前 header 并注入新 header
3. 注入 \\r\\n\\r\\n 可以结束 header 区域并注入 body 内容

参考:
- https://owasp.org/www-community/vulnerabilities/CRLF_Injection
- https://cwe.mitre.org/data/definitions/93.html
"""

import logging
from typing import Any, Dict, List
from urllib.parse import urlparse

from ..base import BaseDetector
from ..factory import register_detector
from ..result import DetectionResult, DetectorType, Severity

logger = logging.getLogger(__name__)

# CRLF 注入 payload — 多种编码变体绕过过滤
CRLF_PAYLOADS: List[Dict[str, Any]] = [
    # 标准 CRLF
    {
        "payload": "%0d%0aX-Injected: crlf_test_{nonce}",
        "header": "X-Injected",
        "desc": "标准 %0d%0a 编码",
    },
    # 仅 LF
    {
        "payload": "%0aX-Injected: crlf_test_{nonce}",
        "header": "X-Injected",
        "desc": "仅 %0a (LF)",
    },
    # 仅 CR
    {
        "payload": "%0dX-Injected: crlf_test_{nonce}",
        "header": "X-Injected",
        "desc": "仅 %0d (CR)",
    },
    # Unicode 变体
    {
        "payload": "%E5%98%8A%E5%98%8DX-Injected: crlf_test_{nonce}",
        "header": "X-Injected",
        "desc": "Unicode U+560A U+560D 变体",
    },
    # 双重 URL 编码
    {
        "payload": "%250d%250aX-Injected: crlf_test_{nonce}",
        "header": "X-Injected",
        "desc": "双重URL编码 %250d%250a",
    },
    # Response splitting — 注入 Set-Cookie
    {
        "payload": "%0d%0aSet-Cookie: crlftest={nonce}",
        "header": "Set-Cookie",
        "desc": "Set-Cookie 注入",
    },
    # Response splitting — 注入 body (XSS)
    {
        "payload": "%0d%0a%0d%0a<script>var crlf='{nonce}'</script>",
        "header": None,
        "desc": "HTTP Response Splitting (body 注入)",
        "body_check": True,
    },
]


@register_detector("crlf_injection")
class CRLFInjectionDetector(BaseDetector):
    """CRLF Injection 检测器

    通过注入 CRLF 字符到 URL 参数中，检测是否能在响应头/body 中注入内容。

    使用示例:
        detector = CRLFInjectionDetector()
        results = detector.detect("https://example.com/redirect?url=test")
    """

    name = "crlf_injection"
    description = "CRLF Injection HTTP响应头注入检测器"
    vuln_type = "crlf_injection"
    severity = Severity.MEDIUM
    detector_type = DetectorType.INJECTION
    version = "1.0.0"

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测 CRLF Injection 漏洞

        Args:
            url: 目标 URL (应包含可注入的参数)
            **kwargs: 额外参数
                params: 要测试的参数字典

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        parsed = urlparse(url)
        if not parsed.hostname:
            logger.warning("[%s] 无效URL: %s", self.name, url)
            return results

        params = kwargs.get("params", {})
        nonce = f"crlfn{id(self) % 100000:05d}"

        # 如果有显式参数，测试每个参数
        if params:
            for param_name in params:
                param_results = self._test_param(url, param_name, nonce)
                results.extend(param_results)
        else:
            # 尝试常见的注入点: URL path 末尾
            path_results = self._test_path_injection(url, nonce)
            results.extend(path_results)

            # 测试常见的反射参数
            for param_name in ["url", "redirect", "next", "return", "returnTo", "goto", "path"]:
                param_results = self._test_param(url, param_name, nonce)
                results.extend(param_results)
                if param_results:
                    break  # 发现一个即可

        self._log_detection_end(url, results)
        return results

    def _test_param(self, url: str, param_name: str, nonce: str) -> List[DetectionResult]:
        """测试单个参数的 CRLF 注入"""
        results = []

        for payload_info in CRLF_PAYLOADS:
            payload = payload_info["payload"].format(nonce=nonce)
            expected_header = payload_info["header"]
            body_check = payload_info.get("body_check", False)

            # 构造请求
            separator = "&" if "?" in url else "?"
            test_url = f"{url}{separator}{param_name}={payload}"

            resp = self._safe_request("GET", test_url)
            if resp is None:
                continue

            # 检查响应头
            if expected_header and resp.headers:
                headers_dict = dict(resp.headers) if hasattr(resp.headers, "items") else {}
                for h_name, h_value in headers_dict.items():
                    if h_name.lower() == expected_header.lower():
                        if nonce in str(h_value):
                            results.append(
                                self._create_result(
                                    url=url,
                                    vulnerable=True,
                                    param=param_name,
                                    payload=payload,
                                    evidence=(
                                        f"CRLF 注入确认: 注入的 header "
                                        f"'{expected_header}: ...{nonce}...' "
                                        f"出现在响应头中。({payload_info['desc']})"
                                    ),
                                    confidence=0.90,
                                    verified=True,
                                    remediation=self._get_remediation(),
                                    references=self._get_references(),
                                    extra={
                                        "crlf_type": "header_injection",
                                        "injected_header": expected_header,
                                        "encoding": payload_info["desc"],
                                        "param": param_name,
                                    },
                                )
                            )
                            return results  # 已确认

            # 检查响应 body (response splitting)
            if body_check:
                body = getattr(resp, "text", "") or ""
                if nonce in body:
                    results.append(
                        self._create_result(
                            url=url,
                            vulnerable=True,
                            param=param_name,
                            payload=payload,
                            evidence=(
                                f"HTTP Response Splitting: 注入内容 "
                                f"出现在响应 body 中。({payload_info['desc']})"
                            ),
                            confidence=0.85,
                            verified=True,
                            remediation=self._get_remediation(),
                            references=self._get_references(),
                            extra={
                                "crlf_type": "response_splitting",
                                "encoding": payload_info["desc"],
                                "param": param_name,
                            },
                        )
                    )
                    return results

        return results

    def _test_path_injection(self, url: str, nonce: str) -> List[DetectionResult]:
        """测试 URL 路径的 CRLF 注入"""
        results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 在路径末尾注入 CRLF
        for payload_info in CRLF_PAYLOADS[:3]:  # 仅测试前 3 个基本变体
            payload = payload_info["payload"].format(nonce=nonce)
            test_url = f"{base}{parsed.path}/{payload}"

            resp = self._safe_request("GET", test_url)
            if resp is None:
                continue

            if resp.headers:
                headers_dict = dict(resp.headers) if hasattr(resp.headers, "items") else {}
                for h_name, h_value in headers_dict.items():
                    if "injected" in h_name.lower() and nonce in str(h_value):
                        results.append(
                            self._create_result(
                                url=url,
                                vulnerable=True,
                                payload=f"PATH: {payload}",
                                evidence=(
                                    f"路径 CRLF 注入: URL 路径中的 CRLF "
                                    f"导致响应头注入。({payload_info['desc']})"
                                ),
                                confidence=0.85,
                                verified=True,
                                remediation=self._get_remediation(),
                                references=self._get_references(),
                                extra={
                                    "crlf_type": "path_injection",
                                    "encoding": payload_info["desc"],
                                },
                            )
                        )
                        return results

        return results

    @staticmethod
    def _get_remediation() -> str:
        return (
            "1. 对所有用户输入进行 URL 编码后再放入响应头\n"
            "2. 过滤/拒绝包含 \\r\\n (CR LF) 的输入\n"
            "3. 使用框架提供的安全 header 设置 API\n"
            "4. 避免将用户输入直接拼接到 Location/Set-Cookie 头"
        )

    @staticmethod
    def _get_references() -> list:
        return [
            "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
            "https://cwe.mitre.org/data/definitions/93.html",
        ]
