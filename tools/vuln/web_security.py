#!/usr/bin/env python3
"""
漏洞检测工具 - Web安全类漏洞检测
包含: CSRF、CORS、安全头检测、缓存投毒
"""
import logging
from urllib.parse import urlparse

from .._common import GLOBAL_CONFIG, HAS_REQUESTS, get_verify_ssl

if HAS_REQUESTS:
    import requests

logger = logging.getLogger(__name__)


# ============ CSRF检测 ============

def csrf_detect(url: str, method: str = "POST") -> dict:
    """CSRF检测 - 跨站请求伪造漏洞检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    
    try:
        # 获取页面内容
        resp = requests.get(url, timeout=10, verify=get_verify_ssl())
        html = resp.text.lower()
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # 检查CSRF Token
        csrf_indicators = [
            "csrf_token", "csrftoken", "_token", "authenticity_token",
            "csrf-token", "__requestverificationtoken", "antiforgery",
            "_csrf", "xsrf-token", "x-csrf-token"
        ]

        has_csrf_token = any(token in html for token in csrf_indicators)
        has_csrf_header = any(token in str(headers) for token in ["x-csrf", "x-xsrf"])

        if not has_csrf_token and not has_csrf_header:
            vulns.append({
                "type": "Missing CSRF Token",
                "severity": "HIGH",
                "detail": "页面缺少CSRF令牌保护",
                "url": url
            })

        # 检查SameSite Cookie属性
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            if "samesite=strict" not in set_cookie.lower() and "samesite=lax" not in set_cookie.lower():
                vulns.append({
                    "type": "Missing SameSite Cookie",
                    "severity": "MEDIUM",
                    "detail": "Cookie缺少SameSite属性",
                    "cookie": set_cookie[:100]
                })

        # 检查Referer验证
        # 发送无Referer的请求测试
        if method.upper() == "POST":
            try:
                no_referer_resp = requests.post(
                    url, 
                    data={"test": "test"}, 
                    headers={"Referer": ""},
                    timeout=10, 
                    verify=get_verify_ssl()
                )
                if no_referer_resp.status_code == 200:
                    vulns.append({
                        "type": "No Referer Validation",
                        "severity": "MEDIUM",
                        "detail": "服务器不验证Referer头",
                        "url": url
                    })
            except Exception:
                logger.warning("Suppressed exception", exc_info=True)

    except Exception:
        logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "csrf_vulns": vulns,
        "total": len(vulns),
        "recommendations": [
            "实施CSRF Token机制",
            "设置Cookie的SameSite属性",
            "验证Origin/Referer头"
        ] if vulns else []
    }


# ============ CORS深度检测 ============

CORS_TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://example.com.evil.com",
    "https://evil.example.com",
    "http://localhost",
    "https://evil%00.com",
]


def cors_deep_check(url: str) -> dict:
    """CORS深度检测 - 跨域资源共享配置检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    parsed = urlparse(url)
    trusted_origin = f"{parsed.scheme}://{parsed.netloc}"

    for test_origin in CORS_TEST_ORIGINS:
        try:
            headers = {"Origin": test_origin}
            resp = requests.get(url, headers=headers, timeout=10, verify=get_verify_ssl())
            
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            # 检查反射Origin
            if acao == test_origin:
                severity = "CRITICAL" if acac == "true" else "HIGH"
                vulns.append({
                    "type": "CORS Origin Reflection",
                    "severity": severity,
                    "origin": test_origin,
                    "acao": acao,
                    "credentials": acac == "true",
                    "detail": f"服务器反射了恶意Origin: {test_origin}"
                })

            # 检查通配符
            elif acao == "*":
                if acac == "true":
                    vulns.append({
                        "type": "CORS Wildcard with Credentials",
                        "severity": "CRITICAL",
                        "detail": "CORS配置允许任意来源且携带凭证"
                    })
                else:
                    vulns.append({
                        "type": "CORS Wildcard",
                        "severity": "MEDIUM",
                        "detail": "CORS配置允许任意来源"
                    })

            # 检查null origin
            elif test_origin == "null" and acao == "null":
                vulns.append({
                    "type": "CORS Null Origin",
                    "severity": "HIGH",
                    "detail": "服务器接受null Origin，可能被iframe利用"
                })

        except Exception:
            logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "cors_vulns": vulns,
        "total": len(vulns),
        "recommendations": [
            "配置明确的白名单Origin",
            "避免使用通配符*",
            "谨慎启用Allow-Credentials",
            "不要接受null Origin"
        ] if vulns else []
    }


# ============ 安全头检测 ============

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HTTP严格传输安全",
        "recommendation": "设置 Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "内容安全策略",
        "recommendation": "配置严格的CSP策略"
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "点击劫持防护",
        "recommendation": "设置 X-Frame-Options: DENY 或 SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "MIME类型嗅探防护",
        "recommendation": "设置 X-Content-Type-Options: nosniff"
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "XSS过滤器（已弃用但仍有用）",
        "recommendation": "设置 X-XSS-Protection: 1; mode=block"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Referrer信息控制",
        "recommendation": "设置 Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "浏览器功能权限控制",
        "recommendation": "配置Permissions-Policy限制敏感API"
    },
}

DANGEROUS_HEADERS = {
    "Server": "泄露服务器信息",
    "X-Powered-By": "泄露技术栈信息",
    "X-AspNet-Version": "泄露.NET版本",
    "X-AspNetMvc-Version": "泄露MVC版本",
}


def security_headers_check(url: str) -> dict:
    """安全头检测 - HTTP安全响应头检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    missing_headers = []
    dangerous_headers = []
    present_headers = {}

    try:
        resp = requests.get(url, timeout=10, verify=get_verify_ssl())
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # 检查缺失的安全头
        for header, info in SECURITY_HEADERS.items():
            header_lower = header.lower()
            if header_lower in headers:
                present_headers[header] = headers[header_lower]
            else:
                missing_headers.append({
                    "header": header,
                    "severity": info["severity"],
                    "description": info["description"],
                    "recommendation": info["recommendation"]
                })

        # 检查危险的信息泄露头
        for header, description in DANGEROUS_HEADERS.items():
            header_lower = header.lower()
            if header_lower in headers:
                dangerous_headers.append({
                    "header": header,
                    "value": headers[header_lower],
                    "severity": "LOW",
                    "description": description
                })

        # 检查CSP配置问题
        csp = headers.get("content-security-policy", "")
        if csp:
            csp_issues = []
            if "unsafe-inline" in csp:
                csp_issues.append("允许unsafe-inline")
            if "unsafe-eval" in csp:
                csp_issues.append("允许unsafe-eval")
            if "data:" in csp:
                csp_issues.append("允许data:协议")
            if "*" in csp:
                csp_issues.append("使用通配符")

            if csp_issues:
                missing_headers.append({
                    "header": "Content-Security-Policy (弱配置)",
                    "severity": "MEDIUM",
                    "description": "CSP配置存在安全隐患",
                    "issues": csp_issues
                })

    except Exception:
        logger.warning("Suppressed exception", exc_info=True)

    # 计算安全分数
    total_headers = len(SECURITY_HEADERS)
    present_count = len(present_headers)
    score = int((present_count / total_headers) * 100) if total_headers > 0 else 0

    return {
        "success": True,
        "url": url,
        "security_score": score,
        "present_headers": present_headers,
        "missing_headers": missing_headers,
        "dangerous_headers": dangerous_headers,
        "total_missing": len(missing_headers),
        "total_dangerous": len(dangerous_headers)
    }


# ============ 缓存投毒检测 ============

CACHE_POISON_HEADERS = [
    ("X-Forwarded-Host", "evil.com"),
    ("X-Forwarded-Server", "evil.com"),
    ("X-Forwarded-Scheme", "https"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Host", "evil.com"),
]


def cache_poisoning_detect(url: str) -> dict:
    """缓存投毒检测 - Web缓存投毒漏洞检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    cache_indicators = ["x-cache", "cf-cache-status", "x-varnish", "age", "x-cache-hit"]

    try:
        # 获取基线响应
        baseline_resp = requests.get(url, timeout=10, verify=get_verify_ssl())
        baseline_body = baseline_resp.text

        # 检查是否有缓存
        has_cache = any(h.lower() in baseline_resp.headers for h in cache_indicators)

        for header_name, header_value in CACHE_POISON_HEADERS:
            try:
                # 添加缓存破坏参数
                import time
                cache_buster = f"{url}{'&' if '?' in url else '?'}cb={int(time.time())}"
                
                headers = {header_name: header_value}
                resp = requests.get(cache_buster, headers=headers, timeout=10, verify=get_verify_ssl())

                # 检查响应是否包含注入的值
                if header_value in resp.text and header_value not in baseline_body:
                    vulns.append({
                        "type": "Cache Poisoning",
                        "severity": "HIGH",
                        "header": header_name,
                        "value": header_value,
                        "detail": f"注入的{header_name}头被反射到响应中"
                    })

                # 检查响应头反射
                for resp_header, resp_value in resp.headers.items():
                    if header_value in resp_value:
                        vulns.append({
                            "type": "Header Injection",
                            "severity": "MEDIUM",
                            "inject_header": header_name,
                            "reflected_in": resp_header,
                            "detail": f"注入的值被反射到{resp_header}头中"
                        })

            except Exception:
                logger.warning("Suppressed exception", exc_info=True)

    except Exception:
        logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "has_cache": has_cache if 'has_cache' in dir() else False,
        "cache_vulns": vulns,
        "total": len(vulns),
        "recommendations": [
            "验证并过滤所有X-Forwarded-*头",
            "使用Cache-Control: private防止缓存敏感内容",
            "配置CDN正确处理Vary头"
        ] if vulns else []
    }


# ============ MCP工具注册 ============

def register_web_security_tools(mcp) -> None:
    """注册Web安全类检测工具到MCP服务器"""
    
    @mcp.tool()
    def csrf_detect_tool(url: str, method: str = "POST") -> dict:
        """CSRF检测 - 跨站请求伪造漏洞检测"""
        return csrf_detect(url, method)
    
    @mcp.tool()
    def cors_deep_check_tool(url: str) -> dict:
        """CORS深度检测 - 跨域资源共享配置检测"""
        return cors_deep_check(url)
    
    @mcp.tool()
    def security_headers_check_tool(url: str) -> dict:
        """安全头检测 - HTTP安全响应头检测"""
        return security_headers_check(url)
    
    @mcp.tool()
    def cache_poisoning_detect_tool(url: str) -> dict:
        """缓存投毒检测 - Web缓存投毒漏洞检测"""
        return cache_poisoning_detect(url)
    
    logger.info("已注册Web安全类漏洞检测工具: csrf, cors, security_headers, cache_poisoning")


__all__ = [
    "csrf_detect",
    "cors_deep_check",
    "security_headers_check",
    "cache_poisoning_detect",
    "register_web_security_tools",
]