#!/usr/bin/env python3
"""
公共配置和辅助函数 - 所有工具模块共享
"""

import sys
import os
import shutil
import socket
import ssl
import json
import subprocess
import platform
import re
import time
import threading
from typing import Optional
from urllib.parse import urlparse
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed

# 尝试导入可选依赖
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False

IS_WINDOWS = platform.system() == "Windows"

# ========== 全局配置 ==========
GLOBAL_CONFIG = {
    "verify_ssl": os.getenv("VERIFY_SSL", "true").lower() == "true",
    "rate_limit_delay": float(os.getenv("RATE_LIMIT_DELAY", "0.3")),
    "max_threads": int(os.getenv("MAX_THREADS", "50")),
    "request_timeout": int(os.getenv("REQUEST_TIMEOUT", "10")),
    "max_response_size": int(os.getenv("MAX_RESPONSE_SIZE", "100000")),
    "max_consecutive_failures": int(os.getenv("MAX_CONSECUTIVE_FAILURES", "3")),
}

# 全局代理配置
PROXY_CONFIG = {
    "enabled": False,
    "http": None,
    "https": None,
}

# 全局失败计数器
_failure_counter = {"count": 0, "lock": threading.Lock()}

# 速率限制器
_rate_limit_lock = threading.Lock()
_last_request_time = 0


def rate_limited(func):
    """速率限制装饰器 - 防止触发WAF/被封IP"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        global _last_request_time
        with _rate_limit_lock:
            elapsed = time.time() - _last_request_time
            delay = GLOBAL_CONFIG["rate_limit_delay"]
            if elapsed < delay:
                time.sleep(delay - elapsed)
            _last_request_time = time.time()
        return func(*args, **kwargs)
    return wrapper


def get_verify_ssl():
    """获取SSL验证配置"""
    return GLOBAL_CONFIG["verify_ssl"]


def get_proxies():
    """获取代理配置"""
    if PROXY_CONFIG["enabled"] and PROXY_CONFIG["url"]:
        return {
            "http": PROXY_CONFIG["url"],
            "https": PROXY_CONFIG["url"],
        }
    return None


def safe_execute(func, *args, timeout_sec: int = 30, default=None, **kwargs):
    """安全执行函数 - 带超时保护"""
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout_sec)
        except concurrent.futures.TimeoutError:
            return default if default is not None else {"success": False, "error": f"操作超时 ({timeout_sec}s)"}
        except Exception as e:
            return default if default is not None else {"success": False, "error": str(e)}


# ========== 网络可达性与快速失败机制 ==========

def check_target_reachable(target: str, timeout: int = 5) -> dict:
    """快速检查目标是否可达"""
    import urllib.request
    import urllib.error

    if target.startswith("http"):
        url = target
    else:
        url = f"https://{target}"

    try:
        req = urllib.request.Request(url, method='HEAD')
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"reachable": True, "status": resp.status, "error": None, "suggestions": []}
    except urllib.error.HTTPError as e:
        return {"reachable": True, "status": e.code, "error": None, "suggestions": []}
    except urllib.error.URLError as e:
        return {"reachable": False, "status": 0, "error": str(e.reason),
                "suggestions": get_network_error_suggestions(str(e.reason))}
    except Exception as e:
        return {"reachable": False, "status": 0, "error": str(e),
                "suggestions": get_network_error_suggestions(str(e))}


def get_network_error_suggestions(error_msg: str) -> list:
    """根据网络错误信息返回建议"""
    suggestions = []
    error_lower = error_msg.lower()

    if "timeout" in error_lower or "timed out" in error_lower:
        suggestions.append("目标响应超时，可能存在网络延迟或目标服务器负载过高")
        suggestions.append("尝试增加超时时间: set_config(request_timeout=30)")

    if "connection refused" in error_lower:
        suggestions.append("目标拒绝连接，可能端口未开放或被防火墙阻止")

    if "name or service not known" in error_lower or "getaddrinfo failed" in error_lower:
        suggestions.append("DNS解析失败，请检查域名是否正确")

    if "connection reset" in error_lower or "reset by peer" in error_lower:
        suggestions.append("连接被重置，可能被WAF或防火墙拦截")
        suggestions.append("尝试配置代理: set_proxy('http://127.0.0.1:7890')")

    if "ssl" in error_lower or "certificate" in error_lower:
        suggestions.append("SSL证书问题，尝试禁用SSL验证: set_config(verify_ssl=False)")

    if not suggestions:
        suggestions.append("网络连接失败，请检查网络环境")

    return suggestions


def record_failure(is_network_error: bool = False):
    """记录一次失败"""
    with _failure_counter["lock"]:
        increment = 2 if is_network_error else 1
        _failure_counter["count"] += increment


def reset_failure_counter():
    """重置失败计数器"""
    with _failure_counter["lock"]:
        _failure_counter["count"] = 0


def get_failure_count() -> int:
    """获取当前失败计数"""
    with _failure_counter["lock"]:
        return _failure_counter["count"]


def should_abort_scan() -> bool:
    """判断是否应该中止扫描"""
    return get_failure_count() >= GLOBAL_CONFIG["max_consecutive_failures"]


def safe_json_response(data: dict, max_size: int = None) -> dict:
    """确保返回值可以安全序列化为JSON"""
    if max_size is None:
        max_size = GLOBAL_CONFIG["max_response_size"]

    def _sanitize(obj, depth=0):
        if depth > 10:
            return str(obj)
        if obj is None:
            return None
        elif isinstance(obj, (str, int, float, bool)):
            return obj
        elif isinstance(obj, bytes):
            try:
                return obj.decode('utf-8', errors='replace')
            except Exception:
                return str(obj)
        elif isinstance(obj, dict):
            return {str(k): _sanitize(v, depth + 1) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [_sanitize(item, depth + 1) for item in obj]
        elif hasattr(obj, '__dict__'):
            return _sanitize(obj.__dict__, depth + 1)
        else:
            return str(obj)

    try:
        sanitized = _sanitize(data)
        json_str = json.dumps(sanitized, ensure_ascii=False, default=str)
        if len(json_str) > max_size:
            return {
                "success": sanitized.get("success", True),
                "truncated": True,
                "original_size": len(json_str),
                "message": f"响应过大({len(json_str)}字符)，已截断",
                "summary": _extract_summary(sanitized)
            }
        return sanitized
    except Exception as e:
        return {"success": False, "error": f"JSON序列化失败: {str(e)}", "raw_type": type(data).__name__}


def _extract_summary(data: dict) -> dict:
    """从大响应中提取摘要"""
    summary = {}
    for key in ["target", "success", "vulnerable", "risk_summary", "findings_count", "error"]:
        if key in data:
            summary[key] = data[key]

    if "findings" in data and isinstance(data["findings"], list):
        summary["findings_count"] = len(data["findings"])
        summary["findings_preview"] = data["findings"][:5]

    if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
        summary["vulnerabilities_count"] = len(data["vulnerabilities"])
        summary["vulnerabilities_preview"] = data["vulnerabilities"][:5]

    return summary


# ========== 渗透测试阶段定义 ==========
PENTEST_PHASES = {
    "recon": {
        "name": "信息收集",
        "checks": ["dns", "http", "tech", "subdomain", "port"],
        "timeout": 60
    },
    "vuln_basic": {
        "name": "基础漏洞扫描",
        "checks": ["dir", "sensitive", "vuln", "sqli", "xss"],
        "timeout": 90
    },
    "vuln_advanced": {
        "name": "高级漏洞检测",
        "checks": ["csrf", "ssrf", "cmd_inject", "xxe", "idor", "auth_bypass", "logic", "file_upload", "ssti", "lfi", "waf"],
        "timeout": 120
    }
}

# ========== 内置字典 ==========
COMMON_DIRS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "phpmyadmin",
    "backup", "backups", "bak", "old", "test", "dev", "api", "v1", "v2",
    ".git", ".svn", ".env", ".htaccess", "robots.txt", "sitemap.xml",
    "config", "conf", "configuration", "settings", "setup", "install",
    "upload", "uploads", "files", "images", "img", "static", "assets",
    "js", "css", "scripts", "includes", "inc", "lib", "libs",
    "admin.php", "config.php", "database.php", "db.php", "conn.php",
    "phpinfo.php", "info.php", "test.php", "shell.php", "cmd.php",
    "console", "dashboard", "panel", "manage", "manager", "management",
    "user", "users", "member", "members", "account", "accounts",
    "data", "database", "db", "sql", "mysql", "dump", "export",
    "log", "logs", "debug", "error", "errors", "tmp", "temp", "cache",
    "private", "secret", "hidden", "internal", "secure",
    "wp-content", "wp-includes", "xmlrpc.php", "readme.html",
    "server-status", "server-info", ".well-known", "actuator", "swagger",
    "api-docs", "graphql", "graphiql", "metrics", "health", "status"
]

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "blog", "dev", "test", "staging",
    "api", "app", "admin", "portal", "vpn", "remote", "secure", "shop", "store",
    "m", "mobile", "wap", "static", "cdn", "img", "images", "assets", "media",
    "video", "download", "downloads", "upload", "uploads", "files", "docs",
    "support", "help", "forum", "community", "wiki", "kb", "status", "monitor",
    "git", "gitlab", "github", "svn", "jenkins", "ci", "build", "deploy",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic", "es",
    "auth", "login", "sso", "oauth", "id", "identity", "accounts", "account",
    "pay", "payment", "billing", "invoice", "order", "orders", "cart", "checkout",
    "crm", "erp", "hr", "internal", "intranet", "extranet", "partner", "partners",
    "demo", "sandbox", "beta", "alpha", "preview", "new", "old", "legacy", "v2"
]

SENSITIVE_FILES = [
    ".git/config", ".git/HEAD", ".svn/entries", ".env", ".env.local", ".env.prod",
    "wp-config.php", "configuration.php", "config.php", "settings.php", "database.php",
    "web.config", "applicationHost.config", ".htaccess", ".htpasswd",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "backup.sql", "dump.sql", "database.sql", "db.sql", "data.sql",
    "backup.zip", "backup.tar.gz", "backup.rar", "site.zip", "www.zip",
    "id_rsa", "id_dsa", ".ssh/id_rsa", ".ssh/authorized_keys",
    "server.key", "server.crt", "ssl.key", "private.key", "certificate.crt",
    "composer.json", "package.json", "Gemfile", "requirements.txt", "pom.xml",
    "Dockerfile", "docker-compose.yml", ".dockerignore", "Vagrantfile",
    "README.md", "CHANGELOG.md", "LICENSE", "VERSION", "INSTALL",
    "error_log", "error.log", "access.log", "debug.log", "app.log",
    "adminer.php", "phpmyadmin/", "pma/", "mysql/", "myadmin/",
    "elmah.axd", "trace.axd", "Elmah.axd",
    "actuator/env", "actuator/health", "actuator/info", "actuator/mappings",
    "swagger.json", "swagger-ui.html", "api-docs", "v2/api-docs",
    ".DS_Store", "Thumbs.db", "desktop.ini",
    "main.js.map", "bundle.js.map", "app.js.map", "vendor.js.map",
    "runtime.js.map", "webpack.js.map", "polyfills.js.map", "chunk.js.map",
    "static/js/main.js.map", "assets/js/app.js.map", "_next/static/chunks/main.js.map",
    "dist/main.js.map", "build/static/js/main.js.map",
    "webpack.config.js", "webpack.mix.js", "vue.config.js", "vite.config.js",
    "next.config.js", "nuxt.config.js", ".babelrc", "tsconfig.json",
    "openapi.json", "openapi.yaml", "api/swagger.json", "docs/api.json",
    "graphql", "graphiql", "playground", "altair"
]


def check_tool(name: str) -> bool:
    """检查外部工具是否可用"""
    return shutil.which(name) is not None


def validate_cli_target(target: str) -> tuple:
    """验证CLI目标参数，防止选项注入"""
    if not target:
        return False, "目标不能为空"
    if target.startswith('-'):
        return False, f"目标不能以'-'开头 (防止CLI选项注入): {target}"
    dangerous = [';', '|', '&', '`', '$', '>', '<', '\n', '\r', '\x00']
    if any(c in target for c in dangerous):
        return False, f"目标包含危险字符: {target}"
    return True, None


def is_private_ip(ip_str: str) -> bool:
    """检查 IP 地址是否为私有/保留地址 (防止 SSRF)

    Args:
        ip_str: IP 地址字符串

    Returns:
        True 如果是私有/保留地址，False 否则
    """
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_str)
        # 检查各种私有/保留地址范围
        return (
            ip.is_private or           # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            ip.is_loopback or          # 127.0.0.0/8, ::1
            ip.is_link_local or        # 169.254.0.0/16, fe80::/10
            ip.is_multicast or         # 224.0.0.0/4, ff00::/8
            ip.is_reserved or          # 保留地址
            ip.is_unspecified or       # 0.0.0.0, ::
            str(ip).startswith('0.')   # 0.x.x.x
        )
    except ValueError:
        return True  # 无效 IP 视为不安全


def validate_target_host(hostname: str, port: int = 80, allow_private: bool = False) -> tuple:
    """验证目标主机是否安全 (防止 SSRF 攻击)

    Args:
        hostname: 主机名或 IP 地址
        port: 端口号
        allow_private: 是否允许私有 IP (默认 False)

    Returns:
        (is_safe, error_message) 元组
    """
    if not hostname:
        return False, "主机名不能为空"

    # 检查端口范围
    if not (1 <= port <= 65535):
        return False, f"无效端口: {port}"

    # 危险主机名黑名单
    dangerous_hosts = [
        'localhost', 'localhost.localdomain',
        'metadata.google.internal',  # GCP 元数据
        '169.254.169.254',           # AWS/Azure 元数据
        'metadata.internal',
    ]
    if hostname.lower() in dangerous_hosts:
        return False, f"禁止访问的主机: {hostname}"

    # 解析主机名到 IP
    try:
        resolved_ips = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not resolved_ips:
            return False, f"无法解析主机: {hostname}"

        # 检查所有解析的 IP
        for family, socktype, proto, canonname, sockaddr in resolved_ips:
            ip_str = sockaddr[0]
            if not allow_private and is_private_ip(ip_str):
                return False, f"目标解析到私有/保留 IP: {hostname} -> {ip_str}"

        return True, None

    except socket.gaierror as e:
        return False, f"DNS 解析失败: {hostname} - {e}"
    except Exception as e:
        return False, f"主机验证失败: {e}"


def run_cmd(cmd: list, timeout: int = 300) -> dict:
    """跨平台命令执行 - 安全版本"""
    if not cmd or not isinstance(cmd, list):
        return {"success": False, "error": "命令必须是非空列表"}

    tool = cmd[0]
    if not check_tool(tool):
        return {"success": False, "error": f"工具 {tool} 未安装"}

    dangerous_chars = [';', '|', '&', '`', '$', '>', '<', '\n', '\r', '\x00', '\t', '\x0b', '\x0c']
    for arg in cmd:
        if any(c in str(arg) for c in dangerous_chars):
            return {"success": False, "error": f"检测到危险字符，拒绝执行: {arg}"}

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
        return {"success": True, "stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"命令超时 ({timeout}s)"}
    except FileNotFoundError:
        return {"success": False, "error": f"工具 {tool} 未找到"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_user_agent():
    """获取随机 User-Agent"""
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ]
    import random
    return random.choice(agents)


def make_request(url: str, method: str = "GET", headers: dict = None, data: str = None,
                 timeout: int = None, verify: bool = None) -> dict:
    """统一的 HTTP 请求函数"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "requests 库未安装"}

    if timeout is None:
        timeout = GLOBAL_CONFIG["request_timeout"]
    if verify is None:
        verify = get_verify_ssl()

    default_headers = {"User-Agent": get_user_agent()}
    if headers:
        default_headers.update(headers)

    proxies = get_proxies()

    try:
        if method.upper() == "GET":
            resp = requests.get(url, headers=default_headers, timeout=timeout, verify=verify, proxies=proxies)
        elif method.upper() == "POST":
            resp = requests.post(url, headers=default_headers, data=data, timeout=timeout, verify=verify, proxies=proxies)
        elif method.upper() == "PUT":
            resp = requests.put(url, headers=default_headers, data=data, timeout=timeout, verify=verify, proxies=proxies)
        elif method.upper() == "DELETE":
            resp = requests.delete(url, headers=default_headers, timeout=timeout, verify=verify, proxies=proxies)
        elif method.upper() == "HEAD":
            resp = requests.head(url, headers=default_headers, timeout=timeout, verify=verify, proxies=proxies)
        else:
            return {"success": False, "error": f"不支持的方法: {method}"}

        return {
            "success": True,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "text": resp.text[:GLOBAL_CONFIG["max_response_size"]],
            "url": resp.url,
        }
    except requests.exceptions.Timeout:
        return {"success": False, "error": "请求超时"}
    except requests.exceptions.ConnectionError as e:
        return {"success": False, "error": f"连接错误: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
