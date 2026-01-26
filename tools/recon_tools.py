#!/usr/bin/env python3
"""
侦察工具模块 - 信息收集相关功能
包含: 端口扫描、DNS查询、HTTP探测、子域名枚举、目录扫描、技术栈识别等
"""
import logging

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin

from ._common import (
    GLOBAL_CONFIG, HAS_REQUESTS, HAS_DNS,
    COMMON_DIRS, COMMON_SUBDOMAINS, SENSITIVE_FILES,
    get_verify_ssl, check_target_reachable, check_tool, run_cmd
)

# 可选依赖
if HAS_REQUESTS:
    import requests
if HAS_DNS:
    import dns.resolver


def register_recon_tools(mcp):
    """注册所有侦察工具到 MCP 服务器"""

    @mcp.tool()
    def port_scan(target: str, ports: str = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443", threads: int = 50) -> dict:
        """端口扫描 - 并发版本，大幅提升扫描速度"""
        results = {"target": target, "open_ports": [], "closed_ports": [], "scan_time": 0}
        port_list = [int(p.strip()) for p in ports.split(",")]
        threads = min(threads, GLOBAL_CONFIG["max_threads"])

        def scan_single_port(port: int) -> tuple:
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
            try:
                ip = socket.gethostbyname(domain)
                return {"success": True, "domain": domain, "type": "A", "records": [ip]}
            except Exception as e:
                return {"success": False, "error": str(e)}

    @mcp.tool()
    def network_check(target: str, timeout: int = 10) -> dict:
        """网络可达性检测 - 在开始扫描前检查目标是否可访问"""
        result = check_target_reachable(target, timeout=timeout)

        if not result["reachable"]:
            result["proxy_hint"] = "配置代理: set_proxy('http://127.0.0.1:7890')"
            result["config_hint"] = "禁用SSL验证: set_config(verify_ssl=False)"
        else:
            result["proxy_hint"] = None
            result["config_hint"] = None
            result["message"] = f"目标可达，HTTP状态码: {result['status']}"

        return result

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

    @mcp.tool()
    def ssl_info(host: str, port: int = 443) -> dict:
        """SSL证书信息 - 纯Python实现"""
        import ssl
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
        if check_tool("whois"):
            return run_cmd(["whois", target], 30)

        try:
            import whois
            w = whois.whois(target)
            return {"success": True, "data": str(w)}
        except ImportError:
            return {"success": False, "error": "需要安装 python-whois: pip install python-whois"}
        except Exception as e:
            return {"success": False, "error": str(e)}

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

    @mcp.tool()
    def dir_bruteforce(url: str, threads: int = 10) -> dict:
        """目录扫描 - 纯Python实现，内置字典"""
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        base_url = url.rstrip('/')
        found = []
        checked = 0

        def check_path(path):
            try:
                test_url = urljoin(base_url + "/", path)
                resp = requests.get(test_url, timeout=5, verify=get_verify_ssl(), allow_redirects=False)
                if resp.status_code in [200, 301, 302, 403]:
                    return {"path": path, "url": test_url, "status": resp.status_code, "size": len(resp.content)}
            except (requests.RequestException, OSError):
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_path, path): path for path in COMMON_DIRS}
            for future in as_completed(futures):
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

        def check_subdomain(sub):
            try:
                full_domain = f"{sub}.{domain}"
                ip = socket.gethostbyname(full_domain)
                return {"subdomain": full_domain, "ip": ip}
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in COMMON_SUBDOMAINS}
            for future in as_completed(futures):
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

        # 尝试导入响应过滤器
        try:
            from core.response_filter import get_response_filter
            resp_filter = get_response_filter()
            resp_filter.calibrate(url)
        except ImportError:
            resp_filter = None

        base_url = url.rstrip('/')
        found = []
        filtered_count = 0

        def check_file(path):
            nonlocal filtered_count
            try:
                test_url = urljoin(base_url + "/", path)
                resp = requests.get(test_url, timeout=5, verify=get_verify_ssl(), allow_redirects=False)
                if resp.status_code == 200:
                    content = resp.text
                    content_type = resp.headers.get('Content-Type', '')

                    if resp_filter:
                        validation = resp_filter.validate_sensitive_file(
                            test_url, content, path, resp.status_code, content_type
                        )
                        if not validation["valid"]:
                            filtered_count += 1
                            return None
                        confidence = validation["confidence"]
                    else:
                        confidence = 0.5

                    return {
                        "path": path,
                        "url": test_url,
                        "status": resp.status_code,
                        "size": len(resp.content),
                        "content_type": content_type,
                        "confidence": confidence,
                        "preview": content[:200] if len(content) > 0 else ""
                    }
            except (requests.RequestException, OSError):
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_file, f): f for f in SENSITIVE_FILES}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        found.sort(key=lambda x: x.get("confidence", 0), reverse=True)

        return {
            "success": True,
            "url": base_url,
            "sensitive_files": found,
            "total_checked": len(SENSITIVE_FILES),
            "filtered_spa_fallback": filtered_count
        }

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

        if target.startswith("http"):
            parsed = urlparse(target)
            domain = parsed.netloc
            url = target
        else:
            domain = target
            url = f"https://{target}"

        # 1. DNS查询
        try:
            results["dns"] = dns_lookup(domain)
        except (ConnectionError, TimeoutError, OSError):
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        # 2. HTTP探测
        try:
            results["http"] = http_probe(url)
        except (ConnectionError, TimeoutError, OSError):
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        # 3. SSL信息
        try:
            results["ssl"] = ssl_info(domain)
        except (ConnectionError, TimeoutError, OSError):
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        # 4. 技术栈识别
        try:
            results["tech"] = tech_detect(url)
        except (ConnectionError, TimeoutError, OSError):
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        # 5. 子域名枚举
        try:
            results["subdomains"] = subdomain_bruteforce(domain, threads=5)
        except (ConnectionError, TimeoutError, OSError):
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        # 6. 目录扫描
        try:
            results["directories"] = dir_bruteforce(url, threads=5)
        except (ConnectionError, TimeoutError, OSError):
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        # 7. 敏感文件
        try:
            results["sensitive_files"] = sensitive_scan(url, threads=5)
        except (ConnectionError, TimeoutError, OSError):
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        # 8. 端口扫描
        try:
            ip = socket.gethostbyname(domain)
            results["ports"] = port_scan(ip)
        except (ConnectionError, TimeoutError, OSError):
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        return {"success": True, "results": results}

    # 返回注册的工具列表
    return [
        "port_scan", "dns_lookup", "network_check", "http_probe",
        "ssl_info", "whois_query", "google_dorks", "dir_bruteforce",
        "subdomain_bruteforce", "sensitive_scan", "tech_detect", "full_recon"
    ]


def _extract_title(html: str) -> str:
    """提取HTML标题"""
    import re
    match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
    return match.group(1).strip() if match else ""


# ============ 独立实现函数（供任务队列异步调用） ============
# 这些函数封装了上面 @mcp.tool() 注册的功能，可以直接被 task_tools.py 导入使用

def _port_scan_impl(target: str, ports: str = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443", threads: int = 50) -> dict:
    """端口扫描实现 - 供任务队列调用"""
    port_list = [int(p.strip()) for p in ports.split(",")]
    threads = min(threads, GLOBAL_CONFIG["max_threads"])
    results = {"target": target, "open_ports": [], "closed_ports": [], "scan_time": 0}
    
    def scan_single_port(port: int) -> tuple:
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


def _full_recon_impl(target: str) -> dict:
    """完整侦察实现 - 供任务队列调用"""
    from urllib.parse import urlparse
    
    results = {
        "target": target,
        "dns": None,
        "http": None,
        "ports": None,
    }
    
    if target.startswith("http"):
        parsed = urlparse(target)
        domain = parsed.netloc
    else:
        domain = target
    
    # 1. DNS 查询
    try:
        ip = socket.gethostbyname(domain)
        results["dns"] = {"success": True, "domain": domain, "ip": ip}
    except Exception as e:
        results["dns"] = {"success": False, "error": str(e)}
    
    # 2. 端口扫描
    try:
        if results["dns"] and results["dns"].get("ip"):
            results["ports"] = _port_scan_impl(results["dns"]["ip"])
    except Exception as e:
        results["ports"] = {"success": False, "error": str(e)}
    
    # 3. HTTP 探测
    if HAS_REQUESTS:
        try:
            url = target if target.startswith("http") else f"https://{target}"
            resp = requests.get(url, timeout=10, verify=get_verify_ssl())
            results["http"] = {
                "success": True,
                "status_code": resp.status_code,
                "server": resp.headers.get("Server", "Unknown"),
                "title": _extract_title(resp.text)
            }
        except Exception as e:
            results["http"] = {"success": False, "error": str(e)}
    
    return {"success": True, "results": results}


def _subdomain_bruteforce_impl(domain: str, threads: int = 10) -> dict:
    """子域名枚举实现 - 供任务队列调用"""
    found = []
    checked = 0
    
    def check_subdomain(sub):
        try:
            full_domain = f"{sub}.{domain}"
            ip = socket.gethostbyname(full_domain)
            return {"subdomain": full_domain, "ip": ip}
        except Exception:
            return None
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in COMMON_SUBDOMAINS}
        for future in as_completed(futures):
            checked += 1
            result = future.result()
            if result:
                found.append(result)
    
    return {"success": True, "domain": domain, "found": found, "total_checked": checked}


def _dir_bruteforce_impl(url: str, threads: int = 10) -> dict:
    """目录扫描实现 - 供任务队列调用"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests"}
    
    base_url = url.rstrip('/')
    found = []
    
    def check_path(path):
        try:
            test_url = urljoin(base_url + "/", path)
            resp = requests.get(test_url, timeout=5, verify=get_verify_ssl(), allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                return {"path": path, "url": test_url, "status": resp.status_code, "size": len(resp.content)}
        except (requests.RequestException, OSError):
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path, path): path for path in COMMON_DIRS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return {"success": True, "url": base_url, "found": found, "total_checked": len(COMMON_DIRS)}


def _sensitive_scan_impl(url: str, threads: int = 10) -> dict:
    """敏感文件扫描实现 - 供任务队列调用"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests"}
    
    base_url = url.rstrip('/')
    found = []
    
    def check_file(path):
        try:
            test_url = urljoin(base_url + "/", path)
            resp = requests.get(test_url, timeout=5, verify=get_verify_ssl(), allow_redirects=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                return {
                    "path": path,
                    "url": test_url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "content_type": resp.headers.get('Content-Type', ''),
                }
        except (requests.RequestException, OSError):
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_file, f): f for f in SENSITIVE_FILES}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
    
    return {"success": True, "url": base_url, "sensitive_files": found, "total_checked": len(SENSITIVE_FILES)}


def _dns_lookup_impl(domain: str, record_type: str = "A") -> dict:
    """DNS查询实现 - 供 pentest_tools 调用"""
    if HAS_DNS:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, record_type)
            records = [str(r) for r in answers]
            return {"success": True, "domain": domain, "type": record_type, "records": records}
        except Exception as e:
            return {"success": False, "error": str(e)}
    else:
        try:
            ip = socket.gethostbyname(domain)
            return {"success": True, "domain": domain, "type": "A", "records": [ip]}
        except Exception as e:
            return {"success": False, "error": str(e)}


def _http_probe_impl(url: str) -> dict:
    """HTTP探测实现 - 供 pentest_tools 调用"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests"}
    
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


def _tech_detect_impl(url: str) -> dict:
    """技术栈识别实现 - 供 pentest_tools 调用"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests"}
    
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
        
        # CMS检测
        if "wp-content" in html or "wordpress" in html:
            tech["cms"].append("WordPress")
        if "joomla" in html:
            tech["cms"].append("Joomla")
        if "drupal" in html:
            tech["cms"].append("Drupal")
        if "thinkphp" in html or "think_template" in html:
            tech["cms"].append("ThinkPHP")
        
        # CDN检测
        if "cloudflare" in str(headers).lower():
            tech["cdn"].append("Cloudflare")
        
        return {"success": True, "url": url, "technology": tech}
    except Exception as e:
        return {"success": False, "error": str(e)}


