"""
外部工具集成模块

包含工具:
- nmap_scan: Nmap端口扫描
- nuclei_scan: Nuclei漏洞扫描
- sqlmap_scan: SQLMap扫描
- gobuster_scan: Gobuster目录扫描
- subfinder_enum: Subfinder子域名枚举
- check_tools: 检查所有安全工具可用性
- help_info: 显示帮助信息
"""

import os
import shutil
import subprocess
import platform


# Python 库可用性检查
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


def check_tool(name: str) -> bool:
    """检查外部工具是否可用"""
    return shutil.which(name) is not None


def validate_cli_target(target: str) -> tuple:
    """验证CLI目标参数，防止选项注入

    Returns:
        (is_valid, error_message)
    """
    if not target:
        return False, "目标不能为空"
    # 防止CLI选项注入: 禁止以 - 或 -- 开头
    if target.startswith('-'):
        return False, f"目标不能以'-'开头 (防止CLI选项注入): {target}"
    # 检查危险字符
    dangerous = [';', '|', '&', '`', '$', '>', '<', '\n', '\r', '\x00']
    if any(c in target for c in dangerous):
        return False, f"目标包含危险字符: {target}"
    return True, None


def run_cmd(cmd: list, timeout: int = 300) -> dict:
    """跨平台命令执行 - 安全版本，避免命令注入"""
    if not cmd or not isinstance(cmd, list):
        return {"success": False, "error": "命令必须是非空列表"}

    tool = cmd[0]
    if not check_tool(tool):
        return {"success": False, "error": f"工具 {tool} 未安装。Windows用户请安装对应工具或使用WSL。"}

    # 安全检查：禁止危险字符
    dangerous_chars = [';', '|', '&', '`', '$', '>', '<', '\n', '\r', '\x00', '\t', '\x0b', '\x0c']
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


def register_external_tools(mcp):
    """注册外部工具集成到MCP服务器"""

    @mcp.tool()
    def nmap_scan(target: str, ports: str = "1-1000", scan_type: str = "quick") -> dict:
        """Nmap端口扫描 - 需要安装nmap"""
        # 安全验证: 防止CLI选项注入
        valid, err = validate_cli_target(target)
        if not valid:
            return {"success": False, "error": err}
        # 验证ports参数
        if ports.startswith('-'):
            return {"success": False, "error": "ports参数不能以'-'开头"}

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
        # 安全验证: 防止CLI选项注入
        valid, err = validate_cli_target(target)
        if not valid:
            return {"success": False, "error": err}
        # 验证severity参数
        if severity and severity.startswith('-'):
            return {"success": False, "error": "severity参数不能以'-'开头"}

        if not check_tool("nuclei"):
            return {"success": False, "error": "nuclei未安装。请从 https://github.com/projectdiscovery/nuclei 下载安装。"}

        cmd = ["nuclei", "-u", target, "-silent"]
        if severity:
            cmd.extend(["-severity", severity])
        return run_cmd(cmd, 600)

    @mcp.tool()
    def sqlmap_scan(url: str, level: int = 1, risk: int = 1) -> dict:
        """SQLMap扫描 - 需要安装sqlmap"""
        # 安全验证: 防止CLI选项注入
        valid, err = validate_cli_target(url)
        if not valid:
            return {"success": False, "error": err}

        if not check_tool("sqlmap"):
            return {"success": False, "error": "sqlmap未安装。请从 https://sqlmap.org 下载安装。"}

        cmd = ["sqlmap", "-u", url, "--batch", "--level", str(level), "--risk", str(risk)]
        return run_cmd(cmd, 300)

    @mcp.tool()
    def gobuster_scan(url: str, wordlist: str) -> dict:
        """Gobuster目录扫描 - 需要安装gobuster"""
        # 安全验证: 防止CLI选项注入
        valid, err = validate_cli_target(url)
        if not valid:
            return {"success": False, "error": err}
        # 验证wordlist路径
        if wordlist.startswith('-'):
            return {"success": False, "error": "wordlist参数不能以'-'开头"}
        if not os.path.isfile(wordlist):
            return {"success": False, "error": f"字典文件不存在: {wordlist}"}

        if not check_tool("gobuster"):
            return {"success": False, "error": "gobuster未安装。请从 https://github.com/OJ/gobuster 下载安装。"}

        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q"]
        return run_cmd(cmd, 300)

    @mcp.tool()
    def subfinder_enum(domain: str) -> dict:
        """子域名枚举 - 需要安装subfinder"""
        # 安全验证: 防止CLI选项注入
        valid, err = validate_cli_target(domain)
        if not valid:
            return {"success": False, "error": err}

        if not check_tool("subfinder"):
            return {"success": False, "error": "subfinder未安装。请从 https://github.com/projectdiscovery/subfinder 下载安装。"}

        cmd = ["subfinder", "-d", domain, "-silent"]
        return run_cmd(cmd, 300)

    @mcp.tool()
    def whatweb_scan(url: str, aggression: int = 1) -> dict:
        """WhatWeb Web指纹识别 - 需要安装whatweb

        Args:
            url: 目标URL
            aggression: 扫描强度 1(安静)-4(激进)
        """
        valid, err = validate_cli_target(url)
        if not valid:
            return {"success": False, "error": err}
        if aggression not in [1, 2, 3, 4]:
            return {"success": False, "error": "aggression必须是1-4之间的整数"}

        if not check_tool("whatweb"):
            return {"success": False, "error": "whatweb未安装。Linux: apt install whatweb | macOS: brew install whatweb"}

        cmd = ["whatweb", "-a", str(aggression), "--color=never", "-q", url]
        return run_cmd(cmd, 60)

    @mcp.tool()
    def wafw00f_scan(url: str) -> dict:
        """WAF检测 - 需要安装wafw00f

        Args:
            url: 目标URL
        """
        valid, err = validate_cli_target(url)
        if not valid:
            return {"success": False, "error": err}

        if not check_tool("wafw00f"):
            return {"success": False, "error": "wafw00f未安装。安装: pip install wafw00f 或 https://github.com/EnableSecurity/wafw00f"}

        cmd = ["wafw00f", "-a", url]
        return run_cmd(cmd, 60)

    @mcp.tool()
    def dirsearch_scan(url: str, extensions: str = "php,asp,aspx,jsp,html,js", threads: int = 10) -> dict:
        """目录扫描 - 需要安装dirsearch

        Args:
            url: 目标URL
            extensions: 文件扩展名，逗号分隔
            threads: 并发线程数
        """
        valid, err = validate_cli_target(url)
        if not valid:
            return {"success": False, "error": err}
        if extensions.startswith('-'):
            return {"success": False, "error": "extensions参数不能以'-'开头"}

        if not check_tool("dirsearch"):
            return {"success": False, "error": "dirsearch未安装。安装: pip install dirsearch 或 https://github.com/maurosoria/dirsearch"}

        cmd = ["dirsearch", "-u", url, "-e", extensions, "-t", str(threads), "--format=plain", "-q"]
        return run_cmd(cmd, 300)

    @mcp.tool()
    def ffuf_scan(url: str, wordlist: str, method: str = "GET", threads: int = 40) -> dict:
        """Ffuf模糊测试 - 需要安装ffuf

        Args:
            url: 目标URL，使用FUZZ标记模糊位置 (如 http://target.com/FUZZ)
            wordlist: 字典文件路径
            method: HTTP方法
            threads: 并发线程数
        """
        valid, err = validate_cli_target(url)
        if not valid:
            return {"success": False, "error": err}
        if wordlist.startswith('-'):
            return {"success": False, "error": "wordlist参数不能以'-'开头"}
        if not os.path.isfile(wordlist):
            return {"success": False, "error": f"字典文件不存在: {wordlist}"}
        if method.upper() not in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]:
            return {"success": False, "error": f"不支持的HTTP方法: {method}"}

        if not check_tool("ffuf"):
            return {"success": False, "error": "ffuf未安装。安装: https://github.com/ffuf/ffuf 或 go install github.com/ffuf/ffuf@latest"}

        cmd = ["ffuf", "-u", url, "-w", wordlist, "-X", method.upper(), "-t", str(threads), "-s"]
        return run_cmd(cmd, 300)

    @mcp.tool()
    def hydra_scan(target: str, service: str, userlist: str, passlist: str, port: int = None, threads: int = 16) -> dict:
        """Hydra密码爆破 - 需要安装hydra

        Args:
            target: 目标主机
            service: 服务类型 (ssh, ftp, mysql, rdp, smb, http-get等)
            userlist: 用户名字典文件路径
            passlist: 密码字典文件路径
            port: 服务端口 (默认使用服务标准端口)
            threads: 并发线程数
        """
        valid, err = validate_cli_target(target)
        if not valid:
            return {"success": False, "error": err}

        # 验证服务类型
        allowed_services = ["ssh", "ftp", "mysql", "rdp", "smb", "http-get", "http-post",
                          "http-form-get", "http-form-post", "telnet", "vnc", "postgres",
                          "mssql", "oracle", "ldap", "imap", "pop3", "smtp"]
        if service.lower() not in allowed_services:
            return {"success": False, "error": f"不支持的服务类型: {service}. 支持: {', '.join(allowed_services)}"}

        # 验证字典文件
        if userlist.startswith('-') or passlist.startswith('-'):
            return {"success": False, "error": "字典路径不能以'-'开头"}
        if not os.path.isfile(userlist):
            return {"success": False, "error": f"用户名字典不存在: {userlist}"}
        if not os.path.isfile(passlist):
            return {"success": False, "error": f"密码字典不存在: {passlist}"}

        if not check_tool("hydra"):
            return {"success": False, "error": "hydra未安装。Linux: apt install hydra | macOS: brew install hydra"}

        cmd = ["hydra", "-L", userlist, "-P", passlist, "-t", str(threads)]
        if port:
            cmd.extend(["-s", str(port)])
        cmd.extend([target, service.lower()])
        return run_cmd(cmd, 600)

    @mcp.tool()
    def sslscan_scan(target: str, port: int = 443) -> dict:
        """SSL/TLS安全扫描 - 需要安装sslscan

        Args:
            target: 目标主机
            port: HTTPS端口
        """
        valid, err = validate_cli_target(target)
        if not valid:
            return {"success": False, "error": err}

        if not check_tool("sslscan"):
            return {"success": False, "error": "sslscan未安装。Linux: apt install sslscan | macOS: brew install sslscan"}

        cmd = ["sslscan", "--no-colour", f"{target}:{port}"]
        return run_cmd(cmd, 60)

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
            "whois": "域名查询",
            "dirsearch": "目录扫描(Python)",
            "ffuf": "模糊测试",
            "sslscan": "SSL/TLS扫描"
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
            "message": "AutoRedTeam - 全自动红队渗透测试智能体 v2.6",
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
                "smart_exploit_suggest - 智能漏洞利用建议",
                "attack_chain_plan - 自动化攻击链规划",
                "poc_generator - PoC模板生成"
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
                "csrf_detect - CSRF检测",
                "ssrf_detect - SSRF检测",
                "cmd_inject_detect - 命令注入检测",
                "xxe_detect - XXE检测",
                "idor_detect - IDOR越权检测",
                "auth_bypass_detect - 认证绕过检测",
                "file_upload_detect - 文件上传漏洞检测",
                "logic_vuln_check - 逻辑漏洞检测"
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
            "api_security_tools": [
                "jwt_full_scan - JWT完整安全扫描",
                "graphql_full_scan - GraphQL完整安全扫描",
                "websocket_full_scan - WebSocket完整安全扫描",
                "cors_bypass_test - CORS绕过测试",
                "security_headers_score - 安全头评分"
            ],
            "supply_chain_tools": [
                "sbom_generate - 生成SBOM (CycloneDX/SPDX)",
                "dependency_audit - 依赖漏洞扫描",
                "cicd_security_scan - CI/CD安全扫描",
                "supply_chain_full_scan - 供应链完整扫描"
            ],
            "cloud_security_tools": [
                "k8s_full_scan - Kubernetes安全扫描",
                "grpc_full_scan - gRPC安全扫描"
            ],
            "report_formats": [
                "markdown - Markdown格式报告",
                "json - JSON格式报告"
            ],
            "coverage": {
                "owasp_top10": "SQL注入, XSS, CSRF, SSRF, XXE, IDOR等",
                "api_security": "JWT, CORS, GraphQL, WebSocket",
                "supply_chain": "SBOM, 依赖漏洞, CI/CD安全",
                "cloud_native": "Kubernetes, gRPC"
            }
        }

    return ["nmap_scan", "nuclei_scan", "sqlmap_scan", "gobuster_scan",
            "subfinder_enum", "whatweb_scan", "wafw00f_scan", "dirsearch_scan",
            "ffuf_scan", "hydra_scan", "sslscan_scan", "check_tools", "help_info"]
