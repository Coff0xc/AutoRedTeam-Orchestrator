#!/usr/bin/env python3
"""
DLUT.edu.cn 全面侦察测试脚本
测试 MCP 红队工具的能力
"""

import sys
import os
import time
import json
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp_tools import (
    run_cmd, 
    run_cmd_with_progress, 
    ProgressBar,
    _dns_enum,
    _subdomain_enum,
    _httpx_probe,
    _wafw00f,
    _google_dork,
    _nmap_scan
)

# 颜色定义
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   {Colors.BOLD}🔥 AI Red Team MCP - 目标侦察测试{Colors.CYAN}                              ║
║                                                                          ║
║   目标: https://www.dlut.edu.cn/                                         ║
║   时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                                      ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)

def print_section(title):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}")
    print(f"  📌 {title}")
    print(f"{'='*70}{Colors.END}\n")

def print_result(name, result, show_detail=True):
    if result.get("success", False):
        print(f"{Colors.GREEN}✓ {name}: 成功{Colors.END}")
        if show_detail and result.get("stdout"):
            lines = result["stdout"].strip().split('\n')[:20]  # 只显示前20行
            for line in lines:
                print(f"  {Colors.WHITE}{line}{Colors.END}")
            if len(result["stdout"].strip().split('\n')) > 20:
                print(f"  {Colors.YELLOW}... (更多结果省略){Colors.END}")
    else:
        print(f"{Colors.RED}✗ {name}: 失败 - {result.get('error', '未知错误')}{Colors.END}")

def test_whois(domain):
    """Whois查询"""
    print(f"{Colors.YELLOW}[*] 正在执行 Whois 查询...{Colors.END}")
    result = run_cmd_with_progress(["whois", domain], "whois", domain, 30)
    return result

def test_dns(domain):
    """DNS枚举"""
    print(f"{Colors.YELLOW}[*] 正在执行 DNS 枚举...{Colors.END}")
    result = _dns_enum({"domain": domain})
    return result

def test_subdomain(domain):
    """子域名枚举"""
    print(f"{Colors.YELLOW}[*] 正在枚举子域名...{Colors.END}")
    result = _subdomain_enum({"domain": domain})
    return result

def test_whatweb(url):
    """WhatWeb扫描"""
    print(f"{Colors.YELLOW}[*] 正在执行 WhatWeb 技术栈识别...{Colors.END}")
    result = run_cmd_with_progress(["whatweb", "-a", "3", url], "whatweb", url, 60)
    return result

def test_wafw00f(url):
    """WAF检测"""
    print(f"{Colors.YELLOW}[*] 正在检测 WAF...{Colors.END}")
    result = _wafw00f({"target": url})
    return result

def test_httpx(url):
    """Httpx探测"""
    print(f"{Colors.YELLOW}[*] 正在执行 Httpx 探测...{Colors.END}")
    result = _httpx_probe({"targets": url})
    return result

def test_nmap(target):
    """Nmap端口扫描"""
    print(f"{Colors.YELLOW}[*] 正在执行 Nmap 端口扫描...{Colors.END}")
    result = _nmap_scan({"target": target, "scan_type": "quick", "ports": "21,22,25,53,80,110,143,443,445,3306,3389,8080,8443"})
    return result

def test_curl(url):
    """HTTP头信息"""
    print(f"{Colors.YELLOW}[*] 正在获取 HTTP 头信息...{Colors.END}")
    result = run_cmd(["curl", "-sI", "-L", "--max-time", "10", url], 15)
    return result

def test_dig(domain):
    """DIG查询"""
    print(f"{Colors.YELLOW}[*] 正在执行 DIG 查询...{Colors.END}")
    result = run_cmd(["dig", domain, "+noall", "+answer"], 30)
    return result

def test_sslscan(host):
    """SSL扫描"""
    print(f"{Colors.YELLOW}[*] 正在执行 SSL 扫描...{Colors.END}")
    result = run_cmd_with_progress(["sslscan", "--no-colour", host], "sslscan", host, 60)
    return result

def generate_report(results, domain, url):
    """生成测试报告"""
    report = {
        "target": {
            "domain": domain,
            "url": url
        },
        "scan_time": datetime.now().isoformat(),
        "results": results,
        "summary": {
            "total_tests": len(results),
            "successful": sum(1 for r in results.values() if r.get("success", False)),
            "failed": sum(1 for r in results.values() if not r.get("success", False))
        }
    }
    
    # 保存报告
    report_file = f"/home/kali/Desktop/ai-recon-mcp/reports/dlut_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    os.makedirs(os.path.dirname(report_file), exist_ok=True)
    
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    
    return report_file

def main():
    print_banner()
    
    target_url = "https://www.dlut.edu.cn/"
    target_domain = "dlut.edu.cn"
    
    results = {}
    
    # ========== 阶段1: 基础信息收集 ==========
    print_section("阶段1: 基础信息收集")
    
    # 1. Whois
    results["whois"] = test_whois(target_domain)
    print_result("Whois", results["whois"], show_detail=False)
    
    # 2. DNS枚举
    results["dns"] = test_dns(target_domain)
    if results["dns"].get("success"):
        print(f"{Colors.GREEN}✓ DNS枚举: 成功{Colors.END}")
        for rtype, records in results["dns"].get("records", {}).items():
            if records:
                print(f"  {Colors.CYAN}{rtype}: {Colors.WHITE}{', '.join(records[:5])}{Colors.END}")
    else:
        print(f"{Colors.RED}✗ DNS枚举: 失败{Colors.END}")
    
    # 3. DIG查询
    results["dig"] = test_dig(target_domain)
    print_result("DIG", results["dig"])
    
    # ========== 阶段2: 子域名枚举 ==========
    print_section("阶段2: 子域名枚举")
    
    results["subdomain"] = test_subdomain(target_domain)
    if results["subdomain"].get("success"):
        subs = results["subdomain"].get("subdomains", [])
        print(f"{Colors.GREEN}✓ 子域名枚举: 发现 {len(subs)} 个子域名{Colors.END}")
        for sub in subs[:15]:  # 只显示前15个
            print(f"  {Colors.WHITE}• {sub}{Colors.END}")
        if len(subs) > 15:
            print(f"  {Colors.YELLOW}... 还有 {len(subs)-15} 个子域名{Colors.END}")
    else:
        print(f"{Colors.RED}✗ 子域名枚举: 失败{Colors.END}")
    
    # ========== 阶段3: Web技术栈识别 ==========
    print_section("阶段3: Web技术栈识别")
    
    # 4. HTTP头信息
    results["http_headers"] = test_curl(target_url)
    print_result("HTTP头信息", results["http_headers"])
    
    # 5. WhatWeb
    results["whatweb"] = test_whatweb(target_url)
    print_result("WhatWeb", results["whatweb"])
    
    # 6. Httpx探测
    results["httpx"] = test_httpx(target_url)
    if results["httpx"].get("success"):
        print(f"{Colors.GREEN}✓ Httpx探测: 成功{Colors.END}")
        for r in results["httpx"].get("results", []):
            print(f"  {Colors.WHITE}URL: {r.get('url', 'N/A')}")
            print(f"  状态码: {r.get('status_code', 'N/A')}")
            print(f"  标题: {r.get('title', 'N/A')}{Colors.END}")
    else:
        print(f"{Colors.RED}✗ Httpx探测: 失败{Colors.END}")
    
    # ========== 阶段4: 安全检测 ==========
    print_section("阶段4: 安全检测")
    
    # 7. WAF检测
    results["wafw00f"] = test_wafw00f(target_url)
    print_result("WAF检测", results["wafw00f"])
    
    # 8. SSL扫描
    results["sslscan"] = test_sslscan("www.dlut.edu.cn:443")
    print_result("SSL扫描", results["sslscan"], show_detail=False)
    
    # ========== 阶段5: 端口扫描 ==========
    print_section("阶段5: 端口扫描")
    
    # 9. Nmap
    results["nmap"] = test_nmap("www.dlut.edu.cn")
    print_result("Nmap扫描", results["nmap"])
    
    # ========== 阶段6: Google Dorks ==========
    print_section("阶段6: Google Dorks 生成")
    
    dorks = _google_dork({"domain": target_domain, "dork_type": "all"})
    results["google_dorks"] = dorks
    if dorks.get("success"):
        print(f"{Colors.GREEN}✓ Google Dorks 生成: 成功{Colors.END}")
        for dork in dorks.get("dorks", [])[:10]:
            print(f"  {Colors.WHITE}• {dork}{Colors.END}")
    
    # ========== 生成报告 ==========
    print_section("测试报告")
    
    report_file = generate_report(results, target_domain, target_url)
    
    # 统计
    total = len(results)
    success = sum(1 for r in results.values() if r.get("success", False))
    failed = total - success
    
    print(f"{Colors.BOLD}📊 测试统计:{Colors.END}")
    print(f"  • 总测试数: {total}")
    print(f"  • {Colors.GREEN}成功: {success}{Colors.END}")
    print(f"  • {Colors.RED}失败: {failed}{Colors.END}")
    print(f"\n📄 报告已保存: {Colors.CYAN}{report_file}{Colors.END}")
    
    # 问题总结
    print(f"\n{Colors.BOLD}{Colors.YELLOW}⚠️ 发现的问题和优化建议:{Colors.END}")
    
    issues = []
    if not results.get("subdomain", {}).get("success"):
        issues.append("subfinder 子域名枚举工具可能未安装或配置问题")
    if not results.get("whatweb", {}).get("success"):
        issues.append("whatweb 工具可能未安装")
    if not results.get("wafw00f", {}).get("success"):
        issues.append("wafw00f 工具可能未安装")
    if not results.get("httpx", {}).get("success"):
        issues.append("httpx 工具可能未安装或网络问题")
    if not results.get("sslscan", {}).get("success"):
        issues.append("sslscan 工具可能未安装")
    if not results.get("nmap", {}).get("success"):
        issues.append("nmap 扫描需要 sudo 权限或工具未安装")
    
    if issues:
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {Colors.YELLOW}{issue}{Colors.END}")
    else:
        print(f"  {Colors.GREEN}所有工具运行正常!{Colors.END}")
    
    print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}测试完成!{Colors.END}")


if __name__ == "__main__":
    main()
