#!/usr/bin/env python3
"""
智能打点功能测试脚本
测试新增的智能侦察和深度漏洞扫描功能
"""

import sys
import os
import json
from datetime import datetime

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp_tools import (
    _intelligent_recon,
    _deep_vuln_scan,
    _js_source_analysis,
    _default_credential_test,
    _waf_bypass_test
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
║   {Colors.BOLD}🔥 智能打点功能测试{Colors.CYAN}                                            ║
║                                                                          ║
║   测试目标: https://www.dlut.edu.cn/                                     ║
║   时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                                      ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)


def test_intelligent_recon(target: str):
    """测试智能侦察"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}")
    print(f"  📡 测试1: 智能侦察引擎")
    print(f"{'='*70}{Colors.END}\n")
    
    try:
        result = _intelligent_recon({"target": target})
        
        if result.get("success"):
            print(f"{Colors.GREEN}✓ 智能侦察成功{Colors.END}")
            print(f"  发现数: {result.get('findings_count', 0)}")
            print(f"  高危发现: {result.get('high_risk_count', 0)}")
            
            # 显示部分结果
            results = result.get("results", {})
            if "attack_surface" in results:
                surface = results["attack_surface"]
                print(f"\n{Colors.CYAN}攻击面分析:{Colors.END}")
                print(f"  • 子域名: {surface.get('subdomains_count', 0)}")
                print(f"  • 开放端口: {surface.get('open_ports', [])}")
                print(f"  • API端点: {surface.get('api_endpoints_count', 0)}")
                print(f"  • 敏感文件: {surface.get('sensitive_files', 0)}")
                print(f"  • WAF: {'检测到' if surface.get('waf_detected') else '未检测到'}")
        else:
            print(f"{Colors.RED}✗ 智能侦察失败: {result.get('error')}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}✗ 测试失败: {e}{Colors.END}")


def test_deep_vuln_scan(target: str):
    """测试深度漏洞扫描"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}")
    print(f"  🎯 测试2: 深度漏洞扫描")
    print(f"{'='*70}{Colors.END}\n")
    
    try:
        result = _deep_vuln_scan({"target": target, "dnslog": "test.dnslog.cn"})
        
        if result.get("success"):
            print(f"{Colors.GREEN}✓ 漏洞扫描成功{Colors.END}")
            print(f"  漏洞数: {result.get('vuln_count', 0)}")
            print(f"  严重漏洞: {result.get('critical_count', 0)}")
            
            # 显示发现的漏洞
            vulns = result.get("vulnerabilities", [])
            if vulns:
                print(f"\n{Colors.YELLOW}发现的漏洞:{Colors.END}")
                for vuln in vulns[:5]:  # 只显示前5个
                    severity_color = Colors.RED if vuln['severity'] in ['critical', 'high'] else Colors.YELLOW
                    print(f"  {severity_color}[{vuln['severity'].upper()}]{Colors.END} {vuln['title']}")
                    print(f"    {vuln['description']}")
        else:
            print(f"{Colors.RED}✗ 漏洞扫描失败: {result.get('error')}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}✗ 测试失败: {e}{Colors.END}")


def test_js_analysis(target: str):
    """测试JS源码分析"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}")
    print(f"  📜 测试3: JS源码深度分析")
    print(f"{'='*70}{Colors.END}\n")
    
    try:
        result = _js_source_analysis({"target": target})
        
        if result.get("success"):
            print(f"{Colors.GREEN}✓ JS分析成功{Colors.END}")
            print(f"  JS文件数: {len(result.get('js_files', []))}")
            print(f"  API端点: {len(result.get('api_endpoints', []))}")
            print(f"  敏感信息: {len(result.get('sensitive_info', []))}")
            print(f"  SourceMap: {'发现' if result.get('sourcemap_found') else '未发现'}")
            
            # 显示部分API端点
            endpoints = result.get('api_endpoints', [])
            if endpoints:
                print(f"\n{Colors.CYAN}API端点示例:{Colors.END}")
                for ep in endpoints[:10]:
                    print(f"  • {ep}")
        else:
            print(f"{Colors.RED}✗ JS分析失败: {result.get('error')}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}✗ 测试失败: {e}{Colors.END}")


def test_default_credentials(target: str):
    """测试默认口令"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}")
    print(f"  🔑 测试4: 默认口令检测")
    print(f"{'='*70}{Colors.END}\n")
    
    try:
        result = _default_credential_test({"target": target, "cms_type": "common"})
        
        if result.get("success"):
            print(f"{Colors.GREEN}✓ 默认口令检测成功{Colors.END}")
            print(f"  CMS类型: {result.get('cms_type')}")
            
            creds = result.get('credentials_to_test', [])
            print(f"\n{Colors.YELLOW}建议测试的口令:{Colors.END}")
            for username, password in creds:
                print(f"  • {username} / {password}")
            
            print(f"\n{Colors.CYAN}注意: {result.get('note')}{Colors.END}")
        else:
            print(f"{Colors.RED}✗ 检测失败: {result.get('error')}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}✗ 测试失败: {e}{Colors.END}")


def test_waf_bypass(target: str):
    """测试WAF绕过"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}")
    print(f"  🛡️ 测试5: WAF绕过技巧")
    print(f"{'='*70}{Colors.END}\n")
    
    try:
        result = _waf_bypass_test({"target": target})
        
        if result.get("success"):
            print(f"{Colors.GREEN}✓ WAF检测成功{Colors.END}")
            print(f"  WAF: {result.get('waf_detected')}")
            
            techniques = result.get('bypass_techniques', [])
            print(f"\n{Colors.CYAN}绕过技巧:{Colors.END}")
            for i, tech in enumerate(techniques, 1):
                print(f"  {i}. {tech}")
        else:
            print(f"{Colors.RED}✗ 检测失败: {result.get('error')}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}✗ 测试失败: {e}{Colors.END}")


def main():
    print_banner()
    
    target = "https://www.dlut.edu.cn/"
    
    # 测试1: 智能侦察
    test_intelligent_recon(target)
    
    # 测试2: 深度漏洞扫描
    test_deep_vuln_scan(target)
    
    # 测试3: JS源码分析
    test_js_analysis(target)
    
    # 测试4: 默认口令
    test_default_credentials(target)
    
    # 测试5: WAF绕过
    test_waf_bypass(target)
    
    # 总结
    print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*70}")
    print(f"  ✅ 所有测试完成")
    print(f"{'='*70}{Colors.END}\n")
    
    print(f"{Colors.CYAN}新增功能总结:{Colors.END}")
    print(f"  • 智能侦察引擎 - 8个阶段全面分析")
    print(f"  • 深度漏洞扫描 - 7种实战漏洞检测")
    print(f"  • JS源码分析 - API/敏感信息挖掘")
    print(f"  • 默认口令库 - 常见OA/CMS系统")
    print(f"  • WAF绕过技巧 - 9种绕过方法")
    print()


if __name__ == "__main__":
    main()
