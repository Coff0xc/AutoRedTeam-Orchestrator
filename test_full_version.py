#!/usr/bin/env python3
"""
全量版本测试脚本 - 测试无依赖的完整功能
"""

import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.full_recon_engine import FullReconEngine
from core.full_vuln_scanner import FullVulnScanner

# 颜色
class C:
    G = '\033[92m'  # Green
    Y = '\033[93m'  # Yellow
    R = '\033[91m'  # Red
    C = '\033[96m'  # Cyan
    B = '\033[1m'   # Bold
    E = '\033[0m'   # End

def print_banner():
    print(f"""
{C.C}╔══════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   {C.B}🔥 全量智能打点系统测试{C.C}                                          ║
║                                                                          ║
║   版本: v2.2 Full Edition                                                ║
║   时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                                      ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{C.E}
""")

def test_full_recon(target):
    """测试全量侦察引擎"""
    print(f"\n{C.B}{C.Y}{'='*70}")
    print(f"  📡 测试1: 全量智能侦察引擎")
    print(f"{'='*70}{C.E}\n")
    
    try:
        engine = FullReconEngine(target)
        results = engine.run_full_scan()
        
        print(f"\n{C.G}✓ 侦察完成!{C.E}")
        print(f"\n{C.C}资产信息:{C.E}")
        assets = results.get("assets", {})
        print(f"  • IP: {assets.get('ip', 'N/A')}")
        print(f"  • 开放端口: {assets.get('open_ports', [])}")
        print(f"  • 子域名: {len(assets.get('subdomains', []))} 个")
        print(f"  • 指纹: {list(assets.get('fingerprints', {}).keys())}")
        print(f"  • 目录: {len(assets.get('directories', []))} 个")
        print(f"  • JS文件: {len(assets.get('js_files', []))} 个")
        print(f"  • API端点: {len(assets.get('api_endpoints', []))} 个")
        print(f"  • 敏感文件: {len(assets.get('sensitive_files', []))} 个")
        print(f"  • WAF: {assets.get('waf', 'N/A')}")
        
        summary = results.get("summary", {})
        print(f"\n{C.Y}漏洞摘要:{C.E}")
        print(f"  • 总数: {summary.get('total_vulnerabilities', 0)}")
        print(f"  • 高危: {summary.get('high_risk', 0)}")
        print(f"  • 中危: {summary.get('medium_risk', 0)}")
        print(f"  • 低危: {summary.get('low_risk', 0)}")
        
        return True
    except Exception as e:
        print(f"{C.R}✗ 测试失败: {e}{C.E}")
        return False

def test_full_vuln_scan(target):
    """测试全量漏洞扫描器"""
    print(f"\n{C.B}{C.Y}{'='*70}")
    print(f"  🎯 测试2: 全量深度漏洞扫描器")
    print(f"{'='*70}{C.E}\n")
    
    try:
        scanner = FullVulnScanner(target, "test.dnslog.cn")
        results = scanner.scan_all()
        
        print(f"\n{C.G}✓ 扫描完成!{C.E}")
        
        summary = results.get("summary", {})
        print(f"\n{C.C}扫描摘要:{C.E}")
        print(f"  • 总漏洞: {summary.get('total', 0)}")
        print(f"  • 严重: {summary.get('critical', 0)}")
        print(f"  • 高危: {summary.get('high', 0)}")
        print(f"  • 中危: {summary.get('medium', 0)}")
        print(f"  • 低危: {summary.get('low', 0)}")
        
        vulns = results.get("vulnerabilities", [])
        if vulns:
            print(f"\n{C.Y}发现的漏洞:{C.E}")
            for vuln in vulns[:10]:  # 只显示前10个
                severity_color = C.R if vuln['severity'] in ['critical', 'high'] else C.Y
                print(f"  {severity_color}[{vuln['severity'].upper()}]{C.E} {vuln['type']}")
                print(f"    {vuln['description']}")
        
        return True
    except Exception as e:
        print(f"{C.R}✗ 测试失败: {e}{C.E}")
        return False

def main():
    print_banner()
    
    target = "https://www.dlut.edu.cn/"
    
    results = []
    
    # 测试1: 全量侦察
    results.append(("全量侦察引擎", test_full_recon(target)))
    
    # 测试2: 全量漏洞扫描
    results.append(("全量漏洞扫描器", test_full_vuln_scan(target)))
    
    # 总结
    print(f"\n{C.B}{C.G}{'='*70}")
    print(f"  ✅ 测试总结")
    print(f"{'='*70}{C.E}\n")
    
    for name, success in results:
        status = f"{C.G}✓ 通过{C.E}" if success else f"{C.R}✗ 失败{C.E}"
        print(f"  {name}: {status}")
    
    success_count = sum(1 for _, s in results if s)
    print(f"\n  总计: {success_count}/{len(results)} 测试通过")
    
    print(f"\n{C.C}{'='*70}")
    print(f"  🎉 全量版本特性")
    print(f"{'='*70}{C.E}")
    print(f"""
  ✨ 无外部依赖 - 仅使用Python标准库
  ✨ 10阶段侦察 - 全面资产发现
  ✨ 10种漏洞检测 - 覆盖实战场景
  ✨ 28个Shiro密钥 - 完整密钥库
  ✨ 11个Log4j Payload - 多种变体
  ✨ 完整SQL注入库 - 错误/时间/布尔盲注
  ✨ XSS/XXE/SSRF/RCE - 全覆盖
  ✨ 实时进度显示 - 用户友好
  ✨ 详细漏洞报告 - 包含修复建议
  ✨ MCP协议集成 - AI对话调用
    """)

if __name__ == "__main__":
    main()
