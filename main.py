#!/usr/bin/env python3
"""
AutoRedTeam-Orchestrator
AI驱动的自动化红队渗透测试代理

Usage:
    python main.py scan example.com
    python main.py scan example.com --output report.json
    python main.py check-tools
"""

import asyncio
import argparse
import logging
import sys
import json
from pathlib import Path
from datetime import datetime

from core import RedTeamOrchestrator, ToolExecutor


# 配置日志
def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    
    # 控制台Handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_format = logging.Formatter(
        '%(asctime)s %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    
    # 文件Handler
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    file_handler = logging.FileHandler(
        log_dir / f"redteam_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_format)
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)


def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║     _         _        ____          _ _____                  ║
    ║    / \\  _   _| |_ ___ |  _ \\ ___  __| |_   _|__  __ _ _ __ ___║
    ║   / _ \\| | | | __/ _ \\| |_) / _ \\/ _` | | |/ _ \\/ _` | '_ ` _ \\
    ║  / ___ \\ |_| | || (_) |  _ <  __/ (_| | | |  __/ (_| | | | | | |
    ║ /_/   \\_\\__,_|\\__\\___/|_| \\_\\___|\\__,_| |_|\\___|\\__,_|_| |_| |_|
    ║                                                               ║
    ║          AI-Driven Automated Red Team Orchestrator            ║
    ║                        v1.0.0                                 ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def check_tools():
    """检查工具安装状态"""
    print("\n[*] Checking required tools...\n")
    
    executor = ToolExecutor()
    status = executor.get_tool_status()
    
    all_ok = True
    for tool, available in status.items():
        icon = "✓" if available else "✗"
        color = "\033[92m" if available else "\033[91m"
        reset = "\033[0m"
        print(f"    {color}{icon}{reset} {tool}")
        if not available:
            all_ok = False
    
    print()
    
    if not all_ok:
        print("[!] Some tools are missing. Install them with:")
        print("    sudo apt install nmap")
        print("    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        print("    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        print("    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        print("    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
        print()
        print("    Make sure ~/go/bin is in your PATH")
        return False
    
    print("[+] All tools are available!")
    return True


async def run_scan(target: str, output: str = None, config: dict = None):
    """执行扫描"""
    print(f"\n[*] Target: {target}")
    print("[*] Starting automated red team operation...\n")
    
    config = config or {}
    orchestrator = RedTeamOrchestrator(config)
    
    try:
        report = await orchestrator.run(target)
        
        # 打印摘要
        print("\n" + "=" * 60)
        print("                     SCAN SUMMARY")
        print("=" * 60)
        
        if "error" in report:
            print(f"\n[!] Scan failed: {report['error']}")
            return
        
        summary = report.get("summary", {})
        assets = report.get("assets", {})
        
        print(f"""
    Target:                 {target}
    Subdomains Discovered:  {assets.get('subdomains_discovered', 0)}
    Assets Mapped:          {assets.get('assets_mapped', 0)}
    HTTP Services:          {assets.get('http_services', 0)}
    
    Vulnerabilities Found:  {summary.get('total_findings', 0)}
    Verified:               {summary.get('verified_vulnerabilities', 0)}
    False Positives:        {summary.get('false_positives_filtered', 0)}
    
    Severity Breakdown:
      - Critical:  {summary.get('severity_breakdown', {}).get('critical', 0)}
      - High:      {summary.get('severity_breakdown', {}).get('high', 0)}
      - Medium:    {summary.get('severity_breakdown', {}).get('medium', 0)}
      - Low:       {summary.get('severity_breakdown', {}).get('low', 0)}
        """)
        
        print("=" * 60)
        
        # 显示高危漏洞
        vulns = report.get("vulnerabilities", [])
        critical_high = [v for v in vulns if v.get("severity") in ["critical", "high"]]
        
        if critical_high:
            print("\n[!] Critical/High Vulnerabilities:\n")
            for v in critical_high[:10]:  # 最多显示10个
                print(f"    [{v['severity'].upper()}] {v['name']}")
                print(f"        Target: {v['target']}")
                print(f"        Confidence: {v.get('confidence', 0):.2f}")
                print()
        
        # 保存报告
        if output:
            output_path = Path(output)
            output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
            print(f"\n[+] Report saved to: {output_path}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(
        description="AutoRedTeam-Orchestrator - AI-Driven Red Team Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s scan example.com
    %(prog)s scan example.com -o report.json -v
    %(prog)s check-tools
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # scan命令
    scan_parser = subparsers.add_parser("scan", help="Run red team scan against a target")
    scan_parser.add_argument("target", help="Target domain to scan")
    scan_parser.add_argument("-o", "--output", help="Output report file (JSON)")
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    scan_parser.add_argument("--workspace", default="/tmp/redteam", help="Workspace directory")
    scan_parser.add_argument("--timeout", type=int, default=300, help="Tool timeout (seconds)")
    
    # check-tools命令
    subparsers.add_parser("check-tools", help="Check required tools installation")
    
    # status命令
    subparsers.add_parser("status", help="Show current status")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.command == "check-tools":
        check_tools()
        
    elif args.command == "scan":
        setup_logging(args.verbose)
        
        # 先检查工具
        if not check_tools():
            print("\n[!] Please install missing tools before scanning")
            sys.exit(1)
        
        config = {
            "workspace": args.workspace,
            "timeout": args.timeout
        }
        
        asyncio.run(run_scan(args.target, args.output, config))
        
    elif args.command == "status":
        print("[*] No active scan")
        
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
