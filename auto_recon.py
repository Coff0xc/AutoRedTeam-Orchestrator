#!/usr/bin/env python3
"""
智能自动化打点系统 - AI驱动的全自动渗透测试
根据目标自动执行完整的侦察和漏洞发现流程
"""

import subprocess
import json
import sys
import time
import threading
import re
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==================== 进度显示系统 ====================

class ReconProgress:
    """智能打点进度显示"""
    
    def __init__(self):
        self.current_phase = ""
        self.current_tool = ""
        self.overall_progress = 0
        self.findings = []
        self.running = False
        self._lock = threading.Lock()
    
    def start(self):
        self.running = True
        self.start_time = time.time()
        self._print_banner()
    
    def _print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════╗
║         🔍 AI智能自动打点系统 - Auto Recon Engine           ║
╠══════════════════════════════════════════════════════════════╣
║  Phase 1: 信息收集 → Phase 2: 服务识别 → Phase 3: 漏洞扫描  ║
║  Phase 4: Web分析  → Phase 5: 深度扫描 → Phase 6: 报告生成  ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(banner)
    
    def update_phase(self, phase: str, tool: str = "", progress: int = 0):
        with self._lock:
            self.current_phase = phase
            self.current_tool = tool
            self.overall_progress = progress
            self._display()
    
    def add_finding(self, finding: Dict):
        with self._lock:
            self.findings.append(finding)
            self._display_finding(finding)
    
    def _display(self):
        elapsed = time.time() - self.start_time
        bar = self._make_bar(self.overall_progress)
        status = f"\r⚡ [{self.current_phase}] {self.current_tool} {bar} {self.overall_progress}% | 用时: {elapsed:.1f}s"
        sys.stderr.write(status + " " * 20)
        sys.stderr.flush()
    
    def _make_bar(self, progress: int) -> str:
        filled = int(progress / 5)
        empty = 20 - filled
        return f"[{'█' * filled}{'░' * empty}]"
    
    def _display_finding(self, finding: Dict):
        severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
        icon = severity_icons.get(finding.get("severity", "info"), "⚪")
        print(f"\n  {icon} 发现: {finding.get('type', 'unknown')} - {finding.get('detail', '')}")
    
    def complete(self):
        self.running = False
        elapsed = time.time() - self.start_time
        print(f"\n\n✅ 智能打点完成 | 总用时: {elapsed:.1f}s | 发现: {len(self.findings)} 项")


# ==================== 智能决策引擎 ====================

class IntelligentDecisionEngine:
    """AI决策引擎 - 根据发现动态调整扫描策略"""
    
    def __init__(self):
        self.discovered_services = {}
        self.discovered_ports = []
        self.discovered_vulns = []
        self.web_targets = []
        self.attack_surface = {}
    
    def analyze_nmap_result(self, result: Dict) -> List[Dict]:
        """分析Nmap结果，决定下一步动作"""
        actions = []
        
        output = result.get("stdout", "")
        
        # 解析开放端口和服务
        port_pattern = r"(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?"
        for match in re.finditer(port_pattern, output):
            port = int(match.group(1))
            service = match.group(2)
            version = match.group(3) or ""
            
            self.discovered_ports.append(port)
            self.discovered_services[port] = {"service": service, "version": version}
            
            # 根据服务类型决定后续动作
            if service in ["http", "https", "http-proxy"]:
                self.web_targets.append(port)
                actions.append({"action": "web_scan", "port": port, "priority": "high"})
            elif service == "ssh":
                actions.append({"action": "ssh_audit", "port": port, "priority": "medium"})
            elif service in ["mysql", "postgresql", "mssql"]:
                actions.append({"action": "db_scan", "port": port, "service": service, "priority": "high"})
            elif service in ["smb", "microsoft-ds", "netbios-ssn"]:
                actions.append({"action": "smb_scan", "port": port, "priority": "high"})
            elif service == "ftp":
                actions.append({"action": "ftp_scan", "port": port, "priority": "medium"})
            elif service in ["ldap", "ldaps"]:
                actions.append({"action": "ldap_scan", "port": port, "priority": "medium"})
            elif service == "snmp":
                actions.append({"action": "snmp_scan", "port": port, "priority": "medium"})
        
        return actions
    
    def get_web_scan_tools(self, port: int) -> List[str]:
        """获取Web扫描工具列表"""
        return ["whatweb", "wafw00f", "dir_scan", "nikto", "nuclei"]
    
    def prioritize_actions(self, actions: List[Dict]) -> List[Dict]:
        """按优先级排序动作"""
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(actions, key=lambda x: priority_order.get(x.get("priority", "low"), 4))
    
    def generate_attack_surface(self) -> Dict:
        """生成攻击面分析"""
        return {
            "total_ports": len(self.discovered_ports),
            "open_ports": self.discovered_ports,
            "services": self.discovered_services,
            "web_targets": self.web_targets,
            "potential_vectors": self._identify_attack_vectors()
        }
    
    def _identify_attack_vectors(self) -> List[Dict]:
        """识别潜在攻击向量"""
        vectors = []
        
        for port, info in self.discovered_services.items():
            service = info["service"]
            version = info["version"]
            
            if service in ["http", "https"]:
                vectors.append({"type": "Web应用攻击", "target": f"port {port}", "techniques": ["SQLi", "XSS", "目录遍历", "文件上传"]})
            elif service == "ssh":
                vectors.append({"type": "SSH攻击", "target": f"port {port}", "techniques": ["密码爆破", "密钥泄露", "CVE利用"]})
            elif service in ["smb", "microsoft-ds"]:
                vectors.append({"type": "SMB攻击", "target": f"port {port}", "techniques": ["空会话枚举", "密码喷洒", "EternalBlue"]})
            elif service in ["mysql", "postgresql", "mssql"]:
                vectors.append({"type": "数据库攻击", "target": f"port {port}", "techniques": ["默认凭证", "SQL注入", "提权"]})
        
        return vectors


# ==================== 自动化打点引擎 ====================

class AutoReconEngine:
    """自动化打点引擎 - 完整渗透测试流程"""
    
    def __init__(self, target: str, options: Dict = None):
        self.target = target
        self.options = options or {}
        self.progress = ReconProgress()
        self.decision_engine = IntelligentDecisionEngine()
        self.results = {
            "target": target,
            "start_time": None,
            "end_time": None,
            "phases": {},
            "findings": [],
            "attack_surface": {},
            "recommendations": []
        }
        self.executor = ThreadPoolExecutor(max_workers=5)
    
    def run(self) -> Dict:
        """执行完整的自动化打点"""
        self.results["start_time"] = datetime.now().isoformat()
        self.progress.start()
        
        try:
            # Phase 1: 主机发现和端口扫描
            self._phase1_discovery()
            
            # Phase 2: 服务识别和版本检测
            self._phase2_service_detection()
            
            # Phase 3: 漏洞扫描
            self._phase3_vuln_scan()
            
            # Phase 4: Web应用分析
            self._phase4_web_analysis()
            
            # Phase 5: 深度扫描
            self._phase5_deep_scan()
            
            # Phase 6: 生成报告
            self._phase6_report()
            
        except Exception as e:
            print(f"\n❌ 错误: {e}")
        
        self.progress.complete()
        self.results["end_time"] = datetime.now().isoformat()
        
        return self.results
    
    def _run_cmd(self, cmd: List[str], timeout: int = 300) -> Dict:
        """执行命令"""
        try:
            # 检查是否需要sudo
            if cmd[0] in ["nmap", "masscan"]:
                cmd = ["sudo"] + cmd
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {"success": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "超时"}
        except FileNotFoundError:
            return {"success": False, "error": f"工具未安装: {cmd[0]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _phase1_discovery(self):
        """Phase 1: 主机发现和端口扫描"""
        self.progress.update_phase("Phase 1: 主机发现", "nmap", 5)
        
        # 快速端口扫描
        self.progress.update_phase("Phase 1: 端口扫描", "nmap -T4 -F", 10)
        result = self._run_cmd(["nmap", "-T4", "-F", "--open", self.target], 120)
        
        if result["success"]:
            self.results["phases"]["discovery"] = result
            actions = self.decision_engine.analyze_nmap_result(result)
            
            for port in self.decision_engine.discovered_ports:
                service = self.decision_engine.discovered_services.get(port, {})
                self.progress.add_finding({
                    "type": "开放端口",
                    "severity": "info",
                    "detail": f"Port {port} - {service.get('service', 'unknown')}"
                })
        
        self.progress.update_phase("Phase 1: 完成", "", 15)
    
    def _phase2_service_detection(self):
        """Phase 2: 服务识别和版本检测"""
        if not self.decision_engine.discovered_ports:
            return
        
        self.progress.update_phase("Phase 2: 服务识别", "nmap -sV", 20)
        
        ports = ",".join(map(str, self.decision_engine.discovered_ports))
        result = self._run_cmd(["nmap", "-sV", "-sC", "-p", ports, self.target], 300)
        
        if result["success"]:
            self.results["phases"]["service_detection"] = result
            self.decision_engine.analyze_nmap_result(result)
            
            # 检测版本信息中的潜在漏洞
            for port, info in self.decision_engine.discovered_services.items():
                version = info.get("version", "")
                if version:
                    self.progress.add_finding({
                        "type": "服务版本",
                        "severity": "info",
                        "detail": f"Port {port}: {info['service']} {version}"
                    })
        
        self.progress.update_phase("Phase 2: 完成", "", 30)
    
    def _phase3_vuln_scan(self):
        """Phase 3: 漏洞扫描"""
        self.progress.update_phase("Phase 3: 漏洞扫描", "nuclei", 35)
        
        # 对所有发现的服务进行漏洞扫描
        targets_scanned = []
        
        # Nuclei扫描
        for port in self.decision_engine.web_targets:
            scheme = "https" if port == 443 else "http"
            target_url = f"{scheme}://{self.target}:{port}"
            
            self.progress.update_phase("Phase 3: 漏洞扫描", f"nuclei -> {target_url}", 40)
            result = self._run_cmd(["nuclei", "-u", target_url, "-severity", "medium,high,critical", "-silent", "-json"], 300)
            
            if result["success"] and result["stdout"]:
                for line in result["stdout"].split('\n'):
                    if line.strip():
                        try:
                            vuln = json.loads(line)
                            self.decision_engine.discovered_vulns.append(vuln)
                            self.progress.add_finding({
                                "type": "漏洞",
                                "severity": vuln.get("info", {}).get("severity", "info"),
                                "detail": vuln.get("info", {}).get("name", "Unknown")
                            })
                        except:
                            pass
        
        # SSH审计
        if 22 in self.decision_engine.discovered_ports:
            self.progress.update_phase("Phase 3: SSH审计", "ssh-audit", 45)
            result = self._run_cmd(["ssh-audit", f"{self.target}:22"], 60)
            if result["success"]:
                self.results["phases"]["ssh_audit"] = result
        
        self.results["phases"]["vuln_scan"] = {"vulns_found": len(self.decision_engine.discovered_vulns)}
        self.progress.update_phase("Phase 3: 完成", "", 50)
    
    def _phase4_web_analysis(self):
        """Phase 4: Web应用分析"""
        if not self.decision_engine.web_targets:
            self.progress.update_phase("Phase 4: 跳过", "无Web服务", 60)
            return
        
        self.progress.update_phase("Phase 4: Web分析", "", 55)
        
        for port in self.decision_engine.web_targets:
            scheme = "https" if port == 443 else "http"
            target_url = f"{scheme}://{self.target}:{port}"
            
            # WhatWeb - 技术识别
            self.progress.update_phase("Phase 4: 技术识别", f"whatweb -> {target_url}", 57)
            result = self._run_cmd(["whatweb", "-a", "3", target_url], 60)
            if result["success"]:
                self.results["phases"].setdefault("web_analysis", {})["whatweb"] = result
            
            # WAF检测
            self.progress.update_phase("Phase 4: WAF检测", f"wafw00f -> {target_url}", 60)
            result = self._run_cmd(["wafw00f", target_url], 30)
            if result["success"]:
                if "is behind" in result["stdout"].lower():
                    self.progress.add_finding({
                        "type": "WAF检测",
                        "severity": "medium",
                        "detail": "检测到WAF保护"
                    })
            
            # 目录扫描
            self.progress.update_phase("Phase 4: 目录扫描", f"gobuster -> {target_url}", 65)
            result = self._run_cmd([
                "gobuster", "dir", "-u", target_url, 
                "-w", "/usr/share/wordlists/dirb/common.txt",
                "-t", "20", "-q", "--no-error"
            ], 180)
            
            if result["success"] and result["stdout"]:
                dirs_found = len([l for l in result["stdout"].split('\n') if l.strip()])
                if dirs_found > 0:
                    self.progress.add_finding({
                        "type": "目录发现",
                        "severity": "info",
                        "detail": f"发现 {dirs_found} 个目录/文件"
                    })
                self.results["phases"].setdefault("web_analysis", {})["dir_scan"] = result
        
        self.progress.update_phase("Phase 4: 完成", "", 70)
    
    def _phase5_deep_scan(self):
        """Phase 5: 深度扫描（基于发现的服务）"""
        self.progress.update_phase("Phase 5: 深度扫描", "", 75)
        
        # SMB枚举
        if any(p in self.decision_engine.discovered_ports for p in [139, 445]):
            self.progress.update_phase("Phase 5: SMB枚举", "enum4linux", 77)
            result = self._run_cmd(["enum4linux", "-a", self.target], 120)
            if result["success"]:
                self.results["phases"]["smb_enum"] = result
                if "share" in result["stdout"].lower():
                    self.progress.add_finding({
                        "type": "SMB共享",
                        "severity": "medium",
                        "detail": "发现SMB共享"
                    })
        
        # SNMP枚举
        if 161 in self.decision_engine.discovered_ports:
            self.progress.update_phase("Phase 5: SNMP枚举", "snmpwalk", 80)
            result = self._run_cmd(["snmpwalk", "-v2c", "-c", "public", self.target], 60)
            if result["success"] and result["stdout"]:
                self.progress.add_finding({
                    "type": "SNMP泄露",
                    "severity": "medium",
                    "detail": "SNMP使用默认community string"
                })
        
        # Nmap漏洞脚本
        if self.decision_engine.discovered_ports:
            self.progress.update_phase("Phase 5: NSE漏洞脚本", "nmap --script vuln", 85)
            ports = ",".join(map(str, self.decision_engine.discovered_ports[:10]))  # 限制端口数量
            result = self._run_cmd(["nmap", "--script", "vuln", "-p", ports, self.target], 300)
            if result["success"]:
                self.results["phases"]["nse_vuln"] = result
                # 解析漏洞
                if "VULNERABLE" in result["stdout"]:
                    self.progress.add_finding({
                        "type": "NSE漏洞",
                        "severity": "high",
                        "detail": "Nmap脚本检测到漏洞"
                    })
        
        self.progress.update_phase("Phase 5: 完成", "", 90)
    
    def _phase6_report(self):
        """Phase 6: 生成综合报告"""
        self.progress.update_phase("Phase 6: 生成报告", "", 95)
        
        # 生成攻击面分析
        self.results["attack_surface"] = self.decision_engine.generate_attack_surface()
        
        # 汇总发现
        self.results["findings"] = self.progress.findings
        
        # 生成建议
        self.results["recommendations"] = self._generate_recommendations()
        
        # 保存报告
        report_file = f"/tmp/recon_report_{self.target.replace('.', '_')}_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        self.results["report_file"] = report_file
        self.progress.update_phase("Phase 6: 完成", "", 100)
        
        # 打印摘要
        self._print_summary()
    
    def _generate_recommendations(self) -> List[str]:
        """生成渗透测试建议"""
        recommendations = []
        
        services = self.decision_engine.discovered_services
        
        if self.decision_engine.web_targets:
            recommendations.append("🌐 建议: 对Web应用进行深入测试 (SQL注入、XSS、文件上传)")
        
        if 22 in services:
            recommendations.append("🔐 建议: 尝试SSH密码爆破或查找密钥泄露")
        
        if any(p in services for p in [139, 445]):
            recommendations.append("📁 建议: 深入枚举SMB共享，尝试空会话连接")
        
        if any(p in services for p in [3306, 5432, 1433]):
            recommendations.append("🗄️ 建议: 测试数据库默认凭证和SQL注入")
        
        if self.decision_engine.discovered_vulns:
            recommendations.append(f"⚠️ 建议: 优先利用已发现的 {len(self.decision_engine.discovered_vulns)} 个漏洞")
        
        if not recommendations:
            recommendations.append("ℹ️ 建议: 继续进行更深入的手动渗透测试")
        
        return recommendations
    
    def _print_summary(self):
        """打印扫描摘要"""
        print("\n")
        print("=" * 60)
        print("📊 智能打点报告摘要")
        print("=" * 60)
        print(f"🎯 目标: {self.target}")
        print(f"⏱️  用时: {self.results.get('end_time', 'N/A')}")
        print()
        
        # 攻击面
        attack_surface = self.results.get("attack_surface", {})
        print(f"🔍 发现端口: {attack_surface.get('total_ports', 0)} 个")
        print(f"   开放端口: {attack_surface.get('open_ports', [])}")
        print()
        
        # 服务
        print("📡 发现服务:")
        for port, info in attack_surface.get("services", {}).items():
            print(f"   • {port}/tcp - {info.get('service', 'unknown')} {info.get('version', '')}")
        print()
        
        # 发现
        findings = self.results.get("findings", [])
        if findings:
            print(f"🔔 重要发现: {len(findings)} 项")
            for f in findings[:10]:  # 只显示前10个
                severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
                icon = severity_icons.get(f.get("severity", "info"), "⚪")
                print(f"   {icon} {f.get('type')}: {f.get('detail')}")
        print()
        
        # 建议
        print("💡 渗透建议:")
        for rec in self.results.get("recommendations", []):
            print(f"   {rec}")
        print()
        
        print(f"📄 完整报告: {self.results.get('report_file', 'N/A')}")
        print("=" * 60)


# ==================== MCP集成函数 ====================

def auto_recon(args: Dict) -> Dict:
    """MCP工具: 智能自动化打点"""
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


# ==================== 主函数 ====================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="智能自动化打点系统")
    parser.add_argument("target", help="目标IP或域名")
    parser.add_argument("--fast", action="store_true", help="快速模式")
    parser.add_argument("--deep", action="store_true", default=True, help="深度扫描")
    
    args = parser.parse_args()
    
    result = auto_recon({
        "target": args.target,
        "fast_mode": args.fast,
        "deep_scan": args.deep
    })
    
    print(json.dumps(result, indent=2, ensure_ascii=False))
