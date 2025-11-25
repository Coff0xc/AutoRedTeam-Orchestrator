"""
Red Team Orchestrator - 主协调器
负责协调AI决策和工具执行的完整流程
"""

import asyncio
import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
from enum import Enum

from .ai_brain import AIBrain, Asset, Vulnerability, RiskLevel, ServiceType
from .tool_executor import ToolExecutor, ToolStatus

logger = logging.getLogger(__name__)


class Phase(Enum):
    INIT = "init"
    RECON = "recon"
    MAPPING = "mapping"
    ATTACK = "attack"
    VERIFY = "verify"
    REPORT = "report"
    COMPLETE = "complete"


class RedTeamOrchestrator:
    """
    红队协调器 - AI驱动的自动化渗透测试
    模拟真实红队的工作流程
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.ai_brain = AIBrain()
        self.tool_executor = ToolExecutor(
            workspace=self.config.get("workspace", "/tmp/redteam"),
            timeout=self.config.get("timeout", 300)
        )
        
        self.phase = Phase.INIT
        self.target_domain = ""
        self.state = {
            "subdomains": [],
            "assets": [],
            "vulnerabilities": [],
            "http_services": [],
            "scan_history": []
        }
        self.report_path = Path(self.config.get("report_dir", "./reports"))
        self.report_path.mkdir(parents=True, exist_ok=True)
        
    async def run(self, target: str) -> Dict[str, Any]:
        """
        执行完整的红队渗透流程
        
        Args:
            target: 目标域名
            
        Returns:
            最终报告
        """
        self.target_domain = target
        logger.info(f"[*] Starting red team operation against: {target}")
        
        try:
            # Phase 1: 资产发现
            await self._phase_recon()
            
            # Phase 2: 资产测绘
            await self._phase_mapping()
            
            # Phase 3: 攻击执行
            await self._phase_attack()
            
            # Phase 4: 漏洞验证
            await self._phase_verify()
            
            # Phase 5: 生成报告
            report = await self._phase_report()
            
            self.phase = Phase.COMPLETE
            logger.info("[+] Red team operation completed")
            
            return report
            
        except Exception as e:
            logger.error(f"[-] Operation failed: {e}")
            return {"error": str(e), "phase": self.phase.value}

    async def _phase_recon(self):
        """Phase 1: 资产发现"""
        self.phase = Phase.RECON
        logger.info("[*] Phase 1: Reconnaissance - Asset Discovery")
        
        # 运行Subfinder
        logger.info(f"    [>] Running subfinder on {self.target_domain}")
        result = await self.tool_executor.run_subfinder(self.target_domain)
        
        if result.status == ToolStatus.SUCCESS and result.parsed_data:
            subdomains = result.parsed_data.get("subdomains", [])
            logger.info(f"    [+] Found {len(subdomains)} subdomains")
            
            # DNS验证
            if subdomains:
                logger.info("    [>] Validating subdomains with dnsx")
                dns_result = await self.tool_executor.run_dnsx(subdomains)
                
                if dns_result.status == ToolStatus.SUCCESS and dns_result.parsed_data:
                    valid_subs = []
                    for r in dns_result.parsed_data.get("results", []):
                        if r.get("host"):
                            valid_subs.append(r["host"])
                    subdomains = valid_subs if valid_subs else subdomains
                    logger.info(f"    [+] {len(subdomains)} subdomains resolved")
            
            self.state["subdomains"] = subdomains
            
            # AI分析子域名优先级
            analyzed = self.ai_brain.analyze_subdomains(subdomains)
            self.state["assets"] = analyzed
            
            high_value = [a for a in analyzed if a.priority >= 7]
            logger.info(f"    [+] AI identified {len(high_value)} high-value targets")
        else:
            logger.warning("    [-] Subfinder returned no results")
            # 回退策略：直接扫描主域名
            self.state["subdomains"] = [self.target_domain]
            self.state["assets"] = [Asset(hostname=self.target_domain, priority=5)]

        self._log_phase("recon", {"subdomains_found": len(self.state["subdomains"])})

    async def _phase_mapping(self):
        """Phase 2: 资产测绘"""
        self.phase = Phase.MAPPING
        logger.info("[*] Phase 2: Mapping - Port Scanning & Service Detection")
        
        assets = self.state["assets"]
        
        # 优先扫描高价值目标
        high_priority = [a for a in assets if a.priority >= 6][:10]  # 最多10个
        targets = high_priority if high_priority else assets[:5]
        
        logger.info(f"    [>] Scanning {len(targets)} priority targets")
        
        # HTTP探测
        hostnames = [a.hostname for a in targets]
        logger.info("    [>] Running httpx for HTTP service detection")
        httpx_result = await self.tool_executor.run_httpx(hostnames)
        
        if httpx_result.status == ToolStatus.SUCCESS and httpx_result.parsed_data:
            http_services = httpx_result.parsed_data.get("results", [])
            self.state["http_services"] = http_services
            logger.info(f"    [+] Found {len(http_services)} HTTP services")
        
        # Nmap端口扫描 (批量)
        for asset in targets:
            logger.info(f"    [>] Port scanning: {asset.hostname}")
            nmap_result = await self.tool_executor.run_nmap(asset.hostname, ports="top-1000")
            
            if nmap_result.status == ToolStatus.SUCCESS and nmap_result.parsed_data:
                hosts = nmap_result.parsed_data.get("hosts", [])
                if hosts:
                    host_data = hosts[0]
                    asset.ip = host_data.get("ip")
                    asset.ports = [p["port"] for p in host_data.get("ports", [])]
                    asset.services = {
                        p["port"]: f"{p['service']} {p.get('version', '')}".strip()
                        for p in host_data.get("ports", [])
                    }
                    logger.info(f"        [+] {asset.hostname}: {len(asset.ports)} open ports")
        
        # 更新状态
        mapped_assets = [a for a in targets if a.ports]
        self.state["assets"] = mapped_assets + [a for a in assets if a not in targets]
        
        self._log_phase("mapping", {
            "targets_scanned": len(targets),
            "assets_with_services": len(mapped_assets)
        })

    async def _phase_attack(self):
        """Phase 3: 攻击执行"""
        self.phase = Phase.ATTACK
        logger.info("[*] Phase 3: Attack - Vulnerability Scanning")
        
        # AI制定攻击计划
        assets_with_services = [a for a in self.state["assets"] if a.services]
        attack_plan = self.ai_brain.plan_attack(assets_with_services)
        
        all_findings = []
        
        # Web漏洞扫描
        web_targets = []
        for asset in attack_plan.get("web_scan", []):
            for port in (asset.ports or []):
                svc_type = self.ai_brain.classify_service(port)[1]
                if svc_type == ServiceType.WEB:
                    scheme = "https" if port in [443, 8443] else "http"
                    port_str = "" if port in [80, 443] else f":{port}"
                    web_targets.append(f"{scheme}://{asset.hostname}{port_str}")
        
        # 添加httpx发现的URL
        for svc in self.state.get("http_services", []):
            if svc.get("url") and svc["url"] not in web_targets:
                web_targets.append(svc["url"])
        
        if web_targets:
            logger.info(f"    [>] Scanning {len(web_targets)} web targets with Nuclei")
            nuclei_result = await self.tool_executor.run_nuclei(
                web_targets,
                severity="critical,high,medium"
            )
            
            if nuclei_result.status == ToolStatus.SUCCESS and nuclei_result.parsed_data:
                findings = nuclei_result.parsed_data.get("findings", [])
                all_findings.extend(findings)
                logger.info(f"    [+] Nuclei found {len(findings)} potential vulnerabilities")
        
        # 转换为Vulnerability对象
        vulnerabilities = []
        for f in all_findings:
            severity_map = {
                "critical": RiskLevel.CRITICAL,
                "high": RiskLevel.HIGH,
                "medium": RiskLevel.MEDIUM,
                "low": RiskLevel.LOW,
                "info": RiskLevel.INFO
            }
            vuln = Vulnerability(
                id=f.get("template-id", "unknown"),
                name=f.get("info", {}).get("name", "Unknown"),
                severity=severity_map.get(f.get("info", {}).get("severity", "info"), RiskLevel.INFO),
                target=f.get("host", ""),
                port=f.get("port"),
                evidence=json.dumps(f.get("matched-at", "")),
                is_verified=False
            )
            vulnerabilities.append(vuln)
        
        self.state["vulnerabilities"] = vulnerabilities
        self._log_phase("attack", {"findings": len(vulnerabilities)})

    async def _phase_verify(self):
        """Phase 4: 漏洞验证"""
        self.phase = Phase.VERIFY
        logger.info("[*] Phase 4: Verification - False Positive Filtering")
        
        vulns = self.state["vulnerabilities"]
        verified = []
        false_positives = 0
        
        for vuln in vulns:
            # AI验证漏洞
            verified_vuln = self.ai_brain.verify_vulnerability(vuln, vuln.evidence)
            
            if verified_vuln.is_false_positive:
                false_positives += 1
                logger.info(f"    [-] FP filtered: {vuln.name} @ {vuln.target}")
            else:
                verified.append(verified_vuln)
                logger.info(f"    [+] Verified: {vuln.name} @ {vuln.target} (conf: {verified_vuln.confidence:.2f})")
        
        self.state["vulnerabilities"] = verified
        logger.info(f"    [*] Filtered {false_positives} false positives, {len(verified)} verified")
        
        self._log_phase("verify", {
            "total": len(vulns),
            "verified": len(verified),
            "false_positives": false_positives
        })

    async def _phase_report(self) -> Dict[str, Any]:
        """Phase 5: 生成报告"""
        self.phase = Phase.REPORT
        logger.info("[*] Phase 5: Report Generation")
        
        summary = self.ai_brain.summarize_findings(self.state["vulnerabilities"])
        
        report = {
            "meta": {
                "target": self.target_domain,
                "scan_time": datetime.now().isoformat(),
                "tool": "AutoRedTeam-Orchestrator"
            },
            "summary": summary,
            "assets": {
                "subdomains_discovered": len(self.state["subdomains"]),
                "assets_mapped": len([a for a in self.state["assets"] if a.ports]),
                "http_services": len(self.state.get("http_services", []))
            },
            "vulnerabilities": [
                {
                    "id": v.id,
                    "name": v.name,
                    "severity": v.severity.value,
                    "target": v.target,
                    "port": v.port,
                    "confidence": v.confidence,
                    "evidence": v.evidence
                }
                for v in self.state["vulnerabilities"]
            ],
            "ai_decisions": self.ai_brain.get_decision_log(),
            "scan_history": self.state["scan_history"]
        }
        
        # 保存报告
        report_file = self.report_path / f"report_{self.target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_file.write_text(json.dumps(report, indent=2, ensure_ascii=False))
        logger.info(f"    [+] Report saved: {report_file}")
        
        return report

    def _log_phase(self, phase: str, data: Dict):
        """记录阶段信息"""
        self.state["scan_history"].append({
            "phase": phase,
            "timestamp": datetime.now().isoformat(),
            "data": data
        })

    def get_status(self) -> Dict[str, Any]:
        """获取当前状态"""
        return {
            "phase": self.phase.value,
            "target": self.target_domain,
            "subdomains": len(self.state["subdomains"]),
            "assets": len(self.state["assets"]),
            "vulnerabilities": len(self.state["vulnerabilities"]),
            "tools": self.tool_executor.get_tool_status()
        }
