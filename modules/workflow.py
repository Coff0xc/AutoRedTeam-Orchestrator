#!/usr/bin/env python3
"""
自动化工作流 - AI驱动的渗透测试流程
"""

import logging
import time
from typing import Any, Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class AutoWorkflow:
    """自动化渗透测试工作流"""
    
    def __init__(self, tool_registry, ai_engine, session):
        self.tools = tool_registry
        self.ai = ai_engine
        self.session = session
        self.results = {}
        self.current_phase = "init"
    
    def execute(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """执行自动化工作流"""
        options = options or {}
        
        # 添加目标到会话
        target_type = self.ai._identify_target_type(target)
        self.session.add_target(target, target_type)
        
        logger.info(f"开始自动化工作流: {target} [{target_type}]")
        
        workflow_result = {
            "target": target,
            "target_type": target_type,
            "phases": [],
            "findings": [],
            "recommendations": [],
            "start_time": datetime.now().isoformat()
        }
        
        try:
            # 阶段1: 信息收集
            recon_result = self._phase_recon(target, target_type, options)
            workflow_result["phases"].append(recon_result)
            
            # 阶段2: 漏洞扫描
            if options.get("skip_vuln_scan", False) is False:
                vuln_result = self._phase_vuln_scan(target, target_type, recon_result)
                workflow_result["phases"].append(vuln_result)
            
            # 阶段3: AI分析和攻击规划
            analysis = self.ai.analyze_target(target, {
                "recon_data": self.results.get("recon", {}),
                "vuln_data": self.results.get("vuln", {})
            })
            workflow_result["analysis"] = analysis
            
            # 生成攻击计划
            attack_plan = self.ai.generate_attack_plan(
                target, 
                self.results.get("recon", {})
            )
            workflow_result["attack_plan"] = attack_plan
            
            # 收集发现
            workflow_result["findings"] = self.session.findings
            workflow_result["recommendations"] = attack_plan.get("recommendations", [])
            
        except Exception as e:
            logger.error(f"工作流执行失败: {str(e)}")
            workflow_result["error"] = str(e)
        
        workflow_result["end_time"] = datetime.now().isoformat()
        
        return workflow_result
    
    def _phase_recon(self, target: str, target_type: str, 
                     options: Dict) -> Dict[str, Any]:
        """信息收集阶段"""
        self.current_phase = "recon"
        logger.info("阶段1: 信息收集")
        
        phase_result = {
            "phase": "recon",
            "name": "信息收集",
            "status": "running",
            "tools_used": [],
            "results": {}
        }
        
        start_time = time.time()
        
        try:
            if target_type == "ip":
                # IP目标: 端口扫描
                phase_result["tools_used"].append("nmap_scan")
                nmap_result = self._execute_tool("nmap_scan", {
                    "target": target,
                    "timing": "T4"
                })
                phase_result["results"]["nmap"] = nmap_result
                
                # 提取端口信息
                if nmap_result.get("success"):
                    ports = []
                    services = []
                    for host in nmap_result.get("hosts", []):
                        for port in host.get("ports", []):
                            if port.get("state") == "open":
                                ports.append(port.get("port"))
                                if port.get("service"):
                                    services.append(port.get("service"))
                    
                    self.results["recon"] = {
                        "ports": ports,
                        "services": services,
                        "hosts": nmap_result.get("hosts", [])
                    }
                    
                    # 添加发现
                    if ports:
                        self.session.add_finding(
                            title=f"发现 {len(ports)} 个开放端口",
                            severity="info",
                            description=f"开放端口: {', '.join(map(str, ports[:10]))}",
                            evidence={"ports": ports}
                        )
            
            elif target_type == "domain":
                # 域名目标: 子域名枚举 + DNS
                phase_result["tools_used"].extend(["subfinder", "dns_enum"])
                
                # 子域名枚举
                subfinder_result = self._execute_tool("subfinder", {
                    "domain": target
                })
                phase_result["results"]["subfinder"] = subfinder_result
                
                # DNS枚举
                dns_result = self._execute_tool("dns_enum", {
                    "domain": target
                })
                phase_result["results"]["dns"] = dns_result
                
                subdomains = []
                if subfinder_result.get("success"):
                    subdomains = [s.get("host") for s in subfinder_result.get("subdomains", [])]
                
                self.results["recon"] = {
                    "subdomains": subdomains,
                    "dns_records": dns_result.get("records", {})
                }
                
                if subdomains:
                    self.session.add_finding(
                        title=f"发现 {len(subdomains)} 个子域名",
                        severity="info",
                        description=f"子域名: {', '.join(subdomains[:5])}...",
                        evidence={"subdomains": subdomains[:20]}
                    )
            
            elif target_type == "url":
                # URL目标: Web技术识别
                phase_result["tools_used"].extend(["whatweb", "wafw00f"])
                
                whatweb_result = self._execute_tool("whatweb", {
                    "target": target
                })
                phase_result["results"]["whatweb"] = whatweb_result
                
                waf_result = self._execute_tool("wafw00f", {
                    "target": target
                })
                phase_result["results"]["waf"] = waf_result
                
                self.results["recon"] = {
                    "technologies": whatweb_result.get("technologies", []),
                    "waf_detected": waf_result.get("waf_detected", False),
                    "waf_names": waf_result.get("waf_names", [])
                }
                
                if waf_result.get("waf_detected"):
                    self.session.add_finding(
                        title="检测到WAF防护",
                        severity="info",
                        description=f"WAF: {', '.join(waf_result.get('waf_names', []))}",
                        recommendations=["考虑WAF绕过技术", "调整攻击策略"]
                    )
            
            phase_result["status"] = "completed"
            
        except Exception as e:
            logger.error(f"信息收集失败: {str(e)}")
            phase_result["status"] = "failed"
            phase_result["error"] = str(e)
        
        phase_result["duration"] = time.time() - start_time
        
        return phase_result
    
    def _phase_vuln_scan(self, target: str, target_type: str,
                         recon_result: Dict) -> Dict[str, Any]:
        """漏洞扫描阶段"""
        self.current_phase = "vuln_scan"
        logger.info("阶段2: 漏洞扫描")
        
        phase_result = {
            "phase": "vuln_scan",
            "name": "漏洞扫描",
            "status": "running",
            "tools_used": [],
            "results": {}
        }
        
        start_time = time.time()
        
        try:
            # 根据目标类型选择扫描工具
            if target_type in ["ip", "domain", "url"]:
                # Nuclei扫描
                phase_result["tools_used"].append("nuclei_scan")
                
                scan_target = target
                if target_type == "ip":
                    scan_target = f"http://{target}"
                
                nuclei_result = self._execute_tool("nuclei_scan", {
                    "target": scan_target,
                    "severity": "medium,high,critical"
                })
                phase_result["results"]["nuclei"] = nuclei_result
                
                # 处理漏洞发现
                if nuclei_result.get("success"):
                    vulns = nuclei_result.get("vulnerabilities", [])
                    self.results["vuln"] = {
                        "vulnerabilities": vulns,
                        "count": len(vulns)
                    }
                    
                    for vuln in vulns[:10]:  # 限制添加数量
                        self.session.add_finding(
                            title=vuln.get("template_name", "未知漏洞"),
                            severity=vuln.get("severity", "medium"),
                            description=vuln.get("description", ""),
                            evidence={
                                "template_id": vuln.get("template_id"),
                                "matched_at": vuln.get("matched_at")
                            }
                        )
            
            # Web目标额外扫描
            if target_type == "url":
                phase_result["tools_used"].append("nikto_scan")
                
                nikto_result = self._execute_tool("nikto_scan", {
                    "target": target
                })
                phase_result["results"]["nikto"] = nikto_result
            
            phase_result["status"] = "completed"
            
        except Exception as e:
            logger.error(f"漏洞扫描失败: {str(e)}")
            phase_result["status"] = "failed"
            phase_result["error"] = str(e)
        
        phase_result["duration"] = time.time() - start_time
        
        return phase_result
    
    def _execute_tool(self, tool_name: str, params: Dict) -> Dict[str, Any]:
        """执行工具并记录结果"""
        start_time = time.time()
        
        try:
            result = self.tools.execute(tool_name, params, self.session.id)
            duration = time.time() - start_time
            
            self.session.add_result(
                tool_name=tool_name,
                params=params,
                result=result,
                duration=duration,
                success=result.get("success", False)
            )
            
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            error_result = {"success": False, "error": str(e)}
            
            self.session.add_result(
                tool_name=tool_name,
                params=params,
                result=error_result,
                duration=duration,
                success=False,
                error=str(e)
            )
            
            return error_result


class WorkflowBuilder:
    """工作流构建器"""
    
    def __init__(self):
        self.steps = []
    
    def add_step(self, tool_name: str, params: Dict = None, 
                 condition: str = None) -> 'WorkflowBuilder':
        """添加步骤"""
        self.steps.append({
            "tool": tool_name,
            "params": params or {},
            "condition": condition
        })
        return self
    
    def build(self) -> List[Dict]:
        """构建工作流"""
        return self.steps
    
    @staticmethod
    def web_pentest() -> 'WorkflowBuilder':
        """Web渗透测试工作流"""
        return (WorkflowBuilder()
            .add_step("whatweb", {})
            .add_step("wafw00f", {})
            .add_step("gobuster", {"mode": "dir"})
            .add_step("nuclei_scan", {"severity": "medium,high,critical"})
            .add_step("nikto_scan", {}))
    
    @staticmethod
    def network_pentest() -> 'WorkflowBuilder':
        """网络渗透测试工作流"""
        return (WorkflowBuilder()
            .add_step("nmap_scan", {"timing": "T4"})
            .add_step("nmap_service", {})
            .add_step("nmap_vuln", {})
            .add_step("enum4linux", {}, condition="port_445_open"))
    
    @staticmethod
    def recon_only() -> 'WorkflowBuilder':
        """仅信息收集工作流"""
        return (WorkflowBuilder()
            .add_step("whois_lookup", {})
            .add_step("dns_enum", {})
            .add_step("subfinder", {})
            .add_step("shodan_lookup", {}))
