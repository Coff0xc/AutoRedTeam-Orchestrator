#!/usr/bin/env python3
"""
攻击链引擎 - AI驱动的自动化攻击链推理
"""

import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class AttackPhase(Enum):
    """攻击阶段 (MITRE ATT&CK框架)"""
    RECONNAISSANCE = "reconnaissance"          # 侦察
    RESOURCE_DEV = "resource_development"      # 资源开发
    INITIAL_ACCESS = "initial_access"          # 初始访问
    EXECUTION = "execution"                    # 执行
    PERSISTENCE = "persistence"                # 持久化
    PRIVILEGE_ESC = "privilege_escalation"     # 权限提升
    DEFENSE_EVASION = "defense_evasion"        # 防御规避
    CREDENTIAL_ACCESS = "credential_access"    # 凭证访问
    DISCOVERY = "discovery"                    # 发现
    LATERAL_MOVEMENT = "lateral_movement"      # 横向移动
    COLLECTION = "collection"                  # 收集
    EXFILTRATION = "exfiltration"              # 数据外传
    IMPACT = "impact"                          # 影响


@dataclass
class AttackNode:
    """攻击节点"""
    id: str
    phase: AttackPhase
    technique: str
    tool: str
    params: Dict[str, Any]
    dependencies: List[str] = field(default_factory=list)
    status: str = "pending"  # pending, running, success, failed, skipped
    result: Dict[str, Any] = None
    started_at: datetime = None
    finished_at: datetime = None


@dataclass
class AttackChain:
    """攻击链"""
    id: str
    name: str
    target: str
    nodes: List[AttackNode] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    status: str = "created"
    findings: List[Dict] = field(default_factory=list)


class AttackChainEngine:
    """攻击链推理引擎"""
    
    # 技术到工具的映射
    TECHNIQUE_TOOLS = {
        # 侦察阶段
        "active_scanning": ["nmap_scan", "masscan"],
        "passive_recon": ["shodan_lookup", "censys_lookup"],
        "subdomain_enum": ["subfinder", "amass", "assetfinder"],
        "dns_recon": ["dns_enum", "dnsrecon"],
        "web_fingerprint": ["whatweb", "wappalyzer"],
        
        # 漏洞发现
        "vuln_scan": ["nuclei_scan", "nikto_scan"],
        "ssl_analysis": ["sslscan", "testssl"],
        "web_vuln_scan": ["zap_scan", "nikto_scan"],
        
        # 初始访问
        "exploit_public_app": ["sqlmap", "xsstrike"],
        "brute_force": ["hydra", "medusa"],
        "default_creds": ["crackmapexec"],
        
        # 执行
        "command_injection": ["commix"],
        "script_execution": ["reverse_shell"],
        
        # 权限提升
        "linux_privesc": ["linpeas", "linux_exploit_suggester"],
        "windows_privesc": ["winpeas", "powerup"],
        
        # 凭证访问
        "credential_dump": ["mimikatz", "secretsdump"],
        "password_crack": ["hashcat", "john"],
        
        # 横向移动
        "smb_lateral": ["crackmapexec", "psexec"],
        "ssh_lateral": ["ssh_bruteforce"],
    }
    
    # 攻击阶段流程
    PHASE_FLOW = [
        AttackPhase.RECONNAISSANCE,
        AttackPhase.INITIAL_ACCESS,
        AttackPhase.EXECUTION,
        AttackPhase.PRIVILEGE_ESC,
        AttackPhase.CREDENTIAL_ACCESS,
        AttackPhase.LATERAL_MOVEMENT,
        AttackPhase.EXFILTRATION,
    ]
    
    def __init__(self, tool_registry):
        self.tool_registry = tool_registry
        self.chains: Dict[str, AttackChain] = {}
    
    def create_chain(self, target: str, target_type: str, 
                     objectives: List[str] = None) -> AttackChain:
        """创建攻击链"""
        import uuid
        
        chain_id = str(uuid.uuid4())[:8]
        chain = AttackChain(
            id=chain_id,
            name=f"chain_{target}",
            target=target
        )
        
        # 根据目标类型和目标生成攻击节点
        nodes = self._generate_nodes(target, target_type, objectives)
        chain.nodes = nodes
        
        self.chains[chain_id] = chain
        logger.info(f"创建攻击链: {chain_id}, 节点数: {len(nodes)}")
        
        return chain
    
    def _generate_nodes(self, target: str, target_type: str,
                        objectives: List[str] = None) -> List[AttackNode]:
        """生成攻击节点"""
        nodes = []
        node_id = 0
        
        # 阶段1: 侦察
        if target_type == "ip":
            nodes.append(AttackNode(
                id=f"node_{node_id}",
                phase=AttackPhase.RECONNAISSANCE,
                technique="active_scanning",
                tool="nmap_scan",
                params={"target": target, "timing": "T4"}
            ))
            node_id += 1
            
        elif target_type == "domain":
            nodes.append(AttackNode(
                id=f"node_{node_id}",
                phase=AttackPhase.RECONNAISSANCE,
                technique="subdomain_enum",
                tool="subfinder",
                params={"domain": target}
            ))
            node_id += 1
            
            nodes.append(AttackNode(
                id=f"node_{node_id}",
                phase=AttackPhase.RECONNAISSANCE,
                technique="dns_recon",
                tool="dns_enum",
                params={"domain": target},
                dependencies=[f"node_{node_id-1}"]
            ))
            node_id += 1
        
        elif target_type == "url":
            nodes.append(AttackNode(
                id=f"node_{node_id}",
                phase=AttackPhase.RECONNAISSANCE,
                technique="web_fingerprint",
                tool="whatweb",
                params={"target": target}
            ))
            node_id += 1
            
            # WAF检测
            nodes.append(AttackNode(
                id=f"node_{node_id}",
                phase=AttackPhase.RECONNAISSANCE,
                technique="waf_detection",
                tool="wafw00f",
                params={"target": target}
            ))
            node_id += 1
        
        # 阶段2: 漏洞扫描
        vuln_node = AttackNode(
            id=f"node_{node_id}",
            phase=AttackPhase.RECONNAISSANCE,
            technique="vuln_scan",
            tool="nuclei_scan",
            params={
                "target": target if target_type == "url" else f"http://{target}",
                "severity": "medium,high,critical"
            },
            dependencies=[f"node_{node_id-1}"]
        )
        nodes.append(vuln_node)
        node_id += 1
        
        # 阶段3: 初始访问尝试
        if target_type in ["url", "domain"]:
            # Web攻击
            nodes.append(AttackNode(
                id=f"node_{node_id}",
                phase=AttackPhase.INITIAL_ACCESS,
                technique="exploit_public_app",
                tool="sqlmap",
                params={
                    "url": target if target_type == "url" else f"http://{target}",
                    "batch": True,
                    "level": 2
                },
                dependencies=[vuln_node.id]
            ))
            node_id += 1
            
            # 目录扫描
            nodes.append(AttackNode(
                id=f"node_{node_id}",
                phase=AttackPhase.RECONNAISSANCE,
                technique="content_discovery",
                tool="gobuster",
                params={
                    "url": target if target_type == "url" else f"http://{target}",
                    "mode": "dir"
                },
                dependencies=[f"node_0"]
            ))
            node_id += 1
        
        elif target_type == "ip":
            # 服务爆破 (根据扫描结果动态决定)
            nodes.append(AttackNode(
                id=f"node_{node_id}",
                phase=AttackPhase.INITIAL_ACCESS,
                technique="brute_force",
                tool="hydra",
                params={
                    "target": target,
                    "service": "ssh",  # 将根据扫描结果动态调整
                    "username": "root"
                },
                dependencies=["node_0"]
            ))
            node_id += 1
        
        return nodes
    
    def execute_chain(self, chain_id: str, 
                      session_id: str = None) -> Dict[str, Any]:
        """执行攻击链"""
        chain = self.chains.get(chain_id)
        if not chain:
            raise ValueError(f"攻击链不存在: {chain_id}")
        
        chain.status = "running"
        results = []
        
        for node in chain.nodes:
            # 检查依赖
            if not self._check_dependencies(chain, node):
                node.status = "skipped"
                continue
            
            # 执行节点
            node.status = "running"
            node.started_at = datetime.now()
            
            try:
                result = self.tool_registry.execute(
                    node.tool,
                    node.params,
                    session_id
                )
                
                node.result = result
                node.status = "success" if result.get("success") else "failed"
                
                # 提取发现
                findings = self._extract_findings(node, result)
                chain.findings.extend(findings)
                
                # 动态调整后续节点
                self._adjust_chain(chain, node, result)
                
            except Exception as e:
                node.status = "failed"
                node.result = {"error": str(e)}
                logger.error(f"节点执行失败: {node.id}, {str(e)}")
            
            node.finished_at = datetime.now()
            results.append({
                "node_id": node.id,
                "tool": node.tool,
                "status": node.status,
                "duration": (node.finished_at - node.started_at).total_seconds()
            })
        
        chain.status = "completed"
        
        return {
            "chain_id": chain_id,
            "status": chain.status,
            "results": results,
            "findings": chain.findings
        }
    
    def _check_dependencies(self, chain: AttackChain, 
                            node: AttackNode) -> bool:
        """检查节点依赖"""
        for dep_id in node.dependencies:
            dep_node = next((n for n in chain.nodes if n.id == dep_id), None)
            if dep_node and dep_node.status not in ["success"]:
                return False
        return True
    
    def _extract_findings(self, node: AttackNode, 
                          result: Dict) -> List[Dict]:
        """从结果中提取发现"""
        findings = []
        
        if node.technique == "vuln_scan":
            for vuln in result.get("vulnerabilities", []):
                findings.append({
                    "type": "vulnerability",
                    "severity": vuln.get("severity", "unknown"),
                    "title": vuln.get("template_name", "Unknown"),
                    "source": node.tool
                })
        
        elif node.technique == "active_scanning":
            for host in result.get("hosts", []):
                for port in host.get("ports", []):
                    if port.get("state") == "open":
                        findings.append({
                            "type": "open_port",
                            "port": port.get("port"),
                            "service": port.get("service"),
                            "source": node.tool
                        })
        
        elif node.technique == "brute_force":
            for cred in result.get("credentials", []):
                findings.append({
                    "type": "credential",
                    "severity": "critical",
                    "data": cred,
                    "source": node.tool
                })
        
        return findings
    
    def _adjust_chain(self, chain: AttackChain, 
                      completed_node: AttackNode,
                      result: Dict):
        """根据结果动态调整攻击链"""
        if completed_node.technique == "active_scanning":
            # 根据扫描发现的服务调整后续节点
            open_ports = []
            for host in result.get("hosts", []):
                for port in host.get("ports", []):
                    if port.get("state") == "open":
                        open_ports.append({
                            "port": port.get("port"),
                            "service": port.get("service", "")
                        })
            
            # 为发现的服务添加针对性攻击节点
            for port_info in open_ports:
                service = port_info.get("service", "").lower()
                port = port_info.get("port")
                
                if "http" in service:
                    # 添加Web攻击节点
                    self._add_web_attack_nodes(chain, completed_node, port)
                elif service in ["ssh", "ftp", "mysql", "smb"]:
                    # 更新爆破节点的服务类型
                    for node in chain.nodes:
                        if node.technique == "brute_force":
                            node.params["service"] = service
                            if port:
                                node.params["port"] = port
    
    def _add_web_attack_nodes(self, chain: AttackChain,
                               parent_node: AttackNode, port: int):
        """添加Web攻击节点"""
        target = chain.target
        base_url = f"http://{target}:{port}" if port != 80 else f"http://{target}"
        
        # 检查是否已有相关节点
        existing_tools = [n.tool for n in chain.nodes]
        
        if "gobuster" not in existing_tools:
            chain.nodes.append(AttackNode(
                id=f"node_web_{port}",
                phase=AttackPhase.RECONNAISSANCE,
                technique="content_discovery",
                tool="gobuster",
                params={"url": base_url, "mode": "dir"},
                dependencies=[parent_node.id]
            ))
    
    def get_chain_status(self, chain_id: str) -> Dict[str, Any]:
        """获取攻击链状态"""
        chain = self.chains.get(chain_id)
        if not chain:
            return None
        
        return {
            "id": chain.id,
            "name": chain.name,
            "target": chain.target,
            "status": chain.status,
            "nodes": [
                {
                    "id": n.id,
                    "phase": n.phase.value,
                    "technique": n.technique,
                    "tool": n.tool,
                    "status": n.status
                }
                for n in chain.nodes
            ],
            "findings_count": len(chain.findings),
            "created_at": chain.created_at.isoformat()
        }
    
    def suggest_next_steps(self, chain_id: str) -> List[Dict]:
        """建议下一步操作"""
        chain = self.chains.get(chain_id)
        if not chain:
            return []
        
        suggestions = []
        
        # 分析发现
        vulns = [f for f in chain.findings if f.get("type") == "vulnerability"]
        creds = [f for f in chain.findings if f.get("type") == "credential"]
        ports = [f for f in chain.findings if f.get("type") == "open_port"]
        
        if vulns:
            critical_vulns = [v for v in vulns if v.get("severity") == "critical"]
            if critical_vulns:
                suggestions.append({
                    "priority": "high",
                    "action": "exploit_vulnerability",
                    "description": f"发现 {len(critical_vulns)} 个严重漏洞，建议立即利用",
                    "tools": ["metasploit", "searchsploit"]
                })
        
        if creds:
            suggestions.append({
                "priority": "high",
                "action": "use_credentials",
                "description": f"已获取 {len(creds)} 组凭证，建议横向移动",
                "tools": ["crackmapexec", "psexec"]
            })
        
        # 根据开放端口建议
        for port in ports:
            if port.get("service") == "smb":
                suggestions.append({
                    "priority": "medium",
                    "action": "smb_enum",
                    "description": "发现SMB服务，建议进行枚举",
                    "tools": ["enum4linux", "smbclient"]
                })
        
        return suggestions
