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
    result: Optional[Dict[str, Any]] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


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
    
    # 技术到工具的映射 (工具名与 MCP handlers 注册名一致)
    TECHNIQUE_TOOLS = {
        # 侦察阶段
        "active_scanning": ["port_scan"],
        "passive_recon": ["full_recon"],
        "subdomain_enum": ["subdomain_enum"],
        "dns_recon": ["dns_lookup"],
        "web_fingerprint": ["tech_detect", "fingerprint"],
        "waf_detection": ["waf_detect"],
        "content_discovery": ["dir_scan"],

        # 漏洞发现
        "vuln_scan": ["vuln_scan"],
        "ssl_analysis": ["security_headers_scan"],
        "web_vuln_scan": [
            "vuln_scan", "sqli_scan", "xss_scan", "ssrf_scan", "rce_scan",
            "ssti_scan", "xxe_scan", "path_traversal_scan", "idor_scan"
        ],

        # 初始访问
        "exploit_public_app": ["exploit_vulnerability"],
        "brute_force": [],
        "default_creds": [],

        # 执行
        "command_injection": ["rce_scan"],
        "script_execution": ["payload_obfuscate"],

        # 权限提升
        "linux_privesc": ["privilege_escalate"],
        "windows_privesc": ["privilege_escalate"],

        # 凭证访问
        "credential_dump": ["credential_find"],
        "password_crack": ["credential_find"],

        # 横向移动
        "smb_lateral": ["lateral_smb"],
        "ssh_lateral": [],
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
                tool="port_scan",
                params={"target": target, "ports": "1-1000", "timeout": 2.0}
            ))
            node_id += 1
            
        elif target_type == "domain":
            nodes.append(AttackNode(
                id=f"node_{node_id}",
                phase=AttackPhase.RECONNAISSANCE,
                technique="subdomain_enum",
                tool="subdomain_enum",
                params={"domain": target}
            ))
            node_id += 1

            nodes.append(AttackNode(
                id=f"node_{node_id}",
                phase=AttackPhase.RECONNAISSANCE,
                technique="dns_recon",
                tool="dns_lookup",  # 修正: 使用 recon_tools 中的 dns_lookup
                params={"domain": target},
                dependencies=[f"node_{node_id-1}"]
            ))
            node_id += 1
        
        elif target_type == "url":
            nodes.append(AttackNode(
                id=f"node_{node_id}",
                phase=AttackPhase.RECONNAISSANCE,
                technique="web_fingerprint",
                tool="tech_detect",
                params={"url": target}
            ))
            node_id += 1

            # WAF检测
            nodes.append(AttackNode(
                id=f"node_{node_id}",
                phase=AttackPhase.RECONNAISSANCE,
                technique="waf_detection",
                tool="waf_detect",
                params={"url": target}
            ))
            node_id += 1
        
        # 阶段2: 漏洞扫描
        vuln_node = AttackNode(
            id=f"node_{node_id}",
            phase=AttackPhase.RECONNAISSANCE,
            technique="vuln_scan",
            tool="vuln_scan",
            params={
                "url": target if target_type == "url" else f"http://{target}"
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
                tool="exploit_vulnerability",
                params={
                    "detection_result": {
                        "vulnerable": False,
                        "vuln_type": "sqli",
                        "url": target if target_type == "url" else f"http://{target}"
                    }
                },
                dependencies=[vuln_node.id]
            ))
            node_id += 1

            # 目录扫描
            nodes.append(AttackNode(
                id=f"node_{node_id}",
                phase=AttackPhase.RECONNAISSANCE,
                technique="content_discovery",
                tool="dir_scan",
                params={
                    "url": target if target_type == "url" else f"http://{target}",
                    "wordlist": "common"
                },
                dependencies=[f"node_0"]
            ))
            node_id += 1
        
        return nodes
    
    def execute_chain(self, chain_id: str,
                      session_id: str = None) -> Dict[str, Any]:
        """执行攻击链"""
        chain = self.chains.get(chain_id)
        if not chain:
            raise ValueError(f"攻击链不存在: {chain_id}")

        # 修复: 执行前检测循环依赖
        if self._detect_cycle(chain):
            raise ValueError(f"攻击链存在循环依赖: {chain_id}")

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
            # 修复: 依赖节点不存在或未成功都应返回False
            if dep_node is None:
                logger.warning(f"依赖节点不存在: {dep_id}")
                return False
            if dep_node.status != "success":
                return False
        return True

    def _detect_cycle(self, chain: AttackChain) -> bool:
        """检测循环依赖"""
        visited = set()
        rec_stack = set()

        def dfs(node_id: str) -> bool:
            visited.add(node_id)
            rec_stack.add(node_id)

            node = next((n for n in chain.nodes if n.id == node_id), None)
            if node:
                for dep_id in node.dependencies:
                    if dep_id not in visited:
                        if dfs(dep_id):
                            return True
                    elif dep_id in rec_stack:
                        return True

            rec_stack.remove(node_id)
            return False

        for node in chain.nodes:
            if node.id not in visited:
                if dfs(node.id):
                    return True
        return False
    
    def _extract_findings(self, node: AttackNode, 
                          result: Dict) -> List[Dict]:
        """从结果中提取发现"""
        findings = []
        
        if node.technique == "vuln_scan":
            vulnerabilities = result.get("vulnerabilities") or result.get("vulns") or []
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                findings.append({
                    "type": "vulnerability",
                    "severity": vuln.get("severity", "unknown"),
                    "title": vuln.get("template_name") or vuln.get("title") or vuln.get("type", "Unknown"),
                    "source": node.tool
                })

        elif node.technique == "active_scanning":
            open_ports = []
            if isinstance(result.get("open_ports"), list):
                open_ports = result.get("open_ports", [])
            elif isinstance(result.get("hosts"), list):
                for host in result.get("hosts", []):
                    for port in host.get("ports", []):
                        if port.get("state") == "open":
                            open_ports.append(port)

            for port in open_ports:
                if isinstance(port, dict) and port.get("state") not in (None, "open"):
                    continue
                findings.append({
                    "type": "open_port",
                    "port": port.get("port") if isinstance(port, dict) else None,
                    "service": port.get("service") if isinstance(port, dict) else None,
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
            if isinstance(result.get("open_ports"), list):
                for port in result.get("open_ports", []):
                    if isinstance(port, dict):
                        open_ports.append({
                            "port": port.get("port"),
                            "service": port.get("service", "")
                        })
            elif isinstance(result.get("hosts"), list):
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

        if "dir_scan" not in existing_tools:
            chain.nodes.append(AttackNode(
                id=f"node_web_{port}",
                phase=AttackPhase.RECONNAISSANCE,
                technique="content_discovery",
                tool="dir_scan",
                params={"url": base_url, "wordlist": "common"},
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
