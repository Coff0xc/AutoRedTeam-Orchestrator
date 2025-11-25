"""
AI Brain - 智能决策引擎
负责分析数据、制定计划、判断误报
"""

import json
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ServiceType(Enum):
    """服务类型枚举"""
    WEB = "web"
    DATABASE = "database"
    CACHE = "cache"
    MAIL = "mail"
    FILE = "file"
    REMOTE = "remote"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """风险等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Asset:
    """资产数据结构"""
    hostname: str
    ip: Optional[str] = None
    ports: Optional[List[int]] = None
    services: Optional[Dict[int, str]] = None
    priority: int = 5  # 1-10, 10最高
    tags: Optional[List[str]] = None


@dataclass
class Vulnerability:
    """漏洞数据结构"""
    id: str
    name: str
    severity: RiskLevel
    target: str
    port: Optional[int]
    evidence: str
    is_verified: bool = False
    is_false_positive: bool = False
    confidence: float = 0.0


class AIBrain:
    """
    AI决策引擎
    模拟红队专家的思维过程
    """
    
    # 端口-服务映射表
    PORT_SERVICE_MAP = {
        21: ("ftp", ServiceType.FILE),
        22: ("ssh", ServiceType.REMOTE),
        23: ("telnet", ServiceType.REMOTE),
        25: ("smtp", ServiceType.MAIL),
        53: ("dns", ServiceType.UNKNOWN),
        80: ("http", ServiceType.WEB),
        110: ("pop3", ServiceType.MAIL),
        111: ("rpc", ServiceType.UNKNOWN),
        135: ("msrpc", ServiceType.UNKNOWN),
        139: ("netbios", ServiceType.FILE),
        143: ("imap", ServiceType.MAIL),
        443: ("https", ServiceType.WEB),
        445: ("smb", ServiceType.FILE),
        993: ("imaps", ServiceType.MAIL),
        995: ("pop3s", ServiceType.MAIL),
        1433: ("mssql", ServiceType.DATABASE),
        1521: ("oracle", ServiceType.DATABASE),
        3306: ("mysql", ServiceType.DATABASE),
        3389: ("rdp", ServiceType.REMOTE),
        5432: ("postgresql", ServiceType.DATABASE),
        5900: ("vnc", ServiceType.REMOTE),
        6379: ("redis", ServiceType.CACHE),
        8080: ("http-proxy", ServiceType.WEB),
        8443: ("https-alt", ServiceType.WEB),
        9200: ("elasticsearch", ServiceType.DATABASE),
        11211: ("memcached", ServiceType.CACHE),
        27017: ("mongodb", ServiceType.DATABASE),
    }

    # 高价值目标关键词
    HIGH_VALUE_KEYWORDS = [
        'dev', 'test', 'staging', 'uat', 'admin', 'manage', 'api', 
        'internal', 'backend', 'dashboard', 'portal', 'vpn', 'git',
        'jenkins', 'jira', 'confluence', 'gitlab', 'nexus', 'harbor'
    ]

    # 误报特征模式
    FALSE_POSITIVE_PATTERNS = [
        r'404\s*not\s*found',
        r'page\s*not\s*found',
        r'<!DOCTYPE\s+html>.*?error',
        r'access\s*denied',
        r'forbidden',
        r'static.*?page',
    ]

    def __init__(self, llm_client=None):
        """
        初始化AI大脑
        
        Args:
            llm_client: 可选的LLM客户端，用于高级推理
        """
        self.llm_client = llm_client
        self.context = {}  # 存储上下文信息
        self.decision_log = []  # 决策日志
        
    def analyze_subdomains(self, subdomains: List[str]) -> List[Asset]:
        """
        分析子域名并进行优先级排序
        
        Args:
            subdomains: 子域名列表
            
        Returns:
            按优先级排序的资产列表
        """
        assets = []
        
        for subdomain in subdomains:
            priority = 5  # 默认优先级
            tags = []
            
            subdomain_lower = subdomain.lower()
            
            # 检测高价值关键词
            for keyword in self.HIGH_VALUE_KEYWORDS:
                if keyword in subdomain_lower:
                    priority = min(priority + 2, 10)
                    tags.append(f"high_value:{keyword}")
            
            # 检测开发/测试环境 (更高优先级)
            if any(env in subdomain_lower for env in ['dev', 'test', 'staging', 'uat']):
                priority = min(priority + 3, 10)
                tags.append("environment:non-production")
                
            # 检测管理后台
            if any(admin in subdomain_lower for admin in ['admin', 'manage', 'dashboard', 'portal']):
                priority = min(priority + 2, 10)
                tags.append("type:admin_panel")
                
            # 检测API端点
            if 'api' in subdomain_lower:
                priority = min(priority + 1, 10)
                tags.append("type:api")
            
            assets.append(Asset(
                hostname=subdomain,
                priority=priority,
                tags=tags
            ))
        
        # 按优先级降序排序
        assets.sort(key=lambda x: x.priority, reverse=True)
        
        self._log_decision(
            action="analyze_subdomains",
            input_count=len(subdomains),
            output_count=len(assets),
            reasoning=f"Identified {sum(1 for a in assets if a.priority >= 7)} high-value targets"
        )
        
        return assets

    def classify_service(self, port: int, banner: str = "") -> tuple:
        """
        根据端口和Banner识别服务类型
        
        Args:
            port: 端口号
            banner: 服务Banner
            
        Returns:
            (服务名, 服务类型)
        """
        # 首先查表
        if port in self.PORT_SERVICE_MAP:
            return self.PORT_SERVICE_MAP[port]
        
        # Banner分析
        banner_lower = banner.lower()
        
        if any(web in banner_lower for web in ['http', 'nginx', 'apache', 'tomcat', 'iis']):
            return ("http", ServiceType.WEB)
        if any(db in banner_lower for db in ['mysql', 'mariadb', 'postgresql', 'oracle', 'mssql']):
            return ("database", ServiceType.DATABASE)
        if 'ssh' in banner_lower:
            return ("ssh", ServiceType.REMOTE)
        if 'redis' in banner_lower:
            return ("redis", ServiceType.CACHE)
        if 'ftp' in banner_lower:
            return ("ftp", ServiceType.FILE)
            
        # 常见Web端口范围
        if 8000 <= port <= 9999:
            return ("http-alt", ServiceType.WEB)
            
        return ("unknown", ServiceType.UNKNOWN)

    def plan_attack(self, assets: List[Asset]) -> Dict[str, List[Asset]]:
        """
        根据资产类型制定攻击计划
        
        Args:
            assets: 资产列表
            
        Returns:
            按攻击策略分组的资产字典
        """
        attack_plan = {
            "web_scan": [],      # Web漏洞扫描
            "service_scan": [],  # 服务漏洞扫描
            "auth_test": [],     # 认证测试
            "exposure_check": [] # 敏感信息暴露检查
        }
        
        for asset in assets:
            if not asset.services:
                continue
                
            for port, service in asset.services.items():
                service_name, service_type = self.classify_service(port, service)
                
                if service_type == ServiceType.WEB:
                    attack_plan["web_scan"].append(asset)
                    attack_plan["exposure_check"].append(asset)
                    
                elif service_type == ServiceType.DATABASE:
                    attack_plan["auth_test"].append(asset)
                    attack_plan["service_scan"].append(asset)
                    
                elif service_type == ServiceType.CACHE:
                    # Redis/Memcached 未授权访问检测
                    attack_plan["auth_test"].append(asset)
                    
                elif service_type == ServiceType.REMOTE:
                    attack_plan["auth_test"].append(asset)
                    
                elif service_type == ServiceType.FILE:
                    attack_plan["auth_test"].append(asset)
                    attack_plan["service_scan"].append(asset)
        
        # 去重
        for key in attack_plan:
            seen = set()
            unique = []
            for asset in attack_plan[key]:
                if asset.hostname not in seen:
                    seen.add(asset.hostname)
                    unique.append(asset)
            attack_plan[key] = unique
        
        self._log_decision(
            action="plan_attack",
            reasoning=f"Web targets: {len(attack_plan['web_scan'])}, "
                     f"Service targets: {len(attack_plan['service_scan'])}, "
                     f"Auth targets: {len(attack_plan['auth_test'])}"
        )
        
        return attack_plan

    def select_nuclei_templates(self, service_type: ServiceType, port: int = None) -> List[str]:
        """
        根据服务类型选择合适的Nuclei模板
        
        Args:
            service_type: 服务类型
            port: 端口号(可选)
            
        Returns:
            模板标签列表
        """
        templates = []
        
        if service_type == ServiceType.WEB:
            templates = [
                "cve",
                "sqli", 
                "xss",
                "lfi",
                "rce",
                "ssrf",
                "exposure",
                "misconfig",
                "default-login"
            ]
        elif service_type == ServiceType.DATABASE:
            templates = ["mysql", "postgresql", "mssql", "oracle", "mongodb", "cve"]
            if port == 6379:
                templates = ["redis", "cve"]
            elif port == 9200:
                templates = ["elasticsearch", "cve"]
        elif service_type == ServiceType.CACHE:
            templates = ["redis", "memcached", "cve", "unauth"]
        elif service_type == ServiceType.REMOTE:
            templates = ["ssh", "rdp", "vnc", "default-login", "cve"]
        elif service_type == ServiceType.FILE:
            templates = ["ftp", "smb", "default-login", "cve"]
        else:
            templates = ["cve", "misconfig", "default-login"]
            
        return templates

    def verify_vulnerability(self, vuln: Vulnerability, response_data: str) -> Vulnerability:
        """
        验证漏洞是否为误报
        
        Args:
            vuln: 漏洞对象
            response_data: HTTP响应或其他证据数据
            
        Returns:
            更新后的漏洞对象
        """
        vuln.is_verified = True
        confidence = 0.5  # 基础置信度
        
        response_lower = response_data.lower()
        
        # 检查误报特征
        for pattern in self.FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, response_lower, re.IGNORECASE | re.DOTALL):
                vuln.is_false_positive = True
                vuln.confidence = 0.1
                self._log_decision(
                    action="verify_vulnerability",
                    vuln_id=vuln.id,
                    reasoning=f"False positive detected: matches pattern '{pattern}'"
                )
                return vuln
        
        # SQL注入验证
        if 'sql' in vuln.name.lower():
            sql_indicators = ['sql syntax', 'mysql', 'postgresql', 'sqlite', 'oracle', 
                            'syntax error', 'unclosed quotation', 'query failed']
            if any(ind in response_lower for ind in sql_indicators):
                confidence = 0.9
            else:
                confidence = 0.3  # 无明显数据库错误特征
                
        # XSS验证
        elif 'xss' in vuln.name.lower():
            # 检查payload是否被反射
            if '<script>' in response_lower or 'javascript:' in response_lower:
                confidence = 0.85
            else:
                confidence = 0.4
                
        # RCE验证 - 高危，保守处理
        elif 'rce' in vuln.name.lower() or 'command' in vuln.name.lower():
            confidence = 0.7  # RCE需要人工确认
            
        # 未授权访问验证
        elif 'unauth' in vuln.name.lower() or 'unauthorized' in vuln.name.lower():
            if '200' in response_data[:50]:  # 假设response开头包含状态码
                confidence = 0.85
            else:
                confidence = 0.5
        
        # 默认信息泄露检测
        elif 'exposure' in vuln.name.lower() or 'disclosure' in vuln.name.lower():
            sensitive_patterns = ['password', 'secret', 'api_key', 'token', 'private_key']
            if any(pat in response_lower for pat in sensitive_patterns):
                confidence = 0.9
            else:
                confidence = 0.6
        
        vuln.confidence = confidence
        vuln.is_false_positive = confidence < 0.4
        
        self._log_decision(
            action="verify_vulnerability",
            vuln_id=vuln.id,
            reasoning=f"Confidence: {confidence:.2f}, False positive: {vuln.is_false_positive}"
        )
        
        return vuln

    def decide_next_action(self, current_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        基于当前状态决定下一步行动
        
        Args:
            current_state: 当前状态字典
            
        Returns:
            下一步行动指令
        """
        action = {"type": "wait", "params": {}}
        
        # 状态检查
        subdomains_found = current_state.get("subdomains", [])
        assets_mapped = current_state.get("assets", [])
        vulns_found = current_state.get("vulnerabilities", [])
        current_phase = current_state.get("phase", "init")
        
        if current_phase == "init" or current_phase == "recon":
            if not subdomains_found:
                # 没找到子域名，尝试其他策略
                action = {
                    "type": "recon_fallback",
                    "params": {
                        "strategies": ["bruteforce", "permutation", "c_segment"]
                    },
                    "reasoning": "No subdomains found, trying fallback strategies"
                }
            else:
                action = {
                    "type": "start_mapping",
                    "params": {
                        "targets": [s for s in subdomains_found[:20]],  # 限制前20个
                        "ports": "top-1000"
                    },
                    "reasoning": f"Found {len(subdomains_found)} subdomains, proceeding to port scan"
                }
                
        elif current_phase == "mapping":
            if assets_mapped:
                # 根据服务类型制定攻击计划
                attack_plan = self.plan_attack(assets_mapped)
                action = {
                    "type": "start_attack",
                    "params": {
                        "plan": attack_plan
                    },
                    "reasoning": "Assets mapped, initiating targeted vulnerability scan"
                }
            else:
                action = {
                    "type": "expand_scan",
                    "params": {
                        "port_range": "1-65535"
                    },
                    "reasoning": "No services found on common ports, expanding scan range"
                }
                
        elif current_phase == "attack":
            if vulns_found:
                # 过滤未验证的漏洞
                unverified = [v for v in vulns_found if not v.is_verified]
                if unverified:
                    action = {
                        "type": "verify_vulns",
                        "params": {
                            "vulnerabilities": unverified
                        },
                        "reasoning": f"{len(unverified)} vulnerabilities pending verification"
                    }
                else:
                    action = {
                        "type": "generate_report",
                        "params": {},
                        "reasoning": "All vulnerabilities verified, generating final report"
                    }
            else:
                action = {
                    "type": "complete",
                    "params": {},
                    "reasoning": "Scan complete, no vulnerabilities found"
                }
        
        self._log_decision(
            action="decide_next_action",
            current_phase=current_phase,
            decision=action["type"],
            reasoning=action.get("reasoning", "")
        )
        
        return action

    def analyze_with_llm(self, prompt: str, context: Dict = None) -> str:
        """
        使用LLM进行高级分析（可选功能）
        
        Args:
            prompt: 分析提示
            context: 上下文信息
            
        Returns:
            LLM分析结果
        """
        if not self.llm_client:
            logger.warning("LLM client not configured, using rule-based analysis")
            return ""
        
        try:
            full_prompt = f"""You are an expert red team security analyst. 
            Analyze the following security data and provide your assessment.
            
            Context: {json.dumps(context or {}, indent=2)}
            
            Task: {prompt}
            
            Provide a concise, actionable analysis."""
            
            response = self.llm_client.generate(full_prompt)
            return response
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return ""

    def _log_decision(self, **kwargs):
        """记录决策日志"""
        self.decision_log.append({
            "timestamp": __import__("datetime").datetime.now().isoformat(),
            **kwargs
        })
        logger.info(f"AI Decision: {kwargs}")

    def get_decision_log(self) -> List[Dict]:
        """获取决策日志"""
        return self.decision_log

    def summarize_findings(self, vulns: List[Vulnerability]) -> Dict[str, Any]:
        """
        生成发现总结
        
        Args:
            vulns: 漏洞列表
            
        Returns:
            总结字典
        """
        verified_vulns = [v for v in vulns if v.is_verified and not v.is_false_positive]
        
        summary = {
            "total_findings": len(vulns),
            "verified_vulnerabilities": len(verified_vulns),
            "false_positives_filtered": len([v for v in vulns if v.is_false_positive]),
            "severity_breakdown": {
                "critical": len([v for v in verified_vulns if v.severity == RiskLevel.CRITICAL]),
                "high": len([v for v in verified_vulns if v.severity == RiskLevel.HIGH]),
                "medium": len([v for v in verified_vulns if v.severity == RiskLevel.MEDIUM]),
                "low": len([v for v in verified_vulns if v.severity == RiskLevel.LOW]),
                "info": len([v for v in verified_vulns if v.severity == RiskLevel.INFO]),
            },
            "verified_findings": [
                {
                    "id": v.id,
                    "name": v.name,
                    "severity": v.severity.value,
                    "target": v.target,
                    "confidence": v.confidence
                }
                for v in verified_vulns
            ]
        }
        
        return summary
