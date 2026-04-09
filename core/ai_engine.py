#!/usr/bin/env python3
"""
AI决策引擎 - 智能分析和攻击规划
"""

import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LLM 输出 Pydantic Schema — 防止 Prompt 注入 / 格式异常
# ---------------------------------------------------------------------------


class LLMAttackSuggestion(BaseModel):
    """LLM返回的攻击建议 — Pydantic schema 验证，防止 Prompt 注入"""

    attack_type: str = Field(..., max_length=100)
    tool_name: str = Field(..., max_length=100)
    priority: str = Field(..., pattern=r"^(critical|high|medium|low|info)$")
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str = Field(..., max_length=500)
    params: dict = Field(default_factory=dict)


class LLMAnalysisResponse(BaseModel):
    """LLM分析响应的标准 schema"""

    suggestions: List[LLMAttackSuggestion] = Field(default_factory=list, max_length=20)
    risk_assessment: Optional[str] = Field(None, max_length=1000)


def _parse_llm_json(raw: str) -> Optional[Dict[str, Any]]:
    """从 LLM 原始文本中提取 JSON 块并返回 dict，解析失败返回 None

    支持 ```json ... ``` 包裹和裸 JSON。
    """
    text = raw.strip()
    # 处理 ```json ... ``` 格式
    if "```json" in text:
        try:
            start = text.index("```json") + 7
            end = text.index("```", start)
            text = text[start:end].strip()
        except ValueError:
            pass
    elif "```" in text:
        try:
            start = text.index("```") + 3
            end = text.index("```", start)
            text = text[start:end].strip()
        except ValueError:
            pass
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def validate_llm_response(raw_text: str) -> Optional[LLMAnalysisResponse]:
    """验证 LLM 返回文本是否符合 LLMAnalysisResponse schema

    Args:
        raw_text: LLM 原始响应文本

    Returns:
        验证通过的 LLMAnalysisResponse，失败返回 None
    """
    parsed = _parse_llm_json(raw_text)
    if parsed is None:
        logger.warning("LLM 响应 JSON 解析失败，将回退到本地规则引擎")
        return None
    try:
        return LLMAnalysisResponse.model_validate(parsed)
    except ValidationError as e:
        logger.warning("LLM 响应 schema 验证失败: %s，将回退到本地规则引擎", e)
        return None


class RiskLevel(Enum):
    """风险等级"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AttackVector:
    """攻击向量"""

    name: str
    description: str
    risk_level: RiskLevel
    tools: List[str]
    prerequisites: List[str]
    success_probability: float


class AIDecisionEngine:
    """AI决策引擎"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.provider = self.config.get("provider", "openai")
        self.model = self.config.get("model", "gpt-4")
        env_key_map = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
        self.api_key = self.config.get("api_key") or os.getenv(env_key_map.get(self.provider, ""))
        self._client = None
        self._client_lock = threading.Lock()

        logger.info("AI决策引擎初始化: provider=%s, model=%s", self.provider, self.model)

    def _get_client(self):
        """获取AI客户端（线程安全，double-check locking）"""
        if self._client is None:
            with self._client_lock:
                if self._client is None:
                    self._client = self._create_provider_client()
        return self._client

    def _create_provider_client(self):
        """根据 provider 创建对应的 AI 客户端，失败时降级为 local"""
        provider_map = {
            "openai": ("openai", "OpenAI"),
            "anthropic": ("anthropic", "Anthropic"),
        }
        spec = provider_map.get(self.provider)
        if spec is None:
            return "local"

        module_name, class_name = spec
        if not self.api_key:
            logger.warning("未配置%s API Key，使用本地规则引擎", class_name)
            return "local"
        try:
            mod = __import__(module_name, fromlist=[class_name])
            cls = getattr(mod, class_name)
            return cls(api_key=self.api_key)
        except ImportError:
            logger.warning("%s库未安装，使用本地规则引擎", class_name)
            return "local"

    def analyze_target(
        self, target: str, context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """分析目标"""
        context = context or {}

        # 确定目标类型
        target_type = self._identify_target_type(target)

        analysis = {
            "target": target,
            "type": target_type,
            "recommended_tools": self._get_recommended_tools(target_type),
            "attack_surface": self._analyze_attack_surface(target, target_type, context),
            "risk_assessment": self._assess_risk(target, context),
            "next_steps": self._suggest_next_steps(target_type, context),
        }

        # 如果配置了AI，使用AI增强分析
        client = self._get_client()
        if client != "local" and client is not None:
            try:
                enhanced = self._ai_enhance_analysis(target, context, analysis)
                analysis["ai_insights"] = enhanced
            except Exception as e:
                logger.warning("AI增强分析失败: %s", e)

        return analysis

    def generate_attack_plan(self, target: str, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """生成攻击计划"""
        target_type = self._identify_target_type(target)

        # 分析侦察数据
        open_ports = recon_data.get("ports", [])
        services = recon_data.get("services", [])
        technologies = recon_data.get("technologies", [])
        vulnerabilities = recon_data.get("vulnerabilities", [])

        # 生成攻击向量
        attack_vectors = self._generate_attack_vectors(
            target_type, open_ports, services, technologies, vulnerabilities
        )

        # 排序攻击向量
        sorted_vectors = sorted(
            attack_vectors,
            key=lambda x: (self._risk_priority(x.risk_level), -x.success_probability),
        )

        plan = {
            "target": target,
            "target_type": target_type,
            "phases": self._create_attack_phases(sorted_vectors, recon_data),
            "attack_vectors": [
                {
                    "name": v.name,
                    "description": v.description,
                    "risk_level": v.risk_level.value,
                    "tools": v.tools,
                    "prerequisites": v.prerequisites,
                    "success_probability": v.success_probability,
                }
                for v in sorted_vectors
            ],
            "estimated_time": self._estimate_time(sorted_vectors),
            "recommendations": self._generate_recommendations(recon_data),
        }

        return plan

    def _identify_target_type(self, target: str) -> str:
        """识别目标类型"""
        # IP地址
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ip_pattern, target):
            return "ip"

        # CIDR网段
        cidr_pattern = r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"
        if re.match(cidr_pattern, target):
            return "network"

        # URL
        if target.startswith(("http://", "https://")):
            return "url"

        # 域名
        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
        if re.match(domain_pattern, target):
            return "domain"

        return "unknown"

    def _get_recommended_tools(self, target_type: str) -> Dict[str, List[str]]:
        """根据目标类型推荐工具"""
        recommendations = {
            "ip": {
                "recon": ["nmap_scan", "masscan", "shodan_lookup"],
                "vuln_scan": ["nmap_vuln", "nikto", "nuclei"],
                "exploit": ["metasploit", "searchsploit"],
            },
            "domain": {
                "recon": ["dns_enum", "subfinder", "whois_lookup", "theHarvester"],
                "vuln_scan": ["nuclei", "nikto"],
                "web_attack": ["sqlmap", "xsstrike", "dirb"],
            },
            "url": {
                "recon": ["whatweb", "wappalyzer", "wafw00f"],
                "vuln_scan": ["nikto", "nuclei", "zap_scan"],
                "web_attack": ["sqlmap", "xsstrike", "burp"],
            },
            "network": {
                "recon": ["nmap_discovery", "masscan", "arp_scan"],
                "vuln_scan": ["openvas", "nessus"],
                "network": ["responder", "mitm6"],
            },
        }
        return recommendations.get(target_type, {})

    def _analyze_attack_surface(
        self, target: str, target_type: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """分析攻击面"""
        surface: Dict[str, Any] = {"entry_points": [], "potential_weaknesses": [], "hardening_indicators": []}

        if target_type == "ip":
            surface["entry_points"] = ["开放端口", "运行服务", "管理接口"]
            surface["potential_weaknesses"] = ["过时服务版本", "弱口令", "配置错误"]

        elif target_type == "domain":
            surface["entry_points"] = ["子域名", "Web应用", "邮件服务器", "DNS"]
            surface["potential_weaknesses"] = ["子域名接管", "DNS区域传送", "SPF/DMARC配置"]

        elif target_type == "url":
            surface["entry_points"] = ["Web表单", "API端点", "文件上传", "认证系统"]
            surface["potential_weaknesses"] = ["SQL注入", "XSS", "CSRF", "文件包含"]

        elif target_type == "network":
            surface["entry_points"] = ["网络边界", "内部主机", "网络设备"]
            surface["potential_weaknesses"] = ["广播协议", "内网服务", "凭证复用"]

        return surface

    def _assess_risk(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """风险评估"""
        return {
            "overall_risk": "medium",
            "factors": [
                {"name": "暴露面", "level": "unknown", "details": "需要进一步侦察"},
                {"name": "技术栈", "level": "unknown", "details": "需要识别技术"},
                {"name": "安全配置", "level": "unknown", "details": "需要漏洞扫描"},
            ],
        }

    def _suggest_next_steps(self, target_type: str, context: Dict[str, Any]) -> List[str]:
        """建议下一步操作"""
        steps = {
            "ip": [
                "执行端口扫描确定开放服务",
                "对发现的服务进行版本识别",
                "搜索已知漏洞",
                "尝试默认凭证",
            ],
            "domain": ["收集子域名信息", "执行DNS枚举", "识别Web技术栈", "搜索敏感信息泄露"],
            "url": ["识别Web框架和技术", "扫描常见漏洞", "测试认证机制", "枚举隐藏路径和文件"],
            "network": ["执行主机发现", "识别活跃设备", "扫描常见服务端口", "检测网络协议弱点"],
        }
        return steps.get(target_type, ["执行基础侦察"])

    def _generate_attack_vectors(
        self,
        target_type: str,
        ports: List[int],
        services: List[str],
        technologies: List[str],
        vulnerabilities: List[Dict[str, Any]],
    ) -> List[AttackVector]:
        """生成攻击向量"""
        vectors = []

        # 基于端口的攻击向量
        port_vectors = {
            21: AttackVector(
                "FTP攻击",
                "针对FTP服务的攻击",
                RiskLevel.MEDIUM,
                ["hydra", "nmap_ftp"],
                ["端口21开放"],
                0.6,
            ),
            22: AttackVector(
                "SSH暴力破解",
                "SSH密码爆破",
                RiskLevel.LOW,
                ["hydra", "medusa"],
                ["端口22开放"],
                0.3,
            ),
            23: AttackVector(
                "Telnet攻击",
                "Telnet服务攻击",
                RiskLevel.HIGH,
                ["hydra", "nmap_telnet"],
                ["端口23开放"],
                0.7,
            ),
            80: AttackVector(
                "Web应用攻击",
                "HTTP服务攻击",
                RiskLevel.MEDIUM,
                ["nikto", "dirb", "sqlmap"],
                ["端口80开放"],
                0.5,
            ),
            443: AttackVector(
                "HTTPS应用攻击",
                "HTTPS服务攻击",
                RiskLevel.MEDIUM,
                ["nikto", "sslscan", "sqlmap"],
                ["端口443开放"],
                0.5,
            ),
            445: AttackVector(
                "SMB攻击",
                "SMB/CIFS服务攻击",
                RiskLevel.HIGH,
                ["smbclient", "enum4linux", "eternal_blue"],
                ["端口445开放"],
                0.7,
            ),
            1433: AttackVector(
                "MSSQL攻击",
                "MSSQL数据库攻击",
                RiskLevel.HIGH,
                ["hydra", "mssqlclient"],
                ["端口1433开放"],
                0.5,
            ),
            1521: AttackVector(
                "Oracle攻击",
                "Oracle数据库攻击",
                RiskLevel.HIGH,
                ["hydra", "odat"],
                ["端口1521开放"],
                0.4,
            ),
            3306: AttackVector(
                "MySQL攻击",
                "MySQL数据库攻击",
                RiskLevel.HIGH,
                ["hydra", "sqlmap"],
                ["端口3306开放"],
                0.5,
            ),
            3389: AttackVector(
                "RDP攻击",
                "远程桌面攻击",
                RiskLevel.MEDIUM,
                ["hydra", "rdp_check"],
                ["端口3389开放"],
                0.4,
            ),
            5432: AttackVector(
                "PostgreSQL攻击",
                "PostgreSQL数据库攻击",
                RiskLevel.HIGH,
                ["hydra", "psql"],
                ["端口5432开放"],
                0.5,
            ),
            5900: AttackVector(
                "VNC攻击",
                "VNC远程桌面攻击",
                RiskLevel.MEDIUM,
                ["hydra", "vnc_scanner"],
                ["端口5900开放"],
                0.5,
            ),
            6379: AttackVector(
                "Redis未授权访问",
                "Redis服务攻击",
                RiskLevel.CRITICAL,
                ["redis-cli", "redis_rce"],
                ["端口6379开放"],
                0.8,
            ),
            8080: AttackVector(
                "Web代理/应用服务器攻击",
                "应用服务器攻击",
                RiskLevel.MEDIUM,
                ["nikto", "nuclei"],
                ["端口8080开放"],
                0.5,
            ),
            9200: AttackVector(
                "Elasticsearch未授权访问",
                "ES服务攻击",
                RiskLevel.HIGH,
                ["curl", "es_scanner"],
                ["端口9200开放"],
                0.7,
            ),
            27017: AttackVector(
                "MongoDB未授权访问",
                "MongoDB服务攻击",
                RiskLevel.HIGH,
                ["mongo", "nosql_scanner"],
                ["端口27017开放"],
                0.7,
            ),
        }

        for port in ports:
            if port in port_vectors:
                vectors.append(port_vectors[port])

        # 基于技术栈的攻击向量
        tech_vectors = {
            "wordpress": AttackVector(
                "WordPress攻击",
                "WP插件/主题漏洞利用",
                RiskLevel.MEDIUM,
                ["wpscan", "nuclei"],
                ["WordPress CMS"],
                0.6,
            ),
            "spring": AttackVector(
                "Spring框架攻击",
                "Spring漏洞利用(SPEL/RCE)",
                RiskLevel.HIGH,
                ["nuclei", "spring_scanner"],
                ["Spring框架"],
                0.7,
            ),
            "struts": AttackVector(
                "Struts2攻击",
                "Struts2 RCE漏洞利用",
                RiskLevel.CRITICAL,
                ["struts_scanner", "nuclei"],
                ["Struts2框架"],
                0.8,
            ),
            "thinkphp": AttackVector(
                "ThinkPHP攻击",
                "ThinkPHP RCE漏洞利用",
                RiskLevel.CRITICAL,
                ["thinkphp_scanner", "nuclei"],
                ["ThinkPHP框架"],
                0.8,
            ),
            "weblogic": AttackVector(
                "WebLogic攻击",
                "WebLogic反序列化利用",
                RiskLevel.CRITICAL,
                ["weblogic_scanner", "nuclei"],
                ["WebLogic服务器"],
                0.8,
            ),
            "tomcat": AttackVector(
                "Tomcat攻击",
                "Tomcat管理接口攻击",
                RiskLevel.HIGH,
                ["tomcat_scanner", "nuclei"],
                ["Tomcat服务器"],
                0.6,
            ),
            "jenkins": AttackVector(
                "Jenkins攻击",
                "Jenkins未授权访问/RCE",
                RiskLevel.CRITICAL,
                ["jenkins_scanner", "nuclei"],
                ["Jenkins CI/CD"],
                0.7,
            ),
            "gitlab": AttackVector(
                "GitLab攻击",
                "GitLab CVE漏洞利用",
                RiskLevel.HIGH,
                ["gitlab_scanner", "nuclei"],
                ["GitLab"],
                0.6,
            ),
            "confluence": AttackVector(
                "Confluence攻击",
                "Confluence OGNL注入",
                RiskLevel.CRITICAL,
                ["confluence_scanner", "nuclei"],
                ["Confluence"],
                0.8,
            ),
            "jira": AttackVector(
                "Jira攻击",
                "Jira SSRF/模板注入",
                RiskLevel.HIGH,
                ["jira_scanner", "nuclei"],
                ["Jira"],
                0.6,
            ),
            "exchange": AttackVector(
                "Exchange攻击",
                "ProxyLogon/ProxyShell利用",
                RiskLevel.CRITICAL,
                ["exchange_scanner", "nuclei"],
                ["Exchange服务器"],
                0.7,
            ),
            "vcenter": AttackVector(
                "vCenter攻击",
                "vCenter RCE漏洞利用",
                RiskLevel.CRITICAL,
                ["vcenter_scanner", "nuclei"],
                ["VMware vCenter"],
                0.7,
            ),
            "kubernetes": AttackVector(
                "K8s攻击",
                "K8s API未授权访问",
                RiskLevel.CRITICAL,
                ["kubectl", "kube_hunter"],
                ["Kubernetes集群"],
                0.6,
            ),
            "docker": AttackVector(
                "Docker攻击",
                "Docker API未授权访问",
                RiskLevel.CRITICAL,
                ["docker_scanner", "nuclei"],
                ["Docker服务"],
                0.7,
            ),
        }

        for tech in technologies:
            tech_lower = tech.lower()
            for key, vector in tech_vectors.items():
                if key in tech_lower:
                    vectors.append(vector)
                    break

        # 基于漏洞的攻击向量
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "medium").lower()
            risk_map = {
                "critical": RiskLevel.CRITICAL,
                "high": RiskLevel.HIGH,
                "medium": RiskLevel.MEDIUM,
                "low": RiskLevel.LOW,
            }
            vectors.append(
                AttackVector(
                    name=f"利用 {vuln.get('id', 'Unknown')}",
                    description=vuln.get("description", "已知漏洞利用"),
                    risk_level=risk_map.get(severity, RiskLevel.MEDIUM),
                    tools=["metasploit", "searchsploit"],
                    prerequisites=[f"存在{vuln.get('id')}漏洞"],
                    success_probability=0.8 if severity == "critical" else 0.5,
                )
            )

        return vectors

    def _create_attack_phases(
        self, vectors: List[AttackVector], recon_data: Dict
    ) -> List[Dict[str, Any]]:
        """创建攻击阶段"""
        phases = [
            {
                "phase": 1,
                "name": "信息收集",
                "status": "completed" if recon_data else "pending",
                "tools": ["nmap", "subfinder", "whatweb"],
                "objectives": ["识别目标", "收集开放端口和服务", "识别技术栈"],
            },
            {
                "phase": 2,
                "name": "漏洞发现",
                "status": "pending",
                "tools": ["nuclei", "nikto", "nmap_vuln"],
                "objectives": ["扫描已知漏洞", "识别配置错误", "发现安全弱点"],
            },
            {
                "phase": 3,
                "name": "漏洞利用",
                "status": "pending",
                "tools": [v.tools[0] for v in vectors[:3] if v.tools],
                "objectives": ["获取初始访问", "验证漏洞可利用性"],
            },
            {
                "phase": 4,
                "name": "权限提升",
                "status": "pending",
                "tools": ["linpeas", "winpeas", "linux_exploit_suggester"],
                "objectives": ["提升权限", "获取更高访问级别"],
            },
            {
                "phase": 5,
                "name": "后渗透",
                "status": "pending",
                "tools": ["mimikatz", "bloodhound", "empire"],
                "objectives": ["横向移动", "持久化", "数据收集"],
            },
        ]
        return phases

    def _risk_priority(self, risk: RiskLevel) -> int:
        """风险优先级"""
        priority = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 3,
            RiskLevel.INFO: 4,
        }
        return priority.get(risk, 5)

    def _estimate_time(self, vectors: List[AttackVector]) -> str:
        """估计时间"""
        base_time = 30  # 基础30分钟
        per_vector = 15  # 每个向量15分钟
        total_minutes = base_time + len(vectors) * per_vector

        if total_minutes < 60:
            return f"{total_minutes}分钟"
        else:
            hours = total_minutes // 60
            minutes = total_minutes % 60
            return f"{hours}小时{minutes}分钟"

    def _generate_recommendations(self, recon_data: Dict) -> List[str]:
        """生成建议"""
        recommendations = []

        ports = recon_data.get("ports", [])
        if 21 in ports:
            recommendations.append("发现FTP服务，建议检查匿名登录和弱口令")
        if 22 in ports:
            recommendations.append("发现SSH服务，建议检查密钥认证和版本漏洞")
        if 80 in ports or 443 in ports:
            recommendations.append("发现Web服务，建议进行全面Web漏洞扫描")
        if 445 in ports:
            recommendations.append("发现SMB服务，建议检查EternalBlue等漏洞")
        if 3389 in ports:
            recommendations.append("发现RDP服务，建议检查BlueKeep漏洞和弱口令")

        if not recommendations:
            recommendations.append("建议先执行全面端口扫描以发现可攻击面")

        return recommendations

    @staticmethod
    def _sanitize_input(text: str, max_length: int = 200) -> str:
        """清理用户输入，防止 prompt 注入

        Args:
            text: 原始输入
            max_length: 最大长度

        Returns:
            清理后的字符串
        """
        # 移除控制字符（保留常规空格）
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
        # 移除换行符（防止 prompt 注入换行分割）
        text = text.replace("\n", " ").replace("\r", " ")
        # 截断到最大长度
        return text[:max_length]

    def _ai_enhance_analysis(self, target: str, context: Dict, analysis: Dict) -> Dict[str, Any]:
        """AI增强分析 — 通过 Pydantic schema 验证 LLM 输出，防止 Prompt 注入"""
        client = self._get_client()

        # 清理输入防止 prompt 注入（基础防护: 控制字符/换行/截断）
        # NOTE: 作为红队工具，target 本身可能包含恶意内容，此处仅做格式层面清理，
        # 不防御语义级 prompt 注入（如"忽略以上指令"），因为 AI 输出仅用于分析建议
        safe_target = self._sanitize_input(target, max_length=200)
        safe_context = self._sanitize_input(
            json.dumps(context, ensure_ascii=False), max_length=2000
        )
        analysis_type = self._sanitize_input(str(analysis.get("type", "")), max_length=50)

        prompt = f"""作为红队安全专家,分析以下目标并提供攻击建议。

目标: {safe_target}
类型: {analysis_type}
上下文: {safe_context}

请严格以以下 JSON schema 返回结果（不要添加任何额外字段）:
{{
  "suggestions": [
    {{
      "attack_type": "攻击类型 (max 100字符)",
      "tool_name": "推荐工具名 (max 100字符)",
      "priority": "critical|high|medium|low|info",
      "confidence": 0.0-1.0,
      "reason": "推荐理由 (max 500字符)",
      "params": {{}}
    }}
  ],
  "risk_assessment": "整体风险评估 (max 1000字符)"
}}

仅回答安全相关内容，以纯 JSON 格式返回。"""

        raw_text: Optional[str] = None
        try:
            if self.provider == "openai":
                response = client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": "你是一个安全分析助手，只回答与网络安全分析相关的问题。以纯JSON格式回答。",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.3,
                    timeout=30,
                )
                raw_text = response.choices[0].message.content
            elif self.provider == "anthropic":
                response = client.messages.create(
                    model=self.model,
                    max_tokens=2000,
                    messages=[{"role": "user", "content": prompt}],
                    timeout=30,
                )
                raw_text = response.content[0].text
        except Exception as e:
            logger.error("AI调用失败: %s", e)
            return {"error": str(e)}

        if not raw_text:
            return {}

        # 通过 Pydantic schema 验证 LLM 输出
        validated = validate_llm_response(raw_text)
        if validated is not None:
            return {
                "insights": validated.model_dump(),
                "validated": True,
            }

        # Schema 验证失败 — 回退到本地规则引擎的基础分析
        logger.warning("LLM 输出未通过 schema 验证，使用本地规则引擎回退")
        return {
            "insights": self._local_fallback_analysis(target, analysis),
            "validated": False,
            "fallback": True,
        }

    def _local_fallback_analysis(self, target: str, analysis: Dict) -> Dict[str, Any]:
        """当 LLM 输出 schema 验证失败时的本地规则引擎回退

        基于目标类型提供静态攻击建议，不依赖 LLM。
        """
        target_type = analysis.get("type", "unknown")
        fallback_map: Dict[str, List[Dict[str, Any]]] = {
            "ip": [
                {
                    "attack_type": "端口扫描与服务识别",
                    "tool_name": "nmap_scan",
                    "priority": "high",
                    "confidence": 0.8,
                    "reason": "IP目标优先执行端口扫描发现攻击面",
                    "params": {},
                }
            ],
            "url": [
                {
                    "attack_type": "Web漏洞扫描",
                    "tool_name": "nuclei",
                    "priority": "high",
                    "confidence": 0.7,
                    "reason": "URL目标优先执行Web漏洞扫描",
                    "params": {},
                }
            ],
            "domain": [
                {
                    "attack_type": "子域名枚举",
                    "tool_name": "subfinder",
                    "priority": "high",
                    "confidence": 0.8,
                    "reason": "域名目标优先枚举子域名扩大攻击面",
                    "params": {},
                }
            ],
        }
        return {
            "suggestions": fallback_map.get(target_type, []),
            "risk_assessment": "本地规则引擎评估 — LLM 不可用",
        }

    def suggest_tool(self, context: Dict[str, Any]) -> str:
        """根据上下文推荐工具"""
        phase = context.get("phase", "recon")
        target_type = context.get("target_type", "unknown")
        context.get("previous_results", [])

        tool_matrix = {
            ("recon", "ip"): "nmap_scan",
            ("recon", "domain"): "subfinder",
            ("recon", "url"): "whatweb",
            ("vuln_scan", "ip"): "nmap_vuln",
            ("vuln_scan", "url"): "nikto",
            ("exploit", "ip"): "metasploit",
            ("exploit", "url"): "sqlmap",
        }

        return tool_matrix.get((phase, target_type), "nmap_scan")
