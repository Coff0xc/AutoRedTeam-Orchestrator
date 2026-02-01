#!/usr/bin/env python3
"""
decision.py - 智能决策引擎

根据侦察结果和漏洞发现智能选择攻击路径

增强功能 (v3.0.0):
- 多因素攻击路径评分
- 风险评估与规避建议
- 自适应策略调整
- 攻击链优化
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from .state import PentestPhase, PentestState

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """风险级别"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackComplexity(Enum):
    """攻击复杂度"""

    TRIVIAL = "trivial"  # 一键利用
    LOW = "low"  # 简单配置
    MEDIUM = "medium"  # 需要定制
    HIGH = "high"  # 复杂利用链
    EXPERT = "expert"  # 需要专家技能


@dataclass
class AttackPath:
    """攻击路径 - 增强版"""

    name: str
    description: str
    phases: List["PentestPhase"]
    priority: int
    success_probability: float
    tools: List[str]
    prerequisites: List[str]

    # v3.0.0 新增字段
    complexity: AttackComplexity = AttackComplexity.MEDIUM
    detection_risk: RiskLevel = RiskLevel.MEDIUM
    impact_score: float = 0.0  # 0-10
    time_estimate_minutes: int = 30
    fallback_paths: List[str] = field(default_factory=list)
    required_vulns: List[str] = field(default_factory=list)

    @property
    def weighted_score(self) -> float:
        """计算加权评分"""
        success_weight = self.success_probability * 0.4
        impact_weight = (self.impact_score / 10) * 0.3
        complexity_map = {
            AttackComplexity.TRIVIAL: 1.0,
            AttackComplexity.LOW: 0.8,
            AttackComplexity.MEDIUM: 0.6,
            AttackComplexity.HIGH: 0.4,
            AttackComplexity.EXPERT: 0.2,
        }
        complexity_weight = complexity_map.get(self.complexity, 0.5) * 0.15
        risk_map = {
            RiskLevel.LOW: 1.0,
            RiskLevel.MEDIUM: 0.7,
            RiskLevel.HIGH: 0.4,
            RiskLevel.CRITICAL: 0.1,
        }
        risk_weight = risk_map.get(self.detection_risk, 0.5) * 0.15
        return success_weight + impact_weight + complexity_weight + risk_weight

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "phases": [p.value if hasattr(p, "value") else str(p) for p in self.phases],
            "priority": self.priority,
            "success_probability": self.success_probability,
            "tools": self.tools,
            "prerequisites": self.prerequisites,
            "complexity": self.complexity.value,
            "detection_risk": self.detection_risk.value,
            "impact_score": self.impact_score,
            "time_estimate_minutes": self.time_estimate_minutes,
            "weighted_score": self.weighted_score,
        }


@dataclass
class ThreatContext:
    """威胁上下文 - 描述当前环境的防御态势"""

    waf_detected: bool = False
    waf_type: Optional[str] = None
    ids_suspected: bool = False
    rate_limiting_detected: bool = False
    honeypot_suspected: bool = False
    captcha_required: bool = False
    multi_factor_auth: bool = False
    defense_score: float = 0.0  # 0-10

    @classmethod
    def from_recon_data(cls, recon_data: Dict[str, Any]) -> "ThreatContext":
        """从侦察数据创建威胁上下文"""
        waf = recon_data.get("waf_detected")
        defense_score = 0.0

        if waf:
            defense_score += 3.0
        if recon_data.get("captcha_detected"):
            defense_score += 1.5
        if recon_data.get("rate_limiting"):
            defense_score += 1.0
        if recon_data.get("security_headers", {}).get("x-frame-options"):
            defense_score += 0.5
        if recon_data.get("security_headers", {}).get("content-security-policy"):
            defense_score += 1.0

        return cls(
            waf_detected=bool(waf),
            waf_type=waf if isinstance(waf, str) else None,
            rate_limiting_detected=bool(recon_data.get("rate_limiting")),
            captcha_required=bool(recon_data.get("captcha_detected")),
            defense_score=min(defense_score, 10.0),
        )


class DecisionEngine:
    """智能决策引擎 - 增强版"""

    def __init__(self, state: "PentestState"):
        self.state = state
        self.logger = logging.getLogger(__name__)
        self.threat_context: Optional[ThreatContext] = None
        self._attack_history: List[Dict[str, Any]] = []
        self._failed_paths: List[str] = []
        self._successful_techniques: List[str] = []
        self._weights = {
            "success_probability": 0.35,
            "impact": 0.25,
            "stealth": 0.20,
            "complexity": 0.10,
            "time": 0.10,
        }

    def update_threat_context(self, recon_data: Dict[str, Any]) -> None:
        """更新威胁上下文"""
        self.threat_context = ThreatContext.from_recon_data(recon_data)
        self.logger.info(f"威胁上下文更新: 防御评分={self.threat_context.defense_score:.1f}")

    def record_attack_result(
        self,
        path_name: str,
        success: bool,
        techniques_used: List[str],
        detection_events: Optional[List[str]] = None,
    ) -> None:
        """记录攻击结果用于自适应学习"""
        self._attack_history.append(
            {
                "path": path_name,
                "success": success,
                "techniques": techniques_used,
                "detection_events": detection_events or [],
                "timestamp": datetime.now().isoformat(),
            }
        )

        if success:
            self._successful_techniques.extend(techniques_used)
        else:
            self._failed_paths.append(path_name)

        if detection_events:
            self._adjust_stealth_preference()

    def _adjust_stealth_preference(self) -> None:
        """根据检测事件调整隐蔽性权重"""
        detection_count = sum(len(h.get("detection_events", [])) for h in self._attack_history[-5:])
        if detection_count > 3:
            self._weights["stealth"] = min(0.35, self._weights["stealth"] + 0.05)
            self._weights["success_probability"] = max(
                0.25, self._weights["success_probability"] - 0.025
            )
            self._weights["impact"] = max(0.15, self._weights["impact"] - 0.025)
            self.logger.info(f"检测到多次告警，提升隐蔽性权重至 {self._weights['stealth']:.2f}")

    def suggest_next_phase(self) -> Optional["PentestPhase"]:
        """建议下一个阶段"""
        from .state import PentestPhase

        phase_order = [
            PentestPhase.RECON,
            PentestPhase.VULN_SCAN,
            PentestPhase.POC_EXEC,
            PentestPhase.EXPLOIT,
            PentestPhase.PRIVILEGE_ESC,
            PentestPhase.LATERAL_MOVE,
            PentestPhase.EXFILTRATE,
            PentestPhase.REPORT,
        ]

        current = self.state.current_phase
        try:
            current_idx = phase_order.index(current)
        except ValueError:
            return PentestPhase.RECON

        if self._should_backtrack():
            backtrack_phase = self._get_backtrack_phase(current)
            if backtrack_phase:
                self.logger.info(f"检测到攻击受阻，回退至 {backtrack_phase.value}")
                return backtrack_phase

        next_idx = current_idx + 1
        while next_idx < len(phase_order):
            next_phase = phase_order[next_idx]
            skip_reason = self._should_skip_phase_v2(next_phase)
            if skip_reason:
                self.logger.info(f"跳过阶段 {next_phase.value}: {skip_reason}")
                next_idx += 1
                continue
            return next_phase
        return PentestPhase.REPORT

    def _should_backtrack(self) -> bool:
        """判断是否需要回退"""
        recent = self._attack_history[-3:]
        if len(recent) >= 3 and all(not h["success"] for h in recent):
            return True
        return False

    def _get_backtrack_phase(self, current: "PentestPhase") -> Optional["PentestPhase"]:
        """获取回退目标阶段"""
        from .state import PentestPhase

        if current == PentestPhase.EXPLOIT:
            return PentestPhase.VULN_SCAN
        if current == PentestPhase.PRIVILEGE_ESC:
            return PentestPhase.EXPLOIT
        return None

    def _should_skip_phase_v2(self, phase: "PentestPhase") -> Optional[str]:
        """判断是否应该跳过阶段，返回跳过原因"""
        from .state import PentestPhase

        if phase == PentestPhase.EXPLOIT:
            high_vulns = self.state.get_high_value_findings()
            if not high_vulns:
                return "无高危漏洞发现"
            exploitable = [v for v in high_vulns if self._is_exploitable(v)]
            if not exploitable:
                return "无可直接利用的漏洞"

        if phase == PentestPhase.POC_EXEC:
            findings = self.state.findings
            if not findings:
                return "无漏洞发现需要验证"

        if phase == PentestPhase.PRIVILEGE_ESC:
            if not self.state.access_list:
                return "无初始访问权限"
            if self._has_high_privilege():
                return "已获得高权限访问"

        if phase == PentestPhase.LATERAL_MOVE:
            if not self.state.credentials:
                return "无可用凭证"
            if len(self.state.discovered_hosts) <= 1:
                return "仅单一目标"
            if self._is_network_fully_compromised():
                return "目标网段已完全控制"

        if phase == PentestPhase.EXFILTRATE:
            if self.state.config.get("skip_exfiltrate", True):
                return "配置禁止数据外泄"

        return None

    def _is_exploitable(self, vuln: Dict[str, Any]) -> bool:
        """判断漏洞是否可直接利用"""
        vuln_type = vuln.get("type", "").lower()
        direct_exploitable = ["rce", "sqli", "ssrf", "lfi", "xxe", "deserialize", "upload"]

        if any(t in vuln_type for t in direct_exploitable):
            return True
        if vuln.get("poc_available") or vuln.get("cve_id"):
            return True
        return False

    def _has_high_privilege(self) -> bool:
        """检查是否已获得高权限"""
        for access in self.state.access_list:
            # AccessInfo 是 dataclass，使用属性访问
            level = getattr(access, "privilege_level", "").lower()
            if level in ("root", "system", "admin", "administrator", "domain_admin"):
                return True
        return False

    def _is_network_fully_compromised(self) -> bool:
        """检查网段是否已完全控制"""
        compromised_hosts = set(self.state.discovered_hosts)
        total_hosts = set(self.state.recon_data.get("all_hosts", []))

        if not total_hosts:
            return False

        coverage = len(compromised_hosts & total_hosts) / len(total_hosts)
        return coverage >= 0.9

    def _should_skip_phase(self, phase: "PentestPhase") -> bool:
        """判断是否应该跳过阶段（兼容旧接口）"""
        return bool(self._should_skip_phase_v2(phase))

    def suggest_attack_paths(self) -> List[AttackPath]:
        """建议攻击路径"""

        paths: List[AttackPath] = []
        findings = self.state.findings
        recon_data = self.state.recon_data

        if not self.threat_context:
            self.update_threat_context(recon_data)

        vuln_categories = self._categorize_vulns(findings)

        if vuln_categories["rce"]:
            paths.append(self._build_rce_path(vuln_categories["rce"]))

        if vuln_categories["deserialize"]:
            paths.append(self._build_deserialize_path(vuln_categories["deserialize"]))

        if vuln_categories["sqli"]:
            paths.append(self._build_sqli_path(vuln_categories["sqli"]))

        if vuln_categories["ssrf"]:
            paths.append(self._build_ssrf_path(vuln_categories["ssrf"]))

        if vuln_categories["xxe"]:
            paths.append(self._build_xxe_path(vuln_categories["xxe"]))

        if vuln_categories["upload"]:
            paths.append(self._build_upload_path(vuln_categories["upload"]))

        if vuln_categories["lfi"]:
            paths.append(self._build_lfi_path(vuln_categories["lfi"]))

        if vuln_categories["auth"]:
            paths.append(self._build_auth_bypass_path(vuln_categories["auth"]))

        if vuln_categories["ssti"]:
            paths.append(self._build_ssti_path(vuln_categories["ssti"]))

        open_ports = recon_data.get("open_ports", [])
        service_ports = [
            p
            for p in open_ports
            if p.get("service") in ("ssh", "ftp", "mysql", "smb", "rdp", "winrm")
        ]
        if service_ports:
            paths.append(self._build_brute_force_path(service_ports))

        paths = self._adjust_paths_for_context(paths)
        paths = [p for p in paths if p.name not in self._failed_paths]
        paths.sort(key=lambda p: (-p.weighted_score, p.priority))

        return paths

    def _categorize_vulns(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """分类漏洞"""
        categories: Dict[str, List[Dict[str, Any]]] = {
            "rce": [],
            "sqli": [],
            "ssrf": [],
            "xxe": [],
            "lfi": [],
            "ssti": [],
            "xss": [],
            "auth": [],
            "upload": [],
            "deserialize": [],
            "other": [],
        }

        for finding in findings:
            vuln_type = finding.get("type", "").lower()

            if any(t in vuln_type for t in ["rce", "cmd", "command", "exec"]):
                categories["rce"].append(finding)
            elif "sql" in vuln_type:
                categories["sqli"].append(finding)
            elif "ssrf" in vuln_type:
                categories["ssrf"].append(finding)
            elif "xxe" in vuln_type or "xml" in vuln_type:
                categories["xxe"].append(finding)
            elif any(t in vuln_type for t in ["lfi", "path", "traversal", "directory"]):
                categories["lfi"].append(finding)
            elif "ssti" in vuln_type or "template" in vuln_type:
                categories["ssti"].append(finding)
            elif "xss" in vuln_type:
                categories["xss"].append(finding)
            elif any(t in vuln_type for t in ["auth", "bypass", "login"]):
                categories["auth"].append(finding)
            elif "upload" in vuln_type:
                categories["upload"].append(finding)
            elif any(t in vuln_type for t in ["deserialize", "serial", "fastjson", "jackson"]):
                categories["deserialize"].append(finding)
            else:
                categories["other"].append(finding)

        return categories

    def _build_rce_path(self, vulns: List[Dict[str, Any]]) -> AttackPath:
        """构建RCE攻击路径"""
        from .state import PentestPhase

        return AttackPath(
            name="RCE直接利用",
            description="通过远程代码执行直接获取系统访问",
            phases=[PentestPhase.POC_EXEC, PentestPhase.EXPLOIT, PentestPhase.PRIVILEGE_ESC],
            priority=1,
            success_probability=0.85,
            tools=["poc_execute", "reverse_shell", "webshell_manager"],
            prerequisites=["verified_rce_vuln"],
            complexity=AttackComplexity.LOW,
            detection_risk=RiskLevel.MEDIUM,
            impact_score=9.5,
            time_estimate_minutes=15,
            required_vulns=[v.get("id", "") for v in vulns],
            fallback_paths=["反序列化利用", "SSTI利用"],
        )

    def _build_deserialize_path(self, vulns: List[Dict[str, Any]]) -> AttackPath:
        """构建反序列化攻击路径"""
        from .state import PentestPhase

        complexity = AttackComplexity.MEDIUM
        for v in vulns:
            if "fastjson" in v.get("type", "").lower():
                complexity = AttackComplexity.LOW
                break

        return AttackPath(
            name="反序列化利用",
            description="通过不安全反序列化获取代码执行",
            phases=[PentestPhase.POC_EXEC, PentestPhase.EXPLOIT, PentestPhase.PRIVILEGE_ESC],
            priority=1,
            success_probability=0.75,
            tools=["ysoserial", "fastjson_exploit", "deserialize_scan"],
            prerequisites=["verified_deserialize_vuln"],
            complexity=complexity,
            detection_risk=RiskLevel.LOW,
            impact_score=9.0,
            time_estimate_minutes=25,
            required_vulns=[v.get("id", "") for v in vulns],
            fallback_paths=["RCE直接利用", "XXE利用"],
        )

    def _build_sqli_path(self, vulns: List[Dict[str, Any]]) -> AttackPath:
        """构建SQL注入攻击路径"""
        from .state import PentestPhase

        can_rce = any(
            v.get("stacked_queries") or "stacked" in v.get("type", "").lower() for v in vulns
        )

        phases = [PentestPhase.POC_EXEC, PentestPhase.EXPLOIT]
        if can_rce:
            phases.append(PentestPhase.PRIVILEGE_ESC)

        return AttackPath(
            name="SQL注入利用",
            description="通过SQL注入获取数据库访问和敏感数据" + (" (可能RCE)" if can_rce else ""),
            phases=phases,
            priority=2,
            success_probability=0.80 if can_rce else 0.70,
            tools=["sqlmap", "sqli_exploiter", "db_dumper"],
            prerequisites=["verified_sqli_vuln"],
            complexity=AttackComplexity.LOW,
            detection_risk=RiskLevel.MEDIUM,
            impact_score=8.5 if can_rce else 7.0,
            time_estimate_minutes=30,
            required_vulns=[v.get("id", "") for v in vulns],
            fallback_paths=["认证绕过"],
        )

    def _build_ssrf_path(self, vulns: List[Dict[str, Any]]) -> AttackPath:
        """构建SSRF攻击路径"""
        from .state import PentestPhase

        return AttackPath(
            name="SSRF内网探测",
            description="通过SSRF探测内网服务并尝试访问",
            phases=[PentestPhase.POC_EXEC, PentestPhase.EXPLOIT, PentestPhase.LATERAL_MOVE],
            priority=2,
            success_probability=0.65,
            tools=["ssrf_detect", "internal_scan", "cloud_metadata"],
            prerequisites=["verified_ssrf_vuln"],
            complexity=AttackComplexity.MEDIUM,
            detection_risk=RiskLevel.LOW,
            impact_score=7.5,
            time_estimate_minutes=40,
            required_vulns=[v.get("id", "") for v in vulns],
            fallback_paths=["XXE利用"],
        )

    def _build_xxe_path(self, vulns: List[Dict[str, Any]]) -> AttackPath:
        """构建XXE攻击路径"""
        from .state import PentestPhase

        return AttackPath(
            name="XXE利用",
            description="通过XXE读取敏感文件或进行SSRF",
            phases=[PentestPhase.POC_EXEC, PentestPhase.EXPLOIT],
            priority=2,
            success_probability=0.70,
            tools=["xxe_exploit", "oob_exfil"],
            prerequisites=["verified_xxe_vuln"],
            complexity=AttackComplexity.MEDIUM,
            detection_risk=RiskLevel.LOW,
            impact_score=7.0,
            time_estimate_minutes=25,
            required_vulns=[v.get("id", "") for v in vulns],
            fallback_paths=["LFI利用", "SSRF内网探测"],
        )

    def _build_upload_path(self, vulns: List[Dict[str, Any]]) -> AttackPath:
        """构建文件上传攻击路径"""
        from .state import PentestPhase

        return AttackPath(
            name="文件上传利用",
            description="通过任意文件上传获取Webshell",
            phases=[PentestPhase.POC_EXEC, PentestPhase.EXPLOIT, PentestPhase.PRIVILEGE_ESC],
            priority=1,
            success_probability=0.80,
            tools=["upload_bypass", "webshell_manager"],
            prerequisites=["verified_upload_vuln"],
            complexity=AttackComplexity.LOW,
            detection_risk=RiskLevel.MEDIUM,
            impact_score=9.0,
            time_estimate_minutes=20,
            required_vulns=[v.get("id", "") for v in vulns],
            fallback_paths=["RCE直接利用"],
        )

    def _build_lfi_path(self, vulns: List[Dict[str, Any]]) -> AttackPath:
        """构建LFI攻击路径"""
        from .state import PentestPhase

        return AttackPath(
            name="LFI利用",
            description="通过本地文件包含读取敏感配置或RCE",
            phases=[PentestPhase.POC_EXEC, PentestPhase.EXPLOIT],
            priority=2,
            success_probability=0.65,
            tools=["lfi_exploit", "log_poisoning", "php_filter"],
            prerequisites=["verified_lfi_vuln"],
            complexity=AttackComplexity.MEDIUM,
            detection_risk=RiskLevel.LOW,
            impact_score=7.5,
            time_estimate_minutes=35,
            required_vulns=[v.get("id", "") for v in vulns],
            fallback_paths=["XXE利用"],
        )

    def _build_auth_bypass_path(self, vulns: List[Dict[str, Any]]) -> AttackPath:
        """构建认证绕过攻击路径"""
        from .state import PentestPhase

        return AttackPath(
            name="认证绕过",
            description="绕过认证获取未授权访问",
            phases=[PentestPhase.POC_EXEC, PentestPhase.EXPLOIT],
            priority=2,
            success_probability=0.70,
            tools=["auth_bypass_detect", "session_hijack"],
            prerequisites=["verified_auth_vuln"],
            complexity=AttackComplexity.MEDIUM,
            detection_risk=RiskLevel.MEDIUM,
            impact_score=8.0,
            time_estimate_minutes=20,
            required_vulns=[v.get("id", "") for v in vulns],
            fallback_paths=["服务凭证爆破"],
        )

    def _build_ssti_path(self, vulns: List[Dict[str, Any]]) -> AttackPath:
        """构建SSTI攻击路径"""
        from .state import PentestPhase

        return AttackPath(
            name="SSTI利用",
            description="通过服务端模板注入获取代码执行",
            phases=[PentestPhase.POC_EXEC, PentestPhase.EXPLOIT, PentestPhase.PRIVILEGE_ESC],
            priority=1,
            success_probability=0.75,
            tools=["ssti_exploit", "tplmap"],
            prerequisites=["verified_ssti_vuln"],
            complexity=AttackComplexity.MEDIUM,
            detection_risk=RiskLevel.LOW,
            impact_score=9.0,
            time_estimate_minutes=25,
            required_vulns=[v.get("id", "") for v in vulns],
            fallback_paths=["RCE直接利用"],
        )

    def _build_brute_force_path(self, service_ports: List[Dict[str, Any]]) -> AttackPath:
        """构建服务凭证爆破攻击路径"""
        from .state import PentestPhase

        services = list(set(p.get("service", "unknown") for p in service_ports))

        return AttackPath(
            name="服务凭证爆破",
            description=f'对开放服务进行凭证爆破: {", ".join(services)}',
            phases=[PentestPhase.EXPLOIT, PentestPhase.PRIVILEGE_ESC],
            priority=3,
            success_probability=0.35,
            tools=["hydra", "medusa", "weak_password_detect"],
            prerequisites=["open_service_ports"],
            complexity=AttackComplexity.TRIVIAL,
            detection_risk=RiskLevel.HIGH,
            impact_score=8.0,
            time_estimate_minutes=60,
            required_vulns=[],
            fallback_paths=[],
        )

    def _adjust_paths_for_context(self, paths: List[AttackPath]) -> List[AttackPath]:
        """根据威胁上下文调整攻击路径评分"""
        if not self.threat_context:
            return paths

        adjusted_paths: List[AttackPath] = []
        for path in paths:
            # WAF环境下降低成功概率
            if self.threat_context.waf_detected:
                if path.detection_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                    path.success_probability *= 0.7

            # 高防御环境提升低检测风险路径
            if self.threat_context.defense_score > 5:
                if path.detection_risk == RiskLevel.LOW:
                    path.success_probability *= 1.1
                elif path.detection_risk == RiskLevel.CRITICAL:
                    path.success_probability *= 0.6

            adjusted_paths.append(path)

        return adjusted_paths

    def select_tools_for_phase(self, phase: "PentestPhase") -> List[str]:
        """为阶段选择工具"""
        from .state import PentestPhase

        recon_data = self.state.recon_data
        technologies = recon_data.get("technologies", [])
        waf_detected = recon_data.get("waf_detected")

        tools: List[str] = []

        if phase == PentestPhase.VULN_SCAN:
            tools = ["sqli", "xss", "ssrf", "ssti", "path_traversal"]
            tech_str = " ".join(str(t) for t in technologies).lower()
            if "php" in tech_str:
                tools.extend(["lfi", "rfi", "serialize"])
            if "java" in tech_str:
                tools.extend(["xxe", "deserialize", "fastjson"])
            if "node" in tech_str or "express" in tech_str:
                tools.extend(["prototype_pollution"])
            if "graphql" in tech_str:
                tools.extend(["graphql_introspection", "graphql_dos"])
            if waf_detected:
                tools.append("waf_bypass")

        elif phase == PentestPhase.EXPLOIT:
            for finding in self.state.findings:
                vuln_type = finding.get("type", "").lower()
                if "sql" in vuln_type:
                    tools.append("sqlmap")
                if "rce" in vuln_type or "cmd" in vuln_type:
                    tools.append("reverse_shell")
                if "ssrf" in vuln_type:
                    tools.append("ssrf_exploit")
                if "deserialize" in vuln_type or "fastjson" in vuln_type:
                    tools.append("ysoserial")
                if "upload" in vuln_type:
                    tools.append("webshell_manager")

        elif phase == PentestPhase.PRIVILEGE_ESC:
            tools = ["linpeas", "winpeas", "sudo_check", "suid_exploit"]

        elif phase == PentestPhase.LATERAL_MOVE:
            tools = ["psexec", "wmiexec", "ssh_lateral", "pass_the_hash"]

        return list(set(tools))

    def analyze_result(self, phase: "PentestPhase", result: Dict[str, Any]) -> Dict[str, Any]:
        """分析阶段执行结果"""
        from .state import PentestPhase

        analysis: Dict[str, Any] = {
            "phase": phase.value,
            "success": result.get("success", False),
            "key_findings": [],
            "recommendations": [],
            "next_actions": [],
        }

        findings = result.get("findings", [])
        critical_findings = [f for f in findings if f.get("severity") == "critical"]
        high_findings = [f for f in findings if f.get("severity") == "high"]

        if critical_findings:
            analysis["key_findings"].append(f"发现 {len(critical_findings)} 个严重漏洞")
            analysis["recommendations"].append("立即验证并利用严重漏洞")
            analysis["next_actions"].append("poc_exec")

        if high_findings:
            analysis["key_findings"].append(f"发现 {len(high_findings)} 个高危漏洞")
            analysis["next_actions"].append("poc_exec")

        if phase == PentestPhase.RECON:
            open_ports = result.get("data", {}).get("open_ports", [])
            if open_ports:
                analysis["key_findings"].append(f"发现 {len(open_ports)} 个开放端口")
            waf = result.get("data", {}).get("waf_detected")
            if waf:
                analysis["key_findings"].append(f"检测到WAF: {waf}")
                analysis["recommendations"].append("使用WAF绕过技术")

        return analysis

    def get_attack_summary(self) -> Dict[str, Any]:
        """获取攻击摘要"""
        successful = [h for h in self._attack_history if h["success"]]
        failed = [h for h in self._attack_history if not h["success"]]

        return {
            "total_attempts": len(self._attack_history),
            "successful": len(successful),
            "failed": len(failed),
            "success_rate": len(successful) / max(len(self._attack_history), 1),
            "successful_techniques": list(set(self._successful_techniques)),
            "failed_paths": self._failed_paths,
            "current_weights": self._weights.copy(),
        }


__all__ = ["AttackPath", "DecisionEngine", "ThreatContext", "RiskLevel", "AttackComplexity"]
