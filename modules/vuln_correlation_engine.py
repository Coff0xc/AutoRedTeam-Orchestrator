#!/usr/bin/env python3
"""
智能漏洞关联分析引擎
分析漏洞间的关联关系，自动推荐利用链
"""

import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

logger = logging.getLogger(__name__)


class VulnSeverity(Enum):
    """漏洞严重程度"""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


@dataclass
class Vulnerability:
    """漏洞信息"""
    vuln_type: str
    url: str
    param: Optional[str] = None
    payload: Optional[str] = None
    evidence: str = ""
    severity: VulnSeverity = VulnSeverity.MEDIUM
    exploitable: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExploitChain:
    """利用链"""
    name: str
    steps: List[str]
    vulns_required: List[str]
    impact: str
    difficulty: str  # easy, medium, hard
    success_rate: float = 0.0


class VulnCorrelationEngine:
    """漏洞关联分析引擎"""

    # 漏洞关联图 - 定义漏洞间的因果关系
    VULN_GRAPH = {
        "sqli": {
            "leads_to": ["data_leak", "auth_bypass", "rce"],
            "severity": VulnSeverity.CRITICAL,
            "impact": "数据库访问、数据泄露、可能RCE"
        },
        "xss": {
            "leads_to": ["session_hijack", "phishing", "csrf"],
            "severity": VulnSeverity.HIGH,
            "impact": "会话劫持、钓鱼攻击"
        },
        "lfi": {
            "leads_to": ["source_leak", "rce", "credential_leak"],
            "severity": VulnSeverity.HIGH,
            "impact": "源码泄露、配置泄露、可能RCE"
        },
        "ssrf": {
            "leads_to": ["internal_scan", "cloud_metadata", "rce"],
            "severity": VulnSeverity.HIGH,
            "impact": "内网探测、云凭证泄露"
        },
        "file_upload": {
            "leads_to": ["webshell", "rce"],
            "severity": VulnSeverity.CRITICAL,
            "impact": "Webshell上传、远程代码执行"
        },
        "xxe": {
            "leads_to": ["file_read", "ssrf", "dos"],
            "severity": VulnSeverity.HIGH,
            "impact": "文件读取、SSRF、拒绝服务"
        },
        "ssti": {
            "leads_to": ["rce", "file_read"],
            "severity": VulnSeverity.CRITICAL,
            "impact": "远程代码执行"
        },
        "cmd_inject": {
            "leads_to": ["rce", "privilege_escalation"],
            "severity": VulnSeverity.CRITICAL,
            "impact": "远程代码执行、权限提升"
        },
        "idor": {
            "leads_to": ["data_leak", "privilege_escalation"],
            "severity": VulnSeverity.MEDIUM,
            "impact": "越权访问、数据泄露"
        },
        "auth_bypass": {
            "leads_to": ["admin_access", "data_leak"],
            "severity": VulnSeverity.CRITICAL,
            "impact": "认证绕过、管理员访问"
        },
        "csrf": {
            "leads_to": ["account_takeover", "data_modification"],
            "severity": VulnSeverity.MEDIUM,
            "impact": "账户操作、数据篡改"
        },
        "deserialize": {
            "leads_to": ["rce"],
            "severity": VulnSeverity.CRITICAL,
            "impact": "远程代码执行"
        },
        # 新增漏洞类型
        "prototype_pollution": {
            "leads_to": ["xss", "rce", "auth_bypass"],
            "severity": VulnSeverity.HIGH,
            "impact": "原型链污染可导致XSS/RCE"
        },
        "race_condition": {
            "leads_to": ["privilege_escalation", "data_corruption"],
            "severity": VulnSeverity.MEDIUM,
            "impact": "竞态条件利用"
        },
        "jwt_vuln": {
            "leads_to": ["auth_bypass", "privilege_escalation"],
            "severity": VulnSeverity.HIGH,
            "impact": "JWT伪造、权限提升"
        },
        "graphql_vuln": {
            "leads_to": ["data_leak", "dos", "sqli"],
            "severity": VulnSeverity.MEDIUM,
            "impact": "GraphQL注入、信息泄露"
        },
        "cors_misconfig": {
            "leads_to": ["data_theft", "csrf"],
            "severity": VulnSeverity.MEDIUM,
            "impact": "跨域数据窃取"
        },
        "open_redirect": {
            "leads_to": ["phishing", "ssrf", "oauth_bypass"],
            "severity": VulnSeverity.LOW,
            "impact": "钓鱼攻击、OAuth绕过"
        },
        "cache_poisoning": {
            "leads_to": ["xss", "dos", "phishing"],
            "severity": VulnSeverity.HIGH,
            "impact": "缓存投毒攻击"
        },
        "request_smuggling": {
            "leads_to": ["cache_poisoning", "auth_bypass", "xss"],
            "severity": VulnSeverity.CRITICAL,
            "impact": "请求走私攻击"
        },
        "log4j": {
            "leads_to": ["rce"],
            "severity": VulnSeverity.CRITICAL,
            "impact": "Log4Shell RCE"
        },
        "spring4shell": {
            "leads_to": ["rce"],
            "severity": VulnSeverity.CRITICAL,
            "impact": "Spring RCE"
        }
    }

    # 预定义利用链 - 扩展版
    EXPLOIT_CHAINS = [
        ExploitChain(
            name="SQL注入到RCE",
            steps=["sqli", "file_write", "webshell", "rce"],
            vulns_required=["sqli"],
            impact="完全控制服务器",
            difficulty="medium",
            success_rate=0.6
        ),
        ExploitChain(
            name="LFI到RCE",
            steps=["lfi", "log_poisoning", "rce"],
            vulns_required=["lfi"],
            impact="远程代码执行",
            difficulty="medium",
            success_rate=0.5
        ),
        ExploitChain(
            name="LFI + PHP Wrapper到RCE",
            steps=["lfi", "php_wrapper", "code_injection", "rce"],
            vulns_required=["lfi"],
            impact="通过PHP伪协议实现RCE",
            difficulty="easy",
            success_rate=0.7
        ),
        ExploitChain(
            name="SSRF到云凭证",
            steps=["ssrf", "cloud_metadata", "credential_leak"],
            vulns_required=["ssrf"],
            impact="云环境凭证泄露",
            difficulty="easy",
            success_rate=0.8
        ),
        ExploitChain(
            name="SSRF到K8s接管",
            steps=["ssrf", "k8s_api", "service_account_token", "cluster_admin"],
            vulns_required=["ssrf"],
            impact="Kubernetes集群接管",
            difficulty="medium",
            success_rate=0.6
        ),
        ExploitChain(
            name="XSS到账户接管",
            steps=["xss", "session_hijack", "account_takeover"],
            vulns_required=["xss"],
            impact="用户账户接管",
            difficulty="easy",
            success_rate=0.7
        ),
        ExploitChain(
            name="XSS + CSRF组合攻击",
            steps=["xss", "csrf_token_steal", "admin_action"],
            vulns_required=["xss", "csrf"],
            impact="以管理员身份执行操作",
            difficulty="medium",
            success_rate=0.65
        ),
        ExploitChain(
            name="文件上传到Webshell",
            steps=["file_upload", "bypass_filter", "webshell", "rce"],
            vulns_required=["file_upload"],
            impact="完全控制服务器",
            difficulty="medium",
            success_rate=0.65
        ),
        ExploitChain(
            name="XXE到内网探测",
            steps=["xxe", "ssrf", "internal_scan"],
            vulns_required=["xxe"],
            impact="内网信息收集",
            difficulty="medium",
            success_rate=0.55
        ),
        ExploitChain(
            name="XXE到文件读取",
            steps=["xxe", "file_read", "credential_leak", "lateral_movement"],
            vulns_required=["xxe"],
            impact="敏感文件读取和横向移动",
            difficulty="easy",
            success_rate=0.75
        ),
        ExploitChain(
            name="IDOR到数据泄露",
            steps=["idor", "enum_users", "data_leak"],
            vulns_required=["idor"],
            impact="批量数据泄露",
            difficulty="easy",
            success_rate=0.85
        ),
        ExploitChain(
            name="认证绕过到管理员",
            steps=["auth_bypass", "admin_access", "full_control"],
            vulns_required=["auth_bypass"],
            impact="管理员权限",
            difficulty="easy",
            success_rate=0.9
        ),
        # 新增利用链
        ExploitChain(
            name="JWT伪造到权限提升",
            steps=["jwt_vuln", "token_forge", "privilege_escalation"],
            vulns_required=["jwt_vuln"],
            impact="任意用户身份伪造",
            difficulty="easy",
            success_rate=0.85
        ),
        ExploitChain(
            name="开放重定向到OAuth劫持",
            steps=["open_redirect", "oauth_callback_hijack", "token_steal"],
            vulns_required=["open_redirect"],
            impact="OAuth令牌窃取",
            difficulty="medium",
            success_rate=0.5
        ),
        ExploitChain(
            name="GraphQL批量查询到数据泄露",
            steps=["graphql_vuln", "introspection", "batch_query", "data_exfil"],
            vulns_required=["graphql_vuln"],
            impact="大规模数据导出",
            difficulty="easy",
            success_rate=0.8
        ),
        ExploitChain(
            name="请求走私到缓存投毒",
            steps=["request_smuggling", "cache_poisoning", "mass_xss"],
            vulns_required=["request_smuggling"],
            impact="大规模用户攻击",
            difficulty="hard",
            success_rate=0.4
        ),
        ExploitChain(
            name="CORS + XSS跨站数据窃取",
            steps=["cors_misconfig", "xss", "cross_origin_data_theft"],
            vulns_required=["cors_misconfig", "xss"],
            impact="跨域敏感数据窃取",
            difficulty="medium",
            success_rate=0.7
        ),
        ExploitChain(
            name="原型链污染到RCE",
            steps=["prototype_pollution", "gadget_chain", "rce"],
            vulns_required=["prototype_pollution"],
            impact="Node.js RCE",
            difficulty="hard",
            success_rate=0.35
        ),
        ExploitChain(
            name="Log4j到反弹Shell",
            steps=["log4j", "jndi_injection", "reverse_shell", "rce"],
            vulns_required=["log4j"],
            impact="完全控制服务器",
            difficulty="easy",
            success_rate=0.9
        ),
        ExploitChain(
            name="SSTI到RCE",
            steps=["ssti", "sandbox_escape", "rce"],
            vulns_required=["ssti"],
            impact="模板注入RCE",
            difficulty="medium",
            success_rate=0.7
        ),
    ]

    def __init__(self):
        self.found_vulns: List[Vulnerability] = []
        self.correlation_cache: Dict[str, List[str]] = {}

    def add_vulnerability(self, vuln: Vulnerability):
        """添加发现的漏洞"""
        self.found_vulns.append(vuln)
        self.correlation_cache.clear()  # 清除缓存

    def add_vulns_from_scan(self, scan_results: Dict[str, Any]):
        """从扫描结果添加漏洞"""
        vulns = scan_results.get("vulnerabilities", [])
        for v in vulns:
            vuln = Vulnerability(
                vuln_type=v.get("type", "unknown"),
                url=v.get("url", ""),
                param=v.get("param"),
                payload=v.get("payload"),
                evidence=v.get("evidence", ""),
                severity=VulnSeverity[v.get("severity", "MEDIUM").upper()]
            )
            self.add_vulnerability(vuln)

    def analyze_correlations(self) -> Dict[str, Any]:
        """分析漏洞关联"""
        if not self.found_vulns:
            return {"correlations": [], "chains": [], "recommendations": []}

        vuln_types = set(v.vuln_type for v in self.found_vulns)

        # 查找关联
        correlations = []
        for vuln_type in vuln_types:
            if vuln_type in self.VULN_GRAPH:
                graph_info = self.VULN_GRAPH[vuln_type]
                for leads_to in graph_info["leads_to"]:
                    correlations.append({
                        "from": vuln_type,
                        "to": leads_to,
                        "impact": graph_info["impact"]
                    })

        # 匹配利用链
        matched_chains = []
        for chain in self.EXPLOIT_CHAINS:
            if all(req in vuln_types for req in chain.vulns_required):
                matched_chains.append({
                    "name": chain.name,
                    "steps": chain.steps,
                    "impact": chain.impact,
                    "difficulty": chain.difficulty,
                    "success_rate": chain.success_rate
                })

        # 生成建议
        recommendations = self._generate_recommendations(vuln_types, matched_chains)

        return {
            "found_vulns": [v.vuln_type for v in self.found_vulns],
            "correlations": correlations,
            "exploit_chains": matched_chains,
            "recommendations": recommendations,
            "risk_score": self._calculate_risk_score()
        }

    def _generate_recommendations(
        self,
        vuln_types: Set[str],
        chains: List[Dict]
    ) -> List[Dict[str, str]]:
        """生成利用建议"""
        recommendations = []

        # 基于漏洞类型的建议
        if "sqli" in vuln_types:
            recommendations.append({
                "priority": "critical",
                "action": "尝试SQL注入数据提取",
                "tool": "sqlmap_scan",
                "reason": "SQL注入可导致数据库完全泄露"
            })

        if "lfi" in vuln_types:
            recommendations.append({
                "priority": "high",
                "action": "尝试读取敏感配置文件",
                "targets": ["/etc/passwd", "config.php", ".env"],
                "reason": "LFI可泄露敏感信息，可能升级为RCE"
            })

        if "ssrf" in vuln_types:
            recommendations.append({
                "priority": "high",
                "action": "探测云元数据服务",
                "targets": ["169.254.169.254", "metadata.google.internal"],
                "reason": "SSRF可获取云凭证"
            })

        if "file_upload" in vuln_types:
            recommendations.append({
                "priority": "critical",
                "action": "尝试上传Webshell",
                "tool": "file_upload_exploit",
                "reason": "文件上传可直接获取服务器权限"
            })

        # 基于利用链的建议
        if chains:
            best_chain = max(chains, key=lambda x: x["success_rate"])
            recommendations.insert(0, {
                "priority": "critical",
                "action": f"执行利用链: {best_chain['name']}",
                "steps": best_chain["steps"],
                "success_rate": f"{best_chain['success_rate']*100:.0f}%"
            })

        return recommendations

    def _calculate_risk_score(self) -> Dict[str, Any]:
        """计算风险评分"""
        if not self.found_vulns:
            return {"score": 0, "level": "safe"}

        # 基于漏洞严重程度计算
        severity_scores = [v.severity.value for v in self.found_vulns]
        max_severity = max(severity_scores)
        avg_severity = sum(severity_scores) / len(severity_scores)

        # 综合评分 (0-100)
        score = min(100, (max_severity * 20) + (avg_severity * 10) + (len(self.found_vulns) * 5))

        if score >= 80:
            level = "critical"
        elif score >= 60:
            level = "high"
        elif score >= 40:
            level = "medium"
        elif score >= 20:
            level = "low"
        else:
            level = "info"

        return {
            "score": round(score),
            "level": level,
            "vuln_count": len(self.found_vulns),
            "critical_count": sum(1 for v in self.found_vulns if v.severity == VulnSeverity.CRITICAL)
        }

    def suggest_next_tests(self) -> List[Dict[str, Any]]:
        """建议下一步测试"""
        vuln_types = set(v.vuln_type for v in self.found_vulns)
        suggestions = []

        # 基于已发现漏洞推荐后续测试
        for vuln_type in vuln_types:
            if vuln_type in self.VULN_GRAPH:
                leads_to = self.VULN_GRAPH[vuln_type]["leads_to"]
                for target in leads_to:
                    if target not in vuln_types:  # 还未测试的
                        suggestions.append({
                            "test": target,
                            "reason": f"基于已发现的{vuln_type}，可能存在{target}",
                            "priority": "high"
                        })

        # 如果没有发现漏洞，推荐基础测试
        if not suggestions:
            suggestions = [
                {"test": "sqli_detect", "reason": "SQL注入是最常见的高危漏洞", "priority": "high"},
                {"test": "xss_detect", "reason": "XSS是最常见的Web漏洞", "priority": "medium"},
                {"test": "lfi_detect", "reason": "LFI可能导致敏感信息泄露", "priority": "medium"},
                {"test": "ssrf_detect", "reason": "SSRF在云环境中危害极大", "priority": "high"}
            ]

        return suggestions[:5]

    def generate_report(self) -> str:
        """生成分析报告"""
        analysis = self.analyze_correlations()
        risk = analysis["risk_score"]

        report = f"""
# 漏洞关联分析报告

## 风险评估
- 风险评分: {risk['score']}/100 ({risk['level'].upper()})
- 发现漏洞数: {risk['vuln_count']}
- 严重漏洞数: {risk['critical_count']}

## 发现的漏洞
"""
        for vuln in self.found_vulns:
            report += f"- [{vuln.severity.name}] {vuln.vuln_type} @ {vuln.url}\n"

        if analysis["exploit_chains"]:
            report += "\n## 可用利用链\n"
            for chain in analysis["exploit_chains"]:
                report += f"### {chain['name']}\n"
                report += f"- 步骤: {' -> '.join(chain['steps'])}\n"
                report += f"- 影响: {chain['impact']}\n"
                report += f"- 难度: {chain['difficulty']}\n"
                report += f"- 成功率: {chain['success_rate']*100:.0f}%\n\n"

        if analysis["recommendations"]:
            report += "\n## 建议操作\n"
            for i, rec in enumerate(analysis["recommendations"], 1):
                report += f"{i}. [{rec['priority'].upper()}] {rec['action']}\n"

        return report

    def clear(self):
        """清除所有数据"""
        self.found_vulns.clear()
        self.correlation_cache.clear()


# 全局实例
_engine_instance: Optional[VulnCorrelationEngine] = None

def get_correlation_engine() -> VulnCorrelationEngine:
    """获取关联分析引擎单例"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = VulnCorrelationEngine()
    return _engine_instance
