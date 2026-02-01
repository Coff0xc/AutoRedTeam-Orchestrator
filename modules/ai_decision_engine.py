#!/usr/bin/env python3
"""
AI智能攻击决策引擎 v2.0
基于目标特征、历史数据、攻击图谱进行智能决策
"""

import json
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AttackPriority(Enum):
    """攻击优先级"""

    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class AttackSuggestion:
    """攻击建议"""

    attack_type: str
    tool_name: str
    priority: AttackPriority
    confidence: float  # 0-1
    reason: str
    params: Dict[str, Any] = field(default_factory=dict)
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class TargetContext:
    """目标上下文"""

    url: str
    tech_stack: Dict[str, Any] = field(default_factory=dict)
    open_ports: List[int] = field(default_factory=list)
    waf_detected: Optional[str] = None
    vulnerabilities_found: List[str] = field(default_factory=list)
    recon_data: Dict[str, Any] = field(default_factory=dict)


class AttackKnowledgeGraph:
    """攻击知识图谱 - 定义攻击类型间的关系和前置条件"""

    ATTACK_GRAPH = {
        # 信息收集 -> 漏洞检测
        "recon": {
            "leads_to": ["sqli_detect", "xss_detect", "lfi_detect", "ssrf_detect"],
            "weight": 1.0,
        },
        # SQL注入 -> 数据提取/权限提升
        "sqli_detect": {
            "leads_to": ["data_extraction", "auth_bypass_detect"],
            "prerequisites": ["recon"],
            "weight": 0.9,
        },
        # XSS -> 会话劫持
        "xss_detect": {
            "leads_to": ["session_hijack", "csrf_detect"],
            "prerequisites": ["recon"],
            "weight": 0.8,
        },
        # LFI -> RCE
        "lfi_detect": {
            "leads_to": ["rce_detect", "sensitive_scan"],
            "prerequisites": ["recon"],
            "weight": 0.85,
        },
        # SSRF -> 内网探测
        "ssrf_detect": {
            "leads_to": ["internal_scan", "cloud_metadata"],
            "prerequisites": ["recon"],
            "weight": 0.9,
        },
        # 文件上传 -> RCE
        "file_upload_detect": {
            "leads_to": ["webshell_upload", "rce_detect"],
            "prerequisites": ["recon"],
            "weight": 0.95,
        },
        # 认证绕过 -> 权限提升
        "auth_bypass_detect": {
            "leads_to": ["privilege_escalation", "idor_detect"],
            "prerequisites": ["recon"],
            "weight": 0.9,
        },
    }

    # 技术栈 -> 推荐攻击映射
    TECH_ATTACK_MAP = {
        "php": ["lfi_detect", "sqli_detect", "file_upload_detect", "rce_detect"],
        "java": ["deserialize_detect", "sqli_detect", "xxe_detect", "ssti_detect"],
        "python": ["ssti_detect", "sqli_detect", "cmd_inject_detect"],
        "nodejs": ["ssti_detect", "prototype_pollution", "ssrf_detect"],
        "asp": ["sqli_detect", "file_upload_detect", "iis_shortname"],
        "ruby": ["ssti_detect", "sqli_detect", "cmd_inject_detect"],
    }

    # 端口 -> 服务 -> 攻击映射
    PORT_ATTACK_MAP = {
        21: {"service": "ftp", "attacks": ["ftp_brute", "ftp_anon"]},
        22: {"service": "ssh", "attacks": ["ssh_brute", "ssh_enum"]},
        23: {"service": "telnet", "attacks": ["telnet_brute"]},
        25: {"service": "smtp", "attacks": ["smtp_enum", "smtp_relay"]},
        80: {"service": "http", "attacks": ["web_scan"]},
        443: {"service": "https", "attacks": ["web_scan", "ssl_vuln"]},
        445: {"service": "smb", "attacks": ["smb_enum", "smb_vuln"]},
        1433: {"service": "mssql", "attacks": ["sqli_detect", "mssql_brute"]},
        3306: {"service": "mysql", "attacks": ["sqli_detect", "mysql_brute"]},
        3389: {"service": "rdp", "attacks": ["rdp_brute", "rdp_vuln"]},
        5432: {"service": "postgresql", "attacks": ["sqli_detect", "pg_brute"]},
        6379: {"service": "redis", "attacks": ["redis_unauth", "redis_rce"]},
        8080: {"service": "http-alt", "attacks": ["web_scan", "tomcat_vuln"]},
        27017: {"service": "mongodb", "attacks": ["mongo_unauth", "nosql_inject"]},
    }


class AIDecisionEngine:
    """AI智能决策引擎"""

    def __init__(self, history_file: Optional[Path] = None):
        self.knowledge_graph = AttackKnowledgeGraph()
        self.attack_history: Dict[str, Dict] = defaultdict(
            lambda: {"success": 0, "fail": 0, "total_time": 0}
        )
        self.history_file = history_file
        self._load_history()

    def _load_history(self):
        """加载历史攻击数据"""
        if self.history_file and self.history_file.exists():
            try:
                with open(self.history_file, "r", encoding="utf-8") as f:
                    self.attack_history.update(json.load(f))
            except Exception as e:
                logger.warning(f"加载历史数据失败: {e}")

    def _save_history(self):
        """保存历史攻击数据"""
        if self.history_file:
            try:
                self.history_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self.history_file, "w", encoding="utf-8") as f:
                    json.dump(dict(self.attack_history), f, indent=2)
            except Exception as e:
                logger.warning(f"保存历史数据失败: {e}")

    def analyze_target(self, context: TargetContext) -> List[AttackSuggestion]:
        """分析目标并生成攻击建议"""
        suggestions = []

        # 1. 基于技术栈推荐
        suggestions.extend(self._suggest_by_tech_stack(context))

        # 2. 基于开放端口推荐
        suggestions.extend(self._suggest_by_ports(context))

        # 3. 基于已发现漏洞推荐后续攻击
        suggestions.extend(self._suggest_by_vulns(context))

        # 4. 基于WAF调整策略
        suggestions = self._adjust_for_waf(suggestions, context.waf_detected)

        # 5. 基于历史成功率排序
        suggestions = self._rank_by_history(suggestions)

        return suggestions[:10]  # 返回Top 10建议

    def _suggest_by_tech_stack(self, context: TargetContext) -> List[AttackSuggestion]:
        """基于技术栈推荐攻击"""
        suggestions = []
        tech = context.tech_stack

        # 检测语言
        language = tech.get("language", "").lower()
        if language in self.knowledge_graph.TECH_ATTACK_MAP:
            for attack in self.knowledge_graph.TECH_ATTACK_MAP[language]:
                suggestions.append(
                    AttackSuggestion(
                        attack_type=attack,
                        tool_name=attack,
                        priority=AttackPriority.HIGH,
                        confidence=0.8,
                        reason=f"目标使用{language}，该语言常见{attack}漏洞",
                    )
                )

        # 检测框架特定漏洞
        framework = tech.get("framework", "").lower()
        framework_vulns = {
            "django": ["ssti_detect", "csrf_detect"],
            "flask": ["ssti_detect", "debug_mode"],
            "spring": ["deserialize_detect", "actuator_exploit"],
            "struts": ["ognl_inject", "rce_detect"],
            "laravel": ["debug_mode", "sqli_detect"],
            "wordpress": ["wpscan", "plugin_vuln"],
            "drupal": ["drupalgeddon", "sqli_detect"],
        }

        if framework in framework_vulns:
            for attack in framework_vulns[framework]:
                suggestions.append(
                    AttackSuggestion(
                        attack_type=attack,
                        tool_name=attack,
                        priority=AttackPriority.CRITICAL,
                        confidence=0.9,
                        reason=f"检测到{framework}框架，存在已知漏洞类型",
                    )
                )

        return suggestions

    def _suggest_by_ports(self, context: TargetContext) -> List[AttackSuggestion]:
        """基于开放端口推荐攻击"""
        suggestions = []

        for port in context.open_ports:
            if port in self.knowledge_graph.PORT_ATTACK_MAP:
                port_info = self.knowledge_graph.PORT_ATTACK_MAP[port]
                service = port_info["service"]

                for attack in port_info["attacks"]:
                    # 数据库端口优先级更高
                    priority = (
                        AttackPriority.CRITICAL
                        if port in [3306, 5432, 1433, 27017, 6379]
                        else AttackPriority.HIGH
                    )

                    suggestions.append(
                        AttackSuggestion(
                            attack_type=attack,
                            tool_name=attack,
                            priority=priority,
                            confidence=0.85,
                            reason=f"端口{port}({service})开放，可尝试{attack}",
                            params={"port": port, "service": service},
                        )
                    )

        return suggestions

    def _suggest_by_vulns(self, context: TargetContext) -> List[AttackSuggestion]:
        """基于已发现漏洞推荐后续攻击"""
        suggestions = []

        for vuln in context.vulnerabilities_found:
            if vuln in self.knowledge_graph.ATTACK_GRAPH:
                graph_node = self.knowledge_graph.ATTACK_GRAPH[vuln]

                for next_attack in graph_node.get("leads_to", []):
                    suggestions.append(
                        AttackSuggestion(
                            attack_type=next_attack,
                            tool_name=next_attack,
                            priority=AttackPriority.CRITICAL,
                            confidence=0.95,
                            reason=f"已发现{vuln}，可进一步利用进行{next_attack}",
                            prerequisites=[vuln],
                        )
                    )

        return suggestions

    def _adjust_for_waf(
        self, suggestions: List[AttackSuggestion], waf: Optional[str]
    ) -> List[AttackSuggestion]:
        """根据WAF调整攻击策略"""
        if not waf:
            return suggestions

        # WAF绕过策略
        waf_bypass_tips = {
            "cloudflare": "使用Unicode编码、分块传输、HTTP参数污染",
            "aws_waf": "使用大小写混淆、注释分割、双重URL编码",
            "modsecurity": "使用HPP、换行符注入、编码绕过",
            "akamai": "使用分块编码、参数污染、时间延迟",
        }

        for suggestion in suggestions:
            if waf.lower() in waf_bypass_tips:
                suggestion.params["waf_bypass"] = waf_bypass_tips[waf.lower()]
                suggestion.confidence *= 0.7  # WAF存在时降低置信度
                suggestion.reason += f" (注意: 检测到{waf} WAF)"

        return suggestions

    def _rank_by_history(self, suggestions: List[AttackSuggestion]) -> List[AttackSuggestion]:
        """基于历史成功率排序"""

        def score(s: AttackSuggestion) -> float:
            history = self.attack_history.get(s.attack_type, {})
            total = history.get("success", 0) + history.get("fail", 0)

            if total == 0:
                # 新攻击类型，给予探索奖励
                history_score = 0.5
            else:
                success_rate = history.get("success", 0) / total
                history_score = success_rate

            # 综合评分 = 置信度 * 0.4 + 历史成功率 * 0.3 + 优先级 * 0.3
            priority_score = (5 - s.priority.value) / 4  # 转换为0-1
            return s.confidence * 0.4 + history_score * 0.3 + priority_score * 0.3

        return sorted(suggestions, key=score, reverse=True)

    def record_result(self, attack_type: str, success: bool, duration: float):
        """记录攻击结果用于学习"""
        if success:
            self.attack_history[attack_type]["success"] += 1
        else:
            self.attack_history[attack_type]["fail"] += 1
        self.attack_history[attack_type]["total_time"] += duration
        self._save_history()

    def get_attack_chain(self, context: TargetContext, max_depth: int = 5) -> List[List[str]]:
        """生成攻击链路径"""
        chains = []

        def dfs(current: str, path: List[str], depth: int):
            if depth >= max_depth:
                chains.append(path.copy())
                return

            if current not in self.knowledge_graph.ATTACK_GRAPH:
                chains.append(path.copy())
                return

            next_attacks = self.knowledge_graph.ATTACK_GRAPH[current].get("leads_to", [])
            if not next_attacks:
                chains.append(path.copy())
                return

            for next_attack in next_attacks:
                path.append(next_attack)
                dfs(next_attack, path, depth + 1)
                path.pop()

        # 从已发现的漏洞开始构建攻击链
        for vuln in context.vulnerabilities_found:
            dfs(vuln, [vuln], 0)

        # 如果没有已发现漏洞，从recon开始
        if not chains:
            dfs("recon", ["recon"], 0)

        return chains

    def suggest_next_action(self, context: TargetContext) -> Dict[str, Any]:
        """智能推荐下一步行动"""
        suggestions = self.analyze_target(context)
        chains = self.get_attack_chain(context)

        if not suggestions:
            return {
                "action": "recon",
                "reason": "建议先进行信息收集",
                "tool": "full_recon",
                "params": {"target": context.url},
            }

        top_suggestion = suggestions[0]

        return {
            "action": top_suggestion.attack_type,
            "reason": top_suggestion.reason,
            "tool": top_suggestion.tool_name,
            "params": top_suggestion.params,
            "confidence": top_suggestion.confidence,
            "priority": top_suggestion.priority.name,
            "attack_chains": chains[:3],  # 返回前3条攻击链
            "alternatives": [
                {"action": s.attack_type, "confidence": s.confidence} for s in suggestions[1:5]
            ],
        }


# 全局实例
_engine_instance: Optional[AIDecisionEngine] = None


_engine_lock = threading.Lock()


def get_decision_engine() -> AIDecisionEngine:
    """获取决策引擎单例（线程安全）"""
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            import tempfile
            from pathlib import Path

            history_path = Path(tempfile.gettempdir()) / "autored_history.json"
            _engine_instance = AIDecisionEngine(history_file=history_path)
        return _engine_instance


def reset_decision_engine() -> None:
    """重置决策引擎（仅用于测试）"""
    global _engine_instance
    with _engine_lock:
        _engine_instance = None
