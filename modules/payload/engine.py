#!/usr/bin/env python3
"""
Payload 引擎模块 - 统一的自适应 Payload 引擎

整合自:
- smart_payload_engine.py: 智能 Payload 选择和变异
- smart_payload_selector.py: 目标特征分析和 Payload 选择
- adaptive_payload_engine.py: 自适应学习和反馈机制

提供统一的 Payload 生成、选择、变异和学习接口
"""

import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .mutator import PayloadMutator, mutate_payload
from .selector import SmartPayloadSelector
from .signatures import WAF_BYPASS_STRATEGIES, TargetProfile
from .types import (
    PayloadResult,
    ScoredPayload,
    get_payload_key,
)

logger = logging.getLogger(__name__)


class AdaptivePayloadEngine:
    """
    自适应 Payload 引擎

    整合选择器、变异器和学习机制，提供统一的 Payload 管理接口。

    特性:
    - 基于目标特征智能选择 Payload
    - 支持多种 WAF 绕过策略
    - 历史成功率学习
    - 自动 Payload 变异
    """

    def __init__(self, history_file: Optional[Path] = None):
        """
        初始化引擎

        Args:
            history_file: 历史数据文件路径
        """
        if history_file is None:
            history_file = Path(tempfile.gettempdir()) / "adaptive_payload_history.json"

        self.history_file = history_file
        self.selector = SmartPayloadSelector(stats_file=history_file)

        # 缓存
        self._payload_cache: Dict[str, List[str]] = {}

    def select_payloads(
        self,
        vuln_type: str,
        waf: Optional[str] = None,
        target_info: Optional[Dict[str, Any]] = None,
        category: Optional[str] = None,
        top_n: int = 10,
        include_mutations: bool = True,
    ) -> List[Tuple[str, float]]:
        """
        选择最优 Payload

        Args:
            vuln_type: 漏洞类型 (sqli, xss, lfi, rce, ssrf, xxe)
            waf: 检测到的 WAF 类型
            target_info: 目标信息字典
            category: Payload 分类（如 error_based, blind_time 等）
            top_n: 返回数量
            include_mutations: 是否包含变异 Payload

        Returns:
            [(payload, score), ...] 按得分排序
        """
        target_info = target_info or {}
        if waf:
            target_info["waf"] = waf

        # 获取基础 Payload
        base_payloads = self.selector.select(vuln_type, target_info, limit=top_n * 2)

        # 如果指定了分类，过滤
        if category:
            base_payloads = self._filter_by_category(base_payloads, vuln_type, category)

        # 添加变异 Payload
        if include_mutations and waf:
            mutated = []
            for p in base_payloads[:5]:
                mutated.extend(PayloadMutator.mutate(p, waf=waf, include_original=False))
            base_payloads.extend(mutated)

        # 计算评分
        scored = []
        for payload in base_payloads:
            score = self._calculate_score(vuln_type, payload, waf)
            scored.append((payload, score))

        # 排序并去重
        scored.sort(key=lambda x: -x[1])
        seen = set()
        unique_scored = []
        for p, s in scored:
            if p not in seen:
                seen.add(p)
                unique_scored.append((p, s))

        return unique_scored[:top_n]

    def get_payloads_for_target(
        self,
        target: TargetProfile,
        vuln_type: str,
        max_count: int = 20,
    ) -> List[ScoredPayload]:
        """
        根据目标特征获取最优 Payload

        Args:
            target: 目标特征配置
            vuln_type: 漏洞类型
            max_count: 最大返回数量

        Returns:
            带评分的 Payload 列表
        """
        return self.selector.select_with_scores(vuln_type, target, max_count)

    def mutate_payload(
        self,
        payload: str,
        waf: Optional[str] = None,
        count: int = 10,
    ) -> Dict[str, Any]:
        """
        变异 Payload

        Args:
            payload: 原始 Payload
            waf: WAF 类型
            count: 生成变体数量

        Returns:
            变异结果
        """
        return mutate_payload(payload, waf, count)

    def record_result(
        self,
        vuln_type: str,
        payload: str,
        result: PayloadResult,
    ):
        """
        记录 Payload 执行结果

        Args:
            vuln_type: 漏洞类型
            payload: Payload 内容
            result: 执行结果
        """
        self.selector.update_stats(
            payload=payload,
            vuln_type=vuln_type,
            success=result.success,
            blocked=result.blocked,
        )

        logger.debug(
            f"Recorded result for {vuln_type}: "
            f"success={result.success}, blocked={result.blocked}"
        )

    def get_stats(self, vuln_type: Optional[str] = None) -> Dict[str, Any]:
        """
        获取统计信息

        Args:
            vuln_type: 可选的漏洞类型过滤

        Returns:
            统计摘要
        """
        summary = self.selector.get_stats_summary()

        if vuln_type:
            # 过滤特定类型
            relevant_stats = {
                k: v for k, v in self.selector.stats.items() if k.startswith(vuln_type)
            }
            filtered_success = sum(s.success_count for s in relevant_stats.values())
            filtered_total = sum(s.total_uses for s in relevant_stats.values())
            summary["filtered_vuln_type"] = vuln_type
            summary["filtered_payloads"] = len(relevant_stats)
            summary["filtered_success_rate"] = filtered_success / max(filtered_total, 1)

        return summary

    def get_recommendations(self, target: TargetProfile) -> List[str]:
        """
        获取针对目标的测试建议

        Args:
            target: 目标特征

        Returns:
            建议列表
        """
        recommendations = []
        features = target.features

        # WAF 相关建议
        waf = features.get("waf")
        if waf:
            bypass_info = WAF_BYPASS_STRATEGIES.get(waf, WAF_BYPASS_STRATEGIES["default"])
            recommendations.append(
                f"检测到 {waf} WAF，建议使用 {', '.join(bypass_info.get('techniques', [])[:3])} 绕过技术"
            )

        # 框架相关建议
        framework = features.get("framework")
        if framework:
            recommendations.append(f"检测到 {framework} 框架，建议测试框架特定漏洞")

        # 数据库相关建议
        database = features.get("database")
        if database:
            recommendations.append(f"推测数据库类型为 {database}，建议使用对应的 SQL 语法")

        # CSP 相关建议
        if features.get("has_csp"):
            recommendations.append("检测到 CSP 策略，XSS 测试需使用 CSP 绕过技术")

        if not recommendations:
            recommendations.append("未检测到特殊防护，使用标准 Payload 集")

        return recommendations

    def _calculate_score(
        self,
        vuln_type: str,
        payload: str,
        waf: Optional[str] = None,
    ) -> float:
        """计算 Payload 评分"""
        payload_key = get_payload_key(vuln_type, payload)
        stats = self.selector.stats.get(payload_key)

        # 基础分
        if stats and stats.total_uses > 0:
            base_score = stats.success_rate * 70
        else:
            base_score = 50.0  # 新 Payload 探索奖励

        # WAF 绕过加分
        if waf:
            if self._is_waf_bypass_payload(payload, waf):
                base_score += 15
            else:
                base_score -= 5

        # 被拦截惩罚
        if stats and stats.blocked_count > 2:
            base_score -= 20

        # 长度惩罚
        if len(payload) > 100:
            base_score -= 5

        return max(0, min(100, base_score))

    def _is_waf_bypass_payload(self, payload: str, waf: str) -> bool:
        """检查是否为 WAF 绕过 Payload"""
        waf_config = WAF_BYPASS_STRATEGIES.get(waf.lower(), {})
        specific = waf_config.get("specific_payloads", [])
        return any(s in payload for s in specific)

    def _filter_by_category(
        self,
        payloads: List[str],
        vuln_type: str,
        category: str,
    ) -> List[str]:
        """按分类过滤 Payload"""
        # 简单的关键字过滤
        category_keywords = {
            "error_based": ["'", '"', "syntax", "error"],
            "union_based": ["union", "select"],
            "blind_time": ["sleep", "waitfor", "delay", "benchmark"],
            "blind_bool": ["and", "or", "1=1", "1=2"],
            "basic": ["script", "img", "svg"],
            "event_handler": ["on", "="],
        }

        keywords = category_keywords.get(category.lower(), [])
        if not keywords:
            return payloads

        filtered = [p for p in payloads if any(kw in p.lower() for kw in keywords)]

        return filtered if filtered else payloads


# ============== 全局实例和便捷函数 ==============

_engine_instance: Optional[AdaptivePayloadEngine] = None


def get_payload_engine() -> AdaptivePayloadEngine:
    """获取 Payload 引擎单例"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = AdaptivePayloadEngine()
    return _engine_instance


def smart_select_payloads(
    vuln_type: str,
    waf: Optional[str] = None,
    top_n: int = 10,
) -> List[str]:
    """
    智能选择 Payload（便捷函数）

    Args:
        vuln_type: 漏洞类型
        waf: WAF 类型
        top_n: 返回数量

    Returns:
        Payload 列表
    """
    engine = get_payload_engine()
    scored = engine.select_payloads(vuln_type, waf=waf, top_n=top_n)
    return [p for p, _ in scored]


def get_waf_bypass_payloads(payload: str, waf: str) -> Dict[str, Any]:
    """
    获取 WAF 绕过方案（便捷函数）

    Args:
        payload: 原始 Payload
        waf: WAF 类型

    Returns:
        包含变体和策略的字典
    """
    engine = get_payload_engine()
    return engine.mutate_payload(payload, waf=waf, count=15)


def record_payload_result(
    vuln_type: str,
    payload: str,
    success: bool,
    blocked: bool = False,
    response_time: float = 0.0,
    evidence: str = "",
):
    """
    记录 Payload 结果（便捷函数）

    Args:
        vuln_type: 漏洞类型
        payload: Payload 内容
        success: 是否成功
        blocked: 是否被拦截
        response_time: 响应时间
        evidence: 证据
    """
    engine = get_payload_engine()
    result = PayloadResult(
        payload=payload,
        success=success,
        blocked=blocked,
        response_time=response_time,
        evidence=evidence,
    )
    engine.record_result(vuln_type, payload, result)
