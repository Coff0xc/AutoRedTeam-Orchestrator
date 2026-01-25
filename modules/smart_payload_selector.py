#!/usr/bin/env python3
"""
智能Payload选择器 - 根据目标指纹自动选择最优Payload
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
from .mega_payloads import MegaPayloads


@dataclass
class PayloadStats:
    """Payload统计信息"""
    payload: str
    success_count: int = 0
    fail_count: int = 0

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.fail_count
        return self.success_count / total if total > 0 else 0.5


class SmartPayloadSelector:
    """智能Payload选择器"""

    # WAF特征映射
    WAF_SIGNATURES = {
        "cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
        "aws_waf": ["awselb", "x-amzn", "aws"],
        "modsecurity": ["mod_security", "modsec"],
        "akamai": ["akamai", "ak_bmsc"],
        "imperva": ["incapsula", "visid_incap"],
        "f5_bigip": ["bigip", "f5"],
        "fortinet": ["fortigate", "fortiweb"],
        "barracuda": ["barracuda", "barra"],
    }

    # 数据库特征映射
    DB_SIGNATURES = {
        "mysql": ["mysql", "mariadb", "mysqli", "pdo_mysql"],
        "mssql": ["mssql", "sqlserver", "sql server", "odbc"],
        "postgresql": ["postgresql", "postgres", "pgsql", "pg_"],
        "oracle": ["oracle", "oci8", "ora-"],
        "sqlite": ["sqlite", "sqlite3"],
        "mongodb": ["mongodb", "mongoose", "mongo"],
        "redis": ["redis", "predis"],
        "elasticsearch": ["elasticsearch", "elastic"],
    }

    # 框架特征映射
    FRAMEWORK_SIGNATURES = {
        "spring": ["spring", "springframework", "springboot"],
        "django": ["django", "csrfmiddlewaretoken"],
        "flask": ["flask", "werkzeug"],
        "express": ["express", "x-powered-by: express"],
        "laravel": ["laravel", "laravel_session"],
        "rails": ["rails", "x-rails"],
        "asp.net": ["asp.net", "aspnet", "__viewstate"],
        "php": ["php", "phpsessid", "x-powered-by: php"],
    }

    def __init__(self):
        self.payload_stats: Dict[str, PayloadStats] = {}
        self._load_default_stats()

    def _load_default_stats(self):
        """加载默认成功率统计"""
        # 高成功率Payload
        high_success = [
            "' OR '1'='1", "' OR 1=1--", "<script>alert(1)</script>",
            "{{7*7}}", "${7*7}", "../../../etc/passwd",
        ]
        for p in high_success:
            self.payload_stats[p] = PayloadStats(payload=p, success_count=70, fail_count=30)

    def select(self, target_info: Dict, vuln_type: str = "sqli", limit: int = 20) -> List[str]:
        """
        根据目标信息选择最优Payload

        Args:
            target_info: 目标信息字典，包含 waf, db, framework, technologies 等
            vuln_type: 漏洞类型 (sqli, xss, lfi, rce, ssrf, xxe, nosql, graphql)
            limit: 返回Payload数量限制

        Returns:
            排序后的Payload列表
        """
        payloads = []

        # 检测WAF类型
        waf_type = self._detect_waf(target_info)

        # 检测数据库类型
        db_type = self._detect_db(target_info)

        # 检测框架类型
        framework = self._detect_framework(target_info)

        # 根据漏洞类型选择基础Payload
        if vuln_type == "sqli":
            payloads = self._select_sqli_payloads(db_type, waf_type)
        elif vuln_type == "xss":
            payloads = self._select_xss_payloads(waf_type, framework)
        elif vuln_type == "lfi":
            payloads = self._select_lfi_payloads(target_info)
        elif vuln_type == "rce":
            payloads = self._select_rce_payloads(framework)
        elif vuln_type == "ssrf":
            payloads = self._select_ssrf_payloads(target_info)
        elif vuln_type == "nosql":
            payloads = self._select_nosql_payloads(db_type)
        elif vuln_type == "graphql":
            payloads = MegaPayloads.GRAPHQL.copy()
        else:
            payloads = MegaPayloads.get(vuln_type)

        # 按成功率排序
        payloads = self._sort_by_success_rate(payloads)

        return payloads[:limit]

    def _detect_waf(self, target_info: Dict) -> Optional[str]:
        """检测WAF类型"""
        waf = target_info.get("waf", "")
        headers = str(target_info.get("headers", {})).lower()
        content = str(target_info.get("content", "")).lower()

        combined = f"{waf} {headers} {content}".lower()

        for waf_name, signatures in self.WAF_SIGNATURES.items():
            if any(sig in combined for sig in signatures):
                from core.evasion import normalize_waf_type
                return normalize_waf_type(waf_name).value
        return None

    def _detect_db(self, target_info: Dict) -> str:
        """检测数据库类型"""
        technologies = str(target_info.get("technologies", {})).lower()
        content = str(target_info.get("content", "")).lower()
        errors = str(target_info.get("errors", "")).lower()

        combined = f"{technologies} {content} {errors}"

        for db_name, signatures in self.DB_SIGNATURES.items():
            if any(sig in combined for sig in signatures):
                return db_name
        return "mysql"  # 默认MySQL

    def _detect_framework(self, target_info: Dict) -> Optional[str]:
        """检测框架类型"""
        technologies = str(target_info.get("technologies", {})).lower()
        headers = str(target_info.get("headers", {})).lower()

        combined = f"{technologies} {headers}"

        for fw_name, signatures in self.FRAMEWORK_SIGNATURES.items():
            if any(sig in combined for sig in signatures):
                return fw_name
        return None

    def _select_sqli_payloads(self, db_type: str, waf_type: Optional[str]) -> List[str]:
        """选择SQL注入Payload"""
        payloads = []

        # 基础Payload
        payloads.extend(MegaPayloads.get("sqli", "auth_bypass", db_type))
        payloads.extend(MegaPayloads.get("sqli", "union_select", db_type))
        payloads.extend(MegaPayloads.get("sqli", "time_based", db_type))

        # 如果检测到WAF，添加绕过Payload
        if waf_type:
            if waf_type == "cloudflare":
                payloads.extend(MegaPayloads.WAF_BYPASS.get("cloudflare_bypass", []))
            elif waf_type == "modsecurity":
                payloads.extend(MegaPayloads.WAF_BYPASS.get("modsecurity_bypass", []))
            elif waf_type == "aws_waf":
                payloads.extend(MegaPayloads.WAF_BYPASS.get("aws_waf_bypass", []))

            # 通用WAF绕过
            payloads.extend(MegaPayloads.WAF_BYPASS.get("unicode", []))
            payloads.extend(MegaPayloads.WAF_BYPASS.get("double_url", []))
            payloads.extend(MegaPayloads.WAF_BYPASS.get("comment", []))

        return payloads

    def _select_xss_payloads(self, waf_type: Optional[str], framework: Optional[str]) -> List[str]:
        """选择XSS Payload"""
        payloads = []

        # 基础Payload
        payloads.extend(MegaPayloads.XSS.get("basic", []))
        payloads.extend(MegaPayloads.XSS.get("event_handlers", []))

        # WAF绕过
        if waf_type:
            payloads.extend(MegaPayloads.XSS.get("waf_bypass", []))
            payloads.extend(MegaPayloads.XSS.get("encoded", []))

        # CSP绕过
        payloads.extend(MegaPayloads.XSS.get("csp_bypass", []))

        # DOM XSS
        payloads.extend(MegaPayloads.XSS.get("dom_based", []))

        return payloads

    def _select_lfi_payloads(self, target_info: Dict) -> List[str]:
        """选择LFI Payload"""
        payloads = []

        # 检测操作系统
        os_type = target_info.get("os", "linux").lower()

        if "windows" in os_type:
            payloads.extend(MegaPayloads.LFI.get("windows", []))
        else:
            payloads.extend(MegaPayloads.LFI.get("linux", []))

        # PHP Wrapper
        if "php" in str(target_info.get("technologies", {})).lower():
            payloads.extend(MegaPayloads.LFI.get("php_wrapper", []))

        # 编码绕过
        payloads.extend(MegaPayloads.LFI.get("encoded", []))
        payloads.extend(MegaPayloads.LFI.get("double_encoding", []))

        return payloads

    def _select_rce_payloads(self, framework: Optional[str]) -> List[str]:
        """选择RCE Payload"""
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

    def _select_ssrf_payloads(self, target_info: Dict) -> List[str]:
        """选择SSRF Payload"""
        payloads = []

        # 基础
        payloads.extend(MegaPayloads.SSRF.get("basic", []))

        # 云环境元数据
        cloud = target_info.get("cloud", "").lower()
        payloads.extend(MegaPayloads.SSRF.get("cloud_metadata", []))

        # 绕过
        payloads.extend(MegaPayloads.SSRF.get("bypass", []))

        # 协议
        payloads.extend(MegaPayloads.SSRF.get("protocol", []))

        return payloads

    def _select_nosql_payloads(self, db_type: str) -> List[str]:
        """选择NoSQL注入Payload"""
        payloads = []

        if db_type == "mongodb":
            for category in MegaPayloads.NOSQL.get("mongodb", {}).values():
                payloads.extend(category)
        elif db_type == "redis":
            payloads.extend(MegaPayloads.NOSQL.get("redis", []))
        elif db_type == "elasticsearch":
            payloads.extend(MegaPayloads.NOSQL.get("elasticsearch", []))
        else:
            # 默认MongoDB
            for category in MegaPayloads.NOSQL.get("mongodb", {}).values():
                payloads.extend(category)

        return payloads

    def _sort_by_success_rate(self, payloads: List[str]) -> List[str]:
        """按成功率排序Payload"""
        def get_rate(p):
            if p in self.payload_stats:
                return self.payload_stats[p].success_rate
            return 0.5  # 默认50%

        return sorted(payloads, key=get_rate, reverse=True)

    def update_stats(self, payload: str, success: bool):
        """更新Payload统计"""
        if payload not in self.payload_stats:
            self.payload_stats[payload] = PayloadStats(payload=payload)

        if success:
            self.payload_stats[payload].success_count += 1
        else:
            self.payload_stats[payload].fail_count += 1

    def get_waf_bypass_payloads(self, waf_type: str) -> List[str]:
        """获取特定WAF的绕过Payload"""
        payloads = []

        waf_map = {
            "cloudflare": "cloudflare_bypass",
            "modsecurity": "modsecurity_bypass",
            "aws": "aws_waf_bypass",
        }

        key = waf_map.get(waf_type.lower())
        if key:
            payloads.extend(MegaPayloads.WAF_BYPASS.get(key, []))

        # 通用绕过
        for bypass_type in ["unicode", "double_url", "hex", "comment", "whitespace"]:
            payloads.extend(MegaPayloads.WAF_BYPASS.get(bypass_type, []))

        return payloads


# 单例
_selector = None

def get_selector() -> SmartPayloadSelector:
    """获取选择器单例"""
    global _selector
    if _selector is None:
        _selector = SmartPayloadSelector()
    return _selector
