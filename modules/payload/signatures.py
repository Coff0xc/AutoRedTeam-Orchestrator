#!/usr/bin/env python3
"""
目标特征检测模块 - 统一的 WAF/数据库/框架检测

整合自:
- smart_payload_engine.py: TargetProfile, waf_signatures, framework_patterns
- smart_payload_selector.py: WAF_SIGNATURES, DB_SIGNATURES, FRAMEWORK_SIGNATURES
- adaptive_payload_engine.py: WAF_BYPASS

消除了三个文件中的重复定义
"""

import re
import json
import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ============== 统一的特征签名定义 ==============

WAF_SIGNATURES: Dict[str, List[str]] = {
    "cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "aws_waf": ["awselb", "x-amzn-requestid", "x-amzn", "aws-waf"],
    "akamai": ["akamai", "ak_bmsc", "x-akamai"],
    "modsecurity": ["mod_security", "modsecurity", "modsec"],
    "f5_bigip": ["bigip", "f5", "x-wa-info"],
    "imperva": ["incapsula", "incap_ses", "visid_incap", "x-iinfo"],
    "sucuri": ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "fortinet": ["fortigate", "fortiweb", "fortiwebid"],
    "barracuda": ["barracuda", "barra", "bnmsg"],
    "citrix": ["citrix", "ns_af", "citrix_ns_id"],
    "radware": ["radware", "x-sl-compstate"],
    "wallarm": ["wallarm", "nginx-wallarm"],
}

DB_SIGNATURES: Dict[str, List[str]] = {
    "mysql": ["mysql", "mariadb", "mysqli", "pdo_mysql", "mysql_"],
    "mssql": ["mssql", "sqlserver", "sql server", "odbc", "sqlsrv"],
    "postgresql": ["postgresql", "postgres", "pgsql", "pg_"],
    "oracle": ["oracle", "oci8", "ora-", "oradb"],
    "sqlite": ["sqlite", "sqlite3"],
    "mongodb": ["mongodb", "mongoose", "mongo"],
    "redis": ["redis", "predis"],
    "elasticsearch": ["elasticsearch", "elastic"],
    "cassandra": ["cassandra", "cql"],
    "couchdb": ["couchdb"],
}

FRAMEWORK_SIGNATURES: Dict[str, List[str]] = {
    "django": ["django", "csrfmiddlewaretoken", "djdt"],
    "flask": ["flask", "werkzeug"],
    "spring": ["spring", "springframework", "springboot", "jsessionid"],
    "express": ["express", "x-powered-by: express"],
    "laravel": ["laravel", "laravel_session", "_token"],
    "rails": ["rails", "x-rails", "authenticity_token", "_rails_"],
    "asp.net": ["asp.net", "aspnet", "__viewstate", "__eventvalidation", "aspnetcore"],
    "php": ["php", "phpsessid", "x-powered-by: php"],
    "fastapi": ["fastapi", "starlette"],
    "nextjs": ["next.js", "__next", "_next"],
    "nuxtjs": ["nuxt", "__nuxt"],
    "struts": ["struts", "s2-"],
    "thinkphp": ["thinkphp", "think_"],
}

LANGUAGE_INDICATORS: Dict[str, List[str]] = {
    "php": [".php", "phpsessid", "x-powered-by: php"],
    "java": [".jsp", ".do", ".action", "jsessionid", "java"],
    "python": [".py", "wsgi", "django", "flask", "fastapi"],
    "asp": [".asp", ".aspx", "asp.net"],
    "node": ["express", "node.js", "nodejs"],
    "ruby": [".rb", "rails", "rack", "sinatra"],
    "go": ["go-", "golang"],
}

SERVER_SIGNATURES: Dict[str, List[str]] = {
    "nginx": ["nginx"],
    "apache": ["apache", "httpd"],
    "iis": ["iis", "microsoft-iis"],
    "tomcat": ["tomcat", "coyote"],
    "jetty": ["jetty"],
    "lighttpd": ["lighttpd"],
    "caddy": ["caddy"],
    "gunicorn": ["gunicorn"],
    "uvicorn": ["uvicorn"],
}

# WAF 绕过策略配置
WAF_BYPASS_STRATEGIES: Dict[str, Dict[str, Any]] = {
    "cloudflare": {
        "techniques": ["case_swap", "comment_split", "unicode", "double_url"],
        "specific_payloads": ["/*!50000*/", "/**/", "\\u0027"],
        "difficulty": "hard",
    },
    "aws_waf": {
        "techniques": ["double_encode", "case_swap", "hpp", "unicode"],
        "specific_payloads": ["%2527", "%252f", "%u0027"],
        "difficulty": "medium",
    },
    "modsecurity": {
        "techniques": ["comment_split", "newline", "null_byte", "hex"],
        "specific_payloads": ["/*!", "%0a", "%00", "0x"],
        "difficulty": "medium",
    },
    "imperva": {
        "techniques": ["unicode", "case_swap", "whitespace", "concat"],
        "specific_payloads": ["\\u", "%20", "||"],
        "difficulty": "hard",
    },
    "akamai": {
        "techniques": ["double_url", "unicode", "comment_split"],
        "specific_payloads": ["%25", "\\u0027"],
        "difficulty": "hard",
    },
    "default": {
        "techniques": ["case_swap", "url_encode", "comment_split"],
        "specific_payloads": [],
        "difficulty": "unknown",
    },
}


@dataclass
class TargetProfile:
    """
    目标特征分析配置

    整合自 smart_payload_engine.py 的 TargetProfile 类
    """
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    status_code: int = 200

    # 检测结果缓存
    _features: Optional[Dict[str, Any]] = field(default=None, repr=False)

    @property
    def features(self) -> Dict[str, Any]:
        """懒加载特征分析"""
        if self._features is None:
            self._features = self._analyze()
        return self._features

    def _analyze(self) -> Dict[str, Any]:
        """分析目标特征"""
        return {
            "server": self.detect_server(),
            "waf": self.detect_waf(),
            "framework": self.detect_framework(),
            "language": self.detect_language(),
            "database": self.detect_database(),
            "encoding": self.detect_encoding(),
            "content_type": self.headers.get("content-type", ""),
            "has_csp": "content-security-policy" in {k.lower() for k in self.headers},
            "has_xss_protection": "x-xss-protection" in {k.lower() for k in self.headers},
        }

    def detect_server(self) -> str:
        """检测服务器类型"""
        server_header = self.headers.get("server", "").lower()

        for server_name, signatures in SERVER_SIGNATURES.items():
            if any(sig in server_header for sig in signatures):
                return server_name

        return "unknown"

    def detect_waf(self) -> Optional[str]:
        """检测 WAF 类型"""
        headers_str = json.dumps(self.headers).lower()
        body_lower = self.body.lower()
        combined = f"{headers_str} {body_lower}"

        for waf_name, signatures in WAF_SIGNATURES.items():
            if any(sig.lower() in combined for sig in signatures):
                # 规范化 WAF 类型
                try:
                    from core.evasion import normalize_waf_type
                    return normalize_waf_type(waf_name).value
                except ImportError:
                    return waf_name

        return None

    def detect_framework(self) -> Optional[str]:
        """检测 Web 框架"""
        combined = (json.dumps(self.headers) + self.body).lower()

        for framework, signatures in FRAMEWORK_SIGNATURES.items():
            for sig in signatures:
                if re.search(re.escape(sig), combined, re.IGNORECASE):
                    return framework

        return None

    def detect_language(self) -> Optional[str]:
        """检测后端语言"""
        combined = (self.url + json.dumps(self.headers) + self.body).lower()

        for lang, indicators in LANGUAGE_INDICATORS.items():
            if any(ind in combined for ind in indicators):
                return lang

        return None

    def detect_database(self) -> str:
        """检测数据库类型"""
        combined = (json.dumps(self.headers) + self.body).lower()

        for db_name, signatures in DB_SIGNATURES.items():
            if any(sig in combined for sig in signatures):
                return db_name

        # 基于框架推断数据库
        framework = self.detect_framework()
        lang = self.detect_language()

        framework_db_map = {
            "laravel": "mysql",
            "django": "postgresql",
            "flask": "postgresql",
            "spring": "mysql",
            "rails": "postgresql",
            "asp.net": "mssql",
        }

        if framework in framework_db_map:
            return framework_db_map[framework]

        lang_db_map = {
            "php": "mysql",
            "java": "mysql",
            "python": "postgresql",
            "asp": "mssql",
        }

        if lang in lang_db_map:
            return lang_db_map[lang]

        return "mysql"  # 默认

    def detect_encoding(self) -> str:
        """检测字符编码"""
        content_type = self.headers.get("content-type", "").lower()

        if "utf-8" in content_type:
            return "utf-8"
        elif "gbk" in content_type or "gb2312" in content_type:
            return "gbk"
        elif "iso-8859" in content_type:
            return "iso-8859-1"

        return "utf-8"

    def get_waf_bypass_strategy(self) -> Dict[str, Any]:
        """获取 WAF 绕过策略"""
        waf = self.detect_waf()
        if waf:
            return WAF_BYPASS_STRATEGIES.get(waf, WAF_BYPASS_STRATEGIES["default"])
        return WAF_BYPASS_STRATEGIES["default"]

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "url": self.url,
            "features": self.features,
        }


def detect_waf_from_dict(target_info: Dict[str, Any]) -> Optional[str]:
    """
    从目标信息字典中检测 WAF

    Args:
        target_info: 包含 waf, headers, content 等字段的字典

    Returns:
        WAF 类型或 None
    """
    waf = target_info.get("waf", "")
    headers = str(target_info.get("headers", {})).lower()
    content = str(target_info.get("content", "")).lower()

    combined = f"{waf} {headers} {content}".lower()

    for waf_name, signatures in WAF_SIGNATURES.items():
        if any(sig in combined for sig in signatures):
            try:
                from core.evasion import normalize_waf_type
                return normalize_waf_type(waf_name).value
            except ImportError:
                return waf_name

    return None


def detect_db_from_dict(target_info: Dict[str, Any]) -> str:
    """
    从目标信息字典中检测数据库类型

    Args:
        target_info: 包含 technologies, content, errors 等字段的字典

    Returns:
        数据库类型（默认 mysql）
    """
    technologies = str(target_info.get("technologies", {})).lower()
    content = str(target_info.get("content", "")).lower()
    errors = str(target_info.get("errors", "")).lower()

    combined = f"{technologies} {content} {errors}"

    for db_name, signatures in DB_SIGNATURES.items():
        if any(sig in combined for sig in signatures):
            return db_name

    return "mysql"


def detect_framework_from_dict(target_info: Dict[str, Any]) -> Optional[str]:
    """
    从目标信息字典中检测框架类型

    Args:
        target_info: 包含 technologies, headers 等字段的字典

    Returns:
        框架类型或 None
    """
    technologies = str(target_info.get("technologies", {})).lower()
    headers = str(target_info.get("headers", {})).lower()

    combined = f"{technologies} {headers}"

    for fw_name, signatures in FRAMEWORK_SIGNATURES.items():
        if any(sig in combined for sig in signatures):
            return fw_name

    return None
