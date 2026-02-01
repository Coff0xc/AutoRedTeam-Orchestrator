#!/usr/bin/env python3
"""
SSTI (Server-Side Template Injection) 检测器

检测服务端模板注入漏洞，支持多种模板引擎:
- Jinja2 (Python)
- Twig (PHP)
- Freemarker (Java)
- Velocity (Java)
- Smarty (PHP)
- Mako (Python)
- ERB (Ruby)
- Thymeleaf (Java)
"""

import logging
import re
from typing import Any, Dict, List, Optional

from ..base import BaseDetector, Vulnerability


class SSTIDetector(BaseDetector):
    """
    SSTI 漏洞检测器

    通过注入模板表达式检测服务端模板注入漏洞。
    """

    # SSTI 专用测试参数
    DEFAULT_PARAMS = [
        "q",
        "search",
        "query",
        "name",
        "input",
        "template",
        "page",
        "view",
        "content",
        "text",
        "message",
        "title",
        "email",
        "username",
        "comment",
        "data",
    ]

    # 模板引擎特征
    ENGINE_SIGNATURES = {
        "jinja2": {
            "payloads": [
                ("{{7*7}}", "49"),
                ("{{7*'7'}}", "7777777"),
                ("{{config}}", "Config"),
                ("{{self.__class__}}", "class"),
            ],
            "error_patterns": [
                r"jinja2\.exceptions",
                r"UndefinedError",
                r"TemplateSyntaxError",
            ],
        },
        "twig": {
            "payloads": [
                ("{{7*7}}", "49"),
                ("{{7*'7'}}", "49"),
                ("{{_self.env}}", "Environment"),
                ("{{dump(app)}}", "AppVariable"),
            ],
            "error_patterns": [
                r"Twig_Error",
                r"Twig\\Error",
            ],
        },
        "freemarker": {
            "payloads": [
                ("${7*7}", "49"),
                ("${.version}", "version"),
                ("<#assign x=7*7>${x}", "49"),
            ],
            "error_patterns": [
                r"freemarker\.core",
                r"FreeMarker",
                r"ParseException",
            ],
        },
        "velocity": {
            "payloads": [
                ("#set($x=7*7)$x", "49"),
                ("$class.inspect", "class"),
            ],
            "error_patterns": [
                r"org\.apache\.velocity",
                r"VelocityException",
            ],
        },
        "smarty": {
            "payloads": [
                ("{$smarty.version}", "Smarty"),
                ("{7*7}", "49"),
                ("{php}echo 7*7;{/php}", "49"),
            ],
            "error_patterns": [
                r"Smarty",
                r"SmartyCompilerException",
            ],
        },
        "mako": {
            "payloads": [
                ("${7*7}", "49"),
                ('<%page args="x=7*7"/>${x}', "49"),
            ],
            "error_patterns": [
                r"mako\.exceptions",
                r"MakoException",
            ],
        },
        "erb": {
            "payloads": [
                ("<%=7*7%>", "49"),
                ("<%=`id`%>", "uid="),
            ],
            "error_patterns": [
                r"ERB",
                r"SyntaxError",
            ],
        },
        "thymeleaf": {
            "payloads": [
                ("[[${7*7}]]", "49"),
                ("[(${7*7})]", "49"),
            ],
            "error_patterns": [
                r"org\.thymeleaf",
                r"TemplateProcessingException",
            ],
        },
        "pebble": {
            "payloads": [
                ("{{7*7}}", "49"),
                ("{{request}}", "request"),
            ],
            "error_patterns": [
                r"PebbleException",
                r"com\.mitchellbosecke\.pebble",
            ],
        },
        "handlebars": {
            "payloads": [
                ('{{#with "s" as |string|}}', ""),
            ],
            "error_patterns": [
                r"Handlebars",
            ],
        },
    }

    def get_payloads(self) -> Dict[str, List[str]]:
        """获取 SSTI Payload 库"""
        payloads = {}
        for engine, config in self.ENGINE_SIGNATURES.items():
            payloads[engine] = [p[0] for p in config["payloads"]]
        return payloads

    def validate_response(
        self, response: Dict[str, Any], payload: str, baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在 SSTI 漏洞"""
        if not response.get("success"):
            return False

        text = response.get("response_text", "")

        # 检查每个引擎的预期输出
        for engine, config in self.ENGINE_SIGNATURES.items():
            for test_payload, expected in config["payloads"]:
                if payload == test_payload and expected in text:
                    # 确保不是原始 payload 被反射
                    if payload not in text or expected != payload:
                        return True

        return False

    def detect(
        self, url: str, param: Optional[str] = None, deep_scan: bool = False
    ) -> Dict[str, Any]:
        """执行 SSTI 检测"""
        from tools._common import reset_failure_counter

        reset_failure_counter()

        vulnerabilities = []
        test_params = self.get_test_params(param)
        baseline = self.get_baseline(url)

        for test_param in test_params[:5]:  # 限制参数数量
            for engine, config in self.ENGINE_SIGNATURES.items():
                for test_payload, expected in config["payloads"]:
                    try:
                        response = self.send_request(url, test_payload, test_param)

                        if not response or not response.get("success"):
                            continue

                        text = response.get("response_text", "")

                        # 检查预期输出
                        if expected in text:
                            # 排除 payload 本身被反射的情况
                            if test_payload in text and expected == test_payload:
                                continue

                            vuln = Vulnerability(
                                type=f"SSTI ({engine})",
                                severity="CRITICAL",
                                param=test_param,
                                payload=test_payload,
                                url=response.get("url", url),
                                evidence=f"Expected '{expected}' found in response",
                                verified=False,
                                confidence=0.8,
                                details={"engine": engine, "expected_output": expected},
                            )
                            vulnerabilities.append(vuln)

                            if not deep_scan:
                                break

                        # 检查错误信息泄露
                        for pattern in config.get("error_patterns", []):
                            if re.search(pattern, text, re.IGNORECASE):
                                if baseline:
                                    baseline_text = baseline.get("response_text", "")
                                    if not re.search(pattern, baseline_text, re.IGNORECASE):
                                        vuln = Vulnerability(
                                            type=f"SSTI Error ({engine})",
                                            severity="MEDIUM",
                                            param=test_param,
                                            payload=test_payload,
                                            url=response.get("url", url),
                                            evidence=f"Template error: {pattern}",
                                            verified=False,
                                            confidence=0.5,
                                            details={"engine": engine, "error_pattern": pattern},
                                        )
                                        vulnerabilities.append(vuln)
                                break

                    except Exception as exc:
                        logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

                if vulnerabilities and not deep_scan:
                    break
            if vulnerabilities and not deep_scan:
                break

        # 二次验证
        verified_vulns = []
        for vuln in vulnerabilities:
            if self._verify_ssti(url, vuln):
                vuln.verified = True
                vuln.confidence = min(1.0, vuln.confidence + 0.15)
            verified_vulns.append(vuln)

        return {
            "success": True,
            "url": url,
            "detector": "SSTIDetector",
            "vulnerabilities": [v.to_dict() for v in verified_vulns],
            "total": len(verified_vulns),
            "verified_count": sum(1 for v in verified_vulns if v.verified),
            "recommendations": self._get_recommendations() if verified_vulns else [],
        }

    def _verify_ssti(self, url: str, vuln: Vulnerability) -> bool:
        """二次验证 SSTI 漏洞"""
        if not vuln.param:
            return False

        engine = vuln.details.get("engine", "")
        verify_payloads = {
            "jinja2": ("{{8*8}}", "64"),
            "twig": ("{{8*8}}", "64"),
            "freemarker": ("${8*8}", "64"),
            "velocity": ("#set($y=8*8)$y", "64"),
            "smarty": ("{8*8}", "64"),
            "mako": ("${8*8}", "64"),
            "erb": ("<%=8*8%>", "64"),
            "thymeleaf": ("[[${8*8}]]", "64"),
        }

        if engine in verify_payloads:
            payload, expected = verify_payloads[engine]
            try:
                response = self.send_request(url, payload, vuln.param)
                if response and response.get("success"):
                    if expected in response.get("response_text", ""):
                        return True
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        return False

    def _get_recommendations(self) -> List[str]:
        """获取修复建议"""
        return [
            "避免将用户输入直接传入模板引擎",
            "使用沙箱模式渲染模板",
            "对用户输入进行严格的白名单过滤",
            "使用逻辑无关的模板引擎 (如 Mustache)",
            "禁用模板引擎的危险功能和内置对象",
            "实施 CSP 策略限制脚本执行",
        ]
