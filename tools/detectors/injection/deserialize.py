#!/usr/bin/env python3
"""
Deserialize (反序列化漏洞) 检测器

检测不安全的反序列化漏洞，支持多种语言/框架:
- Java (ysoserial, Commons Collections, etc.)
- PHP (unserialize)
- Python (pickle)
- .NET (BinaryFormatter, ObjectStateFormatter)
"""

from typing import Dict, List, Any, Optional
import re
import base64

from ..base import BaseDetector, Vulnerability


class DeserializeDetector(BaseDetector):
    """
    反序列化漏洞检测器

    检测 Java/PHP/Python/.NET 等语言的不安全反序列化漏洞。
    """

    # 反序列化专用测试参数
    DEFAULT_PARAMS = [
        "data", "object", "payload", "session", "state",
        "viewstate", "token", "serialized", "obj", "input"
    ]

    # Java 序列化特征
    JAVA_SIGNATURES = {
        "magic_bytes": [
            ("aced0005", "Java 序列化魔数 (hex)"),
            ("rO0AB", "Java 序列化 Base64"),
            ("H4sIAAAA", "Java Gzip 序列化 Base64"),
        ],
        "error_patterns": [
            r"java\.io\.ObjectInputStream",
            r"java\.io\.InvalidClassException",
            r"java\.lang\.ClassNotFoundException",
            r"java\.io\.StreamCorruptedException",
            r"org\.apache\.commons\.collections",
            r"ysoserial",
            r"gadget\s*chain",
        ],
        "dangerous_endpoints": [
            "/invoker/readonly",
            "/invoker/JMXInvokerServlet",
            "/_async/AsyncResponseService",
            "/wls-wsat/",
            "/console/",
            "/solr/admin/cores",
            "/actuator",
            "/actuator/env",
            "/actuator/heapdump",
        ]
    }

    # PHP 序列化特征
    PHP_SIGNATURES = {
        "patterns": [
            ('O:8:"stdClass"', "PHP 对象序列化"),
            ("a:1:{", "PHP 数组序列化"),
            ("s:4:", "PHP 字符串序列化"),
            ('O:4:"User"', "PHP 自定义对象"),
        ],
        "error_patterns": [
            r"unserialize\(\)",
            r"__wakeup",
            r"__destruct",
            r"allowed_classes",
            r"PHP\s*Fatal\s*error.*unserialize",
        ]
    }

    # Python 序列化特征
    PYTHON_SIGNATURES = {
        "patterns": [
            ("gASV", "Python Pickle Base64"),
            ("(dp0", "Python Pickle Protocol 0"),
            ("cos\nsystem", "Python Pickle RCE"),
            ("cposix\nsystem", "Python Pickle POSIX"),
            ("c__builtin__\neval", "Python Pickle eval"),
        ],
        "error_patterns": [
            r"pickle\.UnpicklingError",
            r"_pickle\.UnpicklingError",
            r"cPickle",
            r"marshal\.loads",
        ]
    }

    # .NET 序列化特征
    DOTNET_SIGNATURES = {
        "patterns": [
            ("AAEAAAD/////", ".NET BinaryFormatter Base64"),
            ("__VIEWSTATE", "ASP.NET ViewState"),
            ("__EVENTVALIDATION", "ASP.NET EventValidation"),
        ],
        "error_patterns": [
            r"System\.Runtime\.Serialization",
            r"BinaryFormatter",
            r"ObjectStateFormatter",
            r"LosFormatter",
            r"SoapFormatter",
        ]
    }

    def get_payloads(self) -> Dict[str, List[str]]:
        """获取反序列化 Payload 库"""
        return {
            "java_detection": [
                # 基础检测 payload (不执行命令，仅触发反序列化)
                "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
                "aced0005737200116a6176612e7574696c2e486173684d6170",
            ],
            "php_detection": [
                'O:8:"stdClass":0:{}',
                'a:1:{s:4:"test";s:4:"test";}',
                'O:7:"Example":1:{s:4:"data";s:4:"test";}',
            ],
            "python_detection": [
                # 安全的检测 payload
                "gASVDgAAAAAAAACMBHRlc3SULg==",  # pickle.dumps("test")
            ],
            "dotnet_detection": [
                "AAEAAAD/////AQAAAAAAAAAMAgAAAFRTeXN0ZW0=",
            ],
        }

    def validate_response(
        self,
        response: Dict[str, Any],
        payload: str,
        baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在反序列化漏洞"""
        if not response.get("success"):
            return False

        text = response.get("response_text", "")

        # 检查 Java 错误特征
        for pattern in self.JAVA_SIGNATURES["error_patterns"]:
            if re.search(pattern, text, re.IGNORECASE):
                if baseline:
                    baseline_text = baseline.get("response_text", "")
                    if not re.search(pattern, baseline_text, re.IGNORECASE):
                        return True
                else:
                    return True

        # 检查 PHP 错误特征
        for pattern in self.PHP_SIGNATURES["error_patterns"]:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        # 检查 Python 错误特征
        for pattern in self.PYTHON_SIGNATURES["error_patterns"]:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        # 检查 .NET 错误特征
        for pattern in self.DOTNET_SIGNATURES["error_patterns"]:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        # 检查 500 错误 + 异常关键词
        status = response.get("status_code", 0)
        if status == 500:
            exception_keywords = ["exception", "error", "stack", "trace", "serialize"]
            if any(kw in text.lower() for kw in exception_keywords):
                return True

        return False

    def detect(
        self,
        url: str,
        param: Optional[str] = None,
        deep_scan: bool = False
    ) -> Dict[str, Any]:
        """执行反序列化漏洞检测"""
        from tools._common import reset_failure_counter
        reset_failure_counter()

        vulnerabilities = []
        test_params = self.get_test_params(param)
        baseline = self.get_baseline(url)

        # 1. 检测响应/Cookie 中的序列化数据
        if baseline and baseline.get("success"):
            content = baseline.get("response_text", "")
            cookies = baseline.get("cookies", {})

            # 检查响应内容
            for lang, sigs in [
                ("Java", self.JAVA_SIGNATURES),
                ("PHP", self.PHP_SIGNATURES),
                ("Python", self.PYTHON_SIGNATURES),
                (".NET", self.DOTNET_SIGNATURES)
            ]:
                patterns = sigs.get("magic_bytes", sigs.get("patterns", []))
                for pattern_data in patterns:
                    pattern = pattern_data[0] if isinstance(pattern_data, tuple) else pattern_data
                    desc = pattern_data[1] if isinstance(pattern_data, tuple) else "Serialized data"
                    if pattern in content:
                        vuln = Vulnerability(
                            type=f"Deserialization ({lang})",
                            severity="HIGH",
                            url=url,
                            evidence=f"Response contains: {desc}",
                            verified=False,
                            confidence=0.6,
                            details={"language": lang, "location": "response"}
                        )
                        vulnerabilities.append(vuln)

            # 检查 Cookie
            for name, value in cookies.items():
                for lang, sigs in [
                    ("Java", self.JAVA_SIGNATURES),
                    ("PHP", self.PHP_SIGNATURES),
                    ("Python", self.PYTHON_SIGNATURES),
                    (".NET", self.DOTNET_SIGNATURES)
                ]:
                    patterns = sigs.get("magic_bytes", sigs.get("patterns", []))
                    for pattern_data in patterns:
                        pattern = pattern_data[0] if isinstance(pattern_data, tuple) else pattern_data
                        if pattern in value:
                            vuln = Vulnerability(
                                type=f"Deserialization in Cookie ({lang})",
                                severity="CRITICAL",
                                url=url,
                                evidence=f"Cookie '{name}' contains serialized data",
                                verified=False,
                                confidence=0.8,
                                details={"language": lang, "cookie_name": name}
                            )
                            vulnerabilities.append(vuln)

        # 2. 检测危险端点
        base_url = url.rstrip('/')
        for endpoint in self.JAVA_SIGNATURES["dangerous_endpoints"]:
            try:
                response = self.send_request(f"{base_url}{endpoint}")
                if response and response.get("success"):
                    status = response.get("status_code", 0)
                    if status != 404:
                        severity = "HIGH" if status == 200 else "MEDIUM"
                        vuln = Vulnerability(
                            type="Dangerous Deserialization Endpoint",
                            severity=severity,
                            url=f"{base_url}{endpoint}",
                            evidence=f"Endpoint accessible (HTTP {status})",
                            verified=False,
                            confidence=0.7,
                            details={"endpoint": endpoint, "status_code": status}
                        )
                        vulnerabilities.append(vuln)
            except Exception:
                pass

        # 3. 参数注入测试
        payloads = self.get_payloads()
        for test_param in test_params[:5]:
            for lang, payload_list in payloads.items():
                for payload in payload_list:
                    try:
                        response = self.send_request(url, payload, test_param)

                        if not response or not response.get("success"):
                            continue

                        if self.validate_response(response, payload, baseline):
                            lang_name = lang.replace("_detection", "").upper()
                            vuln = Vulnerability(
                                type=f"Deserialization ({lang_name})",
                                severity="CRITICAL",
                                param=test_param,
                                payload=payload[:50] + "..." if len(payload) > 50 else payload,
                                url=response.get("url", url),
                                evidence="Deserialization error triggered",
                                verified=False,
                                confidence=0.7,
                                details={"language": lang_name}
                            )
                            vulnerabilities.append(vuln)

                            if not deep_scan:
                                break
                    except Exception:
                        pass

                if vulnerabilities and not deep_scan:
                    break
            if vulnerabilities and not deep_scan:
                break

        # 二次验证
        verified_vulns = []
        for vuln in vulnerabilities:
            if self._verify_deserialize(url, vuln):
                vuln.verified = True
                vuln.confidence = min(1.0, vuln.confidence + 0.15)
            verified_vulns.append(vuln)

        return {
            "success": True,
            "url": url,
            "detector": "DeserializeDetector",
            "vulnerabilities": [v.to_dict() for v in verified_vulns],
            "total": len(verified_vulns),
            "verified_count": sum(1 for v in verified_vulns if v.verified),
            "recommendations": self._get_recommendations() if verified_vulns else []
        }

    def _verify_deserialize(self, url: str, vuln: Vulnerability) -> bool:
        """二次验证反序列化漏洞"""
        if not vuln.param:
            # 端点类型漏洞，检查是否持续可访问
            if "Endpoint" in vuln.type:
                try:
                    response = self.send_request(vuln.url)
                    if response and response.get("success"):
                        return response.get("status_code", 0) != 404
                except Exception:
                    pass
            return False

        # 使用不同的 payload 重新测试
        lang = vuln.details.get("language", "").lower()
        verify_payloads = {
            "java": "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0",
            "php": 'O:8:"stdClass":1:{s:1:"a";s:1:"b";}',
            "python": "gASVEgAAAAAAAACMBHRlc3QylC4=",
            "dotnet": "AAEAAAD/////AQAAAAAAAAAPAQAAAA==",
        }

        if lang in verify_payloads:
            try:
                response = self.send_request(url, verify_payloads[lang], vuln.param)
                if response and response.get("success"):
                    return self.validate_response(response, verify_payloads[lang])
            except Exception:
                pass

        return False

    def _get_recommendations(self) -> List[str]:
        """获取修复建议"""
        return [
            "避免反序列化不可信数据",
            "使用白名单验证反序列化的类",
            "升级到安全版本的序列化库",
            "使用 JSON 等安全的数据格式替代",
            "实施输入验证和完整性检查",
            "对于 Java: 使用 SerialKiller 或 NotSoSerial",
            "对于 PHP: 使用 allowed_classes 参数",
            "对于 Python: 避免使用 pickle，改用 json",
            "对于 .NET: 避免使用 BinaryFormatter"
        ]
