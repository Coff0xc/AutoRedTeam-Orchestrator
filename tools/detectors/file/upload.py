#!/usr/bin/env python3
"""
文件上传漏洞检测器 - 基于 BaseDetector 重构

支持检测类型:
- 文件上传表单发现
- 客户端验证绕过
- 危险文件类型上传
- MIME 类型绕过
- 双扩展名绕过
"""

import os
import re
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
)

from tools.detectors.base import BaseDetector, Vulnerability


class FileUploadDetector(BaseDetector):
    """文件上传漏洞检测器"""

    # 测试文件列表 (filename, content, content_type)
    TEST_FILES = [
        # PHP
        ("test.php", "<?php echo 'test'; ?>", "application/x-php"),
        ("test.php.jpg", "<?php echo 'test'; ?>", "image/jpeg"),
        ("test.phtml", "<?php echo 'test'; ?>", "text/html"),
        ("test.php%00.jpg", "<?php echo 'test'; ?>", "image/jpeg"),
        ("test.phar", "<?php echo 'test'; ?>", "application/octet-stream"),
        ("test.php5", "<?php echo 'test'; ?>", "application/x-php"),
        ("test.php7", "<?php echo 'test'; ?>", "application/x-php"),
        # JSP
        ("test.jsp", '<% out.println("test"); %>', "application/x-jsp"),
        ("test.jspx", '<% out.println("test"); %>', "application/xml"),
        # ASP
        ("test.asp", '<% Response.Write("test") %>', "application/x-asp"),
        ("test.aspx", '<% Response.Write("test") %>', "application/x-aspx"),
        # 其他危险类型
        ("test.svg", "<svg onload=alert(1)>", "image/svg+xml"),
        ("test.html", "<script>alert(1)</script>", "text/html"),
        ("test.htm", "<script>alert(1)</script>", "text/html"),
        ("test.shtml", '<!--#exec cmd="id" -->', "text/html"),
        # 配置文件
        (".htaccess", "AddType application/x-httpd-php .jpg", "text/plain"),
        ("web.config", '<?xml version="1.0"?><configuration></configuration>', "text/xml"),
    ]

    # 危险扩展名
    DANGEROUS_EXTENSIONS = [
        ".php",
        ".php3",
        ".php4",
        ".php5",
        ".php7",
        ".phtml",
        ".phar",
        ".jsp",
        ".jspx",
        ".jsw",
        ".jsv",
        ".asp",
        ".aspx",
        ".asa",
        ".asax",
        ".ascx",
        ".ashx",
        ".asmx",
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".sh",
        ".ps1",
        ".svg",
        ".html",
        ".htm",
        ".shtml",
        ".xhtml",
        ".htaccess",
        ".htpasswd",
        "web.config",
    ]

    # 表单相关正则
    FORM_PATTERN = re.compile(r"<form[^>]*>(.*?)</form>", re.DOTALL | re.IGNORECASE)
    FILE_INPUT_PATTERN = re.compile(r'<input[^>]*type=["\']?file["\']?[^>]*>', re.IGNORECASE)
    ACCEPT_PATTERN = re.compile(r'accept=["\']?([^"\'>\s]+)["\']?', re.IGNORECASE)
    ACTION_PATTERN = re.compile(r'action=["\']?([^"\'>\s]+)["\']?', re.IGNORECASE)

    def get_payloads(self) -> Dict[str, List]:
        """获取 Payload 库"""
        return {
            "Test Files": self.TEST_FILES,
            "Dangerous Extensions": self.DANGEROUS_EXTENSIONS,
        }

    def validate_response(
        self, response: Dict[str, Any], payload: str, baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在文件上传漏洞"""
        if not response or not response.get("success"):
            return False

        resp_text = response.get("response_text", "").lower()

        # 检查上传成功指示器
        success_indicators = [
            "upload success",
            "上传成功",
            "文件已上传",
            "uploaded successfully",
            "file saved",
        ]

        for indicator in success_indicators:
            if indicator in resp_text:
                return True

        return False

    def _find_upload_forms(self, html: str, base_url: str) -> List[Dict[str, Any]]:
        """查找页面中的文件上传表单"""
        forms = []
        html_lower = html.lower()

        # 检查是否存在文件上传
        if 'type="file"' not in html_lower and "type='file'" not in html_lower:
            return forms

        # 查找所有表单
        form_matches = self.FORM_PATTERN.findall(html)

        for i, form_content in enumerate(form_matches):
            # 检查是否包含文件输入
            if not self.FILE_INPUT_PATTERN.search(form_content):
                continue

            form_info = {
                "index": i,
                "has_file_input": True,
                "accept_types": [],
                "action": None,
                "is_multipart": "multipart/form-data" in form_content.lower(),
            }

            # 提取 accept 属性
            accept_match = self.ACCEPT_PATTERN.search(form_content)
            if accept_match:
                form_info["accept_types"] = accept_match.group(1).split(",")

            # 提取 action 属性
            action_match = self.ACTION_PATTERN.search(form_content)
            if action_match:
                action = action_match.group(1)
                form_info["action"] = urljoin(base_url, action)

            forms.append(form_info)

        return forms

    def _check_client_side_validation(self, html: str) -> Dict[str, Any]:
        """检查客户端验证"""
        html_lower = html.lower()

        checks = {
            "has_accept_attribute": False,
            "has_js_validation": False,
            "accept_types": [],
            "js_patterns": [],
        }

        # 检查 accept 属性
        accept_matches = self.ACCEPT_PATTERN.findall(html)
        if accept_matches:
            checks["has_accept_attribute"] = True
            checks["accept_types"] = accept_matches

        # 检查 JavaScript 验证
        js_validation_patterns = [
            r"\.files\[0\]\.type",
            r"\.files\[0\]\.name",
            r"filetype",
            r"allowedextensions",
            r"validextensions",
            r"checkfiletype",
            r"validatefile",
        ]

        for pattern in js_validation_patterns:
            if re.search(pattern, html_lower):
                checks["has_js_validation"] = True
                checks["js_patterns"].append(pattern)

        return checks

    def detect_upload_forms(self, url: str) -> List[Vulnerability]:
        """检测文件上传表单"""
        vulnerabilities = []

        response = self.send_request(url)
        if not response or not response.get("success"):
            return vulnerabilities

        html = response.get("response_text", "")
        forms = self._find_upload_forms(html, url)

        if forms:
            for form in forms:
                severity = "INFO"
                evidence = "发现文件上传表单"

                # 检查是否缺少 multipart
                if not form["is_multipart"]:
                    severity = "LOW"
                    evidence += "，但未使用 multipart/form-data"

                vulnerabilities.append(
                    Vulnerability(
                        type="File Upload Form Found",
                        severity=severity,
                        url=form.get("action") or url,
                        evidence=evidence,
                        verified=True,
                        confidence=0.95,
                        details={
                            "form_index": form["index"],
                            "is_multipart": form["is_multipart"],
                            "accept_types": form["accept_types"],
                            "action": form["action"],
                        },
                    )
                )

        return vulnerabilities

    def detect_client_validation(self, url: str) -> List[Vulnerability]:
        """检测仅客户端验证的问题"""
        vulnerabilities = []

        response = self.send_request(url)
        if not response or not response.get("success"):
            return vulnerabilities

        html = response.get("response_text", "")
        validation = self._check_client_side_validation(html)

        # 检查是否只有客户端验证
        if validation["has_accept_attribute"] or validation["has_js_validation"]:
            issues = []
            if validation["has_accept_attribute"]:
                issues.append(f"accept 属性限制: {', '.join(validation['accept_types'])}")
            if validation["has_js_validation"]:
                issues.append("JavaScript 文件类型验证")

            vulnerabilities.append(
                Vulnerability(
                    type="Client-side Validation Only",
                    severity="MEDIUM",
                    url=url,
                    evidence=f"仅有客户端验证可被绕过: {'; '.join(issues)}",
                    verified=True,
                    confidence=0.8,
                    details={
                        "has_accept_attribute": validation["has_accept_attribute"],
                        "has_js_validation": validation["has_js_validation"],
                        "accept_types": validation["accept_types"],
                        "js_patterns": validation["js_patterns"],
                        "bypass_note": "客户端验证可通过修改请求或禁用 JavaScript 绕过",
                    },
                )
            )

        return vulnerabilities

    def detect_dangerous_extensions(self, url: str) -> List[Vulnerability]:
        """检测是否允许危险扩展名"""
        vulnerabilities = []

        response = self.send_request(url)
        if not response or not response.get("success"):
            return vulnerabilities

        html = response.get("response_text", "")
        html_lower = html.lower()

        # 检查 accept 属性是否允许危险类型
        accept_matches = self.ACCEPT_PATTERN.findall(html)

        dangerous_allowed = []
        for accept in accept_matches:
            accept_lower = accept.lower()
            # 检查是否允许所有类型
            if "*/*" in accept_lower or ".*" in accept_lower:
                dangerous_allowed.append("*/* (所有类型)")
            # 检查是否允许危险 MIME 类型
            dangerous_mimes = [
                "application/x-php",
                "application/x-httpd-php",
                "text/x-php",
                "application/x-jsp",
                "application/x-asp",
                "text/html",
            ]
            for mime in dangerous_mimes:
                if mime in accept_lower:
                    dangerous_allowed.append(mime)

        if dangerous_allowed:
            vulnerabilities.append(
                Vulnerability(
                    type="Dangerous File Types Allowed",
                    severity="HIGH",
                    url=url,
                    evidence=f"允许上传危险文件类型: {', '.join(set(dangerous_allowed))}",
                    verified=True,
                    confidence=0.75,
                    details={
                        "dangerous_types": list(set(dangerous_allowed)),
                        "all_accept_types": accept_matches,
                    },
                )
            )

        return vulnerabilities

    def get_bypass_payloads(self) -> List[Dict[str, Any]]:
        """获取文件上传绕过 Payload"""
        return [
            {
                "technique": "Double Extension",
                "files": ["test.php.jpg", "test.php.png", "test.php.gif"],
                "description": "双扩展名绕过",
            },
            {
                "technique": "Null Byte",
                "files": ["test.php%00.jpg", "test.php\x00.jpg"],
                "description": "空字节截断 (PHP < 5.3.4)",
            },
            {
                "technique": "Case Variation",
                "files": ["test.PhP", "test.pHp", "test.PHP"],
                "description": "大小写变换绕过",
            },
            {
                "technique": "Alternative Extensions",
                "files": ["test.phtml", "test.php5", "test.phar"],
                "description": "替代扩展名",
            },
            {
                "technique": "MIME Type Mismatch",
                "files": [("test.php", "image/jpeg"), ("test.php", "image/gif")],
                "description": "MIME 类型欺骗",
            },
            {
                "technique": "Content-Type Bypass",
                "files": [("test.php", "application/octet-stream")],
                "description": "Content-Type 绕过",
            },
            {
                "technique": "Magic Bytes",
                "files": ["GIF89a<?php echo 'test'; ?>"],
                "description": "文件头伪造",
            },
        ]

    def detect(
        self, url: str, param: Optional[str] = None, deep_scan: bool = True
    ) -> Dict[str, Any]:
        """
        文件上传漏洞检测入口

        Args:
            url: 目标 URL
            param: 未使用 (保持接口一致)
            deep_scan: 是否深度扫描

        Returns:
            检测结果字典
        """
        all_vulnerabilities = []

        # 1. 检测文件上传表单
        form_vulns = self.detect_upload_forms(url)
        all_vulnerabilities.extend(form_vulns)

        # 2. 检测客户端验证
        if form_vulns:  # 只有发现表单才检测验证
            validation_vulns = self.detect_client_validation(url)
            all_vulnerabilities.extend(validation_vulns)

        if deep_scan:
            # 3. 检测危险扩展名
            extension_vulns = self.detect_dangerous_extensions(url)
            all_vulnerabilities.extend(extension_vulns)

        # 获取绕过建议
        bypass_payloads = self.get_bypass_payloads() if form_vulns else []

        return {
            "success": True,
            "url": url,
            "detector": self.__class__.__name__,
            "vulnerabilities": [v.to_dict() for v in all_vulnerabilities],
            "total": len(all_vulnerabilities),
            "verified_count": sum(1 for v in all_vulnerabilities if v.verified),
            "by_severity": {
                "high": sum(1 for v in all_vulnerabilities if v.severity == "HIGH"),
                "medium": sum(1 for v in all_vulnerabilities if v.severity == "MEDIUM"),
                "low": sum(1 for v in all_vulnerabilities if v.severity == "LOW"),
                "info": sum(1 for v in all_vulnerabilities if v.severity == "INFO"),
            },
            "test_files": [f[0] for f in self.TEST_FILES],
            "bypass_techniques": bypass_payloads,
            "note": "文件上传漏洞需要手动测试实际上传功能",
        }


# 便捷函数 - 兼容旧接口
def file_upload_detect(url: str, deep_scan: bool = True) -> Dict[str, Any]:
    """文件上传漏洞检测 (兼容旧接口)"""
    with FileUploadDetector() as detector:
        return detector.detect(url, deep_scan=deep_scan)
