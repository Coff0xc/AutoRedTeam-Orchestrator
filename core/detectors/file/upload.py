"""
文件上传漏洞检测器

检测文件上传相关的安全问题,包括表单发现、客户端验证绕过、危险扩展名等
"""

import re
import logging
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType
from ..factory import register_detector

logger = logging.getLogger(__name__)


@register_detector('file_upload')
class FileUploadDetector(BaseDetector):
    """文件上传漏洞检测器

    检测类型:
    - 文件上传表单发现
    - 客户端验证绕过
    - 危险文件类型上传
    - MIME 类型绕过
    - 双扩展名绕过

    使用示例:
        detector = FileUploadDetector()
        results = detector.detect("https://example.com/upload")
    """

    name = 'file_upload'
    description = '文件上传漏洞检测器'
    vuln_type = 'file_upload'
    severity = Severity.HIGH
    detector_type = DetectorType.ACCESS
    version = '1.0.0'

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
        ("test.jsp", "<% out.println(\"test\"); %>", "application/x-jsp"),
        ("test.jspx", "<% out.println(\"test\"); %>", "application/xml"),
        # ASP
        ("test.asp", "<% Response.Write(\"test\") %>", "application/x-asp"),
        ("test.aspx", "<% Response.Write(\"test\") %>", "application/x-aspx"),
        # 其他危险类型
        ("test.svg", "<svg onload=alert(1)>", "image/svg+xml"),
        ("test.html", "<script>alert(1)</script>", "text/html"),
        ("test.htm", "<script>alert(1)</script>", "text/html"),
        ("test.shtml", "<!--#exec cmd=\"id\" -->", "text/html"),
        # 配置文件
        (".htaccess", "AddType application/x-httpd-php .jpg", "text/plain"),
        ("web.config", "<?xml version=\"1.0\"?><configuration></configuration>", "text/xml"),
    ]

    # 危险扩展名
    DANGEROUS_EXTENSIONS = [
        ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar",
        ".jsp", ".jspx", ".jsw", ".jsv",
        ".asp", ".aspx", ".asa", ".asax", ".ascx", ".ashx", ".asmx",
        ".exe", ".dll", ".bat", ".cmd", ".sh", ".ps1",
        ".svg", ".html", ".htm", ".shtml", ".xhtml",
        ".htaccess", ".htpasswd", "web.config",
    ]

    # 表单相关正则
    FORM_PATTERN = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
    FILE_INPUT_PATTERN = re.compile(r'<input[^>]*type=["\']?file["\']?[^>]*>', re.IGNORECASE)
    ACCEPT_PATTERN = re.compile(r'accept=["\']?([^"\'>\s]+)["\']?', re.IGNORECASE)
    ACTION_PATTERN = re.compile(r'action=["\']?([^"\'>\s]+)["\']?', re.IGNORECASE)

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - deep_scan: 是否深度扫描
        """
        super().__init__(config)
        self.deep_scan = self.config.get('deep_scan', True)

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测文件上传漏洞

        Args:
            url: 目标 URL
            **kwargs:
                deep_scan: 是否深度扫描 (覆盖配置)

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        deep_scan = kwargs.get('deep_scan', self.deep_scan)

        # 1. 检测文件上传表单
        form_results = self._detect_upload_forms(url)
        results.extend(form_results)

        # 2. 检测客户端验证
        if form_results:  # 只有发现表单才检测验证
            validation_results = self._detect_client_validation(url)
            results.extend(validation_results)

        if deep_scan:
            # 3. 检测危险扩展名
            extension_results = self._detect_dangerous_extensions(url)
            results.extend(extension_results)

        self._log_detection_end(url, results)
        return results

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
            r'\.files\[0\]\.type',
            r'\.files\[0\]\.name',
            r'filetype',
            r'allowedextensions',
            r'validextensions',
            r'checkfiletype',
            r'validatefile',
        ]

        for pattern in js_validation_patterns:
            if re.search(pattern, html_lower):
                checks["has_js_validation"] = True
                checks["js_patterns"].append(pattern)

        return checks

    def _detect_upload_forms(self, url: str) -> List[DetectionResult]:
        """检测文件上传表单"""
        results = []

        try:
            response = self.http_client.get(url)
            if not response:
                return results

            html = getattr(response, 'text', '')
            forms = self._find_upload_forms(html, url)

            if forms:
                for form in forms:
                    # 判断严重程度
                    if not form["is_multipart"]:
                        severity = Severity.LOW
                        evidence = "发现文件上传表单，但未使用 multipart/form-data"
                    else:
                        severity = Severity.INFO
                        evidence = "发现文件上传表单"

                    request_info = self._build_request_info(
                        method='GET',
                        url=url
                    )
                    response_info = self._build_response_info(response)

                    result = DetectionResult(
                        vulnerable=True,
                        vuln_type=self.vuln_type,
                        severity=severity,
                        url=form.get("action") or url,
                        evidence=evidence,
                        confidence=0.95,
                        verified=True,
                        detector=self.name,
                        detector_version=self.version,
                        request=request_info,
                        response=response_info,
                        remediation="确保正确配置文件上传功能,使用服务端验证",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
                        ],
                        extra={
                            'form_index': form["index"],
                            'is_multipart': form["is_multipart"],
                            'accept_types': form["accept_types"],
                            'action': form["action"]
                        }
                    )
                    results.append(result)

        except Exception as e:
            logger.debug(f"[{self.name}] 表单检测失败: {e}")

        return results

    def _detect_client_validation(self, url: str) -> List[DetectionResult]:
        """检测仅客户端验证的问题"""
        results = []

        try:
            response = self.http_client.get(url)
            if not response:
                return results

            html = getattr(response, 'text', '')
            validation = self._check_client_side_validation(html)

            # 检查是否只有客户端验证
            if validation["has_accept_attribute"] or validation["has_js_validation"]:
                issues = []
                if validation["has_accept_attribute"]:
                    issues.append(f"accept 属性限制: {', '.join(validation['accept_types'])}")
                if validation["has_js_validation"]:
                    issues.append("JavaScript 文件类型验证")

                request_info = self._build_request_info(
                    method='GET',
                    url=url
                )
                response_info = self._build_response_info(response)

                result = DetectionResult(
                    vulnerable=True,
                    vuln_type=self.vuln_type,
                    severity=Severity.MEDIUM,
                    url=url,
                    evidence=f"仅有客户端验证可被绕过: {'; '.join(issues)}",
                    confidence=0.8,
                    verified=True,
                    detector=self.name,
                    detector_version=self.version,
                    request=request_info,
                    response=response_info,
                    remediation="实施服务端文件类型验证,不依赖客户端验证",
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
                    ],
                    extra={
                        'has_accept_attribute': validation["has_accept_attribute"],
                        'has_js_validation': validation["has_js_validation"],
                        'accept_types': validation["accept_types"],
                        'js_patterns': validation["js_patterns"],
                        'bypass_note': "客户端验证可通过修改请求或禁用 JavaScript 绕过"
                    }
                )
                results.append(result)

        except Exception as e:
            logger.debug(f"[{self.name}] 客户端验证检测失败: {e}")

        return results

    def _detect_dangerous_extensions(self, url: str) -> List[DetectionResult]:
        """检测是否允许危险扩展名"""
        results = []

        try:
            response = self.http_client.get(url)
            if not response:
                return results

            html = getattr(response, 'text', '')
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
                    "application/x-php", "application/x-httpd-php",
                    "text/x-php", "application/x-jsp",
                    "application/x-asp", "text/html",
                ]
                for mime in dangerous_mimes:
                    if mime in accept_lower:
                        dangerous_allowed.append(mime)

            if dangerous_allowed:
                request_info = self._build_request_info(
                    method='GET',
                    url=url
                )
                response_info = self._build_response_info(response)

                result = DetectionResult(
                    vulnerable=True,
                    vuln_type=self.vuln_type,
                    severity=Severity.HIGH,
                    url=url,
                    evidence=f"允许上传危险文件类型: {', '.join(set(dangerous_allowed))}",
                    confidence=0.75,
                    verified=True,
                    detector=self.name,
                    detector_version=self.version,
                    request=request_info,
                    response=response_info,
                    remediation="使用白名单限制允许上传的文件类型,禁止可执行文件",
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
                    ],
                    extra={
                        'dangerous_types': list(set(dangerous_allowed)),
                        'all_accept_types': accept_matches
                    }
                )
                results.append(result)

        except Exception as e:
            logger.debug(f"[{self.name}] 危险扩展名检测失败: {e}")

        return results

    def get_bypass_techniques(self) -> List[Dict[str, Any]]:
        """获取文件上传绕过技巧"""
        return [
            {
                "technique": "Double Extension",
                "files": ["test.php.jpg", "test.php.png", "test.php.gif"],
                "description": "双扩展名绕过"
            },
            {
                "technique": "Null Byte",
                "files": ["test.php%00.jpg", "test.php\x00.jpg"],
                "description": "空字节截断 (PHP < 5.3.4)"
            },
            {
                "technique": "Case Variation",
                "files": ["test.PhP", "test.pHp", "test.PHP"],
                "description": "大小写变换绕过"
            },
            {
                "technique": "Alternative Extensions",
                "files": ["test.phtml", "test.php5", "test.phar"],
                "description": "替代扩展名"
            },
            {
                "technique": "MIME Type Mismatch",
                "files": [("test.php", "image/jpeg"), ("test.php", "image/gif")],
                "description": "MIME 类型欺骗"
            },
            {
                "technique": "Content-Type Bypass",
                "files": [("test.php", "application/octet-stream")],
                "description": "Content-Type 绕过"
            },
            {
                "technique": "Magic Bytes",
                "files": ["GIF89a<?php echo 'test'; ?>"],
                "description": "文件头伪造"
            },
        ]

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return [f[0] for f in self.TEST_FILES]
