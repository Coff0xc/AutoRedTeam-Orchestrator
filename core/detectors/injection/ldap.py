"""
LDAP 注入检测器

检测 LDAP 查询注入漏洞
"""

from typing import List, Optional, Dict, Any
import re
import logging
from urllib.parse import urlparse, parse_qs

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType
from ..factory import register_detector
from ..payloads import get_payloads, PayloadCategory

logger = logging.getLogger(__name__)


@register_detector('ldap')
class LDAPiDetector(BaseDetector):
    """LDAP 注入检测器

    检测 LDAP 查询注入漏洞，可能导致认证绕过或信息泄露

    使用示例:
        detector = LDAPiDetector()
        results = detector.detect("https://example.com/login", params={"user": "admin"})
    """

    name = 'ldap'
    description = 'LDAP 注入漏洞检测器'
    vuln_type = 'ldap_injection'
    severity = Severity.HIGH
    detector_type = DetectorType.INJECTION
    version = '1.0.0'

    # LDAP 错误模式
    ERROR_PATTERNS = [
        r'ldap_search',
        r'ldap_bind',
        r'invalid DN syntax',
        r'Bad search filter',
        r'Invalid filter',
        r'LDAP.*error',
        r'LDAP.*exception',
        r'javax\.naming\.directory',
        r'javax\.naming\.ldap',
        r'com\.sun\.jndi\.ldap',
        r'LdapException',
        r'Invalid LDAP filter',
        r'filter error',
        r'DSA is unwilling to perform',
    ]

    # 认证绕过成功的标志
    AUTH_BYPASS_PATTERNS = [
        r'welcome',
        r'dashboard',
        r'logged in',
        r'login successful',
        r'authentication successful',
        r'session_id',
        r'authenticated',
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
        """
        super().__init__(config)

        # 加载 payload
        self.payloads = get_payloads(PayloadCategory.LDAP)

        # 编译模式
        self._error_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.ERROR_PATTERNS
        ]
        self._auth_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.AUTH_BYPASS_PATTERNS
        ]

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测 LDAP 注入漏洞

        Args:
            url: 目标 URL
            **kwargs:
                params: GET 参数字典
                data: POST 数据字典
                method: HTTP 方法

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        params = kwargs.get('params', {})
        data = kwargs.get('data', {})
        method = kwargs.get('method', 'GET').upper()
        headers = kwargs.get('headers', {})

        # 解析 URL 参数
        if not params:
            parsed = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # 测试参数
        test_params = params if method == 'GET' else data

        for param_name, original_value in test_params.items():
            # 获取基线响应
            baseline = self._get_baseline(url, test_params, method, headers)

            for payload in self.payloads:
                test_value = str(original_value) + payload
                test_data = test_params.copy()
                test_data[param_name] = test_value

                try:
                    if method == 'GET':
                        response = self.http_client.get(url, params=test_data, headers=headers)
                    else:
                        response = self.http_client.post(url, data=test_data, headers=headers)

                    # 检查错误信息
                    error_match = self._check_error_response(response.text)
                    if error_match:
                        results.append(self._create_result(
                            url=url,
                            vulnerable=True,
                            param=param_name,
                            payload=payload,
                            evidence=error_match,
                            confidence=0.85,
                            verified=True,
                            remediation="对用户输入进行严格过滤，转义 LDAP 特殊字符",
                            references=[
                                "https://owasp.org/www-community/attacks/LDAP_Injection"
                            ],
                            extra={'injection_type': 'error-based'}
                        ))
                        break

                    # 检查认证绕过
                    if baseline and self._check_auth_bypass(baseline.text, response.text):
                        results.append(self._create_result(
                            url=url,
                            vulnerable=True,
                            param=param_name,
                            payload=payload,
                            evidence="检测到可能的认证绕过",
                            confidence=0.75,
                            verified=False,
                            remediation="对用户输入进行严格过滤，转义 LDAP 特殊字符",
                            extra={'injection_type': 'auth-bypass'}
                        ))
                        break

                except Exception as e:
                    logger.debug(f"LDAP 注入检测失败: {e}")

        self._log_detection_end(url, results)
        return results

    def _get_baseline(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        headers: Dict[str, str]
    ) -> Optional[Any]:
        """获取基线响应"""
        try:
            if method == 'GET':
                return self.http_client.get(url, params=params, headers=headers)
            else:
                return self.http_client.post(url, data=params, headers=headers)
        except (ConnectionError, TimeoutError, OSError):
            return None

    def _check_error_response(self, response_text: str) -> Optional[str]:
        """检查错误响应"""
        for pattern in self._error_patterns:
            match = pattern.search(response_text)
            if match:
                start = max(0, match.start() - 30)
                end = min(len(response_text), match.end() + 30)
                return response_text[start:end]
        return None

    def _check_auth_bypass(self, baseline_text: str, response_text: str) -> bool:
        """检查认证绕过"""
        # 检查是否有认证成功的标志
        for pattern in self._auth_patterns:
            if pattern.search(response_text) and not pattern.search(baseline_text):
                return True

        # 检查响应长度变化
        if len(response_text) > len(baseline_text) * 1.5:
            return True

        return False

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return self.payloads
