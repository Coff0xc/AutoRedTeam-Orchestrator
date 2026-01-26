"""
CSRF (跨站请求伪造) 检测器

检测 CSRF 防护缺失或配置问题
"""

from typing import List, Optional, Dict, Any, Set
import re
import logging
from urllib.parse import urlparse, parse_qs

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType
from ..factory import register_detector

logger = logging.getLogger(__name__)


@register_detector('csrf')
class CSRFDetector(BaseDetector):
    """CSRF (跨站请求伪造) 检测器

    检测 CSRF 防护问题:
    - 缺失 CSRF Token
    - Token 验证绕过
    - Referer/Origin 检查缺失
    - SameSite Cookie 配置

    使用示例:
        detector = CSRFDetector()
        results = detector.detect("https://example.com/transfer", data={"amount": "100"})
    """

    name = 'csrf'
    description = 'CSRF 跨站请求伪造检测器'
    vuln_type = 'csrf'
    severity = Severity.MEDIUM
    detector_type = DetectorType.MISC
    version = '1.0.0'

    # CSRF Token 参数名
    TOKEN_NAMES = [
        'csrf', 'csrf_token', 'csrftoken', 'csrfmiddlewaretoken',
        '_csrf', '_token', 'token', 'authenticity_token',
        'xsrf', 'xsrf_token', '_xsrf', '__requestverificationtoken',
        'antiforgery', 'anti_csrf_token', 'security_token',
    ]

    # CSRF Token 头部名
    TOKEN_HEADERS = [
        'X-CSRF-Token',
        'X-XSRF-Token',
        'X-Requested-With',
    ]

    # 敏感操作关键词
    SENSITIVE_ACTIONS = [
        'transfer', 'payment', 'pay', 'withdraw',
        'delete', 'remove', 'update', 'edit', 'modify',
        'create', 'add', 'new', 'submit',
        'change', 'reset', 'password', 'email',
        'profile', 'settings', 'preferences',
        'admin', 'manage', 'config',
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - check_token: 是否检测 Token
                - check_referer: 是否检测 Referer
                - check_samesite: 是否检测 SameSite
        """
        super().__init__(config)

        self.check_token = self.config.get('check_token', True)
        self.check_referer = self.config.get('check_referer', True)
        self.check_samesite = self.config.get('check_samesite', True)

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测 CSRF 漏洞

        Args:
            url: 目标 URL
            **kwargs:
                data: POST 数据
                method: HTTP 方法
                headers: 请求头
                html_content: 表单 HTML 内容

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        data = kwargs.get('data', {})
        method = kwargs.get('method', 'POST').upper()
        headers = kwargs.get('headers', {})
        html_content = kwargs.get('html_content', '')

        # 只检测状态修改操作
        if method not in ('POST', 'PUT', 'DELETE', 'PATCH'):
            self._log_detection_end(url, results)
            return results

        # 检查是否是敏感操作
        if not self._is_sensitive_action(url, data):
            logger.info("非敏感操作，跳过 CSRF 检测")
            self._log_detection_end(url, results)
            return results

        # 检测 Token 缺失
        if self.check_token:
            token_result = self._check_csrf_token(url, data, headers, html_content)
            if token_result:
                results.append(token_result)

        # 检测 Token 验证绕过
        if self.check_token and not results:
            bypass_results = self._test_token_bypass(url, data, method, headers)
            results.extend(bypass_results)

        # 检测 Referer/Origin 验证
        if self.check_referer:
            referer_result = self._check_referer_validation(url, data, method, headers)
            if referer_result:
                results.append(referer_result)

        # 检测 SameSite Cookie
        if self.check_samesite:
            samesite_result = self._check_samesite_cookie(url, headers)
            if samesite_result:
                results.append(samesite_result)

        self._log_detection_end(url, results)
        return results

    def _check_csrf_token(
        self,
        url: str,
        data: Dict[str, str],
        headers: Dict[str, str],
        html_content: str
    ) -> Optional[DetectionResult]:
        """检测 CSRF Token 是否存在

        Args:
            url: 目标 URL
            data: POST 数据
            headers: 请求头
            html_content: HTML 内容

        Returns:
            检测结果或 None
        """
        # 检查表单数据中的 Token
        has_token_in_data = any(
            token_name in data_key.lower()
            for data_key in data.keys()
            for token_name in self.TOKEN_NAMES
        )

        # 检查请求头中的 Token
        has_token_in_headers = any(
            token_header.lower() in [h.lower() for h in headers.keys()]
            for token_header in self.TOKEN_HEADERS
        )

        # 检查 HTML 中的隐藏 Token 字段
        has_token_in_html = False
        if html_content:
            for token_name in self.TOKEN_NAMES:
                pattern = rf'<input[^>]+name=["\']?{token_name}["\']?[^>]*>'
                if re.search(pattern, html_content, re.IGNORECASE):
                    has_token_in_html = True
                    break

        if not (has_token_in_data or has_token_in_headers or has_token_in_html):
            return self._create_result(
                url=url,
                vulnerable=True,
                payload=None,
                evidence="未检测到 CSRF Token 保护",
                confidence=0.80,
                verified=False,
                remediation="为所有状态修改操作添加 CSRF Token 保护",
                references=[
                    "https://owasp.org/www-community/attacks/csrf"
                ],
                extra={'csrf_type': 'missing_token'}
            )

        return None

    def _test_token_bypass(
        self,
        url: str,
        data: Dict[str, str],
        method: str,
        headers: Dict[str, str]
    ) -> List[DetectionResult]:
        """测试 Token 验证绕过

        Args:
            url: 目标 URL
            data: POST 数据
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果列表
        """
        results = []

        # 获取基线响应（正常请求）
        try:
            baseline = self.http_client.request(method, url, data=data, headers=headers)
        except (ConnectionError, TimeoutError, OSError):
            return results

        # 测试 1: 移除 Token
        test_data = {k: v for k, v in data.items()
                     if not any(tn in k.lower() for tn in self.TOKEN_NAMES)}

        if len(test_data) < len(data):
            try:
                response = self.http_client.request(method, url, data=test_data, headers=headers)
                if self._is_request_accepted(response, baseline):
                    results.append(self._create_result(
                        url=url,
                        vulnerable=True,
                        payload="移除 CSRF Token",
                        evidence="移除 Token 后请求仍被接受",
                        confidence=0.90,
                        verified=True,
                        remediation="确保服务端验证 CSRF Token 的存在性",
                        extra={'csrf_type': 'token_removal'}
                    ))
            except Exception as e:
                logger.debug(f"Token 移除测试失败: {e}")

        # 测试 2: 空 Token
        for key in data.keys():
            if any(tn in key.lower() for tn in self.TOKEN_NAMES):
                test_data = data.copy()
                test_data[key] = ''
                try:
                    response = self.http_client.request(method, url, data=test_data, headers=headers)
                    if self._is_request_accepted(response, baseline):
                        results.append(self._create_result(
                            url=url,
                            vulnerable=True,
                            payload="空 CSRF Token",
                            evidence="空 Token 请求被接受",
                            confidence=0.90,
                            verified=True,
                            remediation="验证 Token 不能为空",
                            extra={'csrf_type': 'empty_token'}
                        ))
                except Exception as e:
                    logger.debug(f"空 Token 测试失败: {e}")

        # 测试 3: 错误的 Token
        for key in data.keys():
            if any(tn in key.lower() for tn in self.TOKEN_NAMES):
                test_data = data.copy()
                test_data[key] = 'invalid_token_12345'
                try:
                    response = self.http_client.request(method, url, data=test_data, headers=headers)
                    if self._is_request_accepted(response, baseline):
                        results.append(self._create_result(
                            url=url,
                            vulnerable=True,
                            payload="无效 CSRF Token",
                            evidence="无效 Token 请求被接受",
                            confidence=0.95,
                            verified=True,
                            remediation="正确验证 CSRF Token 的有效性",
                            extra={'csrf_type': 'invalid_token'}
                        ))
                except Exception as e:
                    logger.debug(f"无效 Token 测试失败: {e}")

        return results

    def _check_referer_validation(
        self,
        url: str,
        data: Dict[str, str],
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """检测 Referer 验证

        Args:
            url: 目标 URL
            data: POST 数据
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        # 测试恶意 Referer
        test_headers = headers.copy()
        test_headers['Referer'] = 'https://evil.com/attack'
        test_headers['Origin'] = 'https://evil.com'

        try:
            response = self.http_client.request(method, url, data=data, headers=test_headers)

            if response.status_code == 200:
                return self._create_result(
                    url=url,
                    vulnerable=True,
                    payload="Referer: https://evil.com",
                    evidence="服务端未验证 Referer/Origin 头",
                    confidence=0.75,
                    verified=True,
                    remediation="验证 Referer 和 Origin 头部",
                    extra={'csrf_type': 'referer_bypass'}
                )

        except Exception as e:
            logger.debug(f"Referer 验证测试失败: {e}")

        return None

    def _check_samesite_cookie(
        self,
        url: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """检测 SameSite Cookie 配置

        Args:
            url: 目标 URL
            headers: 请求头

        Returns:
            检测结果或 None
        """
        try:
            response = self.http_client.get(url, headers=headers)
            set_cookie = response.headers.get('Set-Cookie', '')

            # 检查会话 Cookie
            session_patterns = ['session', 'sid', 'auth', 'token']

            if any(p in set_cookie.lower() for p in session_patterns):
                if 'samesite' not in set_cookie.lower():
                    return self._create_result(
                        url=url,
                        vulnerable=True,
                        payload=None,
                        evidence="会话 Cookie 缺少 SameSite 属性",
                        confidence=0.70,
                        verified=True,
                        remediation="为会话 Cookie 设置 SameSite=Strict 或 SameSite=Lax",
                        extra={'csrf_type': 'missing_samesite'}
                    )
                elif 'samesite=none' in set_cookie.lower():
                    return self._create_result(
                        url=url,
                        vulnerable=True,
                        payload=None,
                        evidence="会话 Cookie SameSite=None 允许跨站发送",
                        confidence=0.65,
                        verified=True,
                        remediation="除非必要，避免使用 SameSite=None",
                        extra={'csrf_type': 'samesite_none'}
                    )

        except Exception as e:
            logger.debug(f"SameSite 检测失败: {e}")

        return None

    def _is_sensitive_action(self, url: str, data: Dict[str, str]) -> bool:
        """判断是否是敏感操作"""
        url_lower = url.lower()
        data_str = str(data).lower()

        return any(
            action in url_lower or action in data_str
            for action in self.SENSITIVE_ACTIONS
        )

    def _is_request_accepted(self, response: Any, baseline: Any) -> bool:
        """判断请求是否被接受"""
        # 与基线状态码相同
        if response.status_code == baseline.status_code:
            return True

        # 成功状态码
        if response.status_code in (200, 201, 204, 302, 303):
            return True

        return False

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return ['移除 Token', '空 Token', '无效 Token', '恶意 Referer']
