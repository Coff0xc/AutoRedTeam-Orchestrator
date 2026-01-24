"""
安全头检测器

检测 HTTP 安全响应头的配置问题
"""

from typing import List, Optional, Dict, Any, Tuple
import re
import logging
from urllib.parse import urlparse

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType
from ..factory import register_detector

logger = logging.getLogger(__name__)


@register_detector('headers')
class SecurityHeadersDetector(BaseDetector):
    """安全头检测器

    检测 HTTP 安全响应头配置:
    - Content-Security-Policy (CSP)
    - X-Frame-Options
    - X-Content-Type-Options
    - X-XSS-Protection
    - Strict-Transport-Security (HSTS)
    - Referrer-Policy
    - Permissions-Policy

    使用示例:
        detector = SecurityHeadersDetector()
        results = detector.detect("https://example.com")
    """

    name = 'headers'
    description = 'HTTP 安全头检测器'
    vuln_type = 'security_headers'
    severity = Severity.LOW
    detector_type = DetectorType.MISC
    version = '1.0.0'

    # 安全头定义
    SECURITY_HEADERS = {
        'Content-Security-Policy': {
            'severity': Severity.MEDIUM,
            'description': '内容安全策略',
            'remediation': "添加 CSP 头防止 XSS 和数据注入攻击",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
        },
        'X-Frame-Options': {
            'severity': Severity.MEDIUM,
            'description': '点击劫持防护',
            'remediation': "添加 X-Frame-Options: DENY 或 SAMEORIGIN",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'
        },
        'X-Content-Type-Options': {
            'severity': Severity.LOW,
            'description': 'MIME 类型嗅探防护',
            'remediation': "添加 X-Content-Type-Options: nosniff",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'
        },
        'Strict-Transport-Security': {
            'severity': Severity.MEDIUM,
            'description': 'HTTP 严格传输安全',
            'remediation': "添加 HSTS 头强制 HTTPS 连接",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
        },
        'Referrer-Policy': {
            'severity': Severity.LOW,
            'description': 'Referrer 信息控制',
            'remediation': "添加 Referrer-Policy 控制 Referrer 信息泄露",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'
        },
        'Permissions-Policy': {
            'severity': Severity.LOW,
            'description': '浏览器功能权限控制',
            'remediation': "添加 Permissions-Policy 限制浏览器功能",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'
        },
        'X-XSS-Protection': {
            'severity': Severity.INFO,
            'description': 'XSS 过滤器 (已弃用)',
            'remediation': "使用 CSP 替代 X-XSS-Protection",
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection'
        }
    }

    # CSP 危险指令
    CSP_DANGEROUS_DIRECTIVES = [
        "unsafe-inline",
        "unsafe-eval",
        "data:",
        "*",
    ]

    # 需要移除的不安全头
    INSECURE_HEADERS = [
        'Server',
        'X-Powered-By',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - check_missing: 是否检测缺失的头
                - check_misconfigured: 是否检测配置错误
                - check_insecure: 是否检测不安全的头
                - required_headers: 必须的头列表
        """
        super().__init__(config)

        self.check_missing = self.config.get('check_missing', True)
        self.check_misconfigured = self.config.get('check_misconfigured', True)
        self.check_insecure = self.config.get('check_insecure', True)

        # 必须的头（可自定义）
        self.required_headers = self.config.get('required_headers', [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
        ])

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测安全头配置

        Args:
            url: 目标 URL
            **kwargs:
                headers: 请求头

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        headers = kwargs.get('headers', {})
        parsed = urlparse(url)
        is_https = parsed.scheme == 'https'

        try:
            response = self.http_client.get(url, headers=headers)
        except Exception as e:
            logger.warning(f"无法获取响应: {e}")
            self._log_detection_end(url, results)
            return results

        response_headers = {k.lower(): v for k, v in response.headers.items()}

        # 检测缺失的安全头
        if self.check_missing:
            missing_results = self._check_missing_headers(url, response_headers, is_https)
            results.extend(missing_results)

        # 检测配置错误的头
        if self.check_misconfigured:
            misconfig_results = self._check_misconfigured_headers(url, response_headers)
            results.extend(misconfig_results)

        # 检测不安全的信息泄露头
        if self.check_insecure:
            insecure_results = self._check_insecure_headers(url, response_headers)
            results.extend(insecure_results)

        self._log_detection_end(url, results)
        return results

    def _check_missing_headers(
        self,
        url: str,
        response_headers: Dict[str, str],
        is_https: bool
    ) -> List[DetectionResult]:
        """检测缺失的安全头

        Args:
            url: 目标 URL
            response_headers: 响应头
            is_https: 是否是 HTTPS

        Returns:
            检测结果列表
        """
        results = []

        for header_name in self.required_headers:
            header_lower = header_name.lower()

            # HSTS 只对 HTTPS 有效
            if header_name == 'Strict-Transport-Security' and not is_https:
                continue

            if header_lower not in response_headers:
                header_info = self.SECURITY_HEADERS.get(header_name, {})
                results.append(self._create_result(
                    url=url,
                    vulnerable=True,
                    param=header_name,
                    payload=None,
                    evidence=f"缺少安全头: {header_name}",
                    confidence=0.95,
                    verified=True,
                    remediation=header_info.get('remediation', f"添加 {header_name} 头"),
                    references=[header_info.get('reference', '')] if header_info.get('reference') else [],
                    extra={
                        'header_type': 'missing',
                        'header_name': header_name,
                        'description': header_info.get('description', '')
                    }
                ))
                # 使用头定义的严重程度
                if header_info.get('severity'):
                    results[-1].severity = header_info['severity']

        return results

    def _check_misconfigured_headers(
        self,
        url: str,
        response_headers: Dict[str, str]
    ) -> List[DetectionResult]:
        """检测配置错误的安全头

        Args:
            url: 目标 URL
            response_headers: 响应头

        Returns:
            检测结果列表
        """
        results = []

        # 检查 CSP 配置
        csp = response_headers.get('content-security-policy', '')
        if csp:
            csp_issues = self._analyze_csp(csp)
            for issue in csp_issues:
                results.append(self._create_result(
                    url=url,
                    vulnerable=True,
                    param='Content-Security-Policy',
                    payload=None,
                    evidence=f"CSP 配置问题: {issue}",
                    confidence=0.85,
                    verified=True,
                    remediation="移除 CSP 中的危险指令",
                    extra={
                        'header_type': 'misconfigured',
                        'header_name': 'Content-Security-Policy',
                        'issue': issue
                    }
                ))

        # 检查 X-Frame-Options 配置
        xfo = response_headers.get('x-frame-options', '')
        if xfo and xfo.upper() not in ('DENY', 'SAMEORIGIN'):
            results.append(self._create_result(
                url=url,
                vulnerable=True,
                param='X-Frame-Options',
                payload=None,
                evidence=f"X-Frame-Options 配置不当: {xfo}",
                confidence=0.80,
                verified=True,
                remediation="使用 DENY 或 SAMEORIGIN",
                extra={
                    'header_type': 'misconfigured',
                    'header_name': 'X-Frame-Options',
                    'value': xfo
                }
            ))

        # 检查 HSTS 配置
        hsts = response_headers.get('strict-transport-security', '')
        if hsts:
            hsts_issues = self._analyze_hsts(hsts)
            for issue in hsts_issues:
                results.append(self._create_result(
                    url=url,
                    vulnerable=True,
                    param='Strict-Transport-Security',
                    payload=None,
                    evidence=f"HSTS 配置问题: {issue}",
                    confidence=0.75,
                    verified=True,
                    remediation="增加 max-age 值，考虑添加 includeSubDomains 和 preload",
                    extra={
                        'header_type': 'misconfigured',
                        'header_name': 'Strict-Transport-Security',
                        'issue': issue
                    }
                ))

        return results

    def _check_insecure_headers(
        self,
        url: str,
        response_headers: Dict[str, str]
    ) -> List[DetectionResult]:
        """检测不安全的信息泄露头

        Args:
            url: 目标 URL
            response_headers: 响应头

        Returns:
            检测结果列表
        """
        results = []

        for header_name in self.INSECURE_HEADERS:
            header_lower = header_name.lower()

            if header_lower in response_headers:
                value = response_headers[header_lower]
                results.append(self._create_result(
                    url=url,
                    vulnerable=True,
                    param=header_name,
                    payload=None,
                    evidence=f"信息泄露头: {header_name}: {value}",
                    confidence=0.90,
                    verified=True,
                    remediation=f"移除或隐藏 {header_name} 头",
                    extra={
                        'header_type': 'insecure',
                        'header_name': header_name,
                        'value': value
                    }
                ))
                results[-1].severity = Severity.INFO

        return results

    def _analyze_csp(self, csp: str) -> List[str]:
        """分析 CSP 配置

        Args:
            csp: CSP 头值

        Returns:
            问题列表
        """
        issues = []

        for directive in self.CSP_DANGEROUS_DIRECTIVES:
            if directive in csp.lower():
                issues.append(f"包含危险指令 '{directive}'")

        # 检查是否过于宽松
        if 'default-src *' in csp.lower():
            issues.append("default-src 过于宽松")

        # 检查是否缺少关键指令
        if 'script-src' not in csp.lower() and 'default-src' not in csp.lower():
            issues.append("缺少 script-src 指令")

        return issues

    def _analyze_hsts(self, hsts: str) -> List[str]:
        """分析 HSTS 配置

        Args:
            hsts: HSTS 头值

        Returns:
            问题列表
        """
        issues = []

        # 检查 max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # 小于一年
                issues.append(f"max-age 过短 ({max_age} 秒，建议至少一年)")
        else:
            issues.append("缺少 max-age 指令")

        return issues

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return []

    def get_score(self, url: str, **kwargs) -> Dict[str, Any]:
        """获取安全头评分

        Args:
            url: 目标 URL
            **kwargs: 额外参数

        Returns:
            评分结果
        """
        results = self.detect(url, **kwargs)

        total_headers = len(self.SECURITY_HEADERS)
        missing_count = sum(1 for r in results if r.extra.get('header_type') == 'missing')
        misconfig_count = sum(1 for r in results if r.extra.get('header_type') == 'misconfigured')

        score = max(0, 100 - (missing_count * 10) - (misconfig_count * 5))

        return {
            'score': score,
            'grade': self._score_to_grade(score),
            'total_headers': total_headers,
            'missing_headers': missing_count,
            'misconfigured_headers': misconfig_count,
            'details': results
        }

    def _score_to_grade(self, score: int) -> str:
        """分数转等级"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
