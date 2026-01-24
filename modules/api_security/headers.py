#!/usr/bin/env python3
"""
安全头测试模块

提供全面的HTTP安全头检测和评分功能，包括:
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
- 安全头评分和对比

作者: AutoRedTeam
版本: 3.0.0
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .base import (
    APITestResult,
    APIVulnType,
    BaseAPITester,
    Severity,
)

logger = logging.getLogger(__name__)


@dataclass
class SecurityHeader:
    """安全头信息"""
    name: str
    value: str
    present: bool
    secure: bool
    issues: List[str] = field(default_factory=list)
    score: int = 0
    max_score: int = 10
    recommendations: List[str] = field(default_factory=list)


@dataclass
class SecurityScore:
    """安全评分"""
    total_score: int
    max_score: int
    grade: str
    headers: Dict[str, SecurityHeader] = field(default_factory=dict)
    missing_headers: List[str] = field(default_factory=list)
    weak_headers: List[str] = field(default_factory=list)


class SecurityHeadersTester(BaseAPITester):
    """
    安全头测试器

    检测和评估HTTP安全头的配置。

    使用示例:
        tester = SecurityHeadersTester('https://example.com')
        results = tester.test()
        score = tester.get_security_score()
    """

    name = 'security_headers'
    description = 'HTTP安全头测试器'
    version = '3.0.0'

    # 安全头定义和权重
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'weight': 15,
            'required': True,
            'aliases': ['strict-transport-security'],
        },
        'Content-Security-Policy': {
            'weight': 20,
            'required': True,
            'aliases': ['content-security-policy'],
        },
        'X-Frame-Options': {
            'weight': 10,
            'required': True,
            'aliases': ['x-frame-options'],
        },
        'X-Content-Type-Options': {
            'weight': 10,
            'required': True,
            'aliases': ['x-content-type-options'],
        },
        'X-XSS-Protection': {
            'weight': 5,
            'required': False,  # 已被CSP替代
            'aliases': ['x-xss-protection'],
        },
        'Referrer-Policy': {
            'weight': 10,
            'required': True,
            'aliases': ['referrer-policy'],
        },
        'Permissions-Policy': {
            'weight': 10,
            'required': False,
            'aliases': ['permissions-policy', 'feature-policy'],
        },
        'Cross-Origin-Opener-Policy': {
            'weight': 5,
            'required': False,
            'aliases': ['cross-origin-opener-policy'],
        },
        'Cross-Origin-Resource-Policy': {
            'weight': 5,
            'required': False,
            'aliases': ['cross-origin-resource-policy'],
        },
        'Cross-Origin-Embedder-Policy': {
            'weight': 5,
            'required': False,
            'aliases': ['cross-origin-embedder-policy'],
        },
    }

    # 不安全的CSP指令
    INSECURE_CSP_DIRECTIVES = [
        "'unsafe-inline'",
        "'unsafe-eval'",
        "data:",
        "blob:",
        "*",
    ]

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        """
        初始化安全头测试器

        Args:
            target: 目标URL
            config: 可选配置
        """
        super().__init__(target, config)
        self._response_headers: Dict[str, str] = {}
        self._security_score: Optional[SecurityScore] = None

    def test(self) -> List[APITestResult]:
        """执行所有安全头测试"""
        self.clear_results()

        # 获取响应头
        if not self._fetch_headers():
            self._create_result(
                vulnerable=False,
                severity=Severity.INFO,
                title='无法获取响应头',
                description=f'无法连接到目标: {self.target}'
            )
            return self._results

        # 测试各个安全头
        self.test_hsts()
        self.test_csp()
        self.test_x_frame_options()
        self.test_x_content_type_options()
        self.test_referrer_policy()
        self.test_permissions_policy()
        self.test_cross_origin_policies()

        # 计算整体评分
        self._calculate_security_score()

        return self._results

    def _fetch_headers(self) -> bool:
        """获取目标响应头"""
        try:
            client = self._get_http_client()
            response = client.get(self.target, timeout=self.timeout)

            # 存储响应头（小写键名）
            self._response_headers = {
                k.lower(): v for k, v in response.headers.items()
            }

            return True

        except Exception as e:
            logger.error(f'获取响应头失败: {e}')
            return False

    def test_hsts(self) -> Optional[APITestResult]:
        """
        测试HSTS (HTTP Strict Transport Security)

        检测项:
            - 是否存在
            - max-age值是否足够
            - 是否包含includeSubDomains
            - 是否包含preload

        Returns:
            测试结果或None
        """
        header_value = self._get_header('strict-transport-security')

        if not header_value:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.HEADERS_MISSING_HSTS,
                severity=Severity.HIGH,
                title='缺少HSTS安全头',
                description=(
                    '未设置Strict-Transport-Security头，'
                    '可能遭受SSL剥离攻击。'
                ),
                evidence={'header': 'Strict-Transport-Security', 'value': None},
                remediation=(
                    '添加HSTS头:\n'
                    'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
                )
            )
            return result

        # 解析HSTS参数
        issues = []
        max_age = self._extract_max_age(header_value)

        if max_age is None:
            issues.append('缺少max-age参数')
        elif max_age < 31536000:  # 1年
            issues.append(f'max-age过短: {max_age}秒（建议至少1年）')

        if 'includesubdomains' not in header_value.lower():
            issues.append('未包含includeSubDomains')

        if issues:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.HEADERS_WEAK_HSTS,
                severity=Severity.MEDIUM,
                title='HSTS配置不完善',
                description=f'HSTS存在以下问题: {"; ".join(issues)}',
                evidence={
                    'header': 'Strict-Transport-Security',
                    'value': header_value,
                    'issues': issues
                },
                remediation=(
                    '建议配置:\n'
                    'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
                )
            )
            return result

        return None

    def test_csp(self) -> Optional[APITestResult]:
        """
        测试CSP (Content Security Policy)

        检测项:
            - 是否存在
            - 是否包含unsafe-inline/unsafe-eval
            - default-src配置
            - script-src配置

        Returns:
            测试结果或None
        """
        header_value = self._get_header('content-security-policy')

        if not header_value:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.HEADERS_MISSING_CSP,
                severity=Severity.HIGH,
                title='缺少CSP安全头',
                description=(
                    '未设置Content-Security-Policy头，'
                    '无法有效防护XSS攻击。'
                ),
                evidence={'header': 'Content-Security-Policy', 'value': None},
                remediation=(
                    "添加CSP头，最小配置:\n"
                    "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'"
                )
            )
            return result

        # 检查不安全指令
        issues = []

        for directive in self.INSECURE_CSP_DIRECTIVES:
            if directive in header_value.lower():
                issues.append(f'包含不安全指令: {directive}')

        # 检查是否有default-src
        if 'default-src' not in header_value.lower():
            issues.append('缺少default-src指令')

        # 检查report-uri/report-to
        if 'report' not in header_value.lower():
            issues.append('未配置CSP报告机制')

        if issues:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.HEADERS_INSECURE_CSP,
                severity=Severity.MEDIUM,
                title='CSP配置存在安全问题',
                description=f'CSP存在以下问题: {"; ".join(issues)}',
                evidence={
                    'header': 'Content-Security-Policy',
                    'value': header_value[:200] + '...' if len(header_value) > 200 else header_value,
                    'issues': issues
                },
                remediation=(
                    "1. 移除 'unsafe-inline' 和 'unsafe-eval'\n"
                    "2. 使用nonce或hash替代内联脚本\n"
                    "3. 配置report-uri收集违规报告\n"
                    "4. 使用CSP Evaluator工具检查配置"
                )
            )
            return result

        return None

    def test_x_frame_options(self) -> Optional[APITestResult]:
        """
        测试X-Frame-Options

        Returns:
            测试结果或None
        """
        header_value = self._get_header('x-frame-options')

        if not header_value:
            # 检查是否有CSP frame-ancestors
            csp = self._get_header('content-security-policy')
            if csp and 'frame-ancestors' in csp.lower():
                return None  # CSP frame-ancestors替代

            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.HEADERS_MISSING_X_FRAME,
                severity=Severity.MEDIUM,
                title='缺少X-Frame-Options头',
                description=(
                    '未设置X-Frame-Options头，'
                    '可能遭受点击劫持攻击。'
                ),
                evidence={'header': 'X-Frame-Options', 'value': None},
                remediation='添加: X-Frame-Options: DENY 或 SAMEORIGIN'
            )
            return result

        # 验证值
        valid_values = ['deny', 'sameorigin']
        if header_value.lower() not in valid_values and not header_value.lower().startswith('allow-from'):
            self._create_result(
                vulnerable=False,
                severity=Severity.INFO,
                title='X-Frame-Options值非标准',
                description=f'X-Frame-Options值为: {header_value}',
                evidence={'value': header_value},
                remediation='建议使用: DENY 或 SAMEORIGIN'
            )

        return None

    def test_x_content_type_options(self) -> Optional[APITestResult]:
        """
        测试X-Content-Type-Options

        Returns:
            测试结果或None
        """
        header_value = self._get_header('x-content-type-options')

        if not header_value:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.HEADERS_MISSING_X_CONTENT_TYPE,
                severity=Severity.LOW,
                title='缺少X-Content-Type-Options头',
                description=(
                    '未设置X-Content-Type-Options头，'
                    '可能遭受MIME类型嗅探攻击。'
                ),
                evidence={'header': 'X-Content-Type-Options', 'value': None},
                remediation='添加: X-Content-Type-Options: nosniff'
            )
            return result

        if header_value.lower() != 'nosniff':
            self._create_result(
                vulnerable=False,
                severity=Severity.INFO,
                title='X-Content-Type-Options值不正确',
                description=f'X-Content-Type-Options值为: {header_value}',
                evidence={'value': header_value},
                remediation='应设置为: nosniff'
            )

        return None

    def test_referrer_policy(self) -> Optional[APITestResult]:
        """
        测试Referrer-Policy

        Returns:
            测试结果或None
        """
        header_value = self._get_header('referrer-policy')

        if not header_value:
            self._create_result(
                vulnerable=False,
                severity=Severity.INFO,
                title='缺少Referrer-Policy头',
                description='未设置Referrer-Policy头，使用浏览器默认策略。',
                evidence={'header': 'Referrer-Policy', 'value': None},
                remediation='添加: Referrer-Policy: strict-origin-when-cross-origin'
            )
            return None

        # 检查不安全策略
        unsafe_policies = ['unsafe-url', 'no-referrer-when-downgrade']

        if header_value.lower() in unsafe_policies:
            self._create_result(
                vulnerable=True,
                severity=Severity.LOW,
                title='Referrer-Policy配置不安全',
                description=f'Referrer-Policy值为: {header_value}，可能泄露敏感信息。',
                evidence={'value': header_value},
                remediation='建议使用: strict-origin-when-cross-origin 或 no-referrer'
            )

        return None

    def test_permissions_policy(self) -> Optional[APITestResult]:
        """
        测试Permissions-Policy (原Feature-Policy)

        Returns:
            测试结果或None
        """
        header_value = self._get_header('permissions-policy')

        if not header_value:
            # 检查旧版Feature-Policy
            header_value = self._get_header('feature-policy')

        if not header_value:
            self._create_result(
                vulnerable=False,
                severity=Severity.INFO,
                title='缺少Permissions-Policy头',
                description='未设置Permissions-Policy头，未限制浏览器功能。',
                evidence={'header': 'Permissions-Policy', 'value': None},
                remediation=(
                    '添加Permissions-Policy限制敏感功能:\n'
                    'Permissions-Policy: geolocation=(), camera=(), microphone=()'
                )
            )

        return None

    def test_cross_origin_policies(self) -> Optional[APITestResult]:
        """
        测试跨域隔离相关策略

        Returns:
            测试结果或None
        """
        coop = self._get_header('cross-origin-opener-policy')
        coep = self._get_header('cross-origin-embedder-policy')
        corp = self._get_header('cross-origin-resource-policy')

        missing = []
        if not coop:
            missing.append('Cross-Origin-Opener-Policy')
        if not coep:
            missing.append('Cross-Origin-Embedder-Policy')
        if not corp:
            missing.append('Cross-Origin-Resource-Policy')

        if missing:
            self._create_result(
                vulnerable=False,
                severity=Severity.INFO,
                title='缺少跨域隔离策略',
                description=f'缺少以下跨域策略头: {", ".join(missing)}',
                evidence={'missing': missing},
                remediation=(
                    '添加跨域隔离策略:\n'
                    'Cross-Origin-Opener-Policy: same-origin\n'
                    'Cross-Origin-Embedder-Policy: require-corp\n'
                    'Cross-Origin-Resource-Policy: same-origin'
                )
            )

        return None

    def _calculate_security_score(self) -> None:
        """计算安全评分"""
        total_score = 0
        max_score = 0
        headers_info = {}
        missing = []
        weak = []

        for header_name, config in self.SECURITY_HEADERS.items():
            weight = config['weight']
            max_score += weight

            header_value = self._get_header(header_name.lower())

            header_info = SecurityHeader(
                name=header_name,
                value=header_value or '',
                present=bool(header_value),
                secure=False,
                max_score=weight
            )

            if header_value:
                # 简单评分：存在得满分
                # TODO: 根据配置质量调整分数
                header_info.score = weight
                header_info.secure = True
                total_score += weight
            else:
                header_info.score = 0
                if config['required']:
                    missing.append(header_name)

            headers_info[header_name] = header_info

        # 计算等级
        percentage = (total_score / max_score) * 100 if max_score > 0 else 0

        if percentage >= 90:
            grade = 'A'
        elif percentage >= 80:
            grade = 'B'
        elif percentage >= 70:
            grade = 'C'
        elif percentage >= 60:
            grade = 'D'
        else:
            grade = 'F'

        self._security_score = SecurityScore(
            total_score=total_score,
            max_score=max_score,
            grade=grade,
            headers=headers_info,
            missing_headers=missing,
            weak_headers=weak
        )

    def get_security_score(self) -> Optional[SecurityScore]:
        """获取安全评分"""
        if self._security_score is None:
            self._calculate_security_score()
        return self._security_score

    def _get_header(self, name: str) -> Optional[str]:
        """获取响应头值（支持别名）"""
        # 直接查找
        if name in self._response_headers:
            return self._response_headers[name]

        # 查找别名
        for header_name, config in self.SECURITY_HEADERS.items():
            if name.lower() == header_name.lower():
                for alias in config.get('aliases', []):
                    if alias in self._response_headers:
                        return self._response_headers[alias]

        return None

    def _extract_max_age(self, hsts_value: str) -> Optional[int]:
        """从HSTS值中提取max-age"""
        match = re.search(r'max-age=(\d+)', hsts_value, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None

    def compare_with(self, other_url: str) -> Dict[str, Any]:
        """
        与另一个URL的安全头进行对比

        Args:
            other_url: 对比目标URL

        Returns:
            对比结果
        """
        other_tester = SecurityHeadersTester(other_url, self.config)
        other_tester.test()
        other_score = other_tester.get_security_score()

        self_score = self.get_security_score()

        comparison = {
            'target1': {
                'url': self.target,
                'score': self_score.total_score if self_score else 0,
                'grade': self_score.grade if self_score else 'F'
            },
            'target2': {
                'url': other_url,
                'score': other_score.total_score if other_score else 0,
                'grade': other_score.grade if other_score else 'F'
            },
            'header_comparison': {}
        }

        if self_score and other_score:
            for header_name in self.SECURITY_HEADERS.keys():
                h1 = self_score.headers.get(header_name)
                h2 = other_score.headers.get(header_name)

                comparison['header_comparison'][header_name] = {
                    'target1_present': h1.present if h1 else False,
                    'target2_present': h2.present if h2 else False,
                    'target1_value': h1.value if h1 else None,
                    'target2_value': h2.value if h2 else None,
                }

        return comparison

    def generate_report(self) -> str:
        """生成安全头报告"""
        score = self.get_security_score()
        if not score:
            return "无法生成报告：未完成测试"

        lines = [
            "=" * 60,
            "HTTP安全头评估报告",
            "=" * 60,
            f"目标: {self.target}",
            f"评分: {score.total_score}/{score.max_score} ({score.grade})",
            "",
            "-" * 60,
            "安全头状态:",
            "-" * 60,
        ]

        for header_name, header_info in score.headers.items():
            status = "OK" if header_info.present else "MISSING"
            icon = "[+]" if header_info.present else "[-]"
            lines.append(f"{icon} {header_name}: {status}")
            if header_info.value:
                value_preview = header_info.value[:50] + '...' if len(header_info.value) > 50 else header_info.value
                lines.append(f"    Value: {value_preview}")

        if score.missing_headers:
            lines.extend([
                "",
                "-" * 60,
                "缺失的必需安全头:",
                "-" * 60,
            ])
            for header in score.missing_headers:
                lines.append(f"  - {header}")

        lines.append("=" * 60)

        return "\n".join(lines)


# 便捷函数
def quick_headers_test(target: str) -> Dict[str, Any]:
    """
    快速安全头测试

    Args:
        target: 目标URL

    Returns:
        测试结果和评分
    """
    tester = SecurityHeadersTester(target)
    results = tester.test()
    score = tester.get_security_score()

    return {
        'summary': tester.get_summary().to_dict(),
        'score': {
            'total': score.total_score if score else 0,
            'max': score.max_score if score else 0,
            'grade': score.grade if score else 'F',
            'missing': score.missing_headers if score else [],
        }
    }


def compare_security_headers(url1: str, url2: str) -> Dict[str, Any]:
    """
    对比两个URL的安全头

    Args:
        url1: 第一个URL
        url2: 第二个URL

    Returns:
        对比结果
    """
    tester = SecurityHeadersTester(url1)
    tester.test()
    return tester.compare_with(url2)


__all__ = [
    'SecurityHeadersTester',
    'SecurityHeader',
    'SecurityScore',
    'quick_headers_test',
    'compare_security_headers',
]
