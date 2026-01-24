#!/usr/bin/env python3
"""
CORS安全测试模块

提供全面的CORS（跨域资源共享）安全测试功能，包括:
- 通配符Origin测试
- Null Origin测试
- Origin反射测试
- 凭证与通配符组合测试
- 子域名绕过测试
- Preflight请求测试

作者: AutoRedTeam
版本: 3.0.0
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import (
    APITestResult,
    APIVulnType,
    BaseAPITester,
    Severity,
)

logger = logging.getLogger(__name__)


class CORSTester(BaseAPITester):
    """
    CORS配置安全测试器

    测试目标站点的CORS配置是否存在安全问题。

    使用示例:
        tester = CORSTester('https://api.example.com/data')
        results = tester.test()
    """

    name = 'cors'
    description = 'CORS跨域配置安全测试器'
    version = '3.0.0'

    # 测试用Origin列表
    MALICIOUS_ORIGINS = [
        'https://evil.com',
        'https://attacker.com',
        'https://malicious.example',
        'http://localhost',
        'http://127.0.0.1',
        'http://[::1]',
    ]

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        """
        初始化CORS测试器

        Args:
            target: 目标URL
            config: 可选配置，可包含:
                - legitimate_origin: 合法Origin（用于子域名绕过测试）
                - test_methods: 要测试的HTTP方法列表
                - custom_origins: 自定义恶意Origin列表
        """
        super().__init__(target, config)

        # 解析目标URL
        parsed = urlparse(target)
        self.target_host = parsed.netloc
        self.target_scheme = parsed.scheme

        # 配置项
        self.legitimate_origin = self.config.get(
            'legitimate_origin',
            f'{self.target_scheme}://{self.target_host}'
        )
        self.test_methods = self.config.get(
            'test_methods',
            ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        )
        self.custom_origins = self.config.get('custom_origins', [])

    def test(self) -> List[APITestResult]:
        """执行所有CORS安全测试"""
        self.clear_results()

        # 执行各项测试
        self.test_wildcard_origin()
        self.test_null_origin()
        self.test_origin_reflection()
        self.test_credentials_with_wildcard()
        self.test_subdomain_bypass()
        self.test_preflight_bypass()
        self.test_method_override()

        return self._results

    def test_wildcard_origin(self) -> Optional[APITestResult]:
        """
        测试通配符Origin (ACAO: *)

        漏洞描述:
            当Access-Control-Allow-Origin设置为*时，
            任何网站都可以读取响应内容（不带凭证情况下）。

        Returns:
            测试结果或None
        """
        response = self._send_cors_request('https://evil.com')
        if not response:
            return None

        acao = response.get('acao', '')

        if acao == '*':
            acac = response.get('acac', '')

            # 如果同时设置了Allow-Credentials: true，这是严重漏洞
            if acac.lower() == 'true':
                result = self._create_result(
                    vulnerable=True,
                    vuln_type=APIVulnType.CORS_CREDENTIALS_WITH_WILDCARD,
                    severity=Severity.CRITICAL,
                    title='CORS通配符与凭证组合漏洞',
                    description=(
                        'Access-Control-Allow-Origin设置为*，'
                        '同时Allow-Credentials为true。'
                        '这违反了CORS规范，但某些旧浏览器可能存在漏洞。'
                    ),
                    evidence={
                        'Access-Control-Allow-Origin': acao,
                        'Access-Control-Allow-Credentials': acac
                    },
                    remediation=(
                        '1. 不要同时使用*和Allow-Credentials\n'
                        '2. 使用具体的Origin白名单\n'
                        '3. 根据请求动态设置允许的Origin'
                    )
                )
                return result
            else:
                result = self._create_result(
                    vulnerable=True,
                    vuln_type=APIVulnType.CORS_WILDCARD,
                    severity=Severity.MEDIUM,
                    title='CORS允许任意Origin',
                    description=(
                        'Access-Control-Allow-Origin设置为*，'
                        '允许任何网站在不带凭证的情况下读取响应。'
                    ),
                    evidence={
                        'Access-Control-Allow-Origin': acao,
                        'Access-Control-Allow-Credentials': acac or 'not set'
                    },
                    remediation=(
                        '1. 如果API只对特定来源开放，使用白名单\n'
                        '2. 如果是公开API，确保不包含敏感数据\n'
                        '3. 考虑使用更严格的Origin限制'
                    )
                )
                return result

        return None

    def test_null_origin(self) -> Optional[APITestResult]:
        """
        测试Null Origin

        漏洞描述:
            Origin: null可能来自:
            - 沙箱iframe
            - file://协议
            - data: URL
            - 某些重定向场景

            如果服务端接受null Origin，攻击者可以通过这些方式绕过CORS限制。

        Returns:
            测试结果或None
        """
        response = self._send_cors_request('null')
        if not response:
            return None

        acao = response.get('acao', '')

        if acao == 'null':
            acac = response.get('acac', '')

            severity = Severity.HIGH if acac.lower() == 'true' else Severity.MEDIUM

            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.CORS_NULL_ORIGIN,
                severity=severity,
                title='CORS允许Null Origin',
                description=(
                    'Access-Control-Allow-Origin接受null值。'
                    '攻击者可以通过沙箱iframe或data: URL发起跨域请求。'
                ),
                evidence={
                    'Access-Control-Allow-Origin': acao,
                    'Access-Control-Allow-Credentials': acac or 'not set',
                    'attack_vector': 'sandboxed iframe / data: URL / file:// protocol'
                },
                remediation=(
                    '1. 不要接受null作为Origin\n'
                    '2. 使用严格的Origin白名单验证\n'
                    '3. 验证Origin格式的有效性'
                )
            )
            return result

        return None

    def test_origin_reflection(self) -> Optional[APITestResult]:
        """
        测试Origin反射

        漏洞描述:
            服务端直接将请求的Origin值反射到ACAO头中，
            这允许任何网站进行跨域访问。

        Returns:
            测试结果或None
        """
        test_origins = self.MALICIOUS_ORIGINS + self.custom_origins
        reflected_origins = []

        for origin in test_origins:
            response = self._send_cors_request(origin)
            if not response:
                continue

            acao = response.get('acao', '')

            if acao == origin:
                reflected_origins.append({
                    'origin': origin,
                    'acac': response.get('acac', '')
                })

        if reflected_origins:
            # 检查是否带凭证
            has_credentials = any(
                r['acac'].lower() == 'true'
                for r in reflected_origins
            )

            severity = Severity.CRITICAL if has_credentials else Severity.HIGH

            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.CORS_ORIGIN_REFLECTION,
                severity=severity,
                title='CORS Origin反射漏洞',
                description=(
                    '服务端将请求的Origin值直接反射到Access-Control-Allow-Origin头中，'
                    '任何网站都可以进行跨域访问。'
                ),
                evidence={
                    'reflected_origins': reflected_origins,
                    'total_reflected': len(reflected_origins),
                    'credentials_allowed': has_credentials
                },
                remediation=(
                    '1. 使用Origin白名单，不要直接反射\n'
                    '2. 验证Origin是否在允许的列表中\n'
                    '3. 对于敏感API，限制允许的Origin'
                )
            )
            return result

        return None

    def test_credentials_with_wildcard(self) -> Optional[APITestResult]:
        """
        测试凭证与通配符组合

        漏洞描述:
            CORS规范禁止ACAO为*时使用Allow-Credentials: true，
            但某些服务器可能配置错误。

        Returns:
            测试结果或None
        """
        # 这个测试在test_wildcard_origin中已经覆盖
        # 这里单独测试以确保完整性
        response = self._send_cors_request('https://evil.com', with_credentials=True)
        if not response:
            return None

        acao = response.get('acao', '')
        acac = response.get('acac', '')

        # 检查是否反射了Origin且允许凭证
        if acao == 'https://evil.com' and acac.lower() == 'true':
            if not any(r.vuln_type == APIVulnType.CORS_ORIGIN_REFLECTION for r in self._results):
                result = self._create_result(
                    vulnerable=True,
                    vuln_type=APIVulnType.CORS_MISCONFIGURATION,
                    severity=Severity.CRITICAL,
                    title='CORS允许带凭证的跨域请求',
                    description=(
                        '服务端反射Origin并允许携带凭证(cookies, Authorization headers)，'
                        '攻击者可以读取用户的敏感数据。'
                    ),
                    evidence={
                        'Access-Control-Allow-Origin': acao,
                        'Access-Control-Allow-Credentials': acac,
                        'malicious_origin_used': 'https://evil.com'
                    },
                    remediation=(
                        '1. 严格验证Origin白名单\n'
                        '2. 仅对可信来源允许凭证\n'
                        '3. 考虑使用CSRF token额外保护'
                    )
                )
                return result

        return None

    def test_subdomain_bypass(self) -> Optional[APITestResult]:
        """
        测试子域名绕过

        漏洞描述:
            某些CORS实现使用后缀匹配，导致:
            - evil-example.com 可以访问 example.com
            - example.com.evil.com 可以访问 example.com

        Returns:
            测试结果或None
        """
        parsed = urlparse(self.legitimate_origin)
        legitimate_host = parsed.netloc

        # 构造绕过payload
        bypass_origins = [
            # 后缀攻击
            f'{parsed.scheme}://evil{legitimate_host}',
            f'{parsed.scheme}://evil.{legitimate_host}',
            f'{parsed.scheme}://{legitimate_host}.evil.com',
            # 前缀攻击
            f'{parsed.scheme}://evilexample.com' if 'example.com' in legitimate_host else None,
            # URL混淆
            f'{parsed.scheme}://evil.com#{self.legitimate_origin}',
            f'{parsed.scheme}://evil.com?url={self.legitimate_origin}',
            # 用户信息绕过
            f'{parsed.scheme}://{legitimate_host}@evil.com',
            f'{parsed.scheme}://evil.com@{legitimate_host}',
        ]

        bypass_origins = [o for o in bypass_origins if o]

        successful_bypasses = []

        for origin in bypass_origins:
            response = self._send_cors_request(origin)
            if not response:
                continue

            acao = response.get('acao', '')

            if acao == origin:
                successful_bypasses.append({
                    'bypass_origin': origin,
                    'acac': response.get('acac', '')
                })

        if successful_bypasses:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.CORS_SUBDOMAIN_BYPASS,
                severity=Severity.HIGH,
                title='CORS子域名验证绕过',
                description=(
                    'Origin验证存在绕过漏洞，攻击者可以使用特制域名绕过限制。'
                ),
                evidence={
                    'successful_bypasses': successful_bypasses,
                    'legitimate_origin': self.legitimate_origin
                },
                remediation=(
                    '1. 使用精确匹配而不是后缀/前缀匹配\n'
                    '2. 验证完整的Origin URL格式\n'
                    '3. 使用URL解析库验证域名'
                )
            )
            return result

        return None

    def test_preflight_bypass(self) -> Optional[APITestResult]:
        """
        测试Preflight请求绕过

        漏洞描述:
            某些服务器可能对OPTIONS请求和实际请求的CORS处理不一致。

        Returns:
            测试结果或None
        """
        malicious_origin = 'https://evil.com'

        # 发送OPTIONS preflight请求
        preflight_response = self._send_preflight_request(malicious_origin)

        # 发送实际请求
        actual_response = self._send_cors_request(malicious_origin)

        if not preflight_response or not actual_response:
            return None

        preflight_acao = preflight_response.get('acao', '')
        actual_acao = actual_response.get('acao', '')

        # 检查是否存在不一致
        if preflight_acao != actual_acao:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.CORS_MISCONFIGURATION,
                severity=Severity.MEDIUM,
                title='CORS Preflight响应不一致',
                description=(
                    'OPTIONS请求和实际请求的CORS响应不一致，'
                    '可能导致预检绕过或策略混淆。'
                ),
                evidence={
                    'preflight_acao': preflight_acao or 'not set',
                    'actual_acao': actual_acao or 'not set',
                    'origin_tested': malicious_origin
                },
                remediation=(
                    '1. 确保OPTIONS和实际请求的CORS处理一致\n'
                    '2. 在同一处理逻辑中设置CORS头\n'
                    '3. 审查中间件和代理的CORS配置'
                )
            )
            return result

        return None

    def test_method_override(self) -> Optional[APITestResult]:
        """
        测试HTTP方法覆盖

        漏洞描述:
            某些服务器支持X-HTTP-Method-Override头，
            可能绕过Access-Control-Allow-Methods限制。

        Returns:
            测试结果或None
        """
        override_headers = [
            'X-HTTP-Method-Override',
            'X-HTTP-Method',
            'X-Method-Override',
        ]

        vulnerable_methods = []

        for method in ['PUT', 'DELETE', 'PATCH']:
            for header in override_headers:
                response = self._send_method_override_request(
                    'https://evil.com',
                    method,
                    header
                )

                if response and response.get('acao') == 'https://evil.com':
                    acam = response.get('acam', '')
                    if method not in acam.upper():
                        vulnerable_methods.append({
                            'method': method,
                            'header': header
                        })

        if vulnerable_methods:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.CORS_MISCONFIGURATION,
                severity=Severity.MEDIUM,
                title='CORS方法覆盖绕过',
                description=(
                    '服务器支持HTTP方法覆盖，可能绕过Allow-Methods限制。'
                ),
                evidence={
                    'vulnerable_methods': vulnerable_methods
                },
                remediation=(
                    '1. 禁用HTTP方法覆盖头\n'
                    '2. 在CORS层验证实际HTTP方法\n'
                    '3. 严格限制Allow-Methods'
                )
            )
            return result

        return None

    # ==================== 辅助方法 ====================

    def _send_cors_request(
        self,
        origin: str,
        method: str = 'GET',
        with_credentials: bool = False
    ) -> Optional[Dict[str, str]]:
        """
        发送CORS测试请求

        Args:
            origin: Origin头值
            method: HTTP方法
            with_credentials: 是否包含凭证

        Returns:
            CORS相关响应头或None
        """
        try:
            client = self._get_http_client()

            headers = self.extra_headers.copy()
            headers['Origin'] = origin

            if method == 'GET':
                response = client.get(
                    self.target,
                    headers=headers,
                    timeout=self.timeout
                )
            else:
                response = client.request(
                    method,
                    self.target,
                    headers=headers,
                    timeout=self.timeout
                )

            return self._extract_cors_headers(response)

        except Exception as e:
            logger.debug(f'CORS请求失败: {e}')
            return None

    def _send_preflight_request(
        self,
        origin: str,
        method: str = 'POST'
    ) -> Optional[Dict[str, str]]:
        """
        发送Preflight OPTIONS请求

        Args:
            origin: Origin头值
            method: 实际请求方法

        Returns:
            CORS相关响应头或None
        """
        try:
            client = self._get_http_client()

            headers = self.extra_headers.copy()
            headers.update({
                'Origin': origin,
                'Access-Control-Request-Method': method,
                'Access-Control-Request-Headers': 'Content-Type, Authorization'
            })

            response = client.options(
                self.target,
                headers=headers,
                timeout=self.timeout
            )

            return self._extract_cors_headers(response)

        except Exception as e:
            logger.debug(f'Preflight请求失败: {e}')
            return None

    def _send_method_override_request(
        self,
        origin: str,
        target_method: str,
        override_header: str
    ) -> Optional[Dict[str, str]]:
        """
        发送方法覆盖请求

        Args:
            origin: Origin头值
            target_method: 目标方法
            override_header: 覆盖头名称

        Returns:
            CORS相关响应头或None
        """
        try:
            client = self._get_http_client()

            headers = self.extra_headers.copy()
            headers['Origin'] = origin
            headers[override_header] = target_method

            response = client.post(
                self.target,
                headers=headers,
                timeout=self.timeout
            )

            return self._extract_cors_headers(response)

        except Exception as e:
            logger.debug(f'方法覆盖请求失败: {e}')
            return None

    def _extract_cors_headers(self, response) -> Dict[str, str]:
        """从响应中提取CORS相关头"""
        headers = {}

        cors_header_names = {
            'access-control-allow-origin': 'acao',
            'access-control-allow-credentials': 'acac',
            'access-control-allow-methods': 'acam',
            'access-control-allow-headers': 'acah',
            'access-control-expose-headers': 'aceh',
            'access-control-max-age': 'acma',
        }

        for header_name, short_name in cors_header_names.items():
            value = response.headers.get(header_name, '')
            if value:
                headers[short_name] = value

        headers['status_code'] = response.status_code

        return headers


# 便捷函数
def quick_cors_test(target: str) -> Dict[str, Any]:
    """
    快速CORS安全测试

    Args:
        target: 目标URL

    Returns:
        测试结果摘要
    """
    tester = CORSTester(target)
    results = tester.test()
    return tester.get_summary().to_dict()


__all__ = [
    'CORSTester',
    'quick_cors_test',
]
