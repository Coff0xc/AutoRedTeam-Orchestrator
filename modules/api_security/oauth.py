#!/usr/bin/env python3
"""
OAuth安全测试模块

提供全面的OAuth 2.0 / OpenID Connect安全测试功能，包括:
- 重定向URI验证绕过测试
- CSRF/State参数测试
- 授权码泄露测试
- PKCE实施测试
- Token泄露测试
- Scope操纵测试
- 隐式流安全测试

作者: AutoRedTeam
版本: 3.0.0
"""

import base64
import hashlib
import logging
import secrets
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse

from .base import (
    APITestResult,
    APIVulnType,
    BaseAPITester,
    Severity,
)

logger = logging.getLogger(__name__)


class OAuthTester(BaseAPITester):
    """
    OAuth安全测试器

    对OAuth 2.0 / OIDC端点进行全面的安全测试。

    使用示例:
        tester = OAuthTester(
            target='https://auth.example.com/oauth/authorize',
            config={
                'client_id': 'your_client_id',
                'redirect_uri': 'https://app.example.com/callback',
                'scope': 'openid profile email'
            }
        )
        results = tester.test()
    """

    name = "oauth"
    description = "OAuth 2.0 / OIDC安全测试器"
    version = "3.0.0"

    # 重定向URI绕过Payload
    REDIRECT_BYPASS_PAYLOADS = [
        # 开放重定向
        ("https://evil.com", "external_domain"),
        ("//evil.com", "protocol_relative"),
        ("https://evil.com@legitimate.com", "userinfo_bypass"),
        ("/\\evil.com", "backslash_bypass"),
        # 路径遍历
        ("/../../../evil.com", "path_traversal"),
        ("/..;/evil.com", "semicolon_bypass"),
        # 编码绕过
        ("https://evil%2ecom", "url_encoding"),
        ("https://evil。com", "unicode_dot"),
        # 本地重定向
        ("javascript:alert(1)", "javascript_protocol"),
        ("data:text/html,<script>alert(1)</script>", "data_protocol"),
    ]

    # 常见OAuth端点
    COMMON_ENDPOINTS = {
        "authorize": ["/oauth/authorize", "/authorize", "/oauth2/authorize", "/connect/authorize"],
        "token": ["/oauth/token", "/token", "/oauth2/token", "/connect/token"],
        "userinfo": ["/userinfo", "/oauth/userinfo", "/connect/userinfo"],
        "jwks": ["/.well-known/jwks.json", "/oauth/jwks", "/jwks"],
        "openid_config": [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        ],
    }

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        """
        初始化OAuth测试器

        Args:
            target: OAuth授权端点URL
            config: 可选配置，可包含:
                - client_id: 客户端ID
                - client_secret: 客户端密钥（可选）
                - redirect_uri: 重定向URI
                - scope: 请求的权限范围
                - response_type: 响应类型（code/token）
        """
        super().__init__(target, config)

        # 解析授权URL
        parsed = urlparse(target)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

        # OAuth配置
        self.client_id = self.config.get("client_id", "test_client")
        self.client_secret = self.config.get("client_secret")
        self.redirect_uri = self.config.get("redirect_uri", "https://app.example.com/callback")
        self.scope = self.config.get("scope", "openid profile")
        self.response_type = self.config.get("response_type", "code")

        # 发现的端点
        self._discovered_endpoints: Dict[str, str] = {}

    def test(self) -> List[APITestResult]:
        """执行所有OAuth安全测试"""
        self.clear_results()

        # 首先尝试发现端点
        self._discover_endpoints()

        # 执行各项测试
        self.test_redirect_uri_validation()
        self.test_state_csrf()
        self.test_pkce_implementation()
        self.test_scope_manipulation()
        self.test_token_leak_referrer()
        self.test_implicit_flow()
        self.test_authorization_code_reuse()

        return self._results

    def _discover_endpoints(self) -> None:
        """发现OAuth端点"""
        # 尝试获取OpenID配置
        for path in self.COMMON_ENDPOINTS["openid_config"]:
            try:
                client = self._get_http_client()
                response = client.get(f"{self.base_url}{path}", timeout=self.timeout)

                if response.status_code == 200:
                    config = response.json()
                    self._discovered_endpoints = {
                        "authorization_endpoint": config.get("authorization_endpoint"),
                        "token_endpoint": config.get("token_endpoint"),
                        "userinfo_endpoint": config.get("userinfo_endpoint"),
                        "jwks_uri": config.get("jwks_uri"),
                    }
                    logger.info(f"发现OpenID配置: {path}")
                    break

            except Exception as e:
                logger.debug(f"获取OpenID配置失败 {path}: {e}")

    def test_redirect_uri_validation(self) -> Optional[APITestResult]:
        """
        测试重定向URI验证绕过

        漏洞描述:
            如果授权服务器不严格验证redirect_uri参数，
            攻击者可以将授权码/Token重定向到恶意网站。

        Returns:
            测试结果或None
        """
        vulnerable_payloads: List[Dict[str, Any]] = []

        # 解析合法redirect_uri
        parsed_redirect = urlparse(self.redirect_uri)
        legitimate_host = parsed_redirect.netloc

        # 构造绕过payload
        bypass_attempts = list(self.REDIRECT_BYPASS_PAYLOADS)

        # 添加基于合法域名的绕过
        bypass_attempts.extend(
            [
                (f"https://{legitimate_host}.evil.com/callback", "subdomain_suffix"),
                (f"https://evil.{legitimate_host}/callback", "subdomain_prefix"),
                (f"{self.redirect_uri}/../../../evil", "path_traversal_relative"),
                (f"{self.redirect_uri}?url=https://evil.com", "open_redirect_param"),
                (f"{self.redirect_uri}#access_token=stolen", "fragment_injection"),
            ]
        )

        for payload, bypass_type in bypass_attempts:
            result = self._test_redirect_uri(payload)

            if result.get("accepted"):
                vulnerable_payloads.append(
                    {
                        "payload": payload,
                        "bypass_type": bypass_type,
                        "response": result.get("response", {}),
                    }
                )

        if vulnerable_payloads:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.OAUTH_REDIRECT,
                severity=Severity.CRITICAL,
                title="OAuth重定向URI验证绕过",
                description=(
                    f"发现{len(vulnerable_payloads)}种方式可以绕过redirect_uri验证，"
                    "攻击者可以将授权码或Token重定向到恶意网站。"
                ),
                evidence={
                    "vulnerable_payloads": vulnerable_payloads,
                    "legitimate_redirect_uri": self.redirect_uri,
                },
                remediation=(
                    "1. 严格验证redirect_uri，使用精确匹配\n"
                    "2. 预注册允许的redirect_uri白名单\n"
                    "3. 不允许通配符或模式匹配\n"
                    "4. 验证完整URI包括路径和查询参数"
                ),
            )
            return result

        return None

    def test_state_csrf(self) -> Optional[APITestResult]:
        """
        测试State参数CSRF防护

        漏洞描述:
            如果授权请求不使用state参数或state可预测，
            攻击者可以进行CSRF攻击。

        Returns:
            测试结果或None
        """
        # 测试不带state参数
        result_no_state = self._send_auth_request(include_state=False)

        if result_no_state.get("success") and result_no_state.get("status_code") < 400:
            self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.OAUTH_CSRF,
                severity=Severity.HIGH,
                title="OAuth CSRF - State参数可选",
                description=("授权服务器接受不带state参数的请求，" "可能导致CSRF攻击。"),
                evidence={
                    "request_without_state": "accepted",
                    "response_code": result_no_state.get("status_code"),
                },
                remediation=(
                    "1. 强制要求state参数\n"
                    "2. 验证state参数的随机性和唯一性\n"
                    "3. 在回调时验证state与会话匹配"
                ),
            )
            return None  # 继续其他测试

        # 测试空state
        result_empty_state = self._send_auth_request(state="")

        if result_empty_state.get("success") and result_empty_state.get("status_code") < 400:
            self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.OAUTH_CSRF,
                severity=Severity.MEDIUM,
                title="OAuth CSRF - State参数可为空",
                description="授权服务器接受空的state参数。",
                evidence={"empty_state": "accepted"},
                remediation="验证state参数不为空且具有足够熵",
            )

        return None

    def test_pkce_implementation(self) -> Optional[APITestResult]:
        """
        测试PKCE实施

        漏洞描述:
            如果OAuth流程不使用PKCE（Proof Key for Code Exchange），
            授权码可能被拦截和重放。

        Returns:
            测试结果或None
        """
        # 测试不带PKCE参数
        result_no_pkce = self._send_auth_request(include_pkce=False)

        if result_no_pkce.get("success") and result_no_pkce.get("status_code") < 400:
            # 检查是否为公开客户端
            # 对于公开客户端，PKCE是强制的（根据OAuth 2.1）

            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.OAUTH_PKCE_MISSING,
                severity=Severity.MEDIUM,
                title="OAuth PKCE未强制",
                description=("授权服务器不强制要求PKCE，" "授权码可能被拦截和重放攻击。"),
                evidence={
                    "pkce_required": False,
                    "response_code": result_no_pkce.get("status_code"),
                },
                remediation=(
                    "1. 强制要求所有客户端使用PKCE\n"
                    "2. 使用code_challenge_method=S256\n"
                    "3. 在token端点验证code_verifier"
                ),
            )
            return result

        return None

    def test_scope_manipulation(self) -> Optional[APITestResult]:
        """
        测试Scope操纵

        漏洞描述:
            如果授权服务器不严格验证scope，
            攻击者可能获取超出授权的权限。

        Returns:
            测试结果或None
        """
        # 测试扩展scope
        elevated_scopes = [
            "admin",
            "openid profile email admin",
            "read write delete admin",
            "*",
            "all",
        ]

        accepted_scopes: List[str] = []

        for scope in elevated_scopes:
            result = self._send_auth_request(scope=scope)

            if result.get("success") and result.get("status_code") < 400:
                # 检查响应中是否包含扩展的scope
                accepted_scopes.append(scope)

        if accepted_scopes:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.OAUTH_SCOPE_MANIPULATION,
                severity=Severity.HIGH,
                title="OAuth Scope操纵",
                description=(f"授权服务器接受了{len(accepted_scopes)}个可能的特权scope。"),
                evidence={"accepted_scopes": accepted_scopes, "original_scope": self.scope},
                remediation=(
                    "1. 严格验证请求的scope\n"
                    "2. 只允许客户端预注册的scope\n"
                    "3. 不接受通配符或未知scope\n"
                    "4. 实施最小权限原则"
                ),
            )
            return result

        return None

    def test_token_leak_referrer(self) -> Optional[APITestResult]:
        """
        测试Token通过Referrer泄露

        漏洞描述:
            如果回调页面包含外部链接，
            Token可能通过Referrer头泄露。

        Returns:
            测试结果或None
        """
        # 构造带token的隐式流请求
        auth_url = self._build_auth_url(response_type="token")

        try:
            client = self._get_http_client()
            response = client.get(auth_url, timeout=self.timeout, allow_redirects=False)

            # 检查响应头
            referrer_policy = response.headers.get("Referrer-Policy", "")

            if not referrer_policy or referrer_policy.lower() in [
                "unsafe-url",
                "no-referrer-when-downgrade",
            ]:
                self._create_result(
                    vulnerable=False,
                    vuln_type=APIVulnType.OAUTH_TOKEN_LEAK,
                    severity=Severity.INFO,
                    title="OAuth Token Referrer泄露风险",
                    description=(
                        f'授权端点的Referrer-Policy为: {referrer_policy or "未设置"}\n'
                        "如果使用隐式流，Token可能通过Referrer泄露。"
                    ),
                    evidence={"referrer_policy": referrer_policy or "not set"},
                    remediation=(
                        "1. 设置Referrer-Policy: no-referrer\n"
                        "2. 避免使用隐式流（response_type=token）\n"
                        "3. 使用授权码流+PKCE"
                    ),
                )

        except Exception as e:
            logger.debug(f"Token泄露测试失败: {e}")

        return None

    def test_implicit_flow(self) -> Optional[APITestResult]:
        """
        测试隐式流安全性

        漏洞描述:
            隐式流（response_type=token）直接在URL fragment中返回Token，
            存在多种安全风险。

        Returns:
            测试结果或None
        """
        # 测试是否支持隐式流
        result = self._send_auth_request(response_type="token")

        if result.get("success") and result.get("status_code") < 400:
            self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.OAUTH_TOKEN_LEAK,
                severity=Severity.MEDIUM,
                title="OAuth支持不安全的隐式流",
                description=(
                    "授权服务器支持隐式流（response_type=token），"
                    "Token在URL fragment中传输，存在安全风险。"
                ),
                evidence={
                    "implicit_flow_supported": True,
                    "response_code": result.get("status_code"),
                },
                remediation=(
                    "1. 禁用隐式流\n"
                    "2. 使用授权码流+PKCE替代\n"
                    "3. 对于SPA应用，使用BFF（Backend For Frontend）模式"
                ),
            )

        # 测试response_type=token id_token（OIDC隐式流）
        result_oidc = self._send_auth_request(response_type="token id_token")

        if result_oidc.get("success") and result_oidc.get("status_code") < 400:
            self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.OAUTH_TOKEN_LEAK,
                severity=Severity.MEDIUM,
                title="OIDC支持隐式流",
                description="支持response_type=token id_token的OIDC隐式流。",
                evidence={"oidc_implicit_flow": True},
                remediation="使用授权码流替代隐式流",
            )

        return None

    def test_authorization_code_reuse(self) -> Optional[APITestResult]:
        """
        测试授权码重用

        漏洞描述:
            根据RFC 6749，授权码只能使用一次，
            如果可以重用，可能导致Token劫持。

        Returns:
            测试结果或None
        """
        # 注意：这个测试需要实际获取授权码
        # 这里只检查配置和返回建议

        self._create_result(
            vulnerable=False,
            vuln_type=APIVulnType.OAUTH_CSRF,
            severity=Severity.INFO,
            title="OAuth授权码重用检查",
            description=(
                "建议验证授权服务器是否正确实施授权码一次性使用策略。\n"
                "需要手动测试：\n"
                "1. 获取授权码\n"
                "2. 使用授权码获取Token\n"
                "3. 再次使用相同授权码\n"
                "4. 如果第二次成功，则存在漏洞"
            ),
            evidence={"test_type": "manual_verification_required"},
            remediation=(
                "1. 授权码使用后立即失效\n"
                "2. 检测到授权码重用时撤销所有相关Token\n"
                "3. 设置授权码短有效期（建议10分钟以内）"
            ),
        )

        return None

    # ==================== 辅助方法 ====================

    def _build_auth_url(
        self,
        response_type: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
        state: Optional[str] = None,
        include_pkce: bool = True,
    ) -> str:
        """构造授权URL"""
        params = {
            "client_id": self.client_id,
            "response_type": response_type or self.response_type,
            "redirect_uri": redirect_uri or self.redirect_uri,
            "scope": scope or self.scope,
        }

        if state is not None:
            params["state"] = state
        else:
            params["state"] = secrets.token_urlsafe(32)

        if include_pkce and params["response_type"] == "code":
            code_verifier = secrets.token_urlsafe(64)
            code_challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
                .rstrip(b"=")
                .decode()
            )

            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        return f"{self.target}?{urlencode(params)}"

    def _send_auth_request(
        self,
        response_type: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
        state: Optional[str] = None,
        include_state: bool = True,
        include_pkce: bool = True,
    ) -> Dict[str, Any]:
        """发送授权请求"""
        try:
            client = self._get_http_client()

            params = {
                "client_id": self.client_id,
                "response_type": response_type or self.response_type,
                "redirect_uri": redirect_uri or self.redirect_uri,
                "scope": scope or self.scope,
            }

            if include_state:
                params["state"] = state if state is not None else secrets.token_urlsafe(32)

            if include_pkce and params["response_type"] == "code":
                code_verifier = secrets.token_urlsafe(64)
                code_challenge = (
                    base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
                    .rstrip(b"=")
                    .decode()
                )

                params["code_challenge"] = code_challenge
                params["code_challenge_method"] = "S256"

            url = f"{self.target}?{urlencode(params)}"

            response = client.get(url, timeout=self.timeout, allow_redirects=False)

            return {
                "success": True,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "location": response.headers.get("Location", ""),
            }

        except Exception as e:
            logger.debug(f"授权请求失败: {e}")
            return {"success": False, "error": str(e)}

    def _test_redirect_uri(self, redirect_uri: str) -> Dict[str, Any]:
        """测试特定的redirect_uri"""
        try:
            client = self._get_http_client()

            params = {
                "client_id": self.client_id,
                "response_type": self.response_type,
                "redirect_uri": redirect_uri,
                "scope": self.scope,
                "state": secrets.token_urlsafe(32),
            }

            url = f"{self.target}?{urlencode(params)}"

            response = client.get(url, timeout=self.timeout, allow_redirects=False)

            # 检查是否接受了redirect_uri
            # 通常接受会返回302重定向到redirect_uri
            # 拒绝会返回400或错误页面
            accepted = False

            if response.status_code in [302, 303, 307]:
                location = response.headers.get("Location", "")
                # 检查重定向目标是否包含我们的redirect_uri
                if redirect_uri in location or urlparse(redirect_uri).netloc in location:
                    accepted = True
            elif response.status_code == 200:
                # 某些实现返回200并显示同意页面
                # 需要进一步分析响应内容
                pass

            return {
                "accepted": accepted,
                "status_code": response.status_code,
                "response": {
                    "location": response.headers.get("Location", ""),
                    "content_length": len(response.content) if hasattr(response, "content") else 0,
                },
            }

        except Exception as e:
            logger.debug(f"redirect_uri测试失败: {e}")
            return {"accepted": False, "error": str(e)}


# 便捷函数
def quick_oauth_test(target: str, client_id: str, redirect_uri: str) -> Dict[str, Any]:
    """
    快速OAuth安全测试

    Args:
        target: OAuth授权端点URL
        client_id: 客户端ID
        redirect_uri: 重定向URI

    Returns:
        测试结果摘要
    """
    tester = OAuthTester(target, config={"client_id": client_id, "redirect_uri": redirect_uri})
    results = tester.test()
    return tester.get_summary().to_dict()


__all__ = [
    "OAuthTester",
    "quick_oauth_test",
]
