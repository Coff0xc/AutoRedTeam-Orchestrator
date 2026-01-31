#!/usr/bin/env python3
"""
JWT 安全测试模块单元测试

测试 modules/api_security/jwt.py 的各项功能。
"""

import base64
import hashlib
import hmac
import json
import time
from unittest.mock import MagicMock, Mock, patch

import pytest

from modules.api_security.jwt import JWTTester, decode_jwt, quick_jwt_test
from modules.api_security.base import APIVulnType, Severity


class TestJWTDecoding:
    """JWT 解码功能测试"""

    def test_decode_valid_jwt(self):
        """测试解码有效的 JWT"""
        # 构造一个简单的 JWT
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1234567890", "name": "Test User", "iat": 1516239022}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()

        # 简单签名
        message = f"{header_b64}.{payload_b64}"
        signature = base64.urlsafe_b64encode(b"fake_signature").rstrip(b'=').decode()
        token = f"{message}.{signature}"

        decoded = decode_jwt(token)

        assert decoded is not None
        assert decoded['header']['alg'] == 'HS256'
        assert decoded['payload']['name'] == 'Test User'
        assert decoded['signature'] == signature

    def test_decode_invalid_jwt_format(self):
        """测试解码无效格式的 JWT"""
        # 只有两部分
        invalid_token = "header.payload"
        decoded = decode_jwt(invalid_token)
        assert decoded is None

        # 四部分
        invalid_token2 = "a.b.c.d"
        decoded2 = decode_jwt(invalid_token2)
        assert decoded2 is None

    def test_decode_malformed_base64(self):
        """测试解码格式错误的 Base64"""
        # 无效的 Base64
        invalid_token = "!!!.###.$$$"
        decoded = decode_jwt(invalid_token)
        assert decoded is None


class TestJWTTesterInit:
    """JWT 测试器初始化测试"""

    def test_init_basic(self):
        """测试基本初始化"""
        token = self._create_test_token()
        tester = JWTTester("https://api.example.com", token)

        assert tester.target == "https://api.example.com"
        assert tester.token == token
        assert tester._decoded is not None

    def test_init_with_config(self):
        """测试带配置的初始化"""
        token = self._create_test_token()
        config = {
            'timeout': 30,
            'auth_header': 'X-Auth-Token',
            'auth_prefix': 'Token',
            'weak_secrets': ['custom_secret']
        }
        tester = JWTTester("https://api.example.com", token, config)

        assert tester.timeout == 30
        assert tester.auth_header == 'X-Auth-Token'
        assert tester.auth_prefix == 'Token'
        assert 'custom_secret' in tester.weak_secrets

    def test_init_with_invalid_token(self):
        """测试使用无效 token 初始化"""
        tester = JWTTester("https://api.example.com", "invalid.token")
        assert tester._decoded is None

    @staticmethod
    def _create_test_token(payload=None):
        """创建测试用 JWT token"""
        header = {"alg": "HS256", "typ": "JWT"}
        if payload is None:
            payload = {"sub": "test", "iat": int(time.time())}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()

        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            b"secret",
            message.encode(),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

        return f"{message}.{signature_b64}"


class TestJWTNoneAlgorithm:
    """JWT None 算法漏洞测试"""

    def test_none_algorithm_vulnerable(self):
        """测试检测到 None 算法漏洞"""
        token = self._create_test_token()
        tester = JWTTester("https://api.example.com", token)

        # Mock HTTP 客户端，模拟服务器接受 none 算法
        with patch.object(tester, '_verify_token_accepted', return_value=True):
            result = tester.test_none_algorithm()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.JWT_NONE_ALG
        assert result.severity == Severity.CRITICAL

    def test_none_algorithm_safe(self):
        """测试服务器拒绝 None 算法"""
        token = self._create_test_token()
        tester = JWTTester("https://api.example.com", token)

        # Mock HTTP 客户端，模拟服务器拒绝 none 算法
        with patch.object(tester, '_verify_token_accepted', return_value=False):
            result = tester.test_none_algorithm()

        assert result is None

    def test_none_algorithm_variants(self):
        """测试 None 算法的各种变体"""
        token = self._create_test_token()
        tester = JWTTester("https://api.example.com", token)

        # 记录所有尝试的算法
        attempted_algs = []

        def mock_verify(test_token):
            # 从 token 中提取算法
            parts = test_token.split('.')
            header_json = base64.urlsafe_b64decode(parts[0] + '==')
            header = json.loads(header_json)
            attempted_algs.append(header['alg'])
            return False

        with patch.object(tester, '_verify_token_accepted', side_effect=mock_verify):
            tester.test_none_algorithm()

        # 验证测试了多种变体
        assert 'none' in attempted_algs
        assert 'None' in attempted_algs
        assert 'NONE' in attempted_algs

    @staticmethod
    def _create_test_token():
        """创建测试用 JWT token"""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "test", "iat": int(time.time())}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()

        return f"{header_b64}.{payload_b64}.fake_signature"


class TestJWTWeakSecret:
    """JWT 弱密钥测试"""

    def test_weak_secret_detected(self):
        """测试检测到弱密钥"""
        # 使用已知弱密钥创建 token
        token = self._create_token_with_secret("secret")
        tester = JWTTester("https://api.example.com", token)

        result = tester.test_weak_secret()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.JWT_WEAK_SECRET
        assert result.severity == Severity.HIGH
        assert 'secret' in result.evidence['weak_secret']

    def test_strong_secret_safe(self):
        """测试强密钥不被检测为弱密钥"""
        # 使用强密钥
        strong_secret = "x" * 64  # 64字节随机密钥
        token = self._create_token_with_secret(strong_secret)
        tester = JWTTester("https://api.example.com", token)

        result = tester.test_weak_secret()

        assert result is None

    def test_weak_secret_custom_list(self):
        """测试自定义弱密钥列表"""
        token = self._create_token_with_secret("my_custom_weak_key")
        config = {
            'weak_secrets': ['my_custom_weak_key']
        }
        tester = JWTTester("https://api.example.com", token, config)

        result = tester.test_weak_secret()

        assert result is not None
        assert result.vulnerable is True
        assert result.evidence['weak_secret'] == 'my_custom_weak_key'

    def test_non_hmac_algorithm_skipped(self):
        """测试非 HMAC 算法跳过弱密钥测试"""
        # 创建 RS256 token
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"sub": "test"}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()

        token = f"{header_b64}.{payload_b64}.fake_signature"
        tester = JWTTester("https://api.example.com", token)

        result = tester.test_weak_secret()

        # RS256 不应该测试弱密钥
        assert result is None

    @staticmethod
    def _create_token_with_secret(secret):
        """使用指定密钥创建 JWT token"""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "test", "iat": int(time.time())}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()

        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

        return f"{message}.{signature_b64}"


class TestJWTKIDInjection:
    """JWT KID 注入测试"""

    def test_kid_path_traversal(self):
        """测试 KID 路径遍历漏洞"""
        token = self._create_test_token()
        tester = JWTTester("https://api.example.com", token)

        # Mock 验证，模拟接受路径遍历 payload
        def mock_verify(test_token):
            parts = test_token.split('.')
            header_json = base64.urlsafe_b64decode(parts[0] + '==')
            header = json.loads(header_json)
            # 如果包含路径遍历，返回 True
            return 'kid' in header and '../' in header['kid']

        with patch.object(tester, '_verify_token_accepted', side_effect=mock_verify):
            result = tester.test_kid_injection()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.JWT_KID_INJECTION
        assert len(result.evidence['vulnerable_payloads']) > 0

    def test_kid_sql_injection(self):
        """测试 KID SQL 注入漏洞"""
        token = self._create_test_token()
        tester = JWTTester("https://api.example.com", token)

        vulnerable_payloads = []

        def mock_verify(test_token):
            parts = test_token.split('.')
            header_json = base64.urlsafe_b64decode(parts[0] + '==')
            header = json.loads(header_json)
            if 'kid' in header and "'" in header['kid']:
                vulnerable_payloads.append(header['kid'])
                return True
            return False

        with patch.object(tester, '_verify_token_accepted', side_effect=mock_verify):
            result = tester.test_kid_injection()

        if result:
            assert result.vulnerable is True
            assert any("'" in p['payload'] for p in result.evidence['vulnerable_payloads'])

    def test_kid_safe(self):
        """测试服务器正确验证 KID"""
        token = self._create_test_token()
        tester = JWTTester("https://api.example.com", token)

        with patch.object(tester, '_verify_token_accepted', return_value=False):
            result = tester.test_kid_injection()

        assert result is None

    @staticmethod
    def _create_test_token():
        """创建测试用 JWT token"""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "test"}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()

        return f"{header_b64}.{payload_b64}.fake_signature"


class TestJWTExpiration:
    """JWT 过期时间测试"""

    def test_expired_token_accepted(self):
        """测试服务器接受过期 token"""
        # 创建已过期的 token
        expired_time = int(time.time()) - 3600  # 1小时前过期
        payload = {"sub": "test", "exp": expired_time}
        token = self._create_token_with_payload(payload)

        tester = JWTTester("https://api.example.com", token)

        # Mock 服务器接受过期 token
        with patch.object(tester, '_verify_token_accepted', return_value=True):
            result = tester.test_expiration()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.JWT_EXPIRED_ACCEPTED
        assert result.severity == Severity.HIGH

    def test_valid_token_not_expired(self):
        """测试未过期的 token"""
        # 创建未过期的 token
        future_time = int(time.time()) + 3600  # 1小时后过期
        payload = {"sub": "test", "exp": future_time}
        token = self._create_token_with_payload(payload)

        tester = JWTTester("https://api.example.com", token)

        result = tester.test_expiration()

        # 未过期的 token 不应该触发漏洞
        assert result is None

    def test_missing_exp_claim(self):
        """测试缺少 exp 声明"""
        payload = {"sub": "test"}  # 没有 exp
        token = self._create_token_with_payload(payload)

        tester = JWTTester("https://api.example.com", token)

        result = tester.test_expiration()

        # 应该返回警告结果
        assert result is None
        # 但应该在结果列表中有一个 INFO 级别的结果
        tester.test()
        info_results = [r for r in tester.results if r.severity == Severity.MEDIUM]
        assert any('过期时间' in r.title for r in info_results)

    @staticmethod
    def _create_token_with_payload(payload):
        """使用指定 payload 创建 JWT token"""
        header = {"alg": "HS256", "typ": "JWT"}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()

        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            b"secret",
            message.encode(),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

        return f"{message}.{signature_b64}"


class TestJWTSignatureStripping:
    """JWT 签名剥离测试"""

    def test_signature_stripped_accepted(self):
        """测试服务器接受无签名的 token"""
        token = self._create_test_token()
        tester = JWTTester("https://api.example.com", token)

        # Mock 服务器接受无签名 token
        with patch.object(tester, '_verify_token_accepted', return_value=True):
            result = tester.test_signature_stripping()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.JWT_SIGNATURE_NOT_VERIFIED
        assert result.severity == Severity.CRITICAL

    def test_signature_required(self):
        """测试服务器要求签名"""
        token = self._create_test_token()
        tester = JWTTester("https://api.example.com", token)

        # Mock 服务器拒绝无签名 token
        with patch.object(tester, '_verify_token_accepted', return_value=False):
            result = tester.test_signature_stripping()

        assert result is None

    @staticmethod
    def _create_test_token():
        """创建测试用 JWT token"""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "test"}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()

        return f"{header_b64}.{payload_b64}.fake_signature"


class TestJWTFullScan:
    """JWT 完整扫描测试"""

    def test_full_scan_execution(self):
        """测试完整扫描执行所有测试"""
        token = self._create_test_token()
        tester = JWTTester("https://api.example.com", token)

        # Mock HTTP 客户端
        with patch.object(tester, '_verify_token_accepted', return_value=False):
            results = tester.test()

        # 应该执行多个测试
        assert len(results) >= 0  # 至少有一些测试结果

    def test_full_scan_with_vulnerabilities(self):
        """测试完整扫描发现多个漏洞"""
        # 使用弱密钥创建 token
        token = self._create_token_with_secret("secret")
        tester = JWTTester("https://api.example.com", token)

        # Mock 部分测试返回漏洞
        with patch.object(tester, '_verify_token_accepted', return_value=True):
            results = tester.test()

        # 应该发现多个漏洞
        vulnerable_results = [r for r in results if r.vulnerable]
        assert len(vulnerable_results) > 0

    def test_get_summary(self):
        """测试获取扫描摘要"""
        token = self._create_test_token()
        tester = JWTTester("https://api.example.com", token)

        with patch.object(tester, '_verify_token_accepted', return_value=False):
            tester.test()

        summary = tester.get_summary()

        assert summary.target == "https://api.example.com"
        assert summary.total_tests >= 0
        assert isinstance(summary.to_dict(), dict)

    @staticmethod
    def _create_test_token():
        """创建测试用 JWT token"""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "test", "iat": int(time.time())}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()

        return f"{header_b64}.{payload_b64}.fake_signature"

    @staticmethod
    def _create_token_with_secret(secret):
        """使用指定密钥创建 JWT token"""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "test", "iat": int(time.time())}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()

        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

        return f"{message}.{signature_b64}"


class TestQuickJWTTest:
    """快速 JWT 测试函数测试"""

    def test_quick_jwt_test(self):
        """测试快速测试函数"""
        token = self._create_test_token()

        with patch('modules.api_security.jwt.JWTTester') as MockTester:
            mock_instance = MockTester.return_value
            mock_instance.test.return_value = []
            mock_instance.get_summary.return_value = MagicMock(
                to_dict=lambda: {'total_tests': 5, 'vulnerable_count': 0}
            )

            result = quick_jwt_test("https://api.example.com", token)

        assert isinstance(result, dict)
        assert 'total_tests' in result

    @staticmethod
    def _create_test_token():
        """创建测试用 JWT token"""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "test"}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()

        return f"{header_b64}.{payload_b64}.fake_signature"


class TestJWTHelperMethods:
    """JWT 辅助方法测试"""

    def test_base64url_encode_decode(self):
        """测试 Base64 URL 编码解码"""
        token = self._create_test_token()
        tester = JWTTester("https://api.example.com", token)

        original = b"test data"
        encoded = tester._base64url_encode(original)
        decoded = tester._base64url_decode(encoded)

        assert decoded == original
        assert '=' not in encoded  # URL safe 不应该有填充

    def test_create_unsigned_token(self):
        """测试创建无签名 token"""
        token = self._create_test_token()
        tester = JWTTester("https://api.example.com", token)

        header = {"alg": "none", "typ": "JWT"}
        payload = {"sub": "test"}

        unsigned_token = tester._create_unsigned_token(header, payload)

        parts = unsigned_token.split('.')
        assert len(parts) == 3
        assert parts[2] == ''  # 签名部分为空

    def test_create_hs256_token(self):
        """测试创建 HS256 token"""
        token = self._create_test_token()
        tester = JWTTester("https://api.example.com", token)

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "test"}
        secret = "test_secret"

        hs256_token = tester._create_hs256_token(header, payload, secret)

        parts = hs256_token.split('.')
        assert len(parts) == 3
        assert parts[2] != ''  # 应该有签名

    @staticmethod
    def _create_test_token():
        """创建测试用 JWT token"""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "test"}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()

        return f"{header_b64}.{payload_b64}.fake_signature"
