#!/usr/bin/env python3
"""
MCP 安全中间件测试

测试 core/security/mcp_security.py 的所有核心功能
"""

import pytest
import time
import threading

from core.security.mcp_security import (
    InputValidator,
    MCPSecurityMiddleware,
    OperationAuthorizer,
    RateLimitConfig,
    RateLimiter,
    RiskLevel,
    ValidationResult,
)


# ==================== ValidationResult 测试 ====================


class TestValidationResult:
    """ValidationResult 数据类测试"""

    def test_valid_result(self):
        r = ValidationResult(valid=True, sanitized_value="test")
        assert r.valid is True
        assert r.errors == []

    def test_invalid_result(self):
        r = ValidationResult(valid=False, errors=["error"])
        assert r.valid is False
        assert len(r.errors) == 1

    def test_to_dict(self):
        r = ValidationResult(valid=True, warnings=["warn"])
        d = r.to_dict()
        assert d["valid"] is True
        assert "warn" in d["warnings"]


# ==================== InputValidator 测试 ====================


class TestInputValidator:
    """InputValidator 测试"""

    @pytest.fixture
    def validator(self):
        return InputValidator()

    # --- validate_target ---

    def test_validate_ipv4(self, validator):
        result = validator.validate_target("192.168.1.1")
        assert result.valid is True

    def test_validate_ipv6(self, validator):
        result = validator.validate_target("::1")
        assert result.valid is True

    def test_validate_domain(self, validator):
        result = validator.validate_target("example.com")
        assert result.valid is True

    def test_validate_subdomain(self, validator):
        result = validator.validate_target("sub.example.com")
        assert result.valid is True

    def test_validate_url(self, validator):
        result = validator.validate_target("https://example.com/path")
        assert result.valid is True

    def test_validate_cidr(self, validator):
        result = validator.validate_target("192.168.1.0/24")
        assert result.valid is True

    def test_validate_empty_target(self, validator):
        result = validator.validate_target("")
        assert result.valid is False

    def test_validate_long_target(self, validator):
        result = validator.validate_target("a" * 3000)
        assert result.valid is False

    def test_validate_unknown_type(self, validator):
        result = validator.validate_target("not-a-valid-target")
        assert result.valid is False

    def test_validate_command_injection(self, validator):
        result = validator.validate_target("192.168.1.1; rm -rf /")
        assert result.valid is False
        # 包含分号的输入被识别为 unknown 类型或被危险字符检测拦截
        assert len(result.errors) > 0

    def test_validate_pipe_injection(self, validator):
        result = validator.validate_target("192.168.1.1| cat /etc/passwd")
        assert result.valid is False

    def test_validate_backtick_injection(self, validator):
        result = validator.validate_target("192.168.1.1`whoami`")
        assert result.valid is False

    def test_validate_private_ip_allowed(self, validator):
        result = validator.validate_target("10.0.0.1", allow_private=True)
        assert result.valid is True

    def test_validate_private_ip_denied(self, validator):
        result = validator.validate_target("10.0.0.1", allow_private=False)
        assert result.valid is False

    def test_validate_loopback_denied(self, validator):
        result = validator.validate_target("127.0.0.1", allow_private=False)
        assert result.valid is False

    def test_validate_type_restriction(self, validator):
        result = validator.validate_target(
            "192.168.1.1", allowed_types=["domain"]
        )
        assert result.valid is False
        assert "不允许的目标类型" in result.errors[0]

    def test_validate_large_cidr_warning(self, validator):
        result = validator.validate_target("10.0.0.0/8")
        assert result.valid is True
        assert any("大型网段" in w for w in result.warnings)

    def test_validate_ftp_url_rejected(self, validator):
        result = validator.validate_target("ftp://example.com")
        assert result.valid is False

    # --- validate_port ---

    def test_validate_port_valid(self, validator):
        result = validator.validate_port(80)
        assert result.valid is True
        assert result.sanitized_value == 80

    def test_validate_port_zero(self, validator):
        result = validator.validate_port(0)
        assert result.valid is False

    def test_validate_port_too_high(self, validator):
        result = validator.validate_port(70000)
        assert result.valid is False

    def test_validate_port_string(self, validator):
        result = validator.validate_port("443")
        assert result.valid is True
        assert result.sanitized_value == 443

    def test_validate_port_range(self, validator):
        result = validator.validate_port("1-1024")
        assert result.valid is True
        assert result.sanitized_value == "1-1024"

    def test_validate_port_range_disabled(self, validator):
        result = validator.validate_port("1-1024", allow_range=False)
        assert result.valid is False

    def test_validate_port_range_invalid(self, validator):
        result = validator.validate_port("1024-80")
        assert result.valid is False
        assert "起始值大于结束值" in result.errors[0]

    def test_validate_port_invalid_string(self, validator):
        result = validator.validate_port("abc")
        assert result.valid is False

    def test_validate_port_invalid_type(self, validator):
        result = validator.validate_port([80])
        assert result.valid is False

    # --- validate_path ---

    def test_validate_path_valid(self, validator):
        result = validator.validate_path("/tmp/output.txt")
        assert result.valid is True

    def test_validate_path_empty(self, validator):
        result = validator.validate_path("")
        assert result.valid is False

    def test_validate_path_traversal(self, validator):
        result = validator.validate_path("../../etc/passwd")
        assert result.valid is False
        assert "路径遍历" in result.errors[0]

    def test_validate_path_null_byte(self, validator):
        result = validator.validate_path("file.txt\x00.jpg")
        assert result.valid is False
        assert "空字节" in result.errors[0]

    def test_validate_path_url_encoded_traversal(self, validator):
        result = validator.validate_path("%2e%2e%2f%2e%2e%2fetc/passwd")
        assert result.valid is False

    # --- sanitize_string ---

    def test_sanitize_normal(self, validator):
        assert validator.sanitize_string("hello world") == "hello world"

    def test_sanitize_control_chars(self, validator):
        result = validator.sanitize_string("hello\x00\x08world")
        assert "\x00" not in result
        assert "\x08" not in result

    def test_sanitize_truncate(self, validator):
        result = validator.sanitize_string("a" * 500, max_length=100)
        assert len(result) == 100

    def test_sanitize_allowed_chars(self, validator):
        result = validator.sanitize_string(
            "abc123!@#", allowed_chars="a-zA-Z0-9"
        )
        assert result == "abc123"


# ==================== RateLimiter 测试 ====================


class TestRateLimiter:
    """RateLimiter 测试"""

    @pytest.fixture
    def limiter(self):
        return RateLimiter(RateLimitConfig(
            requests_per_minute=5,
            requests_per_hour=100,
            burst_limit=3,
        ))

    def test_allow_first_request(self, limiter):
        allowed, reason = limiter.check("test")
        assert allowed is True

    def test_burst_limit(self, limiter):
        # 连续发送，应该在 burst_limit 后被限制
        for _ in range(3):
            allowed, _ = limiter.check("test")
            assert allowed is True

        allowed, reason = limiter.check("test")
        assert allowed is False
        assert "突发" in reason

    def test_different_keys_independent(self, limiter):
        for _ in range(3):
            limiter.check("key1")

        # key2 不受 key1 影响
        allowed, _ = limiter.check("key2")
        assert allowed is True

    def test_get_remaining(self, limiter):
        limiter.check("test")
        remaining = limiter.get_remaining("test")
        assert remaining["minute"] == 4  # 5 - 1
        assert remaining["hour"] == 99  # 100 - 1

    def test_minute_limit(self):
        limiter = RateLimiter(RateLimitConfig(
            requests_per_minute=3,
            requests_per_hour=1000,
            burst_limit=100,  # 高突发限制，只测每分钟限制
        ))

        for _ in range(3):
            allowed, _ = limiter.check("test")
            assert allowed is True

        allowed, reason = limiter.check("test")
        assert allowed is False
        assert "每分钟" in reason


# ==================== OperationAuthorizer 测试 ====================


class TestOperationAuthorizer:
    """OperationAuthorizer 测试"""

    @pytest.fixture
    def authorizer(self):
        return OperationAuthorizer(max_risk=RiskLevel.CRITICAL)

    def test_safe_operation_allowed(self, authorizer):
        allowed, _ = authorizer.check_authorization("dns_lookup")
        assert allowed is True

    def test_low_risk_allowed(self, authorizer):
        allowed, _ = authorizer.check_authorization("port_scan")
        assert allowed is True

    def test_medium_risk_allowed(self, authorizer):
        allowed, _ = authorizer.check_authorization("vuln_scan")
        assert allowed is True

    def test_high_risk_allowed(self, authorizer):
        allowed, _ = authorizer.check_authorization("exploit")
        assert allowed is True

    def test_critical_risk_denied(self, authorizer):
        allowed, reason = authorizer.check_authorization("lateral_move")
        assert allowed is False
        assert "显式授权" in reason

    def test_critical_after_authorization(self, authorizer):
        authorizer.authorize_operation("lateral_move")
        allowed, _ = authorizer.check_authorization("lateral_move")
        assert allowed is True

    def test_revoke_authorization(self, authorizer):
        authorizer.authorize_operation("lateral_move")
        authorizer.revoke_operation("lateral_move")
        allowed, _ = authorizer.check_authorization("lateral_move")
        assert allowed is False

    def test_max_risk_restriction(self):
        authorizer = OperationAuthorizer(max_risk=RiskLevel.LOW)
        allowed, reason = authorizer.check_authorization("vuln_scan")
        assert allowed is False
        assert "风险等级" in reason

    def test_get_risk_level(self, authorizer):
        assert authorizer.get_risk_level("dns_lookup") == RiskLevel.SAFE
        assert authorizer.get_risk_level("exploit") == RiskLevel.HIGH
        assert authorizer.get_risk_level("unknown_op") == RiskLevel.MEDIUM


# ==================== MCPSecurityMiddleware 测试 ====================


class TestMCPSecurityMiddleware:
    """MCPSecurityMiddleware 集成测试"""

    @pytest.fixture
    def security(self):
        return MCPSecurityMiddleware(
            rate_limit_config=RateLimitConfig(
                requests_per_minute=10,
                burst_limit=5,
            ),
            max_risk=RiskLevel.CRITICAL,
        )

    def test_validate_target(self, security):
        result = security.validate_target("192.168.1.1")
        assert result.valid is True

    def test_validate_port(self, security):
        result = security.validate_port(80)
        assert result.valid is True

    def test_check_rate_limit(self, security):
        allowed, _ = security.check_rate_limit("scan")
        assert allowed is True

    def test_check_operation(self, security):
        allowed, _ = security.check_operation("port_scan")
        assert allowed is True

    def test_authorize_critical(self, security):
        allowed, _ = security.check_operation("lateral_move")
        assert allowed is False

        security.authorize("lateral_move")
        allowed, _ = security.check_operation("lateral_move")
        assert allowed is True

    def test_sanitize(self, security):
        result = security.sanitize("test\x00\x08value")
        assert "\x00" not in result
        assert "test" in result

    def test_secure_tool_decorator(self, security):
        """测试 secure_tool 装饰器"""

        @security.secure_tool(operation="port_scan", rate_limit_key="scan")
        async def mock_scan(target: str):
            return {"success": True, "target": target}

        # 装饰器应该返回可调用对象
        import asyncio
        assert callable(mock_scan)


# ==================== 线程安全测试 ====================


class TestThreadSafety:
    """线程安全测试"""

    def test_concurrent_rate_limiting(self):
        limiter = RateLimiter(RateLimitConfig(
            requests_per_minute=100,
            burst_limit=50,
        ))

        results = []

        def make_request():
            allowed, _ = limiter.check("concurrent_test")
            results.append(allowed)

        threads = [threading.Thread(target=make_request) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 20
        # 至少一部分应该通过
        assert any(r is True for r in results)

    def test_concurrent_authorization(self):
        authorizer = OperationAuthorizer(max_risk=RiskLevel.CRITICAL)
        errors = []

        def authorize_and_check():
            try:
                authorizer.authorize_operation("lateral_move")
                allowed, _ = authorizer.check_authorization("lateral_move")
                assert allowed is True
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=authorize_and_check) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
