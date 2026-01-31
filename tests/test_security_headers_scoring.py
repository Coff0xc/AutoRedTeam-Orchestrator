"""Security Headers 评分测试"""

import pytest

# 模块级别标记 - 标识为单元测试和安全测试
pytestmark = [pytest.mark.unit, pytest.mark.security]

from modules.api_security.headers import SecurityHeadersTester


def test_security_headers_scoring_quality():
    tester = SecurityHeadersTester("https://example.com")
    tester._response_headers = {
        "strict-transport-security": "max-age=1000",
        "content-security-policy": "default-src * 'unsafe-inline'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "SAMEORIGIN",
    }

    tester._calculate_security_score()
    score = tester.get_security_score()

    hsts = score.headers["Strict-Transport-Security"]
    csp = score.headers["Content-Security-Policy"]
    xcto = score.headers["X-Content-Type-Options"]

    assert hsts.score < hsts.max_score
    assert csp.score < csp.max_score
    assert xcto.score == xcto.max_score
    assert "Strict-Transport-Security" in score.weak_headers
    assert "Content-Security-Policy" in score.weak_headers
