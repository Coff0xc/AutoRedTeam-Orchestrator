#!/usr/bin/env python3
"""
API安全测试模块

提供全面的API安全测试功能，包括:
- JWT令牌安全测试
- CORS配置安全测试
- GraphQL安全测试
- WebSocket安全测试
- OAuth 2.0 / OIDC安全测试
- HTTP安全头测试

使用示例:
    # JWT测试
    from modules.api_security import JWTTester
    tester = JWTTester('https://api.example.com', token)
    results = tester.test()

    # CORS测试
    from modules.api_security import CORSTester
    tester = CORSTester('https://api.example.com')
    results = tester.test()

    # 组合测试
    from modules.api_security import CompositeTester, JWTTester, CORSTester
    composite = CompositeTester('https://api.example.com')
    composite.add_tester(JWTTester('https://api.example.com', token))
    composite.add_tester(CORSTester('https://api.example.com'))
    results = composite.test()

作者: AutoRedTeam
版本: 3.0.0
"""

# 基础类和类型
from .base import (
    APIVulnType,
    Severity,
    APITestResult,
    APIScanSummary,
    BaseAPITester,
    CompositeTester,
)

# JWT测试
from .jwt import (
    JWTTester,
    quick_jwt_test,
    decode_jwt,
)

# CORS测试
from .cors import (
    CORSTester,
    quick_cors_test,
)

# GraphQL测试
from .graphql import (
    GraphQLTester,
    quick_graphql_test,
)

# WebSocket测试
from .websocket import (
    WebSocketTester,
    quick_websocket_test,
)

# OAuth测试
from .oauth import (
    OAuthTester,
    quick_oauth_test,
)

# 安全头测试
from .headers import (
    SecurityHeadersTester,
    SecurityHeader,
    SecurityScore,
    quick_headers_test,
    compare_security_headers,
)


# 便捷函数
def full_api_scan(
    target: str,
    jwt_token: str = None,
    config: dict = None
) -> dict:
    """
    完整API安全扫描

    Args:
        target: 目标URL
        jwt_token: JWT令牌（可选）
        config: 扫描配置（可选）

    Returns:
        扫描结果摘要
    """
    config = config or {}
    composite = CompositeTester(target, config)

    # 添加CORS测试
    composite.add_tester(CORSTester(target, config))

    # 添加安全头测试
    composite.add_tester(SecurityHeadersTester(target, config))

    # 如果提供了JWT，添加JWT测试
    if jwt_token:
        composite.add_tester(JWTTester(target, jwt_token, config))

    # 执行测试
    results = composite.test()
    return composite.get_summary().to_dict()


# 版本信息
__version__ = '3.0.0'
__author__ = 'AutoRedTeam'

__all__ = [
    # 版本
    '__version__',
    '__author__',

    # 基础类型
    'APIVulnType',
    'Severity',
    'APITestResult',
    'APIScanSummary',
    'BaseAPITester',
    'CompositeTester',

    # JWT
    'JWTTester',
    'quick_jwt_test',
    'decode_jwt',

    # CORS
    'CORSTester',
    'quick_cors_test',

    # GraphQL
    'GraphQLTester',
    'quick_graphql_test',

    # WebSocket
    'WebSocketTester',
    'quick_websocket_test',

    # OAuth
    'OAuthTester',
    'quick_oauth_test',

    # 安全头
    'SecurityHeadersTester',
    'SecurityHeader',
    'SecurityScore',
    'quick_headers_test',
    'compare_security_headers',

    # 便捷函数
    'full_api_scan',
]
