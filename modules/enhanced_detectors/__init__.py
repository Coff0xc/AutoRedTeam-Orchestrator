#!/usr/bin/env python3
"""
增强检测器模块
提供: JWT增强检测、CORS绕过测试、安全头评分
"""

from .jwt_enhanced import JWTSecurityTester, JWTVulnType
from .cors_enhanced import CORSEnhancedTester
from .security_headers_scorer import SecurityHeadersScorer

__all__ = [
    'JWTSecurityTester',
    'JWTVulnType',
    'CORSEnhancedTester',
    'SecurityHeadersScorer',
]
