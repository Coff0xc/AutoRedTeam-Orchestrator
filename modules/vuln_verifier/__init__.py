#!/usr/bin/env python3
"""
漏洞验证模块 (vuln_verifier)

模块结构:
- models.py: 数据类 (VerificationResult, StatisticalVerification)
- base.py: 基础验证器 (BaseVerifier) 和完整验证器 (VulnerabilityVerifier)
- sqli.py: SQLi 验证混入 (SQLiVerifierMixin)
- xss.py: XSS 验证混入 (XSSVerifierMixin)
- lfi_rce.py: LFI/RCE 验证混入 (LFIRCEVerifierMixin)
- ssrf.py: SSRF 验证混入 (SSRFVerifierMixin)
- statistical.py: 统计学验证器 (StatisticalVerifier)
- oob.py: OOB 验证器 (OOBIntegratedVerifier)

使用示例:
    from modules.vuln_verifier import VulnerabilityVerifier, VerificationResult
    
    verifier = VulnerabilityVerifier(timeout=10)
    result = verifier.verify("http://example.com?id=1", "id", "sqli")
    
    # 或直接使用特定验证
    from modules.vuln_verifier import StatisticalVerifier
    stat_verifier = StatisticalVerifier(sample_size=10)
"""

# 数据模型
from .models import StatisticalVerification, VerificationResult

# 基础类和主验证器
from .base import BaseVerifier, VulnerabilityVerifier, get_vulnerability_verifier_class

# 验证 Mixin（高级用户）
from .sqli import SQLiVerifierMixin
from .xss import XSSVerifierMixin
from .lfi_rce import LFIRCEVerifierMixin
from .ssrf import SSRFVerifierMixin

# 统计验证
from .statistical import StatisticalVerifier, verify_vuln_statistically

# OOB 验证
from .oob import OOBIntegratedVerifier, verify_with_oob

__all__ = [
    # 数据模型
    "VerificationResult",
    "StatisticalVerification",
    # 主验证器
    "VulnerabilityVerifier",
    "BaseVerifier",
    "get_vulnerability_verifier_class",
    # Mixin 类
    "SQLiVerifierMixin",
    "XSSVerifierMixin",
    "LFIRCEVerifierMixin",
    "SSRFVerifierMixin",
    # 统计验证
    "StatisticalVerifier",
    "verify_vuln_statistically",
    # OOB 验证
    "OOBIntegratedVerifier",
    "verify_with_oob",
]