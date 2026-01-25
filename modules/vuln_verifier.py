#!/usr/bin/env python3
"""
漏洞验证模块 - 兼容层

此文件保留用于向后兼容。实际实现已拆分到 modules/vuln_verifier/ 子模块。

重构说明:
- 原始文件: 1645 行
- 拆分为 8 个子模块:
  - models.py: 数据类定义 (VerificationResult, StatisticalVerification)
  - base.py: 基础验证器类 (BaseVerifier, VulnerabilityVerifier)
  - sqli.py: SQL注入验证 Mixin
  - xss.py: XSS验证 Mixin
  - lfi_rce.py: LFI/RCE验证 Mixin
  - ssrf.py: SSRF验证 Mixin
  - statistical.py: 统计学验证器
  - oob.py: OOB带外验证器

使用方式（保持不变）:
    from modules.vuln_verifier import VulnerabilityVerifier, StatisticalVerifier

迁移建议:
    # 旧方式（继续支持）
    from modules.vuln_verifier import VulnerabilityVerifier
    
    # 新方式（推荐）
    from modules.vuln_verifier import VulnerabilityVerifier
    from modules.vuln_verifier.statistical import StatisticalVerifier
    from modules.vuln_verifier.oob import OOBIntegratedVerifier
"""

# 从子模块导入所有公开接口
from modules.vuln_verifier.models import (
    VerificationResult,
    StatisticalVerification,
)

from modules.vuln_verifier.base import (
    BaseVerifier,
    VulnerabilityVerifier,
    get_vulnerability_verifier_class,
)

from modules.vuln_verifier.sqli import SQLiVerifierMixin
from modules.vuln_verifier.xss import XSSVerifierMixin
from modules.vuln_verifier.lfi_rce import LFIRCEVerifierMixin
from modules.vuln_verifier.ssrf import SSRFVerifierMixin

from modules.vuln_verifier.statistical import (
    StatisticalVerifier,
    verify_vuln_statistically,
)

from modules.vuln_verifier.oob import (
    OOBIntegratedVerifier,
    verify_with_oob,
)

# 公开接口
__all__ = [
    # 数据类
    "VerificationResult",
    "StatisticalVerification",
    # 基础类
    "BaseVerifier",
    "VulnerabilityVerifier",
    "get_vulnerability_verifier_class",
    # Mixin类
    "SQLiVerifierMixin",
    "XSSVerifierMixin",
    "LFIRCEVerifierMixin",
    "SSRFVerifierMixin",
    # 高级验证器
    "StatisticalVerifier",
    "OOBIntegratedVerifier",
    # 便捷函数
    "verify_vuln_statistically",
    "verify_with_oob",
]
