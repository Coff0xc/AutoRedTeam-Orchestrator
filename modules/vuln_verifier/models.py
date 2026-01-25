#!/usr/bin/env python3
"""
漏洞验证数据模型

包含:
- VerificationResult: 验证结果数据类
- StatisticalVerification: 统计验证结果数据类
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List


@dataclass
class VerificationResult:
    """验证结果"""
    vuln_type: str
    payload: str
    url: str
    is_vulnerable: bool
    confidence: str  # high, medium, low, false_positive
    evidence: str
    response_time: float
    response_code: int
    response_length: int
    verification_method: str
    recommendation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class StatisticalVerification:
    """统计验证结果"""
    vuln_type: str
    url: str
    param: str
    payload: str
    rounds: int
    positive_count: int
    confidence_score: float  # 0-1
    is_confirmed: bool
    details: List[Dict] = field(default_factory=list)
    recommendation: str = ""