#!/usr/bin/env python3
"""
Payload 类型定义模块 - 统一的数据类型

整合自:
- smart_payload_engine.py: PayloadStats, TargetProfile
- smart_payload_selector.py: PayloadStats
- adaptive_payload_engine.py: PayloadResult
"""

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class VulnType(Enum):
    """漏洞类型枚举"""

    SQLI = "sqli"
    XSS = "xss"
    LFI = "lfi"
    RCE = "rce"
    SSRF = "ssrf"
    XXE = "xxe"
    CSRF = "csrf"
    SSTI = "ssti"
    NOSQL = "nosql"
    GRAPHQL = "graphql"
    IDOR = "idor"
    DESERIALIZATION = "deserialization"


class PayloadCategory(Enum):
    """Payload 分类枚举"""

    # SQLi
    ERROR_BASED = "error_based"
    UNION_BASED = "union_based"
    BLIND_TIME = "blind_time"
    BLIND_BOOL = "blind_bool"
    AUTH_BYPASS = "auth_bypass"

    # XSS
    BASIC = "basic"
    EVENT_HANDLER = "event_handler"
    ENCODED = "encoded"
    DOM_BASED = "dom_based"
    CSP_BYPASS = "csp_bypass"
    WAF_BYPASS = "waf_bypass"

    # LFI
    LINUX = "linux"
    WINDOWS = "windows"
    PHP_WRAPPER = "php_wrapper"

    # SSRF
    CLOUD_METADATA = "cloud_metadata"
    PROTOCOL = "protocol"
    BYPASS = "bypass"

    # RCE
    COMMAND_INJECTION = "command_injection"
    TEMPLATE_INJECTION = "template_injection"
    LOG4J = "log4j"

    # 通用
    ALL = "all"


@dataclass
class PayloadStats:
    """
    统一的 Payload 统计信息

    整合自三个不同的实现，保留所有有用的字段
    """

    # 基础统计
    total_uses: int = 0
    success_count: int = 0
    fail_count: int = 0
    blocked_count: int = 0

    # 时间相关
    last_used: str = ""
    avg_response_time: float = 0.0
    total_time: float = 0.0

    @property
    def success_rate(self) -> float:
        """计算成功率"""
        total = self.success_count + self.fail_count
        if total == 0:
            return 0.5  # 未使用过的 Payload 默认 50%
        return self.success_count / total

    def update(self, success: bool, blocked: bool = False, response_time: float = 0.0):
        """更新统计信息"""
        self.total_uses += 1
        if success:
            self.success_count += 1
        else:
            self.fail_count += 1

        if blocked:
            self.blocked_count += 1

        if response_time > 0:
            self.total_time += response_time
            self.avg_response_time = self.total_time / self.total_uses

        from datetime import datetime

        self.last_used = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（用于序列化）"""
        return {
            "total_uses": self.total_uses,
            "success_count": self.success_count,
            "fail_count": self.fail_count,
            "blocked_count": self.blocked_count,
            "last_used": self.last_used,
            "avg_response_time": self.avg_response_time,
            "total_time": self.total_time,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PayloadStats":
        """从字典创建实例"""
        return cls(
            total_uses=data.get("total_uses", 0),
            success_count=data.get("success_count", 0),
            fail_count=data.get("fail_count", 0),
            blocked_count=data.get("blocked_count", 0),
            last_used=data.get("last_used", ""),
            avg_response_time=data.get("avg_response_time", 0.0),
            total_time=data.get("total_time", 0.0),
        )


@dataclass
class PayloadResult:
    """
    Payload 执行结果

    整合自 adaptive_payload_engine.py
    """

    payload: str
    success: bool
    blocked: bool = False
    response_time: float = 0.0
    evidence: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "payload": self.payload,
            "success": self.success,
            "blocked": self.blocked,
            "response_time": self.response_time,
            "evidence": self.evidence,
            "error": self.error,
        }


@dataclass
class ScoredPayload:
    """带评分的 Payload"""

    payload: str
    score: float
    category: Optional[str] = None
    mutation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "payload": self.payload,
            "score": round(self.score, 2),
            "category": self.category,
            "mutation": self.mutation,
        }


def get_payload_hash(payload: str, length: int = 12) -> str:
    """
    获取 Payload 的哈希值（用于统计键）

    Args:
        payload: 原始 Payload
        length: 哈希长度（默认12位）

    Returns:
        MD5 哈希的前 N 位
    """
    return hashlib.md5(payload.encode()).hexdigest()[:length]


def get_payload_key(vuln_type: str, payload: str) -> str:
    """
    生成 Payload 唯一键

    Args:
        vuln_type: 漏洞类型
        payload: Payload 内容

    Returns:
        格式: "{vuln_type}:{hash}"
    """
    return f"{vuln_type}:{get_payload_hash(payload, 8)}"
