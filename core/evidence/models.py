"""证据评估与门禁的数据模型。

本模块只定义可序列化数据结构，不依赖任何验证器实现，供门禁与上层
（编排、MCP handler、报告）共享。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

# 允许的证据类型与置信度取值，供 duck typing 归一化时校验。
EVIDENCE_KINDS = frozenset(
    {
        "statistical",
        "oob_callback",
        "replay",
        "http_response",
        "command",
        "unknown",
    }
)

CONFIDENCE_LEVELS = frozenset({"high", "medium", "low", "false_positive"})


@dataclass
class EvidenceItem:
    """单条证据。

    一条证据对应一次可复核的观测（统计验证、OOB 回连、重放、HTTP 响应等）。
    字段保持扁平，避免上层为了取值反复解包嵌套结构。
    """

    kind: str  # "statistical" | "oob_callback" | "replay" | "http_response" | "command" | "unknown"
    method: str = ""  # 如 "time_based_sqli"
    summary: str = ""  # 人可读摘要
    payload: str = ""
    url: str = ""
    response_code: int = 0
    response_time: float = 0.0
    confidence: str = ""  # high/medium/low/false_positive
    observed_at: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转成可 JSON 序列化的字典。"""
        return {
            "kind": self.kind,
            "method": self.method,
            "summary": self.summary,
            "payload": self.payload,
            "url": self.url,
            "response_code": self.response_code,
            "response_time": self.response_time,
            "confidence": self.confidence,
            "observed_at": self.observed_at,
            "raw": self.raw,
        }


@dataclass
class EvidenceAssessment:
    """对一个 finding 的证据状态判定结果。

    status 语义：
    - "verified"：有可复核证据且达到置信度门槛
    - "contradicted"：验证明确报告"不存在漏洞"（verified=False / false_positive）
    - "unverified"：证据不足或置信度不够，需要补充验证
    """

    status: str  # "verified" | "unverified" | "contradicted"
    confidence: str = ""  # high/medium/low/false_positive/""
    evidence: List[EvidenceItem] = field(default_factory=list)
    missing_checks: List[str] = field(default_factory=list)
    reason: str = ""

    def accepted(self) -> bool:
        """是否通过证据门禁（只有 verified 才算通过）。"""
        return self.status == "verified"

    def to_dict(self) -> Dict[str, Any]:
        """转成可 JSON 序列化的字典。"""
        return {
            "status": self.status,
            "confidence": self.confidence,
            "evidence": [item.to_dict() for item in self.evidence],
            "missing_checks": list(self.missing_checks),
            "reason": self.reason,
            "accepted": self.accepted(),
        }
