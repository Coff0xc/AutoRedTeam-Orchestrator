"""证据评估与门禁（P2 核心接口包）。

对外契约：把验证器输出归一化成证据、按严格判据评估 finding、并在证据不足时
降级/标注 finding。上层（编排、MCP handler、报告）只依赖本包符号。
"""

from core.evidence.gate import (
    PROVENANCE_SOURCES,
    UNCONFIRMED_PREFIX,
    assess_finding,
    enforce_evidence_gate,
    evidence_from_verification,
)
from core.evidence.models import (
    CONFIDENCE_LEVELS,
    EVIDENCE_KINDS,
    EvidenceAssessment,
    EvidenceItem,
)

__all__ = [
    "EvidenceItem",
    "EvidenceAssessment",
    "evidence_from_verification",
    "assess_finding",
    "enforce_evidence_gate",
    "UNCONFIRMED_PREFIX",
    "PROVENANCE_SOURCES",
    "EVIDENCE_KINDS",
    "CONFIDENCE_LEVELS",
]
