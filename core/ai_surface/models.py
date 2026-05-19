"""Models for static AI tool-surface analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class SurfaceRiskLevel(Enum):
    """Risk levels used by the static surface scanner."""

    INFO = "info"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


RISK_ORDER = {
    SurfaceRiskLevel.INFO: 0,
    SurfaceRiskLevel.LOW: 1,
    SurfaceRiskLevel.MODERATE: 2,
    SurfaceRiskLevel.HIGH: 3,
    SurfaceRiskLevel.CRITICAL: 4,
}


def max_risk(left: SurfaceRiskLevel, right: SurfaceRiskLevel) -> SurfaceRiskLevel:
    """Return the higher risk level."""
    return left if RISK_ORDER[left] >= RISK_ORDER[right] else right


@dataclass
class SurfaceFinding:
    """One MCP tool discovered by static analysis."""

    tool_name: str
    file_path: str
    line: int
    risk_level: SurfaceRiskLevel
    auth_level: str = "none"
    decorators: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    risk_terms: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "file_path": self.file_path,
            "line": self.line,
            "risk_level": self.risk_level.value,
            "auth_level": self.auth_level,
            "decorators": self.decorators,
            "parameters": self.parameters,
            "risk_terms": self.risk_terms,
            "issues": self.issues,
            "recommendations": self.recommendations,
            "description": self.description,
        }


@dataclass
class SurfaceScanResult:
    """Static scan result for a handler tree."""

    root_path: str
    scanned_files: int = 0
    findings: List[SurfaceFinding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def risk_counts(self) -> Dict[str, int]:
        counts = {level.value: 0 for level in SurfaceRiskLevel}
        for finding in self.findings:
            counts[finding.risk_level.value] += 1
        return counts

    def issue_count(self) -> int:
        return sum(len(finding.issues) for finding in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": True,
            "root_path": self.root_path,
            "summary": {
                "scanned_files": self.scanned_files,
                "tools_scanned": len(self.findings),
                "risk_counts": self.risk_counts(),
                "issue_count": self.issue_count(),
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "warnings": self.warnings,
        }
