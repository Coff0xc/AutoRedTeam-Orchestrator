"""Models for static call-chain context expansion."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class CodeFunction:
    """One local Python function discovered by AST parsing."""

    function_id: str
    qualified_name: str
    file_path: str
    line_start: int
    line_end: int
    parameters: List[str] = field(default_factory=list)
    decorators: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)
    risk_terms: List[str] = field(default_factory=list)
    source_terms: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_id": self.function_id,
            "qualified_name": self.qualified_name,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "parameters": self.parameters,
            "decorators": self.decorators,
            "calls": self.calls,
            "risk_terms": self.risk_terms,
            "source_terms": self.source_terms,
        }


@dataclass
class CallEdge:
    """Resolved local call edge."""

    caller_id: str
    callee_id: str
    call_name: str
    file_path: str
    line: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "caller_id": self.caller_id,
            "callee_id": self.callee_id,
            "call_name": self.call_name,
            "file_path": self.file_path,
            "line": self.line,
        }


@dataclass
class ConfidenceScore:
    """Deterministic confidence for the expanded security context."""

    value: float
    level: str
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": round(self.value, 3),
            "level": self.level,
            "reasons": self.reasons,
        }


@dataclass
class CodeContextResult:
    """Result of static call-chain context expansion."""

    root_path: str
    seed_function: CodeFunction | None
    max_depth: int
    functions_scanned: int = 0
    edges_scanned: int = 0
    context_functions: List[CodeFunction] = field(default_factory=list)
    call_edges: List[CallEdge] = field(default_factory=list)
    confidence: ConfidenceScore = field(
        default_factory=lambda: ConfidenceScore(value=0.0, level="none")
    )
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": True,
            "root_path": self.root_path,
            "summary": {
                "functions_scanned": self.functions_scanned,
                "edges_scanned": self.edges_scanned,
                "context_functions": len(self.context_functions),
                "context_edges": len(self.call_edges),
                "max_depth": self.max_depth,
            },
            "seed_function": self.seed_function.to_dict() if self.seed_function else None,
            "context_functions": [function.to_dict() for function in self.context_functions],
            "call_edges": [edge.to_dict() for edge in self.call_edges],
            "confidence": self.confidence.to_dict(),
            "warnings": self.warnings,
        }
