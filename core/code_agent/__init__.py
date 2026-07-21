"""Static code-agent analysis primitives.

This package is intentionally read-only. It parses local Python source with AST,
builds a small call graph, expands context around a seed function, and assigns a
deterministic confidence score. It does not call models, tools, shells, or
external targets.
"""

from core.code_agent.analyzer import expand_code_context
from core.code_agent.models import (
    CallEdge,
    CodeContextResult,
    CodeFunction,
    ConfidenceScore,
)

__all__ = [
    "CallEdge",
    "CodeContextResult",
    "CodeFunction",
    "ConfidenceScore",
    "expand_code_context",
]
