"""Sandbox policy models for agent runtime planning.

This module intentionally does not start containers or execute commands. It
captures the policy an executor must satisfy before active work is allowed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class SandboxPolicy:
    """Execution isolation policy for a planned action."""

    enabled: bool = False
    provider: str = "none"
    network_policy: str = "deny"
    allowed_tools: List[str] = field(default_factory=list)
    artifact_policy: str = "metadata-only"
    timeout_seconds: int = 300
    metadata: Dict[str, Any] = field(default_factory=dict)

    def allows_network(self) -> bool:
        return self.network_policy not in {"deny", "none", "disabled"}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "network_policy": self.network_policy,
            "allowed_tools": self.allowed_tools,
            "artifact_policy": self.artifact_policy,
            "timeout_seconds": self.timeout_seconds,
            "metadata": self.metadata,
        }
