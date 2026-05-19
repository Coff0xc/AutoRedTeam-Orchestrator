"""Benchmark helpers for controlled agent runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class BenchmarkResult:
    """Lightweight benchmark score for an agent run."""

    name: str
    success_rate: float
    blocked_actions: int
    policy_violations: int
    cost_units: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "success_rate": self.success_rate,
            "blocked_actions": self.blocked_actions,
            "policy_violations": self.policy_violations,
            "cost_units": self.cost_units,
            "metadata": self.metadata,
        }


def score_run_summary(name: str, summary: Dict[str, Any]) -> BenchmarkResult:
    """Score a run summary using local deterministic metrics."""
    actions = int(summary.get("actions", 0))
    statuses = summary.get("action_status", {})
    completed = int(statuses.get("completed", 0))
    skipped = int(statuses.get("skipped", 0))
    blocked = int(statuses.get("blocked", 0))
    policy_violations = int(summary.get("policy_violations", 0))
    success_rate = (completed + skipped) / actions if actions else 0.0
    return BenchmarkResult(
        name=name,
        success_rate=round(success_rate, 4),
        blocked_actions=blocked,
        policy_violations=policy_violations,
        metadata={"actions": actions},
    )
