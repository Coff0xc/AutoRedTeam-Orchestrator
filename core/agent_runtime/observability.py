"""Local observability summaries for agent runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

from core.agent_runtime.models import AgentRunState


@dataclass
class ObservabilitySnapshot:
    """Compact runtime metrics suitable for logs, dashboards, or reports."""

    run_id: str
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"run_id": self.run_id, "metrics": self.metrics}


def build_observability_snapshot(run_state: AgentRunState) -> ObservabilitySnapshot:
    """Build a local metrics snapshot without exporting telemetry."""
    summary = run_state.summary()
    actions = [action for task in run_state.flow.tasks for action in task.actions]
    risk_counts: Dict[str, int] = {}
    network_counts: Dict[str, int] = {}
    for action in actions:
        risk = action.policy.risk_level.value
        network = action.policy.network_policy
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        network_counts[network] = network_counts.get(network, 0) + 1

    return ObservabilitySnapshot(
        run_id=run_state.run_id,
        metrics={
            **summary,
            "risk_counts": risk_counts,
            "network_policy_counts": network_counts,
        },
    )
