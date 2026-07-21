"""Serializable run views for Web/API surfaces."""

from __future__ import annotations

from typing import Any, Dict, List

from core.agent_runtime.models import AgentRunState
from core.agent_runtime.observability import build_observability_snapshot


def build_run_view(run_state: AgentRunState) -> Dict[str, Any]:
    """Build a compact run view suitable for local Web/API endpoints."""
    actions = [action for task in run_state.flow.tasks for action in task.actions]
    gates = [gate for gate in run_state.human_gates if not gate.approved]
    return {
        "run_id": run_state.run_id,
        "mode": run_state.mode.value,
        "flow": {
            "id": run_state.flow.flow_id,
            "name": run_state.flow.name,
            "tasks": len(run_state.flow.tasks),
        },
        "summary": run_state.summary(),
        "observability": build_observability_snapshot(run_state).to_dict(),
        "pending_gates": [gate.to_dict() for gate in gates],
        "recent_trace": [event.to_dict() for event in run_state.trace[-10:]],
        "actions": [
            {
                "action_id": action.action_id,
                "name": action.name,
                "kind": action.kind.value,
                "status": action.status.value,
                "risk_level": action.policy.risk_level.value,
                "network_policy": action.policy.network_policy,
                "requires_human_gate": action.policy.requires_human_gate,
            }
            for action in actions
        ],
    }


def build_runs_index(run_states: List[AgentRunState]) -> Dict[str, Any]:
    """Build a list view for multiple local run states."""
    return {
        "success": True,
        "count": len(run_states),
        "runs": [
            {
                "run_id": state.run_id,
                "name": state.flow.name,
                "mode": state.mode.value,
                "summary": state.summary(),
            }
            for state in run_states
        ],
    }
