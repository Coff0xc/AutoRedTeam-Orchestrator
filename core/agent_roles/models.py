"""Role and team models for multi-agent red-team planning.

These objects are policy descriptions only. They do not call models, tools,
shell commands, browsers, or external targets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.agent_runtime import Action, ActionKind, RiskLevel


RISK_ORDER = {
    RiskLevel.INFO: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MODERATE: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


class RoleKind(Enum):
    """Default agent roles used by the platform."""

    RESEARCHER = "researcher"
    PLANNER = "planner"
    EXECUTOR = "executor"
    VERIFIER = "verifier"
    CRITIC = "critic"
    REPORTER = "reporter"


@dataclass
class AgentRole:
    """Policy envelope for one agent role."""

    name: str
    kind: RoleKind
    goals: List[str] = field(default_factory=list)
    allowed_action_kinds: List[ActionKind] = field(default_factory=list)
    max_risk_level: RiskLevel = RiskLevel.MODERATE
    allowed_network_policies: List[str] = field(default_factory=lambda: ["deny"])
    requires_human_gate_for_high_risk: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.kind, str):
            self.kind = RoleKind(self.kind)
        if isinstance(self.max_risk_level, str):
            self.max_risk_level = RiskLevel(self.max_risk_level)
        self.allowed_action_kinds = [
            ActionKind(item) if isinstance(item, str) else item
            for item in self.allowed_action_kinds
        ]

    def validate_action(self, action: Action) -> List[str]:
        """Return policy issues for an action planned under this role."""
        issues: List[str] = []
        if self.allowed_action_kinds and action.kind not in self.allowed_action_kinds:
            issues.append("action_kind_not_allowed_for_role")
        if RISK_ORDER[action.policy.risk_level] > RISK_ORDER[self.max_risk_level]:
            issues.append("risk_level_exceeds_role_limit")
        if action.policy.network_policy not in self.allowed_network_policies:
            issues.append("network_policy_not_allowed_for_role")
        if (
            self.requires_human_gate_for_high_risk
            and action.policy.risk_level.is_high_risk()
            and not action.policy.requires_human_gate
        ):
            issues.append("high_risk_action_missing_human_gate")
        return issues

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind.value,
            "goals": self.goals,
            "allowed_action_kinds": [kind.value for kind in self.allowed_action_kinds],
            "max_risk_level": self.max_risk_level.value,
            "allowed_network_policies": self.allowed_network_policies,
            "requires_human_gate_for_high_risk": self.requires_human_gate_for_high_risk,
            "metadata": self.metadata,
        }


@dataclass
class AgentTeam:
    """Collection of role policies for a workflow."""

    roles: List[AgentRole] = field(default_factory=list)

    def get(self, kind: RoleKind | str) -> Optional[AgentRole]:
        if isinstance(kind, str):
            kind = RoleKind(kind)
        for role in self.roles:
            if role.kind == kind:
                return role
        return None

    def validate_action(self, kind: RoleKind | str, action: Action) -> List[str]:
        role = self.get(kind)
        if not role:
            return ["role_not_found"]
        return role.validate_action(action)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "roles": [role.to_dict() for role in self.roles],
            "count": len(self.roles),
        }


def build_default_team() -> AgentTeam:
    """Build the default role set for dry-run-first red-team workflows."""
    return AgentTeam(
        roles=[
            AgentRole(
                name="Researcher",
                kind=RoleKind.RESEARCHER,
                goals=["Collect local context", "Summarize constraints"],
                allowed_action_kinds=[ActionKind.MODEL_CALL, ActionKind.TOOL_CALL, ActionKind.REPORT],
                max_risk_level=RiskLevel.MODERATE,
                allowed_network_policies=["deny", "read-only"],
            ),
            AgentRole(
                name="Planner",
                kind=RoleKind.PLANNER,
                goals=["Break scenarios into tasks", "Attach risk policy to every action"],
                allowed_action_kinds=[ActionKind.MODEL_CALL, ActionKind.TOOL_CALL, ActionKind.REPORT],
                max_risk_level=RiskLevel.HIGH,
                allowed_network_policies=["deny", "read-only"],
            ),
            AgentRole(
                name="Executor",
                kind=RoleKind.EXECUTOR,
                goals=["Run approved actions through sandbox policy"],
                allowed_action_kinds=[
                    ActionKind.TOOL_CALL,
                    ActionKind.SHELL,
                    ActionKind.BROWSER,
                    ActionKind.HUMAN_GATE,
                ],
                max_risk_level=RiskLevel.CRITICAL,
                allowed_network_policies=["deny", "scoped"],
            ),
            AgentRole(
                name="Verifier",
                kind=RoleKind.VERIFIER,
                goals=["Check evidence", "Score results", "Reduce false positives"],
                allowed_action_kinds=[ActionKind.TOOL_CALL, ActionKind.MODEL_CALL, ActionKind.REPORT],
                max_risk_level=RiskLevel.MODERATE,
                allowed_network_policies=["deny", "read-only"],
            ),
            AgentRole(
                name="Critic",
                kind=RoleKind.CRITIC,
                goals=["Find unsafe plans", "Enforce policy gates"],
                allowed_action_kinds=[ActionKind.MODEL_CALL, ActionKind.REPORT],
                max_risk_level=RiskLevel.LOW,
                allowed_network_policies=["deny"],
            ),
            AgentRole(
                name="Reporter",
                kind=RoleKind.REPORTER,
                goals=["Produce findings", "Export evidence and benchmark summaries"],
                allowed_action_kinds=[ActionKind.REPORT],
                max_risk_level=RiskLevel.LOW,
                allowed_network_policies=["deny"],
            ),
        ]
    )
