"""Safe runtime objects for agentic red-team workflows.

This module is intentionally execution-free. It models flows, tasks, actions,
artifacts, traces, and human gates so higher-level agents can plan work without
calling dangerous tooling directly.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class RunMode(Enum):
    """Execution mode for a run."""

    DRY_RUN = "dry-run"
    ACTIVE = "active"


class RiskLevel(Enum):
    """Risk level for an agent action."""

    INFO = "info"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"

    def is_high_risk(self) -> bool:
        return self in {RiskLevel.HIGH, RiskLevel.CRITICAL}


class ActionKind(Enum):
    """Supported action categories."""

    MODEL_CALL = "model_call"
    TOOL_CALL = "tool_call"
    SHELL = "shell"
    BROWSER = "browser"
    HUMAN_GATE = "human_gate"
    REPORT = "report"


class ActionStatus(Enum):
    """Lifecycle state for an action."""

    PENDING = "pending"
    BLOCKED = "blocked"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


def _now() -> str:
    return datetime.now().isoformat()


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _enum_value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


@dataclass
class ActionPolicy:
    """Policy attached to an action before any execution is considered."""

    risk_level: RiskLevel = RiskLevel.LOW
    requires_auth: bool = False
    requires_human_gate: bool = False
    allowed_in_dry_run: bool = True
    network_policy: str = "deny"
    artifact_policy: str = "metadata-only"
    cleanup_policy: str = "none"

    def __post_init__(self) -> None:
        if isinstance(self.risk_level, str):
            self.risk_level = RiskLevel(self.risk_level)

    def block_reason(self, mode: RunMode, human_approved: bool = False) -> Optional[str]:
        """Return why the action must not run, or None if policy allows it."""
        if isinstance(mode, str):
            mode = RunMode(mode)
        if mode == RunMode.DRY_RUN and not self.allowed_in_dry_run:
            return "Action is not allowed in dry-run mode"
        if self.requires_human_gate and not human_approved:
            return "Action requires human approval"
        if mode == RunMode.ACTIVE and self.risk_level.is_high_risk() and not human_approved:
            return "High-risk active action requires human approval"
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_level": self.risk_level.value,
            "requires_auth": self.requires_auth,
            "requires_human_gate": self.requires_human_gate,
            "allowed_in_dry_run": self.allowed_in_dry_run,
            "network_policy": self.network_policy,
            "artifact_policy": self.artifact_policy,
            "cleanup_policy": self.cleanup_policy,
        }


@dataclass
class Artifact:
    """Reference to an output produced or planned by an action."""

    name: str
    artifact_type: str
    artifact_id: str = field(default_factory=lambda: _id("artifact"))
    uri: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "name": self.name,
            "artifact_type": self.artifact_type,
            "uri": self.uri,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }


@dataclass
class HumanGate:
    """Approval gate for high-risk or externally visible actions."""

    reason: str
    gate_id: str = field(default_factory=lambda: _id("gate"))
    action_id: Optional[str] = None
    approved: bool = False
    requested_at: str = field(default_factory=_now)
    approved_at: Optional[str] = None
    approver: Optional[str] = None

    def approve(self, approver: str = "user") -> None:
        self.approved = True
        self.approver = approver
        self.approved_at = _now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "action_id": self.action_id,
            "reason": self.reason,
            "approved": self.approved,
            "requested_at": self.requested_at,
            "approved_at": self.approved_at,
            "approver": self.approver,
        }


@dataclass
class Action:
    """A single planned or executed unit of work."""

    name: str
    kind: ActionKind
    inputs: Dict[str, Any] = field(default_factory=dict)
    policy: ActionPolicy = field(default_factory=ActionPolicy)
    action_id: str = field(default_factory=lambda: _id("action"))
    status: ActionStatus = ActionStatus.PENDING
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    artifact_ids: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now)
    updated_at: Optional[str] = None

    def __post_init__(self) -> None:
        if isinstance(self.kind, str):
            self.kind = ActionKind(self.kind)
        if isinstance(self.status, str):
            self.status = ActionStatus(self.status)

    def mark_blocked(self, reason: str) -> None:
        self.status = ActionStatus.BLOCKED
        self.error = reason
        self.updated_at = _now()

    def mark_skipped(self, output: Optional[Dict[str, Any]] = None) -> None:
        self.status = ActionStatus.SKIPPED
        self.output = output or {}
        self.updated_at = _now()

    def mark_completed(self, output: Optional[Dict[str, Any]] = None) -> None:
        self.status = ActionStatus.COMPLETED
        self.output = output or {}
        self.updated_at = _now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "name": self.name,
            "kind": self.kind.value,
            "inputs": self.inputs,
            "policy": self.policy.to_dict(),
            "status": self.status.value,
            "output": self.output,
            "error": self.error,
            "artifact_ids": self.artifact_ids,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class Task:
    """A collection of actions with a common goal."""

    name: str
    description: str = ""
    task_id: str = field(default_factory=lambda: _id("task"))
    actions: List[Action] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_action(self, action: Action) -> Action:
        self.actions.append(action)
        return action

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "name": self.name,
            "description": self.description,
            "actions": [action.to_dict() for action in self.actions],
            "metadata": self.metadata,
        }


@dataclass
class Flow:
    """Top-level unit for an agentic red-team scenario."""

    name: str
    flow_id: str = field(default_factory=lambda: _id("flow"))
    tasks: List[Task] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now)

    def add_task(self, task: Task) -> Task:
        self.tasks.append(task)
        return task

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "name": self.name,
            "tasks": [task.to_dict() for task in self.tasks],
            "metadata": self.metadata,
            "created_at": self.created_at,
        }


@dataclass
class TraceEvent:
    """Structured trace event for audit and observability."""

    event_type: str
    message: str
    event_id: str = field(default_factory=lambda: _id("trace"))
    action_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "message": self.message,
            "action_id": self.action_id,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


@dataclass
class AgentRunState:
    """Serializable state for a controlled agent run."""

    flow: Flow
    mode: RunMode = RunMode.DRY_RUN
    run_id: str = field(default_factory=lambda: _id("run"))
    artifacts: List[Artifact] = field(default_factory=list)
    human_gates: List[HumanGate] = field(default_factory=list)
    trace: List[TraceEvent] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    memory: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=_now)

    def __post_init__(self) -> None:
        if isinstance(self.mode, str):
            self.mode = RunMode(self.mode)

    def add_trace(
        self,
        event_type: str,
        message: str,
        action_id: Optional[str] = None,
        **metadata: Any,
    ) -> TraceEvent:
        event = TraceEvent(
            event_type=event_type,
            message=message,
            action_id=action_id,
            metadata=metadata,
        )
        self.trace.append(event)
        return event

    def require_gate(self, action: Action, reason: str) -> HumanGate:
        gate = HumanGate(reason=reason, action_id=action.action_id)
        self.human_gates.append(gate)
        return gate

    def add_memory(
        self,
        key: str,
        value: str,
        record_type: str = "note",
        source: str = "runtime",
        confidence: float = 0.5,
        **metadata: Any,
    ) -> Dict[str, Any]:
        record = {
            "key": key,
            "value": value,
            "record_type": record_type,
            "source": source,
            "confidence": confidence,
            "metadata": metadata,
            "created_at": _now(),
        }
        self.memory.append(record)
        return record

    def summary(self) -> Dict[str, Any]:
        actions = [action for task in self.flow.tasks for action in task.actions]
        counts: Dict[str, int] = {}
        for action in actions:
            counts[action.status.value] = counts.get(action.status.value, 0) + 1
        return {
            "run_id": self.run_id,
            "mode": self.mode.value,
            "tasks": len(self.flow.tasks),
            "actions": len(actions),
            "action_status": counts,
            "artifacts": len(self.artifacts),
            "human_gates": len(self.human_gates),
            "trace_events": len(self.trace),
            "memory_records": len(self.memory),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "mode": self.mode.value,
            "flow": self.flow.to_dict(),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "human_gates": [gate.to_dict() for gate in self.human_gates],
            "trace": [event.to_dict() for event in self.trace],
            "memory": self.memory,
            "metadata": self.metadata,
            "summary": self.summary(),
            "created_at": self.created_at,
        }
