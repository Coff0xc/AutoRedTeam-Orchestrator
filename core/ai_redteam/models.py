"""Data model for declarative AI red-team scenarios."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from core.agent_runtime import AgentRunState


class ScenarioMode(Enum):
    """Supported scenario modes."""

    DRY_RUN = "dry-run"
    ACTIVE = "active"


def _now() -> str:
    return datetime.now().isoformat()


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


@dataclass
class Scope:
    """Target scope and safety policy for a scenario."""

    allowed_targets: List[str] = field(default_factory=list)
    blocked_targets: List[str] = field(
        default_factory=lambda: ["169.254.169.254", "metadata.google.internal"]
    )

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "Scope":
        data = data or {}
        return cls(
            allowed_targets=[str(item) for item in _as_list(data.get("allowed_targets"))],
            blocked_targets=[str(item) for item in _as_list(data.get("blocked_targets"))]
            or cls().blocked_targets,
        )

    def is_blocked(self, endpoint: str) -> bool:
        return any(blocked and blocked in endpoint for blocked in self.blocked_targets)

    def is_allowed(self, endpoint: str) -> bool:
        if self.is_blocked(endpoint):
            return False
        if not self.allowed_targets:
            return True
        return any(endpoint.startswith(allowed) for allowed in self.allowed_targets)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed_targets": self.allowed_targets,
            "blocked_targets": self.blocked_targets,
        }


@dataclass
class Target:
    """A model, agent, RAG app, MCP server, or HTTP endpoint under test."""

    target_id: str
    target_type: str
    endpoint: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Target":
        return cls(
            target_id=str(data.get("id") or data.get("target_id") or _id("target")),
            target_type=str(data.get("type") or data.get("target_type") or "unknown"),
            endpoint=data.get("endpoint") or data.get("url"),
            metadata=dict(data.get("metadata") or {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.target_id,
            "type": self.target_type,
            "endpoint": self.endpoint,
            "metadata": self.metadata,
        }


@dataclass
class Probe:
    """Risk being tested, such as prompt injection or data leakage."""

    name: str
    probe_id: str = field(default_factory=lambda: _id("probe"))
    category: str = "ai_redteam"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_value(cls, value: Any) -> "Probe":
        if isinstance(value, str):
            return cls(name=value, probe_id=value)
        return cls(
            name=str(value.get("name") or value.get("id")),
            probe_id=str(value.get("id") or value.get("name") or _id("probe")),
            category=str(value.get("category") or "ai_redteam"),
            metadata=dict(value.get("metadata") or {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.probe_id,
            "name": self.name,
            "category": self.category,
            "metadata": self.metadata,
        }


@dataclass
class Strategy:
    """Payload transformation or interaction strategy."""

    name: str
    strategy_id: str = field(default_factory=lambda: _id("strategy"))
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_value(cls, value: Any) -> "Strategy":
        if isinstance(value, str):
            return cls(name=value, strategy_id=value)
        return cls(
            name=str(value.get("name") or value.get("id")),
            strategy_id=str(value.get("id") or value.get("name") or _id("strategy")),
            metadata=dict(value.get("metadata") or {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.strategy_id, "name": self.name, "metadata": self.metadata}


@dataclass
class Scorer:
    """Assertion or detector used to grade a target response."""

    name: str
    scorer_id: str = field(default_factory=lambda: _id("scorer"))
    threshold: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_value(cls, value: Any) -> "Scorer":
        if isinstance(value, str):
            return cls(name=value, scorer_id=value)
        threshold = value.get("threshold")
        return cls(
            name=str(value.get("name") or value.get("id")),
            scorer_id=str(value.get("id") or value.get("name") or _id("scorer")),
            threshold=float(threshold) if threshold is not None else None,
            metadata=dict(value.get("metadata") or {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.scorer_id,
            "name": self.name,
            "threshold": self.threshold,
            "metadata": self.metadata,
        }


@dataclass
class ReportConfig:
    """Requested report outputs."""

    formats: List[str] = field(default_factory=lambda: ["json"])

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ReportConfig":
        data = data or {}
        return cls(formats=[str(item) for item in _as_list(data.get("formats") or ["json"])])

    def to_dict(self) -> Dict[str, Any]:
        return {"formats": self.formats}


@dataclass
class Scenario:
    """Declarative AI red-team scenario."""

    name: str
    mode: ScenarioMode = ScenarioMode.DRY_RUN
    scope: Scope = field(default_factory=Scope)
    targets: List[Target] = field(default_factory=list)
    probes: List[Probe] = field(default_factory=list)
    strategies: List[Strategy] = field(default_factory=lambda: [Strategy(name="direct")])
    scorers: List[Scorer] = field(default_factory=list)
    report: ReportConfig = field(default_factory=ReportConfig)
    gates: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.mode, str):
            self.mode = ScenarioMode(self.mode)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Scenario":
        raw_strategies = _as_list(data.get("strategies"))
        return cls(
            name=str(data.get("name") or "ai-redteam-scenario"),
            mode=ScenarioMode(data.get("mode") or ScenarioMode.DRY_RUN.value),
            scope=Scope.from_dict(data.get("scope")),
            targets=[Target.from_dict(item) for item in _as_list(data.get("targets"))],
            probes=[Probe.from_value(item) for item in _as_list(data.get("probes"))],
            strategies=(
                [Strategy.from_value(item) for item in raw_strategies]
                if raw_strategies
                else [Strategy(name="direct", strategy_id="direct")]
            ),
            scorers=[Scorer.from_value(item) for item in _as_list(data.get("scorers"))],
            report=ReportConfig.from_dict(data.get("report")),
            gates=dict(data.get("gates") or {}),
            metadata=dict(data.get("metadata") or {}),
        )

    def validate(self) -> List[str]:
        errors: List[str] = []
        if not self.targets:
            errors.append("Scenario must include at least one target")
        if not self.probes:
            errors.append("Scenario must include at least one probe")
        for target in self.targets:
            if target.endpoint and not self.scope.is_allowed(target.endpoint):
                errors.append(f"Target endpoint is outside allowed scope: {target.target_id}")
        return errors

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "mode": self.mode.value,
            "scope": self.scope.to_dict(),
            "targets": [target.to_dict() for target in self.targets],
            "probes": [probe.to_dict() for probe in self.probes],
            "strategies": [strategy.to_dict() for strategy in self.strategies],
            "scorers": [scorer.to_dict() for scorer in self.scorers],
            "report": self.report.to_dict(),
            "gates": self.gates,
            "metadata": self.metadata,
        }


@dataclass
class Attempt:
    """One planned probe/strategy/target combination."""

    target_id: str
    probe_id: str
    strategy_id: str
    attempt_id: str = field(default_factory=lambda: _id("attempt"))
    status: str = "planned"
    action_id: Optional[str] = None
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "target_id": self.target_id,
            "probe_id": self.probe_id,
            "strategy_id": self.strategy_id,
            "status": self.status,
            "action_id": self.action_id,
            "created_at": self.created_at,
        }


@dataclass
class Score:
    """Scoring placeholder for a dry-run or evaluated attempt."""

    attempt_id: str
    scorer_id: str
    status: str = "not_run"
    passed: Optional[bool] = None
    severity: str = "info"
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "scorer_id": self.scorer_id,
            "status": self.status,
            "passed": self.passed,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class AIRedTeamRunResult:
    """Result returned by the AI red-team runner."""

    scenario: Scenario
    run_state: AgentRunState
    attempts: List[Attempt] = field(default_factory=list)
    scores: List[Score] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": True,
            "scenario": self.scenario.to_dict(),
            "summary": {
                "mode": self.scenario.mode.value,
                "targets": len(self.scenario.targets),
                "probes": len(self.scenario.probes),
                "strategies": len(self.scenario.strategies),
                "attempts_planned": len(self.attempts),
                "scores": len(self.scores),
                "warnings": len(self.warnings),
            },
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "scores": [score.to_dict() for score in self.scores],
            "warnings": self.warnings,
            "run_state": self.run_state.to_dict(),
        }
