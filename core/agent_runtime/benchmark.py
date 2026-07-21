"""Benchmark helpers for controlled agent runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


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


@dataclass
class BenchmarkCase:
    """Policy benchmark expectations for one controlled run."""

    name: str
    min_success_rate: float = 1.0
    max_blocked_actions: int = 0
    max_policy_violations: int = 0
    max_cost_units: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "min_success_rate": self.min_success_rate,
            "max_blocked_actions": self.max_blocked_actions,
            "max_policy_violations": self.max_policy_violations,
            "max_cost_units": self.max_cost_units,
            "metadata": self.metadata,
        }


@dataclass
class BenchmarkHarnessResult:
    """Benchmark result plus pass/fail decision."""

    case: BenchmarkCase
    result: BenchmarkResult
    passed: bool
    failures: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case": self.case.to_dict(),
            "result": self.result.to_dict(),
            "passed": self.passed,
            "failures": self.failures,
        }


class BenchmarkHarness:
    """Deterministic benchmark harness for AgentRunState summaries."""

    def __init__(self, cases: List[BenchmarkCase] | None = None):
        self.cases = cases or []

    def add_case(self, case: BenchmarkCase) -> BenchmarkCase:
        self.cases.append(case)
        return case

    def evaluate_summary(self, summary: Dict[str, Any], case: BenchmarkCase) -> BenchmarkHarnessResult:
        result = score_run_summary(case.name, summary)
        failures: List[str] = []
        if result.success_rate < case.min_success_rate:
            failures.append("success_rate_below_minimum")
        if result.blocked_actions > case.max_blocked_actions:
            failures.append("blocked_actions_above_maximum")
        if result.policy_violations > case.max_policy_violations:
            failures.append("policy_violations_above_maximum")
        if result.cost_units > case.max_cost_units:
            failures.append("cost_units_above_maximum")
        return BenchmarkHarnessResult(
            case=case,
            result=result,
            passed=not failures,
            failures=failures,
        )

    def evaluate_run(self, run_state: Any, case: BenchmarkCase) -> BenchmarkHarnessResult:
        return self.evaluate_summary(run_state.summary(), case)

    def evaluate_all(self, summary: Dict[str, Any]) -> List[BenchmarkHarnessResult]:
        return [self.evaluate_summary(summary, case) for case in self.cases]


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
