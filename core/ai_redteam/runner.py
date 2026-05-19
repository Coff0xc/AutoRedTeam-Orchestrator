"""Dry-run runner for declarative AI red-team scenarios."""

from __future__ import annotations

from typing import List

from core.agent_runtime import (
    Action,
    ActionKind,
    ActionPolicy,
    AgentRunState,
    Flow,
    RiskLevel,
    RunMode,
    Task,
)
from core.ai_redteam.models import AIRedTeamRunResult, Attempt, Scenario, ScenarioMode, Score


class AIRedTeamRunner:
    """Plan AI red-team attempts without executing external calls by default."""

    def __init__(self, scenario: Scenario, allow_active: bool = False):
        self.scenario = scenario
        self.allow_active = allow_active

    def run(self) -> AIRedTeamRunResult:
        errors = self.scenario.validate()
        if errors:
            raise ValueError("; ".join(errors))

        if self.scenario.mode == ScenarioMode.ACTIVE and not self.allow_active:
            raise PermissionError(
                "Active AI red-team execution is blocked. Use dry-run mode or add an "
                "explicit authorized execution layer."
            )

        mode = RunMode.DRY_RUN if self.scenario.mode == ScenarioMode.DRY_RUN else RunMode.ACTIVE
        flow = Flow(
            name=self.scenario.name,
            metadata={"component": "ai_redteam", "scenario_mode": self.scenario.mode.value},
        )
        task = flow.add_task(
            Task(
                name="Plan AI red-team attempts",
                description="Create controlled target/probe/strategy attempts",
            )
        )
        run_state = AgentRunState(flow=flow, mode=mode)
        attempts: List[Attempt] = []
        scores: List[Score] = []
        warnings: List[str] = []

        for target in self.scenario.targets:
            for probe in self.scenario.probes:
                for strategy in self.scenario.strategies:
                    attempt = Attempt(
                        target_id=target.target_id,
                        probe_id=probe.probe_id,
                        strategy_id=strategy.strategy_id,
                    )
                    action = Action(
                        name=f"ai_redteam:{target.target_id}:{probe.probe_id}:{strategy.strategy_id}",
                        kind=ActionKind.TOOL_CALL,
                        inputs={
                            "target": target.to_dict(),
                            "probe": probe.to_dict(),
                            "strategy": strategy.to_dict(),
                            "dry_run": self.scenario.mode == ScenarioMode.DRY_RUN,
                        },
                        policy=ActionPolicy(
                            risk_level=RiskLevel.MODERATE,
                            requires_auth=True,
                            requires_human_gate=self.scenario.mode == ScenarioMode.ACTIVE,
                            allowed_in_dry_run=True,
                            network_policy=(
                                "deny" if self.scenario.mode == ScenarioMode.DRY_RUN else "scoped"
                            ),
                            artifact_policy="metadata-only",
                            cleanup_policy="not-required",
                        ),
                    )
                    attempt.action_id = action.action_id
                    reason = action.policy.block_reason(mode=mode)
                    if reason:
                        action.mark_blocked(reason)
                        run_state.require_gate(action, reason)
                    else:
                        action.mark_skipped(
                            {
                                "planned_only": True,
                                "reason": "dry-run mode does not call targets or tools",
                            }
                        )
                    task.add_action(action)
                    run_state.add_trace(
                        "attempt_planned",
                        "AI red-team attempt planned without external execution",
                        action_id=action.action_id,
                        target_id=target.target_id,
                        probe_id=probe.probe_id,
                        strategy_id=strategy.strategy_id,
                    )
                    attempts.append(attempt)

                    for scorer in self.scenario.scorers:
                        scores.append(
                            Score(
                                attempt_id=attempt.attempt_id,
                                scorer_id=scorer.scorer_id,
                                status="not_run",
                                evidence=["dry-run: target response was not requested"],
                            )
                        )

        if self.scenario.mode == ScenarioMode.DRY_RUN:
            warnings.append("Dry-run only: no target calls, model calls, shell commands, or tools ran.")

        return AIRedTeamRunResult(
            scenario=self.scenario,
            run_state=run_state,
            attempts=attempts,
            scores=scores,
            warnings=warnings,
        )
