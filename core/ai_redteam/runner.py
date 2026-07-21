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
    RuntimePipeline,
    SandboxMiddleware,
    SandboxPolicy,
    RunMode,
    Task,
    build_observability_snapshot,
    register_runtime_run,
    score_run_summary,
)
from core.ai_redteam.catalog import unknown_items
from core.ai_redteam.models import AIRedTeamRunResult, Attempt, Scenario, ScenarioMode, Score
from core.ai_redteam.strategies import apply_strategy, build_probe_prompt


class AIRedTeamRunner:
    """Plan AI red-team attempts without executing external calls by default."""

    def __init__(
        self,
        scenario: Scenario,
        allow_active: bool = False,
        runtime_pipeline: RuntimePipeline | None = None,
    ):
        self.scenario = scenario
        self.allow_active = allow_active
        self.runtime_pipeline = runtime_pipeline or RuntimePipeline(
            [SandboxMiddleware(SandboxPolicy(enabled=scenario.mode == ScenarioMode.ACTIVE))]
        )

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
        warnings.extend(
            f"Unknown {kind}(s): {', '.join(items)}"
            for kind, items in {
                "probe": unknown_items("probe", [probe.probe_id for probe in self.scenario.probes]),
                "strategy": unknown_items(
                    "strategy", [strategy.strategy_id for strategy in self.scenario.strategies]
                ),
                "scorer": unknown_items(
                    "scorer", [scorer.scorer_id for scorer in self.scenario.scorers]
                ),
            }.items()
            if items
        )

        for target in self.scenario.targets:
            for probe in self.scenario.probes:
                for strategy in self.scenario.strategies:
                    base_prompt = build_probe_prompt(probe.name)
                    strategy_plan = apply_strategy(base_prompt, strategy.strategy_id)
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
                            "strategy_plan": strategy_plan,
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
                    task.add_action(action)
                    self.runtime_pipeline.apply_action(run_state, action)
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
                                metadata={"strategy_plan": strategy_plan},
                            )
                        )

        if self.scenario.mode == ScenarioMode.DRY_RUN:
            warnings.append(
                "Dry-run only: no target calls, model calls, shell commands, or tools ran."
            )
            run_state.add_memory(
                "ai_redteam.mode",
                "dry-run",
                record_type="run_policy",
                source="ai_redteam_runner",
                confidence=1.0,
            )

        run_state.metadata["observability"] = build_observability_snapshot(run_state).to_dict()
        run_state.metadata["benchmark"] = score_run_summary(
            self.scenario.name, run_state.summary()
        ).to_dict()
        register_runtime_run(run_state)

        return AIRedTeamRunResult(
            scenario=self.scenario,
            run_state=run_state,
            attempts=attempts,
            scores=scores,
            warnings=warnings,
        )
