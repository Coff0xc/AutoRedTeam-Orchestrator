"""Plan-time runtime middleware for controlled agent workflows.

Middleware here is intentionally execution-free. It validates planned actions,
applies sandbox policy, records trace events, and leaves real tool execution to a
separate authorized executor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from core.agent_runtime.models import Action, ActionStatus, AgentRunState, RunMode
from core.agent_runtime.sandbox import SandboxPolicy, enforce_sandbox_policy


@dataclass
class MiddlewareDecision:
    """Decision returned by one runtime middleware."""

    allowed: bool
    reason: str = ""
    middleware: str = "runtime"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "middleware": self.middleware,
            "metadata": self.metadata,
        }


class RuntimeMiddleware:
    """Base class for plan-time action middleware."""

    name = "runtime"

    def before_action(self, run_state: AgentRunState, action: Action) -> MiddlewareDecision:
        return MiddlewareDecision(allowed=True, middleware=self.name)


class PolicyMiddleware(RuntimeMiddleware):
    """Enforce ActionPolicy mode and human-gate requirements."""

    name = "policy"

    def __init__(self, human_approved: bool = False):
        self.human_approved = human_approved

    def before_action(self, run_state: AgentRunState, action: Action) -> MiddlewareDecision:
        reason = action.policy.block_reason(
            mode=run_state.mode,
            human_approved=self.human_approved,
        )
        if reason:
            return MiddlewareDecision(allowed=False, reason=reason, middleware=self.name)
        return MiddlewareDecision(allowed=True, middleware=self.name)


class SandboxMiddleware(RuntimeMiddleware):
    """Enforce sandbox policy before active execution is considered."""

    name = "sandbox"

    def __init__(self, sandbox_policy: SandboxPolicy | None = None):
        self.sandbox_policy = sandbox_policy or SandboxPolicy()

    def before_action(self, run_state: AgentRunState, action: Action) -> MiddlewareDecision:
        result = enforce_sandbox_policy(action, self.sandbox_policy, mode=run_state.mode)
        return MiddlewareDecision(
            allowed=result.allowed,
            reason=result.reason,
            middleware=self.name,
            metadata={"sandbox": result.to_dict()},
        )


class RuntimePipeline:
    """Sequential middleware pipeline for planned actions."""

    def __init__(self, middlewares: List[RuntimeMiddleware] | None = None):
        self.middlewares = middlewares or [PolicyMiddleware(), SandboxMiddleware()]

    def evaluate_action(self, run_state: AgentRunState, action: Action) -> List[MiddlewareDecision]:
        decisions: List[MiddlewareDecision] = []
        for middleware in self.middlewares:
            decision = middleware.before_action(run_state, action)
            decisions.append(decision)
            run_state.add_trace(
                "middleware_decision",
                f"{middleware.name}: {'allowed' if decision.allowed else 'blocked'}",
                action_id=action.action_id,
                decision=decision.to_dict(),
            )
            if not decision.allowed:
                break
        return decisions

    def apply_action(self, run_state: AgentRunState, action: Action) -> Action:
        """Apply middleware decisions and set a non-executing lifecycle state."""
        decisions = self.evaluate_action(run_state, action)
        failed = next((decision for decision in decisions if not decision.allowed), None)
        if failed:
            action.mark_blocked(failed.reason)
            if "human approval" in failed.reason.lower() or action.policy.requires_human_gate:
                run_state.require_gate(action, failed.reason)
            return action
        if run_state.mode == RunMode.DRY_RUN:
            action.mark_skipped({"planned_only": True, "middleware": "passed"})
        elif action.status == ActionStatus.PENDING:
            action.mark_skipped({"planned_only": True, "reason": "no executor attached"})
        return action
