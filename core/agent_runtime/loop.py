"""Thin local runtime loop for planned agent actions.

The loop walks pending actions through ``RuntimePipeline``, then either skips
them (plan-only) or runs an allowlisted local step. It does not call models,
shells, or remote targets, and it does not attach the P3 executor harness.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

import yaml

from core.agent_runtime.middleware import RuntimePipeline
from core.agent_runtime.models import (
    Action,
    ActionKind,
    ActionPolicy,
    ActionStatus,
    AgentRunState,
    Flow,
    RunMode,
    Task,
    agent_run_state_from_dict,
)
from core.agent_runtime.observability import build_observability_snapshot
from core.agent_runtime.registry import register_runtime_run

RUNTIME_SCHEMA = "autort.runtime/v1"
LOCAL_STEPS = frozenset(
    {
        "ai_surface.scan",
        "ai_surface.scan_skills",
        "ai_surface.scan_mcp_config",
        "skill.read",
        "eval.document",
    }
)
_FORBIDDEN_KINDS = frozenset({ActionKind.SHELL, ActionKind.BROWSER, ActionKind.MODEL_CALL})
_DEFAULT_MAX_STEPS = 32


def is_runtime_plan(data: Mapping[str, Any]) -> bool:
    """Return True when ``data`` is a runtime plan rather than a run-state dump."""
    schema = str(data.get("schema") or "").strip()
    if schema.startswith("autort.runtime/"):
        return True
    return str(data.get("kind") or "").strip() == "runtime_plan"


def load_runtime_document(path: str | Path) -> Dict[str, Any]:
    """Load a YAML or JSON runtime plan or run-state document."""
    document_path = Path(path)
    raw_text = document_path.read_text(encoding="utf-8")
    if document_path.suffix.lower() == ".json":
        loaded: Any = json.loads(raw_text)
    else:
        loaded = yaml.safe_load(raw_text)
    if not isinstance(loaded, dict):
        raise ValueError("Runtime document must contain a mapping at the top level")
    return loaded


def plan_to_run_state(data: Mapping[str, Any]) -> AgentRunState:
    """Build a dry-run AgentRunState from an ``autort.runtime/v1`` plan."""
    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError("Runtime plan must include a non-empty steps list")
    flow = Flow(
        name=str(data.get("name") or "runtime-plan"),
        metadata={"schema": RUNTIME_SCHEMA, "plan_mode": str(data.get("mode") or "dry-run")},
    )
    task = flow.add_task(Task(name="local-audit", description="Thin local runtime loop"))
    for raw in steps:
        if not isinstance(raw, Mapping):
            raise ValueError("Runtime plan steps must be mappings")
        task.add_action(_action_from_step(raw))
    return AgentRunState(
        flow=flow,
        mode=RunMode.DRY_RUN,
        metadata={
            "schema": RUNTIME_SCHEMA,
            "plan_mode": str(data.get("mode") or "dry-run"),
            "component": "agent_runtime.loop",
        },
    )


def run_runtime_path(
    path: str | Path,
    *,
    allow_local: Optional[bool] = None,
    max_steps: Optional[int] = None,
) -> Dict[str, Any]:
    """Load ``path`` and run it as a plan or an existing AgentRunState dump."""
    document_path = Path(path)
    return run_runtime_document(
        load_runtime_document(document_path),
        allow_local=allow_local,
        max_steps=max_steps,
        base_dir=document_path.parent,
    )


def run_runtime_document(
    data: Mapping[str, Any],
    *,
    allow_local: Optional[bool] = None,
    max_steps: Optional[int] = None,
    base_dir: Optional[Path] = None,
    stop_on_block: Optional[bool] = None,
) -> Dict[str, Any]:
    """Run a plan mapping or an AgentRunState mapping."""
    root = Path(base_dir) if base_dir is not None else Path.cwd()
    if is_runtime_plan(data):
        state = plan_to_run_state(data)
        if allow_local is None:
            local = _plan_allow_local(str(data.get("mode") or "dry-run"))
        else:
            local = allow_local
        steps = data.get("max_steps", _DEFAULT_MAX_STEPS)
        if stop_on_block is None:
            halt = bool(data.get("stop_on_block", True))
        else:
            halt = bool(stop_on_block)
        return RuntimeLoop(
            allow_local=local,
            max_steps=int(max_steps if max_steps is not None else steps),
            stop_on_block=halt,
        ).run(state, base_dir=root)
    state = agent_run_state_from_dict(data)
    return RuntimeLoop(
        allow_local=bool(allow_local),
        max_steps=int(max_steps if max_steps is not None else _DEFAULT_MAX_STEPS),
        stop_on_block=True if stop_on_block is None else bool(stop_on_block),
    ).run(state, base_dir=root)


class RuntimeLoop:
    """Walk pending actions, apply gates, and optionally run local steps."""

    def __init__(
        self,
        *,
        allow_local: bool = False,
        max_steps: int = _DEFAULT_MAX_STEPS,
        stop_on_block: bool = True,
        pipeline: RuntimePipeline | None = None,
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be >= 1")
        self.allow_local = bool(allow_local)
        self.max_steps = int(max_steps)
        self.stop_on_block = bool(stop_on_block)
        self.pipeline = pipeline or RuntimePipeline()

    def run(self, run_state: AgentRunState, *, base_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Process pending actions on ``run_state`` and attach a local eval."""
        root = Path(base_dir) if base_dir is not None else Path.cwd()
        processed = 0
        stopped: Optional[str] = None
        for action in list(_pending_actions(run_state)):
            if processed >= self.max_steps:
                stopped = "max_steps"
                break
            processed += 1
            if not self.allow_local:
                self.pipeline.apply_action(run_state, action)
                if action.status == ActionStatus.BLOCKED and self.stop_on_block:
                    stopped = "blocked"
                    break
                continue
            stopped = self._run_local_action(run_state, action, root)
            if stopped and self.stop_on_block:
                break
            stopped = None
        if stopped:
            for action in _pending_actions(run_state):
                action.mark_skipped({"reason": stopped})
        return self._finish(run_state, processed=processed, stopped=stopped)

    def _run_local_action(
        self, run_state: AgentRunState, action: Action, base_dir: Path
    ) -> Optional[str]:
        decisions = self.pipeline.evaluate_action(run_state, action)
        failed = next((item for item in decisions if not item.allowed), None)
        if failed:
            action.mark_blocked(failed.reason)
            if "human approval" in failed.reason.lower() or action.policy.requires_human_gate:
                run_state.require_gate(action, failed.reason)
            return "blocked"
        if action.kind in _FORBIDDEN_KINDS:
            action.mark_blocked(f"kind {action.kind.value} is not a local runtime step")
            return "forbidden_kind"
        if action.policy.network_policy != "deny":
            action.mark_blocked("local runtime loop requires network_policy=deny")
            return "network"
        if action.name not in LOCAL_STEPS:
            action.mark_blocked(f"unknown local step {action.name!r}; failing closed")
            return "unknown_step"
        try:
            output = _dispatch(action, run_state, base_dir)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            action.mark_failed(str(exc))
            run_state.add_trace(
                "local_step_failed",
                str(exc),
                action_id=action.action_id,
                step=action.name,
            )
            return "step_failed"
        action.mark_completed(output)
        run_state.add_trace(
            "local_step_completed",
            f"local step {action.name}",
            action_id=action.action_id,
            step=action.name,
        )
        return None

    def _finish(
        self, run_state: AgentRunState, *, processed: int, stopped: Optional[str]
    ) -> Dict[str, Any]:
        from core.ai_redteam.eval_cases import evaluate_run_cases

        eval_result = evaluate_run_cases(run_state)
        actions = [action for task in run_state.flow.tasks for action in task.actions]
        blocked = any(action.status == ActionStatus.BLOCKED for action in actions)
        failed = any(action.status == ActionStatus.FAILED for action in actions)
        passed = bool(eval_result.get("passed")) and not blocked and not failed
        loop_meta = {
            "allow_local": self.allow_local,
            "max_steps": self.max_steps,
            "processed": processed,
            "stopped": stopped,
            "finalizable": passed and stopped is None,
        }
        run_state.metadata["eval"] = eval_result
        run_state.metadata["loop"] = loop_meta
        run_state.metadata["observability"] = build_observability_snapshot(run_state).to_dict()
        register_runtime_run(run_state)
        return {
            "success": True,
            "passed": passed,
            "schema": RUNTIME_SCHEMA,
            "run_state": run_state.to_dict(),
            "eval": eval_result,
            "summary": run_state.summary(),
            "loop": loop_meta,
        }


def _action_from_step(raw: Mapping[str, Any]) -> Action:
    policy_raw = raw.get("policy") if isinstance(raw.get("policy"), Mapping) else {}
    raw_inputs = raw.get("inputs")
    if not isinstance(raw_inputs, Mapping):
        raw_inputs = raw.get("input")
    inputs: Mapping[str, Any] = raw_inputs if isinstance(raw_inputs, Mapping) else {}
    kind = str(raw.get("kind") or ActionKind.TOOL_CALL.value)
    return Action(
        name=str(raw.get("name") or "").strip(),
        kind=kind,
        inputs=dict(inputs),
        policy=ActionPolicy(
            risk_level=str(policy_raw.get("risk_level") or "low"),
            requires_human_gate=bool(policy_raw.get("requires_human_gate", False)),
            allowed_in_dry_run=bool(policy_raw.get("allowed_in_dry_run", True)),
            network_policy=str(policy_raw.get("network_policy") or "deny"),
        ),
    )


def _pending_actions(run_state: AgentRunState) -> List[Action]:
    return [
        action
        for task in run_state.flow.tasks
        for action in task.actions
        if action.status == ActionStatus.PENDING
    ]


def _plan_allow_local(mode: str) -> bool:
    return str(mode or "dry-run").strip().lower().replace("_", "-") == "local"


def _dispatch(action: Action, run_state: AgentRunState, base_dir: Path) -> Dict[str, Any]:
    inputs = action.inputs
    if action.name == "ai_surface.scan":
        return _scan_surface("handlers", inputs, base_dir, kind="handlers")
    if action.name == "ai_surface.scan_skills":
        return _scan_surface(".", inputs, base_dir, kind="skills")
    if action.name == "ai_surface.scan_mcp_config":
        return _scan_surface(".", inputs, base_dir, kind="mcp_config")
    if action.name == "skill.read":
        from core.skills import read_skill

        payload = read_skill(str(_resolve_path(inputs.get("path"), base_dir)))
        return {
            "success": bool(payload.get("success")),
            "blocked": bool(payload.get("blocked")),
            "path": payload.get("path"),
            "operator_stop": list(payload.get("operator_stop") or []),
            "error": payload.get("error"),
        }
    if action.name == "eval.document":
        return _eval_document(inputs, run_state, base_dir)
    raise ValueError(f"unhandled local step {action.name!r}")


def _scan_surface(
    default_path: str, inputs: Mapping[str, Any], base_dir: Path, *, kind: str
) -> Dict[str, Any]:
    from core.ai_surface import scan_handler_surface, scan_mcp_config, scan_skill_surface

    path = _resolve_path(inputs.get("path") or default_path, base_dir)
    if kind == "skills":
        result = scan_skill_surface(path)
    elif kind == "mcp_config":
        result = scan_mcp_config(path)
    else:
        reconcile = inputs.get("reconcile")
        result = scan_handler_surface(
            path,
            exclude_tests=bool(inputs.get("exclude_tests", True)),
            reconcile=None if reconcile is None else bool(reconcile),
        )
    payload = result.to_dict()
    return {
        "success": True,
        "root_path": payload.get("root_path"),
        "summary": payload.get("summary") or {},
        "warnings": payload.get("warnings") or [],
    }


def _eval_document(
    inputs: Mapping[str, Any], run_state: AgentRunState, base_dir: Path
) -> Dict[str, Any]:
    from core.ai_redteam import evaluate_eval_document, evaluate_path, evaluate_run_cases

    path = inputs.get("path")
    if path:
        return evaluate_path(_resolve_path(path, base_dir))
    document = inputs.get("document") or inputs.get("suite")
    if isinstance(document, Mapping):
        return evaluate_eval_document(document, base_dir=base_dir)
    return evaluate_run_cases(run_state)


def _resolve_path(value: Any, base_dir: Path) -> Path:
    path = Path(str(value or ""))
    if path.is_absolute():
        return path
    candidates = [base_dir / path, Path.cwd() / path]
    here = base_dir.resolve()
    for parent in (here, *here.parents):
        if (parent / "handlers").is_dir() and (parent / "core").is_dir():
            candidates.append(parent / path)
            break
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return base_dir / path
