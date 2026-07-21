"""Shared runtime instrumentation helpers for MCP handlers."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, Optional

from core.agent_runtime import (
    Action,
    ActionKind,
    ActionPolicy,
    ActionStatus,
    AgentRunState,
    Flow,
    PolicyMiddleware,
    RiskLevel,
    RunMode,
    RuntimePipeline,
    SandboxMiddleware,
    SandboxPolicy,
    Task,
    register_runtime_run,
)

_SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "credential",
    "password",
    "passwd",
    "private_key",
    "secret",
    "secret_key",
    "token",
}


def _sanitize_value(value: Any, key: str = "", depth: int = 0) -> Any:
    lowered = key.lower()
    if lowered in _SENSITIVE_KEYS:
        return "***REDACTED***"
    if depth >= 4:
        return "<truncated>"
    if isinstance(value, dict):
        return {
            str(item_key): _sanitize_value(item_value, str(item_key), depth + 1)
            for item_key, item_value in list(value.items())[:50]
        }
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        sanitized = [_sanitize_value(item, key, depth + 1) for item in items[:20]]
        if len(items) > 20:
            sanitized.append(f"<{len(items) - 20} more>")
        return sanitized
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str) and len(value) > 500:
            return f"{value[:500]}...<truncated>"
        return value
    return str(value)


def sanitize_runtime_inputs(inputs: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a JSON-safe, low-leakage copy of handler runtime inputs."""
    return {str(key): _sanitize_value(value, str(key)) for key, value in (inputs or {}).items()}


def gate_handler_runtime_action(
    tool_name: str,
    inputs: Optional[Dict[str, Any]] = None,
    risk_level: str = "low",
    *,
    source: str = "handler",
    requires_auth: bool = False,
    requires_human_gate: Optional[bool] = None,
    human_approved: bool = True,
    network_policy: str = "deny",
    sandbox_provider: str = "policy",
    artifact_policy: str = "metadata-only",
    cleanup_policy: str = "handler-owned",
) -> Dict[str, Any]:
    """Create, gate, and register a handler action in the runtime store."""
    risk = RiskLevel(risk_level)
    run_state = AgentRunState(
        flow=Flow(
            name=f"handler:{tool_name}",
            metadata={
                "component": "handler_runtime",
                "source": source,
                "tool": tool_name,
            },
        ),
        mode=RunMode.ACTIVE,
        metadata={
            "component": "handler_runtime",
            "source": source,
            "tool": tool_name,
        },
    )
    task = run_state.flow.add_task(
        Task(
            name=f"handler:{tool_name}",
            description="MCP handler action gated by runtime middleware.",
            metadata={"tool": tool_name, "source": source},
        )
    )
    action = task.add_action(
        Action(
            name=f"handler.{tool_name}",
            kind=ActionKind.TOOL_CALL,
            inputs=sanitize_runtime_inputs(inputs),
            policy=ActionPolicy(
                risk_level=risk,
                requires_auth=requires_auth,
                requires_human_gate=(
                    risk.is_high_risk() if requires_human_gate is None else requires_human_gate
                ),
                allowed_in_dry_run=False,
                network_policy=network_policy,
                artifact_policy=artifact_policy,
                cleanup_policy=cleanup_policy,
            ),
        )
    )
    pipeline = RuntimePipeline(
        [
            PolicyMiddleware(human_approved=human_approved),
            SandboxMiddleware(
                SandboxPolicy(
                    enabled=True,
                    provider=sandbox_provider,
                    network_policy=network_policy,
                    artifact_policy=artifact_policy,
                )
            ),
        ]
    )
    decisions = pipeline.evaluate_action(run_state, action)
    blocked = next((decision for decision in decisions if not decision.allowed), None)
    if blocked:
        action.mark_blocked(blocked.reason)
        run_state.require_gate(action, blocked.reason)
        register_runtime_run(run_state)
        return {
            "allowed": False,
            "reason": blocked.reason,
            "action": action,
            "run_state": run_state,
            "decisions": decisions,
        }

    action.status = ActionStatus.RUNNING
    action.updated_at = datetime.now().isoformat()
    run_state.add_trace(
        "handler_action_started",
        f"Handler action started: {tool_name}",
        action_id=action.action_id,
        tool=tool_name,
        source=source,
    )
    register_runtime_run(run_state)
    return {
        "allowed": True,
        "action": action,
        "run_state": run_state,
        "decisions": decisions,
    }


def complete_handler_runtime_action(
    gate: Dict[str, Any],
    success: bool,
    output: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """Complete a handler runtime action and keep the registry in sync."""
    action = gate.get("action")
    run_state = gate.get("run_state")
    if action:
        if success:
            action.mark_completed(output or {"success": True})
        elif action.status == ActionStatus.BLOCKED:
            action.output = output or {"success": False}
            action.updated_at = datetime.now().isoformat()
        else:
            action.status = ActionStatus.FAILED
            action.error = error or gate.get("reason") or "runtime action failed"
            action.output = output or {"success": False}
            action.updated_at = datetime.now().isoformat()
    if run_state:
        run_state.add_trace(
            "handler_action_completed",
            "Handler action completed" if success else "Handler action failed",
            action_id=getattr(action, "action_id", None),
            success=success,
            error=error,
        )
        register_runtime_run(run_state)
        return run_state.to_dict()
    return {}


def blocked_handler_runtime_response(gate: Dict[str, Any]) -> Dict[str, Any]:
    """Return a standard blocked handler response with registered runtime state."""
    return {
        "success": False,
        "error": gate.get("reason") or "runtime action blocked",
        "runtime": complete_handler_runtime_action(gate, False),
    }


def complete_handler_runtime_payload(
    gate: Dict[str, Any],
    payload: Dict[str, Any],
    *,
    summary_keys: Iterable[str] = (),
) -> Dict[str, Any]:
    """Attach runtime metadata to a handler payload using a small output summary."""
    success = bool(payload.get("success", True))
    summary: Dict[str, Any] = {"success": success}
    for key in summary_keys:
        if key not in payload:
            continue
        value = payload[key]
        if isinstance(value, (str, int, float, bool)) or value is None:
            summary[key] = value
        elif isinstance(value, (list, tuple, set)):
            summary[f"{key}_count"] = len(value)
        elif isinstance(value, dict):
            summary[f"{key}_keys"] = list(value.keys())[:20]
    payload["runtime"] = complete_handler_runtime_action(
        gate,
        success,
        output=summary,
        error=payload.get("error"),
    )
    return payload
