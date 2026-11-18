"""Heuristic next-action planner for an engagement.

The planner is code, not a model. An optional LLM suggestion may pick among
the remaining legal steps; unknown suggestions are ignored.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from core.engage.config import EngagementConfig

ENGAGE_STEPS = (
    "engage.recon",
    "engage.detect",
    "engage.verify",
    "engage.export",
)

_NEXT_HINT = {
    "engage.recon": "After recon, run engage.detect (or detect_run).",
    "engage.detect": "After detection, run engage.verify (or verify_finding) on each finding.",
    "engage.verify": "After verify, export confirmed findings with engage.export.",
    "engage.export": "Engagement is complete when export succeeds.",
}


def plan_next(
    config: EngagementConfig,
    state: Mapping[str, Any],
    *,
    use_model: bool = False,
) -> Optional[Dict[str, Any]]:
    """Return the next engage step, or None when the run is finalizable."""
    remaining = list(_heuristic_queue(config, state))
    if not remaining:
        return None
    chosen = remaining[0]
    if use_model or config.use_model:
        suggested = _model_pick(remaining, state)
        if suggested is not None:
            chosen = suggested
    return _card(chosen, config, state)


def next_hint(step: str) -> str:
    return _NEXT_HINT.get(step, "Search the catalog with tool_search.")


def _heuristic_queue(config: EngagementConfig, state: Mapping[str, Any]) -> tuple[str, ...]:
    phases = set(config.phases)
    queue: list[str] = []
    if "recon" in phases and not state.get("recon"):
        queue.append("engage.recon")
    if "detect" in phases and state.get("findings") is None:
        queue.append("engage.detect")
    if "verify" in phases and _unverified(state):
        queue.append("engage.verify")
    if "export" in phases and not state.get("exported"):
        queue.append("engage.export")
    return tuple(queue)


def _unverified(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    findings = state.get("findings")
    if not isinstance(findings, list):
        return []
    pending: list[dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        if item.get("engagement_verified") is True:
            continue
        if str(item.get("verification_status") or "") == "verified":
            continue
        pending.append(item)
    return pending


def _card(step: str, config: EngagementConfig, state: Mapping[str, Any]) -> Dict[str, Any]:
    inputs: Dict[str, Any] = {"target": config.target}
    if step == "engage.recon" and config.recon_modules:
        inputs["modules"] = list(config.recon_modules)
        inputs["quick_mode"] = config.quick_mode
    if step == "engage.detect" and config.classes:
        inputs["classes"] = list(config.classes)
    if step == "engage.verify":
        pending = _unverified(state)
        inputs["finding"] = pending[0] if pending else {}
    if step == "engage.export":
        inputs["output_dir"] = config.output_dir
    return {
        "name": step,
        "kind": "tool_call",
        "inputs": inputs,
        "hint": next_hint(step),
        "remaining": list(_heuristic_queue(config, state)),
        "policy": {
            "risk_level": "moderate" if step != "engage.export" else "low",
            "network_policy": "controlled" if step != "engage.export" else "deny",
            "requires_human_gate": config.hitl != "off" and step in {"engage.verify"},
            "allowed_in_dry_run": True,
        },
    }


def _model_pick(remaining: list[str], state: Mapping[str, Any]) -> Optional[str]:
    try:
        from core.llm.provider import LLMProvider
    except ImportError:
        return None
    provider = LLMProvider()
    if not provider.available:
        return None
    from core.llm.prompts import ENGAGE_PICK_SYSTEM_PROMPT, envelope_intro, wrap_untrusted

    summary = {
        "has_recon": bool(state.get("recon")),
        "findings": (
            len(state.get("findings") or []) if isinstance(state.get("findings"), list) else None
        ),
        "exported": bool(state.get("exported")),
    }
    nonce, framed = wrap_untrusted("state", str(summary))
    prompt = (
        "Pick exactly one next engagement step from this list: "
        + ", ".join(remaining)
        + ".\n"
        + envelope_intro(nonce)
        + "\n"
        + framed
    )
    try:
        reply = provider.complete(prompt, system=ENGAGE_PICK_SYSTEM_PROMPT)
    except Exception:
        return None
    if not isinstance(reply, str):
        return None
    token = reply.strip().split()[0] if reply.strip() else ""
    if token in remaining:
        return token
    return None
