"""Gap-driven next-action planner for an engagement.

The planner is code, not a model. It reads open gaps from engagement state
(missing recon/detect/nuclei, unverified findings, missing export) and returns
one aggregator step. An optional LLM suggestion may pick among those open gaps;
unknown suggestions are ignored.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.engage.config import EngagementConfig
from core.engage.world import coverage, unverified_index

ENGAGE_STEPS = (
    "engage.recon",
    "engage.detect",
    "engage.verify",
    "engage.export",
)

PLAN_STEPS = (
    "recon_run",
    "detect_run",
    "nuclei_scan",
    "verify_finding",
    "export_findings",
)

STEP_ALIASES = {
    "engage.recon": "recon_run",
    "engage.detect": "detect_run",
    "engage.verify": "verify_finding",
    "engage.export": "export_findings",
    "engage.nuclei": "nuclei_scan",
}

_NEXT_HINT = {
    "recon_run": "After recon, run detect_run (or engage.detect).",
    "detect_run": "After detection, run verify_finding on each unverified finding.",
    "nuclei_scan": "After nuclei, verify unverified findings or export.",
    "verify_finding": "After verify, export confirmed findings with export_findings.",
    "export_findings": "Engagement is complete when export succeeds.",
}

_VERIFY_STEPS = frozenset({"verify_finding", "engage.verify"})
_EXPORT_STEPS = frozenset({"export_findings", "engage.export"})


def canonical_step(name: str) -> str:
    """Map an engage.* alias to the resident aggregator name."""
    key = str(name or "").strip()
    return STEP_ALIASES.get(key, key)


def plan_next(
    config: EngagementConfig,
    state: Mapping[str, Any],
    *,
    use_model: bool = False,
) -> Optional[Dict[str, Any]]:
    """Return the next aggregator step, or None when no gaps remain."""
    gaps = open_gaps(config, state)
    if not gaps:
        return None
    remaining = _remaining_names(gaps)
    chosen = remaining[0]
    if use_model or config.use_model:
        suggested = _model_pick(remaining, state)
        if suggested is not None:
            chosen = suggested
    return _card(chosen, config, state, gaps)


def next_hint(step: str) -> str:
    return _NEXT_HINT.get(canonical_step(step), "Search the catalog with tool_search.")


def open_gaps(config: EngagementConfig, state: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Open coverage gaps in priority order. Only currently actionable steps."""
    phases = set(config.phases)
    cov = coverage(state)
    unverified = unverified_index(state) if "verify" in phases else []
    gaps: List[Dict[str, Any]] = []

    if "recon" in phases and not cov["recon"] and not cov["detect"]:
        gaps.append({"step": "recon_run", "reason": "missing_recon"})
    if "detect" in phases and not cov["detect"]:
        gaps.append({"step": "detect_run", "reason": "missing_detect"})
    if "nuclei" in phases and not cov["nuclei"] and _nuclei_surface(cov, phases):
        gaps.append({"step": "nuclei_scan", "reason": "missing_nuclei"})
    if unverified:
        gaps.append(
            {
                "step": "verify_finding",
                "reason": "unverified_findings",
                "count": len(unverified),
            }
        )
    if "export" in phases and not cov["exported"] and _export_ready(phases, cov, unverified):
        gaps.append({"step": "export_findings", "reason": "missing_export"})
    return gaps


def _nuclei_surface(cov: Mapping[str, Any], phases: set[str]) -> bool:
    if cov.get("recon") or cov.get("detect"):
        return True
    return "recon" not in phases and "detect" not in phases


def _export_ready(
    phases: set[str], cov: Mapping[str, Any], unverified: Sequence[Mapping[str, Any]]
) -> bool:
    if "verify" in phases and unverified:
        return False
    if "detect" in phases and not cov.get("detect"):
        return False
    if "nuclei" in phases and not cov.get("nuclei") and _nuclei_surface(cov, phases):
        return False
    if "recon" in phases and not cov.get("recon") and not cov.get("detect"):
        return False
    return True


def _unverified(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    return unverified_index(state)


def _remaining_names(gaps: Sequence[Mapping[str, Any]]) -> list[str]:
    names: list[str] = []
    for gap in gaps:
        step = str(gap.get("step") or "")
        if step and step not in names:
            names.append(step)
    return names


def _card(
    step: str,
    config: EngagementConfig,
    state: Mapping[str, Any],
    gaps: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    canonical = canonical_step(step)
    inputs: Dict[str, Any] = {"target": config.target}
    if canonical == "recon_run":
        if config.recon_modules:
            inputs["modules"] = list(config.recon_modules)
        inputs["quick_mode"] = config.quick_mode
    if canonical == "detect_run":
        inputs["url"] = config.target
        if config.classes:
            inputs["classes"] = list(config.classes)
    if canonical == "nuclei_scan":
        inputs["url"] = config.target
    if canonical == "verify_finding":
        pending = _unverified(state)
        inputs["finding"] = pending[0] if pending else {}
    if canonical == "export_findings":
        inputs["output_dir"] = config.output_dir
    export = canonical in _EXPORT_STEPS
    from core.engage.ledger import build_coverage_ledger

    ledger = build_coverage_ledger(config, state)
    return {
        "name": canonical,
        "kind": "tool_call",
        "inputs": inputs,
        "hint": next_hint(canonical),
        "gaps": [dict(item) for item in gaps],
        "remaining": _remaining_names(gaps),
        "coverage": {
            "open": ledger["open"],
            "examined": ledger["examined"],
            "ruled_out": ledger["ruled_out"],
            "total": ledger["total"],
            "coverage_rate": ledger["coverage_rate"],
        },
        "policy": {
            "risk_level": "low" if export else "moderate",
            "network_policy": "deny" if export else "controlled",
            "requires_human_gate": config.hitl != "off" and canonical in _VERIFY_STEPS,
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

    cov = coverage(state)
    summary = {
        "has_recon": cov["recon"],
        "has_nuclei": cov["nuclei"],
        "assets": cov["assets"],
        "facts": cov["facts"],
        "findings": cov["finding_count"],
        "unverified": len(_unverified(state)),
        "exported": cov["exported"],
        "gaps": list(remaining),
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
    chosen = canonical_step(token)
    if chosen in remaining:
        return chosen
    return None
