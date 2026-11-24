"""Gap-driven next-action planner for an engagement.

The planner is code, not a model. It reads open gaps from engagement state
(missing recon/detect/nuclei, unverified findings, missing export) and returns
one aggregator step. An optional LLM suggestion may pick among coverage ledger
open rows that map to those steps; unknown suggestions are ignored.
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
_PHASE_TO_STEP = {
    "recon": "recon_run",
    "detect": "detect_run",
    "nuclei": "nuclei_scan",
    "verify": "verify_finding",
    "export": "export_findings",
}


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
    picks = coverage_picks(config, state, remaining)
    chosen = remaining[0]
    picked_finding = None
    if use_model or config.use_model:
        suggested = _model_pick(config, state, remaining, picks)
        if suggested is not None:
            chosen = str(suggested.get("step") or chosen)
            if suggested.get("kind") == "finding":
                picked_finding = _finding_from_pick(suggested, state)
    return _card(chosen, config, state, gaps, finding=picked_finding, open_rows=picks)


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


def coverage_picks(
    config: EngagementConfig,
    state: Mapping[str, Any],
    remaining: Sequence[str] | None = None,
) -> List[Dict[str, Any]]:
    """Open coverage rows whose step is currently actionable.

    Examined and ruled_out rows are dropped. Export stays out while verify
    findings are still open because it is not in ``remaining``.
    """
    from core.engage.ledger import build_coverage_ledger, open_coverage_rows

    allowed = set(
        remaining if remaining is not None else _remaining_names(open_gaps(config, state))
    )
    picks: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for row in open_coverage_rows(build_coverage_ledger(config, state)):
        step = _step_for_coverage_row(row)
        if step not in allowed:
            continue
        row_id = str(row.get("id") or "")
        if not row_id or row_id in seen:
            continue
        seen.add(row_id)
        picks.append(
            {
                "id": row_id,
                "kind": str(row.get("kind") or ""),
                "name": str(row.get("name") or ""),
                "step": step,
            }
        )
    return picks


def _step_for_coverage_row(row: Mapping[str, Any]) -> Optional[str]:
    kind = str(row.get("kind") or "")
    if kind == "phase":
        return _PHASE_TO_STEP.get(str(row.get("name") or ""))
    if kind == "finding":
        return "verify_finding"
    return None


def _finding_from_pick(
    pick: Mapping[str, Any], state: Mapping[str, Any]
) -> Optional[Dict[str, Any]]:
    row_id = str(pick.get("id") or "")
    prefix = "finding:"
    if not row_id.startswith(prefix):
        return None
    parts = row_id[len(prefix) :].split("|", 2)
    if len(parts) != 3:
        return None
    url, vuln_type, param = parts
    for item in _unverified(state):
        if (
            str(item.get("url") or "") == url
            and str(item.get("vuln_type") or item.get("type") or "") == vuln_type
            and str(item.get("param") or "") == param
        ):
            return dict(item)
    return None


def _card(
    step: str,
    config: EngagementConfig,
    state: Mapping[str, Any],
    gaps: Sequence[Mapping[str, Any]],
    *,
    finding: Optional[Mapping[str, Any]] = None,
    open_rows: Sequence[Mapping[str, Any]] | None = None,
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
        if finding is not None:
            inputs["finding"] = dict(finding)
        else:
            inputs["finding"] = pending[0] if pending else {}
    if canonical == "export_findings":
        inputs["output_dir"] = config.output_dir
    export = canonical in _EXPORT_STEPS
    from core.engage.ledger import build_coverage_ledger

    ledger = build_coverage_ledger(config, state)
    rows = [
        {"id": str(item.get("id") or ""), "step": str(item.get("step") or "")}
        for item in (open_rows if open_rows is not None else coverage_picks(config, state))
    ]
    return {
        "name": canonical,
        "kind": "tool_call",
        "inputs": inputs,
        "hint": next_hint(canonical),
        "gaps": [dict(item) for item in gaps],
        "remaining": _remaining_names(gaps),
        "open_rows": rows,
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


def _model_pick(
    config: EngagementConfig,
    state: Mapping[str, Any],
    remaining: Sequence[str],
    picks: Sequence[Mapping[str, Any]],
) -> Optional[Dict[str, Any]]:
    try:
        from core.llm.provider import LLMProvider
    except ImportError:
        return None
    provider = LLMProvider()
    if not provider.available:
        return None
    from core.llm.prompts import ENGAGE_PICK_SYSTEM_PROMPT, envelope_intro, wrap_untrusted

    allowed_steps = {str(item.get("step") or "") for item in picks if item.get("step")}
    allowed_ids = {str(item.get("id") or ""): dict(item) for item in picks if item.get("id")}
    if not allowed_steps:
        return None
    cov = coverage(state)
    tokens = ["%s -> %s" % (item.get("id"), item.get("step")) for item in picks]
    summary = {
        "has_recon": cov["recon"],
        "has_nuclei": cov["nuclei"],
        "assets": cov["assets"],
        "facts": cov["facts"],
        "findings": cov["finding_count"],
        "unverified": len(_unverified(state)),
        "exported": cov["exported"],
        "open_rows": [str(item.get("id") or "") for item in picks],
        "gaps": list(remaining),
    }
    nonce, framed = wrap_untrusted("state", str(summary))
    prompt = (
        "Pick exactly one open coverage token from this list: "
        + ", ".join(tokens)
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
    if token in allowed_ids:
        return allowed_ids[token]
    chosen = canonical_step(token)
    if chosen in allowed_steps:
        return {"id": None, "kind": "step", "name": chosen, "step": chosen}
    return None
