"""Run an engagement: plan, execute aggregators, gate evidence, stop on doom-loop."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, Optional

from core.agent_runtime.aggregators import AGGREGATOR_STEPS, dispatch_aggregator_step
from core.agent_runtime.models import (
    Action,
    ActionKind,
    ActionPolicy,
    AgentRunState,
    Flow,
    RunMode,
    Task,
)
from core.agent_runtime.observability import build_observability_snapshot
from core.agent_runtime.registry import register_runtime_run
from core.capability_manifest import require_surface
from core.engage.config import (
    EngagementConfig,
    EngagementError,
    config_path,
    load_config,
    save_config,
    state_path,
)
from core.engage.planner import ENGAGE_STEPS, plan_next
from core.security.target_scope import assert_in_scope

CAPABILITY_ENV = "AUTORT_CAPABILITY_PROFILE"
SCOPE_ENV = "AUTORT_TARGET_SCOPE"
ALLOWLIST_ENV = "AUTORT_TARGET_ALLOWLIST"
HITL_ENV = "AUTORT_HITL_MODE"
_DOOM_LIMIT = 3


def execution_id(name: str, inputs: Mapping[str, Any]) -> str:
    blob = json.dumps({"name": name, "inputs": dict(inputs)}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@contextmanager
def applied_engagement(config: EngagementConfig) -> Iterator[None]:
    """Pin profile, allowlist, and HITL for the duration of one run."""
    updates = {
        CAPABILITY_ENV: config.profile,
        SCOPE_ENV: config.scope_mode,
        ALLOWLIST_ENV: ",".join(config.allowlist),
        HITL_ENV: config.hitl,
    }
    previous = {key: os.environ.get(key) for key in updates}
    try:
        os.environ.update(updates)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def init_engagement(
    target: str,
    *,
    profile: str = "scan",
    path: Optional[str | Path] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Write ``.autort/engage.yaml`` and return the saved document."""
    require_surface("engage_init")
    cleaned = {key: value for key, value in kwargs.items() if value is not None}
    document = config_path(path)
    if "output_dir" not in cleaned:
        cleaned["output_dir"] = str(document.parent)
    config = EngagementConfig(target=target, profile=profile, **cleaned)
    document = save_config(config, path)
    Path(config.output_dir).mkdir(parents=True, exist_ok=True)
    return {
        "success": True,
        "path": str(document),
        "config": config.to_dict(),
        "next": plan_next(config, empty_state()),
    }


def engagement_status(path: Optional[str | Path] = None) -> Dict[str, Any]:
    require_surface("engage_status")
    config = load_config(path)
    state = load_state(config)
    return {
        "success": True,
        "config": config.to_dict(),
        "state": public_state(state),
        "next": plan_next(config, state),
    }


def engagement_next(path: Optional[str | Path] = None) -> Dict[str, Any]:
    require_surface("engage_next")
    config = load_config(path)
    state = load_state(config)
    nxt = plan_next(config, state)
    return {
        "success": True,
        "next": nxt,
        "finalizable": nxt is None,
        "hint": None if nxt is None else nxt.get("hint"),
    }


def run_engagement(
    path: Optional[str | Path] = None,
    *,
    dry_run: bool = False,
    max_steps: Optional[int] = None,
    config: Optional[EngagementConfig] = None,
) -> Dict[str, Any]:
    """Sync wrapper for CLI and RuntimeLoop."""
    return _await(async_run_engagement(path, dry_run=dry_run, max_steps=max_steps, config=config))


async def async_run_engagement(
    path: Optional[str | Path] = None,
    *,
    dry_run: bool = False,
    max_steps: Optional[int] = None,
    config: Optional[EngagementConfig] = None,
) -> Dict[str, Any]:
    selected = config or load_config(path)
    with applied_engagement(selected):
        if dry_run:
            require_surface("engage_next")
        else:
            require_surface("engage_run")
            assert_in_scope(selected.target)
        return await _run(selected, dry_run=dry_run, max_steps=max_steps)


async def dispatch_engage_step(
    name: str,
    inputs: Mapping[str, Any],
    state: Dict[str, Any],
    *,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Execute one engage.* or aggregator step and merge results into ``state``."""
    if name in AGGREGATOR_STEPS:
        return await dispatch_aggregator_step(name, inputs, state, dry_run=dry_run)
    if name not in ENGAGE_STEPS:
        raise EngagementError("unknown engage step %r" % name)
    if dry_run:
        output = {"success": True, "dry_run": True, "step": name, "inputs": dict(inputs)}
        _record_dry(state, name, output)
        return output
    if name == "engage.recon":
        return await _exec_recon(inputs, state)
    if name == "engage.detect":
        return await _exec_detect(inputs, state)
    if name == "engage.verify":
        return await _exec_verify(inputs, state)
    return await _exec_export(inputs, state)


def empty_state() -> Dict[str, Any]:
    return {
        "status": "init",
        "recon": None,
        "nuclei": None,
        "findings": None,
        "verified": [],
        "exported": False,
        "report_path": None,
        "executed": [],
        "repeats": {},
        "stopped": None,
    }


def load_state(config: EngagementConfig) -> Dict[str, Any]:
    document = state_path(config)
    if not document.is_file():
        return empty_state()
    raw = json.loads(document.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return empty_state()
    state = empty_state()
    state.update(raw)
    return state


def save_state(config: EngagementConfig, state: Mapping[str, Any]) -> Path:
    document = state_path(config)
    document.parent.mkdir(parents=True, exist_ok=True)
    document.write_text(json.dumps(dict(state), indent=2, default=str), encoding="utf-8")
    return document


def public_state(state: Mapping[str, Any]) -> Dict[str, Any]:
    findings = state.get("findings")
    verified = state.get("verified") if isinstance(state.get("verified"), list) else []
    return {
        "status": state.get("status"),
        "has_recon": bool(state.get("recon")),
        "finding_count": len(findings) if isinstance(findings, list) else 0,
        "verified_count": len(verified),
        "exported": bool(state.get("exported")),
        "report_path": state.get("report_path"),
        "stopped": state.get("stopped"),
        "executed": list(state.get("executed") or []),
    }


async def _run(
    config: EngagementConfig, *, dry_run: bool, max_steps: Optional[int]
) -> Dict[str, Any]:
    state = load_state(config)
    limit = int(max_steps or config.max_steps)
    flow = Flow(name=config.name, metadata={"schema": "autort.engage/v1", "dry_run": dry_run})
    task = flow.add_task(Task(name="engage", description="Authorized engagement loop"))
    run_state = AgentRunState(
        flow=flow,
        mode=RunMode.DRY_RUN if dry_run else RunMode.ACTIVE,
        metadata={"component": "engage", "target": config.target, "profile": config.profile},
    )
    processed = 0
    stopped: Optional[str] = None
    while processed < limit:
        nxt = plan_next(config, state)
        if nxt is None:
            state["status"] = "complete"
            break
        fingerprint = execution_id(str(nxt["name"]), nxt.get("inputs") or {})
        repeats = dict(state.get("repeats") or {})
        repeats[fingerprint] = int(repeats.get(fingerprint) or 0) + 1
        state["repeats"] = repeats
        if repeats[fingerprint] > _DOOM_LIMIT:
            stopped = "doom_loop"
            state["status"] = "doom_loop"
            state["stopped"] = stopped
            break
        action = _action_from_card(nxt)
        task.add_action(action)
        hitl_stop = await _maybe_hitl(action, dry_run=dry_run)
        if hitl_stop:
            stopped = hitl_stop
            state["status"] = hitl_stop
            state["stopped"] = hitl_stop
            break
        try:
            output = await dispatch_engage_step(action.name, action.inputs, state, dry_run=dry_run)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            action.mark_failed(str(exc))
            stopped = "step_failed"
            state["status"] = "failed"
            state["stopped"] = str(exc)
            break
        action.mark_completed(output)
        executed = list(state.get("executed") or [])
        executed.append(fingerprint)
        state["executed"] = executed
        state["status"] = "running"
        processed += 1
        run_state.add_trace(
            "engage_step", action.name, action_id=action.action_id, step=action.name
        )
    else:
        if plan_next(config, state) is not None:
            stopped = "max_steps"
            state["stopped"] = stopped
            state["status"] = "max_steps"
    save_state(config, state)
    run_state.metadata["engage"] = public_state(state)
    run_state.metadata["observability"] = build_observability_snapshot(run_state).to_dict()
    register_runtime_run(run_state)
    nxt = plan_next(config, state)
    confirmed = [
        item
        for item in (state.get("verified") or [])
        if isinstance(item, dict) and item.get("verification_status") == "verified"
    ]
    gated_findings = (
        [_gate_finding(item) for item in (state.get("findings") or []) if isinstance(item, dict)]
        if isinstance(state.get("findings"), list)
        else []
    )
    from core.engage.scorecard import build_scorecard

    return {
        "success": stopped is None,
        "passed": stopped is None and state.get("status") == "complete",
        "dry_run": dry_run,
        "config": config.to_dict(),
        "state": public_state(state),
        "next": nxt,
        "confirmed": confirmed,
        "findings": gated_findings,
        "scorecard": build_scorecard(gated_findings),
        "loop": {"processed": processed, "stopped": stopped, "max_steps": limit},
        "run_state": run_state.to_dict(),
        "summary": run_state.summary(),
    }


async def _maybe_hitl(action: Action, *, dry_run: bool) -> Optional[str]:
    """Ask HITL before a live verify step. Dry-run skips the gate."""
    if dry_run or not action.policy.requires_human_gate:
        return None
    from core.security.hitl import gate_tool

    level = action.policy.risk_level
    auth_level = level.value if hasattr(level, "value") else str(level)
    decision = await gate_tool(action.name, action.inputs, auth_level)
    if not decision.allowed:
        action.mark_blocked(decision.reason)
        return "hitl_denied"
    if decision.edited_kwargs:
        action.inputs.update(decision.edited_kwargs)
    return None


def _action_from_card(card: Mapping[str, Any]) -> Action:
    policy_raw = card.get("policy") if isinstance(card.get("policy"), Mapping) else {}
    return Action(
        name=str(card["name"]),
        kind=ActionKind.TOOL_CALL,
        inputs=dict(card.get("inputs") or {}),
        policy=ActionPolicy(
            risk_level=str(policy_raw.get("risk_level") or "moderate"),
            requires_human_gate=bool(policy_raw.get("requires_human_gate", False)),
            allowed_in_dry_run=bool(policy_raw.get("allowed_in_dry_run", True)),
            network_policy=str(policy_raw.get("network_policy") or "controlled"),
        ),
    )


async def _exec_recon(inputs: Mapping[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    require_surface("full_recon")
    from autort import Scanner

    target = str(inputs.get("target") or "")
    scanner = Scanner(target, config={"quick_mode": bool(inputs.get("quick_mode", True))})
    result = await scanner.full_recon()
    state["recon"] = result
    return {"success": True, "step": "engage.recon", "recon": result}


async def _exec_detect(inputs: Mapping[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    require_surface("detect_run")
    import core.detectors  # noqa: F401
    from core.detectors import DetectorFactory, DetectorPresets
    from core.detectors.names import canonical_detector_class

    url = str(inputs.get("target") or inputs.get("url") or "")
    raw_classes = inputs.get("classes")
    if raw_classes:
        names = [canonical_detector_class(str(item)) for item in raw_classes]
        composite = DetectorFactory.create_composite(names)
        used = names
    else:
        composite = DetectorPresets.owasp_top10()
        used = ["owasp_top10"]
    results = await composite.async_detect(url)
    findings = []
    for item in results or []:
        payload = item.to_dict() if hasattr(item, "to_dict") else item
        if isinstance(payload, dict) and payload.get("vulnerable"):
            findings.append(payload)
    state["findings"] = findings
    return {
        "success": True,
        "step": "engage.detect",
        "findings": findings,
        "total_vulns": len(findings),
        "detectors_used": used,
    }


async def _exec_verify(inputs: Mapping[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    require_surface("verify_finding")
    finding = inputs.get("finding")
    if not isinstance(finding, dict):
        raise EngagementError("engage.verify requires a finding object")
    from core.evidence import assess_finding, evidence_from_verification
    from core.vuln_verifier import VulnerabilityVerifier

    url = str(finding.get("url") or inputs.get("target") or "")
    vuln_type = str(finding.get("vuln_type") or finding.get("type") or "")
    param = str(finding.get("param") or "")
    verify_input = dict(finding)
    verify_input.setdefault("type", vuln_type)
    verify_input.setdefault("param", param)
    verify_input.setdefault("url", url)
    verifier = VulnerabilityVerifier(timeout=10)
    results = await asyncio.to_thread(verifier.batch_verify, [verify_input])
    evidence_items = [evidence_from_verification(item) for item in results]
    verified = any(getattr(item, "is_vulnerable", False) is True for item in results)
    status = "verified" if verified else "unverified"
    gate_input = dict(finding)
    gate_input["verified"] = verified
    gate_input["verified_by"] = "vuln_verifier" if verified else gate_input.get("verified_by")
    gate_input["evidence"] = [item.to_dict() for item in evidence_items]
    assessment = assess_finding(gate_input)
    gated = _gate_finding(gate_input)
    record = {
        **gated,
        "verification_status": status,
        "engagement_verified": verified,
        "assessment": assessment.to_dict(),
    }
    findings = list(state.get("findings") or [])
    updated = False
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            continue
        if item.get("url") == finding.get("url") and item.get("vuln_type") == finding.get(
            "vuln_type"
        ):
            findings[index] = {**item, **record}
            updated = True
            break
    if not updated:
        findings.append(record)
    state["findings"] = findings
    verified_rows = list(state.get("verified") or [])
    verified_rows.append(record)
    state["verified"] = verified_rows
    return {"success": True, "step": "engage.verify", "finding": record}


async def _exec_export(inputs: Mapping[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    require_surface("export_findings")
    output_dir = Path(str(inputs.get("output_dir") or ".autort"))
    output_dir.mkdir(parents=True, exist_ok=True)
    findings = [item for item in (state.get("findings") or []) if isinstance(item, dict)]
    gated = [_gate_finding(item) for item in findings]
    from core.engage.scorecard import build_scorecard

    card = build_scorecard(gated)
    report = {
        "schema": "autort.engage.report/v1",
        "findings": gated,
        "confirmed": [
            item for item in gated if str(item.get("verification_status") or "") == "verified"
        ],
        "unconfirmed": [
            item for item in gated if str(item.get("verification_status") or "") != "verified"
        ],
        "scorecard": card,
        "state": public_state(state),
    }
    report_path = output_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    state["exported"] = True
    state["report_path"] = str(report_path)
    return {
        "success": True,
        "step": "engage.export",
        "report_path": str(report_path),
        "report": report,
    }


def _gate_finding(finding: Mapping[str, Any]) -> Dict[str, Any]:
    from core.evidence import enforce_evidence_gate

    gated, _assessment = enforce_evidence_gate(dict(finding))
    return gated


def _record_dry(state: Dict[str, Any], name: str, output: Mapping[str, Any]) -> None:
    if name == "engage.recon":
        state["recon"] = {"dry_run": True}
    elif name == "engage.detect":
        state["findings"] = []
    elif name == "engage.verify":
        findings = list(state.get("findings") or [])
        for item in findings:
            if not isinstance(item, dict):
                continue
            if item.get("engagement_verified") is True:
                continue
            if str(item.get("verification_status") or "") == "verified":
                continue
            item["engagement_verified"] = True
            item["verification_status"] = "dry_run"
            break
        state["findings"] = findings
        state.setdefault("verified", [])
    elif name == "engage.export":
        state["exported"] = True
        state["report_path"] = "(dry-run)"


def _await(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise EngagementError("async engagement is already running; await async_run_engagement")
