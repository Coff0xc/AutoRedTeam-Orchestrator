"""Local eval contract for MCP, skill, instruction, and run-state checks.

A suite (``schema: autort.eval/v1``) is ground truth: each case names a probe,
an input, and the expected scorer outcome. Probes stay local. They do not call
models, shells, or remote targets.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

import yaml

from core.ai_redteam.catalog import SCORERS
from core.ai_redteam.converters import convert_prompt
from core.ai_redteam.eval_cases import evaluate_run_cases
from core.ai_redteam.scorers import evaluate_text
from core.reporting.sarif import findings_to_sarif

EVAL_SCHEMA = "autort.eval/v1"
_PROBES = frozenset({"text", "surface", "skill", "run_state"})


def is_eval_suite(data: Mapping[str, Any]) -> bool:
    """Return True when ``data`` is an eval suite rather than a run-state dump."""
    schema = str(data.get("schema") or "").strip()
    if schema.startswith("autort.eval/"):
        return True
    return str(data.get("kind") or "").strip() == "eval_suite"


def load_eval_document(path: str | Path) -> Dict[str, Any]:
    """Load a YAML or JSON eval suite or run-state document."""
    document_path = Path(path)
    raw_text = document_path.read_text(encoding="utf-8")
    if document_path.suffix.lower() == ".json":
        loaded: Any = json.loads(raw_text)
    else:
        loaded = yaml.safe_load(raw_text)
    if not isinstance(loaded, dict):
        raise ValueError("Eval document must contain a mapping at the top level")
    return loaded


def evaluate_eval_document(
    data: Mapping[str, Any],
    *,
    base_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Evaluate a suite or an AgentRunState document."""
    if is_eval_suite(data):
        return evaluate_suite(data, base_dir=base_dir)
    from core.agent_runtime import agent_run_state_from_dict

    return evaluate_run_cases(agent_run_state_from_dict(data))


def evaluate_path(path: str | Path) -> Dict[str, Any]:
    """Load ``path`` and evaluate it as a suite or a run-state dump."""
    document_path = Path(path)
    return evaluate_eval_document(load_eval_document(document_path), base_dir=document_path.parent)


def evaluate_suite(
    data: Mapping[str, Any],
    *,
    base_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run every case in an ``autort.eval/v1`` suite against its expected labels."""
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("Eval suite must include a non-empty cases list")
    root = Path(base_dir) if base_dir is not None else Path.cwd()
    results = [_evaluate_case(item, root) for item in cases]
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for item in results:
        key = str(item["metadata"].get("outcome") or "fn")
        counts[key if key in counts else "fn"] += 1
    passed = all(item["passed"] for item in results)
    return {
        "schema": EVAL_SCHEMA,
        "success": True,
        "passed": passed,
        "name": str(data.get("name") or "eval-suite"),
        "cases": results,
        "summary": {
            "total": len(results),
            "passed": sum(1 for item in results if item["passed"]),
            "failed": sum(1 for item in results if not item["passed"]),
            **counts,
        },
    }


def suite_to_sarif(result: Mapping[str, Any]) -> Dict[str, Any]:
    """Render failed eval cases as SARIF results."""
    findings: List[Dict[str, Any]] = []
    for item in result.get("cases") or []:
        if item.get("passed"):
            continue
        evidence = item.get("evidence") or []
        message = "; ".join(str(part) for part in evidence) or "eval case failed"
        findings.append(
            {
                "rule_id": f"eval.{item.get('probe') or 'case'}",
                "title": item.get("case_id"),
                "severity": item.get("severity") or "high",
                "description": message,
                "evidence": message,
                "file_path": (item.get("metadata") or {}).get("path") or "eval-suite",
                "tool_name": item.get("case_id"),
            }
        )
    return findings_to_sarif(
        findings,
        tool_name="AutoRedTeam-Eval",
        run_properties={
            "eval_passed": bool(result.get("passed")),
            "eval_summary": result.get("summary") or {},
        },
    )


def _evaluate_case(raw: Any, base_dir: Path) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        return _case_result(
            case_id="invalid",
            probe="",
            passed=False,
            severity="high",
            evidence=["case must be a mapping"],
            expected={},
            observed={},
            outcome="fn",
        )
    case_id = str(raw.get("id") or raw.get("case_id") or "unnamed")
    probe = str(raw.get("probe") or "").strip()
    raw_input = raw.get("input")
    payload: Mapping[str, Any] = raw_input if isinstance(raw_input, Mapping) else {}
    raw_expect = raw.get("expect")
    expect: Mapping[str, Any] = raw_expect if isinstance(raw_expect, Mapping) else {}
    if probe not in _PROBES:
        return _case_result(
            case_id=case_id,
            probe=probe,
            passed=False,
            severity="high",
            evidence=[f"unknown probe {probe!r}; failing closed"],
            expected=dict(expect),
            observed={},
            outcome="fn",
        )
    try:
        if probe == "text":
            return _eval_text(case_id, payload, expect)
        if probe == "surface":
            return _eval_surface(case_id, payload, expect, base_dir)
        if probe == "skill":
            return _eval_skill(case_id, payload, expect, base_dir)
        return _eval_run_state(case_id, payload, expect)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _case_result(
            case_id=case_id,
            probe=probe,
            passed=False,
            severity="high",
            evidence=[str(exc)],
            expected=dict(expect),
            observed={},
            outcome="fn",
        )


def _eval_text(
    case_id: str, payload: Mapping[str, Any], expect: Mapping[str, Any]
) -> Dict[str, Any]:
    scorer = str(payload.get("scorer") or expect.get("scorer") or "")
    if scorer not in SCORERS:
        return _case_result(
            case_id=case_id,
            probe="text",
            passed=False,
            severity="high",
            evidence=[f"unknown scorer {scorer!r}; failing closed"],
            expected=dict(expect),
            observed={},
            outcome="fn",
        )
    text = str(payload.get("text") or "")
    converter = str(payload.get("converter") or "identity")
    if converter and converter != "identity":
        text = convert_prompt(text, converter).text
    scored = evaluate_text(scorer, text)
    expected_passed = bool(expect.get("passed", True))
    observed_passed = bool(scored.passed)
    matched = observed_passed == expected_passed
    return _case_result(
        case_id=case_id,
        probe="text",
        passed=matched,
        severity=scored.severity if not matched else "info",
        evidence=list(scored.evidence),
        expected={"passed": expected_passed, "scorer": scorer},
        observed={"passed": observed_passed, "scorer": scorer},
        outcome=_outcome(not expected_passed, not observed_passed),
        metadata={"converter": converter},
    )


def _eval_surface(
    case_id: str,
    payload: Mapping[str, Any],
    expect: Mapping[str, Any],
    base_dir: Path,
) -> Dict[str, Any]:
    from core.ai_surface import scan_handler_surface

    path = _resolve_path(payload.get("path"), base_dir)
    tool_name = str(payload.get("tool") or payload.get("name") or "")
    reconcile = payload.get("reconcile")
    exclude_tests = bool(payload.get("exclude_tests", False))
    result = scan_handler_surface(
        path,
        exclude_tests=exclude_tests,
        reconcile=None if reconcile is None else bool(reconcile),
    )
    by_name = {finding.tool_name: finding for finding in result.findings}
    finding = by_name.get(tool_name)
    observed_issues = list(finding.issues) if finding is not None else []
    expected_exact = _string_list(expect.get("issues"))
    expected_include = _string_list(expect.get("issues_include"))
    if expected_exact:
        matched = set(observed_issues) == set(expected_exact)
        expected_positive = bool(expected_exact)
    else:
        matched = set(expected_include).issubset(observed_issues)
        expected_positive = bool(expected_include)
    evidence = observed_issues or ["no issues"]
    if finding is None:
        evidence = [f"tool {tool_name!r} not found"]
        matched = False
    return _case_result(
        case_id=case_id,
        probe="surface",
        passed=matched,
        severity="medium" if matched else "high",
        evidence=evidence,
        expected={"issues": expected_exact, "issues_include": expected_include, "tool": tool_name},
        observed={"issues": observed_issues, "tool": tool_name},
        outcome=_outcome(expected_positive, bool(observed_issues) and matched),
        metadata={"path": str(path)},
    )


def _eval_skill(
    case_id: str,
    payload: Mapping[str, Any],
    expect: Mapping[str, Any],
    base_dir: Path,
) -> Dict[str, Any]:
    from core.skills import read_skill

    path = _resolve_path(payload.get("path"), base_dir)
    payload_out = read_skill(str(path))
    observed_stop = [str(item) for item in payload_out.get("operator_stop") or []]
    observed_blocked = bool(payload_out.get("blocked"))
    expected_stop = _string_list(expect.get("operator_stop_include"))
    expected_blocked = expect.get("blocked")
    stop_ok = set(expected_stop).issubset(observed_stop)
    blocked_ok = True if expected_blocked is None else bool(expected_blocked) == observed_blocked
    matched = stop_ok and blocked_ok
    expected_positive = bool(expected_stop) or bool(expected_blocked)
    observed_positive = bool(observed_stop) or observed_blocked
    evidence = observed_stop or ["no operator_stop markers"]
    if expected_blocked is not None:
        evidence.append(f"blocked={observed_blocked}")
    return _case_result(
        case_id=case_id,
        probe="skill",
        passed=matched,
        severity="info" if matched else "high",
        evidence=evidence,
        expected={"operator_stop_include": expected_stop, "blocked": expected_blocked},
        observed={"operator_stop": observed_stop, "blocked": observed_blocked},
        outcome=_outcome(expected_positive, observed_positive and matched),
        metadata={"path": str(path)},
    )


def _eval_run_state(
    case_id: str, payload: Mapping[str, Any], expect: Mapping[str, Any]
) -> Dict[str, Any]:
    from core.agent_runtime import agent_run_state_from_dict

    raw_state = payload.get("run_state") if "run_state" in payload else payload
    if not isinstance(raw_state, Mapping):
        return _case_result(
            case_id=case_id,
            probe="run_state",
            passed=False,
            severity="high",
            evidence=["run_state input must be a mapping"],
            expected=dict(expect),
            observed={},
            outcome="fn",
        )
    result = evaluate_run_cases(agent_run_state_from_dict(raw_state))
    failed = [
        str(item.get("case_id")) for item in result.get("cases") or [] if not item.get("passed")
    ]
    expected_failed = _string_list(expect.get("failed_cases"))
    expected_passed = bool(expect.get("passed", not expected_failed))
    if expected_failed:
        matched = set(expected_failed).issubset(failed)
        expected_positive = True
        observed_positive = matched
    else:
        matched = bool(result.get("passed")) == expected_passed
        expected_positive = not expected_passed
        observed_positive = bool(failed)
    return _case_result(
        case_id=case_id,
        probe="run_state",
        passed=matched,
        severity="info" if matched else "high",
        evidence=failed or ["all run-state eval cases passed"],
        expected={"passed": expected_passed, "failed_cases": expected_failed},
        observed={"passed": bool(result.get("passed")), "failed_cases": failed},
        outcome=_outcome(expected_positive, observed_positive and matched),
    )


def _case_result(
    *,
    case_id: str,
    probe: str,
    passed: bool,
    severity: str,
    evidence: Sequence[str],
    expected: Mapping[str, Any],
    observed: Mapping[str, Any],
    outcome: str,
    metadata: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "case_id": case_id,
        "probe": probe,
        "passed": passed,
        "severity": severity,
        "evidence": list(evidence),
        "expected": dict(expected),
        "observed": dict(observed),
        "metadata": {"outcome": outcome, **dict(metadata or {})},
    }
    return payload


def _outcome(expected_positive: bool, observed_positive: bool) -> str:
    if expected_positive and observed_positive:
        return "tp"
    if not expected_positive and observed_positive:
        return "fp"
    if expected_positive and not observed_positive:
        return "fn"
    return "tn"


def _string_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


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
