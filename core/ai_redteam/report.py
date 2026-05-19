"""Report rendering helpers for AI red-team runs."""

from __future__ import annotations

from typing import Any, Dict, List

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def summarize_scores(scores: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize evaluated and planned scores."""
    by_severity = {severity: 0 for severity in SEVERITY_ORDER}
    failed = 0
    evaluated = 0
    for score in scores:
        severity = str(score.get("severity", "info")).lower()
        by_severity[severity] = by_severity.get(severity, 0) + 1
        if score.get("status") == "evaluated":
            evaluated += 1
        if score.get("passed") is False:
            failed += 1
    return {
        "total": len(scores),
        "evaluated": evaluated,
        "failed": failed,
        "by_severity": by_severity,
    }


def severity_meets_threshold(severity: str, threshold: str) -> bool:
    """Return whether severity is at or above threshold."""
    return SEVERITY_ORDER.get(severity.lower(), -1) >= SEVERITY_ORDER.get(
        threshold.lower(), 3
    )


def should_fail_ci(result: Dict[str, Any], threshold: str = "high") -> bool:
    """Return whether a run result should fail CI."""
    for score in result.get("scores", []):
        if score.get("passed") is False and severity_meets_threshold(
            str(score.get("severity", "info")), threshold
        ):
            return True
    return False


def render_markdown(result: Dict[str, Any]) -> str:
    """Render a compact markdown report."""
    summary = result.get("summary", {})
    score_summary = summarize_scores(result.get("scores", []))
    lines = [
        f"# AI Red-Team Report: {result.get('scenario', {}).get('name', 'scenario')}",
        "",
        f"- Mode: `{summary.get('mode')}`",
        f"- Attempts planned: `{summary.get('attempts_planned')}`",
        f"- Scores: `{summary.get('scores')}`",
        f"- Evaluated scores: `{score_summary['evaluated']}`",
        f"- Failed scores: `{score_summary['failed']}`",
        "",
        "## Warnings",
    ]
    warnings = result.get("warnings", [])
    if warnings:
        lines.extend(f"- {warning}" for warning in warnings)
    else:
        lines.append("- None")

    lines.extend(["", "## Score Summary"])
    for severity, count in score_summary["by_severity"].items():
        lines.append(f"- {severity}: {count}")
    return "\n".join(lines) + "\n"
