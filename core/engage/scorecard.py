"""Engagement scorecard: confirmed vs unconfirmed findings with a denominator."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Sequence

SCORECARD_SCHEMA = "autort.engage.scorecard/v1"


def build_scorecard(findings: Sequence[Mapping[str, Any]] | None) -> Dict[str, Any]:
    """Count evidence-gated findings. Detector self-reports stay unconfirmed."""
    from core.evidence import UNCONFIRMED_PREFIX, enforce_evidence_gate

    confirmed = 0
    unconfirmed = 0
    rows: list[Dict[str, Any]] = []
    for item in findings or []:
        if not isinstance(item, Mapping):
            continue
        gated, assessment = enforce_evidence_gate(dict(item))
        accepted = assessment.accepted()
        if accepted:
            confirmed += 1
        else:
            unconfirmed += 1
        title = gated.get("title") or gated.get("name") or gated.get("vuln_type") or ""
        rows.append(
            {
                "title": title,
                "severity": gated.get("severity"),
                "accepted": accepted,
                "verification_status": gated.get("verification_status") or assessment.status,
                "unconfirmed_prefix": (
                    isinstance(title, str) and title.startswith(UNCONFIRMED_PREFIX)
                ),
            }
        )
    return {
        "schema": SCORECARD_SCHEMA,
        "total": confirmed + unconfirmed,
        "confirmed": confirmed,
        "unconfirmed": unconfirmed,
        "findings": rows,
    }
