"""Engagement scorecard: confirmed vs unconfirmed findings with a denominator.

An empty finding list is a gap, not a clean target. confirmation_rate is null
when total is 0 so a dry-run or skipped detect cannot read as 100% confirmed.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Sequence

SCORECARD_SCHEMA = "autort.engage.scorecard/v1"
GAP_NO_FINDINGS = "no_findings_is_not_clean"
PROOF_BOUND = "bound"
PROOF_NONE = "none"


def build_scorecard(findings: Sequence[Mapping[str, Any]] | None) -> Dict[str, Any]:
    """Count evidence-gated findings. Detector self-reports stay unconfirmed."""
    from core.evidence import UNCONFIRMED_PREFIX, enforce_evidence_gate

    confirmed = 0
    unverified = 0
    contradicted = 0
    rows: list[Dict[str, Any]] = []
    for item in findings or []:
        if not isinstance(item, Mapping):
            continue
        gated, assessment = enforce_evidence_gate(dict(item))
        accepted = assessment.accepted()
        status = str(gated.get("verification_status") or assessment.status or "unverified")
        if accepted:
            confirmed += 1
            proof = PROOF_BOUND
        elif status == "contradicted":
            contradicted += 1
            proof = PROOF_NONE
        else:
            unverified += 1
            proof = PROOF_NONE
        title = gated.get("title") or gated.get("name") or gated.get("vuln_type") or ""
        rows.append(
            {
                "title": title,
                "severity": gated.get("severity"),
                "accepted": accepted,
                "verification_status": status,
                "proof": proof,
                "unconfirmed_prefix": (
                    isinstance(title, str) and title.startswith(UNCONFIRMED_PREFIX)
                ),
            }
        )
    total = confirmed + unverified + contradicted
    unconfirmed = unverified + contradicted
    gaps = [GAP_NO_FINDINGS] if total == 0 else []
    return {
        "schema": SCORECARD_SCHEMA,
        "total": total,
        "confirmed": confirmed,
        "unconfirmed": unconfirmed,
        "unverified": unverified,
        "contradicted": contradicted,
        "confirmation_rate": (confirmed / total) if total else None,
        "gaps": gaps,
        "findings": rows,
    }
