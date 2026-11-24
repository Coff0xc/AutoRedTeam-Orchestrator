"""Evidence-gate scorecard against the local XSS reflect lab.

Detector heuristics are not changed. The lab stays on 127.0.0.1.
"""

from __future__ import annotations

import pytest

from core.engage.scorecard import (
    GAP_NO_FINDINGS,
    PROOF_BOUND,
    PROOF_NONE,
    SCORECARD_SCHEMA,
    build_scorecard,
)
from core.evidence import UNCONFIRMED_PREFIX
from tests.test_verify_finding_fixture import _register_verify_finding, _serve

pytestmark = [pytest.mark.unit, pytest.mark.security]


@pytest.fixture
def raw_lab():
    yield from _serve("raw")


@pytest.fixture
def escaped_lab():
    yield from _serve("escaped")


def _self_report(url: str, *, severity: str = "high") -> dict:
    return {
        "url": url,
        "param": "q",
        "vuln_type": "xss",
        "verified": True,
        "confidence": 0.90,
        "evidence": "<html>reflected q=test</html>",
        "severity": severity,
        "title": "Reflected XSS in q",
    }


def test_scorecard_marks_detector_self_report_unconfirmed():
    card = build_scorecard([_self_report("http://127.0.0.1:9/reflect?q=test")])
    row = card["findings"][0]

    assert card["schema"] == SCORECARD_SCHEMA
    assert card["total"] == 1
    assert card["confirmed"] == 0
    assert card["unconfirmed"] == 1
    assert card["unverified"] == 1
    assert card["contradicted"] == 0
    assert card["confirmation_rate"] == 0.0
    assert card["gaps"] == []
    assert row["accepted"] is False
    assert row["proof"] == PROOF_NONE
    assert row["severity"] == "medium"
    assert str(row["title"]).startswith(UNCONFIRMED_PREFIX)


@pytest.mark.asyncio
async def test_scorecard_confirms_raw_reflection_and_rejects_escaped(raw_lab, escaped_lab):
    verify_finding = _register_verify_finding()
    raw = await verify_finding(
        finding={"url": f"{raw_lab}?q=test", "param": "q", "vuln_type": "xss"}
    )
    escaped = await verify_finding(
        finding={"url": f"{escaped_lab}?q=test", "param": "q", "vuln_type": "xss"}
    )
    raw_data = raw["data"]
    escaped_data = escaped["data"]

    confirmed = _self_report(f"{raw_lab}?q=test")
    confirmed["verified"] = True
    confirmed["evidence"] = raw_data["evidence"]
    confirmed["verified_by"] = "vuln_verifier"
    confirmed["verification_status"] = raw_data["verification_status"]
    confirmed["provenance"] = raw_data["provenance"]

    escaped_row = _self_report(f"{escaped_lab}?q=test")
    escaped_row["verified"] = bool(escaped_data.get("verified"))
    escaped_row["evidence"] = escaped_data.get("evidence")
    escaped_row["verification_status"] = escaped_data.get("verification_status")

    card = build_scorecard([confirmed, escaped_row])

    assert raw_data["verification_status"] == "verified"
    assert escaped_data["verification_status"] == "unverified"
    assert escaped_data["verified"] is False
    assert card["total"] == 2
    assert card["confirmed"] == 1
    assert card["unconfirmed"] == 1
    assert card["unverified"] == 0
    assert card["contradicted"] == 1
    assert card["confirmation_rate"] == 0.5
    assert card["gaps"] == []
    assert card["findings"][0]["accepted"] is True
    assert card["findings"][0]["proof"] == PROOF_BOUND
    assert card["findings"][1]["accepted"] is False
    assert card["findings"][1]["proof"] == PROOF_NONE
    assert card["findings"][1]["verification_status"] == "contradicted"
    assert str(card["findings"][1]["title"]).startswith(UNCONFIRMED_PREFIX)
    assert card["findings"][1]["severity"] in {"medium", "low", "info"}


def test_empty_scorecard_is_a_gap_not_a_clean_target():
    card = build_scorecard([])
    none_card = build_scorecard(None)

    for item in (card, none_card):
        assert item["schema"] == SCORECARD_SCHEMA
        assert item["total"] == 0
        assert item["confirmed"] == 0
        assert item["unconfirmed"] == 0
        assert item["unverified"] == 0
        assert item["contradicted"] == 0
        assert item["confirmation_rate"] is None
        assert item["gaps"] == [GAP_NO_FINDINGS]
        assert item["findings"] == []


def test_scorecard_splits_contradicted_from_unverified():
    contradicted = {
        "url": "http://127.0.0.1:9/reflect?q=test",
        "param": "q",
        "vuln_type": "xss",
        "verified": False,
        "confidence": "high",
        "evidence": "no delay observed",
        "severity": "high",
        "title": "Reflected XSS in q",
    }
    card = build_scorecard([contradicted, _self_report("http://127.0.0.1:9/reflect?q=x")])

    assert card["total"] == 2
    assert card["confirmed"] == 0
    assert card["unconfirmed"] == 2
    assert card["unverified"] == 1
    assert card["contradicted"] == 1
    assert card["confirmation_rate"] == 0.0
    assert card["gaps"] == []
    assert card["findings"][0]["verification_status"] == "contradicted"
    assert card["findings"][0]["proof"] == PROOF_NONE
    assert card["findings"][1]["verification_status"] == "unverified"
