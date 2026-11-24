"""Request/response receipts bound as finding provenance."""

from __future__ import annotations

from core.evidence import (
    PROVENANCE_SCHEMA,
    UNCONFIRMED_PREFIX,
    assess_finding,
    build_provenance_receipt,
    enforce_evidence_gate,
    is_bound,
    receipt_from_results,
)
from core.vuln_verifier.models import VerificationResult


def _result(**kwargs) -> VerificationResult:
    payload = {
        "vuln_type": "xss",
        "payload": "q=<script>",
        "url": "http://127.0.0.1:9/reflect?q=x",
        "is_vulnerable": True,
        "confidence": "high",
        "evidence": "<html><div><script></div></html>",
        "response_time": 0.02,
        "response_code": 200,
        "response_length": 32,
        "verification_method": "reflected_xss",
    }
    payload.update(kwargs)
    return VerificationResult(**payload)


def test_receipt_binds_url_and_response():
    receipt = build_provenance_receipt(_result())
    assert receipt["schema"] == PROVENANCE_SCHEMA
    assert receipt["bound"] is True
    assert receipt["request"]["url"].startswith("http://127.0.0.1:9/")
    assert receipt["response"]["status"] == 200
    assert receipt["response"]["body_sha256"]
    assert "<script>" in receipt["response"]["body_preview"]


def test_empty_results_are_unbound():
    receipt = receipt_from_results([])
    assert receipt["bound"] is False
    assert is_bound({"provenance": receipt}) is False


def test_gate_requires_receipt_when_asked():
    finding = {
        "verified": True,
        "confidence": "high",
        "verified_by": "vuln_verifier",
        "evidence": [{"summary": "echo", "method": "reflected_xss"}],
        "title": "XSS",
        "severity": "high",
    }
    loose = assess_finding(finding)
    strict = assess_finding(finding, require_receipt=True)
    assert loose.status == "verified"
    assert strict.status == "unverified"
    assert "no bound request/response receipt" in strict.missing_checks

    finding["provenance"] = build_provenance_receipt(_result())
    accepted, assessment = enforce_evidence_gate(finding, require_receipt=True)
    assert assessment.accepted() is True
    assert is_bound(accepted) is True
    assert not str(accepted.get("title") or "").startswith(UNCONFIRMED_PREFIX)
