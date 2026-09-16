"""证据门禁单测（P2 core/evidence）。

覆盖 assess_finding 的严格判据、enforce_evidence_gate 的降级/前缀/不可变性，
以及 evidence_from_verification 对多种输入形态的 duck typing 兼容。
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List

from core.evidence import (
    EvidenceAssessment,
    EvidenceItem,
    assess_finding,
    enforce_evidence_gate,
    evidence_from_verification,
)


@dataclass
class FakeVerificationResult:
    """结构等价于 core.vuln_verifier.models.VerificationResult。"""

    vuln_type: str
    payload: str
    url: str
    is_vulnerable: bool
    confidence: str
    evidence: str
    response_time: float
    response_code: int
    response_length: int
    verification_method: str
    recommendation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class FakeStatisticalVerification:
    """结构等价于 core.vuln_verifier.models.StatisticalVerification。"""

    vuln_type: str
    url: str
    param: str
    payload: str
    rounds: int
    positive_count: int
    confidence_score: float
    is_confirmed: bool
    details: List[Dict] = field(default_factory=list)
    recommendation: str = ""


# --------------------------------------------------------------------------- #
# assess_finding
# --------------------------------------------------------------------------- #


def test_assess_verified_when_high_confidence_and_evidence():
    finding = {
        "verified": True,
        "confidence": "high",
        "evidence": "time-based delay of 5s reproduced 3 times",
        "verification_method": "time_based_sqli",
        "severity": "critical",
        "title": "SQL Injection",
    }

    assessment = assess_finding(finding)

    assert assessment.status == "verified"
    assert assessment.accepted() is True
    assert assessment.confidence == "high"
    assert assessment.missing_checks == []
    assert len(assessment.evidence) == 1
    assert assessment.evidence[0].kind == "statistical"
    assert assessment.evidence[0].method == "time_based_sqli"


def test_assess_unverified_when_verified_true_but_low_confidence():
    finding = {"verified": True, "confidence": "low", "evidence": "weak signal"}

    assessment = assess_finding(finding)

    assert assessment.status == "unverified"
    assert assessment.accepted() is False
    assert "confidence below threshold" in assessment.missing_checks


def test_assess_contradicted_when_verified_false():
    finding = {"verified": False, "confidence": "high", "evidence": "no delay observed"}

    assessment = assess_finding(finding)

    assert assessment.status == "contradicted"
    assert assessment.accepted() is False
    assert "verification reported contradiction" in assessment.missing_checks


def test_assess_contradicted_when_confidence_false_positive():
    finding = {"verified": True, "confidence": "false_positive", "evidence": "baseline noise"}

    assessment = assess_finding(finding)

    assert assessment.status == "contradicted"


def test_assess_missing_verified_flag_is_unverified():
    finding = {"confidence": "high", "evidence": "looks good", "title": "XSS"}

    assessment = assess_finding(finding)

    assert assessment.status == "unverified"
    assert "verified flag missing" in assessment.missing_checks


def test_assess_missing_evidence_is_unverified():
    finding = {"verified": True, "confidence": "high"}

    assessment = assess_finding(finding)

    assert assessment.status == "unverified"
    assert "no evidence attached" in assessment.missing_checks


def test_numeric_confidence_mapping():
    base = {"verified": True, "evidence": [{"summary": "proof", "method": "time_based_sqli"}]}

    high = assess_finding({**base, "confidence": 0.9})
    medium = assess_finding({**base, "confidence": 0.5})
    low = assess_finding({**base, "confidence": 0.1})

    assert (high.status, high.confidence) == ("verified", "high")
    assert (medium.status, medium.confidence) == ("verified", "medium")
    assert (low.status, low.confidence) == ("unverified", "low")
    assert "confidence below threshold" in low.missing_checks


def test_assess_non_dict_input_does_not_crash():
    assessment = assess_finding("not a mapping")  # type: ignore[arg-type]

    assert isinstance(assessment, EvidenceAssessment)
    assert assessment.status == "unverified"
    assert "verified flag missing" in assessment.missing_checks


def test_assessment_to_dict_serializable():
    assessment = assess_finding(
        {
            "verified": True,
            "confidence": "high",
            "evidence": [{"summary": "proof", "method": "replay"}],
            "title": "X",
        }
    )

    payload = assessment.to_dict()

    assert payload["status"] == "verified"
    assert payload["accepted"] is True
    assert payload["evidence"][0]["summary"] == "proof"


# --------------------------------------------------------------------------- #
# enforce_evidence_gate
# --------------------------------------------------------------------------- #


def test_gate_accepts_verified_finding_unchanged():
    finding = {
        "verified": True,
        "confidence": "high",
        "evidence": [{"summary": "confirmed", "method": "time_based_sqli"}],
        "severity": "critical",
        "title": "SQL Injection",
    }

    processed, assessment = enforce_evidence_gate(finding)

    assert assessment.accepted() is True
    assert processed["severity"] == "critical"
    assert processed["title"] == "SQL Injection"
    assert "missing_checks" not in processed


# --------------------------------------------------------------------------- #
# 独立验证来源（provenance）：探测器自述不得当已验证
# --------------------------------------------------------------------------- #


def test_detector_self_declared_verification_is_not_accepted():
    """真实场景：core/detectors/ 多处自行写 verified=True + confidence=0.90。

    这类 finding 的 evidence 是响应片段字符串，没有验证方法，门禁必须判为
    unverified 并降级，否则门禁退化成“字段填没填”。
    """
    detector_finding = {
        "verified": True,
        "confidence": 0.90,
        "evidence": "<html>redirected to https://evil.example/</html>",
        "severity": "critical",
        "title": "Open Redirect in next",
    }

    processed, assessment = enforce_evidence_gate(detector_finding)

    assert assessment.status == "unverified"
    assert assessment.accepted() is False
    assert "no independent verification provenance" in assessment.missing_checks
    assert processed["severity"] == "medium"
    assert processed["title"].startswith("[UNCONFIRMED] ")


def test_explicit_verified_by_marker_counts_as_provenance():
    finding = {
        "verified": True,
        "confidence": "high",
        "evidence": "callback received",
        "verified_by": "oob_callback",
    }

    assert assess_finding(finding).accepted() is True


def test_unknown_verified_by_marker_is_not_provenance():
    finding = {
        "verified": True,
        "confidence": "high",
        "evidence": "self-declared",
        "verified_by": "detector",
    }

    assert assess_finding(finding).status == "unverified"


def test_require_provenance_false_restores_permissive_behaviour():
    finding = {
        "verified": True,
        "confidence": "high",
        "evidence": "self-declared only",
        "severity": "critical",
        "title": "Legacy finding",
    }

    processed, assessment = enforce_evidence_gate(finding, require_provenance=False)

    assert assessment.accepted() is True
    assert processed["severity"] == "critical"
    assert "[UNCONFIRMED]" not in processed["title"]


def test_gate_does_not_prefix_grouping_key():
    """type 是下游分组键，不能被 [UNCONFIRMED] 弄脏。"""
    finding = {"type": "sqli", "severity": "high"}

    processed, _ = enforce_evidence_gate(finding)

    assert processed["type"] == "sqli"
    assert processed is not finding
    assert processed["verification_status"] == "unverified"


def test_gate_downgrades_low_confidence_and_prefixes_title():
    finding = {
        "verified": True,
        "confidence": "low",
        "evidence": "weak",
        "severity": "critical",
        "title": "SQL Injection",
    }

    processed, assessment = enforce_evidence_gate(finding)

    assert assessment.status == "unverified"
    assert processed["severity"] == "medium"
    assert processed["title"] == "[UNCONFIRMED] SQL Injection"
    assert processed["verification_status"] == "unverified"
    assert "confidence below threshold" in processed["missing_checks"]


def test_gate_downgrades_contradicted_finding():
    finding = {
        "verified": False,
        "confidence": "high",
        "evidence": "no signal",
        "severity": "high",
        "title": "XSS",
    }

    processed, assessment = enforce_evidence_gate(finding)

    assert assessment.status == "contradicted"
    assert processed["severity"] == "medium"
    assert processed["title"] == "[UNCONFIRMED] XSS"


def test_gate_keeps_severity_at_or_below_cap():
    finding = {
        "verified": True,
        "confidence": "low",
        "evidence": "weak",
        "severity": "low",
        "title": "Info leak",
    }

    processed, _ = enforce_evidence_gate(finding)

    assert processed["severity"] == "low"


def test_gate_prefix_is_idempotent():
    finding = {
        "verified": True,
        "confidence": "low",
        "evidence": "weak",
        "severity": "high",
        "title": "[UNCONFIRMED] SQL Injection",
    }

    first, _ = enforce_evidence_gate(finding)
    second, _ = enforce_evidence_gate(first)

    assert first["title"] == "[UNCONFIRMED] SQL Injection"
    assert second["title"] == "[UNCONFIRMED] SQL Injection"


def test_gate_does_not_mutate_input_finding():
    finding = {
        "verified": True,
        "confidence": "low",
        "evidence": "weak",
        "severity": "critical",
        "title": "SQL Injection",
        "type": "sqli",
        "name": "sqli-1",
    }
    snapshot = {
        "verified": finding["verified"],
        "confidence": finding["confidence"],
        "evidence": finding["evidence"],
        "severity": finding["severity"],
        "title": finding["title"],
        "type": finding["type"],
        "name": finding["name"],
    }

    processed, _ = enforce_evidence_gate(finding)

    assert finding == snapshot
    assert "verification_status" not in finding
    assert "missing_checks" not in finding
    # 只对展示标题加前缀；type/name 保持干净以供分组统计
    assert processed["title"] == "[UNCONFIRMED] SQL Injection"
    assert processed["type"] == "sqli"
    assert processed["name"] == "sqli-1"


def test_gate_custom_cap_and_missing_name_key():
    finding = {
        "verified": False,
        "confidence": "high",
        "evidence": "contradiction",
        "severity": "critical",
        "type": "rce",
    }

    processed, _ = enforce_evidence_gate(finding, max_unverified_severity="low")

    assert processed["severity"] == "low"
    # 无 title/name 时不动 type（分组键），靠 verification_status 表达状态
    assert processed["type"] == "rce"
    assert processed["verification_status"] == "contradicted"
    assert "title" not in processed


def test_gate_handles_odd_field_types_without_crashing():
    finding = {
        "verified": "yes",  # 非 bool
        "confidence": ["high"],  # 非 str/float
        "evidence": {"summary": "nested proof"},
        "severity": 7,  # 非 str
        "title": None,
    }

    processed, assessment = enforce_evidence_gate(finding)

    assert assessment.status == "unverified"
    assert processed["severity"] == 7
    assert processed["title"] is None
    assert "verified flag missing" in processed["missing_checks"]


def test_gate_non_dict_input_does_not_crash():
    processed, assessment = enforce_evidence_gate(None)  # type: ignore[arg-type]

    assert processed == {}
    assert assessment.status == "unverified"


# --------------------------------------------------------------------------- #
# evidence_from_verification
# --------------------------------------------------------------------------- #


def test_evidence_from_fake_verification_result():
    result = FakeVerificationResult(
        vuln_type="sql_injection",
        payload="' OR 1=1--",
        url="http://target.local/item?id=1",
        is_vulnerable=True,
        confidence="high",
        evidence="error page leaked SQL syntax",
        response_time=0.42,
        response_code=500,
        response_length=1234,
        verification_method="error_based_sqli",
    )

    item = evidence_from_verification(result)

    assert isinstance(item, EvidenceItem)
    assert item.kind == "http_response"
    assert item.method == "error_based_sqli"
    assert item.payload == "' OR 1=1--"
    assert item.url == "http://target.local/item?id=1"
    assert item.response_code == 500
    assert item.response_time == 0.42
    assert item.confidence == "high"
    assert "sql_injection" in item.summary
    assert item.raw["vuln_type"] == "sql_injection"


def test_evidence_from_fake_statistical_verification():
    result = FakeStatisticalVerification(
        vuln_type="time_based_sqli",
        url="http://target.local/item?id=1",
        param="id",
        payload="1' AND SLEEP(5)--",
        rounds=5,
        positive_count=5,
        confidence_score=0.95,
        is_confirmed=True,
    )

    item = evidence_from_verification(result)

    assert item.kind == "statistical"
    assert item.confidence == "high"
    assert item.url == "http://target.local/item?id=1"
    assert "5 rounds" in item.summary
    assert item.raw["rounds"] == 5


def test_evidence_from_statistical_unconfirmed_maps_to_false_positive():
    result = FakeStatisticalVerification(
        vuln_type="time_based_sqli",
        url="http://target.local",
        param="id",
        payload="sleep",
        rounds=5,
        positive_count=0,
        confidence_score=0.2,
        is_confirmed=False,
    )

    item = evidence_from_verification(result)

    assert item.kind == "statistical"
    assert item.confidence == "false_positive"


def test_evidence_from_oob_dict():
    item = evidence_from_verification(
        {
            "vuln_type": "ssrf",
            "url": "http://target.local/fetch",
            "payload": "http://oob.local/x",
            "confidence": "high",
            "evidence": "callback received for token abc123",
            "verification_method": "oob_callback",
        }
    )

    assert item.kind == "oob_callback"
    assert item.confidence == "high"
    assert item.raw["vuln_type"] == "ssrf"


def test_evidence_from_dict_numeric_confidence():
    item = evidence_from_verification(
        {
            "vuln_type": "xss",
            "is_vulnerable": False,
            "confidence_score": 0.9,
            "verification_method": "replay",
            "evidence": "payload reflected",
        }
    )

    assert item.kind == "replay"
    assert item.confidence == "false_positive"


def test_evidence_from_unrecognized_objects_does_not_crash():
    for value in (None, 42, "plain string", object()):
        item = evidence_from_verification(value)
        assert isinstance(item, EvidenceItem)
        assert item.kind == "unknown"
        assert item.observed_at


def test_evidence_item_to_dict_roundtrip():
    item = EvidenceItem(kind="command", method="rce_echo", summary="cmd output captured")

    payload = item.to_dict()

    assert payload["kind"] == "command"
    assert payload["method"] == "rce_echo"
    assert payload["summary"] == "cmd output captured"
    assert payload["raw"] == {}
