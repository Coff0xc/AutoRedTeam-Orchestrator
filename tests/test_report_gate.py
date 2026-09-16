"""报告生成器的证据门禁接入单测（P2.3）。

覆盖门禁收口处（``ReportGenerator._prepare_report_data`` 链路，经
``_normalize_findings``）的行为：已验证结论保持原样、无证据结论被降级并标记、
汇总计数正确、``require_evidence=False`` 时与接入前一致，且不修改调用方传入的
findings。
"""

from copy import deepcopy
from datetime import datetime
from types import SimpleNamespace

from utils.report_generator import ReportGenerator

# 接入门禁前的报告顶层键集合（用于验证关闭开关后"无新键"）。
LEGACY_KEYS = {
    "session_id",
    "session_name",
    "created_at",
    "status",
    "targets",
    "findings",
    "findings_summary",
    "findings_by_type",
    "findings_by_target",
    "attack_chains",
    "cvss_distribution",
    "remediation_priority",
    "results_count",
    "notes",
    "scan_statistics",
    "generated_at",
}


def _source(findings):
    """构造最小可用的扫描结果源对象（走 scan_source 分支）。"""
    return SimpleNamespace(
        session_id="session-gate",
        target="https://example.com",
        metadata={"findings": findings},
        vulnerabilities=[],
        status="completed",
        started_at=None,
        total_requests=len(findings),
    )


def _legacy_session(findings):
    """构造最小可用的旧版会话对象（走 legacy_session 分支）。"""
    return SimpleNamespace(
        id="session-legacy",
        name="legacy-session",
        created_at=datetime(2024, 1, 1, 0, 0, 0),
        status=SimpleNamespace(value="completed"),
        targets=[SimpleNamespace(value="https://example.com", type="url")],
        findings=findings,
        results=[],
        notes=[],
    )


def _verified_finding(**overrides):
    """带独立验证来源的结构化证据 finding（与 core.vuln_verifier 输出形状一致）。"""
    finding = {
        "title": "SQL Injection",
        "type": "sqli",
        "severity": "critical",
        "verified": True,
        "confidence": "high",
        "evidence": [
            {
                "kind": "statistical",
                "method": "time_based_sqli",
                "summary": "time-based delay of 5s reproduced 3 times",
            }
        ],
    }
    finding.update(overrides)
    return finding


def test_require_evidence_defaults_to_enabled():
    assert ReportGenerator().require_evidence is True


def test_verified_finding_keeps_severity_and_title():
    data = ReportGenerator().to_dict(_source([_verified_finding()]))

    finding = data["findings"][0]

    assert finding["severity"] == "critical"
    assert finding["title"] == "SQL Injection"
    assert "[UNCONFIRMED]" not in finding["title"]
    assert finding["verification_status"] == "verified"
    assert finding["missing_checks"] == []


def test_unverified_critical_finding_is_downgraded_and_marked():
    data = ReportGenerator().to_dict(
        _source([{"title": "SQL Injection", "type": "sqli", "severity": "critical"}])
    )

    finding = data["findings"][0]

    assert finding["severity"] == "medium"
    assert finding["title"] == "[UNCONFIRMED] SQL Injection"
    assert finding["type"] == "sqli"
    assert finding["verification_status"] == "unverified"
    assert "no evidence attached" in finding["missing_checks"]


def test_verified_false_is_counted_as_contradicted():
    data = ReportGenerator().to_dict(
        _source([_verified_finding(verified=False, evidence="no delay observed")])
    )

    assert data["findings"][0]["verification_status"] == "contradicted"
    assert data["evidence_summary"]["contradicted"] == 1
    assert data["evidence_summary"]["verified"] == 0
    assert data["evidence_summary"]["unverified"] == 0


def test_evidence_summary_counts_and_missing_checks_aggregate():
    findings = [
        _verified_finding(),
        {"title": "XSS", "severity": "high"},
        {"title": "SSRF", "severity": "high"},
        _verified_finding(verified=False, title="RCE", evidence="no signal"),
    ]

    data = ReportGenerator().to_dict(_source(findings))
    summary = data["evidence_summary"]

    assert summary["total"] == 4
    assert summary["verified"] == 1
    assert summary["unverified"] == 2
    assert summary["contradicted"] == 1
    # 已有 keys 不被门禁破坏：findings_summary 按降级后的 severity 统计
    assert data["findings_summary"]["total"] == 4
    assert data["findings_summary"]["critical"] == 1  # 仅已验证的那条保持 critical
    assert data["findings_summary"]["high"] == 0
    assert data["findings_summary"]["medium"] == 3

    missing = {entry["check"]: entry["count"] for entry in summary["missing_checks"]}
    assert missing["verified flag missing"] == 2
    assert missing["no evidence attached"] == 2
    assert missing["verification reported contradiction"] == 1
    # 聚合列表按次数降序
    counts = [entry["count"] for entry in summary["missing_checks"]]
    assert counts == sorted(counts, reverse=True)


def test_gate_applies_to_legacy_session_source():
    data = ReportGenerator().to_dict(_legacy_session([{"title": "RCE", "severity": "critical"}]))

    assert data["findings"][0]["severity"] == "medium"
    assert data["findings"][0]["verification_status"] == "unverified"
    assert data["evidence_summary"]["unverified"] == 1


def test_require_evidence_false_matches_legacy_behavior():
    findings = [
        _verified_finding(severity="critical"),
        {"title": "XSS", "severity": "critical"},
    ]

    data = ReportGenerator(require_evidence=False).to_dict(_source(findings))

    assert "evidence_summary" not in data
    assert set(data.keys()) == LEGACY_KEYS
    assert [finding["severity"] for finding in data["findings"]] == ["critical", "critical"]
    assert data["findings_summary"]["critical"] == 2
    for finding in data["findings"]:
        assert "verification_status" not in finding
        assert "missing_checks" not in finding
        assert "[UNCONFIRMED]" not in finding["title"]


def test_gate_does_not_mutate_caller_findings():
    findings = [
        _verified_finding(),
        {"title": "XSS", "severity": "critical", "type": "xss", "name": "xss-1"},
    ]
    snapshot = deepcopy(findings)

    data = ReportGenerator().to_dict(_source(findings))

    assert findings == snapshot
    for finding in findings:
        assert "verification_status" not in finding
        assert "missing_checks" not in finding
    assert data["findings"] is not findings
    assert data["findings"][1]["severity"] == "medium"
    assert data["findings"][1]["title"] == "[UNCONFIRMED] XSS"


def test_gate_reaches_every_rendered_format():
    """门禁接在数据准备收口处，html/markdown/executive 都应带上标记。"""
    generator = ReportGenerator()

    def fresh_source():
        return _source([{"title": "SQL Injection", "severity": "critical"}])

    assert "[UNCONFIRMED] SQL Injection" in generator.to_markdown(fresh_source())
    assert "[UNCONFIRMED] SQL Injection" in generator.to_html(fresh_source())
    assert "[UNCONFIRMED] SQL Injection" in generator.to_executive(fresh_source())
