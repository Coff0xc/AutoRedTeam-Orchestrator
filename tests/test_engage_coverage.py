"""Engagement coverage ledger: examined / ruled_out / open."""

from __future__ import annotations

from core.engage import (
    COVERAGE_SCHEMA,
    EngagementConfig,
    build_coverage_ledger,
    init_engagement,
    plan_next,
    run_engagement,
)
from core.engage.ledger import STATUS_EXAMINED, STATUS_OPEN, STATUS_RULED_OUT
from core.engage.runner import empty_state


def _by_id(ledger):
    return {row["id"]: row for row in ledger["rows"]}


def test_init_denominator_is_open_phases():
    config = EngagementConfig(target="http://127.0.0.1:3000", profile="scan")
    ledger = build_coverage_ledger(config, empty_state())
    rows = _by_id(ledger)

    assert ledger["schema"] == COVERAGE_SCHEMA
    assert ledger["total"] == 4
    assert ledger["open"] == 4
    assert ledger["examined"] == 0
    assert ledger["ruled_out"] == 0
    assert ledger["coverage_rate"] == 0.0
    assert rows["phase:recon"]["status"] == STATUS_OPEN
    assert rows["phase:export"]["status"] == STATUS_OPEN
    card = plan_next(config, empty_state())
    assert card["coverage"]["open"] == 4
    assert card["coverage"]["total"] == 4


def test_detect_without_findings_examines_verify_phase():
    config = EngagementConfig(target="http://127.0.0.1:3000", profile="scan")
    state = empty_state()
    state["world"] = {
        "schema": "autort.engage.world/v1",
        "recon": True,
        "detect": True,
        "exported": False,
        "unverified_index": [],
        "assets_index": [
            {"kind": "target", "name": "http://127.0.0.1:3000"},
            {"kind": "port", "name": "80"},
            {"kind": "port", "name": "443"},
        ],
    }
    ledger = build_coverage_ledger(config, state)
    rows = _by_id(ledger)

    assert rows["phase:recon"]["status"] == STATUS_EXAMINED
    assert rows["phase:detect"]["status"] == STATUS_EXAMINED
    assert rows["phase:verify"]["status"] == STATUS_EXAMINED
    assert rows["phase:export"]["status"] == STATUS_OPEN
    assert rows["asset:port:80"]["status"] == STATUS_EXAMINED
    assert "asset:target:http://127.0.0.1:3000" not in rows
    assert ledger["examined"] == 5
    assert ledger["open"] == 1
    assert ledger["total"] == 6
    assert ledger["coverage_rate"] == 5 / 6


def test_unverified_finding_stays_open_and_blocks_verify_phase():
    config = EngagementConfig(target="http://127.0.0.1:3000", profile="scan")
    state = empty_state()
    state["world"] = {
        "recon": True,
        "detect": True,
        "exported": False,
        "unverified_index": [{"url": "http://127.0.0.1:3000", "vuln_type": "xss", "param": "q"}],
    }
    ledger = build_coverage_ledger(config, state)
    rows = _by_id(ledger)
    assert rows["phase:verify"]["status"] == STATUS_OPEN
    assert rows["finding:http://127.0.0.1:3000|xss|q"]["status"] == STATUS_OPEN
    assert ledger["open"] == 3


def test_contradicted_finding_is_ruled_out():
    config = EngagementConfig(target="http://127.0.0.1:3000", profile="scan")
    state = empty_state()
    state["world"] = {"recon": True, "detect": True, "exported": False, "unverified_index": []}
    state["findings"] = [
        {
            "url": "http://127.0.0.1:3000",
            "vuln_type": "xss",
            "param": "q",
            "verification_status": "contradicted",
        }
    ]
    ledger = build_coverage_ledger(config, state)
    rows = _by_id(ledger)
    assert rows["finding:http://127.0.0.1:3000|xss|q"]["status"] == STATUS_RULED_OUT
    assert ledger["ruled_out"] == 1
    assert rows["phase:verify"]["status"] == STATUS_EXAMINED


def test_dry_run_status_and_run_include_ledger(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "engage.yaml"
    init_engagement(
        "http://127.0.0.1:9",
        path=path,
        output_dir=str(tmp_path),
        profile="scan",
    )
    from core.engage import engagement_status

    before = engagement_status(path)
    assert before["coverage"]["open"] == 4
    assert before["coverage"]["total"] == 4

    result = run_engagement(path, dry_run=True)
    ledger = result["coverage"]
    rows = _by_id(ledger)
    assert result["passed"] is True
    assert ledger["schema"] == COVERAGE_SCHEMA
    assert ledger["open"] == 0
    assert rows["phase:recon"]["status"] == STATUS_EXAMINED
    assert rows["phase:detect"]["status"] == STATUS_EXAMINED
    assert rows["phase:verify"]["status"] == STATUS_EXAMINED
    assert rows["phase:export"]["status"] == STATUS_EXAMINED
    assert ledger["coverage_rate"] == 1.0
