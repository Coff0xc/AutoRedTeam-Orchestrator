"""Engagement world model: SQLite graph plus planner index."""

from __future__ import annotations

from pathlib import Path

from core.engage import (
    WORLD_SCHEMA,
    EngagementConfig,
    ingest_step,
    init_engagement,
    plan_next,
    run_engagement,
)
from core.engage.runner import empty_state
from core.engage.world import snapshot, world_file
from core.knowledge.storage import SQLiteKnowledgeStore


def test_planner_reads_world_index_without_scan_blobs():
    config = EngagementConfig(target="http://127.0.0.1:3000", profile="scan")
    state = empty_state()
    state["world"] = {
        "schema": WORLD_SCHEMA,
        "recon": True,
        "detect": True,
        "nuclei": False,
        "exported": False,
        "assets": 1,
        "facts": 2,
        "findings": 0,
        "unverified": 0,
        "unverified_index": [],
    }

    card = plan_next(config, state)

    assert state.get("recon") is None
    assert state.get("findings") is None
    assert card["name"] == "export_findings"
    assert card["remaining"] == ["export_findings"]


def test_planner_verify_uses_world_unverified_index():
    config = EngagementConfig(target="http://127.0.0.1:3000", profile="scan")
    state = empty_state()
    state["world"] = {
        "schema": WORLD_SCHEMA,
        "recon": True,
        "detect": True,
        "exported": False,
        "unverified": 1,
        "unverified_index": [{"url": "http://127.0.0.1:3000", "vuln_type": "xss", "param": "q"}],
    }
    card = plan_next(config, state)
    assert card["name"] == "verify_finding"
    assert card["inputs"]["finding"]["vuln_type"] == "xss"
    assert "export_findings" not in card["remaining"]


def test_ingest_persists_assets_and_findings_without_scan_json(tmp_path: Path):
    state = empty_state()
    state["output_dir"] = str(tmp_path)
    state["findings"] = [
        {
            "url": "http://127.0.0.1:3000/search",
            "vuln_type": "xss",
            "param": "q",
            "payload": "<script>alert(1)</script>",
            "evidence": "x" * 4000,
        }
    ]
    payload = {
        "success": True,
        "target": "http://127.0.0.1:3000",
        "results": {"port_scan": {"open_ports": [{"port": 80}, {"port": 443}]}},
    }
    index = ingest_step(
        state,
        "detect_run",
        payload,
        inputs={"target": "http://127.0.0.1:3000", "output_dir": str(tmp_path)},
    )
    path = world_file(tmp_path)
    store = SQLiteKnowledgeStore(path)
    try:
        target = store.get_entity(index["target_id"])
        finding = store.find_entities("finding")[0]
        ports = store.find_entities("port")
        rels = store.find_relationships(rel_type="has_vulnerability")
    finally:
        store.close()

    assert index["schema"] == WORLD_SCHEMA
    assert index["detect"] is True
    assert index["facts"] == 2
    assert index["findings"] == 1
    assert index["unverified"] == 1
    assert path.is_file()
    assert target is not None
    assert "results" not in target["properties"]
    assert "data" not in target["properties"]
    assert "payload" not in finding["properties"]
    assert "evidence" not in finding["properties"]
    assert finding["properties"]["confidence_level"] == "tentative"
    assert {item["name"] for item in ports} == {"80", "443"}
    assert rels


def test_verify_promotes_finding_confidence(tmp_path: Path):
    state = empty_state()
    state["output_dir"] = str(tmp_path)
    state["findings"] = [
        {
            "url": "http://127.0.0.1:9",
            "vuln_type": "xss",
            "param": "q",
            "verification_status": "verified",
            "verified_by": "vuln_verifier",
            "provenance": {
                "bound": True,
                "request": {"url": "http://127.0.0.1:9"},
                "response": {"status": 200, "body_sha256": "abc", "body_preview": "<script>"},
            },
        }
    ]
    ingest_step(
        state,
        "verify_finding",
        {"success": True},
        inputs={"target": "http://127.0.0.1:9", "output_dir": str(tmp_path)},
    )
    store = SQLiteKnowledgeStore(world_file(tmp_path))
    try:
        finding = store.find_entities("finding")[0]
    finally:
        store.close()
    assert finding["properties"]["confidence_level"] == "confirmed"
    assert finding["properties"]["verified_by"] == "vuln_verifier"
    assert finding["properties"]["provenance_bound"] is True
    assert finding["properties"]["body_sha256"] == "abc"
    assert finding["properties"]["response_status"] == 200
    assert "body_preview" not in finding["properties"]
    assert state["world"]["unverified"] == 0


def test_dry_run_writes_world_sqlite(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "engage.yaml"
    init_engagement(
        "http://127.0.0.1:9",
        path=path,
        output_dir=str(tmp_path),
        profile="scan",
    )
    result = run_engagement(path, dry_run=True)
    world_path = Path(result["state"]["world"]["path"])

    assert result["passed"] is True
    assert result["state"]["world"]["assets"] == 1
    assert result["state"]["world"]["recon"] is True
    assert world_path.is_file()
    store = SQLiteKnowledgeStore(world_path)
    try:
        targets = store.find_entities("target")
        snap = snapshot(store, "http://127.0.0.1:9", world_path)
    finally:
        store.close()
    assert targets
    assert "results" not in targets[0]["properties"]
    assert snap["recon"] is True
    assert snap["detect"] is True
    assert snap["exported"] is True
