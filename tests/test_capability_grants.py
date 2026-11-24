"""Catalog-enable grant ledger: record, replay, budget, CLI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from core.capability_grants import (
    GRANT_BUDGET_ENV,
    GRANT_LOG_ENV,
    GRANT_SCHEMA,
    GrantBudgetExceeded,
    GrantLedgerError,
    bind_grant_store,
    empty_grant_document,
    grant_budget,
    grant_log_path,
    grant_snapshot,
    load_grants,
    persist_grants,
    record_catalog_grant,
)
from core.capability_manifest import get_capability

runner = CliRunner()


def test_grant_budget_unset_is_unlimited(monkeypatch):
    monkeypatch.delenv(GRANT_BUDGET_ENV, raising=False)
    assert grant_budget() is None


def test_grant_budget_zero_and_invalid(monkeypatch):
    monkeypatch.setenv(GRANT_BUDGET_ENV, "0")
    assert grant_budget() == 0
    monkeypatch.setenv(GRANT_BUDGET_ENV, "-1")
    try:
        grant_budget()
    except GrantLedgerError as exc:
        assert GRANT_BUDGET_ENV in str(exc)
    else:
        raise AssertionError("negative budget should fail closed")
    monkeypatch.setenv(GRANT_BUDGET_ENV, "nope")
    try:
        grant_budget()
    except GrantLedgerError as exc:
        assert GRANT_BUDGET_ENV in str(exc)
    else:
        raise AssertionError("non-integer budget should fail closed")


def test_record_catalog_grant_is_idempotent_and_persists(tmp_path: Path):
    jwt = get_capability("tool", "jwt_scan")
    session = get_capability("tool", "session_list")
    log_path = tmp_path / "grants.json"
    grants: list[dict] = []

    first, added = record_catalog_grant(grants, jwt, "scan", log_path=log_path)
    replay, replayed = record_catalog_grant(grants, jwt, "scan", log_path=log_path)
    second, second_added = record_catalog_grant(grants, session, "safe", log_path=log_path)

    assert added is True
    assert replayed is False
    assert second_added is True
    assert first["name"] == "jwt_scan"
    assert first["kind"] == "tool"
    assert first["source"] == "tool_enable"
    assert replay == first
    assert [item["name"] for item in grants] == ["jwt_scan", "session_list"]
    loaded = load_grants(log_path)
    assert grant_snapshot(loaded)["count"] == 2
    assert grant_snapshot(loaded)["schema"] == GRANT_SCHEMA
    assert second["name"] == "session_list"


def test_bind_grant_store_loads_log_once(tmp_path: Path, monkeypatch):
    log_path = tmp_path / "grants.json"
    persist_grants(
        log_path,
        [
            {
                "kind": "tool",
                "name": "jwt_scan",
                "profile": "scan",
                "risk": "moderate",
                "minimum_profile": "scan",
                "source": "tool_enable",
            }
        ],
    )
    monkeypatch.setenv(GRANT_LOG_ENV, str(log_path))
    assert grant_log_path() == log_path

    class Server:
        pass

    server = Server()
    first = bind_grant_store(server)
    first.append({"kind": "tool", "name": "session_list", "profile": "safe"})
    second = bind_grant_store(server)
    assert second is first
    assert [item["name"] for item in first] == ["jwt_scan", "session_list"]


def test_load_grants_rejects_wrong_schema(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text('{"schema": "nope", "grants": []}', encoding="utf-8")
    try:
        load_grants(path)
    except GrantLedgerError as exc:
        assert GRANT_SCHEMA in str(exc)
    else:
        raise AssertionError("wrong schema should fail closed")
    assert load_grants(tmp_path / "missing.json") == []
    assert empty_grant_document()["count"] == 0


def test_cli_grants_reads_log_and_missing_is_empty(tmp_path: Path):
    from cli.main import app

    missing = runner.invoke(app, ["capabilities", "grants", "--path", str(tmp_path / "none.json")])
    missing_payload = json.loads(missing.stdout)
    assert missing.exit_code == 0
    assert missing_payload["schema"] == GRANT_SCHEMA
    assert missing_payload["count"] == 0

    log_path = tmp_path / "grants.json"
    persist_grants(
        log_path,
        [{"kind": "tool", "name": "jwt_scan", "profile": "scan", "source": "tool_enable"}],
    )
    listed = runner.invoke(app, ["capabilities", "grants", "--path", str(log_path)])
    payload = json.loads(listed.stdout)
    assert listed.exit_code == 0
    assert payload["count"] == 1
    assert payload["grants"][0]["name"] == "jwt_scan"

    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    failed = runner.invoke(app, ["capabilities", "grants", "--path", str(bad)])
    assert failed.exit_code == 2
    assert GRANT_SCHEMA in (failed.output + (failed.stderr or ""))


def test_grant_budget_exceeded_message():
    err = GrantBudgetExceeded(budget=1, count=1, name="session_list")
    assert "session_list" in str(err)
    assert GRANT_BUDGET_ENV in str(err)
    assert "1" in str(err)
