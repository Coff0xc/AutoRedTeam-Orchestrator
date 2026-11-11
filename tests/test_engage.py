"""Authorized engagement loop: init, plan, dry-run, doom-loop."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from core.engage import (
    ENGAGE_STEPS,
    EngagementConfig,
    EngagementError,
    engagement_next,
    execution_id,
    init_engagement,
    plan_next,
    run_engagement,
)
from core.engage.runner import dispatch_engage_step, empty_state

runner = CliRunner()


def test_init_writes_yaml_and_plans_recon(tmp_path: Path):
    path = tmp_path / "engage.yaml"
    result = init_engagement(
        "http://127.0.0.1:3000",
        path=path,
        output_dir=str(tmp_path),
        profile="scan",
    )

    assert result["success"] is True
    assert path.is_file()
    assert result["next"]["name"] == "engage.recon"
    assert "detect" in result["next"]["hint"]
    config = EngagementConfig.from_dict(result["config"])
    assert "127.0.0.1" in config.allowlist
    assert config.scope_mode == "enforce"


def test_safe_profile_rejected():
    with pytest.raises(EngagementError, match="scan"):
        EngagementConfig(target="http://127.0.0.1:3000", profile="safe")


def test_plan_advances_recon_detect_verify_export():
    config = EngagementConfig(target="http://127.0.0.1:3000", profile="scan")
    state = empty_state()
    assert plan_next(config, state)["name"] == "engage.recon"
    state["recon"] = {"ok": True}
    assert plan_next(config, state)["name"] == "engage.detect"
    state["findings"] = [{"url": "http://127.0.0.1:3000", "vuln_type": "xss", "vulnerable": True}]
    assert plan_next(config, state)["name"] == "engage.verify"
    state["findings"][0]["engagement_verified"] = True
    assert plan_next(config, state)["name"] == "engage.export"
    state["exported"] = True
    assert plan_next(config, state) is None


@pytest.mark.asyncio
async def test_dry_dispatch_records_without_network():
    state = empty_state()
    recon = await dispatch_engage_step(
        "engage.recon",
        {"target": "http://127.0.0.1:9"},
        state,
        dry_run=True,
    )
    detect = await dispatch_engage_step(
        "engage.detect",
        {"target": "http://127.0.0.1:9"},
        state,
        dry_run=True,
    )
    export = await dispatch_engage_step(
        "engage.export",
        {"output_dir": "."},
        state,
        dry_run=True,
    )
    assert recon["dry_run"] is True
    assert detect["dry_run"] is True
    assert export["dry_run"] is True
    assert state["recon"] == {"dry_run": True}
    assert state["findings"] == []
    assert state["exported"] is True


def test_dry_run_loop_completes(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "engage.yaml"
    init_engagement(
        "http://127.0.0.1:9",
        path=path,
        output_dir=str(tmp_path),
        profile="scan",
    )
    result = run_engagement(path, dry_run=True)
    assert result["success"] is True
    assert result["passed"] is True
    assert result["dry_run"] is True
    assert result["state"]["status"] == "complete"
    assert result["next"] is None
    assert result["loop"]["stopped"] is None


def test_doom_loop_stops(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "engage.yaml"
    init_engagement(
        "http://127.0.0.1:9",
        path=path,
        output_dir=str(tmp_path),
        profile="scan",
        phases="recon",
    )

    async def _stuck(name, inputs, state, dry_run=False):
        return {"success": True, "dry_run": True, "step": name}

    monkeypatch.setattr("core.engage.runner.dispatch_engage_step", _stuck)
    result = run_engagement(path, dry_run=True, max_steps=8)
    assert result["loop"]["stopped"] == "doom_loop"
    assert result["state"]["status"] == "doom_loop"


def test_execution_id_is_stable():
    left = execution_id("engage.recon", {"target": "http://x"})
    right = execution_id("engage.recon", {"target": "http://x"})
    assert left == right
    assert left != execution_id("engage.detect", {"target": "http://x"})


def test_cli_init_and_next(tmp_path: Path):
    from cli.main import app

    path = tmp_path / "engage.yaml"
    init_result = runner.invoke(
        app,
        [
            "engage",
            "init",
            "http://127.0.0.1:3000",
            "--path",
            str(path),
            "--profile",
            "scan",
        ],
    )
    assert init_result.exit_code == 0, init_result.output
    assert "engage.recon" in init_result.output

    next_result = runner.invoke(app, ["engage", "next", "--path", str(path)])
    assert next_result.exit_code == 0, next_result.output
    assert "engage.recon" in next_result.output


def test_cli_dry_run(tmp_path: Path, monkeypatch):
    from cli.main import app

    monkeypatch.chdir(tmp_path)
    path = tmp_path / "engage.yaml"
    runner.invoke(
        app,
        ["engage", "init", "http://127.0.0.1:9", "--path", str(path), "--profile", "scan"],
    )
    result = runner.invoke(app, ["engage", "run", "--path", str(path), "--dry-run"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output[result.output.index("{") :])
    assert payload["passed"] is True
    assert payload["dry_run"] is True


def test_cli_dry_run_ci_exits_zero_on_pass(tmp_path: Path, monkeypatch):
    from cli.main import app

    monkeypatch.chdir(tmp_path)
    path = tmp_path / "engage.yaml"
    runner.invoke(
        app,
        ["engage", "init", "http://127.0.0.1:9", "--path", str(path), "--profile", "scan"],
    )
    result = runner.invoke(app, ["engage", "run", "--path", str(path), "--dry-run", "--ci"])
    assert result.exit_code == 0, result.output


def test_cli_ci_exits_2_on_doom_loop(tmp_path: Path, monkeypatch):
    from cli.main import app

    monkeypatch.chdir(tmp_path)
    path = tmp_path / "engage.yaml"
    runner.invoke(
        app,
        [
            "engage",
            "init",
            "http://127.0.0.1:9",
            "--path",
            str(path),
            "--profile",
            "scan",
            "--phases",
            "recon",
        ],
    )

    async def _stuck(name, inputs, state, dry_run=False):
        return {"success": True, "dry_run": True, "step": name}

    monkeypatch.setattr("core.engage.runner.dispatch_engage_step", _stuck)
    result = runner.invoke(
        app, ["engage", "run", "--path", str(path), "--dry-run", "--ci", "--max-steps", "8"]
    )
    assert result.exit_code == 2, result.output


def test_engage_steps_are_listed():
    assert "engage.recon" in ENGAGE_STEPS
    assert engagement_next.__name__ == "engagement_next"
