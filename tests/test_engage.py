"""Authorized engagement loop: init, plan, dry-run, doom-loop."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from core.engage import (
    ENGAGE_STEPS,
    PLAN_STEPS,
    EngagementConfig,
    EngagementError,
    canonical_step,
    engagement_next,
    execution_id,
    init_engagement,
    open_gaps,
    plan_next,
    run_engagement,
)
from core.engage.runner import dispatch_engage_step, empty_state, save_state
from core.security.hitl import HitlDecision, reset_hitl, set_approver

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
    assert result["next"]["name"] == "recon_run"
    assert "detect" in result["next"]["hint"]
    assert result["next"]["remaining"] == ["recon_run", "detect_run"]
    config = EngagementConfig.from_dict(result["config"])
    assert "127.0.0.1" in config.allowlist
    assert config.scope_mode == "enforce"


def test_safe_profile_rejected():
    with pytest.raises(EngagementError, match="scan"):
        EngagementConfig(target="http://127.0.0.1:3000", profile="safe")


def test_plan_advances_recon_detect_verify_export():
    config = EngagementConfig(target="http://127.0.0.1:3000", profile="scan")
    state = empty_state()
    first = plan_next(config, state)
    assert first["name"] == "recon_run"
    assert first["remaining"] == ["recon_run", "detect_run"]
    assert [gap["reason"] for gap in first["gaps"]] == ["missing_recon", "missing_detect"]
    state["recon"] = {"ok": True}
    second = plan_next(config, state)
    assert second["name"] == "detect_run"
    assert second["remaining"] == ["detect_run"]
    state["findings"] = [{"url": "http://127.0.0.1:3000", "vuln_type": "xss", "vulnerable": True}]
    third = plan_next(config, state)
    assert third["name"] == "verify_finding"
    assert third["remaining"] == ["verify_finding"]
    assert "export_findings" not in third["remaining"]
    state["findings"][0]["engagement_verified"] = True
    fourth = plan_next(config, state)
    assert fourth["name"] == "export_findings"
    state["exported"] = True
    assert plan_next(config, state) is None


def test_plan_skips_recon_when_findings_exist():
    config = EngagementConfig(target="http://127.0.0.1:3000", profile="scan")
    state = empty_state()
    state["findings"] = [{"url": "http://127.0.0.1:3000", "vuln_type": "xss", "vulnerable": True}]
    card = plan_next(config, state)
    assert card["name"] == "verify_finding"
    assert "recon_run" not in card["remaining"]
    assert "export_findings" not in card["remaining"]


def test_plan_nuclei_gap_when_phased():
    config = EngagementConfig(
        target="http://127.0.0.1:3000",
        profile="scan",
        phases=("recon", "detect", "nuclei", "verify", "export"),
    )
    state = empty_state()
    state["recon"] = {"ok": True}
    state["findings"] = []
    card = plan_next(config, state)
    assert card["name"] == "nuclei_scan"
    assert card["gaps"][0]["reason"] == "missing_nuclei"
    state["nuclei"] = {"ok": True}
    assert plan_next(config, state)["name"] == "export_findings"


def test_canonical_step_maps_engage_aliases():
    assert canonical_step("engage.verify") == "verify_finding"
    assert "verify_finding" in PLAN_STEPS
    assert open_gaps.__name__ == "open_gaps"


def test_model_pick_frames_state_and_uses_authorized_system(monkeypatch):
    captured: dict[str, str] = {}

    class FakeProvider:
        available = True

        def complete(self, prompt, system=""):
            captured["prompt"] = prompt
            captured["system"] = system
            return "engage.detect extra prose"

    monkeypatch.setattr("core.llm.provider.LLMProvider", FakeProvider)
    from core.llm.prompts import DATA_MARKER_STEM, ENGAGE_PICK_SYSTEM_PROMPT

    config = EngagementConfig(target="http://127.0.0.1:3000", profile="scan")
    state = empty_state()
    state["recon"] = {"ok": True}
    card = plan_next(config, state, use_model=True)
    assert card["name"] == "detect_run"
    assert captured["system"] == ENGAGE_PICK_SYSTEM_PROMPT
    assert DATA_MARKER_STEM in captured["prompt"]
    assert "has_recon" in captured["prompt"]
    assert "detect_run" in captured["prompt"]


def test_model_pick_unknown_reply_keeps_heuristic(monkeypatch):
    class FakeProvider:
        available = True

        def complete(self, prompt, system=""):
            return "not-a-step"

    monkeypatch.setattr("core.llm.provider.LLMProvider", FakeProvider)
    config = EngagementConfig(target="http://127.0.0.1:3000", profile="scan")
    state = empty_state()
    state["recon"] = {"ok": True}
    card = plan_next(config, state, use_model=True)
    assert card["name"] == "detect_run"


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
    assert result["scorecard"]["schema"] == "autort.engage.scorecard/v1"
    assert result["scorecard"]["total"] == 0
    assert result["scorecard"]["confirmed"] == 0
    assert result["scorecard"]["unconfirmed"] == 0


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
    assert "recon_run" in init_result.output

    next_result = runner.invoke(app, ["engage", "next", "--path", str(path)])
    assert next_result.exit_code == 0, next_result.output
    assert "recon_run" in next_result.output


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


def _pending_verify_engagement(tmp_path: Path, *, hitl: str) -> Path:
    path = tmp_path / "engage.yaml"
    payload = init_engagement(
        "http://127.0.0.1:9",
        path=path,
        output_dir=str(tmp_path),
        profile="scan",
        hitl=hitl,
    )
    config = EngagementConfig.from_dict(payload["config"])
    state = empty_state()
    state["recon"] = {"ok": True}
    state["findings"] = [{"url": "http://127.0.0.1:9", "vuln_type": "xss", "vulnerable": True}]
    save_state(config, state)
    return path


def test_hitl_denies_live_verify(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = _pending_verify_engagement(tmp_path, hitl="approval")
    called: list[str] = []

    async def _spy(name, inputs, state, dry_run=False):
        called.append(name)
        return {"success": True, "step": name}

    monkeypatch.setattr("core.engage.runner.dispatch_engage_step", _spy)
    try:
        result = run_engagement(path, dry_run=False, max_steps=1)
    finally:
        reset_hitl()

    assert result["loop"]["stopped"] == "hitl_denied"
    assert result["state"]["status"] == "hitl_denied"
    assert called == []


def test_hitl_approval_runs_verify(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = _pending_verify_engagement(tmp_path, hitl="approval")
    called: list[str] = []

    async def _allow(_request):
        return HitlDecision(allowed=True, reason="approved")

    async def _spy(name, inputs, state, dry_run=False):
        called.append(name)
        return {"success": True, "step": name}

    set_approver(_allow)
    monkeypatch.setattr("core.engage.runner.dispatch_engage_step", _spy)
    try:
        result = run_engagement(path, dry_run=False, max_steps=1)
    finally:
        reset_hitl()

    assert called == ["verify_finding"]
    assert result["loop"]["stopped"] == "max_steps"


def test_hitl_skipped_on_dry_run(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = _pending_verify_engagement(tmp_path, hitl="approval")
    result = run_engagement(path, dry_run=True)
    assert result["passed"] is True
    assert result["dry_run"] is True
    assert result["loop"]["stopped"] is None
