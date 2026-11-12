"""Thin local RuntimeLoop: plan loader, allowlist, CLI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from core.agent_runtime import (
    LOCAL_STEPS,
    RUNTIME_SCHEMA,
    Action,
    ActionKind,
    ActionPolicy,
    ActionStatus,
    AgentRunState,
    Flow,
    RuntimeLoop,
    Task,
    clear_runtime_runs,
    get_runtime_run,
    is_runtime_plan,
    plan_to_run_state,
    run_runtime_document,
    run_runtime_path,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_PLAN = REPO_ROOT / "config" / "runtime.local.example.yaml"
runner = CliRunner()


def test_example_plan_is_runtime_document():
    from core.agent_runtime import load_runtime_document

    data = load_runtime_document(EXAMPLE_PLAN)
    assert is_runtime_plan(data) is True
    assert "ai_surface.scan" in LOCAL_STEPS


def test_dry_run_skips_local_steps_and_evals():
    clear_runtime_runs()
    result = run_runtime_path(EXAMPLE_PLAN, allow_local=False)
    actions = result["run_state"]["flow"]["tasks"][0]["actions"]

    assert result["passed"] is True
    assert result["schema"] == RUNTIME_SCHEMA
    assert result["loop"]["allow_local"] is False
    assert {item["status"] for item in actions} == {"skipped"}
    assert get_runtime_run(result["run_state"]["run_id"]) is not None
    clear_runtime_runs()


def test_local_loop_runs_allowlisted_steps():
    clear_runtime_runs()
    result = run_runtime_path(EXAMPLE_PLAN, allow_local=True)
    actions = result["run_state"]["flow"]["tasks"][0]["actions"]
    by_name = {item["name"]: item for item in actions}

    assert result["passed"] is True
    assert result["loop"]["allow_local"] is True
    assert by_name["ai_surface.scan"]["status"] == "completed"
    assert by_name["ai_surface.scan"]["output"]["summary"]["issue_count"] >= 1
    assert "sudo" in by_name["skill.read"]["output"]["operator_stop"]
    assert "body" not in by_name["skill.read"]["output"]
    assert by_name["eval.document"]["output"]["passed"] is True
    clear_runtime_runs()


def test_unknown_step_and_forbidden_kind_fail_closed():
    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {"name": "exploit.run", "inputs": {}},
            {"name": "ai_surface.scan", "kind": "model_call", "inputs": {"path": "handlers"}},
        ],
    }
    result = run_runtime_document(plan, allow_local=True, stop_on_block=False, base_dir=REPO_ROOT)
    actions = result["run_state"]["flow"]["tasks"][0]["actions"]

    assert result["passed"] is False
    assert actions[0]["status"] == "blocked"
    assert "unknown local step" in actions[0]["error"]
    assert actions[1]["status"] == "blocked"
    assert "model_call" in actions[1]["error"]


def test_network_policy_blocks_local_execution():
    state = AgentRunState(flow=Flow(name="net"))
    action = Action(
        name="ai_surface.scan",
        kind=ActionKind.TOOL_CALL,
        inputs={
            "path": str(REPO_ROOT / "tests" / "fixtures" / "ai_surface" / "labeled_handlers.py")
        },
        policy=ActionPolicy(network_policy="scoped"),
    )
    state.flow.add_task(Task(name="plan")).add_action(action)

    result = RuntimeLoop(allow_local=True).run(state, base_dir=REPO_ROOT)

    assert result["passed"] is False
    assert action.status == ActionStatus.BLOCKED
    assert "network" in (action.error or "").lower()


def test_max_steps_skips_remaining():
    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {
                "name": "skill.read",
                "inputs": {"path": "tests/fixtures/eval/operator_stop/SKILL.md"},
            },
            {
                "name": "skill.read",
                "inputs": {"path": "tests/fixtures/eval/operator_stop/SKILL.md"},
            },
        ],
    }
    result = run_runtime_document(plan, allow_local=True, max_steps=1, base_dir=REPO_ROOT)
    actions = result["run_state"]["flow"]["tasks"][0]["actions"]

    assert actions[0]["status"] == "completed"
    assert actions[1]["status"] == "skipped"
    assert result["loop"]["stopped"] == "max_steps"


def test_plan_to_run_state_requires_steps():
    try:
        plan_to_run_state({"schema": RUNTIME_SCHEMA, "name": "empty", "steps": []})
    except ValueError as exc:
        assert "steps" in str(exc)
    else:
        raise AssertionError("empty steps should fail")


def test_cli_runtime_run_dry_run_and_local():
    from cli.main import app

    dry = runner.invoke(app, ["runtime-api", "run", str(EXAMPLE_PLAN), "--dry-run"])
    local = runner.invoke(app, ["runtime-api", "run", str(EXAMPLE_PLAN), "--local"])

    assert dry.exit_code == 0
    dry_payload = json.loads(dry.stdout)
    assert dry_payload["loop"]["allow_local"] is False
    assert dry_payload["passed"] is True
    assert local.exit_code == 0
    local_payload = json.loads(local.stdout)
    assert local_payload["loop"]["allow_local"] is True
    assert local_payload["passed"] is True


def test_cli_runtime_run_ci_fails_on_unknown_step(tmp_path: Path):
    from cli.main import app

    plan = tmp_path / "bad.yaml"
    plan.write_text(
        "schema: autort.runtime/v1\n"
        "mode: local\n"
        "steps:\n"
        "  - name: exploit.run\n"
        "    inputs: {}\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["runtime-api", "run", str(plan), "--ci"])
    assert result.exit_code == 2
    assert '"passed": false' in result.stdout
