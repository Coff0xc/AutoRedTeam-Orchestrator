"""Thin local RuntimeLoop: plan loader, allowlist, CLI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from core.agent_runtime import (
    AGGREGATOR_STEPS,
    ENGAGE_STEPS,
    LOCAL_STEPS,
    MODEL_STEPS,
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
AGGREGATOR_PLAN = REPO_ROOT / "config" / "runtime.aggregators.example.yaml"
runner = CliRunner()


def test_example_plan_is_runtime_document():
    from core.agent_runtime import load_runtime_document

    data = load_runtime_document(EXAMPLE_PLAN)
    assert is_runtime_plan(data) is True
    assert "ai_surface.scan" in LOCAL_STEPS
    assert AGGREGATOR_STEPS == {
        "recon_run",
        "detect_run",
        "verify_finding",
        "nuclei_scan",
        "export_findings",
    }


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


def test_planning_names_fail_closed_as_unknown_steps():
    names = (
        "smart_analyze",
        "attack_chain_plan",
        "plan_attack_path",
        "kg_attack_paths",
        "auto_pentest",
    )
    for name in names:
        assert name not in LOCAL_STEPS
        assert name not in ENGAGE_STEPS
        assert name not in AGGREGATOR_STEPS
        assert name not in MODEL_STEPS
    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [{"name": name, "inputs": {}} for name in names],
    }
    result = run_runtime_document(
        plan,
        allow_local=True,
        allow_engage=True,
        stop_on_block=False,
        base_dir=REPO_ROOT,
    )
    actions = result["run_state"]["flow"]["tasks"][0]["actions"]

    assert result["passed"] is False
    assert [item["name"] for item in actions] == list(names)
    for item in actions:
        assert item["status"] == "blocked"
        assert "unknown local step" in item["error"]


def test_engage_step_runs_when_allowed():
    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "allow_engage": True,
        "steps": [
            {
                "name": "engage.recon",
                "inputs": {"target": "http://127.0.0.1:9", "dry_run": True},
            }
        ],
    }
    result = run_runtime_document(plan, allow_local=True, base_dir=REPO_ROOT)
    actions = result["run_state"]["flow"]["tasks"][0]["actions"]

    assert result["loop"]["allow_engage"] is True
    assert actions[0]["status"] == "completed"
    assert actions[0]["output"]["dry_run"] is True


def test_engage_step_blocked_without_allow_engage():
    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [{"name": "engage.recon", "inputs": {"dry_run": True}}],
    }
    result = run_runtime_document(
        plan, allow_local=True, allow_engage=False, stop_on_block=False, base_dir=REPO_ROOT
    )
    actions = result["run_state"]["flow"]["tasks"][0]["actions"]

    assert result["passed"] is False
    assert actions[0]["status"] == "blocked"
    assert "unknown local step" in actions[0]["error"]


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


def test_aggregator_example_plan_dry_runs():
    clear_runtime_runs()
    result = run_runtime_path(AGGREGATOR_PLAN, allow_local=True)
    actions = result["run_state"]["flow"]["tasks"][0]["actions"]
    names = [item["name"] for item in actions]
    state = result["run_state"]["metadata"]["engage_state"]

    assert names == [
        "recon_run",
        "detect_run",
        "nuclei_scan",
        "verify_finding",
        "export_findings",
    ]
    assert result["passed"] is True
    assert result["loop"]["allow_aggregators"] is True
    assert {item["status"] for item in actions} == {"completed"}
    assert all(item["output"]["dry_run"] is True for item in actions)
    assert state["recon"]["dry_run"] is True
    assert state["findings"] == []
    assert state["exported"] is True
    assert state["report_path"] == "(dry-run)"
    clear_runtime_runs()


def test_aggregator_step_blocked_without_allow_aggregators():
    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {"name": "recon_run", "inputs": {"target": "http://127.0.0.1:9", "dry_run": True}}
        ],
    }
    result = run_runtime_document(
        plan,
        allow_local=True,
        allow_aggregators=False,
        stop_on_block=False,
        base_dir=REPO_ROOT,
    )
    actions = result["run_state"]["flow"]["tasks"][0]["actions"]

    assert result["passed"] is False
    assert actions[0]["status"] == "blocked"
    assert "unknown local step" in actions[0]["error"]


def test_aggregator_pipeline_writes_export(tmp_path: Path):
    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {
                "name": "detect_run",
                "inputs": {"url": "http://127.0.0.1:9", "classes": ["xss"], "dry_run": True},
            },
            {
                "name": "verify_finding",
                "inputs": {
                    "dry_run": True,
                    "finding": {
                        "url": "http://127.0.0.1:9",
                        "vuln_type": "xss",
                        "vulnerable": True,
                    },
                },
            },
            {
                "name": "export_findings",
                "inputs": {"dry_run": True, "output_dir": str(tmp_path)},
            },
        ],
    }
    result = run_runtime_document(plan, allow_local=True, base_dir=REPO_ROOT)
    actions = {item["name"]: item for item in result["run_state"]["flow"]["tasks"][0]["actions"]}
    state = result["run_state"]["metadata"]["engage_state"]
    report_path = tmp_path / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert result["passed"] is True
    assert actions["verify_finding"]["output"]["finding"]["verification_status"] == "dry_run"
    assert state["exported"] is True
    assert report["dry_run"] is True
    assert report["scorecard"]["total"] == 1


def test_aggregator_live_recon_uses_engine(monkeypatch):
    async def fake_full(target, quick_mode):
        return {"success": True, "target": target, "data": {"quick_mode": quick_mode}}

    monkeypatch.setattr("core.agent_runtime.aggregators._exec_full_recon", fake_full)
    monkeypatch.setattr(
        "core.agent_runtime.aggregators.require_surface", lambda *args, **kwargs: "scan"
    )
    monkeypatch.setattr("core.agent_runtime.aggregators.assert_in_scope", lambda target: None)

    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {
                "name": "recon_run",
                "inputs": {"target": "http://127.0.0.1:9", "dry_run": False, "quick_mode": True},
            }
        ],
    }
    result = run_runtime_document(plan, allow_local=True, base_dir=REPO_ROOT)
    action = result["run_state"]["flow"]["tasks"][0]["actions"][0]
    state = result["run_state"]["metadata"]["engage_state"]

    assert action["status"] == "completed"
    assert action["output"]["modules"] == ["full_recon"]
    assert action["output"]["results"]["full_recon"]["data"]["quick_mode"] is True
    assert state["recon"]["target"] == "http://127.0.0.1:9"


def test_aggregator_live_detect_and_nuclei(monkeypatch):
    class FakeComposite:
        async def async_detect(self, url, params=None):
            return [
                type(
                    "Row",
                    (),
                    {
                        "vulnerable": True,
                        "to_dict": lambda self: {
                            "url": url,
                            "vuln_type": "xss",
                            "vulnerable": True,
                            "param": "q",
                        },
                    },
                )()
            ]

    class FakeEngine:
        def __init__(self, template_dir=None):
            self.template_dir = template_dir

        def load_templates(self, tags=None, severity=None, limit=None):
            return 1

        async def scan(self, target, tags=None, severity=None, concurrency=10):
            return [{"template_id": "lab-xss", "name": "xss", "severity": "medium"}]

    monkeypatch.setattr(
        "core.agent_runtime.aggregators.require_surface", lambda *args, **kwargs: "scan"
    )
    monkeypatch.setattr("core.agent_runtime.aggregators.assert_in_scope", lambda target: None)
    monkeypatch.setattr(
        "core.detectors.DetectorFactory.exists", classmethod(lambda cls, name: True)
    )
    monkeypatch.setattr(
        "core.detectors.DetectorFactory.create_composite",
        classmethod(lambda cls, names: FakeComposite()),
    )
    monkeypatch.setattr("core.detectors.nuclei_engine.NucleiEngine", FakeEngine)

    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {
                "name": "detect_run",
                "inputs": {"url": "http://127.0.0.1:9", "classes": ["xss"], "dry_run": False},
            },
            {
                "name": "nuclei_scan",
                "inputs": {"url": "http://127.0.0.1:9", "dry_run": False},
            },
        ],
    }
    result = run_runtime_document(plan, allow_local=True, base_dir=REPO_ROOT)
    state = result["run_state"]["metadata"]["engage_state"]
    types = [item.get("vuln_type") for item in state["findings"]]

    assert result["passed"] is True
    assert types == ["xss", "lab-xss"]


def test_aggregator_live_verify_finding(monkeypatch):
    class FakeResult:
        vuln_type = "xss"
        payload = "q=x"
        url = "http://127.0.0.1:9/?q=x"
        is_vulnerable = True
        confidence = "high"
        evidence = "<html>reflected q=x</html>"
        response_time = 0.01
        response_code = 200
        response_length = 24
        verification_method = "reflected_xss"

    class FakeVerifier:
        def __init__(self, timeout=10):
            self.timeout = timeout

        def batch_verify(self, items):
            return [FakeResult()]

    monkeypatch.setattr(
        "core.agent_runtime.aggregators.require_surface", lambda *args, **kwargs: "scan"
    )
    monkeypatch.setattr("core.agent_runtime.aggregators.assert_in_scope", lambda target: None)
    monkeypatch.setattr("core.vuln_verifier.VulnerabilityVerifier", FakeVerifier)

    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {
                "name": "verify_finding",
                "inputs": {
                    "dry_run": False,
                    "finding": {
                        "url": "http://127.0.0.1:9",
                        "vuln_type": "xss",
                        "param": "q",
                        "vulnerable": True,
                    },
                },
            }
        ],
    }
    result = run_runtime_document(plan, allow_local=True, base_dir=REPO_ROOT)
    action = result["run_state"]["flow"]["tasks"][0]["actions"][0]
    finding = action["output"]["finding"]

    assert action["status"] == "completed"
    assert finding["verification_status"] == "verified"
    assert finding["verified_by"] == "vuln_verifier"
    assert finding["provenance"]["bound"] is True
    assert finding["provenance"]["request"]["url"]
    assert finding["provenance"]["response"]["status"] == 200
    assert finding["provenance"]["response"]["body_sha256"]


def test_aggregator_verify_without_receipt_stays_unconfirmed(monkeypatch):
    class FakeResult:
        is_vulnerable = True
        confidence = "high"
        verification_method = "reflected_xss"

    class FakeVerifier:
        def __init__(self, timeout=10):
            self.timeout = timeout

        def batch_verify(self, items):
            return [FakeResult()]

    monkeypatch.setattr(
        "core.agent_runtime.aggregators.require_surface", lambda *args, **kwargs: "scan"
    )
    monkeypatch.setattr("core.agent_runtime.aggregators.assert_in_scope", lambda target: None)
    monkeypatch.setattr("core.vuln_verifier.VulnerabilityVerifier", FakeVerifier)

    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {
                "name": "verify_finding",
                "inputs": {
                    "dry_run": False,
                    "finding": {
                        "url": "http://127.0.0.1:9",
                        "vuln_type": "xss",
                        "param": "q",
                        "vulnerable": True,
                    },
                },
            }
        ],
    }
    result = run_runtime_document(plan, allow_local=True, base_dir=REPO_ROOT)
    finding = result["run_state"]["flow"]["tasks"][0]["actions"][0]["output"]["finding"]

    assert finding["provenance"]["bound"] is False
    assert finding["verification_status"] != "verified"
    assert finding["engagement_verified"] is False
    assert finding.get("missing_checks")


def test_aggregator_live_requires_scan_profile():
    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {
                "name": "recon_run",
                "inputs": {"target": "http://127.0.0.1:9", "dry_run": False},
            }
        ],
    }
    result = run_runtime_document(plan, allow_local=True, base_dir=REPO_ROOT)
    action = result["run_state"]["flow"]["tasks"][0]["actions"][0]

    assert result["passed"] is False
    assert action["status"] == "failed"
    assert "scan" in (action["error"] or "")


def test_cli_runtime_run_aggregator_example():
    from cli.main import app

    result = runner.invoke(app, ["runtime-api", "run", str(AGGREGATOR_PLAN), "--local"])
    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert payload["passed"] is True
    assert payload["loop"]["allow_aggregators"] is True


def test_duplicate_aggregator_steps_replay_without_rerun():
    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {
                "name": "recon_run",
                "inputs": {"target": "http://127.0.0.1:9", "dry_run": True},
            },
            {
                "name": "recon_run",
                "inputs": {"target": "http://127.0.0.1:9", "dry_run": True},
            },
            {
                "name": "detect_run",
                "inputs": {"url": "http://127.0.0.1:9", "dry_run": True},
            },
        ],
    }
    result = run_runtime_document(plan, allow_local=True, base_dir=REPO_ROOT)
    actions = result["run_state"]["flow"]["tasks"][0]["actions"]
    first_id = actions[0]["output"]["tool_execution_id"]

    assert actions[0]["output"].get("replay") is not True
    assert actions[1]["output"]["replay"] is True
    assert actions[1]["output"]["tool_execution_id"] == first_id
    assert actions[2]["output"].get("replay") is not True
    assert actions[2]["output"]["tool_execution_id"] != first_id


def test_failed_aggregator_is_not_replayed(monkeypatch):
    calls = {"n": 0}

    async def boom(inputs, state):
        calls["n"] += 1
        raise ValueError("engine down")

    monkeypatch.setattr(
        "core.agent_runtime.aggregators.require_surface", lambda *args, **kwargs: "scan"
    )
    monkeypatch.setattr("core.agent_runtime.aggregators.assert_in_scope", lambda target: None)
    monkeypatch.setattr("core.agent_runtime.aggregators._exec_recon_run", boom)

    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {
                "name": "recon_run",
                "inputs": {"target": "http://127.0.0.1:9", "dry_run": False},
            },
            {
                "name": "recon_run",
                "inputs": {"target": "http://127.0.0.1:9", "dry_run": False},
            },
        ],
    }
    result = run_runtime_document(plan, allow_local=True, stop_on_block=False, base_dir=REPO_ROOT)
    actions = result["run_state"]["flow"]["tasks"][0]["actions"]

    assert calls["n"] == 2
    assert actions[0]["status"] == "failed"
    assert actions[1]["status"] == "failed"
    assert actions[1]["output"].get("replay") is not True


def test_model_call_without_provider_fail_closes():
    assert "engage.pick" in MODEL_STEPS
    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {
                "name": "engage.pick",
                "kind": "model_call",
                "inputs": {"target": "http://127.0.0.1:9"},
            }
        ],
    }
    result = run_runtime_document(plan, allow_local=True, stop_on_block=False, base_dir=REPO_ROOT)
    action = result["run_state"]["flow"]["tasks"][0]["actions"][0]

    assert result["passed"] is False
    assert action["status"] == "failed"
    assert "AUTORT_LLM_PROVIDER" in (action["error"] or "")


def test_engage_pick_selects_open_coverage_row(monkeypatch):
    class FakeProvider:
        available = True
        provider = "fake"

        def complete(self, prompt, system=""):
            return "detect_run"

    monkeypatch.setattr("core.llm.provider.LLMProvider", FakeProvider)
    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {
                "name": "recon_run",
                "inputs": {"target": "http://127.0.0.1:9", "dry_run": True},
            },
            {
                "name": "engage.pick",
                "kind": "model_call",
                "inputs": {"target": "http://127.0.0.1:9"},
            },
        ],
    }
    result = run_runtime_document(plan, allow_local=True, base_dir=REPO_ROOT)
    actions = {item["name"]: item for item in result["run_state"]["flow"]["tasks"][0]["actions"]}

    assert result["loop"]["allow_model"] is True
    assert actions["engage.pick"]["status"] == "completed"
    assert actions["engage.pick"]["output"]["next"]["name"] == "detect_run"
    assert actions["engage.pick"]["output"]["provider"] == "fake"


def test_engage_pick_unknown_token_uses_heuristic(monkeypatch):
    class FakeProvider:
        available = True
        provider = "fake"

        def complete(self, prompt, system=""):
            return "exploit_run"

    monkeypatch.setattr("core.llm.provider.LLMProvider", FakeProvider)
    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {
                "name": "recon_run",
                "inputs": {"target": "http://127.0.0.1:9", "dry_run": True},
            },
            {
                "name": "engage.pick",
                "inputs": {"target": "http://127.0.0.1:9"},
            },
        ],
    }
    result = run_runtime_document(plan, allow_local=True, base_dir=REPO_ROOT)
    pick = result["run_state"]["flow"]["tasks"][0]["actions"][1]
    assert pick["output"]["next"]["name"] == "detect_run"


def test_shell_kind_stays_forbidden():
    plan = {
        "schema": RUNTIME_SCHEMA,
        "mode": "local",
        "steps": [
            {"name": "recon_run", "kind": "shell", "inputs": {"target": "http://127.0.0.1:9"}}
        ],
    }
    result = run_runtime_document(plan, allow_local=True, stop_on_block=False, base_dir=REPO_ROOT)
    action = result["run_state"]["flow"]["tasks"][0]["actions"][0]
    assert action["status"] == "blocked"
    assert "shell" in (action["error"] or "")
