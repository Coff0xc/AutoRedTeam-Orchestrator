import json

from typer.testing import CliRunner

from core.agent_runtime import Action, ActionKind, ActionPolicy, RiskLevel, RunMode
from core.ai_redteam import AIRedTeamRunner, Scenario, load_scenario


def test_action_policy_blocks_high_risk_active_without_gate():
    policy = ActionPolicy(risk_level=RiskLevel.HIGH, requires_human_gate=True)

    assert policy.block_reason(RunMode.ACTIVE) == "Action requires human approval"
    assert policy.block_reason(RunMode.ACTIVE, human_approved=True) is None


def test_action_serializes_policy_and_status():
    action = Action(
        name="plan probe",
        kind=ActionKind.TOOL_CALL,
        inputs={"target": "demo"},
        policy=ActionPolicy(risk_level=RiskLevel.MODERATE, network_policy="deny"),
    )
    action.mark_skipped({"planned_only": True})

    data = action.to_dict()
    assert data["kind"] == "tool_call"
    assert data["status"] == "skipped"
    assert data["policy"]["network_policy"] == "deny"
    assert data["output"]["planned_only"] is True


def test_load_yaml_scenario_and_plan_dry_run(tmp_path):
    scenario_file = tmp_path / "scenario.yaml"
    scenario_file.write_text(
        """
name: local-agent-check
mode: dry-run
scope:
  allowed_targets:
    - http://127.0.0.1:8000
targets:
  - id: demo-agent
    type: http_agent
    endpoint: http://127.0.0.1:8000/chat
probes:
  - prompt_injection
  - tool_injection
strategies:
  - direct
  - encoding
scorers:
  - secret_leak_detector
report:
  formats: [json, markdown]
""",
        encoding="utf-8",
    )

    scenario = load_scenario(scenario_file)
    result = AIRedTeamRunner(scenario).run().to_dict()

    assert result["summary"]["mode"] == "dry-run"
    assert result["summary"]["attempts_planned"] == 4
    assert result["summary"]["scores"] == 4
    assert result["run_state"]["summary"]["action_status"]["skipped"] == 4
    assert all(
        action["policy"]["network_policy"] == "deny"
        for action in result["run_state"]["flow"]["tasks"][0]["actions"]
    )
    action_inputs = result["run_state"]["flow"]["tasks"][0]["actions"][0]["inputs"]
    assert action_inputs["strategy_plan"]["strategy"] == "direct"
    assert "payload_preview" in action_inputs["strategy_plan"]
    assert result["run_state"]["summary"]["memory_records"] == 1
    assert "observability" in result["run_state"]["metadata"]
    assert "benchmark" in result["run_state"]["metadata"]


def test_scenario_rejects_blocked_target():
    scenario = Scenario.from_dict(
        {
            "name": "blocked-target",
            "targets": [
                {
                    "id": "metadata",
                    "type": "http_agent",
                    "endpoint": "http://169.254.169.254/latest/meta-data",
                }
            ],
            "probes": ["prompt_injection"],
        }
    )

    errors = scenario.validate()
    assert errors
    assert "outside allowed scope" in errors[0]


def test_json_scenario_loads(tmp_path):
    scenario_file = tmp_path / "scenario.json"
    scenario_file.write_text(
        json.dumps(
            {
                "name": "json-scenario",
                "mode": "dry-run",
                "targets": [{"id": "agent", "type": "text"}],
                "probes": ["jailbreak"],
            }
        ),
        encoding="utf-8",
    )

    scenario = load_scenario(scenario_file)
    assert scenario.name == "json-scenario"
    assert scenario.targets[0].target_id == "agent"
    assert scenario.probes[0].probe_id == "jailbreak"


def test_cli_ai_redteam_dry_run(tmp_path):
    from cli.main import app

    scenario_file = tmp_path / "scenario.yaml"
    scenario_file.write_text(
        """
name: cli-dry-run
mode: dry-run
targets:
  - id: text-target
    type: text
probes:
  - prompt_injection
strategies:
  - direct
scorers:
  - unsafe_tool_call_detector
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["ai-redteam", "run", str(scenario_file)])
    assert result.exit_code == 0
    assert '"attempts_planned": 1' in result.output
    assert "dry-run" in result.output


def test_cli_ai_redteam_catalog():
    from cli.main import app

    result = CliRunner().invoke(app, ["ai-redteam", "catalog"])

    assert result.exit_code == 0
    assert "prompt_injection" in result.output
    assert "secret_leak_detector" in result.output


def test_cli_ai_redteam_markdown_report(tmp_path):
    from cli.main import app

    scenario_file = tmp_path / "scenario.yaml"
    scenario_file.write_text(
        """
name: cli-markdown
mode: dry-run
targets:
  - id: text-target
    type: text
probes:
  - prompt_injection
strategies:
  - direct
scorers:
  - unsafe_tool_call_detector
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app, ["ai-redteam", "run", str(scenario_file), "--format", "markdown"]
    )

    assert result.exit_code == 0
    assert "# AI Red-Team Report: cli-markdown" in result.output
