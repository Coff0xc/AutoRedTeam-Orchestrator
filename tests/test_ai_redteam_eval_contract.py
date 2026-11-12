"""Local autort.eval/v1 contract: suite loader, probes, CLI, SARIF."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from core.ai_redteam import (
    EVAL_SCHEMA,
    evaluate_eval_document,
    evaluate_path,
    evaluate_suite,
    is_eval_suite,
    load_eval_document,
    suite_to_sarif,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_SUITE = REPO_ROOT / "config" / "ai_redteam.eval.example.yaml"
LABELS = REPO_ROOT / "tests" / "fixtures" / "ai_surface" / "labels.json"
runner = CliRunner()


def test_example_suite_is_eval_document_and_passes():
    data = load_eval_document(EXAMPLE_SUITE)

    assert is_eval_suite(data) is True
    result = evaluate_path(EXAMPLE_SUITE)

    assert result["schema"] == EVAL_SCHEMA
    assert result["passed"] is True
    assert result["summary"]["total"] == 6
    assert result["summary"]["failed"] == 0
    assert result["summary"]["tp"] == 4
    assert result["summary"]["tn"] == 2
    probes = {item["probe"] for item in result["cases"]}
    assert probes == {"text", "surface", "skill", "run_state"}


def test_labels_json_is_not_an_eval_suite():
    data = json.loads(LABELS.read_text(encoding="utf-8"))

    assert is_eval_suite(data) is False


def test_unknown_probe_and_scorer_fail_closed():
    result = evaluate_suite(
        {
            "schema": EVAL_SCHEMA,
            "name": "fail-closed",
            "cases": [
                {"id": "bad-probe", "probe": "live_model", "input": {}, "expect": {}},
                {
                    "id": "bad-scorer",
                    "probe": "text",
                    "input": {"text": "x", "scorer": "not_a_scorer"},
                    "expect": {"passed": True},
                },
            ],
        }
    )

    by_id = {item["case_id"]: item for item in result["cases"]}
    assert result["passed"] is False
    assert by_id["bad-probe"]["passed"] is False
    assert "unknown probe" in by_id["bad-probe"]["evidence"][0]
    assert by_id["bad-scorer"]["passed"] is False
    assert "unknown scorer" in by_id["bad-scorer"]["evidence"][0]


def test_wrong_expect_on_clean_text_is_fn():
    result = evaluate_suite(
        {
            "schema": EVAL_SCHEMA,
            "cases": [
                {
                    "id": "expect-leak",
                    "probe": "text",
                    "input": {
                        "text": "the local clock returned epoch notes",
                        "scorer": "secret_leak_detector",
                    },
                    "expect": {"passed": False},
                }
            ],
        }
    )
    case = result["cases"][0]

    assert result["passed"] is False
    assert case["passed"] is False
    assert case["metadata"]["outcome"] == "fn"


def test_surface_effect_mismatch_needs_reconcile():
    result = evaluate_suite(
        {
            "schema": EVAL_SCHEMA,
            "cases": [
                {
                    "id": "session-create",
                    "probe": "surface",
                    "input": {
                        "path": "handlers/session_handlers.py",
                        "tool": "session_create",
                        "reconcile": False,
                    },
                    "expect": {"issues_include": ["declared_effects_omit_target_contact"]},
                }
            ],
        },
        base_dir=REPO_ROOT,
    )
    case = result["cases"][0]

    assert result["passed"] is False
    assert "declared_effects_omit_target_contact" not in case["observed"]["issues"]
    assert case["metadata"]["outcome"] == "fn"


def test_suite_to_sarif_emits_failed_cases_only():
    failing = evaluate_suite(
        {
            "schema": EVAL_SCHEMA,
            "cases": [
                {
                    "id": "expect-leak",
                    "probe": "text",
                    "input": {
                        "text": "clean",
                        "scorer": "secret_leak_detector",
                    },
                    "expect": {"passed": False},
                }
            ],
        }
    )
    passing = evaluate_path(EXAMPLE_SUITE)
    failed_sarif = suite_to_sarif(failing)
    passed_sarif = suite_to_sarif(passing)

    results = failed_sarif["runs"][0]["results"]
    assert results[0]["ruleId"] == "eval.text"
    assert results[0]["message"]["text"]
    assert failed_sarif["runs"][0]["properties"]["eval_passed"] is False
    assert passed_sarif["runs"][0]["results"] == []
    assert passed_sarif["runs"][0]["properties"]["eval_passed"] is True


def test_cli_eval_run_example_suite_and_sarif():
    from cli.main import app

    json_result = runner.invoke(app, ["ai-redteam", "eval-run", str(EXAMPLE_SUITE)])
    sarif_result = runner.invoke(
        app, ["ai-redteam", "eval-run", str(EXAMPLE_SUITE), "--format", "sarif"]
    )

    assert json_result.exit_code == 0
    payload = json.loads(json_result.stdout)
    assert payload["passed"] is True
    assert payload["schema"] == EVAL_SCHEMA
    assert sarif_result.exit_code == 0
    sarif = json.loads(sarif_result.stdout)
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "AutoRedTeam-Eval"
    assert sarif["runs"][0]["results"] == []


def test_cli_eval_run_ci_fails_when_suite_does_not_match(tmp_path: Path):
    from cli.main import app

    suite = tmp_path / "fn.yaml"
    suite.write_text(
        "schema: autort.eval/v1\n"
        "cases:\n"
        "  - id: expect-leak\n"
        "    probe: text\n"
        "    input:\n"
        "      text: clean\n"
        "      scorer: secret_leak_detector\n"
        "    expect:\n"
        "      passed: false\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["ai-redteam", "eval-run", str(suite), "--ci"])

    assert result.exit_code == 2
    assert '"passed": false' in result.stdout


def test_evaluate_eval_document_keeps_run_state_path():
    result = evaluate_eval_document(
        {
            "mode": "dry-run",
            "flow": {
                "name": "safe",
                "tasks": [
                    {
                        "name": "plan",
                        "actions": [
                            {
                                "name": "dry-run",
                                "kind": "tool_call",
                                "policy": {
                                    "risk_level": "moderate",
                                    "network_policy": "deny",
                                },
                                "status": "skipped",
                                "output": {"message": "safe"},
                            }
                        ],
                    }
                ],
            },
        }
    )

    assert result["passed"] is True
    assert result["summary"]["total"] == 6
    assert "schema" not in result
