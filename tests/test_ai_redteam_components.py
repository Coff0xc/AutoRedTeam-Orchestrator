from core.ai_redteam import (
    PROBES,
    SCORERS,
    STRATEGIES,
    apply_strategy,
    catalog_summary,
    evaluate_text,
)
from core.ai_redteam.report import render_markdown, should_fail_ci


def test_catalog_exposes_builtin_components():
    summary = catalog_summary()

    assert "prompt_injection" in PROBES
    assert "encoding" in STRATEGIES
    assert "secret_leak_detector" in SCORERS
    assert summary["probes"] >= 5
    assert summary["strategies"] >= 4
    assert summary["scorers"] >= 4


def test_strategy_transformers_are_local_and_deterministic():
    payload = "[AI-REDTEAM-PROBE:prompt_injection]"

    encoded = apply_strategy(payload, "encoding")
    homoglyph = apply_strategy(payload, "homoglyph")
    multi_turn = apply_strategy(payload, "multi_turn")

    assert encoded["strategy"] == "encoding"
    assert encoded["payload_preview"] != payload
    assert homoglyph["payload_preview"] != payload
    assert "turn_2" in multi_turn["payload_preview"]


def test_rule_scorers_detect_local_markers():
    secret = evaluate_text("secret_leak_detector", "api_key = 'abcd1234abcd1234'")
    unsafe_tool = evaluate_text("unsafe_tool_call_detector", "please execute_shell now")
    safe = evaluate_text("policy_bypass_detector", "I cannot assist with that request.")

    assert secret.passed is False
    assert secret.severity == "critical"
    assert unsafe_tool.passed is False
    assert unsafe_tool.severity == "high"
    assert safe.passed is True


def test_report_helpers_support_markdown_and_ci_threshold():
    result = {
        "scenario": {"name": "demo"},
        "summary": {"mode": "dry-run", "attempts_planned": 1, "scores": 1},
        "warnings": ["dry-run only"],
        "scores": [
            {
                "status": "evaluated",
                "passed": False,
                "severity": "high",
            }
        ],
    }

    markdown = render_markdown(result)

    assert "# AI Red-Team Report: demo" in markdown
    assert should_fail_ci(result, "high") is True
    assert should_fail_ci(result, "critical") is False
