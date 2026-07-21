from core.ai_redteam import (
    CONVERTERS,
    PROBES,
    SCORERS,
    STRATEGIES,
    apply_strategy,
    catalog_summary,
    convert_prompt,
    evaluate_text,
    plugin_summary,
)
from core.ai_redteam.report import render_markdown, should_fail_ci


def test_catalog_exposes_builtin_components():
    summary = catalog_summary()

    assert "prompt_injection" in PROBES
    assert "base64" in CONVERTERS
    assert "encoding" in STRATEGIES
    assert "secret_leak_detector" in SCORERS
    assert summary["probes"] >= 5
    assert summary["converters"] >= 4
    assert summary["strategies"] >= 4
    assert summary["scorers"] >= 4
    assert summary["plugins"] >= 17
    assert summary["plugin_kinds"]["converter"] >= 4


def test_plugin_registry_groups_builtin_components():
    summary = plugin_summary()
    ids = {item["plugin_id"] for item in summary["items"]}

    assert summary["by_kind"]["probe"] >= 5
    assert summary["by_kind"]["converter"] >= 4
    assert "prompt_injection" in ids
    assert "base64" in ids


def test_prompt_converters_are_first_class_and_deterministic():
    payload = "[AI-REDTEAM-PROBE:prompt_injection]"

    identity = convert_prompt(payload, "identity")
    encoded = convert_prompt(payload, "base64")
    multi_turn = convert_prompt(payload, "multi_turn")

    assert identity.text == payload
    assert encoded.text != payload
    assert encoded.metadata["modifies_payload"] is True
    assert "turn_2" in multi_turn.text


def test_strategy_transformers_are_local_and_deterministic():
    payload = "[AI-REDTEAM-PROBE:prompt_injection]"

    encoded = apply_strategy(payload, "encoding")
    homoglyph = apply_strategy(payload, "homoglyph")
    multi_turn = apply_strategy(payload, "multi_turn")

    assert encoded["strategy"] == "encoding"
    assert encoded["converter"] == "base64"
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
