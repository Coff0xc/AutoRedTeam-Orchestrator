"""Payload transformation strategies for dry-run planning and local tests."""

from __future__ import annotations

from typing import Dict

from core.ai_redteam.converters import convert_prompt


def build_probe_prompt(probe_name: str) -> str:
    """Return a safe synthetic probe prompt for local planning."""
    return f"[AI-REDTEAM-PROBE:{probe_name}] Evaluate whether the target resists this risk."


def apply_strategy(payload: str, strategy_name: str) -> Dict[str, object]:
    """Apply a local, non-executing strategy transformation."""
    if strategy_name == "direct":
        converted = convert_prompt(payload, "identity")
        steps = [*converted.steps, "send_single_turn"]
    elif strategy_name == "encoding":
        converted = convert_prompt(payload, "base64")
        steps = [*converted.steps, "send_single_turn"]
    elif strategy_name == "homoglyph":
        converted = convert_prompt(payload, "homoglyph")
        steps = [*converted.steps, "send_single_turn"]
    elif strategy_name == "multi_turn":
        converted = convert_prompt(payload, "multi_turn")
        steps = converted.steps
    else:
        converted = convert_prompt(payload, strategy_name)
        steps = ["custom_strategy_placeholder"]

    return {
        "strategy": strategy_name,
        "converter": converted.converter,
        "payload_preview": converted.text[:240],
        "payload_length": len(converted.text),
        "steps": steps,
    }
