"""Built-in AI red-team probes, strategies, and scorers.

The catalog provides metadata only. It does not contain weaponized payloads or
execute against targets.
"""

from __future__ import annotations

from typing import Any, Dict, List


PROBES: Dict[str, Dict[str, Any]] = {
    "prompt_injection": {
        "category": "llm_security",
        "risk_level": "high",
        "description": "Attempts to override system or developer instructions.",
    },
    "tool_injection": {
        "category": "agent_security",
        "risk_level": "high",
        "description": "Attempts to coerce unsafe or unauthorized tool calls.",
    },
    "data_exfiltration": {
        "category": "data_security",
        "risk_level": "critical",
        "description": "Attempts to extract secrets or sensitive context.",
    },
    "rag_leakage": {
        "category": "rag_security",
        "risk_level": "high",
        "description": "Attempts to leak retrieved private documents or hidden context.",
    },
    "policy_bypass": {
        "category": "policy_security",
        "risk_level": "moderate",
        "description": "Attempts to bypass refusal or policy controls.",
    },
}

STRATEGIES: Dict[str, Dict[str, Any]] = {
    "direct": {
        "description": "Use the base probe intent without transformation.",
        "modifies_payload": False,
    },
    "encoding": {
        "description": "Represent the probe intent as encoded text.",
        "modifies_payload": True,
    },
    "homoglyph": {
        "description": "Use visually similar characters to test normalization.",
        "modifies_payload": True,
    },
    "multi_turn": {
        "description": "Split the probe into a multi-turn interaction plan.",
        "modifies_payload": True,
    },
}

SCORERS: Dict[str, Dict[str, Any]] = {
    "secret_leak_detector": {
        "category": "data_security",
        "severity": "critical",
        "description": "Detects common secret patterns in model or agent output.",
    },
    "unsafe_tool_call_detector": {
        "category": "agent_security",
        "severity": "high",
        "description": "Detects unsafe tool-call intent or execution markers.",
    },
    "policy_bypass_detector": {
        "category": "policy_security",
        "severity": "medium",
        "description": "Detects policy bypass markers and compliance failures.",
    },
    "rag_leakage_detector": {
        "category": "rag_security",
        "severity": "high",
        "description": "Detects retrieved-context leakage markers.",
    },
}


def catalog_summary() -> Dict[str, Any]:
    """Return built-in catalog metadata."""
    return {
        "probes": len(PROBES),
        "strategies": len(STRATEGIES),
        "scorers": len(SCORERS),
        "probe_names": sorted(PROBES),
        "strategy_names": sorted(STRATEGIES),
        "scorer_names": sorted(SCORERS),
    }


def unknown_items(kind: str, names: List[str]) -> List[str]:
    """Return catalog item names that are not built in."""
    catalog = {"probe": PROBES, "strategy": STRATEGIES, "scorer": SCORERS}[kind]
    return sorted({name for name in names if name not in catalog})
