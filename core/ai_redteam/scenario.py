"""Scenario loading helpers for AI red-team dry-runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import yaml

from core.ai_redteam.models import Scenario


def load_scenario(path: str | Path) -> Scenario:
    """Load a scenario from YAML or JSON."""
    scenario_path = Path(path)
    raw_text = scenario_path.read_text(encoding="utf-8")
    data: Dict[str, Any]

    if scenario_path.suffix.lower() == ".json":
        data = json.loads(raw_text)
    else:
        loaded = yaml.safe_load(raw_text) or {}
        if not isinstance(loaded, dict):
            raise ValueError("Scenario file must contain a mapping at the top level")
        data = loaded

    return Scenario.from_dict(data)
