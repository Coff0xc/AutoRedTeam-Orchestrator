"""AI red-team scenario models and dry-run runner."""

from core.ai_redteam.catalog import PROBES, SCORERS, STRATEGIES, catalog_summary
from core.ai_redteam.converters import (
    CONVERTERS,
    ConverterResult,
    convert_prompt,
    converters_summary,
)
from core.ai_redteam.models import (
    AIRedTeamRunResult,
    Attempt,
    Probe,
    ReportConfig,
    Scenario,
    ScenarioMode,
    Scope,
    Score,
    Scorer,
    Strategy,
    Target,
)
from core.ai_redteam.plugins import RedTeamPlugin, built_in_plugins, plugin_summary
from core.ai_redteam.eval_cases import (
    EvalCase,
    EvalCaseResult,
    default_eval_cases,
    evaluate_run_cases,
)
from core.ai_redteam.runner import AIRedTeamRunner
from core.ai_redteam.scenario import load_scenario
from core.ai_redteam.scorers import evaluate_all, evaluate_text
from core.ai_redteam.strategies import apply_strategy, build_probe_prompt

__all__ = [
    "AIRedTeamRunResult",
    "AIRedTeamRunner",
    "Attempt",
    "EvalCase",
    "EvalCaseResult",
    "Probe",
    "ReportConfig",
    "Scenario",
    "ScenarioMode",
    "Scope",
    "Score",
    "Scorer",
    "Strategy",
    "Target",
    "CONVERTERS",
    "PROBES",
    "SCORERS",
    "STRATEGIES",
    "ConverterResult",
    "RedTeamPlugin",
    "apply_strategy",
    "build_probe_prompt",
    "built_in_plugins",
    "catalog_summary",
    "convert_prompt",
    "converters_summary",
    "default_eval_cases",
    "evaluate_all",
    "evaluate_run_cases",
    "evaluate_text",
    "load_scenario",
    "plugin_summary",
]
