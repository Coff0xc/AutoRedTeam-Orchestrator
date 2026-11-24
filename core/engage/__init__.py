"""Authorized engagement loop: init, plan, run, verify, export."""

from core.engage.config import (
    DEFAULT_CONFIG_PATH,
    ENGAGE_SCHEMA,
    EngagementConfig,
    EngagementError,
    host_from_target,
    load_config,
    save_config,
)
from core.engage.planner import (
    ENGAGE_STEPS,
    PLAN_STEPS,
    canonical_step,
    next_hint,
    open_gaps,
    plan_next,
)
from core.engage.runner import (
    applied_engagement,
    async_run_engagement,
    dispatch_engage_step,
    engagement_next,
    engagement_status,
    execution_id,
    init_engagement,
    run_engagement,
)
from core.engage.scorecard import SCORECARD_SCHEMA, build_scorecard

__all__ = [
    "DEFAULT_CONFIG_PATH",
    "ENGAGE_SCHEMA",
    "ENGAGE_STEPS",
    "PLAN_STEPS",
    "EngagementConfig",
    "EngagementError",
    "applied_engagement",
    "async_run_engagement",
    "dispatch_engage_step",
    "engagement_next",
    "engagement_status",
    "execution_id",
    "canonical_step",
    "host_from_target",
    "init_engagement",
    "load_config",
    "next_hint",
    "open_gaps",
    "plan_next",
    "run_engagement",
    "save_config",
    "SCORECARD_SCHEMA",
    "build_scorecard",
]
