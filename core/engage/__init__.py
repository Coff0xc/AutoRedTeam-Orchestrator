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
from core.engage.juiceshop import (
    JUICE_SHOP_DEFAULT,
    JuiceShopError,
    identify_juice_shop,
    juice_shop_reachable,
    run_juice_shop_confirmation_rate,
    seed_findings,
)
from core.engage.ledger import COVERAGE_SCHEMA, build_coverage_ledger
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
from core.engage.world import WORLD_SCHEMA, coverage, ingest_step, unverified_index

__all__ = [
    "DEFAULT_CONFIG_PATH",
    "ENGAGE_SCHEMA",
    "ENGAGE_STEPS",
    "PLAN_STEPS",
    "EngagementConfig",
    "EngagementError",
    "JuiceShopError",
    "JUICE_SHOP_DEFAULT",
    "applied_engagement",
    "async_run_engagement",
    "dispatch_engage_step",
    "engagement_next",
    "engagement_status",
    "execution_id",
    "canonical_step",
    "host_from_target",
    "identify_juice_shop",
    "juice_shop_reachable",
    "run_juice_shop_confirmation_rate",
    "seed_findings",
    "init_engagement",
    "load_config",
    "next_hint",
    "open_gaps",
    "plan_next",
    "run_engagement",
    "save_config",
    "COVERAGE_SCHEMA",
    "SCORECARD_SCHEMA",
    "WORLD_SCHEMA",
    "build_coverage_ledger",
    "build_scorecard",
    "coverage",
    "ingest_step",
    "unverified_index",
]
