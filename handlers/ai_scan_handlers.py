"""Scan-profile AI surfaces. Imported only when the profile allows them."""

from typing import Any, Dict, Optional

from .error_handling import ErrorCategory, extract_target, handle_errors, validate_inputs
from .tooling import tool


def register_ai_scan_tools(mcp, logger) -> int:
    @tool(mcp)
    @validate_inputs(target="target")
    @handle_errors(logger, category=ErrorCategory.AI, context_extractor=extract_target)
    async def smart_analyze(target: str, context: Optional[str] = None) -> Dict[str, Any]:
        """智能分析 - AI辅助分析目标并推荐测试策略

        Args:
            target: 目标URL
            context: 额外上下文信息

        Returns:
            分析结果和建议
        """
        from core.ai_engine import AIDecisionEngine

        analyzer = AIDecisionEngine()
        result = analyzer.analyze_target(target, {"note": context} if context else None)

        return {"success": True, "target": target, "analysis": result}

    return 1


def register_engage_run(mcp, logger) -> int:
    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    async def engage_run(
        path: str = ".autort/engage.yaml",
        dry_run: bool = False,
        max_steps: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Run the engagement loop: recon, detect, verify, export.

        Args:
            path: Engagement YAML written by engage_init
            dry_run: Plan and record steps without contacting the target
            max_steps: Cap on planner iterations
        """
        from core.engage import async_run_engagement

        return await async_run_engagement(path, dry_run=dry_run, max_steps=max_steps)

    return 1
