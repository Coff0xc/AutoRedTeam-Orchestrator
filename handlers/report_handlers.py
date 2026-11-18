"""
报告工具处理器
包含: generate_report, export_findings
"""

from pathlib import Path
from typing import Any, Dict, Optional

from core.capability_manifest import surface_enabled_for_mcp

from .error_handling import ErrorCategory, handle_errors, validate_inputs
from .runtime_helpers import (
    blocked_handler_runtime_response,
    complete_handler_runtime_action,
    complete_handler_runtime_payload,
    gate_handler_runtime_action,
)
from .tooling import tool

# 允许的报告输出目录（相对于项目根）
_ALLOWED_REPORT_DIRS = ("reports", "data", "logs")
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _gate_report_runtime(tool_name: str, inputs: Dict[str, Any], writes_artifact: bool = False):
    return gate_handler_runtime_action(
        tool_name,
        inputs=inputs,
        risk_level="low",
        source="report_handler",
        network_policy="deny",
        artifact_policy="controlled" if writes_artifact else "metadata-only",
    )


def _fail_report_runtime(gate: Dict[str, Any], exc: Exception) -> None:
    complete_handler_runtime_action(
        gate,
        False,
        output={"success": False},
        error=str(exc),
    )


def register_report_tools(mcp, counter, logger):
    """注册报告生成工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    registered = 0
    if surface_enabled_for_mcp(mcp, "tool", "generate_report"):
        from .report_scan_handlers import register_generate_report

        registered += register_generate_report(mcp, logger)

    @tool(mcp)
    @validate_inputs(session_id="session_id")
    @handle_errors(logger, category=ErrorCategory.REPORT)
    async def export_findings(
        session_id: str, severity: Optional[str] = None, format: str = "json"
    ) -> Dict[str, Any]:
        """导出漏洞发现 - 导出会话中发现的漏洞

        Args:
            session_id: 会话ID
            severity: 按严重程度过滤 (critical, high, medium, low)
            format: 输出格式

        Returns:
            漏洞列表
        """
        from core.session import get_session_manager

        runtime_gate = _gate_report_runtime(
            "export_findings",
            {"session_id": session_id, "severity": severity, "format": format},
        )
        if not runtime_gate["allowed"]:
            return blocked_handler_runtime_response(runtime_gate)

        try:
            manager = get_session_manager()
            context = manager.get_session(session_id)
        except Exception as exc:
            _fail_report_runtime(runtime_gate, exc)
            raise

        if not context:
            return complete_handler_runtime_payload(
                runtime_gate,
                {"success": False, "session_id": session_id, "error": f"会话不存在: {session_id}"},
                summary_keys=["session_id"],
            )

        vulns = context.vulnerabilities

        if severity:
            vulns = [v for v in vulns if v.severity.value.lower() == severity.lower()]

        payload = {
            "success": True,
            "session_id": session_id,
            "vulnerabilities": [v.to_dict() for v in vulns],
            "count": len(vulns),
        }
        return complete_handler_runtime_payload(
            runtime_gate,
            payload,
            summary_keys=["session_id", "count"],
        )

    registered += 1
    counter.add("report", registered)
    logger.info("[Report] 已注册 %s 个报告工具", registered)
