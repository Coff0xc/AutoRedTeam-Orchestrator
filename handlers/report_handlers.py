"""
报告工具处理器
包含: generate_report, export_findings
"""

from pathlib import Path
from typing import Any, Dict, Optional

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

    @tool(mcp)
    @validate_inputs(session_id="session_id")
    @handle_errors(logger, category=ErrorCategory.REPORT)
    async def generate_report(
        session_id: str, format: str = "json", output_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """生成渗透测试报告 - 生成详细的安全评估报告

        Args:
            session_id: 会话ID
            format: 报告格式 (json, html, markdown, executive)
            output_path: 输出路径 (可选)

        Returns:
            报告内容或路径
        """
        from utils.report_generator import ReportGenerator

        runtime_gate = _gate_report_runtime(
            "generate_report",
            {
                "session_id": session_id,
                "format": format,
                "has_output_path": bool(output_path),
            },
            writes_artifact=bool(output_path),
        )
        if not runtime_gate["allowed"]:
            return blocked_handler_runtime_response(runtime_gate)

        try:
            generator = ReportGenerator()
            source = generator.load_source(session_id)
            fmt = (format or "json").lower()

            if fmt == "json":
                report = generator.to_dict(source)
            elif fmt == "html":
                report = generator.to_html(source)
            elif fmt == "markdown":
                report = generator.to_markdown(source)
            elif fmt == "executive":
                report = generator.to_executive(source)
            else:
                return complete_handler_runtime_payload(
                    runtime_gate,
                    {"success": False, "format": fmt, "error": f"不支持的报告格式: {format}"},
                    summary_keys=["format"],
                )
        except Exception as exc:
            _fail_report_runtime(runtime_gate, exc)
            raise

        if output_path:
            # 路径安全校验：防止路径遍历写入任意文件
            resolved = Path(output_path).resolve()
            allowed = False
            for allowed_dir in _ALLOWED_REPORT_DIRS:
                try:
                    resolved.relative_to(_PROJECT_ROOT / allowed_dir)
                    allowed = True
                    break
                except ValueError:
                    continue
            if not allowed:
                payload = {
                    "success": False,
                    "format": fmt,
                    "error": f"输出路径不在允许的目录中。允许的目录: {', '.join(_ALLOWED_REPORT_DIRS)}",
                }
                return complete_handler_runtime_payload(
                    runtime_gate,
                    payload,
                    summary_keys=["format"],
                )
            # 确保父目录存在
            try:
                resolved.parent.mkdir(parents=True, exist_ok=True)

                with open(resolved, "w", encoding="utf-8") as f:
                    if isinstance(report, dict):
                        import json

                        json.dump(report, f, indent=2, ensure_ascii=False)
                    else:
                        f.write(report)
            except Exception as exc:
                _fail_report_runtime(runtime_gate, exc)
                raise

            payload = {
                "success": True,
                "session_id": session_id,
                "format": fmt,
                "output_path": output_path,
            }
            return complete_handler_runtime_payload(
                runtime_gate,
                payload,
                summary_keys=["session_id", "format"],
            )

        payload = {"success": True, "session_id": session_id, "format": fmt, "report": report}
        return complete_handler_runtime_payload(
            runtime_gate,
            payload,
            summary_keys=["session_id", "format"],
        )

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

    counter.add("report", 2)
    logger.info("[Report] 已注册 2 个报告工具")
