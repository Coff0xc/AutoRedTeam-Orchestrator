"""Scan-profile report surfaces. Imported only when the profile allows them."""

from pathlib import Path
from typing import Any, Dict, Optional

from .error_handling import ErrorCategory, handle_errors, validate_inputs
from .report_handlers import (
    _ALLOWED_REPORT_DIRS,
    _PROJECT_ROOT,
    _fail_report_runtime,
    _gate_report_runtime,
)
from .runtime_helpers import (
    blocked_handler_runtime_response,
    complete_handler_runtime_payload,
)
from .tooling import tool


def register_generate_report(mcp, logger) -> int:
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
        from utils.report_generator import ReportGenerator, dumps_report_json

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
                    {
                        "success": False,
                        "format": fmt,
                        "error": f"不支持的报告格式: {format}",
                    },
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
                    "error": (
                        "输出路径不在允许的目录中。"
                        f"允许的目录: {', '.join(_ALLOWED_REPORT_DIRS)}"
                    ),
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
                        f.write(dumps_report_json(report))
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

        payload = {
            "success": True,
            "session_id": session_id,
            "format": fmt,
            "report": report,
        }
        return complete_handler_runtime_payload(
            runtime_gate,
            payload,
            summary_keys=["session_id", "format"],
        )

    return 1
