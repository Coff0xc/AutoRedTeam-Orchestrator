#!/usr/bin/env python3
"""
phases/report.py - 报告生成阶段执行器

负责生成渗透测试报告。
"""

import logging
from typing import TYPE_CHECKING, Any, Dict, List

from .base import BasePhaseExecutor, PhaseResult

if TYPE_CHECKING:
    from ..state import PentestPhase, PentestState

logger = logging.getLogger(__name__)


class ReportPhaseExecutor(BasePhaseExecutor):
    """报告生成阶段执行器"""

    name = "report"
    description = "报告生成"
    required_phases: List["PentestPhase"] = []

    @property
    def phase(self):
        from ..state import PentestPhase

        return PentestPhase.REPORT

    async def execute(self) -> PhaseResult:
        from ..state import PentestPhase

        errors: List[str] = []

        try:
            from utils.report_generator import ReportGenerator

            generator = ReportGenerator()
            formats = (
                self.config.get("report_formats")
                or self.config.get("formats")
                or ["html", "json", "markdown"]
            )
            reports: Dict[str, str] = {}

            for fmt in formats:
                try:
                    report_path = generator.generate(self.state.session_id, fmt)
                    reports[fmt] = report_path
                except (OSError, ValueError) as e:
                    errors.append(f"生成 {fmt} 报告失败: {e}")

            return PhaseResult(
                success=len(reports) > 0,
                phase=PentestPhase.REPORT,
                data={"reports": reports},
                findings=[],
                errors=errors,
            )

        except ImportError as e:
            errors.append(f"模块导入失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.REPORT,
                data={},
                findings=[],
                errors=errors,
            )
        except (OSError, ValueError) as e:
            errors.append(str(e))
            return PhaseResult(
                success=False,
                phase=PentestPhase.REPORT,
                data={},
                findings=[],
                errors=errors,
            )


__all__ = ["ReportPhaseExecutor"]
