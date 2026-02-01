#!/usr/bin/env python3
"""
phases/poc_exec.py - PoC验证阶段执行器

负责使用PoC脚本验证漏洞。
"""

import asyncio
import logging
import re
from typing import TYPE_CHECKING, Any, Dict, List

from .base import BasePhaseExecutor, CVE_ID_PATTERN, PhaseResult

if TYPE_CHECKING:
    from ..state import PentestPhase, PentestState

logger = logging.getLogger(__name__)


class PoCExecPhaseExecutor(BasePhaseExecutor):
    """PoC验证阶段执行器"""

    name = "poc_exec"
    description = "PoC漏洞验证"

    @property
    def phase(self):
        from ..state import PentestPhase

        return PentestPhase.POC_EXEC

    @property
    def required_phases(self):
        from ..state import PentestPhase

        return [PentestPhase.VULN_SCAN]

    async def execute(self) -> PhaseResult:
        from ..state import PentestPhase

        errors: List[str] = []
        findings: List[Dict[str, Any]] = []
        verified_count = 0

        try:
            from core.cve.poc_engine import get_poc_engine

            poc_engine = get_poc_engine()
            high_value_findings = self.state.get_high_value_findings()

            for finding in high_value_findings:
                try:
                    cve_id = (
                        finding.get("cve_id")
                        or finding.get("cve")
                        or finding.get("cve-id")
                        or finding.get("cveId")
                    )
                    if not cve_id:
                        for ref in finding.get("references", []) or []:
                            match = CVE_ID_PATTERN.search(str(ref))
                            if match:
                                cve_id = match.group(0)
                                break
                    if not cve_id and finding.get("evidence"):
                        match = CVE_ID_PATTERN.search(str(finding.get("evidence")))
                        if match:
                            cve_id = match.group(0)
                    if cve_id:
                        cve_id = cve_id.upper()
                    if cve_id:
                        finding["cve_id"] = cve_id
                        result = await asyncio.to_thread(
                            poc_engine.execute, finding.get("url", self.state.target), cve_id
                        )
                        if result.get("verified"):
                            finding["verified"] = True
                            finding["poc_result"] = result
                            verified_count += 1
                            findings.append(finding)
                except (OSError, asyncio.TimeoutError) as e:
                    errors.append(f"验证 {finding.get('type')} 失败: {e}")

            return PhaseResult(
                success=True,
                phase=PentestPhase.POC_EXEC,
                data={"verified": verified_count, "total": len(high_value_findings)},
                findings=findings,
                errors=errors,
            )

        except ImportError as e:
            errors.append(f"模块导入失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.POC_EXEC,
                data={},
                findings=findings,
                errors=errors,
            )
        except (OSError, asyncio.TimeoutError) as e:
            errors.append(str(e))
            return PhaseResult(
                success=False,
                phase=PentestPhase.POC_EXEC,
                data={},
                findings=findings,
                errors=errors,
            )


__all__ = ["PoCExecPhaseExecutor"]
