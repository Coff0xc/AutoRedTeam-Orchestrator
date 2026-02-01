#!/usr/bin/env python3
"""
phases/privesc.py - 权限提升阶段执行器

负责权限提升操作。
"""

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Dict, List

from .base import BasePhaseExecutor, PhaseResult

logger = logging.getLogger(__name__)


class PrivilegeEscPhaseExecutor(BasePhaseExecutor):
    """权限提升阶段执行器"""

    name = "privilege_escalation"
    description = "权限提升"

    @property
    def phase(self):
        from ..state import PentestPhase

        return PentestPhase.PRIVILEGE_ESC

    @property
    def required_phases(self):
        from ..state import PentestPhase

        return (PentestPhase.EXPLOIT,)

    async def execute(self) -> PhaseResult:
        from ..state import PentestPhase

        errors: List[str] = []
        findings: List[Dict[str, Any]] = []

        if not self.state.access_list:
            return PhaseResult(
                success=True,
                phase=PentestPhase.PRIVILEGE_ESC,
                data={"skipped": True, "reason": "无初始访问"},
                findings=findings,
                errors=errors,
            )

        try:
            from core.privilege_escalation import (
                EscalationConfig,
                EscalationMethod,
                get_escalation_module,
            )

            from ..state import AccessInfo

            method_names = self.config.get("escalation_methods") or self.config.get("methods") or []
            methods = []
            for name in method_names:
                try:
                    methods.append(EscalationMethod(name))
                except ValueError:
                    self.logger.warning(f"未知提权方法: {name}")

            escalation_config = EscalationConfig(
                timeout=float(self.config.get("timeout", 60)),
                cleanup=bool(self.config.get("cleanup", True)),
                stealth=bool(self.config.get("stealth", False)),
                auto_select=bool(self.config.get("auto_select", True)),
                min_success_probability=float(self.config.get("min_success_probability", 0.3)),
                safe_mode=bool(self.config.get("safe_mode", True)),
                backup_before=bool(self.config.get("backup_before", True)),
            )
            if methods:
                escalation_config.methods = methods

            module = get_escalation_module(escalation_config)
            with module:
                if escalation_config.auto_select:
                    result = await asyncio.to_thread(module.auto_escalate)
                else:
                    method = methods[0] if methods else None
                    result = await asyncio.to_thread(module.escalate, method)

            data = result.to_dict()
            if result.success:
                access_host = (
                    self.state.access_list[-1].host if self.state.access_list else self.state.target
                )
                access = AccessInfo(
                    host=access_host,
                    method=f"privilege_escalation:{result.method.value}",
                    privilege_level=result.to_level.value,
                    credentials=None,
                    session_token=None,
                    notes=result.evidence or result.output or "",
                )
                self.state.add_access(access)

                findings.append(
                    {
                        "type": "privilege_escalation",
                        "severity": "critical",
                        "title": f"权限提升成功: {result.method.value}",
                        "description": result.output or result.evidence or "",
                        "phase": "privilege_escalation",
                    }
                )

            return PhaseResult(
                success=result.success,
                phase=PentestPhase.PRIVILEGE_ESC,
                data=data,
                findings=findings,
                errors=errors,
            )

        except ImportError as e:
            errors.append(f"模块导入失败: {e}")
            self.logger.exception(f"权限提升模块导入失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.PRIVILEGE_ESC,
                data={},
                findings=findings,
                errors=errors,
            )
        except (OSError, asyncio.TimeoutError, PermissionError) as e:
            errors.append(str(e))
            self.logger.exception(f"权限提升阶段失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.PRIVILEGE_ESC,
                data={},
                findings=findings,
                errors=errors,
            )


__all__ = ["PrivilegeEscPhaseExecutor"]
