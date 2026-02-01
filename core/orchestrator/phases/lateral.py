#!/usr/bin/env python3
"""
phases/lateral.py - 横向移动阶段执行器

负责网络内横向移动操作。
"""

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Dict, List

from .base import BasePhaseExecutor, PhaseResult

logger = logging.getLogger(__name__)


class LateralMovePhaseExecutor(BasePhaseExecutor):
    """横向移动阶段执行器"""

    name = "lateral_movement"
    description = "横向移动"

    @property
    def phase(self):
        from ..state import PentestPhase

        return PentestPhase.LATERAL_MOVE

    @property
    def required_phases(self):
        from ..state import PentestPhase

        return (PentestPhase.PRIVILEGE_ESC,)

    async def execute(self) -> PhaseResult:
        from ..state import PentestPhase

        errors: List[str] = []
        findings: List[Dict[str, Any]] = []

        if not self.state.credentials:
            return PhaseResult(
                success=True,
                phase=PentestPhase.LATERAL_MOVE,
                data={"skipped": True, "reason": "无可用凭证"},
                findings=findings,
                errors=errors,
            )

        try:
            from core.lateral import (
                LateralConfig,
                auto_lateral,
                ensure_credentials,
            )

            from ..state import AccessInfo

            targets = self.config.get("lateral_targets") or list(self.state.discovered_hosts)
            if not targets:
                return PhaseResult(
                    success=True,
                    phase=PentestPhase.LATERAL_MOVE,
                    data={"skipped": True, "reason": "无可用横向目标"},
                    findings=findings,
                    errors=errors,
                )

            max_targets = self._clamp_config_int("max_lateral_targets", 10, 1, 100)
            max_creds = self._clamp_config_int(
                "max_lateral_credentials", len(self.state.credentials), 1, 50
            )
            command = self.config.get("lateral_command", "whoami")
            preferred_methods = self.config.get("preferred_methods")

            lateral_config = LateralConfig(timeout=float(self.config.get("timeout", 30.0)))

            success_count = 0
            attempted = 0
            results: Dict[str, List[Dict[str, Any]]] = {}

            for target in targets[:max_targets]:
                target_success = False
                for cred in self.state.credentials[:max_creds]:
                    attempted += 1
                    try:
                        creds = ensure_credentials(cred)
                    except (ValueError, TypeError) as e:
                        errors.append(f"无效凭证: {e}")
                        continue

                    try:
                        module = await asyncio.to_thread(
                            auto_lateral, target, creds, lateral_config, preferred_methods
                        )
                        if not module:
                            continue

                        try:
                            result = await asyncio.to_thread(module.execute, command)
                        finally:
                            await asyncio.to_thread(module.disconnect)

                        results.setdefault(target, []).append(result.to_dict())

                        if result.success:
                            success_count += 1
                            target_success = True
                            access = AccessInfo(
                                host=target,
                                method=f"lateral:{result.method or 'auto'}",
                                privilege_level="unknown",
                                credentials=self._redact_credential(
                                    cred if isinstance(cred, dict) else None
                                ),
                                session_token=None,
                                notes=self._sanitize_output(result.output),
                            )
                            self.state.add_access(access)
                            findings.append(
                                {
                                    "type": "lateral_movement",
                                    "severity": "high",
                                    "title": f"横向移动成功: {target}",
                                    "description": self._sanitize_output(
                                        result.output, max_length=500
                                    ),
                                    "phase": "lateral_movement",
                                }
                            )
                            break
                    except (OSError, ConnectionError, asyncio.TimeoutError) as e:
                        self.logger.exception(f"横向移动失败: {target} - {e}")
                        errors.append(f"横向移动失败 {target}: {e}")

                if not target_success:
                    results.setdefault(target, []).append(
                        {"success": False, "error": "所有凭证均失败"}
                    )

            return PhaseResult(
                success=success_count > 0,
                phase=PentestPhase.LATERAL_MOVE,
                data={
                    "targets": targets[:max_targets],
                    "attempted": attempted,
                    "success_count": success_count,
                    "results": results,
                },
                findings=findings,
                errors=errors,
            )

        except ImportError as e:
            errors.append(f"模块导入失败: {e}")
            self.logger.exception(f"横向移动模块导入失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.LATERAL_MOVE,
                data={},
                findings=findings,
                errors=errors,
            )
        except (OSError, ConnectionError, asyncio.TimeoutError) as e:
            errors.append(str(e))
            self.logger.exception(f"横向移动阶段失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.LATERAL_MOVE,
                data={},
                findings=findings,
                errors=errors,
            )


__all__ = ["LateralMovePhaseExecutor"]
