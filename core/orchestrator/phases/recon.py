#!/usr/bin/env python3
"""
phases/recon.py - 侦察阶段执行器

负责信息收集与资产发现。
"""

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Dict, List

from .base import BasePhaseExecutor, PhaseResult

logger = logging.getLogger(__name__)


class ReconPhaseExecutor(BasePhaseExecutor):
    """侦察阶段执行器"""

    name = "recon"
    description = "信息收集与资产发现"
    required_phases: tuple = ()

    @property
    def phase(self):
        from ..state import PentestPhase

        return PentestPhase.RECON

    async def execute(self) -> PhaseResult:
        from ..state import PentestPhase

        errors: List[str] = []
        findings: List[Dict[str, Any]] = []

        try:
            from core.recon.base import ReconConfig
            from core.recon.engine import StandardReconEngine

            recon_config = ReconConfig(
                quick_mode=self.config.get("quick_mode", False),
                enable_port_scan=self.config.get("enable_port_scan", True),
                enable_subdomain=self.config.get("enable_subdomain", True),
                enable_directory=self.config.get("enable_directory", True),
                enable_waf_detect=self.config.get("enable_waf_detect", True),
                max_threads=self.config.get("max_threads", 20),
                timeout=self.config.get("timeout", 30),
            )

            engine = StandardReconEngine(self.state.target, recon_config)
            result = await asyncio.to_thread(engine.run)

            self.state.recon_data = {
                "ip_addresses": getattr(result, "ip_addresses", []),
                "open_ports": getattr(result, "open_ports", []),
                "subdomains": getattr(result, "subdomains", []),
                "directories": getattr(result, "directories", []),
                "technologies": getattr(result, "technologies", []),
                "fingerprints": getattr(result, "fingerprints", {}),
                "waf_detected": getattr(result, "waf_detected", None),
                "sensitive_files": getattr(result, "sensitive_files", []),
            }

            for ip in self.state.recon_data.get("ip_addresses", []):
                self.state.discovered_hosts.add(ip)

            for subdomain in self.state.recon_data.get("subdomains", []):
                self.state.discovered_hosts.add(subdomain)

            return PhaseResult(
                success=True,
                phase=PentestPhase.RECON,
                data=self.state.recon_data,
                findings=findings,
                errors=errors,
                duration=getattr(result, "duration", 0),
            )

        except ImportError as e:
            errors.append(f"模块导入失败: {e}")
            self.logger.exception(f"侦察阶段导入失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.RECON,
                data={},
                findings=findings,
                errors=errors,
            )
        except (OSError, asyncio.TimeoutError) as e:
            errors.append(str(e))
            self.logger.exception(f"侦察阶段失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.RECON,
                data={},
                findings=findings,
                errors=errors,
            )


__all__ = ["ReconPhaseExecutor"]
