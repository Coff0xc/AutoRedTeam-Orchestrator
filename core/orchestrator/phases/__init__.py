#!/usr/bin/env python3
"""
phases/ - 渗透测试阶段执行器模块

此包包含所有渗透测试阶段的执行器实现：
- ReconPhaseExecutor: 侦察阶段
- VulnScanPhaseExecutor: 漏洞扫描阶段
- PoCExecPhaseExecutor: PoC验证阶段
- ExploitPhaseExecutor: 漏洞利用阶段
- PrivilegeEscPhaseExecutor: 权限提升阶段
- LateralMovePhaseExecutor: 横向移动阶段
- ExfiltratePhaseExecutor: 数据外泄阶段
- ReportPhaseExecutor: 报告生成阶段
"""

from .base import BasePhaseExecutor, CVE_ID_PATTERN, PhaseResult
from .exfiltrate import ExfiltratePhaseExecutor
from .exploit import ExploitPhaseExecutor
from .lateral import LateralMovePhaseExecutor
from .poc_exec import PoCExecPhaseExecutor
from .privesc import PrivilegeEscPhaseExecutor
from .recon import ReconPhaseExecutor
from .report import ReportPhaseExecutor
from .vuln_scan import VulnScanPhaseExecutor

# 阶段执行器注册表
PHASE_EXECUTORS = {
    "recon": ReconPhaseExecutor,
    "vuln_scan": VulnScanPhaseExecutor,
    "poc_exec": PoCExecPhaseExecutor,
    "exploit": ExploitPhaseExecutor,
    "privilege_escalation": PrivilegeEscPhaseExecutor,
    "lateral_movement": LateralMovePhaseExecutor,
    "exfiltrate": ExfiltratePhaseExecutor,
    "report": ReportPhaseExecutor,
}

__all__ = [
    # Base classes
    "BasePhaseExecutor",
    "PhaseResult",
    "CVE_ID_PATTERN",
    # Executors
    "ReconPhaseExecutor",
    "VulnScanPhaseExecutor",
    "PoCExecPhaseExecutor",
    "ExploitPhaseExecutor",
    "PrivilegeEscPhaseExecutor",
    "LateralMovePhaseExecutor",
    "ExfiltratePhaseExecutor",
    "ReportPhaseExecutor",
    # Registry
    "PHASE_EXECUTORS",
]
