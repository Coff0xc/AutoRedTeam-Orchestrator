#!/usr/bin/env python3
"""
phases.py - 渗透测试阶段执行器 (兼容层)

此文件保持向后兼容性，实际实现已拆分到 phases/ 子模块。

导入示例:
    # 新方式 (推荐)
    from core.orchestrator.phases import ReconPhaseExecutor, PHASE_EXECUTORS

    # 旧方式 (兼容)
    from core.orchestrator.phases import ReconPhaseExecutor, PHASE_EXECUTORS
"""

# 从新模块导入所有内容
from .phases import (
    CVE_ID_PATTERN,
    PHASE_EXECUTORS,
    BasePhaseExecutor,
    ExfiltratePhaseExecutor,
    ExploitPhaseExecutor,
    LateralMovePhaseExecutor,
    PhaseResult,
    PoCExecPhaseExecutor,
    PrivilegeEscPhaseExecutor,
    ReconPhaseExecutor,
    ReportPhaseExecutor,
    VulnScanPhaseExecutor,
)

__all__ = [
    "BasePhaseExecutor",
    "PhaseResult",
    "CVE_ID_PATTERN",
    "PHASE_EXECUTORS",
    "ReconPhaseExecutor",
    "VulnScanPhaseExecutor",
    "PoCExecPhaseExecutor",
    "ExploitPhaseExecutor",
    "PrivilegeEscPhaseExecutor",
    "LateralMovePhaseExecutor",
    "ExfiltratePhaseExecutor",
    "ReportPhaseExecutor",
]
