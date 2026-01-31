#!/usr/bin/env python3
"""
core.orchestrator - 自动化渗透编排引擎

提供完整的渗透测试流程编排能力

Usage:
    from core.orchestrator import AutoPentestOrchestrator, run_pentest

    # 方式1：完整控制
    orchestrator = AutoPentestOrchestrator("https://target.com")
    result = await orchestrator.run()

    # 方式2：便捷函数
    result = await run_pentest("https://target.com")

    # 方式3：断点续传
    result = await resume_pentest("session_id")

警告: 仅限授权渗透测试使用！
"""

# 数据协议 - v3.0.0新增
from .contracts import (
    AccessGrant,
    AccessLevel,
    AccumulatedState,
    Credential,
    PhaseDataManager,
)
from .contracts import PhaseResult as ContractPhaseResult
from .contracts import (
    SecretType,
    VulnFinding,
    VulnSeverity,
)
from .decision import (
    AttackComplexity,
    AttackPath,
    DecisionEngine,
    RiskLevel,
    ThreatContext,
)
from .orchestrator import (
    AutoPentestOrchestrator,
    OrchestratorConfig,
    resume_pentest,
    run_pentest,
)
from .phases import (
    PHASE_EXECUTORS,
    BasePhaseExecutor,
    PhaseResult,
)
from .state import (
    AccessInfo,
    Checkpoint,
    PentestPhase,
    PentestState,
    PhaseStatus,
)

__all__ = [
    # State
    "PentestPhase",
    "PhaseStatus",
    "Checkpoint",
    "AccessInfo",
    "PentestState",
    # Phases
    "BasePhaseExecutor",
    "PhaseResult",
    "PHASE_EXECUTORS",
    # Decision
    "AttackPath",
    "DecisionEngine",
    "ThreatContext",
    "RiskLevel",
    "AttackComplexity",
    # Orchestrator
    "OrchestratorConfig",
    "AutoPentestOrchestrator",
    "run_pentest",
    "resume_pentest",
    # Contracts (v3.0.0)
    "SecretType",
    "VulnSeverity",
    "AccessLevel",
    "Credential",
    "VulnFinding",
    "AccessGrant",
    "ContractPhaseResult",
    "AccumulatedState",
    "PhaseDataManager",
]

__version__ = "1.1.0"
