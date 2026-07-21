#!/usr/bin/env python3
"""
orchestrator.py - 自动化渗透编排引擎

AutoPentestOrchestrator: 串联MCP工具，执行完整渗透流程
支持断点续传、状态持久化、智能决策

警告: 仅限授权渗透测试使用！
"""

import asyncio
import logging
import re
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from core.agent_runtime import (
    Action,
    ActionKind,
    ActionPolicy,
    ActionStatus,
    AgentRunState,
    Flow,
    PolicyMiddleware,
    RiskLevel,
    RunMode,
    RuntimePipeline,
    SandboxMiddleware,
    SandboxPolicy,
    Task,
    register_runtime_run,
)

from .decision import DecisionEngine
from .phases import PHASE_EXECUTORS, PhaseResult
from .state import PentestPhase, PentestState, PhaseStatus

logger = logging.getLogger(__name__)

# session_id 格式校验正则 (32字符hex或带破折号的UUID)
SESSION_ID_PATTERN = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9-]{36}$")

PHASE_RISK: Dict[PentestPhase, RiskLevel] = {
    PentestPhase.RECON: RiskLevel.LOW,
    PentestPhase.VULN_SCAN: RiskLevel.MODERATE,
    PentestPhase.POC_EXEC: RiskLevel.HIGH,
    PentestPhase.EXPLOIT: RiskLevel.CRITICAL,
    PentestPhase.PRIVILEGE_ESC: RiskLevel.CRITICAL,
    PentestPhase.LATERAL_MOVE: RiskLevel.CRITICAL,
    PentestPhase.EXFILTRATE: RiskLevel.CRITICAL,
    PentestPhase.REPORT: RiskLevel.LOW,
}

PHASE_REQUIRES_NETWORK = {
    PentestPhase.RECON,
    PentestPhase.VULN_SCAN,
    PentestPhase.POC_EXEC,
    PentestPhase.EXPLOIT,
    PentestPhase.PRIVILEGE_ESC,
    PentestPhase.LATERAL_MOVE,
    PentestPhase.EXFILTRATE,
}


class OrchestratorConfig:
    """编排器配置"""

    def __init__(
        self,
        auto_mode: bool = True,
        skip_phases: Optional[List[str]] = None,
        max_retries: int = 3,
        checkpoint_interval: int = 60,
        timeout: int = 3600,
        quick_mode: bool = False,
        skip_exfiltrate: bool = True,
        report_formats: Optional[List[str]] = None,
        runtime_policy_enabled: bool = True,
        runtime_mode: str = "dry-run",
        runtime_network_policy: str = "controlled",
        runtime_sandbox_provider: str = "policy",
        runtime_human_approved: bool = False,
    ):
        self.auto_mode = auto_mode
        self.skip_phases = skip_phases or []
        self.max_retries = max_retries
        self.checkpoint_interval = checkpoint_interval
        self.timeout = timeout
        self.quick_mode = quick_mode
        self.skip_exfiltrate = skip_exfiltrate
        self.report_formats = report_formats or ["html", "json"]
        self.runtime_policy_enabled = runtime_policy_enabled
        self.runtime_mode = runtime_mode
        self.runtime_network_policy = runtime_network_policy
        self.runtime_sandbox_provider = runtime_sandbox_provider
        self.runtime_human_approved = runtime_human_approved

    def to_dict(self) -> Dict[str, Any]:
        return {
            "auto_mode": self.auto_mode,
            "skip_phases": self.skip_phases,
            "max_retries": self.max_retries,
            "checkpoint_interval": self.checkpoint_interval,
            "timeout": self.timeout,
            "quick_mode": self.quick_mode,
            "skip_exfiltrate": self.skip_exfiltrate,
            "report_formats": self.report_formats,
            "runtime_policy_enabled": self.runtime_policy_enabled,
            "runtime_mode": self.runtime_mode,
            "runtime_network_policy": self.runtime_network_policy,
            "runtime_sandbox_provider": self.runtime_sandbox_provider,
            "runtime_human_approved": self.runtime_human_approved,
        }


class AutoPentestOrchestrator:
    """自动化渗透编排引擎

    串联MCP工具执行完整渗透流程:
    RECON -> VULN_SCAN -> POC_EXEC -> EXPLOIT -> PRIV_ESC -> LATERAL -> EXFIL -> REPORT

    Usage:
        orchestrator = AutoPentestOrchestrator("https://target.com")
        result = await orchestrator.run()

        # 从检查点恢复
        orchestrator = AutoPentestOrchestrator.resume("session_id")
        result = await orchestrator.run()

    警告: 仅限授权渗透测试使用！
    """

    PHASE_ORDER = [
        PentestPhase.RECON,
        PentestPhase.VULN_SCAN,
        PentestPhase.POC_EXEC,
        PentestPhase.EXPLOIT,
        PentestPhase.PRIVILEGE_ESC,
        PentestPhase.LATERAL_MOVE,
        PentestPhase.EXFILTRATE,
        PentestPhase.REPORT,
    ]

    def __init__(
        self,
        target: str,
        config: Optional[OrchestratorConfig] = None,
        state: Optional[PentestState] = None,
    ):
        self.target = target
        self.config = config or OrchestratorConfig()
        self.state = state or PentestState(target=target)
        self.state.config = self.config.to_dict()

        self.decision_engine = DecisionEngine(self.state)
        self.runtime_run_state = AgentRunState(
            flow=Flow(
                name=f"pentest:{target}",
                metadata={"source": "AutoPentestOrchestrator"},
            ),
            mode=RunMode(self.config.runtime_mode),
            metadata={
                "session_id": self.state.session_id,
                "target": target,
                "runtime_policy_enabled": self.config.runtime_policy_enabled,
                "capability_readiness": self._capability_readiness_summary(),
            },
        )
        self.runtime_pipeline = RuntimePipeline(
            [
                PolicyMiddleware(human_approved=self.config.runtime_human_approved),
                SandboxMiddleware(
                    SandboxPolicy(
                        enabled=self.config.runtime_policy_enabled,
                        provider=self.config.runtime_sandbox_provider,
                        network_policy=self.config.runtime_network_policy,
                    )
                ),
            ]
        )
        register_runtime_run(self.runtime_run_state)
        self._storage: Any = None
        self._progress_callback: Optional[Callable] = None
        self._state_lock = asyncio.Lock()  # 并发保护锁
        self._has_critical_failure = False  # 跟踪关键阶段失败

        self.logger = logging.getLogger(__name__)

    def _capability_readiness_summary(self) -> Dict[str, Any]:
        """Attach current AI capability coverage metadata to runtime traces."""
        try:
            from core.ai_capabilities import refactor_readiness

            readiness = refactor_readiness()
            return {
                "ready_for_full_refactor": readiness.get("ready_for_full_refactor"),
                "summary": readiness.get("summary", {}),
            }
        except Exception as exc:  # pragma: no cover - defensive metadata only
            return {"error": str(exc)}

    @classmethod
    def resume(cls, session_id: str) -> "AutoPentestOrchestrator":
        """从会话恢复编排器"""
        # 安全校验: 防止路径遍历攻击
        if not SESSION_ID_PATTERN.match(session_id):
            raise ValueError(f"无效的session_id格式: {session_id}")

        from core.session.storage import SessionStorage

        storage = SessionStorage()
        context = storage.load_context(session_id)

        if not context:
            raise ValueError(f"会话不存在: {session_id}")

        state = PentestState.from_dict(context.to_dict())
        orchestrator = cls(target=state.target, state=state)
        orchestrator._storage = storage

        return orchestrator

    async def run(self, start_phase: Optional[PentestPhase] = None) -> Dict[str, Any]:
        """执行完整渗透流程"""
        start_time = datetime.now()
        self.logger.info("开始渗透测试: %s, session=%s", self.target, self.state.session_id)

        if start_phase:
            start_idx = self.PHASE_ORDER.index(start_phase)
        elif self.state.last_checkpoint:
            start_idx = self.PHASE_ORDER.index(self.state.last_checkpoint.phase)
        else:
            start_idx = 0

        results: Dict[str, Any] = {}
        self._has_critical_failure = False  # 重置失败标志

        try:
            for phase in self.PHASE_ORDER[start_idx:]:
                if phase.value in self.config.skip_phases:
                    self.logger.info("跳过阶段: %s", phase.value)
                    self.state.phase_status[phase.value] = PhaseStatus.SKIPPED
                    continue

                if self.decision_engine._should_skip_phase(phase):
                    self.state.phase_status[phase.value] = PhaseStatus.SKIPPED
                    continue

                self._report_progress(phase, "starting")
                result = await self.execute_phase(phase)
                results[phase.value] = result.to_dict()

                await self._save_state()

                if not result.success and phase in (PentestPhase.RECON, PentestPhase.VULN_SCAN):
                    self.logger.error("关键阶段失败: %s", phase.value)
                    self._has_critical_failure = True
                    break

                self._report_progress(phase, "completed")

            # 根据执行结果设置正确的最终状态
            if self._has_critical_failure:
                self.state.current_phase = PentestPhase.FAILED
            else:
                self.state.current_phase = PentestPhase.COMPLETED

        except Exception as e:
            self.logger.exception("执行失败: %s", e)  # 使用exception记录堆栈
            self.state.current_phase = PentestPhase.FAILED
            results["error"] = str(e)

        finally:
            await self._save_state()

        duration = (datetime.now() - start_time).total_seconds()

        return {
            "session_id": self.state.session_id,
            "target": self.target,
            "status": self.state.current_phase.value,
            "duration": duration,
            "phases": results,
            "runtime": self.runtime_run_state.to_dict(),
            "findings_summary": self._summarize_findings(),
            "attack_paths": [
                {
                    "name": p.name,
                    "description": p.description,
                    "priority": p.priority,
                    "success_probability": p.success_probability,
                }
                for p in self.decision_engine.suggest_attack_paths()[:3]
            ],
        }

    async def execute_phase(
        self, phase: PentestPhase, config: Optional[Dict[str, Any]] = None
    ) -> PhaseResult:
        """执行单个阶段

        Args:
            phase: 要执行的阶段
            config: 阶段特定配置，会覆盖全局配置中的同名键

        Returns:
            PhaseResult 阶段执行结果
        """
        executor_class = PHASE_EXECUTORS.get(phase.value)
        if not executor_class:
            raise ValueError(f"未知阶段: {phase.value}")

        # 配置合并: 全局配置为基础，阶段配置覆盖
        # (修复: 原代码是阶段配置被全局配置覆盖，逻辑相反)
        phase_config = self.config.to_dict()
        if config:
            phase_config.update(config)
        if self.config.runtime_policy_enabled:
            phase_config["_runtime_run_state"] = self.runtime_run_state
            phase_config["_runtime_pipeline"] = self.runtime_pipeline

        executor = executor_class(self.state, phase_config)  # type: ignore[abstract]

        if not executor.can_execute():
            missing = executor.get_missing_requirements()
            return PhaseResult(
                success=False,
                phase=phase,
                data={},
                findings=[],
                errors=[f"缺少前置阶段: {[p.value for p in missing]}"],
            )

        if self.config.runtime_policy_enabled:
            runtime_action = self._create_phase_action(phase, phase_config)
            runtime_decisions = self.runtime_pipeline.evaluate_action(
                self.runtime_run_state,
                runtime_action,
            )
            blocked = next(
                (decision for decision in runtime_decisions if not decision.allowed), None
            )
            if blocked:
                runtime_action.mark_blocked(blocked.reason)
                self.runtime_run_state.require_gate(runtime_action, blocked.reason)
                self.state.fail_phase(phase, blocked.reason)
                return PhaseResult(
                    success=False,
                    phase=phase,
                    data={
                        "runtime": {
                            "action": runtime_action.to_dict(),
                            "decisions": [decision.to_dict() for decision in runtime_decisions],
                        }
                    },
                    findings=[],
                    errors=[blocked.reason],
                )
            if self.runtime_run_state.mode == RunMode.DRY_RUN:
                runtime_action.mark_skipped(
                    {
                        "planned_only": True,
                        "reason": "orchestrator runtime dry-run",
                    }
                )
                self.state.phase_status[phase.value] = PhaseStatus.SKIPPED
                return PhaseResult(
                    success=True,
                    phase=phase,
                    data={
                        "skipped": True,
                        "reason": "runtime_dry_run",
                        "runtime": {
                            "action": runtime_action.to_dict(),
                            "decisions": [decision.to_dict() for decision in runtime_decisions],
                        },
                    },
                    findings=[],
                    errors=[],
                )
            runtime_action.status = ActionStatus.RUNNING
            runtime_action.updated_at = datetime.now().isoformat()
        else:
            runtime_action = None
            runtime_decisions = []

        self.state.set_phase(phase, PhaseStatus.RUNNING)

        try:
            if self.state.last_checkpoint and self.state.last_checkpoint.phase == phase:
                result = await executor.resume(self.state.last_checkpoint.data)
            else:
                result = await executor.execute()

            if result.findings:
                known = {id(finding) for finding in self.state.findings}
                for finding in result.findings:
                    if id(finding) not in known:
                        self.state.add_finding(finding)

            if result.success:
                self.state.complete_phase(phase, result.to_dict())
            else:
                self.state.fail_phase(phase, "; ".join(result.errors))

            analysis = self.decision_engine.analyze_result(phase, result.to_dict())
            result.data["analysis"] = analysis
            if runtime_action:
                runtime_action.mark_completed(
                    {
                        "phase_success": result.success,
                        "findings_count": len(result.findings),
                        "errors_count": len(result.errors),
                    }
                )
                result.data["runtime"] = {
                    "action": runtime_action.to_dict(),
                    "decisions": [decision.to_dict() for decision in runtime_decisions],
                }

            return result

        except Exception as e:
            self.logger.exception("阶段 %s 执行异常: %s", phase.value, e)
            self.state.fail_phase(phase, str(e))
            if runtime_action:
                runtime_action.status = ActionStatus.FAILED
                runtime_action.error = str(e)
                runtime_action.updated_at = datetime.now().isoformat()
            return PhaseResult(success=False, phase=phase, data={}, findings=[], errors=[str(e)])

    def _create_phase_action(
        self,
        phase: PentestPhase,
        phase_config: Dict[str, Any],
    ) -> Action:
        """Represent a legacy orchestrator phase as a runtime-gated action."""
        task = self.runtime_run_state.flow.add_task(
            Task(
                name=f"phase:{phase.value}",
                description="Legacy orchestrator phase gated by runtime middleware.",
                metadata={"phase": phase.value},
            )
        )
        risk_level = PHASE_RISK.get(phase, RiskLevel.MODERATE)
        action = Action(
            name=f"orchestrator.{phase.value}",
            kind=ActionKind.TOOL_CALL,
            inputs={
                "phase": phase.value,
                "target": self.target,
                "quick_mode": bool(phase_config.get("quick_mode")),
                "auto_mode": bool(phase_config.get("auto_mode")),
            },
            policy=ActionPolicy(
                risk_level=risk_level,
                requires_auth=True,
                requires_human_gate=risk_level.is_high_risk(),
                allowed_in_dry_run=risk_level
                in {RiskLevel.INFO, RiskLevel.LOW, RiskLevel.MODERATE},
                network_policy=(
                    self.config.runtime_network_policy
                    if phase in PHASE_REQUIRES_NETWORK
                    else "deny"
                ),
                artifact_policy="metadata-only",
                cleanup_policy="phase-owned",
            ),
        )
        return task.add_action(action)

    def pause(self) -> bool:
        """暂停执行"""
        if self.state.current_phase not in (PentestPhase.COMPLETED, PentestPhase.FAILED):
            self.state.current_phase = PentestPhase.PAUSED
            # 使用同步方式保存，避免在非异步上下文中调用create_task
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._save_state())
            except RuntimeError:
                # 没有运行的事件循环，跳过异步保存
                self.logger.warning("无法异步保存状态: 没有运行的事件循环")
            return True
        return False

    async def _save_state(self) -> None:
        """保存状态到存储 - 使用脱敏数据"""
        async with self._state_lock:  # 并发保护
            from core.session.context import ScanContext
            from core.session.storage import SessionStorage

            if self._storage is None:
                self._storage = SessionStorage()

            try:
                # 使用脱敏数据进行持久化
                context_data = self.state.to_safe_dict()
                context = ScanContext(
                    session_id=self.state.session_id,
                    config=context_data.get("config", {}),
                    fingerprints=context_data.get("recon_data", {}).get("fingerprints", {}),
                    technologies=context_data.get("recon_data", {}).get("technologies", []),
                    ports=[],
                    subdomains=list(self.state.discovered_hosts),
                    metadata=context_data,
                )
                self._storage.save_context(context)
            except Exception as e:
                self.logger.exception("保存状态失败: %s", e)

    def _report_progress(self, phase: PentestPhase, status: str) -> None:
        """报告进度 - 使用脱敏数据"""
        self.logger.info("[%s] %s: %s", self.state.session_id[:8], phase.value, status)

        if self._progress_callback:
            try:
                # 使用脱敏数据进行回调，避免敏感信息泄露
                self._progress_callback(phase.value, status, self.state.to_safe_dict())
            except Exception as e:
                self.logger.warning("进度回调失败: %s", e)

    def _summarize_findings(self) -> Dict[str, Any]:
        """汇总发现"""
        findings = self.state.findings

        summary: Dict[str, Any] = {
            "total": len(findings),
            "critical": len([f for f in findings if f.get("severity") == "critical"]),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
            "low": len([f for f in findings if f.get("severity") == "low"]),
            "info": len([f for f in findings if f.get("severity") == "info"]),
            "verified": len([f for f in findings if f.get("verified")]),
            "by_type": {},
        }

        for finding in findings:
            vuln_type = finding.get("type", "unknown")
            summary["by_type"][vuln_type] = summary["by_type"].get(vuln_type, 0) + 1

        return summary

    def set_progress_callback(self, callback: Callable) -> None:
        """设置进度回调"""
        self._progress_callback = callback

    def get_state(self) -> Dict[str, Any]:
        """获取当前状态"""
        return self.state.to_dict()

    def get_findings(self) -> List[Dict[str, Any]]:
        """获取所有发现"""
        return self.state.findings

    def get_attack_paths(self) -> List[Dict[str, Any]]:
        """获取建议的攻击路径"""
        paths = self.decision_engine.suggest_attack_paths()
        return [
            {
                "name": p.name,
                "description": p.description,
                "priority": p.priority,
                "success_probability": p.success_probability,
                "tools": p.tools,
            }
            for p in paths
        ]


async def run_pentest(
    target: str, quick_mode: bool = False, skip_exfiltrate: bool = True
) -> Dict[str, Any]:
    """便捷函数：执行自动化渗透测试"""
    config = OrchestratorConfig(quick_mode=quick_mode, skip_exfiltrate=skip_exfiltrate)
    orchestrator = AutoPentestOrchestrator(target, config)
    return await orchestrator.run()


async def resume_pentest(session_id: str) -> Dict[str, Any]:
    """便捷函数：恢复渗透测试"""
    orchestrator = AutoPentestOrchestrator.resume(session_id)
    return await orchestrator.run()


__all__ = [
    "OrchestratorConfig",
    "AutoPentestOrchestrator",
    "run_pentest",
    "resume_pentest",
]
