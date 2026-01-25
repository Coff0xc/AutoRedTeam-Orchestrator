#!/usr/bin/env python3
"""
orchestrator.py - 自动化渗透编排引擎

AutoPentestOrchestrator: 串联MCP工具，执行完整渗透流程
支持断点续传、状态持久化、智能决策

警告: 仅限授权渗透测试使用！
"""

from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
import asyncio
import logging
import re

from .state import PentestState, PentestPhase, PhaseStatus
from .phases import BasePhaseExecutor, PhaseResult, PHASE_EXECUTORS
from .decision import DecisionEngine

logger = logging.getLogger(__name__)

# session_id 格式校验正则 (32字符hex或带破折号的UUID)
SESSION_ID_PATTERN = re.compile(r'^[a-f0-9]{32}$|^[a-f0-9-]{36}$')


class OrchestratorConfig:
    """编排器配置"""

    def __init__(
        self,
        auto_mode: bool = True,
        skip_phases: List[str] = None,
        max_retries: int = 3,
        checkpoint_interval: int = 60,
        timeout: int = 3600,
        quick_mode: bool = False,
        skip_exfiltrate: bool = True,
        report_formats: List[str] = None
    ):
        self.auto_mode = auto_mode
        self.skip_phases = skip_phases or []
        self.max_retries = max_retries
        self.checkpoint_interval = checkpoint_interval
        self.timeout = timeout
        self.quick_mode = quick_mode
        self.skip_exfiltrate = skip_exfiltrate
        self.report_formats = report_formats or ['html', 'json']

    def to_dict(self) -> Dict[str, Any]:
        return {
            'auto_mode': self.auto_mode,
            'skip_phases': self.skip_phases,
            'max_retries': self.max_retries,
            'checkpoint_interval': self.checkpoint_interval,
            'timeout': self.timeout,
            'quick_mode': self.quick_mode,
            'skip_exfiltrate': self.skip_exfiltrate,
            'report_formats': self.report_formats
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
        state: Optional[PentestState] = None
    ):
        self.target = target
        self.config = config or OrchestratorConfig()
        self.state = state or PentestState(target=target)
        self.state.config = self.config.to_dict()

        self.decision_engine = DecisionEngine(self.state)
        self._storage = None
        self._progress_callback: Optional[Callable] = None
        self._state_lock = asyncio.Lock()  # 并发保护锁
        self._has_critical_failure = False  # 跟踪关键阶段失败

        self.logger = logging.getLogger(__name__)

    @classmethod
    def resume(cls, session_id: str) -> 'AutoPentestOrchestrator':
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
        self.logger.info(f"开始渗透测试: {self.target}, session={self.state.session_id}")

        if start_phase:
            start_idx = self.PHASE_ORDER.index(start_phase)
        elif self.state.last_checkpoint:
            start_idx = self.PHASE_ORDER.index(self.state.last_checkpoint.phase)
        else:
            start_idx = 0

        results = {}
        self._has_critical_failure = False  # 重置失败标志

        try:
            for phase in self.PHASE_ORDER[start_idx:]:
                if phase.value in self.config.skip_phases:
                    self.logger.info(f"跳过阶段: {phase.value}")
                    self.state.phase_status[phase.value] = PhaseStatus.SKIPPED
                    continue

                if self.decision_engine._should_skip_phase(phase):
                    self.state.phase_status[phase.value] = PhaseStatus.SKIPPED
                    continue

                self._report_progress(phase, 'starting')
                result = await self.execute_phase(phase)
                results[phase.value] = result.to_dict()

                await self._save_state()

                if not result.success and phase in (PentestPhase.RECON, PentestPhase.VULN_SCAN):
                    self.logger.error(f"关键阶段失败: {phase.value}")
                    self._has_critical_failure = True
                    break

                self._report_progress(phase, 'completed')

            # 根据执行结果设置正确的最终状态
            if self._has_critical_failure:
                self.state.current_phase = PentestPhase.FAILED
            else:
                self.state.current_phase = PentestPhase.COMPLETED

        except Exception as e:
            self.logger.exception(f"执行失败: {e}")  # 使用exception记录堆栈
            self.state.current_phase = PentestPhase.FAILED
            results['error'] = str(e)

        finally:
            await self._save_state()

        duration = (datetime.now() - start_time).total_seconds()

        return {
            'session_id': self.state.session_id,
            'target': self.target,
            'status': self.state.current_phase.value,
            'duration': duration,
            'phases': results,
            'findings_summary': self._summarize_findings(),
            'attack_paths': [
                {
                    'name': p.name,
                    'description': p.description,
                    'priority': p.priority,
                    'success_probability': p.success_probability
                }
                for p in self.decision_engine.suggest_attack_paths()[:3]
            ]
        }

    async def execute_phase(
        self,
        phase: PentestPhase,
        config: Optional[Dict[str, Any]] = None
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

        executor = executor_class(self.state, phase_config)

        if not executor.can_execute():
            missing = executor.get_missing_requirements()
            return PhaseResult(
                success=False,
                phase=phase,
                data={},
                findings=[],
                errors=[f"缺少前置阶段: {[p.value for p in missing]}"]
            )

        self.state.set_phase(phase, PhaseStatus.RUNNING)

        try:
            if self.state.last_checkpoint and self.state.last_checkpoint.phase == phase:
                result = await executor.resume(self.state.last_checkpoint.data)
            else:
                result = await executor.execute()

            if result.success:
                self.state.complete_phase(phase, result.to_dict())
            else:
                self.state.fail_phase(phase, '; '.join(result.errors))

            analysis = self.decision_engine.analyze_result(phase, result.to_dict())
            result.data['analysis'] = analysis

            return result

        except Exception as e:
            self.logger.exception(f"阶段 {phase.value} 执行异常: {e}")
            self.state.fail_phase(phase, str(e))
            return PhaseResult(
                success=False,
                phase=phase,
                data={},
                findings=[],
                errors=[str(e)]
            )

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
            from core.session.storage import SessionStorage
            from core.session.context import ScanContext

            if self._storage is None:
                self._storage = SessionStorage()

            try:
                # 使用脱敏数据进行持久化
                context_data = self.state.to_safe_dict()
                context = ScanContext(
                    session_id=self.state.session_id,
                    config=context_data.get('config', {}),
                    fingerprints=context_data.get('recon_data', {}).get('fingerprints', {}),
                    technologies=context_data.get('recon_data', {}).get('technologies', []),
                    ports=[],
                    subdomains=list(self.state.discovered_hosts),
                    metadata=context_data
                )
                self._storage.save_context(context)
            except Exception as e:
                self.logger.exception(f"保存状态失败: {e}")

    def _report_progress(self, phase: PentestPhase, status: str) -> None:
        """报告进度 - 使用脱敏数据"""
        self.logger.info(f"[{self.state.session_id[:8]}] {phase.value}: {status}")

        if self._progress_callback:
            try:
                # 使用脱敏数据进行回调，避免敏感信息泄露
                self._progress_callback(phase.value, status, self.state.to_safe_dict())
            except Exception as e:
                self.logger.warning(f"进度回调失败: {e}")

    def _summarize_findings(self) -> Dict[str, Any]:
        """汇总发现"""
        findings = self.state.findings

        summary = {
            'total': len(findings),
            'critical': len([f for f in findings if f.get('severity') == 'critical']),
            'high': len([f for f in findings if f.get('severity') == 'high']),
            'medium': len([f for f in findings if f.get('severity') == 'medium']),
            'low': len([f for f in findings if f.get('severity') == 'low']),
            'info': len([f for f in findings if f.get('severity') == 'info']),
            'verified': len([f for f in findings if f.get('verified')]),
            'by_type': {}
        }

        for finding in findings:
            vuln_type = finding.get('type', 'unknown')
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1

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
                'name': p.name,
                'description': p.description,
                'priority': p.priority,
                'success_probability': p.success_probability,
                'tools': p.tools
            }
            for p in paths
        ]


async def run_pentest(
    target: str,
    quick_mode: bool = False,
    skip_exfiltrate: bool = True
) -> Dict[str, Any]:
    """便捷函数：执行自动化渗透测试"""
    config = OrchestratorConfig(
        quick_mode=quick_mode,
        skip_exfiltrate=skip_exfiltrate
    )
    orchestrator = AutoPentestOrchestrator(target, config)
    return await orchestrator.run()


async def resume_pentest(session_id: str) -> Dict[str, Any]:
    """便捷函数：恢复渗透测试"""
    orchestrator = AutoPentestOrchestrator.resume(session_id)
    return await orchestrator.run()


__all__ = [
    'OrchestratorConfig',
    'AutoPentestOrchestrator',
    'run_pentest',
    'resume_pentest',
]
