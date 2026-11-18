"""Orchestrator checkpoint persist/resume against real SessionStorage.

Phase executors are stubbed. No network, live target, or default data/sessions dir.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Tuple

import pytest

from core.orchestrator.orchestrator import AutoPentestOrchestrator, OrchestratorConfig
from core.orchestrator.phases.base import BasePhaseExecutor, PhaseResult
from core.orchestrator.state import PentestPhase, PhaseStatus
from core.session.storage import SessionStorage

_LAB_TARGET = "http://127.0.0.1:9"
_HIGH_RISK = (
    "exploit",
    "privilege_escalation",
    "lateral_movement",
    "exfiltrate",
)
Call = Tuple[str, str]


@pytest.fixture
def isolated_sessions(tmp_path, monkeypatch):
    sessions = tmp_path / "sessions"
    original_init = SessionStorage.__init__

    def _init(self, storage_dir=None):
        original_init(self, storage_dir=sessions)

    monkeypatch.setattr(SessionStorage, "__init__", _init)
    return sessions


def _execute_config() -> OrchestratorConfig:
    return OrchestratorConfig(
        runtime_policy_enabled=False,
        runtime_mode="active",
        skip_exfiltrate=True,
        skip_phases=list(_HIGH_RISK),
    )


def _stub_registry(
    calls: List[Call],
    *,
    fail_once: str | None = None,
) -> Dict[str, Callable[..., BasePhaseExecutor]]:
    failures = {fail_once: 0} if fail_once else {}

    def _factory(bound: PentestPhase) -> Callable[..., BasePhaseExecutor]:
        class Stub(BasePhaseExecutor):
            required_phases: tuple = ()

            @property
            def phase(self) -> PentestPhase:
                return bound

            async def execute(self) -> PhaseResult:
                calls.append(("execute", bound.value))
                if bound.value in failures:
                    failures[bound.value] += 1
                    if failures[bound.value] == 1:
                        raise RuntimeError("injected phase failure")
                findings: List[Dict[str, Any]] = []
                if bound in (PentestPhase.RECON, PentestPhase.VULN_SCAN):
                    findings = [
                        {
                            "type": "sqli",
                            "severity": "high",
                            "url": self.state.target,
                            "param": "id",
                            "cve_id": "CVE-2024-0001",
                        }
                    ]
                    if bound is PentestPhase.RECON:
                        self.state.recon_data = {"ip_addresses": ["127.0.0.1"]}
                self.state.add_checkpoint(step=len(calls), data={"stub": bound.value})
                return PhaseResult(
                    success=True,
                    phase=bound,
                    data={"stub": True},
                    findings=findings,
                    errors=[],
                )

            async def resume(self, checkpoint_data: Dict[str, Any]) -> PhaseResult:
                calls.append(("resume", bound.value))
                return await self.execute()

        Stub.name = bound.value
        Stub.__name__ = f"Stub{bound.name}"
        return Stub

    return {phase.value: _factory(phase) for phase in AutoPentestOrchestrator.PHASE_ORDER}


@pytest.mark.asyncio
async def test_resume_retries_failed_phase_and_skips_completed(isolated_sessions, monkeypatch):
    first_calls: List[Call] = []
    monkeypatch.setattr(
        "core.orchestrator.orchestrator.PHASE_EXECUTORS",
        _stub_registry(first_calls, fail_once="vuln_scan"),
    )

    orch = AutoPentestOrchestrator(_LAB_TARGET, config=_execute_config())
    session_id = orch.state.session_id
    first = await orch.run()

    assert first["status"] == "failed"
    assert [item for item in first_calls if item[0] == "execute"] == [
        ("execute", "recon"),
        ("execute", "vuln_scan"),
    ]
    assert orch.state.is_phase_completed(PentestPhase.RECON)
    assert orch.state.phase_status[PentestPhase.VULN_SCAN.value] == PhaseStatus.FAILED
    saved = isolated_sessions / "contexts" / f"{session_id}.json"
    assert saved.is_file()

    second_calls: List[Call] = []
    monkeypatch.setattr(
        "core.orchestrator.orchestrator.PHASE_EXECUTORS",
        _stub_registry(second_calls),
    )
    resumed = AutoPentestOrchestrator.resume(session_id)
    assert resumed.target == _LAB_TARGET
    assert resumed.state.session_id == session_id
    assert resumed.state.is_phase_completed(PentestPhase.RECON)
    assert resumed.state.findings
    assert resumed.config.runtime_policy_enabled is False
    assert resumed.config.runtime_mode == "active"
    assert resumed._storage.storage_dir == isolated_sessions

    second = await resumed.run()
    executed = [item for item in second_calls if item[0] == "execute"]
    assert ("execute", "recon") not in executed
    assert executed[0] == ("execute", "vuln_scan")
    assert ("execute", "poc_exec") in executed
    assert ("execute", "report") in executed
    assert second["status"] == "completed"
    assert resumed.state.is_phase_completed(PentestPhase.VULN_SCAN)
    assert resumed.state.is_phase_completed(PentestPhase.REPORT)


@pytest.mark.asyncio
async def test_resume_uses_executor_resume_for_in_progress_checkpoint(
    isolated_sessions, monkeypatch
):
    first_calls: List[Call] = []
    monkeypatch.setattr(
        "core.orchestrator.orchestrator.PHASE_EXECUTORS",
        _stub_registry(first_calls),
    )
    orch = AutoPentestOrchestrator(
        _LAB_TARGET,
        config=OrchestratorConfig(
            runtime_policy_enabled=False,
            runtime_mode="active",
            skip_phases=list(_HIGH_RISK) + ["vuln_scan", "poc_exec", "report"],
        ),
    )
    session_id = orch.state.session_id
    await orch.run()
    assert orch.state.is_phase_completed(PentestPhase.RECON)

    orch.state.set_phase(PentestPhase.VULN_SCAN, PhaseStatus.RUNNING)
    orch.state.add_checkpoint(step=2, data={"current_target": _LAB_TARGET})
    await orch._save_state()

    second_calls: List[Call] = []
    monkeypatch.setattr(
        "core.orchestrator.orchestrator.PHASE_EXECUTORS",
        _stub_registry(second_calls),
    )
    resumed = AutoPentestOrchestrator.resume(session_id)
    resumed.config.skip_phases = list(_HIGH_RISK)
    second = await resumed.run()

    assert ("resume", "vuln_scan") in second_calls
    assert ("execute", "recon") not in second_calls
    assert second["status"] == "completed"


@pytest.mark.asyncio
async def test_default_dry_run_skips_executors_and_writes_no_phase_checkpoint(
    isolated_sessions, monkeypatch
):
    calls: List[Call] = []
    monkeypatch.setattr(
        "core.orchestrator.orchestrator.PHASE_EXECUTORS",
        _stub_registry(calls),
    )
    orch = AutoPentestOrchestrator(_LAB_TARGET)
    result = await orch.run()

    assert calls == []
    assert result["status"] == "completed"
    assert all(
        orch.state.phase_status.get(phase.value) == PhaseStatus.SKIPPED
        for phase in AutoPentestOrchestrator.PHASE_ORDER
    )
    assert orch.state.last_checkpoint is None
    saved = isolated_sessions / "contexts" / f"{orch.state.session_id}.json"
    assert saved.is_file()


def test_resume_rejects_unknown_and_malformed_session_ids(isolated_sessions):
    with pytest.raises(ValueError, match="无效的session_id格式"):
        AutoPentestOrchestrator.resume("../evil")
    missing = "a" * 32
    with pytest.raises(ValueError, match="会话不存在"):
        AutoPentestOrchestrator.resume(missing)


def test_orchestrator_config_from_dict_roundtrip():
    original = OrchestratorConfig(
        runtime_policy_enabled=False,
        runtime_mode="active",
        skip_phases=["exploit"],
        quick_mode=True,
    )
    restored = OrchestratorConfig.from_dict(original.to_dict())
    assert restored.runtime_policy_enabled is False
    assert restored.runtime_mode == "active"
    assert restored.skip_phases == ["exploit"]
    assert restored.quick_mode is True
    assert OrchestratorConfig.from_dict(None).runtime_mode == "dry-run"
