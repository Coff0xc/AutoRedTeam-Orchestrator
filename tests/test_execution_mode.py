"""Tests for the built-in execution-mode gate (core.security.execution_mode)
and its intrinsic enforcement on core offensive engines (lateral movement)."""

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.security]

from core.security.execution_mode import (
    ExecutionBlocked,
    ExecutionMode,
    active_execution,
    current_mode,
    evaluate,
    is_active,
    require_active,
)


class TestExecutionModeGate:
    """The gate defaults to PLAN and only permits real execution when explicitly
    entered and asserted isolated + authorized."""

    def test_default_is_plan(self):
        assert current_mode() is ExecutionMode.PLAN
        assert is_active() is False

    def test_plan_blocks(self):
        decision = evaluate("test.op")
        assert decision.allowed is False
        assert decision.mode is ExecutionMode.PLAN

    def test_require_active_raises_in_plan(self):
        with pytest.raises(ExecutionBlocked):
            require_active("test.op")

    def test_active_still_requires_isolation_and_authorization(self):
        with active_execution():  # active, but neither isolated nor authorized
            assert is_active() is True
            assert evaluate("test.op").allowed is False

    def test_active_isolated_authorized_allows(self):
        with active_execution(isolated=True, authorized=True):
            decision = evaluate("test.op")
            assert decision.allowed is True
            require_active("test.op")  # must not raise

    def test_low_risk_op_can_waive_requirements(self):
        with active_execution():
            decision = evaluate("test.op", require_isolation=False, require_authorization=False)
            assert decision.allowed is True

    def test_context_restores_plan(self):
        with active_execution(isolated=True, authorized=True):
            assert is_active() is True
        assert current_mode() is ExecutionMode.PLAN


class TestLateralExecutionGate:
    """The safety boundary is intrinsic to the engine: a lateral subclass does not
    contact the target in PLAN mode, without the subclass changing anything."""

    def _make_module(self):
        from core.lateral.base import BaseLateralModule, Credentials, ExecutionResult

        class _FakeLateral(BaseLateralModule):
            name = "fake"

            def connect(self):
                return True

            def disconnect(self):
                return None

            def execute(self, command, timeout=None):
                return ExecutionResult(success=True, output="ran: " + command)

        return _FakeLateral("10.0.0.1", Credentials(username="u", password="p"))

    def test_execute_blocked_in_plan(self):
        module = self._make_module()
        result = module.execute("whoami")
        assert result.success is False
        assert result.method == "blocked"

    def test_connect_blocked_in_plan(self):
        module = self._make_module()
        assert module.connect() is False

    def test_execute_runs_in_authorized_active(self):
        module = self._make_module()
        with active_execution(isolated=True, authorized=True):
            result = module.execute("whoami")
        assert result.success is True
        assert "ran: whoami" in result.output

    def test_execute_still_blocked_when_active_but_unisolated(self):
        module = self._make_module()
        with active_execution():  # active but not isolated/authorized
            result = module.execute("whoami")
        assert result.success is False
        assert result.method == "blocked"
