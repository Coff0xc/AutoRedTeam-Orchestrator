"""Built-in execution-mode gate for core offensive engines.

Offensive engines (lateral movement, persistence, exfiltration, privilege
escalation, C2, ...) must call :func:`require_active` — or check
:func:`evaluate` — before any step that would cause a real side effect on a
host, target, or network.

The default mode is ``PLAN``: a direct call that bypasses the orchestrator still
does not execute. ``ACTIVE`` must be enabled explicitly, and high-risk
operations additionally require the caller to assert an isolated, authorized
context. This makes the safety boundary an intrinsic property of the engines
rather than a governance layer that can be bypassed.

Enabling active execution:

* ``AUTORT_EXECUTION_MODE=active`` (process-wide opt-in), plus
  ``AUTORT_EXECUTION_ISOLATED=1`` / ``AUTORT_EXECUTION_AUTHORIZED=1`` when the
  operation requires them; or
* the :func:`active_execution` context manager for a scoped, auditable window.

The gate never executes anything itself; it only decides and records.
"""

from __future__ import annotations

import contextvars
import logging
import os
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Iterator

logger = logging.getLogger(__name__)

MODE_ENV = "AUTORT_EXECUTION_MODE"
ISOLATION_ENV = "AUTORT_EXECUTION_ISOLATED"
AUTHORIZATION_ENV = "AUTORT_EXECUTION_AUTHORIZED"

_TRUE = {"1", "true", "yes", "on"}


class ExecutionMode(Enum):
    """Whether real side effects are permitted."""

    PLAN = "plan"
    ACTIVE = "active"


class ExecutionBlocked(RuntimeError):
    """Raised when a real side effect is attempted outside an authorized active context."""


@dataclass(frozen=True)
class ExecutionState:
    mode: ExecutionMode = ExecutionMode.PLAN
    isolated: bool = False
    authorized: bool = False


@dataclass(frozen=True)
class ExecutionDecision:
    allowed: bool
    mode: ExecutionMode
    reason: str = ""

    def to_dict(self) -> dict:
        return {"allowed": self.allowed, "mode": self.mode.value, "reason": self.reason}


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in _TRUE


def _initial_state() -> ExecutionState:
    active = os.getenv(MODE_ENV, "").strip().lower() == "active"
    return ExecutionState(
        mode=ExecutionMode.ACTIVE if active else ExecutionMode.PLAN,
        isolated=_env_flag(ISOLATION_ENV),
        authorized=_env_flag(AUTHORIZATION_ENV),
    )


_state_var: contextvars.ContextVar[ExecutionState] = contextvars.ContextVar(
    "autort_execution_state"
)


def _get_state() -> ExecutionState:
    try:
        return _state_var.get()
    except LookupError:
        state = _initial_state()
        _state_var.set(state)
        return state


def current_mode() -> ExecutionMode:
    return _get_state().mode


def is_active() -> bool:
    return _get_state().mode is ExecutionMode.ACTIVE


@contextmanager
def active_execution(*, isolated: bool = False, authorized: bool = False) -> Iterator[None]:
    """Explicitly enter ACTIVE mode for a scope (an authorized, isolated lab run)."""
    token = _state_var.set(
        ExecutionState(mode=ExecutionMode.ACTIVE, isolated=isolated, authorized=authorized)
    )
    try:
        yield
    finally:
        _state_var.reset(token)


def evaluate(
    operation: str,
    *,
    require_isolation: bool = True,
    require_authorization: bool = True,
) -> ExecutionDecision:
    """Decide whether a real side-effect operation may proceed. Executes nothing."""
    state = _get_state()
    if state.mode is not ExecutionMode.ACTIVE:
        return ExecutionDecision(
            False, state.mode, f"{operation}: plan mode — real execution disabled by default"
        )
    if require_isolation and not state.isolated:
        return ExecutionDecision(
            False, state.mode, f"{operation}: active but caller did not assert an isolated context"
        )
    if require_authorization and not state.authorized:
        return ExecutionDecision(
            False, state.mode, f"{operation}: active but caller did not assert authorization"
        )
    return ExecutionDecision(True, state.mode, f"{operation}: active, isolated, authorized")


def require_active(
    operation: str,
    *,
    require_isolation: bool = True,
    require_authorization: bool = True,
) -> None:
    """Gate a real side effect. Raises :class:`ExecutionBlocked` unless authorized-active."""
    decision = evaluate(
        operation,
        require_isolation=require_isolation,
        require_authorization=require_authorization,
    )
    if not decision.allowed:
        logger.warning("execution blocked — %s", decision.reason)
        raise ExecutionBlocked(decision.reason)
    logger.info("execution permitted — %s", decision.reason)
