"""Thread-safe in-memory runtime run registry.

The registry is intentionally local-process only. It gives embedded MCP
handlers, CLI flows, and local Web/API views a shared read-only surface without
adding persistence or a background service.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from threading import RLock
from typing import Optional

from core.agent_runtime.models import AgentRunState


class RuntimeRunRegistry(Mapping[str, AgentRunState]):
    """Small mapping-compatible store for AgentRunState objects."""

    def __init__(self) -> None:
        self._runs: dict[str, AgentRunState] = {}
        self._lock = RLock()

    def register(self, run_state: AgentRunState) -> AgentRunState:
        """Register or replace a run state by run_id."""
        with self._lock:
            self._runs[run_state.run_id] = run_state
        return run_state

    def get(self, run_id: str, default: Optional[AgentRunState] = None) -> Optional[AgentRunState]:
        """Return a run state by id, or default if it is unknown."""
        with self._lock:
            return self._runs.get(run_id, default)

    def list(self) -> list[AgentRunState]:
        """Return a stable snapshot of all known run states."""
        with self._lock:
            return list(self._runs.values())

    def clear(self) -> None:
        """Clear the local registry. Intended for tests and short-lived CLIs."""
        with self._lock:
            self._runs.clear()

    def values(self) -> list[AgentRunState]:  # type: ignore[override]
        """Return values as a snapshot list for API compatibility."""
        return self.list()

    def __getitem__(self, run_id: str) -> AgentRunState:
        with self._lock:
            return self._runs[run_id]

    def __iter__(self) -> Iterator[str]:
        with self._lock:
            return iter(list(self._runs.keys()))

    def __len__(self) -> int:
        with self._lock:
            return len(self._runs)


GLOBAL_RUNTIME_RUN_REGISTRY = RuntimeRunRegistry()


def register_runtime_run(run_state: AgentRunState) -> AgentRunState:
    """Register a run in the process-local runtime registry."""
    return GLOBAL_RUNTIME_RUN_REGISTRY.register(run_state)


def get_runtime_run(run_id: str) -> Optional[AgentRunState]:
    """Return one registered runtime run by id."""
    return GLOBAL_RUNTIME_RUN_REGISTRY.get(run_id)


def list_runtime_runs() -> list[AgentRunState]:
    """Return all registered runtime runs."""
    return GLOBAL_RUNTIME_RUN_REGISTRY.list()


def clear_runtime_runs() -> None:
    """Clear all registered runtime runs."""
    GLOBAL_RUNTIME_RUN_REGISTRY.clear()
