"""Sandbox policy models for agent runtime planning.

This module intentionally does not start containers or execute commands. It
captures the policy an executor must satisfy before active work is allowed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from core.agent_runtime.models import Action, ActionKind, ActionPolicy, RunMode
from core.sandbox.config import CommandResult, SandboxConfig


@dataclass
class SandboxPolicy:
    """Execution isolation policy for a planned action."""

    enabled: bool = False
    provider: str = "none"
    network_policy: str = "deny"
    allowed_tools: List[str] = field(default_factory=list)
    artifact_policy: str = "metadata-only"
    timeout_seconds: int = 300
    metadata: Dict[str, Any] = field(default_factory=dict)

    def allows_network(self) -> bool:
        return self.network_policy not in {"deny", "none", "disabled"}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "network_policy": self.network_policy,
            "allowed_tools": self.allowed_tools,
            "artifact_policy": self.artifact_policy,
            "timeout_seconds": self.timeout_seconds,
            "metadata": self.metadata,
        }


@dataclass
class SandboxDecision:
    """Result of checking one action against sandbox policy."""

    allowed: bool
    reason: str = ""
    required_provider: str = "none"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "required_provider": self.required_provider,
            "metadata": self.metadata,
        }


def enforce_sandbox_policy(
    action: Action,
    policy: SandboxPolicy,
    mode: RunMode | str = RunMode.DRY_RUN,
) -> SandboxDecision:
    """Validate that an action satisfies sandbox constraints.

    This is a policy check only. It never starts a container, command, browser, or
    network connection.
    """
    if isinstance(mode, str):
        mode = RunMode(mode)
    if mode == RunMode.ACTIVE and not policy.enabled:
        return SandboxDecision(
            allowed=False,
            reason="Active action requires an enabled sandbox policy",
            required_provider=policy.provider,
        )
    if action.policy.network_policy != "deny" and not policy.allows_network():
        return SandboxDecision(
            allowed=False,
            reason="Action requests network but sandbox network policy denies it",
            required_provider=policy.provider,
        )
    if policy.allowed_tools and action.name not in policy.allowed_tools:
        return SandboxDecision(
            allowed=False,
            reason="Action is not in sandbox allowed_tools",
            required_provider=policy.provider,
            metadata={"allowed_tools": policy.allowed_tools},
        )
    if action.policy.artifact_policy != "metadata-only" and policy.artifact_policy == "metadata-only":
        return SandboxDecision(
            allowed=False,
            reason="Action artifact policy exceeds sandbox artifact policy",
            required_provider=policy.provider,
        )
    return SandboxDecision(
        allowed=True,
        required_provider=policy.provider,
        metadata={"mode": mode.value, "network_policy": policy.network_policy},
    )


def execute_action_in_docker_sandbox(
    action: Action,
    policy: SandboxPolicy,
    command: str,
    allow_execute: bool = False,
    config: SandboxConfig | None = None,
) -> CommandResult:
    """Execute a command through DockerExecutor only after explicit approval.

    This function is intentionally opt-in. Passing ``allow_execute=False`` keeps
    it in policy-only mode and returns a blocked CommandResult.
    """
    decision = enforce_sandbox_policy(action, policy, mode=RunMode.ACTIVE)
    if not allow_execute:
        return CommandResult(
            stdout="",
            stderr="sandbox execution requires allow_execute=True",
            exit_code=-1,
            duration=0.0,
        )
    if not decision.allowed:
        return CommandResult(
            stdout="",
            stderr=decision.reason,
            exit_code=-1,
            duration=0.0,
        )
    if policy.provider not in {"docker", "container"}:
        return CommandResult(
            stdout="",
            stderr=f"unsupported sandbox provider: {policy.provider}",
            exit_code=-1,
            duration=0.0,
        )

    from core.sandbox.executor import DockerExecutor

    sandbox_config = config or SandboxConfig(
        enabled=True,
        network_mode=("none" if policy.network_policy == "deny" else "bridge"),
        timeout=policy.timeout_seconds,
    )
    return DockerExecutor(sandbox_config).run_command(command, timeout=policy.timeout_seconds)


def smoke_docker_sandbox(
    image: str = "python:3.12-slim",
    timeout_seconds: int = 30,
) -> Dict[str, Any]:
    """Run a local Docker sandbox smoke test when Docker is available.

    The smoke action uses network_mode=none and does not contact external
    targets. If Docker SDK or daemon is unavailable, the result is an explicit
    environment skip instead of an ambiguous failure.
    """
    marker = "autort-docker-sandbox-smoke"
    action = Action(
        name="docker_sandbox_smoke",
        kind=ActionKind.SHELL,
        policy=ActionPolicy(
            risk_level="low",
            network_policy="deny",
            artifact_policy="metadata-only",
        ),
    )
    policy = SandboxPolicy(
        enabled=True,
        provider="docker",
        network_policy="deny",
        timeout_seconds=timeout_seconds,
    )
    config = SandboxConfig(
        enabled=True,
        image=image,
        network_mode="none",
        timeout=timeout_seconds,
    )
    command = f"python3 -c \"print('{marker}')\""
    try:
        result = execute_action_in_docker_sandbox(
            action,
            policy,
            command=command,
            allow_execute=True,
            config=config,
        )
    except RuntimeError as exc:
        return {
            "success": False,
            "skipped": True,
            "reason": "docker_unavailable",
            "error": str(exc),
            "image": image,
            "network_mode": config.network_mode,
        }

    stdout = result.stdout.strip()
    return {
        "success": result.exit_code == 0 and marker in stdout,
        "skipped": False,
        "exit_code": result.exit_code,
        "stdout": stdout,
        "stderr": result.stderr.strip(),
        "duration": result.duration,
        "image": image,
        "network_mode": config.network_mode,
    }
