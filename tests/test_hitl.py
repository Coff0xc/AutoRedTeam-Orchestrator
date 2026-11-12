"""HITL gate on the MCP tool wrapper."""

from __future__ import annotations

import asyncio

import pytest

from core.security.hitl import (
    HitlDecision,
    HitlMode,
    HitlRequest,
    auth_level_of,
    current_mode,
    gate_tool,
    reset_hitl,
    set_approver,
    timeout_seconds,
)
from core.security.mcp_auth_middleware import require_dangerous_auth, require_safe_auth
from utils.mcp_tooling import _wrap_tool_func

pytestmark = [pytest.mark.unit, pytest.mark.security]


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("AUTORT_HITL_MODE", raising=False)
    monkeypatch.delenv("AUTORT_HITL_TIMEOUT_SECONDS", raising=False)
    reset_hitl()
    yield
    reset_hitl()


def test_default_mode_is_off():
    assert current_mode() is HitlMode.OFF


def test_unknown_mode_fails_closed_to_approval(monkeypatch):
    monkeypatch.setenv("AUTORT_HITL_MODE", "open-sesame")
    assert current_mode() is HitlMode.APPROVAL


def test_auth_level_is_marked_on_dangerous_wrapper():
    @require_dangerous_auth
    async def exploit_lab(target: str):
        return {"success": True, "target": target}

    assert auth_level_of(exploit_lab) == "dangerous"


@pytest.mark.asyncio
async def test_off_mode_runs_the_body():
    ran = []

    @require_dangerous_auth
    async def exploit_lab(target: str):
        ran.append(target)
        return {"success": True, "target": target}

    wrapped = _wrap_tool_func(exploit_lab)
    result = await wrapped(target="http://lab.example")

    assert ran == ["http://lab.example"]
    assert result["success"] is True


@pytest.mark.asyncio
async def test_approval_deny_does_not_run_body(monkeypatch, tmp_path):
    import utils.mcp_tooling as tooling

    monkeypatch.setenv("AUTORT_HITL_MODE", "approval")
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(tooling, "_AUDIT_LOG_PATH", log_path)
    monkeypatch.setattr(tooling, "_AUDIT_ENABLED", True)
    monkeypatch.setattr(tooling, "_audit_dir_ensured", False)
    ran = []

    @require_dangerous_auth
    async def exploit_lab(target: str):
        ran.append(target)
        return {"success": True, "target": target}

    wrapped = tooling._wrap_tool_func(exploit_lab)
    result = await wrapped(target="http://lab.example")

    assert ran == []
    assert result["success"] is False
    assert result["data"]["code"] == "approval_required"
    log = log_path.read_text(encoding="utf-8")
    assert "approval_required" in log
    assert '"hitl"' in log


@pytest.mark.asyncio
async def test_injected_allow_runs_body(monkeypatch):
    monkeypatch.setenv("AUTORT_HITL_MODE", "approval")

    async def allow(request: HitlRequest) -> HitlDecision:
        assert request.tool_name == "exploit_lab"
        assert request.auth_level == "dangerous"
        return HitlDecision(allowed=True, reason="approved")

    set_approver(allow)
    ran = []

    @require_dangerous_auth
    async def exploit_lab(target: str):
        ran.append(target)
        return {"success": True, "target": target}

    wrapped = _wrap_tool_func(exploit_lab)
    result = await wrapped(target="http://lab.example")

    assert ran == ["http://lab.example"]
    assert result["success"] is True


@pytest.mark.asyncio
async def test_review_edit_rewrites_kwargs(monkeypatch):
    monkeypatch.setenv("AUTORT_HITL_MODE", "review_edit")

    async def edit(request: HitlRequest) -> HitlDecision:
        return HitlDecision(
            allowed=True,
            reason="edited",
            edited_kwargs={"target": "http://allowed.example"},
        )

    set_approver(edit)
    ran = []

    @require_dangerous_auth
    async def exploit_lab(target: str):
        ran.append(target)
        return {"success": True, "target": target}

    wrapped = _wrap_tool_func(exploit_lab)
    result = await wrapped(target="http://blocked.example")

    assert ran == ["http://allowed.example"]
    assert result["data"]["target"] == "http://allowed.example"


@pytest.mark.asyncio
async def test_timeout_denies_without_running_body(monkeypatch):
    monkeypatch.setenv("AUTORT_HITL_MODE", "approval")
    monkeypatch.setenv("AUTORT_HITL_TIMEOUT_SECONDS", "0.01")

    async def slow(request: HitlRequest) -> HitlDecision:
        await asyncio.sleep(1)
        return HitlDecision(allowed=True, reason="too-late")

    set_approver(slow)
    ran = []

    @require_dangerous_auth
    async def exploit_lab(target: str):
        ran.append(target)
        return {"success": True}

    wrapped = _wrap_tool_func(exploit_lab)
    result = await wrapped(target="http://lab.example")

    assert ran == []
    assert result["data"]["code"] == "approval_timeout"


@pytest.mark.asyncio
async def test_safe_tool_skips_hitl_in_approval_mode(monkeypatch):
    monkeypatch.setenv("AUTORT_HITL_MODE", "approval")
    ran = []

    @require_safe_auth
    async def health_check():
        ran.append("ok")
        return {"success": True, "status": "healthy"}

    wrapped = _wrap_tool_func(health_check)
    result = await wrapped()

    assert ran == ["ok"]
    assert result["success"] is True


@pytest.mark.asyncio
async def test_zero_timeout_denies_immediately(monkeypatch):
    monkeypatch.setenv("AUTORT_HITL_MODE", "approval")
    monkeypatch.setenv("AUTORT_HITL_TIMEOUT_SECONDS", "0")
    called = []

    async def should_not_run(request: HitlRequest) -> HitlDecision:
        called.append(request.tool_name)
        return HitlDecision(allowed=True, reason="should-not")

    set_approver(should_not_run)
    decision = await gate_tool("exploit_lab", {"target": "x"}, "dangerous")

    assert called == []
    assert decision.allowed is False
    assert timeout_seconds() == 0.0


def test_sync_wrapper_denies_when_hitl_required(monkeypatch):
    monkeypatch.setenv("AUTORT_HITL_MODE", "approval")
    ran = []

    @require_dangerous_auth
    def exploit_lab(target: str):
        ran.append(target)
        return {"success": True}

    wrapped = _wrap_tool_func(exploit_lab)
    result = wrapped(target="http://lab.example")

    assert ran == []
    assert result["success"] is False
    assert result["data"]["code"] == "approval_required"
