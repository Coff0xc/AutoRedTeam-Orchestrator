"""Human-in-the-loop gate for MCP tool wrappers.

Modes (``AUTORT_HITL_MODE``):

- ``off``: no extra gate (default)
- ``approval``: moderate/dangerous/critical tools need an independent approver
- ``review_edit``: same, and the approver may rewrite kwargs

The default approver denies immediately. The gate awaits the approver with
``asyncio.wait_for`` and never blocks the event loop; a timeout or missing
approver is deny. A same-process env flag is not independent approval.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional

logger = logging.getLogger(__name__)

HITL_MODE_ENV = "AUTORT_HITL_MODE"
HITL_TIMEOUT_ENV = "AUTORT_HITL_TIMEOUT_SECONDS"
DEFAULT_MODE = "off"
DEFAULT_TIMEOUT = 5.0

_AUTH_RANK = {
    "none": 0,
    "safe": 1,
    "moderate": 2,
    "dangerous": 3,
    "critical": 4,
}


class HitlMode(Enum):
    """Whether the wrapper asks an independent approver before the tool body."""

    OFF = "off"
    APPROVAL = "approval"
    REVIEW_EDIT = "review_edit"


@dataclass(frozen=True)
class HitlRequest:
    """One tool call waiting on an approver."""

    tool_name: str
    auth_level: str
    mode: HitlMode
    params: Mapping[str, Any]


@dataclass(frozen=True)
class HitlDecision:
    """Approver result. Default deny."""

    allowed: bool
    reason: str = "approval_required"
    edited_kwargs: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"allowed": self.allowed, "reason": self.reason}
        if self.edited_kwargs is not None:
            payload["edited"] = True
        return payload


HitlApprover = Callable[[HitlRequest], Awaitable[HitlDecision]]

_approver: Optional[HitlApprover] = None


def reset_hitl() -> None:
    """Drop a test-injected approver. Mode still comes from the environment."""
    global _approver
    _approver = None


def set_approver(approver: Optional[HitlApprover]) -> None:
    """Install an independent approver. ``None`` restores default deny."""
    global _approver
    _approver = approver


def current_mode() -> HitlMode:
    raw = os.environ.get(HITL_MODE_ENV, DEFAULT_MODE).strip().lower().replace("-", "_")
    for mode in HitlMode:
        if raw == mode.value:
            return mode
    logger.warning("Unknown %s=%r; failing closed to approval", HITL_MODE_ENV, raw)
    return HitlMode.APPROVAL


def timeout_seconds() -> float:
    raw = os.environ.get(HITL_TIMEOUT_ENV, str(DEFAULT_TIMEOUT)).strip()
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT
    return value if value >= 0 else DEFAULT_TIMEOUT


def auth_level_of(func: Any) -> str:
    """Highest ``__autort_auth_level__`` on the wrapper chain."""
    best = "none"
    current = func
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        level = str(getattr(current, "__autort_auth_level__", "") or "").lower()
        if _AUTH_RANK.get(level, 0) > _AUTH_RANK[best]:
            best = level
        current = getattr(current, "__wrapped__", None)
    return best


def requires_hitl(mode: HitlMode, auth_level: str) -> bool:
    if mode is HitlMode.OFF:
        return False
    return _AUTH_RANK.get(auth_level, 0) >= _AUTH_RANK["moderate"]


async def _default_deny(_request: HitlRequest) -> HitlDecision:
    return HitlDecision(allowed=False, reason="approval_required")


async def gate_tool(
    tool_name: str,
    params: Mapping[str, Any],
    auth_level: str,
) -> HitlDecision:
    """Decide whether the tool body may run. Timeout and errors deny."""
    mode = current_mode()
    if not requires_hitl(mode, auth_level):
        reason = "hitl_off" if mode is HitlMode.OFF else "below_threshold"
        return HitlDecision(allowed=True, reason=reason)
    timeout = timeout_seconds()
    request = HitlRequest(
        tool_name=tool_name,
        auth_level=auth_level,
        mode=mode,
        params=params,
    )
    if timeout == 0:
        return HitlDecision(allowed=False, reason="approval_required")
    approver = _approver or _default_deny
    try:
        decision = await asyncio.wait_for(approver(request), timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("HITL timed out for %s; denying", tool_name)
        return HitlDecision(allowed=False, reason="approval_timeout")
    except Exception:
        logger.exception("HITL approver failed for %s; denying", tool_name)
        return HitlDecision(allowed=False, reason="approval_required")
    if not isinstance(decision, HitlDecision):
        return HitlDecision(allowed=False, reason="approval_required")
    if mode is not HitlMode.REVIEW_EDIT or not decision.allowed:
        return HitlDecision(allowed=decision.allowed, reason=decision.reason)
    edited = decision.edited_kwargs
    if edited is not None and not isinstance(edited, dict):
        return HitlDecision(allowed=False, reason="approval_required")
    return HitlDecision(allowed=True, reason=decision.reason, edited_kwargs=edited)


def denial_payload(decision: HitlDecision) -> Dict[str, Any]:
    """Structured refusal the tool wrapper returns without running the body."""
    return {
        "success": False,
        "error": "Human approval required before this tool can run.",
        "code": decision.reason or "approval_required",
    }
