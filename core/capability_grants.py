"""In-process catalog-enable grant ledger for MCP02 scope creep.

``tool_enable`` records catalog unlocks. Resident surfaces do not consume the
budget. ``AUTORT_GRANT_BUDGET`` caps new catalog enables. ``AUTORT_GRANT_LOG``
persists ``autort.capability.grants/v1``. Third-party MCP sessions are unread.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

GRANT_SCHEMA = "autort.capability.grants/v1"
GRANT_LOG_ENV = "AUTORT_GRANT_LOG"
GRANT_BUDGET_ENV = "AUTORT_GRANT_BUDGET"


class GrantLedgerError(ValueError):
    """Raised when the grant log or budget cannot be applied."""


class GrantBudgetExceeded(GrantLedgerError):
    """Raised when a catalog enable would exceed AUTORT_GRANT_BUDGET."""

    def __init__(self, *, budget: int, count: int, name: str) -> None:
        self.budget = budget
        self.count = count
        self.name = name
        super().__init__(
            f"{name} would exceed {GRANT_BUDGET_ENV}={budget} " f"(already {count} catalog grants)"
        )


def empty_grant_document() -> dict[str, Any]:
    """Return an empty grant ledger document."""
    return {"schema": GRANT_SCHEMA, "count": 0, "grants": []}


def grant_snapshot(grants: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Return a compact ledger document for the current grant list."""
    items = [dict(item) for item in grants]
    return {"schema": GRANT_SCHEMA, "count": len(items), "grants": items}


def grant_budget(environ: Optional[Mapping[str, str]] = None) -> Optional[int]:
    """Return the catalog-enable budget, or None when unset (unlimited)."""
    env = os.environ if environ is None else environ
    raw = str(env.get(GRANT_BUDGET_ENV) or "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise GrantLedgerError(f"{GRANT_BUDGET_ENV} must be an integer >= 0") from exc
    if value < 0:
        raise GrantLedgerError(f"{GRANT_BUDGET_ENV} must be an integer >= 0")
    return value


def grant_log_path(environ: Optional[Mapping[str, str]] = None) -> Optional[Path]:
    """Return the grant log path from AUTORT_GRANT_LOG, or None."""
    env = os.environ if environ is None else environ
    raw = str(env.get(GRANT_LOG_ENV) or "").strip()
    if not raw:
        return None
    return Path(raw)


def load_grants(path: Path) -> list[dict[str, Any]]:
    """Load grant rows from a ledger file. Missing files are an empty list."""
    if not path.is_file():
        return []
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GrantLedgerError(f"{path} is not readable {GRANT_SCHEMA}") from exc
    if not isinstance(loaded, dict) or loaded.get("schema") != GRANT_SCHEMA:
        raise GrantLedgerError(f"{path} is not {GRANT_SCHEMA}")
    items = loaded.get("grants")
    if not isinstance(items, list):
        raise GrantLedgerError(f"{path} grants must be a list")
    rows: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            raise GrantLedgerError(f"{path} has an invalid grant row")
        kind = str(item.get("kind") or "").strip()
        name = str(item.get("name") or "").strip()
        if not kind or not name:
            raise GrantLedgerError(f"{path} has an invalid grant row")
        rows.append(
            {
                "kind": kind,
                "name": name,
                "profile": str(item.get("profile") or ""),
                "risk": str(item.get("risk") or ""),
                "minimum_profile": str(item.get("minimum_profile") or ""),
                "source": str(item.get("source") or "tool_enable"),
            }
        )
    return rows


def persist_grants(path: Path, grants: Sequence[Mapping[str, Any]]) -> None:
    """Write the grant ledger to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(grant_snapshot(grants), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def bind_grant_store(
    mcp: Any, *, environ: Optional[Mapping[str, str]] = None
) -> list[dict[str, Any]]:
    """Return the in-process grant list, loading AUTORT_GRANT_LOG once."""
    grants = getattr(mcp, "_autort_grants", None)
    if isinstance(grants, list):
        return grants
    path = grant_log_path(environ)
    loaded = load_grants(path) if path is not None else []
    setattr(mcp, "_autort_grants", loaded)
    return loaded


def record_catalog_grant(
    grants: list[dict[str, Any]],
    capability: Any,
    profile: str,
    *,
    log_path: Optional[Path] = None,
) -> tuple[dict[str, Any], bool]:
    """Append a catalog grant. Existing (kind, name) rows are replayed."""
    key = (str(capability.kind), str(capability.name))
    for item in grants:
        if (item.get("kind"), item.get("name")) == key:
            return dict(item), False
    record = {
        "kind": str(capability.kind),
        "name": str(capability.name),
        "profile": str(profile),
        "risk": str(getattr(capability, "risk", "") or ""),
        "minimum_profile": str(getattr(capability, "minimum_profile", "") or ""),
        "source": "tool_enable",
    }
    grants.append(record)
    if log_path is not None:
        persist_grants(log_path, grants)
    return dict(record), True
