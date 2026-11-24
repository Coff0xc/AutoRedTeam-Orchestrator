"""Engagement coverage ledger: examined / ruled_out / open surfaces.

The denominator is in-scope phases plus discovered assets and findings.
A run with no open rows still has a total; rate is null when total is 0.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from core.engage.config import EngagementConfig
from core.engage.world import coverage, unverified_index

COVERAGE_SCHEMA = "autort.engage.coverage/v1"
STATUS_OPEN = "open"
STATUS_EXAMINED = "examined"
STATUS_RULED_OUT = "ruled_out"
_TERMINAL = frozenset({"verified", "dry_run"})
_RULED_OUT = frozenset({"contradicted"})


def build_coverage_ledger(config: EngagementConfig, state: Mapping[str, Any]) -> Dict[str, Any]:
    """Build the coverage denominator for ``engage status`` and run output."""
    cov = coverage(state)
    rows: List[Dict[str, Any]] = []
    for phase in config.phases:
        rows.append(_phase_row(str(phase), cov, state, set(config.phases)))
    for asset in _assets(state):
        kind = str(asset.get("kind") or "asset")
        name = str(asset.get("name") or "")
        rows.append(
            {
                "id": "asset:%s:%s" % (kind, name),
                "kind": "asset",
                "name": name,
                "status": STATUS_EXAMINED,
            }
        )
    for finding in _finding_rows(state):
        rows.append(finding)
    examined = sum(1 for row in rows if row["status"] == STATUS_EXAMINED)
    ruled_out = sum(1 for row in rows if row["status"] == STATUS_RULED_OUT)
    open_count = sum(1 for row in rows if row["status"] == STATUS_OPEN)
    total = len(rows)
    closed = examined + ruled_out
    return {
        "schema": COVERAGE_SCHEMA,
        "examined": examined,
        "ruled_out": ruled_out,
        "open": open_count,
        "total": total,
        "coverage_rate": (closed / total) if total else None,
        "rows": rows,
    }


def open_coverage_rows(ledger: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Return coverage rows whose status is open."""
    rows = ledger.get("rows") if isinstance(ledger, Mapping) else None
    if not isinstance(rows, list):
        return []
    return [
        dict(row)
        for row in rows
        if isinstance(row, Mapping) and str(row.get("status") or "") == STATUS_OPEN
    ]


def _phase_row(
    phase: str, cov: Mapping[str, Any], state: Mapping[str, Any], phases: set[str]
) -> Dict[str, Any]:
    status = STATUS_OPEN
    if phase == "recon" and cov.get("recon"):
        status = STATUS_EXAMINED
    elif phase == "detect" and cov.get("detect"):
        status = STATUS_EXAMINED
    elif phase == "nuclei" and cov.get("nuclei"):
        status = STATUS_EXAMINED
    elif phase == "verify":
        pending = unverified_index(state) if "verify" in phases else []
        if cov.get("detect") and not pending:
            status = STATUS_EXAMINED
        elif not cov.get("detect") and "detect" not in phases and not pending:
            status = STATUS_EXAMINED
    elif phase == "export" and cov.get("exported"):
        status = STATUS_EXAMINED
    return {"id": "phase:%s" % phase, "kind": "phase", "name": phase, "status": status}


def _assets(state: Mapping[str, Any]) -> List[Dict[str, str]]:
    world = state.get("world") if isinstance(state.get("world"), Mapping) else {}
    raw = world.get("assets_index")
    if not isinstance(raw, list):
        return []
    rows: List[Dict[str, str]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        kind = str(item.get("kind") or "asset")
        name = str(item.get("name") or "")
        if not name or kind == "target":
            continue
        rows.append({"kind": kind, "name": name})
    return rows


def _finding_rows(state: Mapping[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen = set()
    for item in _all_findings(state):
        key = (
            str(item.get("url") or ""),
            str(item.get("vuln_type") or item.get("type") or ""),
            str(item.get("param") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        name = key[1] or key[0]
        rows.append(
            {
                "id": "finding:%s|%s|%s" % key,
                "kind": "finding",
                "name": name,
                "status": _finding_status(item),
            }
        )
    return rows


def _all_findings(state: Mapping[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    findings = state.get("findings")
    if isinstance(findings, list):
        rows.extend(item for item in findings if isinstance(item, dict))
    world = state.get("world") if isinstance(state.get("world"), Mapping) else {}
    extra = world.get("unverified_index")
    if isinstance(extra, list):
        have = {
            (
                str(item.get("url") or ""),
                str(item.get("vuln_type") or ""),
                str(item.get("param") or ""),
            )
            for item in rows
        }
        for item in extra:
            if not isinstance(item, dict):
                continue
            key = (
                str(item.get("url") or ""),
                str(item.get("vuln_type") or item.get("type") or ""),
                str(item.get("param") or ""),
            )
            if key not in have:
                rows.append(item)
    return rows


def _finding_status(item: Mapping[str, Any]) -> str:
    status = str(item.get("verification_status") or "")
    if status in _RULED_OUT:
        return STATUS_RULED_OUT
    if status in _TERMINAL or item.get("engagement_verified") is True:
        return STATUS_EXAMINED
    return STATUS_OPEN
