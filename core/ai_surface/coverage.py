"""Reconcile a static surface scan with the capability manifest.

The manifest is the registration source of truth. The scanner only sees source
patterns. This module reports which manifest surfaces were observed, which were
accounted for via the detector factory, and which remain invisible.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence, Tuple

from core.ai_surface.models import SurfaceFinding, SurfaceScanResult

SurfaceKey = Tuple[str, str]


def reconcile_capability_manifest(
    result: SurfaceScanResult,
    capabilities: Sequence[Any],
) -> Dict[str, Any]:
    """Compare scan findings to manifest entries and store the report on ``result``."""
    observed: Dict[SurfaceKey, SurfaceFinding] = {}
    for finding in result.findings:
        observed.setdefault((finding.kind, finding.tool_name), finding)

    matched: List[Dict[str, str]] = []
    factory_accounted: List[Dict[str, str]] = []
    invisible: List[Dict[str, str]] = []
    for capability in capabilities:
        key = (str(capability.kind), str(capability.name))
        finding = observed.get(key)
        record = {
            "kind": key[0],
            "name": key[1],
            "handler": str(capability.handler),
        }
        if finding is None:
            record["reason"] = _invisible_reason(capability)
            invisible.append(record)
            continue
        record["finding_type"] = finding.finding_type
        record["file_path"] = finding.file_path
        matched.append(record)
        if finding.finding_type == "mcp_tool_factory":
            factory_accounted.append(record)

    unlisted = [
        {
            "kind": finding.kind,
            "name": finding.tool_name,
            "finding_type": finding.finding_type,
            "file_path": finding.file_path,
            "line": finding.line,
        }
        for key, finding in observed.items()
        if key not in {(str(item.kind), str(item.name)) for item in capabilities}
    ]
    unlisted.sort(key=lambda item: (item["file_path"], item["line"], item["name"]))

    manifest_total = len(tuple(capabilities))
    accounted = len(matched)
    coverage = {
        "manifest_total": manifest_total,
        "accounted": accounted,
        "ratio": f"{accounted}/{manifest_total}",
        "statically_observed": accounted - len(factory_accounted),
        "factory_accounted": len(factory_accounted),
        "invisible_count": len(invisible),
        "invisible": invisible,
        "invisible_by_reason": _count_by(invisible, "reason"),
        "unlisted_count": len(unlisted),
        "unlisted": unlisted,
    }
    result.coverage = coverage
    return coverage


def _invisible_reason(capability: Any) -> str:
    handler = str(getattr(capability, "handler", ""))
    kind = str(getattr(capability, "kind", ""))
    if handler == "detector":
        return "factory-generated"
    if kind == "prompt":
        return "prompt"
    if kind == "resource":
        return "resource"
    return "unseen"


def _count_by(rows: Iterable[Dict[str, str]], key: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for row in rows:
        label = row.get(key, "")
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))
