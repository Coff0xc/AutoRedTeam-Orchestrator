"""Compare a saved surface inventory with a new static scan.

The comparison reads local JSON and scan findings. It does not connect to a
server or call a tool.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence, Tuple

from core.ai_surface.models import (
    RISK_ORDER,
    SurfaceFinding,
    SurfaceRiskLevel,
    SurfaceScanResult,
    max_risk,
)

InventoryKey = Tuple[str, str]


def diff_surface_inventory(
    baseline: Mapping[str, Any],
    current: SurfaceScanResult,
) -> SurfaceScanResult:
    """Report added, removed, and changed surfaces against a saved scan."""
    result = SurfaceScanResult(
        root_path=current.root_path,
        scanned_files=current.scanned_files,
        warnings=list(current.warnings),
    )
    saved_findings = baseline.get("findings")
    if not isinstance(saved_findings, list):
        result.warnings.append("Saved inventory has no findings list")
        saved_findings = []

    previous = _index(saved_findings)
    seen = _index(finding.to_dict() for finding in current.findings)

    for key, item in seen.items():
        saved = previous.get(key)
        if saved is None:
            result.findings.append(_added(item))
            continue
        changed = _changed(saved, item)
        if changed is not None:
            result.findings.append(changed)

    for key, saved in previous.items():
        if key not in seen:
            result.findings.append(_removed(saved))

    result.findings.sort(key=lambda item: (-RISK_ORDER[item.risk_level], item.file_path, item.line))
    return result


def _index(findings: Sequence[Mapping[str, Any]]) -> Dict[InventoryKey, Mapping[str, Any]]:
    indexed: Dict[InventoryKey, Mapping[str, Any]] = {}
    for item in findings:
        name = str(item.get("tool_name") or "")
        if not name:
            continue
        indexed[(str(item.get("kind") or "tool"), name)] = item
    return indexed


def _added(item: Mapping[str, Any]) -> SurfaceFinding:
    finding = _from_item(item, "Surface added since the saved inventory.")
    finding.issues = ["surface_added"]
    finding.risk_level = max_risk(finding.risk_level, SurfaceRiskLevel.MODERATE)
    return finding


def _removed(item: Mapping[str, Any]) -> SurfaceFinding:
    finding = _from_item(item, "Surface missing from the current inventory.")
    finding.issues = ["surface_removed"]
    finding.risk_level = max_risk(finding.risk_level, SurfaceRiskLevel.MODERATE)
    return finding


def _changed(saved: Mapping[str, Any], item: Mapping[str, Any]) -> SurfaceFinding | None:
    issues: List[str] = []
    notes: List[str] = []
    old_description = str(saved.get("description") or "")
    new_description = str(item.get("description") or "")
    if old_description != new_description:
        issues.append("surface_description_changed")
        notes.append(f"Saved description: {old_description[:200]}")
    old_parameters = _parameters(saved)
    new_parameters = _parameters(item)
    if old_parameters != new_parameters:
        issues.append("surface_parameters_changed")
        notes.append("Saved parameters: " + ", ".join(old_parameters))
    if not issues:
        return None
    finding = _from_item(item, new_description or "Surface changed since the saved inventory.")
    finding.issues = issues
    finding.recommendations = notes
    finding.risk_level = max_risk(finding.risk_level, SurfaceRiskLevel.MODERATE)
    return finding


def _from_item(item: Mapping[str, Any], fallback: str) -> SurfaceFinding:
    description = str(item.get("description") or fallback)
    try:
        risk = SurfaceRiskLevel(str(item.get("risk_level") or "low").lower())
    except ValueError:
        risk = SurfaceRiskLevel.LOW
    return SurfaceFinding(
        tool_name=str(item.get("tool_name") or ""),
        file_path=str(item.get("file_path") or ""),
        line=int(item.get("line") or 1),
        risk_level=risk,
        parameters=_parameters(item),
        description=description,
        finding_type="surface_inventory_diff",
        kind=str(item.get("kind") or "tool"),
        rule_id="surface_inventory_diff",
    )


def _parameters(item: Mapping[str, Any]) -> List[str]:
    raw = item.get("parameters") or []
    if not isinstance(raw, list):
        return []
    return sorted(str(name) for name in raw)
