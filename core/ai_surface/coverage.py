"""Reconcile a static surface scan with the capability manifest.

The manifest is the registration source of truth. The scanner only sees source
patterns. This module reports which manifest surfaces were observed, which were
accounted for via the detector factory, and which remain invisible. It also
flags target-shaped parameters whose declared effects stay local or dry-run.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence, Tuple

from core.ai_surface.models import SurfaceFinding, SurfaceRiskLevel, SurfaceScanResult, max_risk

SurfaceKey = Tuple[str, str]

# Effects that claim no target contact. A URL/host/target parameter with only
# these labels is a schema/effect mismatch.
LOCAL_ONLY_EFFECTS = frozenset(
    {
        "caller-selected-local-read",
        "controlled-artifact-write",
        "dry-run",
        "finding-data",
        "local-read",
        "local-write",
        "metadata-read",
    }
)
EFFECT_PARAMETER_MISMATCH = "declared_effects_omit_target_contact"


def reconcile_capability_manifest(
    result: SurfaceScanResult,
    capabilities: Sequence[Any],
) -> Dict[str, Any]:
    """Compare scan findings to manifest entries and store the report on ``result``."""
    catalog = tuple(capabilities)
    observed: Dict[SurfaceKey, SurfaceFinding] = {}
    for finding in result.findings:
        observed.setdefault((finding.kind, finding.tool_name), finding)

    matched: List[Dict[str, str]] = []
    factory_accounted: List[Dict[str, str]] = []
    invisible: List[Dict[str, str]] = []
    manifest_keys = {(str(item.kind), str(item.name)) for item in catalog}
    for capability in catalog:
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
        if key not in manifest_keys
    ]
    unlisted.sort(key=lambda item: (item["file_path"], item["line"], item["name"]))

    manifest_total = len(catalog)
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
    apply_effect_parameter_mismatches(result, catalog)
    return coverage


def apply_effect_parameter_mismatches(
    result: SurfaceScanResult,
    capabilities: Sequence[Any],
) -> None:
    """Flag local/dry-run effects that still accept url/host/target parameters.

    Joins scan findings to manifest rows on ``(kind, name)``. Parameter names
    come from the AST scan; effects come from the capability row. Unlisted
    findings and empty effect tuples are skipped. Mutates ``result.findings``.
    """
    from core.ai_surface.scanner import TARGET_PARAMS, _surface_rule_id

    catalog = {(str(item.kind), str(item.name)): item for item in capabilities}
    for finding in result.findings:
        capability = catalog.get((finding.kind, finding.tool_name))
        if capability is None:
            continue
        effects = tuple(str(item) for item in (getattr(capability, "effects", ()) or ()) if item)
        if not effects or set(effects) - LOCAL_ONLY_EFFECTS:
            continue
        target_params = [name for name in finding.parameters if name.lower() in TARGET_PARAMS]
        if not target_params:
            continue
        if EFFECT_PARAMETER_MISMATCH not in finding.issues:
            finding.issues.append(EFFECT_PARAMETER_MISMATCH)
        recommendation = (
            "Declared effects ("
            + ", ".join(effects)
            + ") do not include target contact, but parameters include: "
            + ", ".join(target_params)
            + "."
        )
        if recommendation not in finding.recommendations:
            finding.recommendations.append(recommendation)
        finding.risk_level = max_risk(finding.risk_level, SurfaceRiskLevel.MODERATE)
        finding.rule_id = _surface_rule_id(finding)


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
