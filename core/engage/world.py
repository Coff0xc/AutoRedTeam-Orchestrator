"""Engagement world model: SQLite asset/fact/finding graph plus a compact index.

Planner reads the index (counts, coverage flags, unverified finding keys).
Scan JSON stays out of the graph. Persistence uses ``SQLiteKnowledgeStore``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.knowledge.storage import SQLiteKnowledgeStore

WORLD_SCHEMA = "autort.engage.world/v1"
WORLD_FILENAME = "world.sqlite"

_CONFIRMED = "confirmed"
_TENTATIVE = "tentative"


def world_file(output_dir: str | Path) -> Path:
    return Path(output_dir) / WORLD_FILENAME


def ingest_step(
    state: Dict[str, Any],
    name: str,
    payload: Mapping[str, Any],
    *,
    inputs: Mapping[str, Any],
) -> Dict[str, Any]:
    """Write this step into the graph (when a dir exists) and refresh ``state['world']``."""
    target = _target_of(state, inputs, payload)
    flags = _merged_flags(state, name)
    findings = _compact_findings(state)
    output_dir = inputs.get("output_dir") or state.get("output_dir")
    ports = _ports_from_payload(payload) if isinstance(payload, Mapping) else []
    if output_dir and target:
        path = world_file(str(output_dir))
        path.parent.mkdir(parents=True, exist_ok=True)
        with SQLiteKnowledgeStore(path) as store:
            _persist(store, target, name, payload, flags, findings)
            index = snapshot(store, target, path)
    else:
        previous = state.get("world") if isinstance(state.get("world"), Mapping) else {}
        index = _index_from_memory(target, flags, findings, ports=ports, previous=previous)
    state["world"] = index
    return index


def snapshot(store: SQLiteKnowledgeStore, target: str, path: Path | None = None) -> Dict[str, Any]:
    """Build a planner-facing index. No scan bodies."""
    entities = store.find_entities(limit=5000)
    targets = [item for item in entities if item.get("type") == "target"]
    findings = [item for item in entities if item.get("type") == "finding"]
    facts = [item for item in entities if item.get("type") not in {"target", "finding", "session"}]
    target_row = _match_target(targets, target)
    props = dict(target_row.get("properties") or {}) if target_row else {}
    unverified = [_finding_key(item.get("properties") or {}) for item in findings if _is_open(item)]
    port_nums: List[int] = []
    extra_facts: List[Dict[str, str]] = []
    for item in facts:
        if item.get("type") == "port":
            number = _as_int(item.get("name"))
            if number is not None:
                port_nums.append(number)
        else:
            extra_facts.append(
                {"kind": str(item.get("type") or "asset"), "name": str(item.get("name") or "")}
            )
    assets_index = _assets_index(target, port_nums, extra=extra_facts)
    return {
        "schema": WORLD_SCHEMA,
        "path": str(path) if path is not None else None,
        "target": target,
        "target_id": target_row.get("id") if target_row else None,
        "recon": bool(props.get("recon")),
        "detect": bool(props.get("detect")),
        "nuclei": bool(props.get("nuclei")),
        "exported": bool(props.get("exported")),
        "assets": len(targets),
        "facts": len(facts),
        "findings": len(findings),
        "unverified": len(unverified),
        "unverified_index": unverified,
        "assets_index": assets_index,
    }


def coverage(state: Mapping[str, Any]) -> Dict[str, Any]:
    """Coverage flags for the planner. World index wins over scan blobs."""
    world = state.get("world") if isinstance(state.get("world"), Mapping) else {}
    findings = state.get("findings")
    has_list = isinstance(findings, list)
    recon = (
        bool(world["recon"]) if isinstance(world.get("recon"), bool) else bool(state.get("recon"))
    )
    detect = bool(world["detect"]) if isinstance(world.get("detect"), bool) else has_list
    nuclei = (
        bool(world["nuclei"])
        if isinstance(world.get("nuclei"), bool)
        else bool(state.get("nuclei"))
    )
    exported = (
        bool(world["exported"])
        if isinstance(world.get("exported"), bool)
        else bool(state.get("exported"))
    )
    return {
        "recon": recon,
        "detect": detect,
        "nuclei": nuclei,
        "exported": exported,
        "assets": int(world.get("assets") or 0),
        "facts": int(world.get("facts") or 0),
        "finding_count": int(world.get("findings") or (len(findings) if has_list else 0)),
    }


def unverified_index(state: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Compact unverified finding keys. World index first, then state findings."""
    world = state.get("world") if isinstance(state.get("world"), Mapping) else {}
    raw = world.get("unverified_index")
    if isinstance(raw, list):
        return [dict(item) for item in raw if isinstance(item, dict)]
    pending: List[Dict[str, Any]] = []
    findings = state.get("findings")
    if not isinstance(findings, list):
        return pending
    for item in findings:
        if not isinstance(item, dict):
            continue
        if item.get("engagement_verified") is True:
            continue
        if str(item.get("verification_status") or "") == "verified":
            continue
        pending.append(_finding_key(item))
    return pending


def _persist(
    store: SQLiteKnowledgeStore,
    target: str,
    name: str,
    payload: Mapping[str, Any],
    flags: Mapping[str, bool],
    findings: Sequence[Mapping[str, Any]],
) -> None:
    target_id = _stable_id("t", target)
    _upsert(
        store,
        target_id,
        "target",
        target,
        {"target": target, **{key: bool(flags.get(key)) for key in _FLAG_KEYS}},
    )
    for port in _ports_from_payload(payload):
        port_id = _stable_id("p", "%s:%s" % (target, port))
        _upsert(store, port_id, "port", str(port), {"port": port, "target": target})
        _rel(store, target_id, port_id, "has_port")
    for finding in findings:
        key = _finding_key(finding)
        finding_id = _stable_id("f", "%s|%s|%s" % (key["url"], key["vuln_type"], key["param"]))
        verified = str(finding.get("verification_status") or "") == "verified"
        dry = str(finding.get("verification_status") or "") == "dry_run"
        confirmed = verified or dry
        props = {
            **key,
            "verification_status": finding.get("verification_status") or "",
            "verified_by": finding.get("verified_by") or "",
            "confidence_level": _CONFIRMED if confirmed else _TENTATIVE,
            "source_step": name,
        }
        _upsert(store, finding_id, "finding", key["vuln_type"] or key["url"], props)
        _rel(
            store,
            target_id,
            finding_id,
            "has_vulnerability",
            confidence=1.0 if confirmed else 0.5,
        )


def _upsert(
    store: SQLiteKnowledgeStore,
    entity_id: str,
    entity_type: str,
    name: str,
    properties: Mapping[str, Any],
) -> None:
    existing = store.get_entity(entity_id)
    merged = dict(existing.get("properties") or {}) if existing else {}
    merged.update(dict(properties))
    store.add_entity(entity_type, name, dict(merged), entity_id=entity_id)


def _rel(
    store: SQLiteKnowledgeStore,
    source_id: str,
    target_id: str,
    rel_type: str,
    *,
    confidence: float = 1.0,
) -> None:
    rel_id = _stable_id("r", "%s|%s|%s" % (source_id, rel_type, target_id))
    store.add_relationship(source_id, target_id, rel_type, confidence=confidence, rel_id=rel_id)


def _merged_flags(state: Mapping[str, Any], name: str) -> Dict[str, bool]:
    world = state.get("world") if isinstance(state.get("world"), Mapping) else {}
    flags = {
        "recon": bool(world.get("recon") or state.get("recon")),
        "detect": bool(world.get("detect") or isinstance(state.get("findings"), list)),
        "nuclei": bool(world.get("nuclei") or state.get("nuclei")),
        "exported": bool(world.get("exported") or state.get("exported")),
    }
    if name == "recon_run":
        flags["recon"] = True
    elif name == "detect_run":
        flags["detect"] = True
    elif name == "nuclei_scan":
        flags["nuclei"] = True
    elif name == "export_findings":
        flags["exported"] = True
    return flags


def _compact_findings(state: Mapping[str, Any]) -> List[Dict[str, Any]]:
    findings = state.get("findings")
    if not isinstance(findings, list):
        return []
    rows: List[Dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        key = _finding_key(item)
        key["verification_status"] = item.get("verification_status") or ""
        key["verified_by"] = item.get("verified_by") or ""
        key["engagement_verified"] = bool(item.get("engagement_verified"))
        rows.append(key)
    return rows


def _finding_key(item: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "url": str(item.get("url") or ""),
        "vuln_type": str(item.get("vuln_type") or item.get("type") or ""),
        "param": str(item.get("param") or ""),
        "verification_status": str(item.get("verification_status") or ""),
        "verified_by": str(item.get("verified_by") or ""),
    }


def _is_open(entity: Mapping[str, Any]) -> bool:
    props = entity.get("properties") if isinstance(entity.get("properties"), Mapping) else {}
    status = str(props.get("verification_status") or "")
    if status in {"verified", "dry_run", "contradicted"}:
        return False
    if props.get("confidence_level") == _CONFIRMED:
        return False
    return True


def _index_from_memory(
    target: str,
    flags: Mapping[str, bool],
    findings: Sequence[Mapping[str, Any]],
    *,
    ports: Sequence[int] | None = None,
    previous: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    unverified = [_finding_key(item) for item in findings if _finding_is_open(item)]
    prev_assets = previous.get("assets_index") if isinstance(previous, Mapping) else None
    assets_index = _assets_index(target, list(ports or []), previous=prev_assets)
    port_count = sum(1 for item in assets_index if item.get("kind") == "port")
    return {
        "schema": WORLD_SCHEMA,
        "path": None,
        "target": target,
        "target_id": _stable_id("t", target) if target else None,
        "recon": bool(flags.get("recon")),
        "detect": bool(flags.get("detect")),
        "nuclei": bool(flags.get("nuclei")),
        "exported": bool(flags.get("exported")),
        "assets": 1 if target else 0,
        "facts": port_count,
        "findings": len(list(findings)),
        "unverified": len(unverified),
        "unverified_index": unverified,
        "assets_index": assets_index,
    }


def _assets_index(
    target: str,
    ports: Sequence[int],
    previous: Any = None,
    extra: Sequence[Mapping[str, Any]] | None = None,
) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(kind: str, name: str) -> None:
        key = (kind, name)
        if not name or key in seen:
            return
        seen.add(key)
        rows.append({"kind": kind, "name": name})

    if isinstance(previous, list):
        for item in previous:
            if isinstance(item, Mapping):
                _add(str(item.get("kind") or "asset"), str(item.get("name") or ""))
    if target:
        _add("target", target)
    for port in ports:
        _add("port", str(port))
    for item in extra or []:
        if isinstance(item, Mapping):
            _add(str(item.get("kind") or "asset"), str(item.get("name") or ""))
    return rows


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _finding_is_open(item: Mapping[str, Any]) -> bool:
    if item.get("engagement_verified") is True:
        return False
    status = str(item.get("verification_status") or "")
    return status not in {"verified", "dry_run", "contradicted"}


def _ports_from_payload(payload: Mapping[str, Any]) -> List[int]:
    ports: List[int] = []
    stack: List[Any] = [payload]
    results = payload.get("results")
    if isinstance(results, Mapping):
        stack.extend(results.values())
    data = payload.get("data")
    if isinstance(data, Mapping):
        stack.append(data)
    for blob in stack:
        if not isinstance(blob, Mapping):
            continue
        for key in ("open_ports", "ports"):
            items = blob.get(key)
            if not isinstance(items, list):
                continue
            for item in items:
                port = item.get("port") if isinstance(item, Mapping) else item
                try:
                    number = int(port)
                except (TypeError, ValueError):
                    continue
                if number not in ports:
                    ports.append(number)
    return ports


def _target_of(
    state: Mapping[str, Any], inputs: Mapping[str, Any], payload: Mapping[str, Any]
) -> str:
    recon = state.get("recon") if isinstance(state.get("recon"), Mapping) else {}
    world = state.get("world") if isinstance(state.get("world"), Mapping) else {}
    return str(
        inputs.get("target")
        or inputs.get("url")
        or payload.get("target")
        or payload.get("url")
        or recon.get("target")
        or world.get("target")
        or ""
    ).strip()


def _match_target(targets: Sequence[Mapping[str, Any]], target: str) -> Optional[Dict[str, Any]]:
    wanted = _stable_id("t", target)
    for item in targets:
        if item.get("id") == wanted or item.get("name") == target:
            return dict(item)
        props = item.get("properties") if isinstance(item.get("properties"), Mapping) else {}
        if props.get("target") == target:
            return dict(item)
    return dict(targets[0]) if targets else None


def _stable_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]
    return "%s_%s" % (prefix, digest)


_FLAG_KEYS = ("recon", "detect", "nuclei", "exported")
