"""RuntimeLoop dispatch for resident aggregators.

``recon_run``, ``detect_run``, ``verify_finding``, ``nuclei_scan``, and
``export_findings`` write into the shared engagement state bag. Dry-run records
the step without contacting a target. Live paths call the same Python engines
as the MCP aggregators and require the matching capability surface plus target
scope.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence
from urllib.parse import urlparse

from core.capability_manifest import require_surface
from core.security.target_scope import assert_in_scope

AGGREGATOR_STEPS = frozenset(
    {
        "recon_run",
        "detect_run",
        "verify_finding",
        "nuclei_scan",
        "export_findings",
    }
)


def empty_aggregator_state() -> Dict[str, Any]:
    """Shared bag with ``core.engage.runner.empty_state`` so mixed plans compose."""
    return {
        "status": "init",
        "recon": None,
        "nuclei": None,
        "findings": None,
        "verified": [],
        "exported": False,
        "report_path": None,
        "executed": [],
        "repeats": {},
        "stopped": None,
    }


async def dispatch_aggregator_step(
    name: str,
    inputs: Mapping[str, Any],
    state: Dict[str, Any],
    *,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Execute one aggregator and merge results into ``state``."""
    if name not in AGGREGATOR_STEPS:
        raise ValueError("unknown aggregator step %r" % name)
    if dry_run:
        return _record_dry(state, name, inputs)
    if name == "recon_run":
        return await _exec_recon_run(inputs, state)
    if name == "detect_run":
        return await _exec_detect_run(inputs, state)
    if name == "verify_finding":
        return await _exec_verify_finding(inputs, state)
    if name == "nuclei_scan":
        return await _exec_nuclei_scan(inputs, state)
    return await _exec_export_findings(inputs, state)


def _record_dry(state: Dict[str, Any], name: str, inputs: Mapping[str, Any]) -> Dict[str, Any]:
    output: Dict[str, Any] = {
        "success": True,
        "dry_run": True,
        "step": name,
        "inputs": dict(inputs),
    }
    if name == "recon_run":
        state["recon"] = {
            "dry_run": True,
            "target": inputs.get("target"),
            "modules": inputs.get("modules"),
        }
    elif name == "detect_run":
        if state.get("findings") is None:
            state["findings"] = []
        output["url"] = inputs.get("url") or inputs.get("target")
        output["classes"] = inputs.get("classes")
    elif name == "nuclei_scan":
        if state.get("findings") is None:
            state["findings"] = []
        output["url"] = inputs.get("url") or inputs.get("target")
        state["nuclei"] = {
            "dry_run": True,
            "url": output["url"],
            "tags": inputs.get("tags"),
            "severity": inputs.get("severity"),
        }
    elif name == "verify_finding":
        record = _dry_verify(state, inputs)
        output["finding"] = record
        output["skipped"] = record is None
    elif name == "export_findings":
        output.update(_dry_export(state, inputs))
    return output


def _dry_verify(state: Dict[str, Any], inputs: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    finding = inputs.get("finding")
    if not isinstance(finding, dict):
        finding = _first_unverified(state)
    if finding is None:
        return None
    record = dict(finding)
    record["engagement_verified"] = True
    record["verification_status"] = "dry_run"
    _upsert_finding(state, record)
    verified_rows = list(state.get("verified") or [])
    verified_rows.append(record)
    state["verified"] = verified_rows
    return record


def _dry_export(state: Dict[str, Any], inputs: Mapping[str, Any]) -> Dict[str, Any]:
    from core.engage.scorecard import build_scorecard
    from core.evidence import enforce_evidence_gate

    findings = [item for item in (state.get("findings") or []) if isinstance(item, dict)]
    gated = [enforce_evidence_gate(dict(item))[0] for item in findings]
    card = build_scorecard(gated)
    report = {
        "schema": "autort.engage.report/v1",
        "dry_run": True,
        "findings": gated,
        "scorecard": card,
    }
    output_dir = inputs.get("output_dir")
    if output_dir:
        report_path = Path(str(output_dir)) / "report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        path_text = str(report_path)
    else:
        path_text = "(dry-run)"
    state["exported"] = True
    state["report_path"] = path_text
    return {"report_path": path_text, "report": report}


async def _exec_recon_run(inputs: Mapping[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    require_surface("recon_run")
    from core.recon.names import canonical_recon_module

    target = str(inputs.get("target") or "").strip()
    if not target:
        raise ValueError("recon_run requires target")
    assert_in_scope(target)
    selected = _normalize_list(inputs.get("modules"), empty_error="modules")
    if selected is None:
        resolved = ["full_recon"]
    else:
        resolved = [canonical_recon_module(name) for name in selected]
    results: Dict[str, Any] = {}
    for name in resolved:
        results[name] = await _dispatch_recon_module(name, target, inputs)
    payload = {"success": True, "target": target, "modules": resolved, "results": results}
    state["recon"] = payload
    return payload


async def _dispatch_recon_module(
    name: str, target: str, inputs: Mapping[str, Any]
) -> Dict[str, Any]:
    ports = str(inputs.get("ports") or "1-1000")
    timeout = float(inputs.get("timeout") or 2.0)
    wordlist = str(inputs.get("wordlist") or "common")
    extensions = inputs.get("extensions")
    methods = inputs.get("methods")
    record_types = inputs.get("record_types")
    limit = int(inputs.get("limit") or 100)
    quick_mode = bool(inputs.get("quick_mode", False))
    source_timeout = int(inputs.get("source_timeout") or 10)
    if name == "full_recon":
        return await _exec_full_recon(target, quick_mode)
    if name == "port_scan":
        return await _exec_port_scan(_as_host(target), ports, timeout)
    if name == "fingerprint":
        return await _exec_fingerprint(_as_url(target))
    if name == "subdomain_enum":
        return await _exec_subdomain_enum(_as_host(target), methods, limit)
    if name == "dir_scan":
        return await _exec_dir_scan(_as_url(target), wordlist, extensions)
    if name == "dns_lookup":
        return await _exec_dns_lookup(_as_host(target), record_types)
    if name == "tech_detect":
        return await _exec_tech_detect(_as_url(target))
    if name == "waf_detect":
        return await _exec_waf_detect(_as_url(target))
    if name == "passive_subdomain_enum":
        return await _exec_passive_subdomain_enum(_as_host(target), source_timeout)
    raise ValueError("unknown recon module %r" % name)


async def _exec_full_recon(target: str, quick_mode: bool) -> Dict[str, Any]:
    from core.recon import ReconConfig, StandardReconEngine

    engine = StandardReconEngine(target, ReconConfig(quick_mode=quick_mode))
    result = await engine.async_run()
    data = result.to_dict() if hasattr(result, "to_dict") else result
    return {"success": True, "target": target, "data": data}


async def _exec_port_scan(target: str, ports: str, timeout: float) -> Dict[str, Any]:
    from core.recon import async_scan_ports

    results = await async_scan_ports(target, ports, timeout=timeout)
    open_ports = [
        {"port": item.port, "state": item.state, "service": item.service, "version": item.version}
        for item in results
        if item.state == "open"
    ]
    return {
        "success": True,
        "target": target,
        "open_ports": open_ports,
        "total_scanned": len(results),
        "total_open": len(open_ports),
    }


async def _exec_fingerprint(url: str) -> Dict[str, Any]:
    from core.recon import identify_fingerprints

    results = await asyncio.to_thread(identify_fingerprints, url)
    fingerprints = [
        {
            "name": item.name,
            "category": (
                item.category.value if hasattr(item.category, "value") else str(item.category)
            ),
            "version": item.version,
            "confidence": item.confidence,
        }
        for item in results
    ]
    return {"success": True, "url": url, "fingerprints": fingerprints, "count": len(fingerprints)}


async def _exec_subdomain_enum(domain: str, methods: Optional[Any], limit: int) -> Dict[str, Any]:
    from core.recon import async_enumerate_subdomains

    results = await async_enumerate_subdomains(domain, methods=methods)
    subdomains = [
        {"subdomain": item.subdomain, "ip": item.ip, "source": item.source}
        for item in results[:limit]
    ]
    return {"success": True, "domain": domain, "subdomains": subdomains, "count": len(subdomains)}


async def _exec_dir_scan(url: str, wordlist: str, extensions: Optional[Any]) -> Dict[str, Any]:
    from core.recon import async_scan_directories

    results = await async_scan_directories(url, wordlist=wordlist, extensions=extensions)
    directories = [
        {
            "path": item.path,
            "status_code": item.status_code,
            "content_length": item.content_length,
            "redirect": item.redirect_url,
        }
        for item in results
        if item.status_code in (200, 301, 302, 403)
    ]
    return {"success": True, "url": url, "directories": directories, "count": len(directories)}


async def _exec_dns_lookup(domain: str, record_types: Optional[Any]) -> Dict[str, Any]:
    from core.recon import get_dns_records

    results = await asyncio.to_thread(get_dns_records, domain, record_types=record_types)
    records = results.to_dict() if hasattr(results, "to_dict") else results
    return {"success": True, "domain": domain, "records": records}


async def _exec_tech_detect(url: str) -> Dict[str, Any]:
    from core.recon import detect_technologies

    results = await asyncio.to_thread(detect_technologies, url)
    technologies = [
        {
            "name": item.name,
            "category": item.category,
            "version": item.version,
            "confidence": item.confidence,
        }
        for item in results
    ]
    return {"success": True, "url": url, "technologies": technologies}


async def _exec_waf_detect(url: str) -> Dict[str, Any]:
    from core.recon import detect_waf

    result = await asyncio.to_thread(detect_waf, url)
    return {
        "success": True,
        "url": url,
        "waf_detected": result.detected if hasattr(result, "detected") else bool(result),
        "waf_name": result.name if hasattr(result, "name") else None,
        "confidence": result.confidence if hasattr(result, "confidence") else None,
    }


async def _exec_passive_subdomain_enum(domain: str, timeout: int) -> Dict[str, Any]:
    from core.recon.passive_recon import PassiveRecon

    recon = PassiveRecon(timeout=timeout)
    by_source = await recon.discover_subdomains_with_sources(domain)
    all_subs: set[str] = set()
    for subs in by_source.values():
        all_subs.update(subs)
    return {
        "success": True,
        "domain": domain,
        "subdomains": sorted(all_subs),
        "count": len(all_subs),
        "by_source": {
            key: {"subdomains": value, "count": len(value)} for key, value in by_source.items()
        },
    }


async def _exec_detect_run(inputs: Mapping[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    require_surface("detect_run")
    import core.detectors  # noqa: F401
    from core.detectors import DetectorFactory, DetectorPresets
    from core.detectors.names import canonical_detector_class

    url = _require_http_url(str(inputs.get("url") or inputs.get("target") or ""))
    assert_in_scope(url)
    selected = _normalize_list(inputs.get("classes"), empty_error="classes")
    if selected is None:
        composite = DetectorPresets.owasp_top10()
        detectors_used = ["owasp_top10"]
    else:
        resolved = [canonical_detector_class(name) for name in selected]
        missing = [name for name in resolved if not DetectorFactory.exists(name)]
        if missing:
            available = ", ".join(sorted(DetectorFactory.list_detectors()))
            raise ValueError("unknown detector class %r; available: %s" % (missing, available))
        composite = DetectorFactory.create_composite(resolved)
        detectors_used = resolved
    params = inputs.get("params") if isinstance(inputs.get("params"), Mapping) else {}
    results = await composite.async_detect(url, params=dict(params))
    findings = _format_findings(results)
    _append_findings(state, findings)
    return {
        "success": True,
        "url": url,
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "total_vulns": len(findings),
        "classes": selected,
        "detectors_used": detectors_used,
    }


async def _exec_verify_finding(inputs: Mapping[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    require_surface("verify_finding")
    finding = inputs.get("finding")
    if not isinstance(finding, dict):
        finding = _first_unverified(state)
    if finding is None:
        raise ValueError("verify_finding requires a finding object")
    from core.evidence import assess_finding, enforce_evidence_gate, evidence_from_verification
    from core.vuln_verifier import VulnerabilityVerifier

    url = _require_http_url(str(finding.get("url") or inputs.get("target") or ""))
    assert_in_scope(url)
    vuln_type = str(finding.get("vuln_type") or finding.get("type") or "").strip()
    if not vuln_type:
        raise ValueError("verify_finding requires vuln_type/type")
    param = str(finding.get("param") or "").strip()
    verify_input = dict(finding)
    verify_input.setdefault("type", vuln_type)
    verify_input.setdefault("param", param)
    verify_input.setdefault("url", url)
    verifier = VulnerabilityVerifier(timeout=10)
    results = await asyncio.to_thread(verifier.batch_verify, [verify_input])
    evidence_items = [evidence_from_verification(item) for item in results]
    verified = any(getattr(item, "is_vulnerable", False) is True for item in results)
    status = "verified" if verified else "unverified"
    gate_input = dict(finding)
    gate_input["url"] = url
    gate_input["vuln_type"] = vuln_type
    gate_input["verified"] = verified
    gate_input["verified_by"] = "vuln_verifier" if verified else gate_input.get("verified_by")
    gate_input["evidence"] = [item.to_dict() for item in evidence_items]
    assessment = assess_finding(gate_input)
    gated, _assessment = enforce_evidence_gate(gate_input)
    record = {
        **gated,
        "verification_status": status,
        "engagement_verified": verified,
        "assessment": assessment.to_dict(),
    }
    _upsert_finding(state, record)
    verified_rows = list(state.get("verified") or [])
    verified_rows.append(record)
    state["verified"] = verified_rows
    return {"success": True, "step": "verify_finding", "finding": record}


async def _exec_nuclei_scan(inputs: Mapping[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    require_surface("nuclei_scan")
    from core.detectors.nuclei_engine import NucleiEngine

    url = _require_http_url(str(inputs.get("url") or inputs.get("target") or ""))
    assert_in_scope(url)
    tags = _normalize_list(inputs.get("tags"), empty_error="tags", allow_empty=True)
    severity = _normalize_list(inputs.get("severity"), empty_error="severity", allow_empty=True)
    template_dir = inputs.get("template_dir")
    concurrency = int(inputs.get("concurrency") or 10)
    limit = inputs.get("limit")
    engine = NucleiEngine(template_dir=template_dir)
    loaded = engine.load_templates(
        tags=tags,
        severity=severity,
        limit=None if limit is None else int(limit),
    )
    if loaded == 0:
        if state.get("findings") is None:
            state["findings"] = []
        payload = {
            "success": True,
            "url": url,
            "findings": [],
            "templates_loaded": 0,
            "total_findings": 0,
            "message": "未找到匹配的 Nuclei 模板",
        }
        state["nuclei"] = payload
        return payload
    raw = await engine.scan(target=url, tags=tags, severity=severity, concurrency=concurrency)
    findings = [_nuclei_finding(url, item) for item in raw]
    _append_findings(state, findings)
    payload = {
        "success": True,
        "url": url,
        "templates_loaded": loaded,
        "findings": findings,
        "total_findings": len(findings),
    }
    state["nuclei"] = payload
    return payload


async def _exec_export_findings(inputs: Mapping[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    require_surface("export_findings")
    from core.engage.scorecard import build_scorecard
    from core.evidence import enforce_evidence_gate

    output_dir = Path(str(inputs.get("output_dir") or ".autort"))
    output_dir.mkdir(parents=True, exist_ok=True)
    findings = [item for item in (state.get("findings") or []) if isinstance(item, dict)]
    gated = [enforce_evidence_gate(dict(item))[0] for item in findings]
    card = build_scorecard(gated)
    report = {
        "schema": "autort.engage.report/v1",
        "findings": gated,
        "confirmed": [
            item for item in gated if str(item.get("verification_status") or "") == "verified"
        ],
        "unconfirmed": [
            item for item in gated if str(item.get("verification_status") or "") != "verified"
        ],
        "scorecard": card,
    }
    report_path = output_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    state["exported"] = True
    state["report_path"] = str(report_path)
    return {
        "success": True,
        "step": "export_findings",
        "report_path": str(report_path),
        "report": report,
    }


def _format_findings(results: Any) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for item in results or []:
        if hasattr(item, "vulnerable") and not item.vulnerable:
            continue
        if hasattr(item, "to_dict"):
            payload = item.to_dict()
        elif isinstance(item, dict):
            payload = dict(item)
        else:
            continue
        if isinstance(payload, dict) and payload.get("vulnerable") is False:
            continue
        if isinstance(payload, dict):
            findings.append(payload)
    return findings


def _nuclei_finding(url: str, item: Any) -> Dict[str, Any]:
    row = dict(item) if isinstance(item, dict) else {"raw": item}
    row.setdefault("url", url)
    row.setdefault("vuln_type", str(row.get("template_id") or row.get("name") or "nuclei"))
    row.setdefault("vulnerable", True)
    return row


def _append_findings(state: Dict[str, Any], rows: Sequence[Mapping[str, Any]]) -> None:
    current = [item for item in (state.get("findings") or []) if isinstance(item, dict)]
    current.extend(dict(item) for item in rows)
    state["findings"] = current


def _upsert_finding(state: Dict[str, Any], record: Mapping[str, Any]) -> None:
    findings = [item for item in (state.get("findings") or []) if isinstance(item, dict)]
    updated = False
    for index, item in enumerate(findings):
        if item.get("url") == record.get("url") and item.get("vuln_type") == record.get(
            "vuln_type"
        ):
            findings[index] = {**item, **record}
            updated = True
            break
    if not updated:
        findings.append(dict(record))
    state["findings"] = findings


def _first_unverified(state: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    for item in state.get("findings") or []:
        if not isinstance(item, dict):
            continue
        if item.get("engagement_verified") is True:
            continue
        if str(item.get("verification_status") or "") == "verified":
            continue
        return item
    return None


def _normalize_list(
    value: Any, *, empty_error: str, allow_empty: bool = False
) -> Optional[List[str]]:
    if value is None:
        return None
    if isinstance(value, str):
        parts = [part.strip() for part in value.replace(";", ",").split(",")]
        names = [part for part in parts if part]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        names = [str(item).strip() for item in value if str(item).strip()]
    else:
        raise ValueError("%s must be a list or comma-separated string" % empty_error)
    if not names:
        if allow_empty:
            return None
        raise ValueError("%s is empty; omit it or pass one or more names" % empty_error)
    return names


def _require_http_url(url: str) -> str:
    text = str(url or "").strip()
    from utils.validators import validate_url

    if not validate_url(text):
        raise ValueError("url must be an http(s) address without path traversal")
    return text


def _as_url(target: str) -> str:
    text = str(target).strip()
    if text.startswith(("http://", "https://")):
        return text
    return "https://%s" % text


def _as_host(target: str) -> str:
    text = str(target).strip()
    if text.startswith(("http://", "https://")):
        host = urlparse(text).hostname
        if not host:
            raise ValueError("invalid target URL: %s" % target)
        return host
    return text.split("/")[0]
