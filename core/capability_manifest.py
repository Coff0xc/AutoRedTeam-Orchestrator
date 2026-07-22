"""Machine-readable MCP capability manifest and profile policy."""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence

CAPABILITY_PROFILE_ENV = "AUTORT_CAPABILITY_PROFILE"
DEFAULT_MCP_PROFILE = "safe"
PROFILE_ORDER = ("safe", "scan", "active-lab", "full")


class CapabilityManifestError(ValueError):
    """Raised when a profile or surface is missing from the manifest."""


@dataclass(frozen=True)
class CapabilityProfile:
    """An ordered MCP exposure profile."""

    name: str
    description: str
    operating_boundary: str

    def to_dict(self, surface_count: int) -> dict[str, Any]:
        index = PROFILE_ORDER.index(self.name)
        inherits = PROFILE_ORDER[index - 1] if index else None
        return {
            "name": self.name,
            "inherits": inherits,
            "description": self.description,
            "operating_boundary": self.operating_boundary,
            "surface_count": surface_count,
        }


PROFILES = (
    CapabilityProfile(
        name="safe",
        description="Local analysis, dry-run, metadata, and controlled local state only.",
        operating_boundary=(
            "Trusted local process; no target network access or host command execution."
        ),
    ),
    CapabilityProfile(
        name="scan",
        description="Safe profile plus authorized reconnaissance and vulnerability scanning.",
        operating_boundary="Explicit target scope and external network controls are required.",
    ),
    CapabilityProfile(
        name="active-lab",
        description="Scan profile plus exploit validation and offensive planning.",
        operating_boundary="Disposable lab, independent approval, and isolated executor required.",
    ),
    CapabilityProfile(
        name="full",
        description="All surfaces, including post-exploitation and restricted research features.",
        operating_boundary=(
            "Explicit opt-in for isolated, authorized, disposable environments only."
        ),
    ),
)


@dataclass(frozen=True)
class Capability:
    """Registration and operating metadata for one public MCP surface."""

    kind: str
    name: str
    handler: str
    category: str
    minimum_profile: str
    risk: str
    maturity: str
    auth_required: bool
    approval_required: bool
    executor: str
    effects: tuple[str, ...]
    locator: Optional[str] = None

    @property
    def profiles(self) -> tuple[str, ...]:
        minimum_index = PROFILE_ORDER.index(self.minimum_profile)
        return PROFILE_ORDER[minimum_index:]

    def allowed_in(self, profile: str) -> bool:
        return profile in self.profiles

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "kind": self.kind,
            "name": self.name,
            "handler": self.handler,
            "category": self.category,
            "risk": self.risk,
            "maturity": self.maturity,
            "minimum_profile": self.minimum_profile,
            "profiles": list(self.profiles),
            "required_controls": {
                "authentication": self.auth_required,
                "independent_approval": self.approval_required,
                "executor": self.executor,
            },
            "manifest_enforces": ["profile-registration"],
            "effects": list(self.effects),
        }
        if self.locator:
            payload["locator"] = self.locator
        return payload


def _surface_group(
    names: Sequence[str],
    *,
    handler: str,
    category: str,
    minimum_profile: str,
    risk: str,
    maturity: str,
    auth_required: bool = False,
    approval_required: bool = False,
    executor: str = "in-process",
    effects: Sequence[str] = (),
    kind: str = "tool",
    locators: Optional[Mapping[str, str]] = None,
) -> list[Capability]:
    return [
        Capability(
            kind=kind,
            name=name,
            handler=handler,
            category=category,
            minimum_profile=minimum_profile,
            risk=risk,
            maturity=maturity,
            auth_required=auth_required,
            approval_required=approval_required,
            executor=executor,
            effects=tuple(effects),
            locator=locators.get(name) if locators else None,
        )
        for name in names
    ]


def _build_capabilities() -> tuple[Capability, ...]:
    capabilities: list[Capability] = []
    add = capabilities.extend

    add(
        _surface_group(
            (
                "full_recon",
                "port_scan",
                "fingerprint",
                "subdomain_enum",
                "dir_scan",
                "dns_lookup",
                "tech_detect",
                "waf_detect",
                "passive_subdomain_enum",
            ),
            handler="recon",
            category="recon",
            minimum_profile="scan",
            risk="moderate",
            maturity="beta",
            auth_required=True,
            effects=("network-probe",),
        )
    )
    add(
        _surface_group(
            (
                "vuln_scan",
                "nuclei_scan",
                "sqli_scan",
                "xss_scan",
                "ssrf_scan",
                "rce_scan",
                "path_traversal_scan",
                "ssti_scan",
                "xxe_scan",
                "idor_scan",
                "cors_scan",
                "security_headers_scan",
                "http_smuggling_scan",
                "cache_poisoning_scan",
                "prototype_pollution_scan",
                "crlf_injection_scan",
                "host_header_injection_scan",
                "exposure_scan",
                "ldap_scan",
                "open_redirect_scan",
                "info_disclosure_scan",
                "csrf_scan",
                "auth_bypass_scan",
                "weak_password_scan",
                "session_scan",
                "upload_scan",
                "lfi_scan",
                "deserialize_scan",
            ),
            handler="detector",
            category="detector",
            minimum_profile="scan",
            risk="moderate",
            maturity="beta",
            auth_required=True,
            effects=("network-probe", "offensive-content"),
        )
    )
    add(
        _surface_group(
            ("cve_search", "cve_stats", "poc_list"),
            handler="cve",
            category="cve",
            minimum_profile="safe",
            risk="low",
            maturity="preview",
            effects=("local-read", "local-write"),
        )
    )
    add(
        _surface_group(
            ("cve_sync",),
            handler="cve",
            category="cve",
            minimum_profile="scan",
            risk="moderate",
            maturity="preview",
            auth_required=True,
            effects=("internet-egress", "local-write"),
        )
    )
    add(
        _surface_group(
            ("poc_execute", "cve_auto_exploit", "cve_exploit_with_desc", "cve_generate_poc"),
            handler="cve",
            category="cve",
            minimum_profile="active-lab",
            risk="critical",
            maturity="restricted-experimental",
            auth_required=True,
            approval_required=True,
            executor="isolated-required",
            effects=("network-active", "target-write", "offensive-content"),
        )
    )
    add(
        _surface_group(
            (
                "jwt_scan",
                "cors_deep_scan",
                "graphql_scan",
                "websocket_scan",
                "oauth_scan",
                "security_headers_score",
                "full_api_scan",
            ),
            handler="api_security",
            category="api_security",
            minimum_profile="scan",
            risk="moderate",
            maturity="preview",
            auth_required=True,
            effects=("network-probe",),
        )
    )
    add(
        _surface_group(
            ("k8s_scan", "grpc_scan", "aws_scan"),
            handler="cloud_security",
            category="cloud_security",
            minimum_profile="scan",
            risk="high",
            maturity="preview",
            auth_required=True,
            effects=("network-probe", "credential-use", "local-read"),
        )
    )
    add(
        _surface_group(
            ("sbom_generate", "dependency_audit", "cicd_scan"),
            handler="supply_chain",
            category="supply_chain",
            minimum_profile="scan",
            risk="moderate",
            maturity="preview",
            auth_required=True,
            effects=("local-read",),
        )
    )
    add(
        _surface_group(
            (
                "lateral_smb",
                "c2_beacon_start",
                "payload_obfuscate",
                "waf_bypass",
                "credential_find",
                "privilege_check",
                "privilege_escalate",
                "post_exploit_amsi_bypass",
                "post_exploit_etw_bypass",
                "post_exploit_stager",
                "post_exploit_evasion_chain",
                "post_exploit_privesc_suggest",
                "exfiltrate_data",
                "exfiltrate_file",
            ),
            handler="redteam",
            category="redteam",
            minimum_profile="full",
            risk="critical",
            maturity="restricted-experimental",
            auth_required=True,
            approval_required=True,
            executor="isolated-required",
            effects=("host-exec", "credential-use", "target-write", "offensive-content"),
        )
    )
    add(
        _surface_group(
            (
                "pentest_status",
                "exploit_vulnerability",
                "exploit_by_cve",
                "get_attack_paths",
                "exploit_orchestrate",
                "exploit_with_retry",
                "verify_and_exploit",
                "analyze_exploit_failure",
            ),
            handler="orchestration",
            category="orchestration",
            minimum_profile="active-lab",
            risk="critical",
            maturity="restricted-experimental",
            auth_required=True,
            approval_required=True,
            executor="isolated-required",
            effects=("network-active", "target-write", "offensive-content"),
        )
    )
    add(
        _surface_group(
            ("auto_pentest", "pentest_resume", "pentest_phase"),
            handler="orchestration",
            category="orchestration",
            minimum_profile="full",
            risk="critical",
            maturity="restricted-experimental",
            auth_required=True,
            approval_required=True,
            executor="isolated-required",
            effects=("network-active", "host-exec", "target-write", "credential-use"),
        )
    )
    add(
        _surface_group(
            (
                "lateral_ssh",
                "lateral_ssh_tunnel",
                "lateral_wmi",
                "lateral_wmi_query",
                "lateral_winrm",
                "lateral_winrm_ps",
                "lateral_psexec",
                "lateral_auto",
                "credential_spray",
            ),
            handler="lateral",
            category="lateral",
            minimum_profile="full",
            risk="critical",
            maturity="restricted-experimental",
            auth_required=True,
            approval_required=True,
            executor="isolated-required",
            effects=("host-exec", "credential-use", "network-active", "target-write"),
        )
    )
    add(
        _surface_group(
            ("persistence_windows", "persistence_linux", "persistence_webshell"),
            handler="persistence",
            category="persistence",
            minimum_profile="full",
            risk="critical",
            maturity="restricted-experimental",
            auth_required=True,
            approval_required=True,
            executor="isolated-required",
            effects=("host-exec", "target-write", "persistence"),
        )
    )
    add(
        _surface_group(
            ("ad_enumerate", "ad_kerberos_attack", "ad_spn_scan"),
            handler="ad",
            category="ad",
            minimum_profile="full",
            risk="critical",
            maturity="restricted-experimental",
            auth_required=True,
            approval_required=True,
            executor="isolated-required",
            effects=("credential-use", "network-active", "offensive-content"),
        )
    )
    add(
        _surface_group(
            ("session_create", "session_status", "session_list", "session_complete"),
            handler="session",
            category="session",
            minimum_profile="safe",
            risk="low",
            maturity="preview",
            effects=("local-read", "local-write"),
        )
    )
    add(
        _surface_group(
            (
                "ai_redteam_run_scenario",
                "ai_surface_scan_handlers",
                "ai_surface_scan_skills",
                "ai_surface_scan_mcp_config",
                "code_agent_expand_context",
            ),
            handler="ai",
            category="ai",
            minimum_profile="safe",
            risk="moderate",
            maturity="preview",
            effects=("caller-selected-local-read", "dry-run"),
        )
    )
    add(
        _surface_group(
            (
                "ai_redteam_eval_run_state",
                "ai_prompt_convert",
                "ai_capability_matrix",
            ),
            handler="ai",
            category="ai",
            minimum_profile="safe",
            risk="low",
            maturity="preview",
            effects=("local-read", "dry-run"),
        )
    )
    add(
        _surface_group(
            ("export_findings",),
            handler="report",
            category="report",
            minimum_profile="safe",
            risk="low",
            maturity="preview",
            effects=("local-read", "finding-data"),
        )
    )
    add(
        _surface_group(
            ("generate_report",),
            handler="report",
            category="report",
            minimum_profile="scan",
            risk="moderate",
            maturity="preview",
            auth_required=True,
            effects=("local-read", "controlled-artifact-write"),
        )
    )
    add(
        _surface_group(
            ("smart_analyze",),
            handler="ai",
            category="ai",
            minimum_profile="scan",
            risk="moderate",
            maturity="experimental",
            auth_required=True,
            effects=("provider-egress", "network-probe"),
        )
    )
    add(
        _surface_group(
            ("attack_chain_plan", "smart_payload"),
            handler="ai",
            category="ai",
            minimum_profile="active-lab",
            risk="high",
            maturity="experimental",
            auth_required=True,
            approval_required=True,
            executor="isolated-required",
            effects=("offensive-content",),
        )
    )
    add(
        _surface_group(
            ("registry_stats", "health_check"),
            handler="misc",
            category="misc",
            minimum_profile="safe",
            risk="low",
            maturity="preview",
            effects=("metadata-read",),
        )
    )
    add(
        _surface_group(
            ("js_analyze",),
            handler="misc",
            category="misc",
            minimum_profile="scan",
            risk="moderate",
            maturity="preview",
            auth_required=True,
            effects=("network-probe",),
        )
    )
    add(
        _surface_group(
            (
                "ext_nmap_scan",
                "ext_nuclei_scan",
                "ext_ffuf_fuzz",
                "ext_masscan_scan",
                "ext_tools_status",
                "ext_tools_reload",
            ),
            handler="external_tools",
            category="external_tools",
            minimum_profile="scan",
            risk="high",
            maturity="internal",
            auth_required=True,
            executor="external-process",
            effects=("host-exec", "network-probe", "metadata-read"),
        )
    )
    add(
        _surface_group(
            ("ext_sqlmap_scan", "ext_tool_chain"),
            handler="external_tools",
            category="external_tools",
            minimum_profile="active-lab",
            risk="critical",
            maturity="restricted-experimental",
            auth_required=True,
            approval_required=True,
            executor="isolated-required",
            effects=("host-exec", "network-active", "target-write"),
        )
    )
    add(
        _surface_group(
            ("parallel_scan",),
            handler="parallel",
            category="orchestration",
            minimum_profile="scan",
            risk="moderate",
            maturity="preview",
            auth_required=True,
            effects=("network-probe",),
        )
    )
    add(
        _surface_group(
            ("kg_store", "kg_query", "kg_attack_paths"),
            handler="knowledge",
            category="knowledge",
            minimum_profile="full",
            risk="high",
            maturity="experimental",
            auth_required=True,
            approval_required=True,
            executor="isolated-required",
            effects=("local-read", "local-write", "credential-use", "offensive-content"),
        )
    )
    add(
        _surface_group(
            ("plan_attack_path",),
            handler="mcts",
            category="mcts",
            minimum_profile="full",
            risk="high",
            maturity="experimental",
            auth_required=True,
            approval_required=True,
            executor="isolated-required",
            effects=("offensive-content",),
        )
    )
    add(
        _surface_group(
            ("analyze_findings", "write_report", "explain_vulnerability"),
            handler="prompts",
            category="misc",
            minimum_profile="safe",
            risk="low",
            maturity="preview",
            effects=("prompt-content",),
            kind="prompt",
        )
    )
    add(
        _surface_group(
            ("plan_pentest", "plan_attack_chain", "suggest_next_phase"),
            handler="prompts",
            category="misc",
            minimum_profile="active-lab",
            risk="high",
            maturity="experimental",
            auth_required=True,
            approval_required=True,
            executor="isolated-required",
            effects=("offensive-content", "prompt-content"),
            kind="prompt",
        )
    )
    resource_locators = {
        "active_sessions": "redteam://sessions",
        "registered_tools": "redteam://tools",
        "security_config": "redteam://config",
        "payload_library": "redteam://payloads/{category}",
    }
    add(
        _surface_group(
            ("registered_tools", "security_config"),
            handler="resources",
            category="misc",
            minimum_profile="safe",
            risk="low",
            maturity="preview",
            effects=("metadata-read",),
            kind="resource",
            locators=resource_locators,
        )
    )
    add(
        _surface_group(
            ("active_sessions",),
            handler="resources",
            category="misc",
            minimum_profile="scan",
            risk="moderate",
            maturity="preview",
            auth_required=True,
            effects=("local-read", "finding-data"),
            kind="resource",
            locators=resource_locators,
        )
    )
    add(
        _surface_group(
            ("payload_library",),
            handler="resources",
            category="misc",
            minimum_profile="active-lab",
            risk="high",
            maturity="experimental",
            auth_required=True,
            approval_required=True,
            executor="isolated-required",
            effects=("offensive-content",),
            kind="resource",
            locators=resource_locators,
        )
    )

    return tuple(capabilities)


CAPABILITIES = _build_capabilities()
_CAPABILITY_INDEX = {(item.kind, item.name): item for item in CAPABILITIES}
_HANDLER_NAMES = frozenset(item.handler for item in CAPABILITIES)

if len(_CAPABILITY_INDEX) != len(CAPABILITIES):
    raise CapabilityManifestError("Capability manifest contains duplicate (kind, name) entries")


def normalize_profile(profile: str) -> str:
    """Normalize a profile name and reject unknown values."""

    normalized = str(profile).strip().lower().replace("_", "-")
    if normalized not in PROFILE_ORDER:
        available = ", ".join(PROFILE_ORDER)
        raise CapabilityManifestError(
            f"Unknown capability profile {profile!r}; expected one of: {available}"
        )
    return normalized


def resolve_profile(
    profile: Optional[str] = None,
    *,
    default: str = DEFAULT_MCP_PROFILE,
    environ: Optional[Mapping[str, str]] = None,
) -> str:
    """Resolve explicit profile, then environment, then the supplied default."""

    environment = os.environ if environ is None else environ
    if profile is not None:
        selected = profile
    elif CAPABILITY_PROFILE_ENV in environment:
        selected = environment[CAPABILITY_PROFILE_ENV]
    else:
        selected = default
    return normalize_profile(selected)


def get_capability(kind: str, name: str) -> Capability:
    """Return one capability, failing closed when a surface is unclassified."""

    key = (str(kind).strip().lower(), str(name).strip())
    try:
        return _CAPABILITY_INDEX[key]
    except KeyError as exc:
        raise CapabilityManifestError(
            f"Unclassified MCP surface: kind={key[0]!r}, name={key[1]!r}"
        ) from exc


def surface_allowed(profile: str, kind: str, name: str) -> bool:
    """Return whether a classified surface is exposed by a profile."""

    normalized = normalize_profile(profile)
    return get_capability(kind, name).allowed_in(normalized)


def handler_enabled(profile: str, handler: str) -> bool:
    """Return whether a handler contains at least one surface for a profile."""

    normalized = normalize_profile(profile)
    if handler not in _HANDLER_NAMES:
        raise CapabilityManifestError(f"Unclassified MCP handler: {handler!r}")
    return any(
        capability.handler == handler and capability.allowed_in(normalized)
        for capability in CAPABILITIES
    )


def _summary(capabilities: Iterable[Capability]) -> dict[str, Any]:
    selected = tuple(capabilities)
    return {
        "total": len(selected),
        "by_kind": dict(sorted(Counter(item.kind for item in selected).items())),
        "by_risk": dict(sorted(Counter(item.risk for item in selected).items())),
        "by_maturity": dict(sorted(Counter(item.maturity for item in selected).items())),
    }


def capability_manifest(profile: Optional[str] = None) -> dict[str, Any]:
    """Return the complete or profile-filtered manifest as JSON-ready data."""

    normalized = normalize_profile(profile) if profile is not None else None
    selected = [
        capability
        for capability in CAPABILITIES
        if normalized is None or capability.allowed_in(normalized)
    ]
    return {
        "schema_version": "1.0",
        "profile": normalized or "all",
        "summary": _summary(selected),
        "capabilities": [capability.to_dict() for capability in selected],
    }


def capability_profiles() -> dict[str, Any]:
    """Return ordered profile definitions and their effective surface counts."""

    return {
        "schema_version": "1.0",
        "default_mcp_profile": DEFAULT_MCP_PROFILE,
        "environment_variable": CAPABILITY_PROFILE_ENV,
        "profiles": [
            profile.to_dict(sum(capability.allowed_in(profile.name) for capability in CAPABILITIES))
            for profile in PROFILES
        ],
        "security_note": (
            "Required controls are declarative. Profiles enforce MCP schema exposure only; "
            "they do not replace authentication, target scope, independent approval, "
            "or an isolated executor."
        ),
    }
