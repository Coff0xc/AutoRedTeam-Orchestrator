"""Capability registry for the AI red-team refactor target.

The registry is a local, evidence-oriented map. It explains which project
modules implement each borrowed design direction without importing or executing
dangerous tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal

CapabilityStatus = Literal["implemented", "partial", "blocked"]


@dataclass(frozen=True)
class Capability:
    """One externally-inspired capability mapped to local implementation."""

    source: str
    capability: str
    status: CapabilityStatus
    local_modules: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "capability": self.capability,
            "status": self.status,
            "local_modules": self.local_modules,
            "evidence": self.evidence,
            "notes": self.notes,
        }


CAPABILITIES: List[Capability] = [
    Capability(
        source="PentAGI",
        capability="sandbox policy enforcement",
        status="implemented",
        local_modules=["core.agent_runtime.sandbox", "core.agent_runtime.middleware"],
        evidence=[
            "SandboxPolicy/enforce_sandbox_policy",
            "SandboxMiddleware in RuntimePipeline",
            "sandbox docker-smoke CLI",
        ],
        notes=["Docker execution is available but real smoke depends on local Docker daemon."],
    ),
    Capability(
        source="PentAGI",
        capability="multi-agent roles",
        status="implemented",
        local_modules=["core.agent_roles.models"],
        evidence=["AgentRole", "AgentTeam", "build_default_team"],
    ),
    Capability(
        source="PentAGI",
        capability="memory",
        status="implemented",
        local_modules=["core.agent_runtime.memory", "core.agent_runtime.models"],
        evidence=["RunMemory", "AgentRunState.memory", "AgentRunState.add_memory"],
    ),
    Capability(
        source="PentAGI",
        capability="knowledge graph",
        status="implemented",
        local_modules=["handlers.knowledge_handlers", "tests.test_knowledge_manager"],
        evidence=["kg_store", "kg_query", "kg_attack_paths"],
    ),
    Capability(
        source="PentAGI",
        capability="observability",
        status="implemented",
        local_modules=["core.agent_runtime.observability", "core.agent_runtime.views"],
        evidence=[
            "build_observability_snapshot",
            "build_run_view",
            "RuntimeRunRegistry collects handler and runner runs",
        ],
    ),
    Capability(
        source="PentAGI",
        capability="read-only Web/API run view",
        status="implemented",
        local_modules=[
            "core.agent_runtime.api",
            "core.agent_runtime.registry",
            "core.agent_runtime.views",
            "cli.main",
        ],
        evidence=[
            "GET /api/runs",
            "GET /api/runs/{run_id}",
            "runtime-api serve",
            "default API store uses GLOBAL_RUNTIME_RUN_REGISTRY",
        ],
    ),
    Capability(
        source="promptfoo",
        capability="declarative red-team scenario config",
        status="implemented",
        local_modules=["core.ai_redteam.models", "core.ai_redteam.scenario"],
        evidence=["Scenario.from_dict", "load_scenario", "YAML/JSON support"],
    ),
    Capability(
        source="promptfoo",
        capability="plugins/strategies/report/CI",
        status="implemented",
        local_modules=[
            "core.ai_redteam.plugins",
            "core.ai_redteam.strategies",
            "core.ai_redteam.report",
            "cli.main",
        ],
        evidence=[
            "RedTeamPlugin",
            "plugin_summary",
            "apply_strategy",
            "render_markdown",
            "ai-redteam run --ci",
        ],
    ),
    Capability(
        source="garak",
        capability="probe/generator/detector/evaluator organization",
        status="implemented",
        local_modules=[
            "core.ai_redteam.catalog",
            "core.ai_redteam.scorers",
            "core.ai_redteam.eval_cases",
        ],
        evidence=["PROBES", "STRATEGIES", "SCORERS", "EvalCase"],
    ),
    Capability(
        source="PyRIT",
        capability="prompt target/converter/scorer/memory abstractions",
        status="implemented",
        local_modules=[
            "core.ai_redteam.models",
            "core.ai_redteam.converters",
            "core.ai_redteam.scorers",
            "core.agent_runtime.memory",
        ],
        evidence=["Target", "convert_prompt", "Scorer", "RunMemory"],
    ),
    Capability(
        source="AI-Infra-Guard",
        capability="MCP/Skills/Agent/AI infra static security scan",
        status="implemented",
        local_modules=["core.ai_surface.scanner", "handlers.ai_handlers"],
        evidence=["scan_handler_surface", "scan_skill_surface", "scan_mcp_config"],
    ),
    Capability(
        source="CAI",
        capability="guardrails/MCP/benchmark",
        status="implemented",
        local_modules=[
            "core.agent_runtime.middleware",
            "core.agent_runtime.benchmark",
            "handlers.ai_handlers",
        ],
        evidence=["PolicyMiddleware", "SandboxMiddleware", "BenchmarkHarness"],
    ),
    Capability(
        source="Decepticon",
        capability="sandbox/tools/middleware/agent workflow runtime",
        status="implemented",
        local_modules=[
            "core.agent_runtime.middleware",
            "core.agent_runtime.sandbox",
            "core.ai_redteam.runner",
            "core.orchestrator.orchestrator",
        ],
        evidence=[
            "RuntimePipeline.apply_action",
            "AIRedTeamRunner uses runtime_pipeline",
            "AIRedTeamRunner registers run_state in RuntimeRunRegistry",
            "AutoPentestOrchestrator.execute_phase gates legacy phases",
            "AutoPentestOrchestrator registers runtime_run_state in RuntimeRunRegistry",
            "orchestrator phase internals gate concrete tool actions",
            "orchestration handlers return runtime decision metadata",
            "recon/report/knowledge/resource handlers register runtime runs",
        ],
    ),
    Capability(
        source="Vulnhuntr",
        capability="call-chain context expansion and confidence score",
        status="implemented",
        local_modules=["core.code_agent.analyzer", "core.code_agent.models"],
        evidence=["expand_code_context", "ConfidenceScore"],
        notes=["Original AST implementation; no AGPL code copied."],
    ),
    Capability(
        source="Giskard",
        capability="deterministic eval cases",
        status="implemented",
        local_modules=["core.ai_redteam.eval_cases"],
        evidence=["default_eval_cases", "evaluate_run_cases"],
    ),
    Capability(
        source="Inspect",
        capability="agent/tool eval cases",
        status="implemented",
        local_modules=["core.ai_redteam.eval_cases", "core.agent_runtime.models"],
        evidence=["tool.permission_drift", "agent.multi_agent_handoff_trace"],
    ),
    Capability(
        source="Aguara",
        capability="skills/MCP static safety scan",
        status="implemented",
        local_modules=["core.ai_surface.scanner"],
        evidence=["scan_skill_surface", "scan_mcp_config"],
    ),
]


def capability_matrix() -> Dict[str, Any]:
    """Return all tracked capabilities grouped by source and status."""
    by_source: Dict[str, List[Dict[str, Any]]] = {}
    status_counts = {"implemented": 0, "partial": 0, "blocked": 0}
    for item in CAPABILITIES:
        by_source.setdefault(item.source, []).append(item.to_dict())
        status_counts[item.status] += 1
    return {
        "success": True,
        "summary": {
            "total": len(CAPABILITIES),
            "implemented": status_counts["implemented"],
            "partial": status_counts["partial"],
            "blocked": status_counts["blocked"],
            "coverage": round(status_counts["implemented"] / len(CAPABILITIES), 3),
        },
        "sources": by_source,
        "capabilities": [item.to_dict() for item in CAPABILITIES],
    }


def refactor_readiness() -> Dict[str, Any]:
    """Return a concise refactor readiness assessment."""
    matrix = capability_matrix()
    partial = [item for item in CAPABILITIES if item.status == "partial"]
    blocked = [item for item in CAPABILITIES if item.status == "blocked"]
    return {
        "success": True,
        "ready_for_full_refactor": not blocked,
        "summary": matrix["summary"],
        "constraints": [
            "Keep active security execution behind middleware, sandbox, and human gates.",
            "Keep Docker execution optional because it depends on local daemon state.",
            "Preserve CLI/MCP/SDK public APIs with the Vulture whitelist during refactor.",
            "Do not copy AGPL code; keep Vulnhuntr-style logic as original AST implementation.",
        ],
        "partial_capabilities": [item.to_dict() for item in partial],
        "blocked_capabilities": [item.to_dict() for item in blocked],
    }
