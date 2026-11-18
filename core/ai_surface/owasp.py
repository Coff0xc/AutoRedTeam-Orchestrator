"""OWASP MCP Top 10 coverage ledger for the static scanner.

Source: https://owasp.org/www-project-mcp-top-10/ (MCP01:2025–MCP10:2025).
This module is a mapping, not a claim that every category is fully covered.
MCP08 stays a gap: the scanner does not inspect third-party runtime logs,
and this project does not wrap stdio as a TOFU gateway.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

LEDGER_SCHEMA = "autort.owasp.mcp/v1"
OWASP_MCP_SOURCE = "https://owasp.org/www-project-mcp-top-10/"

# coverage: static = scanner/inventory emits findings; partial = control exists
# with a documented limit; none = gap.
OWASP_MCP_ENTRIES: Tuple[Dict[str, Any], ...] = (
    {
        "id": "MCP01",
        "title": "Token Mismanagement & Secret Exposure",
        "coverage": "static",
        "status": "implemented",
        "rules": (
            "mcp.MCP01.secret-env-key",
            "mcp.MCP10.secret-in-schema",
            "skill.hardcoded_secret",
        ),
        "notes": "Config env *names* and secret literals in schemas/skills. Values are not copied.",
    },
    {
        "id": "MCP02",
        "title": "Privilege Escalation via Scope Creep",
        "coverage": "partial",
        "status": "partial",
        "rules": ("mcp_tool.effect-mismatch",),
        "notes": (
            "Capability profiles plus declared_effects_omit_target_contact. "
            "No runtime monitor of growing grants."
        ),
    },
    {
        "id": "MCP03",
        "title": "Tool Poisoning",
        "coverage": "static",
        "status": "implemented",
        "rules": (
            "mcp.MCP03.tool-poisoning",
            "mcp.MCP03.hidden-unicode",
            "surface_description_changed",
        ),
        "notes": "Description-as-instruction and hidden unicode. Drift is ai-surface diff --ci.",
    },
    {
        "id": "MCP04",
        "title": "Software Supply Chain Attacks & Dependency Tampering",
        "coverage": "static",
        "status": "implemented",
        "rules": (
            "mcp.MCP04.unpinned-package",
            "mcp.MCP04.remote-skill-code",
            "skill.unverifiable_remote_code",
            "skill.suspicious_download_url",
            "skill.missing_skill_md",
        ),
        "notes": "Unpinned npx/uvx/pip and remote skill install steps. No package-registry query.",
    },
    {
        "id": "MCP05",
        "title": "Command Injection & Execution",
        "coverage": "static",
        "status": "implemented",
        "rules": ("mcp.MCP05.general-command",),
        "notes": "Flags powershell/pwsh/cmd/bash/sh/python/node as a general interpreter.",
    },
    {
        "id": "MCP06",
        "title": "Intent Flow Subversion",
        "coverage": "static",
        "status": "implemented",
        "rules": ("skill.prompt_injection",),
        "notes": "Skill text that tries to override the agent. Tool-output injection is out of band.",
    },
    {
        "id": "MCP07",
        "title": "Insufficient Authentication & Authorization",
        "coverage": "static",
        "status": "implemented",
        "rules": ("mcp_tool.auth-critical", "mcp_tool.auth-missing"),
        "notes": "Handler AST missing-auth gates. Not a substitute for MCP OAuth on a remote server.",
    },
    {
        "id": "MCP08",
        "title": "Lack of Audit and Telemetry",
        "coverage": "none",
        "status": "gap",
        "rules": (),
        "notes": (
            "The scanner does not read third-party MCP run logs. "
            "This project does not wrap stdio as a TOFU or telemetry gateway."
        ),
    },
    {
        "id": "MCP09",
        "title": "Shadow MCP Servers",
        "coverage": "static",
        "status": "implemented",
        "rules": ("mcp.MCP09.remote-endpoint",),
        "notes": "ai-surface inventory lists local client configs; remote url/serverUrl/baseUrl is flagged.",
    },
    {
        "id": "MCP10",
        "title": "Context Injection & Over-Sharing",
        "coverage": "static",
        "status": "implemented",
        "rules": ("mcp.MCP10.overlong-description", "mcp.MCP10.secret-in-schema"),
        "notes": "Overlong tool text and secret literals in schema strings. Cross-task context is out of band.",
    },
)


def owasp_mcp_ledger() -> Dict[str, Any]:
    """Return the static OWASP MCP Top 10 coverage ledger."""
    entries: List[Dict[str, Any]] = []
    counts = {"implemented": 0, "partial": 0, "gap": 0}
    for item in OWASP_MCP_ENTRIES:
        status = str(item["status"])
        counts[status] = counts.get(status, 0) + 1
        entries.append(
            {
                "id": item["id"],
                "title": item["title"],
                "coverage": item["coverage"],
                "status": status,
                "rules": list(item["rules"]),
                "notes": item["notes"],
            }
        )
    return {
        "schema": LEDGER_SCHEMA,
        "source": OWASP_MCP_SOURCE,
        "network": False,
        "summary": {
            "total": len(entries),
            "implemented": counts["implemented"],
            "partial": counts["partial"],
            "gap": counts["gap"],
        },
        "entries": entries,
    }
