"""MCP prompt handlers.

Each prompt returns the capability-manifest constraint and the caller's
declared parameters. Registration replaces the schema description with the
same manifest text.
"""

from __future__ import annotations

from core.capability_manifest import render_prompt_body

_PROMPT_DESCRIPTION = "Returns the manifest constraint and the declared parameters."


def _messages(name: str, parameters: dict[str, str]) -> list:
    text = render_prompt_body(name, parameters)
    return [{"role": "user", "content": {"type": "text", "text": text}}]


def register_prompt_handlers(mcp, counter, logger):
    """Register the six manifest prompts."""

    @mcp.prompt(name="plan_pentest", description=_PROMPT_DESCRIPTION)
    def plan_pentest(target: str, scope: str = "full") -> list:
        """Return the manifest constraint and the declared parameters."""
        return _messages("plan_pentest", {"target": target, "scope": scope})

    counter.add("misc", 1)

    @mcp.prompt(name="analyze_findings", description=_PROMPT_DESCRIPTION)
    def analyze_findings(findings_json: str) -> list:
        """Return the manifest constraint and the declared parameters."""
        return _messages("analyze_findings", {"findings_json": findings_json})

    counter.add("misc", 1)

    @mcp.prompt(name="plan_attack_chain", description=_PROMPT_DESCRIPTION)
    def plan_attack_chain(
        target: str,
        vulnerabilities: str,
        access_level: str = "none",
    ) -> list:
        """Return the manifest constraint and the declared parameters."""
        return _messages(
            "plan_attack_chain",
            {
                "target": target,
                "vulnerabilities": vulnerabilities,
                "access_level": access_level,
            },
        )

    counter.add("misc", 1)

    @mcp.prompt(name="suggest_next_phase", description=_PROMPT_DESCRIPTION)
    def suggest_next_phase(
        current_phase: str,
        findings_summary: str,
        access_level: str = "none",
    ) -> list:
        """Return the manifest constraint and the declared parameters."""
        return _messages(
            "suggest_next_phase",
            {
                "current_phase": current_phase,
                "findings_summary": findings_summary,
                "access_level": access_level,
            },
        )

    counter.add("misc", 1)

    @mcp.prompt(name="write_report", description=_PROMPT_DESCRIPTION)
    def write_report(
        target: str,
        findings_json: str,
        report_type: str = "executive",
    ) -> list:
        """Return the manifest constraint and the declared parameters."""
        return _messages(
            "write_report",
            {
                "target": target,
                "findings_json": findings_json,
                "report_type": report_type,
            },
        )

    counter.add("misc", 1)

    @mcp.prompt(name="explain_vulnerability", description=_PROMPT_DESCRIPTION)
    def explain_vulnerability(vuln_type: str, context: str = "") -> list:
        """Return the manifest constraint and the declared parameters."""
        return _messages(
            "explain_vulnerability",
            {"vuln_type": vuln_type, "context": context},
        )

    counter.add("misc", 1)

    logger.info("MCP prompts registered: 6 constraint templates")
