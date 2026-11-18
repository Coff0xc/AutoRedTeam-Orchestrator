"""MCP prompt handlers.

Each prompt returns the capability-manifest constraint and the caller's
declared parameters. Registration replaces the schema description with the
same manifest text.
"""

from __future__ import annotations

from core.capability_manifest import render_prompt_body, surface_enabled_for_mcp

_PROMPT_DESCRIPTION = "Returns the manifest constraint and the declared parameters."


def _messages(name: str, parameters: dict[str, str]) -> list:
    text = render_prompt_body(name, parameters)
    return [{"role": "user", "content": {"type": "text", "text": text}}]


def register_prompt_handlers(mcp, counter, logger):
    """Register the six manifest prompts."""

    registered = 0
    if surface_enabled_for_mcp(mcp, "prompt", "plan_pentest"):
        from .prompt_lab_handlers import register_lab_prompts

        registered += register_lab_prompts(mcp, logger)

    @mcp.prompt(name="analyze_findings", description=_PROMPT_DESCRIPTION)
    def analyze_findings(findings_json: str) -> list:
        """Return the manifest constraint and the declared parameters."""
        return _messages("analyze_findings", {"findings_json": findings_json})

    registered += 1

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

    registered += 1

    @mcp.prompt(name="explain_vulnerability", description=_PROMPT_DESCRIPTION)
    def explain_vulnerability(vuln_type: str, context: str = "") -> list:
        """Return the manifest constraint and the declared parameters."""
        return _messages(
            "explain_vulnerability",
            {"vuln_type": vuln_type, "context": context},
        )

    registered += 1
    counter.add("misc", registered)
    logger.info("MCP prompts registered: %s constraint templates", registered)
