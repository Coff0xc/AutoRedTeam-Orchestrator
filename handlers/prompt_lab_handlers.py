"""Active-lab prompt surfaces. Imported only when the profile allows them."""

from .prompt_handlers import _messages

_PROMPT_DESCRIPTION = "Returns the manifest constraint and the declared parameters."


def register_lab_prompts(mcp, logger) -> int:
    registered = 0

    @mcp.prompt(name="plan_pentest", description=_PROMPT_DESCRIPTION)
    def plan_pentest(target: str, scope: str = "full") -> list:
        """Return the manifest constraint and the declared parameters."""
        return _messages("plan_pentest", {"target": target, "scope": scope})

    registered += 1

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

    registered += 1

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

    registered += 1
    return registered
