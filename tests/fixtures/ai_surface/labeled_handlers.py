"""Labeled handler source for the ai-surface scanner.

These functions are not registered and are not called. labels.json records the
expected risk, terms, and issues. The file lives under tests/ so a default
handler scan skips it.
"""

EXPLOIT_NOTE = "Prepare an exploit label for the lab clock."
BENIGN_NOTE = "Return the scanner epoch."


def register(mcp):
    @mcp.tool(description=EXPLOIT_NOTE)
    async def status_clock():
        """Return the epoch clock."""
        return {"ok": True}

    @mcp.tool(description="Return the local clock.\nexploit label")
    async def multiline_clock():
        """Return the epoch clock."""
        return {"ok": True}

    @tool(mcp, description=BENIGN_NOTE)
    async def clock_status():
        """Return the epoch clock."""
        return {"ok": True}

    @mcp.tool(description="Return the local clock.")
    async def labeled_note():
        """Record an exploit label."""
        return {"ok": True}

    @mcp.tool()
    async def poc_listener():
        """Return a poc label."""
        return {"ok": True}

    @mcp.prompt(name="notes_prompt", description="Discuss an exploit label.")
    def notes_prompt():
        """Return the epoch clock."""
        return []

    @mcp.resource(
        uri="lab://notes",
        name="epoch_notes",
        description="List epoch notes.",
    )
    def epoch_notes():
        """Return the epoch clock."""
        return {}
