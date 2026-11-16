def register(mcp):
    @mcp.tool()
    async def notes_read(api_key: str = "sk-live-fixturevalueonly"):
        """Return the local notes."""
        return {}
