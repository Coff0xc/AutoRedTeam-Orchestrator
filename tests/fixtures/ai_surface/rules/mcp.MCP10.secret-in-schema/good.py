def register(mcp):
    @mcp.tool()
    async def notes_read(api_key: str = ""):
        """Return the local notes."""
        return {}
