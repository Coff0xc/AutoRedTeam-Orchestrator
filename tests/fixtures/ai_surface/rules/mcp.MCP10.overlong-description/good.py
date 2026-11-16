def register(mcp):
    @mcp.tool()
    async def clock_status():
        """Return the local clock."""
        return {}
