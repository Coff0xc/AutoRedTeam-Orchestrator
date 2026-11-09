# CVE intelligence

Handlers import `CVEUpdateManager` from `core.cve.update_manager`. Search and storage live in `search.py`, `storage.py`, and `manager.py`.

These files are not part of that path and were removed because nothing imported them:

- `examples.py`
- `mcp_integration.py`
- `subscription_manager.py`

MCP CVE tools are registered from `handlers/cve_handlers.py`.
