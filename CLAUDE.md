# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AutoRedTeam-Orchestrator is an AI-driven automated penetration testing framework based on Model Context Protocol (MCP). It provides 100+ pure Python security tools covering OWASP Top 10, designed for seamless integration with AI editors (Windsurf/Cursor/Claude Desktop/Kiro).

Requirements: Python 3.10+, Windows/Linux/macOS (no external tools required)

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run MCP server (used by AI editors)
python mcp_stdio_server.py

# Run standalone auto recon
python auto_recon.py

# Run tests
python tests/test_v25_integration.py
python tests/test_poc_engine.py
```

## Architecture

```
AI Editor (MCP Protocol)
        │
        ▼
mcp_stdio_server.py ─────► Tool Modules
        │                      │
        ├── core/              ├── lateral/ (SMB/SSH/WMI)
        │   ├── session_manager.py
        │   ├── c2/ (Beacon/DNS隧道)
        │   ├── evasion/ (混淆免杀)
        │   ├── stealth/ (流量混淆/代理池)
        │   └── exploit/ (SQLi/端口扫描)
        │
        └── modules/
            ├── oob_detector.py
            ├── smart_payload_engine.py
            ├── vuln_verifier.py
            └── redteam_tools.py
```

## Key Files

- **mcp_stdio_server.py**: Main MCP server entry point (100+ tools registered here)
- **auto_recon.py**: Standalone reconnaissance engine
- **mcp_tools.py**: Legacy tool definitions
- **core/session_manager.py**: HTTP session with auth support
- **modules/redteam_tools.py**: Red Team MCP tool integration
- **utils/task_queue.py**: Async task queue (3 workers)

## MCP Tool Categories

Tools are registered in `mcp_stdio_server.py`. Main categories:
- **Core**: `auto_pentest`, `pentest_phase`, `generate_report`, `smart_analyze`
- **Recon**: `port_scan`, `dns_lookup`, `http_probe`, `tech_detect`, `full_recon`
- **Vuln Detection**: `sqli_detect`, `xss_detect`, `ssrf_detect`, `xxe_detect`, `cmd_inject_detect`
- **Red Team**: `lateral_*` (横向移动), `c2_*` (C2通信), `evasion_*` (混淆), `stealth_*` (隐蔽)
- **Task Queue**: `task_submit`, `task_status`, `task_cancel`, `task_list`

See README.md for complete tool list.

## Adding New MCP Tools

1. Implement tool function in appropriate module under `modules/` or `core/`
2. Register in `mcp_stdio_server.py` using `@mcp.tool()` decorator
3. Follow existing patterns for error handling and return format

## Configuration

MCP config (`~/.claude/mcp.json` or `.mcp.json`):

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/mcp_stdio_server.py"]
    }
  }
}
```

## Language

Code comments and documentation are in Chinese (简体中文). Maintain this convention.

## Coding Guidelines (CRITICAL)

- **Cross-Platform**: Runs on Windows, Linux, macOS
- **Path Handling**: NEVER use hardcoded paths like `/tmp/`. Use `os.path.join()`, `pathlib.Path`, or `tempfile.gettempdir()`
- **Encoding**: Always specify `encoding='utf-8'` when opening files
- **External Tools**: Check availability with `shutil.which()` before execution
