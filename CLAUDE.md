# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AutoRedTeam-Orchestrator is an AI-driven automated penetration testing framework based on Model Context Protocol (MCP). It provides 130+ pure Python security tools covering OWASP Top 10, API Security, Supply Chain Security, and Cloud Native Security. Designed for seamless integration with AI editors (Windsurf/Cursor/Claude Desktop/Kiro).

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

# CVE operations
python core/cve/update_manager.py sync              # Multi-source sync
python core/cve/update_manager.py search "Log4j"   # CVE search
python core/cve/ai_poc_generator.py --help         # AI PoC generation
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
        │   ├── c2/ (Beacon/DNS/HTTP/WebSocket隧道)
        │   ├── evasion/ (混淆免杀)
        │   ├── stealth/ (流量混淆/代理池)
        │   ├── exploit/ (SQLi/端口扫描)
        │   ├── persistence/ (Windows/Linux持久化)
        │   ├── credential/ (凭证提取)
        │   ├── ad/ (AD域渗透)
        │   └── cve/ (CVE情报/PoC引擎)
        │
        └── modules/
            ├── api_security/ (JWT/CORS/GraphQL/WebSocket)
            ├── supply_chain/ (SBOM/依赖扫描/CI-CD)
            ├── cloud_security/ (K8s/gRPC)
            ├── oob_detector.py
            ├── smart_payload_engine.py
            ├── vuln_verifier.py
            ├── js_analyzer.py
            └── redteam_tools.py
```

## Key Files

- **mcp_stdio_server.py**: Main MCP server entry point (130+ tools registered)
- **auto_recon.py**: Standalone reconnaissance engine
- **mcp_tools.py**: Legacy tool definitions
- **core/session_manager.py**: HTTP session with auth support
- **modules/redteam_tools.py**: Red Team MCP tool integration
- **utils/task_queue.py**: Async task queue (3 workers)
- **core/cve/update_manager.py**: CVE multi-source sync (NVD/Nuclei/Exploit-DB)
- **core/cve/ai_poc_generator.py**: AI-powered PoC generation

## MCP Tool Categories

Tools are registered in `mcp_stdio_server.py`. Main categories:

### Core
- `auto_pentest`, `pentest_phase`, `generate_report`, `smart_analyze`, `smart_pentest`

### Recon
- `port_scan`, `dns_lookup`, `http_probe`, `tech_detect`, `full_recon`
- `subdomain_bruteforce`, `dir_bruteforce`, `sensitive_scan`, `whois_query`

### Vuln Detection
- `sqli_detect`, `xss_detect`, `ssrf_detect`, `xxe_detect`, `cmd_inject_detect`
- `csrf_detect`, `lfi_detect`, `ssti_detect`, `idor_detect`
- `deserialize_detect`, `weak_password_detect`, `auth_bypass_detect`
- `jwt_vuln_detect`, `security_headers_check`, `cors_deep_check`

### API Security (v2.6+)
- `jwt_none_algorithm_test`, `jwt_algorithm_confusion_test`, `jwt_weak_secret_test`
- `jwt_kid_injection_test`, `jwt_full_scan`
- `cors_bypass_test`, `cors_preflight_test`
- `security_headers_score`, `security_headers_compare`, `security_headers_report`
- `graphql_introspection_test`, `graphql_batch_dos_test`, `graphql_deep_nesting_test`
- `graphql_field_suggestion_test`, `graphql_alias_overload_test`, `graphql_full_scan`
- `websocket_origin_bypass_test`, `websocket_cswsh_test`, `websocket_auth_bypass_test`
- `websocket_compression_test`, `websocket_full_scan`

### Supply Chain Security (v2.6+)
- `sbom_generate`, `sbom_summary` (CycloneDX/SPDX format)
- `dependency_audit`, `dependency_check_package`, `dependency_report`
- `cicd_security_scan`, `cicd_github_actions_scan`, `cicd_security_report`
- `supply_chain_full_scan`

### Cloud Native Security (v2.6+)
- `k8s_privileged_check`, `k8s_hostpath_check`, `k8s_rbac_audit`
- `k8s_network_policy_check`, `k8s_secrets_check`, `k8s_manifest_scan`, `k8s_full_scan`
- `grpc_reflection_test`, `grpc_tls_test`, `grpc_auth_test`, `grpc_full_scan`

### Red Team
- **Lateral**: `lateral_smb_exec`, `lateral_smb_upload`, `lateral_ssh_exec`, `lateral_ssh_tunnel`, `lateral_wmi_exec`, `lateral_wmi_query`
- **C2**: `c2_beacon_start`, `c2_dns_tunnel`, `c2_http_tunnel`, `tunnel_websocket_create`, `chunked_split`
- **Evasion**: `evasion_obfuscate_payload`, `evasion_obfuscate_python`, `evasion_shellcode_loader`
- **Stealth**: `stealth_request`, `stealth_proxy_pool`
- **Persistence**: `persistence_windows`, `persistence_linux`, `persistence_webshell`
- **Credential**: `credential_dump`, `credential_find_secrets`
- **AD**: `ad_enumerate`, `ad_kerberos_attack`, `ad_spn_scan`

### CVE Intelligence
- `cve_search`, `cve_detail`, `cve_recent`, `cve_sync`, `cve_search_advanced`, `cve_stats`
- `poc_execute`, `poc_list`, `poc_generator`

### JS/Frontend Analysis
- `js_analyze`, `js_extract_apis`, `js_extract_secrets`

### Task Queue
- `task_submit`, `task_status`, `task_cancel`, `task_list`

### AI Decision
- `smart_exploit_suggest`, `attack_chain_plan`, `ai_suggest_attack`, `ai_attack_chain`
- `ai_record_result`, `smart_payload`, `verify_vuln`

See README.md for complete tool list and usage examples.

## Adding New MCP Tools

1. Implement tool function in appropriate module under `modules/` or `core/`
2. Register in `mcp_stdio_server.py` using `@mcp.tool()` decorator
3. Follow existing patterns for error handling and return format
4. Add corresponding test in `tests/`

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
- **Error Handling**: Use specific exception types, avoid bare `except:` clauses
- **Async Compatibility**: Use Python 3.10+ asyncio APIs, avoid deprecated patterns
