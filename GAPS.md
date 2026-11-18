# Gaps

Honest limits of the default product. Pair this page with `autort ai-surface ledger`.

The package version is `4.0.0` in `_version.py` only. The GitHub Action pin stays `Coff0xc/AutoRedTeam-Orchestrator@v3.1`.

## OWASP MCP Top 10

Offline map: `autort ai-surface ledger` (`autort.owasp.mcp/v1`). `network` is false. Source: [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/).

| ID | Status | Coverage | Limit |
|---|---|---|---|
| MCP01 Token Mismanagement & Secret Exposure | implemented | static | Env *names* and secret literals in schemas/skills. Values are unread. |
| MCP02 Privilege Escalation via Scope Creep | partial | partial | Capability profiles plus `declared_effects_omit_target_contact`. No runtime monitor of growing grants. |
| MCP03 Tool Poisoning | implemented | static | Description-as-instruction and hidden unicode. Drift is `ai-surface diff --ci`. |
| MCP04 Supply Chain & Dependency Tampering | implemented | static | Unpinned npx/uvx/pip and remote skill install steps. No package-registry query. |
| MCP05 Command Injection & Execution | implemented | static | Flags powershell/pwsh/cmd/bash/sh/python/node as a general interpreter. |
| MCP06 Intent Flow Subversion | implemented | static | Skill text that tries to override the agent. Tool-output injection is out of band. |
| MCP07 Insufficient Authentication & Authorization | implemented | static | Handler AST missing-auth gates. Remote MCP OAuth stays uncovered. |
| MCP08 Lack of Audit and Telemetry | gap | none | Third-party MCP run logs are unread. Stdio is not wrapped as a TOFU or telemetry gateway. |
| MCP09 Shadow MCP Servers | implemented | static | `ai-surface inventory` lists local client configs; remote `url` / `serverUrl` / `baseUrl` is flagged. |
| MCP10 Context Injection & Over-Sharing | implemented | static | Overlong tool text and secret literals in schema strings. Cross-task context is out of band. |

`mcp.MCP10.secret-in-schema` is shared between MCP01 and MCP10. Handler auth keeps rule ids `mcp_tool.auth-critical` / `mcp_tool.auth-missing`. Effect mismatch keeps `mcp_tool.effect-mismatch`.

MCP08 stays a gap on purpose. A runtime TOFU/stdio wrapper is out of scope for this increment.

## CLI

Default `autort --help` leads with `ai-surface`, `capabilities`, `skills`, and `engage`. `code-agent`, `runtime-api`, and `sandbox` stay callable and are hidden from that list.

`sandbox` on a run record is a note. It is not a container and it is not an operating-system boundary.

## Frozen

These stay paused. They are product stance.

- P3 offensive harness over catalog tools
- OrcaRouter GitHub PR #8
- Default LLM other than `none`
- New offensive MCP tool names, or a larger `RESIDENT_SURFACES`
- C2 (and the other experimental engines) in the published wheel
- Detector heuristics, payloads, and exploit engines
- Moving tag `v3.1`
- Windows CI Python 3.11, and slow/integration/network on Windows

## Catalog external tools

`ext_nmap_scan`, `ext_nuclei_scan`, `ext_sqlmap_scan`, `ext_ffuf_fuzz`, and `ext_masscan_scan` stay catalog-only. MCP signatures use named parameters and Literal presets/modes. Unbounded `extra_args` is not on the MCP schema; internally built flags still pass `validate_extra_args`. `ext_sqlmap_scan` `preset=exploit` and `ext_ffuf_fuzz` fail closed unless `confirmed=true`.

A public Arcade ToolBench card for this server is a 2026-09-22 crawl of those four `ext_*` wrappers. It is stale against the current schemas. This repo does not submit a rescore as part of the default product.

## Mixed-profile imports

Parent mixed-profile modules (`cve_handlers`, `ai_handlers`, `report_handlers`, `misc_handlers`, `prompt_handlers`, `resource_handlers`) still import under `safe` because they contain a safe surface. Scan and active-lab registrars live in sibling modules and import only when `surface_enabled_for_mcp` allows them. Manifest `handler` fields and MCP names are unchanged.

## Still open in the tree

- Checkpoint/resume integration tests
- Juice Shop live confirmation-rate demo
- Universal engine router (removed; handlers call the Python engines directly)
- Live `initialize` / `tools/list` comparison against a running server
- A proxy in front of other MCP servers
