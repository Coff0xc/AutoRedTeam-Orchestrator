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

## Live MCP protocol

`tests/test_mcp_protocol.py` opens an in-process `mcp.Client` in `mode=legacy` (JSON-RPC `initialize` over in-memory streams). `tools/list`, `prompts/list`, and `resources/list` match the resident set for each profile. The test does not spawn `python mcp_stdio_server.py --stdio`.

## Engagement scorecard

`autort.engage.scorecard/v1` keeps `confirmed` / `unconfirmed` / `total`. Additive fields: `unverified`, `contradicted`, `confirmation_rate` (null when `total` is 0), per-row `proof` (`bound` / `none`), and `gaps`. `proof=bound` only when `provenance.bound` carries a stored request/response receipt (`autort.engage.provenance/v1`). `no_findings_is_not_clean` is the empty-run gap so a dry-run cannot read as a clean target.

Juice Shop confirmation-rate: `autort engage confirmation-rate --url http://127.0.0.1:3000` after `docker compose -f docker-compose.lab.yml up -d`. It verifies `/rest/products/search?q=` (SQLi) and a homepage XSS self-report so the denominator has confirmed and unconfirmed rows. `--ci` exits 2 when `confirmation_rate` is 0 or empty. Default Windows/Ubuntu jobs skip this (`integration`/`network`). A loopback Juice Shop-shaped mock pins the contract in `tests/test_engage_juiceshop.py`.

## Orchestrator checkpoint/resume

`tests/test_orchestrator_checkpoint.py` persists `PentestState` through `SessionStorage` on `tmp_path` and rebuilds via `AutoPentestOrchestrator.resume`. Phase executors are stubbed. `resume` loads metadata (not the `ScanContext` envelope), restores `OrchestratorConfig`, and `run()` skips completed or skipped phases. Default dry-run still skips executors and does not create a phase checkpoint. The pin does not run a live target. `autort engage resume` is unchanged.

## Optional LLM framing

Default `AUTORT_LLM_PROVIDER` stays `none`. The planner is heuristic code. When a provider is set, `core/llm/prompts.py` prepends authorized-engagement rules and `wrap_untrusted` frames scan/state as a nonce `AUTORT_DATA` block (nested marker stems neutralized). Engage pick may only choose a coverage-open row that maps to a currently actionable step (`phase:detect` → `detect_run`, `finding:…` → `verify_finding`). Examined and ruled_out rows are closed. Unknown names fall back to the heuristic queue. Live `engage.verify` HITL stays in code; a HITL permit is not evidence. System prompts omit jailbreak strings so MCP03/`skill.prompt_injection` does not self-flag. Model refusal or an unknown step name falls back to the remaining list. This is refusal reduction plus injection framing. Default-open LLM driving attacks stays frozen. Tool-output injection at the MCP runtime stays out of band (MCP06/MCP10 limits above).

## RuntimeLoop aggregators

`autort runtime-api run` can dispatch `recon_run`, `detect_run`, `verify_finding`,
`nuclei_scan`, and `export_findings`. Example: `config/runtime.aggregators.example.yaml`
(dry-run). Live aggregator steps need `AUTORT_CAPABILITY_PROFILE=scan` and a target
allowlist. CI still smokes the audit plan (`runtime.local.example.yaml --local --ci`).
`plan_next` emits those aggregator names from open state gaps. Findings skip recon.
Unverified findings block export. `nuclei` is an optional phase, not a default.
`MODEL_CALL` in the runtime loop is only `engage.pick`. It uses `LLMProvider` and
`plan_next(..., use_model=True)`. Provider `none` raises and the action fails.
The pick set is coverage-open rows mapped to actionable aggregator steps. Shell
and browser kinds stay blocked. Default `AUTORT_LLM_PROVIDER` remains `none`.

Completed aggregator calls store `tool_execution_id` on `state["executions"]`. A later call with
the same name, inputs, and dry_run flag returns the saved output with `replay: true` and does
not contact the engine. Failed calls are omitted so a retry still runs. The engage doom-loop
(three identical planner fingerprints) is unchanged.

Aggregator steps also write `output_dir/world.sqlite` (`autort.engage.world/v1`).
The planner reads that index (assets/facts/findings/unverified keys), not recon JSON.
`engage status` and `engage run` include `autort.engage.coverage/v1`: examined / ruled_out / open
over in-scope phases, discovered ports, and findings. An empty finding list still has a phase
denominator; `coverage_rate` is null when total is 0.

## Still open in the tree

- Universal engine router (removed; handlers call the Python engines directly)
- A proxy in front of other MCP servers
