# Capability Maturity

This document records what AutoRedTeam-Orchestrator currently provides and how strongly each
capability is supported. It is a product-status document, not a count of modules, decorators, or
source files.

The project is currently a **research preview**. A capability is not considered production-ready
only because an implementation exists in the repository. The OWASP MCP Top 10 coverage table
is [GAPS.md](../GAPS.md); `autort ai-surface ledger` prints the same map.

## Status definitions

| Status | Meaning |
|---|---|
| Beta | Usable from a source checkout, with focused tests and a documented interface. |
| Preview | Useful for local evaluation, but contracts or security boundaries may still change. |
| Experimental | Restricted to disposable labs; end-to-end behavior is not release-certified. |
| Restricted Experimental | Active/high-risk functionality for disposable authorized labs only. |
| Internal | Scaffolding or a partial implementation that should not be advertised as a user feature. |
| Planned | Direction only; no supported user contract exists yet. |

## Current matrix

| Capability | Status | Current boundary |
|---|---|---|
| Python SDK and Typer CLI entry points | Beta | Validated primarily from a source checkout. Default `--help` leads with `ai-surface`, `capabilities`, `skills`, and `engage`. `code-agent`, `runtime-api`, and `sandbox` stay callable and are hidden from that list. |
| Local static AI/MCP surface scan | Preview | Read-only AST analysis of FastMCP `@tool` / `@prompt` / `@resource`, low-level `Tool(...)`, and `DetectorConfig` factory names. Factory tools have no inline function body, so they are accounted for by config name. `--exclude-tests` is the default. `--reconcile` (automatic for the repo root and `handlers/`) reports manifest coverage. SARIF findings carry `properties.tool_name`, `properties.owasp_mcp`, and risk-class `ruleId`s (`mcp.MCP01.secret-env-key`, `mcp.MCP03.*`, `mcp.MCP04.*`, `mcp.MCP05.general-command`, `mcp.MCP09.remote-endpoint`, `mcp.MCP10.*`). Handler auth stays `mcp_tool.auth-*` (MCP07). Effect mismatch stays `mcp_tool.effect-mismatch` (MCP02). `autort ai-surface ledger` (`autort.owasp.mcp/v1`) is the offline Top 10 map; MCP08 is a documented gap. Skill scans emit named rule ids (`skill.prompt_injection`, `skill.hardcoded_secret`, `skill.suspicious_download_url`, `skill.unverifiable_remote_code`, `skill.missing_skill_md`). `skills read` still withholds the body when a finding is critical. Operator-stop markers stay separate. The scan does not execute handlers. `autort ai-surface diff --ci` exits 2 when a surface is added, removed, or has a changed first-line description or argument list against a saved JSON baseline. This repository pins `handlers/` at `tests/fixtures/ai_surface/handlers.baseline.json`. `autort ai-surface inventory` (`autort.inventory/v1`) lists documented client configs and skill roots without starting a server or copying env values or remote URLs. |
| Reconnaissance and vulnerability detectors | Beta | Authorized targets only; accuracy is not yet backed by a public benchmark. |
| JSON and SARIF export primitives | Beta | Finding and artifact schemas still need consolidation. |
| HTML reporting | Preview | Jinja2 HTML, executive, and Markdown templates render with `autoescape=True`. JSON report files encode `<>&` as Unicode escapes; `json.loads` recovers original finding text. |
| Session storage | Preview | Basic persistence exists. Orchestrator checkpoint persist/resume is pinned with stubbed executors on `tmp_path` `SessionStorage`; it is not a live-target run. |
| MCP stdio integration | Preview | Defaults to a fail-closed `safe` registration profile; treat as trusted-local only because authentication is not yet a uniform global boundary. CI pins JSON-RPC `initialize` / `tools/list` to resident surfaces through an in-process client; it does not spawn the stdio server. |
| AI-system red-team scenario runner | Internal (`run`); Preview (`eval-run`) | `ai-redteam run` is plan-only Internal. `eval-run` scores local scanners and instruction text (`autort.eval/v1`). It does not call a model, shell, or remote target. |
| Agent runtime models, policy, trace, and local API | Preview | Hidden from default CLI help; still callable. `runtime-api run --local --ci` is the allowlisted audit loop. Engage steps in that loop are dry-run unless the action opts into network and the sandbox allows it. It does not call a model or a shell. |
| Authorized engagement loop | Preview | `autort engage` / MCP `engage_*` / `autort.Engagement`. Heuristic planner (optional LLM pick among remaining steps). Evidence gate plus a three-repeat doom-loop stop. Live `engage.verify` uses HITL when the engagement `hitl` field is `approval` or `review_edit`; dry-run skips it. Live `engage_run` is `scan`. Profile `safe` is refused as an engagement profile. The run JSON includes `scorecard` (`autort.engage.scorecard/v1`: confirmed / unconfirmed / total, plus unverified, contradicted, confirmation_rate, proof, and gaps). An empty finding list is `no_findings_is_not_clean`, not a clean target. CI smokes `engage run --dry-run --ci`. |
| Automated pentest orchestrator | Experimental | Defaults to dry-run. Checkpoint persist/resume is tested with stubbed phases and is not release-certified. |
| Docker sandbox executor | Experimental | Hidden from default CLI help; still callable. `sandbox` on a run is a record field. `docker-smoke` is a local check with the network off. Policy metadata is not isolation. |
| External engine routing | Planned | No backend-selection layer exists: `core/engine_router.py` had zero callers and unreachable external-tool branches, and has been removed. Handlers and the SDK call the pure-Python engines directly. |
| MCTS, knowledge, feedback, and agent-role research | Experimental | Research components without outcome-backed optimization claims. |
| All active/high-risk operations | Restricted Experimental | Includes exploit, privilege escalation, lateral, AD, post-exploit, persistence, C2, credential, external-tool execution, stealth/evasion, and exfiltration. |
| Multi-user campaigns, collaboration, and distributed execution | Planned | No supported contract yet. |

## Recommended usage profiles

These cumulative profiles are enforced when MCP surfaces are registered and when a CLI or SDK
call maps to a manifest surface. A direct import of `core` outside those entries stays ungated.
The profile does not replace authentication, target scope, independent approval, or an isolated
executor.

### Safe

- Static `ai-surface` analysis.
- AI red-team scenario planning in dry-run mode.
- Local finding export and deterministic evaluation.
- Metadata, local session state, SDK/CLI import, and schema development.
- Default MCP server profile; no target network access or host command execution is registered.
- Engagement plan tools (`engage_init`, `engage_status`, `engage_next`) and `engage run --dry-run`.
  `engage_next` / `plan_next` return aggregator steps from open state gaps.

### Scan

- Includes the `safe` profile.
- Reconnaissance and vulnerability detection against an explicit local or owned target.
- Live `engage_run` against that same scoped target.
- Run from an isolated environment with outbound network controls.
- Record written target authorization and set `AUTORT_TARGET_ALLOWLIST` when contacting a host.

### Active lab

- Includes the `scan` profile.
- Adds exploit validation and offensive planning, but excludes post-exploitation surfaces.
- Disposable lab only, with explicit independent approval and a real isolated executor.

### Full

- Includes every MCP surface, including lateral movement, persistence, C2, credential access,
  evasion, exfiltration, knowledge, and MCTS research components.
- Explicit opt-in for disposable, isolated, authorized environments only.

## Known limitations

- The recommended installation path is a source checkout. The published wheel and the GHCR image
  omit the same experimental engine packages. Neither artifact is release-certified.
- CLI, SDK, and MCP share `resolve_profile` and each surface's minimum profile. Under `safe`,
  those entry points refuse higher surfaces before importing the mapped engine. The gate is not
  authentication, target scope, approval, or process isolation, and direct `core` imports outside
  those entry points stay ungated.
- Mixed-profile parent handler modules (cve, ai, report, resources, prompts, misc) still
  import when they contain a safe surface. Scan and active-lab registrars live in sibling
  modules and import only when the profile enables them. Higher-profile surfaces stay
  undefined under `safe` or `scan`: `cve_auto_exploit`, `smart_analyze` / `attack_chain_plan`,
  `generate_report`, `js_analyze`, `plan_pentest` / `plan_attack_chain` / `suggest_next_phase`,
  `active_sessions`, and `payload_library`. `core.cve` exports load on access, and
  `runtime_helpers` does not import `agent_runtime` until a tool runs. Direct `core` imports
  outside MCP/CLI/SDK entry points stay ungated.
- MCP authentication is enforced at the registration wrapper from the capability manifest
  (`auth_required`) plus decorator rank, for tools, prompts, and resources. HITL stays on
  tools. A prompt denial returns `AUTH_REQUIRED` and does not echo caller parameters.
  Catalog-only prompts and resources stay off the MCP lists until `tool_enable` registers
  the already-wrapped catalog callable; enabling a surface does not skip `AUTH_REQUIRED`.
- MCP API keys are issued with `autort capabilities auth-key`. The secret is printed once;
  the store keeps only the hash.
- Runtime policy and sandbox metadata do not automatically move execution into a container.
- The AI red-team runner produces planned attempts and `not_run` scores; it is not an autonomous
  target executor. The eval contract scores local scanners and instruction text against labels; it
  does not probe live models. The runtime loop executes allowlisted local audit steps
  (`ai_surface.scan`, `ai_surface.scan_skills`, `ai_surface.scan_mcp_config`, `skill.read`,
  `eval.document`) and, when enabled, resident aggregators (`recon_run`, `detect_run`,
  `verify_finding`, `nuclei_scan`, `export_findings`). Aggregator dry-run does not
  contact a target; live aggregator steps need `scan` and a target allowlist.
  Unknown steps, shells, and model calls fail closed.
- The CLI `capabilities matrix` reports source-structure comparisons and must not be interpreted as
  this product maturity matrix.
- HTML, executive, and Markdown reports escape finding strings. JSON report files encode `<>&`
  as Unicode escapes so a raw payload cannot execute if the file is viewed as HTML; `json.loads`
  recovers original finding text. `to_dict()` stays unescaped for programmatic consumers.
- The default wheel ships `core/skills/pins.yaml`. `autort skills catalog` on an installed
  wheel reads that pin table and does not vendor skill bodies or clone. Repo-root
  `templates/` CVE YAML stays checkout-only. Orchestrator checkpoint persist/resume is
  pinned with stubbed executors on `tmp_path` `SessionStorage`; it does not run a live
  target. The universal external engine router was removed.
- Windows CI runs the fast suite on Python 3.10 and 3.12 (`windows-latest`, no
  `--maxfail`). Slow, integration, and network tests stay out of that job. Ubuntu
  covers 3.10/3.11/3.12 with the same marker set and also has no `--maxfail`.
- MCP08 (Lack of Audit and Telemetry) is a documented gap: third-party MCP run
  logs are unread, and stdio is not wrapped as a TOFU or telemetry gateway.
  MCP02 is partial: capability profiles plus effect-mismatch, with no runtime
  monitor of growing grants. See [GAPS.md](../GAPS.md).
- Catalog-only `ext_nmap_scan` / `ext_nuclei_scan` / `ext_sqlmap_scan` /
  `ext_ffuf_fuzz` / `ext_masscan_scan` take named parameters and Literal
  presets/modes. Unbounded `extra_args` is not on the MCP schema; internally
  built flags still pass `validate_extra_args`. Sqlmap `preset=exploit` and
  ffuf fail closed unless `confirmed=true`. See [GAPS.md](../GAPS.md).

## Promotion criteria

A capability can move toward stable support only after it has all of the following:

1. A documented public contract and owner.
2. Fresh-install and entry-point verification.
3. End-to-end tests that avoid mock-only success paths.
4. Explicit authentication, target scope, approval, and audit behavior where relevant.
5. A real execution boundary for active or high-risk operations.
6. Supported-platform CI and failure-path coverage.
7. Documentation generated from, or checked against, the same source of truth.

## Target product model

The intended control flow is:

```text
principal -> capability profile -> authorization -> target scope
          -> approval token -> isolated executor -> artifact/evidence -> audit/report
```

Until that flow is unified across MCP, CLI, and SDK, high-risk capabilities remain restricted
experimental features.
