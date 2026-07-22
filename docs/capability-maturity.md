# Capability Maturity

This document records what AutoRedTeam-Orchestrator currently provides and how strongly each
capability is supported. It is a product-status document, not a count of modules, decorators, or
source files.

The project is currently a **research preview**. A capability is not considered production-ready
only because an implementation exists in the repository.

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
| Python SDK and Typer CLI entry points | Beta | Validated primarily from a source checkout. |
| Local static AI/MCP surface scan | Preview | Read-only AST analysis; does not execute handlers. |
| Reconnaissance and vulnerability detectors | Beta | Authorized targets only; accuracy is not yet backed by a public benchmark. |
| JSON and SARIF export primitives | Beta | Finding and artifact schemas still need consolidation. |
| HTML reporting | Preview | Untrusted finding content needs escaping hardening before reports are broadly shared. |
| Session storage | Preview | Basic persistence exists; orchestrator checkpoint/resume remains Experimental. |
| MCP stdio integration | Preview | Defaults to a fail-closed `safe` registration profile; treat as trusted-local only because authentication is not yet a uniform global boundary. |
| AI-system red-team scenario runner | Preview | Plan-only dry-run; it does not request a target, model, shell, or tool. |
| Agent runtime models, policy, trace, and local API | Preview | Primarily plan-time governance metadata and read-only views. |
| Automated pentest orchestrator | Experimental | Defaults to dry-run; checkpoint/resume is not release-certified. |
| Docker sandbox executor | Experimental | An attached container executor reduces exposure; policy checks alone do not isolate execution. |
| External engine routing | Internal | `EngineRouter` is not the universal SDK/CLI/handler path today. |
| MCTS, knowledge, feedback, and agent-role research | Experimental | Research components without outcome-backed optimization claims. |
| All active/high-risk operations | Restricted Experimental | Includes exploit, privilege escalation, lateral, AD, post-exploit, persistence, C2, credential, external-tool execution, stealth/evasion, and exfiltration. |
| Multi-user campaigns, collaboration, and distributed execution | Planned | No supported contract yet. |

## Recommended usage profiles

These cumulative profiles are enforced when MCP surfaces are registered. They do not yet govern
direct CLI or SDK calls, and they do not replace authentication, target scope, independent approval,
or an isolated executor.

### Safe

- Static `ai-surface` analysis.
- AI red-team scenario planning in dry-run mode.
- Local finding export and deterministic evaluation.
- Metadata, local session state, SDK/CLI import, and schema development.
- Default MCP server profile; no target network access or host command execution is registered.

### Scan

- Includes the `safe` profile.
- Reconnaissance and vulnerability detection against an explicit local or owned target.
- Run from an isolated environment with outbound network controls.
- Record target authorization outside the tool until scope enforcement is unified.

### Active lab

- Includes the `scan` profile.
- Adds exploit validation and offensive planning, but excludes post-exploitation surfaces.
- Disposable lab only, with explicit independent approval and a real isolated executor.

### Full

- Includes every MCP surface, including lateral movement, persistence, C2, credential access,
  evasion, exfiltration, knowledge, and MCTS research components.
- Explicit opt-in for disposable, isolated, authorized environments only.

## Known limitations

- The recommended installation path is currently a source checkout; wheel and container release
  artifacts are not yet release-certified.
- The machine-readable capability manifest controls MCP registration only; CLI and SDK call paths
  do not yet share the same profile gate.
- Profiles filter surfaces after handler modules are imported and do not provide dependency or
  import-side-effect isolation.
- MCP authentication is applied by individual decorators rather than a uniform registration-layer
  boundary.
- MCP key provisioning does not yet have a stable operator CLI contract.
- Runtime policy and sandbox metadata do not automatically move execution into a container.
- The AI red-team runner produces planned attempts and `not_run` scores; it is not an autonomous
  target executor.
- The CLI `capabilities matrix` reports source-structure comparisons and must not be interpreted as
  this product maturity matrix.
- HTML reports may contain untrusted finding content and require isolated viewing until escaping is
  hardened.
- Checkpoint/resume, the universal external engine router, and bundled template/package-data flows
  require further integration testing.
- Windows is an intended platform, but CI does not yet provide a complete Windows matrix.

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
