# Security Model

AutoRedTeam-Orchestrator contains dual-use security capabilities. This document describes the
current trust boundary and the safe operating assumptions for the research-preview release.

## Intended environment

The supported operating model is a trusted, local, single-user process used for:

- explicitly authorized security testing;
- local fixtures, disposable labs, CTFs, and education;
- static AI/MCP surface analysis;
- dry-run planning and report development.

The project is not currently a multi-tenant service, a remote execution service, or a production C2
platform.

## Current trust boundary

### MCP

- The stdio server inherits the permissions and environment of the process that launches it.
- The server defaults to the fail-closed `safe` capability profile. Unknown profiles are rejected
  before any tool, resource, or prompt is registered.
- Profile filtering operates on each public MCP surface rather than on whole handler modules.
- Authentication is currently attached to individual tools; it is not a uniform registration-layer
  boundary for every tool, resource, and prompt.
- A capability profile controls schema exposure only. It is not authentication, target
  authorization, approval, or process isolation.
- API keys are process-level environment configuration, which is appropriate only for a trusted
  local client model.
- Do not expose the MCP server through an untrusted or shared transport.

### Capability profiles

The MCP registration profiles are cumulative:

| Profile | Registration boundary |
|---|---|
| `safe` | Local analysis, dry-run, metadata, and controlled local state; no target network or host command |
| `scan` | `safe` plus authorized reconnaissance, vulnerability scanning, and external scanners |
| `active-lab` | `scan` plus exploit validation and offensive planning |
| `full` | All surfaces, including post-exploitation and restricted research capabilities |

Select a broader profile with `AUTORT_CAPABILITY_PROFILE`. `active-lab` and `full` require a
disposable isolated environment, written target authorization, an external allowlist, and an
independent approval decision. The manifest records these requirements but does not enforce all of
them at request time.

`safe` means no registered target-network or host-command capability; it does not mean filesystem
isolation. Caller-selected paths can read any file available to the trusted local server process.
Profile filtering also happens after handler modules are imported, so it does not reduce the
import-time dependency set.

### Runtime policy and approval

- `ActionPolicy`, middleware decisions, run state, and traces are governance records.
- A policy or sandbox decision does not itself create an operating-system or container boundary.
- An approval flag supplied by the same caller that requests an action is not independent human
  approval.
- Safe active operation requires a separately attached executor and an external authorization
  decision. Current legacy SDK and handler paths do not enforce this universally.

### Sandbox

- An explicitly configured Docker executor can reduce host exposure through container isolation,
  but it is not a complete security boundary.
- A local fallback runs with the permissions of the host process and must not be described as a
  sandbox.
- Run active experiments in a disposable VM or container with no sensitive mounts, credentials, or
  unrestricted network access.

### Target scope

- Target strings are not yet checked by one universal authorization and DNS-resolution policy across
  all legacy handlers, SDK calls, and orchestrator phases.
- Maintain an explicit external allowlist and network egress policy.
- Treat redirects, DNS changes, proxies, and metadata endpoints as separate authorization concerns.

### Data and artifacts

- Reports, session state, traces, payloads, and operation audit logs may contain sensitive target
  data.
- Generated HTML reports may contain untrusted active content until output escaping is hardened;
  review them in an isolated browser context.
- Store outputs in a restricted directory and remove them according to the engagement retention
  policy.
- Do not run file-read, credential, persistence, or exfiltration experiments on a workstation that
  contains real secrets.

## Recommended safe workflow

1. Use a disposable local environment.
2. Start with `ai-surface` or an AI red-team dry-run scenario.
3. Record written authorization and an explicit target allowlist.
4. Use least-privilege credentials and deny network access by default.
5. Require an independent approval step before any active capability.
6. Attach a real isolated executor; do not rely on policy metadata as isolation.
7. Review artifacts and audit output before sharing or retaining them.

## Safe local commands

The following commands inspect local source or generate plans without contacting the scenario
target:

```bash
python -m cli.main ai-surface scan --path handlers -o surface.json
python -m cli.main ai-redteam run config/ai_redteam.example.yaml -o run.json
python -m cli.main ai-redteam catalog
python -m cli.main capabilities manifest --profile safe
```

## Controls required for broader deployment

Before remote, shared, or enterprise deployment, the project requires:

- one request-time policy that enforces manifest metadata across MCP, CLI, and SDK paths;
- request-scoped principals instead of process-global identity;
- consistent RBAC for every tool, resource, and prompt;
- DNS-aware target scope and redirect enforcement;
- action-bound, expiring approval tokens;
- mandatory isolated executors for active operations;
- immutable artifact provenance and durable audit storage;
- multi-tenant data isolation, rate limits, retention, and incident controls.

See [Capability Maturity](capability-maturity.md) for current feature status.
