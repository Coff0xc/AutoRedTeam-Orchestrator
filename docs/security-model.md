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
- The same capability profile gates MCP registration and the CLI and SDK calls that map to a
  manifest surface. It is not authentication, target authorization, approval, or process isolation.
  Direct imports of core modules outside those entry points are not gated.
- API keys are process-level environment configuration, which is appropriate only for a trusted
  local client model.
- Do not expose the MCP server through an untrusted or shared transport.

### Capability profiles

The capability profiles are cumulative. MCP registration, the CLI, and the SDK all resolve
`AUTORT_CAPABILITY_PROFILE` the same way:

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
A handler module is imported only when the selected profile enables at least one of its
surfaces. `safe` therefore does not import modules that exist only for `scan`, `active-lab`,
or `full`. A module that mixes profiles is still imported as a unit; higher-profile functions
in that module are not registered.

The published wheel and the GHCR image omit `core.c2`, `core.lateral`, `core.persistence`,
`core.post_exploit`, `core.privilege_escalation`, `core.exfiltration`, `core.evasion`,
`core.credential`, `core.ad`, and `core.exploit`. Those packages stay in a source checkout.
The image installs that wheel, sets `AUTORT_CAPABILITY_PROFILE=safe`, and does not add host
scanner packages. A handler that needs an omitted package fails with `ImportError`.

Registered MCP descriptions and prompt return bodies come from the capability manifest. They
state the profile, risk, effects, and controls, plus the declared parameter values. They do not
copy procedures into the tool schema or the prompt body.

### Runtime policy and approval

- `ActionPolicy`, middleware decisions, run state, and traces are governance records.
- A policy or sandbox decision does not itself create an operating-system or container boundary.
- An approval flag supplied by the same caller that requests an action is not independent human
  approval.
- `AUTORT_HITL_MODE` (`off` | `approval` | `review_edit`) wraps MCP tools after profile
  registration. The default is `off`. `approval` and `review_edit` ask an independent
  approver before moderate-or-higher tools; a missing, timed-out, or failing approver
  denies and the tool body does not run. A same-process env flag is not that approver.
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

- `AUTORT_TARGET_SCOPE` (`off` | `enforce`) and `AUTORT_TARGET_ALLOWLIST` are one DNS-aware
  policy used by CLI constructors, SDK constructors, MCP `validate_inputs`, and `secure_tool`.
- The default is `off` (format and SSRF checks only). A non-empty allowlist turns the gate on
  even when the mode is `off`. `enforce` with an empty list denies every target. Unknown modes
  fail closed to `enforce`.
- Matching covers exact host, `*.suffix` / `.suffix`, IP, CIDR, and URL origin. Hostnames are
  resolved; private, loopback, link-local, and metadata IPs need an explicit IP or CIDR entry.
- Empty targets (CVE search) skip the gate. Direct `core` imports outside CLI, SDK, and MCP
  stay ungated.
- Treat redirects, DNS changes after the check, proxies, and metadata endpoints as separate
  authorization concerns. Keep an external network egress policy.

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
python -m cli.main ai-redteam eval-run config/ai_redteam.eval.example.yaml
python -m cli.main ai-redteam catalog
python -m cli.main capabilities manifest --profile safe
```

## Controls required for broader deployment

Before remote, shared, or enterprise deployment, the project requires:

- one request-time policy that enforces manifest metadata across MCP, CLI, and SDK paths;
- request-scoped principals instead of process-global identity;
- consistent RBAC for every tool, resource, and prompt;
- redirect enforcement after the DNS-aware allowlist check;
- action-bound, expiring approval tokens;
- mandatory isolated executors for active operations;
- immutable artifact provenance and durable audit storage;
- multi-tenant data isolation, rate limits, retention, and incident controls.

See [Capability Maturity](capability-maturity.md) for current feature status.
