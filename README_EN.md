# AutoRedTeam-Orchestrator

**A local-first, MCP-native security automation workbench for authorized testing and AI/MCP
engineering teams.**

[中文](README.md) · [Capability Maturity](docs/capability-maturity.md) ·
[Security Model](docs/security-model.md) · [Security Audits](docs/security-audits/)

> **Status: Beta / Research Preview**
>
> The project prioritizes static analysis, dry-runs, local labs, and auditable engineering
> workflows. All active or high-risk capabilities, including exploit, privilege escalation,
> lateral movement, AD, post-exploit, persistence, C2, credential, external-tool execution,
> stealth/evasion, and exfiltration, are restricted experimental surfaces. Policy or sandbox
> metadata is not an operating-system or container isolation boundary.

AutoRedTeam-Orchestrator provides overlapping Python core capabilities in one repository and exposes
them through three entry points:

- **MCP Server** for AI editors and agents that support MCP.
- **Python SDK** for composing recon, detection, orchestration, and reporting.
- **Typer CLI** for local analysis, dry-runs, authorized scans, reports, and diagnostics.

The project currently fits authorized labs, security automation development, AI/MCP surface
analysis, CTFs, education, and local fixtures. It is not a turnkey enterprise platform, an
autonomous attacker, or a production C2 system.

The primary product line is **AI-assisted security automation**: an AI editor or agent uses
controlled security capabilities through MCP. The `ai-redteam` command is an **AI-system red
teaming** Preview track and currently generates plans only.

## What it is

- An MCP-native security capability adapter and orchestration framework.
- A local static-analysis workbench for AI Agent, MCP, and Skill surfaces.
- An extensible Python base for detectors, tool adapters, workflows, and reports.
- An evolving controlled-execution model built around policy, run state, traces, approval, and
  artifacts.

## What it is not

- It is not a replacement for Nmap, Nuclei, sqlmap, Burp/ZAP, or Metasploit.
- It is not a completed autonomous pentest platform.
- It is not a multi-tenant, remotely shared, enterprise campaign service.
- It is not a production C2, stealth, or defense-evasion product.
- The current AI-system red-team runner is a **plan-only dry-run**. It does not request a scenario
  target, model, shell, or tool.

## Five-minute safety-first start

A source checkout is currently the recommended execution path. Python 3.10+ is required.

```bash
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator
pip install -r requirements.txt
python -m cli.main --help
```

### 1. Inspect the local MCP / AI tool surface

This command parses local Python source without importing or executing handlers:

```bash
python -m cli.main ai-surface scan --path handlers -o surface.json
```

### 2. Verify the SDK and capability catalog

```bash
python -c "from autort import Scanner; print('SDK import OK')"
python -m cli.main ai-redteam catalog
```

### 3. Optional: generate an AI-system red-team Preview plan

The bundled scenario points only to localhost. The runner generates attempts, scores, and traces
without requesting the target:

```bash
python -m cli.main ai-redteam run config/ai_redteam.example.yaml -o run.json
```

## Three entry points

| Entry point | Path | Current position |
|---|---|---|
| MCP Server | `mcp_stdio_server.py` | Preview; trusted-local stdio only |
| Python SDK | `autort/` | Beta from a source checkout |
| Typer CLI | `cli/main.py` | Beta; primary local-analysis and development entry |

Common read-only or dry-run commands:

```bash
python -m cli.main ai-surface scan --path handlers
python -m cli.main ai-redteam run config/ai_redteam.example.yaml
python -m cli.main ai-redteam catalog
python -m cli.main code-agent expand --path core
python -m cli.main capabilities manifest --profile safe
```

## Capability maturity

| Capability | Status | Boundary |
|---|---|---|
| SDK / CLI entry points | Beta | Primarily validated from a source checkout |
| Recon, detection, and JSON/SARIF output | Beta | Authorized targets only; no public accuracy benchmark yet |
| HTML reporting | Preview | Escaping for untrusted finding content still needs security hardening |
| Session storage | Preview | Basic persistence exists; orchestrator resume remains Experimental |
| AI/MCP static surface scan | Preview | Read-only AST analysis |
| MCP stdio | Preview | Trusted-local only; authentication is not yet a uniform global boundary |
| AI-system red-team scenario runner | Preview | Plan-only dry-run; no target or model requests |
| Agent runtime, policy, trace, and local API | Preview | Primarily plan-time governance metadata |
| Automated pentest orchestrator | Experimental | Defaults to dry-run; resume is not release-certified |
| Docker executor | Experimental | An explicit container executor reduces exposure but is not a complete security boundary |
| All active/high-risk operations | Restricted Experimental | Disposable isolated labs only |
| Multi-user campaigns / distributed execution | Planned | No supported contract yet |

See [Capability Maturity](docs/capability-maturity.md) for definitions, known limitations, and
promotion criteria.

## Actual architecture

```text
AI Editor / Operator
        |
        +-- MCP stdio --> capability profile --> handlers/-+
        |                                                  |
        +-- Python SDK ------ autort/ ----------------------+--> core/
        |                                                  |    recon
        +-- Typer CLI ------- cli/main.py ------------------+    detectors
                                                                  tools
Safe local paths:                                                reporting
  ai-surface -> read-only AST scan                               session
  ai-redteam -> plan-only dry-run

Orchestrated path:
  AutoPentestOrchestrator -> RuntimePipeline -> PhaseExecutor -> core
                            policy / trace       dry-run by default
```

Important boundaries:

- Some legacy SDK and handler paths still call core directly and do not share one runtime executor.
- `RuntimePipeline` policy and sandbox decisions are governance records; they do not create a
  container.
- `EngineRouter` is not currently the universal SDK, CLI, and handler production path.
- MCP capability profiles filter tools, resources, and prompts during registration, but they do not
  replace authentication, target scope, independent approval, or an isolated executor.
- MCP authentication is attached by individual decorators and is not yet a global boundary for
  every registered surface.

See [Security Model](docs/security-model.md) for the complete operating assumptions.

## Authorized scan examples

The following commands create network traffic. Use them only against localhost, a disposable lab,
or a target covered by written authorization.

```bash
python -m cli.main scan http://127.0.0.1:8000 --full
python -m cli.main detect http://127.0.0.1:8000 -c sqli,xss,ssrf
python -m cli.main nuclei http://127.0.0.1:8000 --severity high,critical
python -m cli.main pentest http://127.0.0.1:8000 --phases recon,vuln_scan,report
```

Do not run high-risk phases on a workstation that contains real credentials, source code, or user
files. Use a disposable VM or container, explicit network controls, and independent approval.

## MCP usage

Start the stdio server:

```bash
python mcp_stdio_server.py --stdio
```

The MCP server uses the fail-closed `safe` profile by default. Inspect the profile definitions and
effective manifest before selecting a broader profile:

```bash
python -m cli.main capabilities profiles
python -m cli.main capabilities manifest --profile safe
```

| Profile | Registration boundary |
|---|---|
| `safe` | Local static analysis, dry-run, metadata, and controlled local state; no target network or host command |
| `scan` | `safe` plus authorized reconnaissance, vulnerability scanning, and external scanners |
| `active-lab` | `scan` plus exploit validation and offensive planning; requires a disposable isolated lab and independent approval |
| `full` | Every surface, including post-exploitation, credentials, C2, persistence, evasion, and exfiltration; explicit opt-in only |

An unknown profile fails before any surface is registered. Profiles control MCP schema exposure
only; they do not move in-process calls into a container or replace written authorization, a
network allowlist, or request-scoped RBAC.
`safe` still inherits the launching process's filesystem permissions. Local analysis tools with
path parameters can read caller-selected accessible files, so this profile is for trusted local
clients only.

Current MCP security assumptions:

- The client and server belong to the same trusted local user.
- The server inherits the file and network permissions of the launching process.
- The server is not exposed through a remote, shared, or multi-tenant transport.
- `AuthManager` supports key objects, but there is no stable operator CLI provisioning contract.
- Setting an arbitrary string is not sufficient, and API keys must not be treated as a remote
  deployment security boundary.
- Until registration-layer authentication is complete, `strict` does not mean every tool, resource,
  and prompt is protected.

Relevant environment variables:

| Variable | Description |
|---|---|
| `AUTOREDTEAM_AUTH_MODE` | `strict` or `permissive`; defaults to `strict` |
| `AUTOREDTEAM_API_KEY` | MCP API key |
| `MCP_API_KEY` | Compatibility variable for the MCP API key |
| `AUTORT_CAPABILITY_PROFILE` | `safe`, `scan`, `active-lab`, or `full`; MCP defaults to `safe` |

## Python SDK

This example uses a local authorized target:

```python
import asyncio

from autort import Scanner


async def main() -> None:
    scanner = Scanner("http://127.0.0.1:8000")
    recon = await scanner.full_recon()
    findings = await scanner.detect_vulns(categories=["sqli", "xss", "ssrf"])
    print(recon)
    print(findings)


asyncio.run(main())
```

`AutoPentest` currently inherits the orchestrator's default dry-run runtime configuration. All
active or high-risk `Exploiter`, `RedTeam`, AD, post-exploit, and external-tool APIs are restricted
experimental surfaces.

## Installation and configuration

### Dependency layers

```bash
# Minimal MCP dependencies
pip install -r requirements-core.txt

# Full source-checkout dependencies
pip install -r requirements.txt

# Development also requires this additive file (it does not include runtime dependencies)
pip install -r requirements-dev.txt
```

Use a source checkout for now. Wheel and container artifacts are not marked release-certified until
fresh-install validation is in place.

### Optional LLM configuration

| Variable | Default | Description |
|---|---|---|
| `AUTORT_LLM_PROVIDER` | `none` | `openai`, `anthropic`, or `none`; other providers are Preview |
| `AUTORT_LLM_MODEL` | Provider default | Model name |
| `AUTORT_LLM_API_KEY` | Empty | API key |
| `AUTORT_LLM_BASE_URL` | Empty | Custom compatible endpoint |

Declared dependencies cover the direct OpenAI and Anthropic SDK paths. Ollama, DeepSeek, and custom
`base_url` behavior do not yet have a unified dependency and end-to-end support contract.

Configuration examples:

- `config/config.yaml.example`
- `config/external_tools.yaml.example`
- `config/ai_redteam.example.yaml`
- `.env.example`

## Verification and development

Start narrow, then expand:

```bash
python -m pytest tests/test_sdk.py tests/test_cli.py -q
python -m pytest tests/test_mcp_server_smoke.py -q
```

Quality checks:

```bash
black core/ handlers/ utils/ autort/ cli/
isort core/ handlers/ utils/ autort/ cli/
flake8 core/ handlers/ utils/
mypy core/ handlers/ utils/
bandit -r core handlers utils -c .bandit
pre-commit run --all-files
```

Network, OOB, Docker, external-tool, and active-capability tests should run in isolated jobs rather
than the regular unit suite.

## Known limitations

- CI, Docker, wheel, package-data, and the Windows matrix still require release hardening.
- MCP surfaces now have one machine-readable classification manifest, but profiles are not yet a
  unified CLI and SDK call boundary.
- Profiles filter surfaces after handler modules are imported; they are not a minimal-dependency or
  import-side-effect isolation mechanism.
- MCP RBAC, target scope, approval, and execution are not yet one unified control chain.
- MCP key provisioning has no stable operator CLI contract.
- Checkpoint/resume and bundled Nuclei template discovery are not release-certified.
- HTML report rendering still needs escaping hardening for untrusted finding content.
- AI-system red-team scores are currently primarily `not_run` records, not target evaluations.
- `capabilities matrix` is a source-structure comparison, not proof of product maturity or
  production readiness.
- MCTS, knowledge, and agent-role components are research surfaces.

See [Capability Maturity](docs/capability-maturity.md).

## Roadmap

### Now

- Extend the capability manifest into one request-time policy shared by MCP, CLI, and SDK paths.
- Unify principal, RBAC, target scope, action-bound approval, executor, and audit.
- Repair CI, Docker, wheel, package-data, version, and resume contracts.
- Unify Finding, Artifact, Evidence, RunState, and Report schemas.

### Next

- Deepen AI/MCP surface policy linting, SARIF, and CI integration.
- Add real AI target adapters, response capture, scorers, baselines, and regression evaluation.
- Add a persistent evidence store, artifact provenance, and retention.
- Provide one external-tool adapter SDK with conformance tests.

### Later

- Evolve MCTS, knowledge, and multi-agent recommendations from real outcome data.
- Add multi-target campaigns, a Web UI, collaboration, and distributed executors.

## Contributing

Recommended checks before submitting a change:

```bash
python -m pytest tests/test_sdk.py tests/test_cli.py -q
python -m pytest tests/test_mcp_server_smoke.py -q
pre-commit run --all-files
```

Do not include real targets, credentials, or exploit data in public issues. Changes to execution or
security boundaries should update [Security Model](docs/security-model.md) and
[Capability Maturity](docs/capability-maturity.md).

## License and disclaimer

This project is licensed under the MIT License. See `LICENSE`.

This software is provided only for explicitly authorized security testing, internal validation,
education, local labs, and dry-runs. Users must follow applicable laws and obtain written
authorization from the target owner. Unauthorized scanning, exploitation, persistence,
exfiltration, destructive activity, and evasion of law-enforcement or security controls are
prohibited.
