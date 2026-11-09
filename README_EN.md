# AutoRedTeam-Orchestrator

**A local MCP/AI attack-surface audit and evidence gate.** The default registration profile is `safe`: static analysis, dry-run, and local metadata. Post-exploitation modules that belong only to a higher profile are not imported in that profile.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-3.1.0-orange)
![Status](https://img.shields.io/badge/status-Beta%20%2F%20Research%20Preview-yellow)

[中文](README.md) · **English** · [Русский](README_RU.md)

[Capability Maturity](docs/capability-maturity.md) · [Security Model](docs/security-model.md) · [Security Audits](docs/security-audits/)

> **Beta / Research Preview** — prioritizes static analysis, dry-runs, and local labs. Exploit, lateral movement, persistence, C2, exfiltration, and other high-risk capabilities are restricted experimental features; policy and sandbox metadata are not OS- or container-level isolation.

## Table of contents

- [Overview](#overview)
- [Capabilities](#capabilities)
- [Quick start](#quick-start)
- [AI/MCP self-audit](#aimcp-self-audit)
- [MCP server integration](#mcp-server-integration)
- [Python SDK](#python-sdk)
- [CLI reference](#cli-reference)
- [Configuration & authorization](#configuration--authorization)
- [Design approach](#design-approach)
- [Security and scope](#security-and-scope)
- [License and disclaimer](#license-and-disclaimer)

## Overview

The default product is a local MCP/AI attack-surface audit and evidence gate, used through an **MCP server**, a **Python SDK**, and a **Typer CLI**. The model decides; the process enforces the profile, the evidence gate, and the audit record.

Recon, detection, and post-exploitation code remains in the source tree and is registered only when `scan`, `active-lab`, or `full` is selected explicitly. The default `safe` profile does not import modules that exist only for those profiles. The published wheel omits those experimental engines. Descriptions shown to a model contain the profile, risk, effects, and controls. It fits authorized labs, AI/MCP security review, and teaching. It is not a turnkey enterprise platform, an autonomous attacker, or a production C2.

## Capabilities

| Domain | Status | Scope |
|---|---|---|
| Static AI/MCP surface self-audit | Preview | Read-only AST → SARIF; covers FastMCP and low-level SDK. Default `safe` |
| CVE intelligence | Preview | Local search is available on `safe`. Sync and PoC execution need a higher profile |
| Reporting (JSON/SARIF/HTML) | Beta | Finding export is available on `safe`. `generate_report` requires `scan` |
| Recon and vulnerability detection (JSON/SARIF) | Beta | Minimum profile `scan`; authorized targets only; no public accuracy benchmark yet |
| Orchestration / exploit / post-exploit / C2 / lateral / persistence | Restricted Experimental | `active-lab` or `full`; disposable isolated labs only |

See [Capability Maturity](docs/capability-maturity.md) for full definitions.

## Quick start

One-line install (installs the `autort` and `autoredteam-mcp` commands):

```bash
pip install autoredteam-orchestrator                # PyPI
pipx install autoredteam-orchestrator               # isolated env
uvx --from autoredteam-orchestrator autort --help    # run without installing
```

Can't wait for a PyPI release? Install straight from Git:

```bash
pip install "git+https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git"
uvx --from git+https://github.com/Coff0xc/AutoRedTeam-Orchestrator autort --help
```

Run from source (development):

```bash
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator
pip install -r requirements.txt
python -m cli.main --help
```

The default start is a read-only, no-network local audit. These commands do not contact a target and do not import the experimental engines. From a source checkout, the minimum dependency is `typer`:

```bash
pip install typer
python -m cli.main ai-surface scan --path handlers --format sarif -o surface.sarif
python -m cli.main ai-surface scan-mcp-config --path .mcp.json
python -m cli.main capabilities manifest --profile safe
```

`ai-surface scan` skips test files by default. A scan of the repo root or `handlers/` reconciles findings with the capability manifest. Coverage is reported in JSON `summary.static_coverage` and in SARIF `runs[].properties.static_coverage`.

## AI/MCP self-audit

Run a purely static audit of **your own repository**: inventory the attack surface of MCP server and AI agent tools, with results delivered at `file:line` precision to GitHub Code Scanning. No target, network, secret, or authorization required.

Run as a GitHub Action on every PR (full example in [`self-audit.example.yml`](.github/workflows/self-audit.example.yml)):

```yaml
- uses: Coff0xc/AutoRedTeam-Orchestrator@v3.1
  with:
    mode: self-audit
    path: '.'
    severity-threshold: high
```

Or locally:

```bash
python -m cli.main ai-surface scan --path . --format sarif        # MCP handler tool surface
python -m cli.main ai-surface scan-mcp-config --path .mcp.json    # broad commands and plaintext secrets
python -m cli.main ai-surface scan-skills --path ./skills         # high-risk instruction markers
```

Add `--auth-mode lenient` to drop project-specific authorization findings when auditing external repositories.

## MCP server integration

The MCP server exposes the security capabilities as MCP tools so an AI editor or agent can drive them. It is local-first: no cloud, no telemetry, trusted local stdio only.

### Run the server

Two equivalent ways to start it:

```bash
autoredteam-mcp --stdio                # installed command (from PyPI / Git)
python -m mcp_stdio_server --stdio     # from a source checkout
```

The `--stdio` flag selects the stdio transport, which is what MCP clients (Claude Code, Cursor, Windsurf, Kiro, …) speak.

### Wire into an AI editor

Claude Code, Cursor, and other MCP clients read a JSON config under the `mcpServers` key. A minimal `.mcp.json` for this project:

```json
{
  "mcpServers": {
    "autoredteam": {
      "command": "autoredteam-mcp",
      "args": ["--stdio"],
      "env": {
        "AUTORT_CAPABILITY_PROFILE": "safe",
        "AUTOREDTEAM_AUTH_MODE": "strict",
        "AUTOREDTEAM_API_KEY": "replace-with-a-real-key"
      }
    }
  }
}
```

`AUTORT_CAPABILITY_PROFILE` selects which tools are registered (see [Capability profiles](#capability-profiles)). Omit it to get the fail-closed `safe` default.

### Profile selection

The profile is resolved in this order: explicit argument → `AUTORT_CAPABILITY_PROFILE` environment variable → the `safe` default. Any tool whose `minimum_profile` is above the selected profile is **not registered**, and any surface not classified in the manifest fails closed at registration (`CapabilityManifestError`).

### Environment variables

| Variable | Values | Default | Meaning |
|---|---|---|---|
| `AUTORT_CAPABILITY_PROFILE` | `safe` \| `scan` \| `active-lab` \| `full` | `safe` | Which capability tier is registered as MCP tools |
| `AUTOREDTEAM_AUTH_MODE` | `strict` \| `permissive` \| `disabled` | `strict` | Authorization gate for protected tools |
| `AUTOREDTEAM_API_KEY` | any string | *(unset)* | API key checked in `strict` mode; `MCP_API_KEY` is accepted as an alias |

## Python SDK

The SDK is a thin async wrapper over the `core/` engines, importable from a source checkout. On the default profile, start with finding export and CVE search:

```python
from autort import Exploiter, Reporter
from autort import __version__        # single-source version, e.g. "3.1.0"
```

Every call is async and returns a `dict` (lists for a few scan methods). Success is signaled by `"success": True`; failures carry a real `"error"` string rather than being swallowed. A call is refused before the matching engine is imported when the profile is too low.

### Available on the default profile

```python
from autort import Exploiter, Reporter

exploiter = Exploiter("http://127.0.0.1:8000")
cves = await exploiter.cve_search("Apache Log4j", severity="critical", has_poc=True)

reporter = Reporter("session_id_here")
findings = await reporter.export_findings(format="json")
```

`cve_search(keyword, severity=None, has_poc=None, limit=20)` and `export_findings(format="json")` work on `safe`. `AutoPentest.status(session_id)` reads local session state, maps to `session_status`, and is also available on `safe`.

### Explicit profile

`Scanner` recon and detection methods have a minimum profile of `scan`. The default `safe` profile refuses them before the recon or detector engine is imported.

```python
from autort import Scanner

scanner = Scanner("http://127.0.0.1:8000")

ports = await scanner.port_scan(ports="1-1000")          # or top=100
recon = await scanner.full_recon()                        # 10-stage recon
vulns = await scanner.detect_vulns(categories=["sqli", "xss", "ssrf"])
nuclei = await scanner.nuclei_scan(tags=["cve"], severity=["high", "critical"])
```

Key methods: `full_recon()`, `port_scan(ports="1-1000", top=None)`, `detect_vulns(categories=None, config=None)`, `fingerprint()`, `waf_detect()`, `subdomain_enum(domain=None)`, `passive_recon(domain=None)`, `nuclei_scan(tags=None, severity=None, template_dir=None, concurrency=10, limit=None)`. Set `AUTORT_CAPABILITY_PROFILE=scan` or higher to continue.

`Exploiter.cve_exploit(cve)`, `auto_exploit(top_n=5)`, and `exploit(vuln, **kwargs)` require `active-lab` or above, an authorized disposable target, an isolated executor, and an API key. `Reporter.generate(format="html")` maps to `generate_report` and requires `scan`.

`AutoPentest.run(phases=None)` and `resume(session_id)` map to `auto_pentest` and `pentest_resume`. Both require `full` and run only against isolated, authorized labs. Omitting `phases` runs the full flow.

`RedTeam(config=None)` groups lateral movement, C2, persistence, privilege escalation, and credential discovery. These are `full`-profile, approval-gated, isolated-executor surfaces and are listed here as a catalog only, without call examples.

## CLI reference

The Typer CLI is the local-analysis entry, installed as `autort`. From source, use `python -m cli.main`. Commands that run on the default `safe` profile come first. Commands that need a higher profile follow.

### Default path (`safe`)

These commands do not contact a target. `cve-search` reads local CVE intelligence.

| Command | Purpose | Example |
|---|---|---|
| `ai-surface scan` | Static inventory of MCP handlers | `autort ai-surface scan --path handlers --format sarif -o surface.sarif` |
| `ai-surface scan-mcp-config` | Check an MCP client config | `autort ai-surface scan-mcp-config --path .mcp.json` |
| `ai-surface scan-skills` | Mark high-risk skill/prompt instructions | `autort ai-surface scan-skills --path ./skills` |
| `capabilities profiles` | Show profile inheritance and surface counts | `autort capabilities profiles` |
| `capabilities manifest` | Export the manifest for one profile | `autort capabilities manifest --profile safe` |
| `tools lint` | Static MCP tool-contract check | `autort tools lint --path handlers` |
| `cve-search` | CVE intelligence | `autort cve-search "Log4j" --severity critical --has-poc -n 20` |
| `version` | Print the version | `autort version` |

CI flags on `ai-surface`: `--ci` prints a terse summary and returns a non-zero exit code when findings meet `--severity-threshold` (info/low/medium/high/critical). `detect` is not on this path; it requires `scan`.

### Subcommand groups

| Group | Commands | Minimum profile | Purpose |
|---|---|---|---|
| `ai-surface` | `scan`, `scan-mcp-config`, `scan-skills` | `safe` | Static AI/MCP attack-surface inventory (read-only) |
| `capabilities` | `matrix`, `readiness`, `manifest`, `profiles` | `safe` | Capability manifest and coverage |
| `tools` | `lint` | `safe` | MCP tool contract check (static) |
| `code-agent` | `expand` | `safe` | Call-chain context expansion (no code execution) |
| `runtime-api` | `serve` | `safe` | Read-only local runtime API (`/api/runs`) |
| `sandbox` | `docker-smoke` | `safe` | Local Docker sandbox smoke test |
| `ai-redteam` | `run`, `catalog`, `convert`, `eval-run` | `safe` | Declarative AI red-team scenarios (dry-run by default) |

`autort tools` is the `lint` group above. External-tool status is the `ext_tools_status` surface, whose minimum profile is `scan`. That surface has no separate reachable CLI command.

### Explicit profile

The default `safe` profile refuses these commands. The profile comes from an explicit argument, then from `AUTORT_CAPABILITY_PROFILE`, otherwise `safe`.

| Command | Minimum profile | Purpose | Example (authorized targets only) |
|---|---|---|---|
| `scan` | `scan` | Port scan / full recon | `autort scan http://127.0.0.1:8000 --full` |
| `detect` | `scan` | Vulnerability detection | `autort detect http://127.0.0.1:8000 -c sqli,xss,ssrf --format sarif` |
| `nuclei` | `scan` | Pure-Python Nuclei scan | `autort nuclei http://127.0.0.1:8000 -t cve,rce -s high,critical` |
| `report` | `scan` | Generate a report | `autort report <session-id> -f html` |
| `exploit` | `active-lab` | CVE / auto exploit | `autort exploit http://127.0.0.1:8000 --cve CVE-2021-44228` |
| `pentest` | `full` | One-shot orchestration | `autort pentest http://127.0.0.1:8000 --phases recon,vuln_scan` |

## Configuration & authorization

### Capability profiles

Profiles are an ordered exposure tier; each inherits the previous one:

| Profile | Includes | Operating boundary |
|---|---|---|
| `safe` | Local analysis, dry-run, metadata, controlled local state | Trusted local process; no target network access or host command execution |
| `scan` | `safe` + authorized recon and vulnerability scanning | Explicit target scope and external network controls required |
| `active-lab` | `scan` + exploit validation and offensive planning | Disposable lab, independent approval, isolated executor required |
| `full` | all surfaces, incl. post-exploitation and restricted research | Explicit opt-in for isolated, authorized, disposable environments only |

Inspect the live definitions:

```bash
autort capabilities profiles      # ordered profiles, inheritance, surface counts
autort capabilities manifest -p scan   # full manifest filtered to one profile
```

### Authorization modes

Authorization is applied per tool via decorators. Three modes, selected by `AUTOREDTEAM_AUTH_MODE`:

| Mode | Behavior |
|---|---|
| `strict` (default) | Protected tools require a valid API key (`AUTOREDTEAM_API_KEY` or `MCP_API_KEY`) |
| `permissive` | Logs a warning but allows access |
| `disabled` | No check — honored only when `AUTOREDTEAM_ENV=test` or `PYTEST_CURRENT_TEST` is set |

### Capability manifest

The manifest (`core/capability_manifest.py`) is the machine-readable, single source of truth for every exposed MCP surface. Each entry declares `kind`, `name`, `handler`, `category`, `minimum_profile`, `risk`, `maturity`, and the required controls — `auth_required`, `approval_required`, and `executor` (`in-process` / `external-process` / `isolated-required`). Registration fails closed on any unclassified surface.

The `required_controls` fields are **declarative**: they gate MCP schema exposure, not enforcement. They do not replace authentication, target scope, independent approval, or an isolated executor.

## Design approach

- **One set of engines, three entry points.** AI-surface audit, CVE intelligence, recon, detection, and the experimental orchestration engines live in `core/`; the MCP server, SDK (`autort/`), and CLI (`cli/main.py`) are thin adapters over the same engines. A capability is implemented once, not three times.
- **Fail-closed MCP exposure.** Every registered surface must be classified in the capability manifest. An unclassified or over-minimum-profile surface is not silently exposed — it raises at registration. The default is the narrowest profile (`safe`), not the widest.
- **Declarative exposure vs. enforced authorization are separate layers.** Profiles filter *which* tools exist for a client; authorization decides *whether* a protected tool may run. The two are deliberately independent so a profile change cannot accidentally widen who may act.
- **Local-first, dry-run by default.** The server is stdio-only and trusts the local process. High-risk capabilities default to dry-run and only leave it in an isolated, disposable lab under explicit opt-in.
- **Self-audit is a first-class citizen.** The same repo ships a read-only scanner for MCP handlers, MCP client configs, and skill/prompt files, so the AI/MCP surface itself can be reviewed without a target or network.

## Security and scope

- The same capability profiles (`safe`/`scan`/`active-lab`/`full`) gate MCP registration and the CLI and SDK calls that map to a manifest surface. They do not replace authentication, target scope, independent approval, or an isolated executor. Direct `core` imports outside those entry points stay ungated.
- High-risk capabilities default to dry-run and should be enabled only in disposable, isolated environments.
- Authentication is attached per tool decorator and is not yet a uniform boundary across every registered surface.

See [Security Model](docs/security-model.md) and [Capability Maturity](docs/capability-maturity.md).

## License and disclaimer

MIT License — see [`LICENSE`](LICENSE).

For explicitly authorized security testing, internal validation, education, and local labs only. Users must follow applicable law and obtain written authorization from the target owner. Unauthorized scanning, exploitation, persistence, exfiltration, or evasion of security controls is prohibited.
