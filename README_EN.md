# AutoRedTeam-Orchestrator

**A local-first, MCP-native security automation workbench for authorized testing and AI/MCP attack-surface review.**

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-3.1.0-orange)
![Status](https://img.shields.io/badge/status-Beta%20%2F%20Research%20Preview-yellow)

[中文](README.md) · **English** · [Русский](README_RU.md)

[Capability Maturity](docs/capability-maturity.md) · [Security Model](docs/security-model.md) · [Security Audits](docs/security-audits/)

> **Beta / Research Preview** — prioritizes static analysis, dry-runs, and local labs. Exploit, lateral movement, persistence, C2, exfiltration, and other high-risk capabilities are restricted experimental features; policy and sandbox metadata are not OS- or container-level isolation.

## Overview

AutoRedTeam-Orchestrator provides composable security capabilities in a single codebase, exposed through three entry points: an MCP server, a Python SDK, and a Typer CLI. The primary line is **AI-assisted security automation** — letting AI editors and agents use controlled security capabilities over MCP, and statically auditing the attack surface of AI/MCP systems themselves.

It fits authorized labs, security-automation development, AI/MCP security review, CTFs, and teaching. It is **not** a turnkey enterprise platform, an autonomous attacker, or a production C2.

## Capabilities

| Domain | Status | Scope |
|---|---|---|
| Recon and vulnerability detection (JSON/SARIF) | Beta | Authorized targets only; no public accuracy benchmark yet |
| Static AI/MCP surface self-audit | Preview | Read-only AST → SARIF; covers FastMCP and low-level SDK |
| CVE intelligence and PoC | Preview | NVD sync, Nuclei-compatible execution |
| Reporting (JSON/SARIF/HTML) | Beta | HTML escaping hardening in progress |
| Orchestration / exploit / post-exploit / C2 / lateral / persistence | Restricted Experimental | Disposable isolated labs only |

See [Capability Maturity](docs/capability-maturity.md) for full definitions.

## Quick start

```bash
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator
pip install -r requirements.txt
python -m cli.main --help
```

Read-only, no-network commands to start:

```bash
python -m cli.main ai-surface scan --path handlers --format sarif -o surface.sarif
python -m cli.main capabilities manifest --profile safe
```

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

## Entry points

| Entry point | Path | Position |
|---|---|---|
| MCP Server | `mcp_stdio_server.py` | Fail-closed `safe` profile by default; trusted-local stdio only |
| Python SDK | `autort/` | From a source checkout |
| Typer CLI | `cli/main.py` | Primary local-analysis and development entry |

Authorized scans generate network traffic — use them only against localhost, a disposable lab, or a target under written authorization:

```bash
python -m cli.main scan http://127.0.0.1:8000 --full
python -m cli.main detect http://127.0.0.1:8000 -c sqli,xss,ssrf
```

## Security and scope

- MCP capability profiles (`safe`/`scan`/`active-lab`/`full`) filter tools at registration but do not replace authentication, target scope, independent approval, or an isolated executor.
- High-risk capabilities default to dry-run and should be enabled only in disposable, isolated environments.
- Authentication is attached per tool decorator and is not yet a uniform boundary across every registered surface.

See [Security Model](docs/security-model.md) and [Capability Maturity](docs/capability-maturity.md).

## License and disclaimer

MIT License — see [`LICENSE`](LICENSE).

For explicitly authorized security testing, internal validation, education, and local labs only. Users must follow applicable law and obtain written authorization from the target owner. Unauthorized scanning, exploitation, persistence, exfiltration, or evasion of security controls is prohibited.
