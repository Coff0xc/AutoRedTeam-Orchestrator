# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

AutoRedTeam-Orchestrator is a Python 3.10+ authorized security testing / AI red-team orchestration framework with three entry points: an MCP server, a Python SDK, and a Typer CLI. The code includes dual-use capabilities such as penetration testing, vulnerability detection, C2, lateral movement, and persistence; all implementation and validation should stay within authorized security testing, educational research, or local dry-run scenarios.

## Common Commands

### Installation

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

The minimum dependencies to run MCP are available with:

```bash
pip install -r requirements-core.txt
```

### Entry Points

```bash
python mcp_stdio_server.py --stdio
python -m cli.main --help
autort --help
```

Common CLI commands:

```bash
autort scan http://target.com --full
autort detect http://target.com -c sqli,xss,ssrf
autort nuclei http://target.com --severity high,critical --tags cve
autort pentest http://target.com --phases recon,detect,exploit
autort ai-surface scan --path handlers --format sarif -o surface.sarif
autort ai-surface scan-mcp-config --path .mcp.json --format sarif
autort ai-redteam run scenario.yaml -o run.json
autort ai-redteam eval-run run.json
autort ai-redteam eval-run config/ai_redteam.eval.example.yaml --format sarif --ci
autort runtime-api run config/runtime.local.example.yaml --dry-run
autort runtime-api run config/runtime.local.example.yaml --local
autort runtime-api serve --run-state run.json --host 127.0.0.1 --port 8765
autort sandbox docker-smoke
autort capabilities matrix
autort capabilities auth-key --name operator --storage ./data/auth
autort skills catalog
autort skills read --path ./skills/recon
autort engage init http://127.0.0.1:3000 --profile scan
autort engage run --dry-run --ci
```

SDK smoke test:

```bash
python -c "from autort import Scanner; print('OK')"
```

### Tests

```bash
pytest
pytest -m "not slow"
pytest tests/test_sdk.py
pytest tests/test_sdk.py::test_name
pytest --cov=core --cov=handlers --cov-report=html
```

`pyproject.toml` already configures `tests/`, `pytest-asyncio` auto mode, strict markers, and the `slow`, `integration`, `e2e`, `network`, `unit`, and `security` markers. `tests/conftest.py` disables MCP auth checks during the test session so strict auth does not block unit tests. The CI Windows smoke job and Ubuntu test job also run:

```bash
python -m cli.main ai-redteam eval-run config/ai_redteam.eval.example.yaml --ci
python -m cli.main runtime-api run config/runtime.local.example.yaml --local --ci
python -m cli.main engage run --path config/engage.lab.example.yaml --dry-run --ci
```

### Formatting and Quality Checks

```bash
black core/ handlers/ utils/ autort/ cli/
isort core/ handlers/ utils/ autort/ cli/
flake8 core/ handlers/ utils/
mypy core/ handlers/ utils/
pylint core handlers utils
bandit -r core handlers utils -c .bandit
pre-commit run --all-files
```

Black/isort use a line width of 100. `.pre-commit-config.yaml` also includes trailing whitespace, end-of-file, YAML/JSON, large file, merge conflict, and private key checks, plus `scripts/check_paths.py` for hardcoded path checks.

## High-Level Architecture

### Entry Layer

- `mcp_stdio_server.py` creates `FastMCP("AutoRedTeam")`, calls `handlers.register_all_handlers()` to register MCP tools/resources/prompts, and configures logging, the legal notice, and the auth mode at startup.
- `cli/main.py` is the Typer CLI; its commands wrap SDK and core functionality. The main commands are `scan`, `detect`, `exploit`, `cve-search`, `pentest`, `report`, and `nuclei`, plus the `ai-redteam`, `ai-surface`, `code-agent`, `runtime-api`, `sandbox`, `capabilities`, `skills`, and `engage` subcommands.
- `autort/` is the async Python SDK facade: `Scanner`, `Exploiter`, `AutoPentest`, `RedTeam`, `Reporter`, and `Engagement`. They stay thin wrappers, delegating the real work to `core/`.

### MCP Handler Layer

`handlers/` registers MCP tools by capability domain: recon, detector, CVE, API security, cloud, supply chain, redteam, orchestration, lateral, persistence, AD, session, report, AI, external tools, parallel, knowledge, MCTS, prompts, and resources. `handlers/__init__.py` is the single place that defines registration order and the fault-tolerance boundary; a new MCP tool should normally go into the matching handler module and be wired into `register_all_handlers()`.

### Core Engine Layer

- `core/recon/` handles the recon pipeline, including DNS, ports, fingerprinting, tech stack, WAF, subdomains, directories, and passive recon; the SDK's `Scanner.full_recon()` calls `StandardReconEngine`.
- `core/detectors/` is the vulnerability detection system. `DetectorFactory` manages detector registration, creation, and filtering by type/severity; detectors are grouped under access/auth/file/injection/misc/request, and the result model lives in `core/detectors/result.py`.
- `core/exploit/` provides the exploit engine, concrete exploiters, pure-Python SQLi/scanning capabilities, and the exploit orchestrator.
- `core/orchestrator/` implements one-click penetration phase orchestration: RECON → VULN_SCAN → POC_EXEC → EXPLOIT → PRIV_ESC → LATERAL → EXFILTRATE → REPORT. `AutoPentestOrchestrator` supports checkpoint/resume, phase state, and runtime policy/sandbox gates.
- `core/engage/` is the authorized engagement loop: one YAML file, a heuristic planner, recon/detect/verify/export, an evidence gate, and a stop rule after three identical hashes. Live `engage.verify` goes through HITL; dry-run skips it.
- `core/agent_runtime/` provides controlled AI red-team runtime primitives: run state, action policy, risk level, middleware, sandbox enforcement, observability, benchmarking, a thin local loop, a read-only runtime API view, and an in-process registry. The loop only runs allowlisted local steps — it does not call models and does not connect to the P3 harness.
- External tools (nmap/sqlmap/nuclei/ffuf) currently have **no** backend-selection layer: handlers and the SDK call the pure-Python engines in `core.recon` / `core.detectors` / `core.exploit` directly. `core/engine_router.py`, once treated as the routing layer, has been deleted (zero callers, and its external-tool branch was unreachable in a clean checkout). Any backend selection introduced later must come with a real consumer; see `docs/agent-refactor-plan.md`.
- `core/config/` loads configuration with Pydantic models, in this priority order: environment variables (`AUTORT_` and friends) → `config/config.yaml`/`config.yml` → defaults.
- `core/session/` manages targets, HTTP sessions, context, and persistence for scan/orchestration results and resume.
- `core/skills/` is a read-only SKILL.md adapter: it pins a git URL + full SHA + license, and only returns the text after scanning — it does not clone, does not bundle skill text into the wheel, and does not execute third-party scripts.

### Configuration and Dependency Layers

- `requirements-core.txt`: minimum dependencies to run the MCP server.
- `requirements.txt`: core feature dependencies, including MCP, HTTP, LLM providers, recon/security tool integrations, crypto, config, reporting, and CLI.
- `requirements-optional.txt`: currently annotated as optional/future-extension dependencies — do not install or depend on its packages by default for ordinary tasks.
- `pyproject.toml` defines packaging metadata, console scripts, and pytest/coverage/black/isort/mypy/pylint/vulture configuration in one place.

## Development Notes

- This is a security testing tool, and `.bandit` has many skips for red-team scenarios; do not treat those skips as a baseline for ordinary application security, and do not expand the skip range without a requirement.
- Code or commands involving active scan, exploit, lateral, persistence, C2, or exfiltration should only run against explicitly authorized targets, local fixtures, mocks, dry-runs, or documented test targets.
- Prefer reusing the SDK, `DetectorFactory`, `RuntimePipeline`, and the existing handler registration patterns; avoid duplicating core logic directly in the CLI/MCP layer.
- Windows compatibility is a project concern: pre-commit checks for hardcoded Unix paths; prefer `pathlib` for new path handling.
