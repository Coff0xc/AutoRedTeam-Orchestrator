# Contributing

Work in this tree is for authorized security testing, education, and local dry-run.
The default product is a local MCP/AI attack-surface audit and evidence gate.

## Setup

Python 3.10 or newer.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Unix: source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Optional: copy `.env.example` to `.env`. Defaults already keep the capability profile on `safe` and the LLM provider on `none`.

## Check

```bash
python -c "from autort import Scanner; print('OK')"
python -m cli.main capabilities profiles
pytest tests/ -q --timeout=60 -m "not slow and not network and not e2e and not integration"
black --check --line-length 100 core/ handlers/ utils/ autort/ cli/
isort --check-only --profile black core/ handlers/ utils/ autort/ cli/
flake8 --max-line-length 100 --extend-ignore=E501,W503,E402,E203 core/ handlers/ utils/ autort/ cli/
```

MCP stdio:

```bash
python mcp_stdio_server.py --stdio
```

Packaging uses `pyproject-build`. A leftover setuptools `build/` directory hides `python -m build`.

## Conventions

- Black and isort line width is 100. Prefer `pathlib` over hardcoded Unix paths; pre-commit runs `scripts/check_paths.py`.
- New MCP tools belong in the matching `handlers/` module and must be listed in `core/capability_manifest.py`. Unlisted names fail closed.
- `tools/list` only shows `RESIDENT_SURFACES`. Catalog tools run through `recon_run` / `detect_run` / `exploit_run` or `tool_enable`.
- Default profile is `safe`. Do not change detector or exploit heuristics without an authorized fixture benchmark.
- Do not vendor SKILL.md bodies or execute third-party scripts. Pin packs in `core/skills/pins.yaml` with a full git sha and a MIT/Apache/BSD license.
- Experimental engines stay in git and stay out of the default wheel.

## Tests

Add or update tests for every behavior change. Markers: `slow`, `integration`, `e2e`, `network`, `unit`, `security`. `tests/conftest.py` disables MCP auth checks for the test session.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/). One change per commit.

Default branch is `main`. Open a pull request against `main`.

## Security

Do not file a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
