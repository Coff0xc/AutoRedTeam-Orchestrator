# Issue Drafts (ready to file on Coff0xc/AutoRedTeam-Orchestrator)

> Based on the 2026-11-08 analysis of 596dbca (v3.1.0). Each item includes evidence, a proposal, and acceptance criteria, and stands on its own.

## Status (2026-11-09)

All five items are already closed in code; the original problem descriptions are kept here as a record:

1. `ai-surface scan` reconciles against the manifest at the repo root and under `handlers/`; coverage goes into the JSON summary and SARIF run properties. Factory-generated tools are counted by `DetectorConfig` name and no longer treated as missed.
2. SARIF results carry `properties.tool_name`, and `ruleId` is split by risk class such as `mcp_tool.auth-critical`, `mcp_tool.auth-missing`, `mcp_tool.factory`, `mcp_prompt`, and `mcp_resource`.
3. The scanner recognizes `@mcp.prompt` / `@mcp.resource` (including `name=`) and synchronous functions; `--exclude-tests` is on by default.
4. CI mypy no longer points at the deleted `core/container.py`. The gate now covers `core/result.py`, `core/capability_manifest.py`, `core/mcts_planner.py`, `core/ai_surface`, `core/agent_runtime`, and `core/reporting/sarif.py`, with `--follow-imports=silent` so historical errors are not counted against this gate. `handlers/` still has about 200 pre-existing type errors and has not been put into the blocking gate as a whole. A `windows-latest` test job was also added.
5. `core/__init__.py` lazy-loads the AI engine. The minimum dependency for read-only commands is `typer`, and the README now says so.

---

## Issue 1 — feat(ai-surface): reconcile static scan coverage against the capability manifest

**Title**: ai-surface should reconcile scan results against the capability manifest and report static coverage

**Body**:

The ai-surface AST scanner (`core/ai_surface/scanner.py`) recognizes only two patterns: the FastMCP `@mcp.tool()` decorator and low-level `Tool(...)`/`list_tools` construction. Scanning the repo itself yields 109 findings, but the manifest (`core/capability_manifest.py`) defines 142 surfaces. Reconciling handler by handler:

| handler | manifest | scanned | gap |
|---|---|---|---|
| detector | 28 | 2 | 26 (detector_factory generates them dynamically; invisible to the AST) |
| prompts | 6 | 0 | 6 |
| resources | 4 | 0 | 4 |
| Other 19 handlers | 104 | 104 | 0 |

Static coverage is 106/142 (74.6%), and this structural blind spot is currently not disclosed anywhere in the documentation.

**Proposal**: the manifest is already the machine-readable single source of truth. After a scan, reconcile against the manifest and report `static_coverage` (e.g. `106/142`) plus a list of invisible surfaces in the SARIF `properties` or summary output, grouped by how they are generated (factory-generated / prompt / resource). Factory-generated detector surfaces can carry a locator in the manifest marking their generation source, so the scanner classifies them instead of missing them.

**Acceptance**: scanning this repo reports `106/142` coverage and lists the 36 invisible surfaces; `capability-maturity.md` adds a disclosure that it "cannot see factory-generated surfaces".

---

## Issue 2 — fix(ai-surface): SARIF findings lack a structured tool identity, making Code Scanning triage difficult

**Title**: SARIF findings lack structured tool identity (single ruleId, no tool_name property)

**Body**:

All 109 findings from scanning the repo itself hang under a single `ruleId="mcp_tool"` (`tool.driver.rules` has only 1 entry); `properties` contains only `{confidence, param, payload, verified}` with no tool name; and `message.text` is docstring text (e.g. "AD enumeration - enumerate Active Directory objects"). In GitHub Code Scanning this becomes 109 unstructured alerts under one rule, with no way to filter by tool name or reconcile against the manifest/capability profile.

**Proposal**:

- Add `tool_name` to finding `properties` (taken from the function name, aligned with the manifest `name`);
- or split into multiple rules by risk domain (e.g. `mcp_tool.auth-missing` / `mcp_tool.high-risk` / `mcp_tool.network`), each with its own description — then the Code Scanning rule view can aggregate by class.

**Acceptance**: any finding can be traced to the same-named surface in the manifest via `properties.tool_name`; the Code Scanning UI can group and filter by rule.

---

## Issue 3 — feat(ai-surface): support prompt/resource surface matching and test-directory exclusion

**Title**: scanner misses prompt/resource surfaces entirely and flags test-file fixtures

**Body**:

Two blind spots:

1. `kind: prompt` (6) and `kind: resource` (4) surfaces are not scanned at all — `_is_tool_decorator` and the low-level detection only cover tool-style registration (`mcp.tool()` / `Tool(...)` / `list_tools`); the `@mcp.prompt()` / `@mcp.resource()` patterns are not implemented.
2. Scanning the repo root treats test files as production code: the test fake tool decorators in `tests/test_capability_manifest.py` produce 2 findings, plus 1 false positive in `core/recon/js_analyzer.py`.

**Proposal**:

- Add recognition of prompt/resource decorators and construction patterns, and tag findings with their kind;
- add `--exclude-tests` (excluding `tests/`, `test_*.py`, `*_test.py`, and `conftest.py` by default) or build test filtering into `scan.py`'s `_iter_python_files`.

**Acceptance**: scanning this repo produces 6/4 kind-tagged findings for prompts/resources; after `--exclude-tests`, `tests/` yields zero false positives.

---

## Issue 4 — ci: mypy target includes a deleted file; no Windows matrix

**Title**: CI mypy targets a deleted file (core/container.py) and there is no Windows job

**Body**:

1. `.github/workflows/ci.yml:38`: `mypy ... core/result.py core/container.py core/mcts_planner.py` — `core/container.py` was already deleted in v3.1.0 (CHANGELOG: "core/container.py (527-line unused DI framework)" was removed), so current CI either runs empty or errors; and only 3 files out of a 120k-line engine layer get type checking.
2. Both README and AGENTS.md list Windows as a first-class platform (pre-commit has a `scripts/check_paths.py` hardcoded Unix path check), yet every CI job runs on ubuntu-latest.

**Proposal**:

- Remove `core/container.py` from the mypy targets immediately; add `core/result.py`, `core/capability_manifest.py`, `core/agent_runtime/*`, and `handlers/`, expanding gradually;
- add a `windows-latest` job that at minimum runs `pytest -m "not network and not slow"` plus CLI/SDK smoke tests (`python -m cli.main capabilities manifest --profile safe`, `python -c "from autort import Scanner"`).

**Acceptance**: CI is green; the Windows job passes stably on windows-latest (or is explicitly marked allow-fail and tracked).

---

## Issue 5 — docs: the "read-only, no network" quickstart commands need more dependencies than documented

**Title**: "read-only, no network" quickstart commands need more deps than documented

**Body**:

The README's read-only quickstart commands (`ai-surface scan`, `capabilities manifest`) actually have this import chain:

```
cli/main.py:22        import typer
core/__init__.py:14   from core.ai_engine import ...   → pydantic
(ai-surface config parsing also needs pyyaml)
```

Running `python -m cli.main ai-surface scan` straight from a source checkout fails with `ModuleNotFoundError: No module named 'typer'`, and installing typer just reveals the missing pydantic. The README quickstart only gives `pip install -r requirements.txt` (the full dependency set) and never states the minimal set for these read-only commands.

**Proposal** (either one):

- Documentation fix: state the minimal set `pip install typer pydantic pyyaml` in the quickstart;
- code fix: following the v3.1.0 rework of `utils/__init__.py`, change the eager import in `core/__init__.py` to `__getattr__` lazy loading so the `ai-surface` path never goes through the heavy `ai_engine`/`result` dependencies.

**Acceptance**: in a fresh venv with only the documented dependencies installed, the read-only commands run.

---

## Appendix: Non-Issue Notes

When cloning, 4 files (`core/evasion/payload_obfuscator.py`, `core/exploit/exploiters/upload_exploiter.py`, `core/persistence/webshell_manager.py`, `core/post_exploit/advanced_techniques.py`) failed to read under Windows Git Bash with Permission denied; git mode 100644 is normal and the contents are intact. This is leftover local filesystem ACL state (chmod read-only bit), not a repository problem — no issue needed.
