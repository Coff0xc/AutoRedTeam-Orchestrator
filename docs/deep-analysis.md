# AutoRedTeam-Orchestrator Deep Analysis Report

- **Target**: https://github.com/Coff0xc/AutoRedTeam-Orchestrator @ 596dbca (v3.1.0)
- **Date**: 2026-11-08
- **Method**: Three progressive rounds — ① architecture and governance chain; ② subsystem deep dives with test evidence; ③ meta-testing (auditing itself) + quantified blind spots + restricted-area spot checks
- **Environment**: Windows 11 / Python 3.12 / temporary venv (typer + pydantic + pyyaml); no active capability was run against any external target at any point

---

## 1. Project Positioning and Scale

**One-line positioning (aligned 2026-11-10)**: local MCP/AI attack-surface auditing and evidence gating. The three entry points are still the MCP Server, the Python SDK, and the Typer CLI. The default profile is `safe`: static analysis, dry-run, and local metadata. Recon, detection, and experiment engines stay in the source tree and are only registered when `scan`, `active-lab`, or `full` is explicitly selected. The scale and counts below are still the 2026-11-08 snapshot at commit `596dbca`.

| Dimension | Data |
|---|---|
| Version / License | v3.1.0 (single source in `_version.py`), MIT |
| Language / Platform | Python 3.10+; Windows is a first-class concern (pre-commit has a hardcoded Unix path check) |
| Scale | 456 .py files, ~177k lines; core/ has 304 files and 122k lines |
| Tests | 94 test files, **2,188 test functions** (~35k lines) |
| Contributors | coff0xc as main author with 218 commits, 1 collaborator + copilot bot |
| MCP surface | **142 surfaces** (132 tools / 6 prompts / 4 resources) |

Layering: `core/` is the only engine; `mcp_stdio_server.py` (158 lines), the `autort/` SDK (~1,100 lines of thin async facade), and `cli/main.py` (788 lines) are all adapter layers. Each capability is implemented exactly once. The CHANGELOG records active cleanup: 527 lines of unused DI container deleted, plus the zero-caller `engine_router.py` removed — **an active awareness of dead code**.

## 2. Governance Mechanisms, Taken Apart

### 2.1 Capability Manifest (`core/capability_manifest.py`, 808 lines)

The most valuable design in the whole project: the machine-readable single source of truth for every MCP surface. AST-counted distribution:

| Dimension | Distribution |
|---|---|
| By profile | safe 23 / scan 63 / active-lab 20 / full 36 (cumulative inheritance) |
| By executor | in-process 80 / **isolated-required 56** / external-process 6 |
| By category | detector 29, redteam 14, misc 13, orchestration 12, ai 11, recon 9, lateral 9, cve 8… |
| High-risk controls | 26 places with `auth_required=True` |

Fail-closed has three real gates:

1. **Unclassified means an error at registration**: any `kind:name` not in the manifest raises `CapabilityManifestError` during registration (`handlers/__init__.py:148`).
2. **Handler ownership check**: `_ProfiledMCP._decorator` verifies that a surface's handler matches its registrant, preventing cross-module registration smuggling.
3. **Duplicate registration detection**: the `_autort_capability_profile` attribute prevents the same MCP instance from being re-registered under a different profile (`handlers/__init__.py:211`).

Filtering is clean: functions outside the profile are **returned as-is, unregistered** (`handlers/__init__.py:154`), so they are invisible at the schema level.

### 2.2 Auth Middleware (`core/security/mcp_auth_middleware.py`, 367 lines)

- **DISABLED only takes effect in test environments**: both `set_auth_mode` and module-level initialization check for `AUTOREDTEAM_ENV=test` / `PYTEST_CURRENT_TEST`, otherwise they refuse and fall back to strict (`:55-63, :350-360`).
- **High-risk tools ignore permissive mode**: CRITICAL/DANGEROUS tools are denied outright without a key; when AuthManager is unavailable, fail-closed treats them as high-risk (`:116-134`).
- **Audit redaction**: `_sanitize_params` REDACTs keys like password/token/ntlm_hash and truncates values over 200 characters.
- 69 `require_*_auth` decorators spread across 8 high-risk handler files; a typical decorator stack is four layers (`lateral_ssh`: tool → require_critical_auth → validate_inputs → handle_errors) plus a runtime gate.

**Known gaps (admitted in the project's own docs)**: auth is per-tool decorators, not a unified boundary at the registration layer; resources/prompts are not covered; the CLI/SDK paths bypass the profile gates entirely.

### 2.3 Second Line of Defense: mcp_security (816 lines) — Underestimated by the "Spot Coverage" Conclusion

- **SSRF protection is DNS-aware**: `InputValidator._validate_url()` (`mcp_security.py:430`) re-checks the **DNS-resolved IP** with `_is_private_ip(resolved_ip)` (`:469`), blocking the "public domain resolving to 169.254.169.254" bypass.
- `RateLimiter` (`:513`, with max_keys eviction) + `OperationAuthorizer` (`:623`) + the `secure_tool` decorator (`:760`).
- `SafeExecutor` (882 lines): external-command allowlist + max_args + per-argument validation (`:280-292`), not bare subprocess.
- `.bandit` actually has only 1 skip — the "many skips" claim in AGENTS.md is a historical impression.

Corrected conclusion: the protection is **three stacked layers** (manifest profile filtering → auth decorators → mcp_security input/rate-limit/allowlist), each incomplete on its own, but genuinely defense-in-depth when combined.

### 2.4 Orchestrator / Sandbox / agent_runtime

- **Orchestrator** (orchestrator.py ~590 lines + contracts.py 1,029 lines): 8-phase pipeline, `PHASE_RISK` mapping, checkpoint/resume (also at the executor level), progress callbacks; rated Experimental, which matches reality.
- **Sandbox**: `core/sandbox/executor.py` really calls the Docker SDK (`containers.run` + `wait`); `fallback.py` (218 lines) is a local fallback — the security model states in plain text that "the fallback must not be called a sandbox".
- **agent_runtime** (1,441 lines total): `models.py` (498 lines of object models: RunMode/RiskLevel/Action/Task/Flow/AgentRunState/TraceEvent) + `middleware.py` (responsibility chain) + `sandbox.py` (policy decisions separated from container execution). Its positioning as plan-time governance metadata is honest, and the interface placeholders are complete.

## 3. Engine-Layer Size Map (Pure Python Implementation)

| Module | Lines | Notes |
|---|---|---|
| `core/recon/` | 7,669 | fingerprint 870 / directory 734 / port_scanner 724 / tech_detect 714 / engine 689 / subdomain 680 / waf_detect 600 / dns_resolver 588 / js_analyzer 400 |
| `core/exploit/` | 6,635 | pure_scanner 1,013 / pure_sqli 1,001 / rce_exploiter 587 / orchestrator 601 / engine 552 |
| `core/detectors/` | 27 detectors | injection 10 / access 4 / auth 4 / misc 5 / file 2 / request 2; `sqli.py` (762 lines) is a real implementation (boolean-based two-way verification, payload enhancement) |
| restricted area | 11,855 | c2 + persistence + lateral + post_exploit, all marked isolated-required/full in the manifest |
| `session + config/` | 4,065 | Pydantic config cascade (env → yaml → defaults) |
| `ai_surface/` | 759 | AST NodeVisitor recognizing FastMCP `@mcp.tool()` and low-level `Tool(...)`/`list_tools`, with SARIF output |
| `ai_redteam/` | 1,394 | scenario→plugins→strategies→runner→scorers standard chain skeleton; the runner explicitly produces `not_run` (runner.py:133) with no execution loop — a deliberate scope control |

Roughly 22k lines of scannable surface, ~12k lines of restricted area, and ~4k lines of governance + security layers — the weight is on "governable scanning capability", not a weapons library. Engineering quality detail: `core/http/client.py:21` extracts the retry sleep into a patchable hook (API designed for testability).

## 4. Testing and CI

- **Negative-path tests are real**: `test_capability_manifest.py:108` covers three fail-closed branches (unknown profile / unclassified / duplicate registration) in one test, with `pytest.raises(match=...)` exact assertions.
- **ai_surface tests are behavioral tests**: they write real source into tmp_path and run the AST; they include a false-positive regression case (`test_ai_surface.py:53`).
- **Integration coverage is sparse**: only 3 of 94 test files use network/e2e/integration markers; mocking is heavy (conftest globally disables auth + HTTP retry mocks).
- **CI gaps**: `ci.yml:38` runs mypy on only 3 files, including the already-deleted `core/container.py`; no Windows matrix; the lint/security/docker-publish/self-audit pipelines themselves are complete.

## 5. Meta-Test: ai-surface Auditing Itself

`ai-surface scan --path . --format sarif` runs cleanly and produces valid SARIF 2.1.0: **109 findings** (error 56 / warning 33 / note 20). The hotspots match human judgement: redteam_handlers 14 / orchestration 11 / ai_handlers 11 / lateral 9 / recon 9 — errors concentrate on high-risk tools such as AD/CVE exploitation.

### 5.1 Flaw 1: Weak SARIF Triage

All 109 findings hang under a single `ruleId="mcp_tool"` (driver.rules has only 1 entry); finding properties contain only `{confidence, param, payload, verified}` with **no tool_name**, and the message is just docstring text. Once in GitHub Code Scanning, that is "one rule, 109 unstructured alerts", with no way to filter by tool or reconcile against the manifest.

### 5.2 Flaw 2: 33-Surface Blind Spot (Exact Breakdown)

Reconciled handler by handler against the manifest:

```
handler            manifest  scanned   gap
detector              28        2      26   <-- factory-generated, invisible to the AST
prompts                6        0       6   <-- scanner does not match the prompt kind
resources              4        0       4   <-- scanner does not match the resource kind
Other 19 handlers    104      104       0   ✓ full coverage
```

**33 = 36 invisible surfaces − 3 false positives**. Root causes: ① 26 detector surfaces are generated dynamically by `detector_factory.py`, while the AST scanner only recognizes decorator/construction patterns; ② prompt/resource kinds are entirely unimplemented; ③ 3 false positives come from `tests/test_capability_manifest.py` (2, fake decorators inside tests) and `core/recon/js_analyzer.py` (1). The docs say "does not execute handlers" but **never say "cannot see factory-generated surfaces"** — this structural blind spot is undisclosed.

### 5.3 Minor Friction

The README's quickstart command claims "read-only, no network", but the import chain `cli/main.py:22 → typer`, `core/__init__.py:14 → ai_engine → pydantic` means at minimum typer + pydantic + pyyaml are required.

## 6. c2/beacon.py Spot Check: "Restricted Experimental" Is Rated Correctly

1,714 lines of real implementation, not a stub. Careful engineering details: interruptible heartbeat (`:488,637`, `_stop_event.wait` instead of `time.sleep`), cryptographically secure jitter (`:651-652`, `secrets.randbelow`), pluggable crypto (`:241-242`, `C2Crypto`), and handler-registry task dispatch (`:301`). The manifest marking of `full` + `isolated-required` is appropriate and necessary.

## 7. Overall Assessment

**The governance design (manifest/profile/auth/whitelist/runtime model) is ahead of the execution capability (AI red-team loop, end-to-end verification, unified scope enforcement)**, and code, documentation, and self-assessment are highly consistent with each other — rare for a 170k-line security tool repository. The meta-test verdict: ai-surface passed the "audit yourself" exam — grading accurate, hotspots correct, no high-risk misses (the blind spots are all structural and concentrated in low-risk/restricted surfaces).

### Recommendations (Ranked by Value)

1. **ai-surface × manifest reconciliation**: after scanning, reconcile against the manifest and output "static coverage: 106/142 + invisible list" — the blind spot becomes a first-class metric, and architecturally it is a small change.
2. **Structured SARIF**: add `properties.tool_name` to findings and split rules by risk category.
3. **Scanning blind spots**: implement prompt/resource kind matching + `--exclude-tests`.
4. **CI fixes**: update the mypy file list (remove the deleted `core/container.py`), gradually extend it to handlers/utils; add a windows-latest test job.
5. **README clarification**: state the dependencies for the quickstart commands, or let the ai-surface path bypass the eager import in `core/__init__` (`utils/` already did `__getattr__` lazy loading in 3.1.0 — the pattern is ready-made).

### Appendix: Local Environment Notes

When cloning, 4 files (including `core/evasion/payload_obfuscator.py`) failed with Permission denied on `cat` under Git Bash, but git mode 100644 is normal and the contents are intact (27KB present) — leftover Windows file ACL state, not a repository problem; `chmod +r` or a fresh clone fixes it.
