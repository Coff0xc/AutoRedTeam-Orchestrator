# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Skill-risk fixtures for `skill.hardcoded_secret`, `skill.unverifiable_remote_code`, `mcp.MCP04.remote-skill-code` (`curl|bash`), and `mcp.MCP03.hidden-unicode`. Catalog stays at eight named skill fixtures.

### Changed

- README lead and GitHub About name both loops: local MCP/AI attack-surface audit and authorized-engagement evidence gate. Package version on the README is 4.1.0.

### Fixed

- `ai-surface diff --ci` against `tests/fixtures/ai_surface/handlers.baseline.json` matches the live `engage_next` first-line description (`gap-filling aggregator step`)

## [4.1.0] - 2026-11-25

### Added

- `tool_enable` grant ledger (`autort.capability.grants/v1`): catalog unlocks are recorded in-process, optionally persisted with `AUTORT_GRANT_LOG`, and capped with `AUTORT_GRANT_BUDGET`. Resident surfaces do not consume the budget. Replay of the same (kind, name) does not duplicate. `autort capabilities grants` reads the log. Third-party MCP grant growth stays unread. MCP02 remains partial
- RuntimeLoop `MODEL_CALL` is only `engage.pick` via `core.llm.provider.LLMProvider`. It picks among coverage-open, currently actionable steps. `AUTORT_LLM_PROVIDER=none` fail-closes. Shell and browser kinds stay blocked. Unknown `model_call` names stay blocked
- Aggregator idempotent execution ledger: `tool_execution_id` is sha256(name, inputs, dry_run). A completed id is replayed and does not re-run the engine. Failures are not recorded, so a retry still executes. Doom-loop still stops after three identical planner fingerprints that do not close a gap
- Engage model pick is limited to coverage ledger open rows that map to currently actionable steps. The model may reply with a row id (`phase:detect`, `finding:url|type|param`) or a step name. Examined/ruled_out rows, `export_findings` while verify is open, and unknown names (`exploit_run`) are ignored. Default `AUTORT_LLM_PROVIDER` stays `none`
- Juice Shop confirmation-rate demo: `autort engage confirmation-rate` verifies product-search SQLi against an authorized local Juice Shop and scores a homepage XSS self-report. Scorecard `confirmation_rate` is confirmed/total. Default CI stays dry-run; the live pin is `tests/test_engage_juiceshop.py` (`integration`/`network`, skipped when 127.0.0.1:3000 is down)
- Verify receipts: `verify_finding` stores `autort.engage.provenance/v1` with request URL/payload and response status/length/SHA-256/preview. `require_receipt` keeps findings `[UNCONFIRMED]` without a bound receipt. Scorecard `proof=bound` only when the receipt is present. World graph stores `provenance_bound` and `body_sha256`, not response bodies
- Engagement coverage ledger (`autort.engage.coverage/v1`): in-scope phases plus discovered ports and findings, each `examined` / `ruled_out` / `open`. `engage status` and `engage run` print the denominator. `coverage_rate` is null when total is 0. Contradicted findings are ruled out
- Engagement world model (`autort.engage.world/v1`): aggregators write asset/fact/finding nodes into `world.sqlite` via `SQLiteKnowledgeStore`. Planner reads the compact index (coverage flags, counts, unverified keys). Scan JSON stays out of the graph. Finding confidence is `tentative` until verify
- `plan_next` reads open gaps from engagement state and returns aggregator steps (`recon_run`, `detect_run`, `nuclei_scan`, `verify_finding`, `export_findings`). Findings skip recon; unverified findings block export. Optional `nuclei` phase. `engage.*` names stay aliases
- RuntimeLoop dispatches resident aggregators `recon_run`, `detect_run`, `verify_finding`, `nuclei_scan`, and `export_findings`. Dry-run records shared `engage_state` without target contact (`config/runtime.aggregators.example.yaml`). Live paths require the matching capability profile and target allowlist. Unknown steps, shells, and `model_call` still fail closed
- `autort ai-surface ledger` (`autort.owasp.mcp/v1`): offline OWASP MCP Top 10 coverage map
- Static mappings for MCP01 (`mcp.MCP01.secret-env-key`), MCP05 (`mcp.MCP05.general-command`), MCP07 (`mcp_tool.auth-*`), and MCP09 (`mcp.MCP09.remote-endpoint`)
- [GAPS.md](GAPS.md): MCP08 stays a gap; MCP02 stays partial
- In-process MCP `initialize` / `tools/list` (plus prompts and resources list) matches the resident set for `safe` / `scan` / `active-lab` / `full`
- Orchestrator checkpoint persist/resume pin (`tests/test_orchestrator_checkpoint.py`): `SessionStorage` on `tmp_path`, stubbed phase executors, no live target
- `autort.engage.scorecard/v1` additive fields: `unverified`, `contradicted`, `confirmation_rate` (null when `total` is 0), per-row `proof` (`bound` / `none`), and `gaps` (`no_findings_is_not_clean` on an empty finding list)
- Optional LLM path: code-owned authorized-engagement system prompt plus nonce `AUTORT_DATA` envelope for engage pick and decision analysis. Nested marker stems are neutralized. Jailbreak strings stay out of those prompts. Default `AUTORT_LLM_PROVIDER` remains `none`

### Changed

- Ubuntu pytest fast suite no longer uses `--maxfail`; Windows and Ubuntu now both run the suite to completion
- Default CLI `--help` hides Internal groups `code-agent`, `runtime-api`, and `sandbox`; they stay callable
- Default CLI `--help` hides `pentest` (`auto_pentest`). `smart_analyze`, `attack_chain_plan`, `plan_attack_path`, `kg_attack_paths`, and `auto_pentest` stay catalog/Experimental and still resolve under the matching profile. RuntimeLoop fail-closes those names as unknown local steps. Resident MCP counts are unchanged.
- Catalog MCP tools `ext_nmap_scan`, `ext_nuclei_scan`, `ext_sqlmap_scan`, `ext_ffuf_fuzz`, and `ext_masscan_scan` drop unbounded `extra_args`. Presets and ffuf modes are Literal enums. `ext_sqlmap_scan` `preset=exploit` and `ext_ffuf_fuzz` fail closed unless `confirmed=true`. Internally built flags still pass `validate_extra_args`.
- Mixed-profile scan and active-lab handler registrars load from sibling modules only when the current profile enables them. Parent modules that contain a safe surface still import under `safe`.
- Optional engage `_model_pick` wraps state as DATA, passes the authorized system prompt, continues remaining in-scope steps, and treats HITL on live `engage.verify` as code. A HITL permit is not verification evidence. Unknown model replies fall back to the heuristic queue.
- Version is `4.1.0` in `_version.py` only. The GitHub Action pin `v3.1` is unchanged

### Fixed

- Restore GitHub Action `baseline` input so self-audit can run `ai-surface diff --ci`
- `AutoPentestOrchestrator.resume` loads `PentestState` from `ScanContext.metadata`, restores `OrchestratorConfig`, and `run()` skips completed or skipped phases

## [4.0.0] - 2026-11-16

### Added

- `autort.engage.scorecard/v1`: `confirmed` / `unconfirmed` / `total` on `engage run` and export, with a local XSS reflect lab proving the evidence gate
- `autort ai-surface inventory` (`autort.inventory/v1`)
- OWASP MCP03/04/10 static rules and named skill-install risks (`skill.prompt_injection` and siblings)
- `ai-surface diff --ci` against `tests/fixtures/ai_surface/handlers.baseline.json`

### Changed

- Default CLI help leads with the local audit and evidence gate
- `ai-redteam run` is documented Internal/plan-only; `eval-run` is the scored local path
- Version is `4.0.0` in `_version.py` only. The GitHub Action pin `v3.1` is unchanged

## [3.1.0] - 2026-04-08

### Added

- **AI/MCP self-audit** (`ai-surface`): SARIF output with `file:line` code locations for GitHub Code Scanning; `scan-mcp-config` and `scan-skills` subcommands; `--severity-threshold` / `--exit-code` CI gating; `--auth-mode lenient` and pluggable auth decorators for external repos; detection of both FastMCP (`@mcp.tool()`) and low-level SDK (`@app.list_tools` / `Tool(...)`) tool definitions
- **GitHub Action self-audit mode** (`action.yml`, `.github/workflows/self-audit.example.yml`): `mode: self-audit` audits a repository's MCP/AI attack surface on every PR with no target, network, or secret
- **Python SDK** (`autort/`): Enterprise API with `Scanner`, `Exploiter`, `AutoPentest`, `RedTeam`, `Reporter` classes
- **CLI** (`cli/`): Typer-based CLI — `autort scan`, `autort detect`, `autort exploit`, `autort pentest`, `autort report`
- **Unified Config** (`core/config/`): Pydantic-based configuration system with YAML + env var cascade
- **YAML Payloads** (`data/payloads/`): 14 YAML files extracted from mega_payloads.py with `core/payload/loader.py`
- **Detector Factory**: `detector_factory.py` activated — 25 detector configs, replaces 640-line manual registration
- **Handler Tests**: 95 new tests for handlers, SDK, and CLI (1766 total, 40%+ coverage)
- **HTTP Retry Mock**: conftest.py fixture to eliminate test timeouts from HTTP backoff sleep

### Changed

- **Architecture**: `modules/` merged into `core/` — single unified engine layer
- **utils/__init__.py**: Converted from 455-line eager imports to `__getattr__`-based lazy loading
- **CI**: Coverage threshold raised from 20% to 40%, lint/coverage targets include `handlers/`, `autort/`, `cli/`
- **pyproject.toml**: New entry points `autort` (CLI) and `autoredteam-mcp` (MCP server)

### Removed

- `modules/` package (merged into `core/`)
- `shared/` package (was pure re-export layer)
- `core/container.py` (527-line unused DI framework)
- `utils/config_manager.py` (dead code)
- 6 empty module directories (`modules/enhanced_detectors`, `exploit`, `network`, `post_exploit`, `recon`, `vuln_scan`)

### Fixed

- `handlers/resource_handlers.py`: Logger parameter mismatch (used module-level logger instead of passed parameter)
- `detector_handlers.py`: Double-counting in ToolCounter

## [3.0.2] - 2026-02-02

### Added

- **MCP security middleware** (`core/security/mcp_security.py`): Input validation, rate limiting, operation authorization, SSRF detection
- **DI dependency injection container** (`core/container.py`): Singleton/Scoped/Transient lifecycles, circular dependency detection
- **MCTS attack planner** (`core/mcts_planner.py`): UCB1 algorithm, attack-path optimization, simulation-based evaluation
- **Knowledge graph** (`core/knowledge/`): Entity-relationship storage, BFS path discovery, target similarity matching
- **Advanced verifier enhancements** (`core/detectors/advanced_verifier.py`): OOB / statistical / boolean-based blind / time-based blind multi-method cross-validation
- 291 new test cases (mcp_security: 62, container: 39, mcts: 57, verifier: 43, knowledge: 90)

### Fixed

- TOCTOU race condition (expanded lock scope)
- Time-based authorization expiry logic
- Rate Limiter memory leak (max_keys eviction)
- DNS injection (token ID sanitization)
- MD5 → SHA256 hash upgrade

### Changed

- Version: 3.0.1 → 3.0.2
- Removed the empty `docs/` directory and stale documentation references
- Full multilingual README update (CN/EN/JA/RU/DE/FR)

### Security

- SSRF detection (private IP validation)
- OOB thread safety
- SSTI payload enhancements

## [3.0.1] - 2026-01-05

### Added
- **External tool integration**: Seamless integration of Nmap/Nuclei/SQLMap/ffuf/Masscan
- **Toolchain orchestration**: `ext_tool_chain` supports running multiple external tools in sequence
- **YAML tool configuration**: `config/external_tools.yaml` supports variable substitution
- **CVE auto-exploitation**: Three new tools — `cve_auto_exploit`, `cve_exploit_with_desc`, `cve_generate_poc`
- **Migration guide**: `MIGRATION.md` provides a complete v2.x → v3.0 migration path

### Fixed
- Version sync: VERSION/pyproject.toml/README unified to 3.0.1
- CI/CD lint enforcement (removed `|| true`)
- Upper bounds added to dependency version constraints
- Git line-ending normalization (.gitattributes)
- beacon.py thread race condition (added threading.Lock)
- Generic exception handling upgraded to specific exception types
- Hardcoded paths migrated to tempfile + pathlib

### Changed
- MCP tool count: 89 → 100+
- Test coverage threshold: 30% → 50%

---

## [3.0.0] - 2026-01-04

### Added
- **Modular MCP server**: Complete refactor with a layered `handlers/` architecture
- **Standardized recon engine**: StandardReconEngine 10-phase pipeline
- **Attack surface discovery**: `modules/web_scanner/` injection-point modeling
- **Unified payload engine**: SmartPayloadEngine merges duplicate implementations
- **Input validator**: `utils/validators.py` InputValidator class

### Changed
- Major version upgrade, full architectural refactor
- handlers/ directory: 16 dedicated handler modules
- Tool registration moved from a single file to modules

### Removed
- `core/async_executor.py` - removed
- `core/async_http_client.py` - removed
- `core/concurrency_controller.py` - removed
- `core/recon/standard.py` - removed
- Several outdated test files

### Security
- Sandbox executor `core/security/safe_executor.py` resource limits
- SSH file transfer SFTP upload/download
- Encrypted data exfiltration AES-256-GCM/ChaCha20

---

## [2.6.0] - 2026-01-07

### Added

#### API Security Enhancements
- **Advanced JWT testing**: None-algorithm bypass / algorithm confusion (RS256→HS256) / weak-key brute-forcing / KID injection detection
- **Deep CORS detection**: 30+ Origin bypass techniques, including subdomain spoofing, protocol confusion, and Unicode bypass
- **Security header scoring system**: OWASP-guideline-based weighted scoring, supporting A+ to F ratings
- **GraphQL security**: Introspection leakage / batch DoS / deep-nesting DoS / field-suggestion leakage / alias overloading
- **WebSocket security**: Origin bypass / CSWSH / authentication bypass / compression attacks (CRIME) detection

#### Supply Chain Security
- **SBOM generator**: Supports CycloneDX 1.4 and SPDX 2.3 standard formats
- **Dependency vulnerability scanning**: Integrated OSV API, supporting the PyPI/npm/Go/Maven/crates.io ecosystems
- **CI/CD security scanning**: GitHub Actions/GitLab CI/Jenkins configuration risk detection
- **Full supply chain scan**: One-click SBOM + dependency audit + CI/CD scan

#### Cloud-Native Security
- **K8s security auditing**: Privileged containers / hostPath mounts / RBAC permissions / NetworkPolicy / Secrets exposure
- **K8s manifest scanning**: Static security analysis of YAML configuration files
- **gRPC security testing**: Reflection API leakage / TLS configuration / authentication bypass / metadata injection

### Changed
- Total tool count raised from 100+ to 130+
- 40+ new API / supply chain / cloud-native MCP tools added
- Documentation structure optimized

---

## [2.5.0] - 2026-01-06

### Added

#### CVE Intelligence Management System
- **YAML PoC engine**: Nuclei-compatible PoC template parsing and execution
- **CVE multi-source sync**: Supports the NVD, Nuclei, and Exploit-DB data sources
- **CVE subscription manager**: Keyword / severity / product filtering for subscriptions
- **AI PoC generator**: Automatically generates PoC templates from CVE descriptions

#### C2 Covert Communication
- **WebSocket tunnels**: XOR/AES-encrypted WebSocket tunnel communication
- **Chunked transfer**: Large-file chunked transfer and reassembly
- **Proxy chain executor**: Multi-hop proxy chain routing

#### Frontend Security Analysis
- **JS analysis engine**: API endpoint, route, and sensitive-information extraction
- **Source map leak detection**: Automatically detects leaked `.map` files

#### MCP Tools
- 12 new MCP tools added (CVE/tunnel/JS analysis)
- v2.5 tool registration module

### Changed
- Total tool count raised from 80+ to 100+
- Async scanning performance optimized

### Security
- Fixed 130 bare except statements
- Updated asyncio API for Python 3.10+ compatibility
- Removed redundant legacy server files
- Cleaned up outdated TYPE_CHECKING imports

## [2.4.0] - 2026-01-05

### Added
- Full ATT&CK workflow coverage
- Persistence modules (Windows/Linux)
- Credential collection module
- AD domain penetration module

## [2.3.0] - 2026-01-04

### Added
- Red Team lateral movement tools (SMB/SSH/WMI)
- C2 communication modules (Beacon/DNS tunnel/HTTP tunnel)
- Obfuscation and evasion modules (XOR/AES/Shellcode loaders)
- Covert communication modules (JA3 forgery/proxy pools)
- Pure-Python exploits (SQLi/port scanning)

### Security
- Unified SSL verification configuration
- Dangerous-character filtering hardened
- CI dependency scanning integrated

## [2.2.0] - 2026-01-03

### Added
- OOB out-of-band detection
- Session manager
- Payload mutation engine
- Statistical vulnerability verification

## [2.1.0] - 2026-01-02

### Added
- AI intelligence modules
- Performance monitoring
- Smart caching
- Task queue

## [2.0.0] - 2026-01-01

### Added
- MCP protocol support
- 80+ security tools integrated
- 2000+ payload library
- Nuclei template integration

---

For older versions, see [GitHub Releases](https://github.com/Coff0xc/AutoRedTeam-Orchestrator/releases).
