# Agent-Based Refactor Plan (P1 / P2 / P3) and Borrowing Map

This document is the implementation plan for moving AutoRedTeam-Orchestrator from a "deterministic 8-phase pipeline" to "model-driven tool layer + evidence gating".

Current-state conclusions (based on source inspection, not speculation):

- Keep layer: domain capabilities 106,529 lines / 232 files + tool surface of 106 `@tool`s (`handlers/` 7,992 lines).
- Replace layer: AI / harness / declaration layers 8,382 lines / 40 files.
- Written but unwired assets: `core/vuln_verifier/` (statistical testing + OOB callbacks), `core/knowledge/` (graph storage), `core/feedback/` (failure analysis + strategy adjustment).
- Confirmed dead code: `core/engine_router.py` (zero callers), `core/pipeline.py` (zero imports).

## Target Architecture

```
L4 Evaluation layer  ai_redteam from dry-run skeleton → real probes + ground truth (none of the three reference products has this)
L3 Evidence layer    vuln_verifier wired in as a mandatory gate; findings without evidence are downgraded/rejected by code
L2 Harness           model-driven loop + context compression + HITL approval + resumable runs + memory write-back
L1 Tool layer        106 tools + finding-level evidence contract (keeping verified / verification_confidence / evidence)
```

## Borrowing Map: What to Borrow, From Where, Landing Where

### Decision Principles (Three Levels of Borrowing)

| Level | Scope | License Constraint |
|---|---|---|
| ① Borrow the contract | Data models, fields, interface shapes, state machines | Universal across licenses: a contract is not expression; re-implement it yourself |
| ② Borrow the control flow | Loop structure, termination conditions, gate placement, compression timing | Universal across licenses: learn the structure, implement it yourself |
| ③ Borrow the code | Copy the implementation directly | **Only allowed under MIT / Apache-2.0**, with attribution kept |

**Hard constraint**: `CyberStrikeus/CyberStrike` is AGPL-3.0 and this project is MIT. **Only ① and ② are allowed — not a single line of code may be copied**, or the whole project gets infected. `AIPentest/CyberStrikeAI` is Apache-2.0: code may be copied but the copyright notice must be kept (if an implementation is copied, note the source and license in the file header). `meta-blade` is our own code, no constraint.

**Second constraint**: everything borrowed must land on a "module we already have". If it cannot land anywhere, we do not need it — do not borrow it.

### Table

| # | What to borrow (idea/method) | Source and location | Level | Where it lands for us | How to change it |
|---|---|---|---|---|---|
| 1 | **Terminal-state gate object**: termination is not "the model finished talking" but a structured Decision with `Finalizable` / `MissingChecks` / `RequireExecutionEvidence`; failure auto-continues the run | CyberStrikeAI `internal/agentfinalizer/decision.go:29-150` (Apache-2.0) | ① Contract | **P2**: gate before report generation, reading finding-level `verified` / `evidence` | New gate function in `core/evidence/`; findings without evidence do not reach the report |
| 2 | **Downgrade by code when evidence is missing**: without `execution_evidence`, severity is pressed down to medium and the finding renamed `[UNCONFIRMED CANDIDATE]`; with evidence it is upgraded to confirmed in place | CyberStrike `packages/cyberstrike/src/tool/vulnerability.ts:62-127` (AGPL, idea only) | ② Control flow | **P2**: same as above | Our downgrade basis is stronger than theirs: not "whether a field was filled in" but the **actual replay result** from `vuln_verifier` |
| 3 | **Server-side required-field validation**: check 9 reproduction fields (target / reproduction_steps / evidence / impact …) before storing; reject when missing | CyberStrikeAI `internal/app/vulnerability_tools.go:157,284-290` (Apache-2.0) | ① Contract | **P2**: the standard shape for finding-level evidence fields | Keep the existing `DetectionResult.evidence` fields and only fill the gaps (see design correction notes below) |
| 4 | **HITL middleware**: three modes, `off \| approval \| review_edit`; intercepts both Invokable and Streamable; supports editing parameters before approval; the approver can be a human or an independent audit model | CyberStrikeAI `hitl_middleware.go:42-77` (Apache-2.0) | ② Control flow | **P3**: `utils/mcp_tooling._wrap_tool_func` (already has an audit logging point, a natural middleware position) + `core/security/execution_mode.py` | Add a pre-approval hook in the tool wrapper, reusing the existing `@require_*_auth` tiers as trigger conditions |
| 5 | **Tool-parameter regex interception**: scan tool name + parameters (including JSON strings and percent-encoded values) before execution; block on a hit | CyberStrikeAI `internal/toolguard/toolguard.go:1-56` (Apache-2.0) | ② Control flow | **P3**: `core/security/mcp_security.py` + the tool wrapper | Reuse the existing `safe_executor`, extending the rules from "input validation" to "action interception" |
| 6 | **Context compression trio**: ① summarize when `max_total_tokens × 0.8` is reached; ② spill oversized tool results to disk and return only a preview; ③ prune historical tool outputs | CyberStrikeAI `eino_summarize.go:82-131` + `config.example.yaml:309-311` (Apache-2.0) | ② Control flow | **P3**: harness (`meta-blade-agent/engine/core.py` currently has none of this layer at all) | Make the thresholds configurable; do not hardcode constants |
| 7 | **Lazy tool loading**: when tool count ≥ 20, keep only the first 12 + an allowlist resident, and unlock the rest on demand via `tool_search` (about 50 tokens each) | CyberStrikeAI `config.example.yaml:303-306`; CyberStrike `lazy-registry.ts:36-40` (AGPL, idea only) | ② Control flow | **P1 output list → P3 landing**: our 106 tools are far above the threshold | P1's lint output gives the "suggested resident set"; P3 injects tools on demand in the harness |
| 8 | **Two hard rules for model failover**: ① retries use exponential backoff (default 4 attempts, max 30s); ② **only switch channels when there is no visible output yet**, so one round of output never stitches together multiple sources | CyberStrikeAI `eino_model_resilience.go:217-231` (Apache-2.0); meta-blade `providers/failover.py:31-81` (own code, already implemented) | ② Control flow | **P3**: `core/llm/provider.py` (P0 already fixed key fallback; retries/timeouts still missing) | meta-blade already has the correct implementation; reuse its constraints directly |
| 9 | **Cross-session fact graph**: `project_facts` + edge relations, confidence `confirmed \| tentative \| deprecated`, injecting only the **index** into context rather than the full text | CyberStrikeAI `internal/app/project_fact_tools.go:51-165` + `eino_summarize.go:459` (Apache-2.0) | ① Contract | **P2/P3 wiring**: `core/knowledge/` (`InMemoryGraphStore` + `SQLiteKnowledgeStore` already exist; `add_entity` currently has **zero external callers**) | Do not create a new module; add a confidence field to the existing graph + index injection |
| 10 | **Idempotent execution ledger**: `tool_execution_id = sha256(session, request, call_id, name, args)` + atomic fsync writes, so re-delivered messages never re-execute side-effecting tools | meta-blade `engine/core.py:595-606` + `JsonExecutionStore:107-120` (own code) | ① Contract | **P3**: resumable harness runs | Reuse directly (bring it along when extracting `autort-engine`) |
| 11 | **Complete dangling tool_calls on cancellation**: after cancellation, synthesize tool results for missing tool_calls so the conversation can continue next time | meta-blade `engine/core.py:405` (own code) | ② Control flow | **P3**: harness | Reuse directly |
| 12 | **Methodology as tools**: 13 phases are not hardcoded but exposed as tools like `methodology_status` + prompt text, with the LLM holding the right to advance; preconditions only produce blocking/warning violations | CyberStrike `methodology/{phase,methodology,validation}.ts` (AGPL, idea only) | ② Control flow | **P3**: the `PHASE_ORDER` enum in `core/orchestrator/` becomes tools + prompts | The existing 6 boolean rules in `_should_skip_phase_v2` → become a violation list output (non-blocking, for the model to judge) |
| 13 | **Tiered step limits + wrapUp strips tools**: different limits per role (orchestrator 40 / analyzer 20 / tester 60); on the final round at the limit, all tools are removed outright to force plain-text output from the model | CyberStrike `session/prompt.ts:648-654,733,896` (AGPL, idea only) | ② Control flow | **P3**: harness termination conditions | meta-blade currently has only `max_iterations` + `max_iterations_exceeded → FAILED` (treating over-limit as failure instead of a wrap-up) |
| 14 | **doom-loop / stuck detection**: 3 consecutive identical (tool, args) calls trigger a permission prompt | CyberStrike `session/processor.ts:21,167` (AGPL, idea only) | ② Control flow | **P3**: harness | Pure logic, ~10 lines |
| 15 | **Declarative extension**: `tools/*.yaml` (commands + parameter mappings), `skills/*/SKILL.md` (progressive disclosure), `agents/*.md` (sub-agents), `roles/*.yaml` | CyberStrikeAI's five directories (Apache-2.0) | ① Contract | **P1 onward tool contracts** | We do not adopt yaml tool definitions (Python functions are already the single source of truth); we only borrow "sub-agents/roles declared in markdown" |
| 16 | **Skill-package signing and remote install**: SKILL.md verified with Ed25519 signatures, installable from remote sources | CyberStrike `skill/signing.ts:24` + `skill/discovery.ts:109-116` (AGPL, idea only) | ① Contract | **P4 (evaluation phase), to be decided later** | Pairs naturally with our `ai_surface` skill scanning: scan + verify signatures |
| 17 | **Cost and token breakdown**: separate cache_read / cache_write, with tiered pricing above 200k | CyberStrike `provider/provider.ts:706` + `processor.ts:249-256` (AGPL, idea only) | ① Contract | **P3**: token statistics | We currently have zero token statistics |
| 18 | **Token usage persisted to a table**: prompt / completion / cached / reasoning accumulated separately and stored | CyberStrikeAI `eino_run_usage_accumulator.go:36-47` (Apache-2.0) | ① Contract | **P3**: same as above | — |

### Explicitly Not Borrowed

| What we do not borrow | Why |
|---|---|
| CyberStrike's 22 agents and proxy pipeline | The domain is bug-bounty / proxy traffic analysis, which does not match our assets (106 tools + verifiers); also AGPL |
| CyberStrikeAI's Eino ADK / Go orchestration | We are Python, and handing the control layer to a framework would block the insertion points for the evidence gate |
| CyberStrikeAI's Shell recipe system (90 `tools/*.yaml`) | Doing security actions via shell commands bypasses our Python engine and verifiers — giving up L3 |
| Any evaluation framework | None of the three has one; this is a gap, nothing to borrow |
| The "run high-risk tools inside the service process" deployment model | Both reference products do this (CSAI `exec.CommandContext`, CyberStrike host `spawn`); we do not want it |

## P1: Tool Contract Standardization

| Item | Content | Acceptance |
|---|---|---|
| 1.1 | ~~Add `evidence` / `confidence` / `verified` to `ToolResult`~~ → changed to: the evidence contract lands at the **finding level**, following the domain's existing conventions (see design correction notes below) | The `verified` / `verification_confidence` / `evidence` in tool outputs are no longer swallowed at the MCP boundary (regression tests: `test_handlers_ai` / `test_handlers_recon` / `test_handlers_orchestration`) |
| 1.2 | New tool contract linter (`core/tooling/`), reusing the AST results from `core.ai_surface`, with contract rules added | `autort tools lint` reports on our own repo: 105 tools, errors=0, 55 warnings (48 high-risk tools missing the evidence contract + 7 missing Args documentation) = the P2 work list |
| 1.3 | Delete confirmed consumerless dead code `core/engine_router.py`, `core/pipeline.py` | Zero leftovers in a repo-wide grep; all tests green |
| 1.4 | Stop the MCTS fake-simulation misdirection: `plan()` output is labeled with `probability_source` and `verified=false` | `test_handlers_mcts` asserts `data.verified is False` and includes the static success-rate table explanation |

## P2: Evidence Gate Wiring (Completed)

| Item | Content | Acceptance | Status |
|---|---|---|---|
| 2.1 | Evidence entries reuse the domain's existing `VerificationResult`; no new format is invented | `EvidenceItem` in `core/evidence/models.py` + unit tests | Done |
| 2.2 | Wire `batch_verify` / `OOBIntegratedVerifier` / statistical verification from dead code into the MCP tool `verify_finding` | Verifier mock unit tests + a real replay in the local loopback XSS lab (`tests/test_verify_finding_fixture.py`); external targets still not run | Done |
| 2.3 | Findings without evidence are downgraded and flagged by code, distinguishing "detector self-report" from "independent verification" | Integration test: a detector-style finding gets downgraded; after `verify_finding` it is not downgraded | Done |
| 2.4 | Verifiers exposed as MCP tools, completing manifest registration and profile gating | Manifest had 142 items at the time (132 tools); profile counts were safe 23 / scan 86 / active-lab 106 / full 142. See README for current counts | Done |

## Plan 2: audit-gate Productization

The product direction is local MCP/AI attack-surface auditing + evidence gating, aligned with the evaluation contracts of promptfoo/garak/PyRIT rather than a PentAGI-style autonomous penetration platform. The P3 harness remains paused.

| Item | Content | Acceptance | Status |
|---|---|---|---|
| P2.1 | Fail-closed capability tiers + finding-level evidence gate | profiles + evidence gate tests | Done |
| P2.2 | HITL + DNS-aware target allowlist + local XSS `verify_finding` lab | `test_hitl` / `test_target_scope` / `test_verify_finding_fixture` | Done |
| P2.3 | Local eval contract `autort.eval/v1` (text / surface / skill / run_state), without calling any model | `autort ai-redteam eval-run config/ai_redteam.eval.example.yaml` fully green | Done |
| P2.4 | Thin `agent_runtime` loop: pending actions → policy/sandbox → local allowlist → eval | `autort runtime-api run config/runtime.local.example.yaml`; unknown steps fail closed | Done |

## P3: Harness

Design is in "P3 Detailed Design" below; **not yet implemented**.

## Design Correction Notes

### Correction 1: The Evidence Contract Does Not Go on the `ToolResult` Envelope (P1.1)

The original plan was to add `evidence` / `confidence` / `verified` fields to `ToolResult` and lift them into the envelope layer inside `ensure_tool_result` from dictionary results. It was abandoned after testing, because:

- These three names are **already domain vocabulary**: `confidence` appears 34 times in core/handlers, `evidence` 29 times, `verified` 14 times (e.g. `DetectionResult.evidence/verified/confidence` in `core/detectors/result.py`, `confidence` as a dict in `core/code_agent`, `confidence` as 0.9 in WAF detection).
- Lifting fields in `ensure_tool_result` deletes the tool's own output fields from `data`, causing silent data loss. Testing triggered 2 regressions: `test_code_agent_expand_context_static_scan` (`KeyError: 'confidence'`) and `test_waf_detect_found`.
- The project already has an in-house convention: `verify_and_exploit` returns `verified: bool` + `verification_confidence`, and `DetectionResult` uses `verified: bool` / `confidence: float`.

Conclusion: the evidence contract is defined by **finding-level fields** (`verified` / `verification_confidence` / `evidence`); the envelope layer does not repeat the names; the P2 gate reads the finding fields. The linter accepts both paths (a ToolResult contract, or evidence fields present in the output).

### Correction 2: `backends` Declaration Deferred

"Prefer external binaries, fall back to built-in implementations on failure" is not implemented in P1: after deleting `core/engine_router.py` there are no consumers, and per project rules no extension points are reserved for hypothetical needs. A registry will be built when the harness genuinely needs to select by backend.

### Correction 3: Evidence Must Come From Independent Verification (Provenance)

The first P2 version treated "findings without evidence in the report get downgraded" as a selling point, but a review after implementation found: the gate reads the finding's own `verified` / `confidence` / `evidence`, while **67 places** in `core/detectors/` write `verified=True` themselves after a single syntax/echo check (e.g. `core/detectors/access/open_redirect.py:206-214` with `confidence=0.90, verified=True`). The result was that detector self-report passed the gate directly, reducing the gate to "were the fields filled in" — no substantive difference from the reference products.

Correction: `assess_finding` / `enforce_evidence_gate` gained `require_provenance: bool = True`, with the pass condition additionally requiring provenance, satisfied by either:

- `finding["verified_by"]` hitting `PROVENANCE_SOURCES` (`vuln_verifier` / `statistical_verifier` / `oob_callback` / `manual_review`);
- at least one structured evidence entry carrying a non-empty `method` (`VerificationResult` from `core.vuln_verifier` carries one after conversion via `evidence_from_verification`).

Boundary (already written into the code): the gate can only make a conservative judgement inside the process and cannot stop deliberate forgery; it solves the confusion between "detector self-report" and "verifier observation", not the "who may write a finding" permission problem.

**Behavioral consequence (important)**: with the default on, **any detector finding not passed through `verify_finding` is downgraded to `[UNCONFIRMED]` with severity capped at medium**. That is what we want (that is exactly the source of false positives), but it will noticeably change how existing reports look; use `require_provenance=False` or `ReportGenerator(require_evidence=False)` for the old behavior.

### Correction 4: OOB "Unconfirmed" Is Not "Disproven"

All four OOB methods in `core/vuln_verifier/oob.py` **always return `is_vulnerable=False`** (the source comment itself says "callback confirmation needed", lines 180/224/248/292). The first handler version used `verified = any(is_positive(r) for r in results)`, writing "OOB received no callback" as `contradicted`. Corrected to three states: only `confidence == "false_positive"` is `False`; a positive result is `True`; everything else (including OOB with no callback, or no results) is `None` (unverified). The fix also corrected `_statistical_request_func` swallowing exceptions so that a "hang was treated as latency" and produced a false verified, and bound the statistical request timeout to the decision threshold (`expected_delay * 0.8`).

## P3 Detailed Design

### Base Choice: Vendor meta-blade's AgentEngine

Extract into `core/agent_engine/`, **not as a standalone package**. Rationale (from the planner comparison):

| Dimension | Vendor code into `core/agent_engine/` | Standalone package `autort-engine` |
|---|---|---|
| Python version | Downgrade syntax during extraction to stay on 3.10 | meta-blade declares `>=3.14`, so a published package would force this project (`>=3.10`) up to 3.14 |
| Private repo coupling | A single local copy of the code | Must first detach from meta-blade's private index configuration |
| Release cost | Zero | Needs CI/versioning/registry; one line changed means two releases |
| Two-copy divergence | Present, converged with `scripts/sync_agent_engine.py` + recorded upstream commits | Worse (two repos evolving separately) |

### Extraction Checklist (Required)

| Extract | Source | Why |
|---|---|---|
| `engine/core.py` | `AgentEngine` / `EngineLimits` / `ToolExecutionResult` / `JsonExecutionStore` / `EngineResult` / `tool_execution_id` | Core loop + idempotent ledger + completing dangling tool_calls on cancellation |
| `engine/tools.py` | `LocalToolExecutor` / `McpToolExecutor` / `CompositeToolExecutor` / `SubAgentToolExecutor` / `ToolBackend` | Tool composition and three backends |
| `providers/{base,failover,openai}.py` | `ModelMessage` / `NormalizedModelEvent` / `FailoverProvider` | Failover hard rule "only switch with no visible output" |
| `audit/trail.py` | `AuditTrail` | JSONL audit + secret redaction |
| `tools/definition.py` | `AgentTool` + `tool` decorator | Tool metadata |

**Stays in meta-blade**: `private_task_executor.py` (RQ/queue/publisher deployment-specific), `consumer/`, `publisher/`, `storage/`, `tools/{oss_*,report_card_server,knowledge_tools,cvss_guide,todo_write}.py`, `subagent_registry.py`.
**Minimum dependency set**: stdlib + `mcp` + `httpx`; `EngineLimits` is a dataclass, no pydantic dependency.

Layout: `core/agent_engine/{__init__,engine,limits,store,tools,audit}.py` + `providers/` + `context/compactor.py` + `guard/hitl.py` + `session/store.py`.

### Detailed Design for the Four Gaps

| Gap | Landing point | Approach | Acceptance |
|---|---|---|---|
| Context compression | `context/compactor.py`, called before each round's `_model_turn` in `run()` | `CompactorConfig(max_total_tokens, trigger_ratio=0.8, tool_result_preview_bytes, keep_recent_tools)`; thresholds read from the previous turn's `turn.input_tokens`; oversized tool results spill to `data/sessions/<sid>/harness/toolout/` with only a preview + path + line count returned; pruning must **keep whole assistant(tool_calls)+tool blocks**, otherwise cancellation completion breaks | Fake provider running 60 rounds × 20KB tool results: no limit exceeded, spill files exist, tool_calls still pair up |
| Dangerous-action approval gate | `core/security/hitl.py` + `utils/mcp_tooling._wrap_tool_func` (already has parameter redaction + auditing, a natural insertion point) | Three modes `off/approval/review_edit`, mode read from `AUTORT_HITL_MODE`; trigger levels reuse the existing three-tier decorators (MODERATE→approval, DANGEROUS→approval+review, CRITICAL→mandatory human); rejection returns `is_error=True, reason="approval_required"` and is fed back to the model; **async approval must not block the event loop**, with a timeout + default deny | Injecting a deny on a `@require_dangerous_auth` tool: the function body never executes, the audit contains a hitl record, and the model receives is_error |
| Tool exception degradation | `_execute_tool` in `engine.py` | Catch non-cancellation/non-timeout exceptions → feed back a `ToolExecutionResult(..., is_error=True)`; **keep hard failures**: `CancelledError`, run-level `TimeoutError`, provider errors, `max_iterations_exceeded`, token over-limit | A handler raising `ValueError` → the task is `COMPLETED`, an is_error message appears in the session, and the model can retry with different parameters |
| Session state externalized | `JsonConversationStore` in `session/store.py` | Same fsync + `os.replace` pattern as `JsonExecutionStore`; one line per message with request_id/iteration/role; before restore, complete dangling tool_calls with `_close_cancelled_tool_calls`; idempotency reuses `tool_execution_id` | Run one round → kill the process → rebuild: history is restored and completed tools are not re-executed |

### Interfaces to L1 / L3

- **L1 in-process**: `register_all_handlers(mcp, counter, logger, profile=...)` already supports building FastMCP in-process; add `InProcessMcpToolExecutor(mcp)` implementing `ToolBackend` (`list_tools()` / `call_tool()`), keeping `McpToolExecutor` only for cross-process use.
- **L3 terminal gate**: new `core/evidence/finalizer.py`, shaped after CyberStrikeAI `decision.go:29-150` (`Finalizable/MissingChecks/RequireExecutionEvidence`); called before the engine returns `COMPLETED`; when `finalizable=False`, the `missing_checks` are fed back as a message to continue the run (bounded by `max_iterations`). The gate reads finding-level `verified` / `verification_confidence` / `verifiable evidence`, not the envelope layer.

### Implementation Order (Each Step Independently Deliverable and Verifiable)

| Step | Content |
|---|---|
| 3.0 | Vendor extraction into `core/agent_engine/`, downgrading 3.14 syntax (PEP 695 `type` / `StrEnum` are the main pitfalls) |
| 3.1 | Tool exception degradation |
| 3.2 | Session externalization |
| 3.3 | Approval gate |
| 3.4 | Context compression |
| 3.5 | Memory write-back to `core/knowledge` + token statistics |
| 3.6 | L3 terminal gate wiring |

### Risks

- Downgrading 3.14 → 3.10 syntax is the first extraction pitfall; every file needs rewriting and a mypy run.
- Divergence: vendor code and meta-blade evolve separately afterwards, converged via the sync script + upstream commit records.
- Compression pruning breaking assistant(tool_calls)+tool pairing → the provider rejects the history outright.
- The gate continuing the run conflicts with `max_iterations`; the limit must be explicit to prevent infinite loops.

## Known Open Items

- P3 needs a decision on whether the harness is vendored from meta-blade (which introduces a private-repo dependency) or extracted as a standalone `autort-engine` package.
- The `backends` declaration for the tool layer is covered in "Design Correction Notes, Correction 2" above — not done now.
- `core/mcts_planner.py`: keep the algorithm (it runs and has tests) and only fix the output semantics; whether to delete it is left for evaluation after P3.
