# AutoRedTeam-Orchestrator Benchmark Against Peer AI Automated Red-Team Projects

Date: 2026-05-19

## Scope of This Round

The user explicitly asked to focus on:

- AI automated red-teaming
- AI red-team attacks / LLM red-teaming
- AI automated penetration platforms
- Agentic pentest / autonomous cyber agents

So this round no longer puts traditional high-star security projects like Metasploit, Nuclei, ZAP, or DefectDojo in the main comparison table. They still have engineering reference value, but they are not "peer products" for the main sample.

## Analysis Boundaries

- This round only covers public project searches, repository structure observation, license checks, and architecture comparison.
- No external scanning, exploitation, C2, lateral movement, persistence, phishing, or data exfiltration capability was run.
- "Borrowing" is limited to architecture, module boundaries, metadata models, evaluation/scoring, sandboxes, memory, observability, reporting, and UX.
- Third-party code is not copied directly by default. When a small generic snippet under MIT/BSD/Apache-2.0 genuinely needs to be brought in, its source, license, file-level attribution, and NOTICE/PROVENANCE must be recorded.
- GPL/AGPL/unclear-license projects are used for ideas only; their code is not copied into this repository.

## Current Project Baseline

AutoRedTeam-Orchestrator is currently positioned as a **research preview** AI red-team orchestration tool, with three entry points:

- CLI: `autort`, covering scan, detect, exploit, cve-search, pentest, report, and nuclei.
- SDK: `Scanner`, `Exploiter`, `AutoPentest`, `RedTeam`, `Reporter`.
- MCP: 142 registered capabilities locally, of which 132 tools, 6 prompts, and 4 resources (2026-05-19 baseline; see README for the current count).

Current strengths:

- Broad traditional security coverage: recon, detector, CVE, exploit, lateral, persistence, AD, C2, report, knowledge, MCTS, and prompt.
- MCP/CLI/SDK three-layer entry points already exist, suitable as an AI orchestration shell.
- Large local test surface: 83 test files and 2,107 test functions under tests/ (static count by `def test_`); any claim that the full suite passes needs to be re-verified by running it, and this document no longer cites historical numbers.

Current weaknesses:

- The AI automated red-team "task loop" is incomplete: no unified object model for planner, executor, critic, human gate, run state, artifact, cost, or trace.
- No agent sandbox: there are security tool capabilities, but no unified agent runtime for isolated execution, browser, commands, logs, and artifacts like PentAGI/Decepticon have.
- No AI red-team-specific schema: prompt injection, tool injection, data exfiltration, jailbreak, agent overreach, and MCP/skill risks have no unified plugin interface.
- No security evaluation loop: no standard target, probe/plugin, strategy/converter, scorer/assertion, report chain like promptfoo/garak/PyRIT/Giskard.
- No enterprise-grade observability: no Langfuse/OTel/Grafana-level trace, token, cost, failure-rate, or tool-call audit metrics.

## Main Peer Projects

Data source: GitHub REST API + GitHub repository pages, retrieved 2026-05-19. Stars are the values read from the API/pages at the time and will change later.

| Project | Stars | License | Activity | Type | Most relevant takeaway for this project |
| --- | ---: | --- | --- | --- | --- |
| [promptfoo](https://github.com/promptfoo/promptfoo) | 21381 | MIT | 2026-05-18 | LLM eval/red-team platform | Declarative config, providers/assertions/plugins/strategies, CI/CD, results views, risk scoring. |
| [PentAGI](https://github.com/vxcontrol/pentagi) | 17005 | MIT | 2026-05-18 | Fully automated AI penetration platform | Multi-agent, Docker sandbox, 20+ tools, long-term memory, knowledge graph, Langfuse/Grafana/OTel, REST/GraphQL, Web UI. |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) | 13170 | MIT | 2026-02-23 | LLM penetration testing agent framework | Pentest task tree, reasoning/session separation, prompt/tool organization, benchmark, research-paper backing. |
| [CAI](https://github.com/aliasrobotics/cai) | 8545 | NOASSERTION / MIT files | 2026-05-18 | Cybersecurity AI framework | Offensive/defensive automation, prompt injection protection, MCP support, benchmark/fluency, bug-bounty-ready positioning. |
| [garak](https://github.com/NVIDIA/garak) | 7846 | Apache-2.0 | 2026-05-15 | LLM vulnerability scanner | probes/generators/detectors/evaluators/harnesses, attack strategy library, extensible detectors. |
| [Giskard OSS](https://github.com/Giskard-AI/giskard-oss) | 5357 | Apache-2.0 | 2026-05-18 | LLM agent evaluation library | Black-box agent/multi-step pipeline wrapping, agent evaluation, RAG evaluation, modular packaging. |
| [PurpleLlama](https://github.com/meta-llama/PurpleLlama) | 4180 | NOASSERTION | 2026-05-18 | LLM security evaluation collection | CyberSecEval, visual prompt injection, spear phishing capability, autonomous offensive cyber operations test suite. |
| [Decepticon](https://github.com/PurpleAILAB/Decepticon) | 3886 | Apache-2.0 | 2026-05-18 | Autonomous Hacking Agent | agents/backends/llm/middleware/sandbox/tools layering — a good model for the agent runtime structure. |
| [PyRIT](https://github.com/microsoft/PyRIT) | 3851 | MIT | 2026-05-19 | Generative AI risk identification framework | prompt_target, prompt_converter, scenario, score, memory, dataset, executor. |
| [AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | 3743 | Apache-2.0 | 2026-05-15 | Full-stack AI red-team platform | OpenClaw scan, Agent scan, Skills scan, MCP scan, AI infra scan, LLM jailbreak evaluation. |
| [Vulnhuntr](https://github.com/protectai/vulnhuntr) | 2660 | AGPL-3.0 | 2025-02-06 | LLM code vulnerability discovery | Call-chain context expansion from remote input to server output, second-pass analysis, confidence score. AGPL — do not copy code. |
| [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai) | 2076 | MIT | 2026-05-18 | LLM eval framework | Prompt engineering, tool usage, multi-turn dialog, model-graded evals, 200+ built-in evaluations. |
| [AI Red Teaming Playground Labs](https://github.com/microsoft/AI-Red-Teaming-Playground-Labs) | 1938 | MIT | 2026-02-13 | AI red-team training range | Challenge/lab organization, Docker/K8s deployment, trainable and demonstrable AI red-team labs. |
| [Agentic Security](https://github.com/msoedov/agentic_security) | 1875 | Apache-2.0 | 2026-05-14 | Agentic LLM vulnerability scanner | attack_rules, probe_actor, probe_data, refusal_classifier, report_chart, MCP integration. |

## Who to Borrow From Most

### P0: PentAGI

Why: it is the closest thing to an "AI automated penetration platform", not just an LLM eval tool. Its GitHub README explicitly emphasizes autonomous penetration testing, Docker sandboxing, professional security tools, long-term memory, knowledge graphs, Langfuse/Grafana observability, REST/GraphQL APIs, and a Web UI.

What this project should borrow is not its tool-call details, but its platform skeleton:

- `Flow -> Task -> SubTask -> Action -> Artifact -> Memory` data model.
- Agent roles: researcher, developer, executor, critic, reporter.
- Sandboxed execution: commands, browser, tools, file artifacts, and network egress policy all governed by the runtime.
- Long-term memory: successful attack paths, target profiles, tool outputs, and failure causes are reusable.
- Knowledge graph: relationships between target, service, vulnerability, credential, artifact, and finding.
- Observability: Langfuse records LLM traces; OTel/Grafana records system metrics.

Landing actions for AutoRedTeam:

- Add `core/agent_runtime/`: flow, task, action, artifact, memory, sandbox, trace.
- Add `core/agent_roles/`: researcher, planner, executor, verifier, reporter.
- Wrap existing MCP/CLI tools as governed `Action`s instead of letting the agent call dangerous functions freely.

### P0: promptfoo

Why: it most maturely solves "AI red-teaming that is configurable, repeatable, and CI-ready".

Borrowable design:

- `targets`: HTTP, OpenAI-compatible, custom provider, MCP target.
- `plugins`: prompt injection, data exfiltration, agentic overreach, tool abuse, RAG leakage.
- `strategies`: base64, hex, homoglyph, multilingual, multi-turn, jailbreak variants.
- `assertions`: refusal quality, sensitive data leakage, out-of-scope tool calls, policy bypass.
- `report`: json, markdown, sarif, html, CI exit code.

Landing actions for AutoRedTeam:

- Add `config/ai_redteam.schema.yaml`.
- Add `core/ai_redteam/runner.py` to chain target/plugin/strategy/assertion/report.
- Add the `autort ai-redteam run scenario.yaml` CLI.
- Add the MCP tool `ai_redteam_run_scenario`, defaulting to dry-run and requiring explicit authorization for real calls to external targets.

### P0: garak + PyRIT

Why: they are the two projects with the clearest LLM red-team plugin boundaries.

Borrowable merged model:

- `Target`: the model under test, HTTP agent, browser agent, MCP agent, RAG app.
- `Probe`: what risk to test.
- `Strategy/Converter`: how to transform the payload.
- `Scorer/Detector`: how to judge the result.
- `Memory/Dataset`: samples, historical results, context.
- `Executor`: batching, concurrency, retries, cost control.

Landing actions for AutoRedTeam:

- Add `core/ai_redteam/targets/`
- Add `core/ai_redteam/probes/`
- Add `core/ai_redteam/strategies/`
- Add `core/ai_redteam/scorers/`
- Add `core/ai_redteam/datasets/`
- Add `core/ai_redteam/executors/`

### P1: AI-Infra-Guard

Why: it is the closest sample to the current trend of "AI infrastructure red-teaming", covering Agent, Skills, MCP, AI infra, and jailbreak evaluation.

Borrowable design:

- MCP scan: scan an MCP server's exposed tools, dangerous parameters, out-of-scope calls, and prompt/tool injection surface.
- Skills scan: scan Agent skills / plugins for dangerous instructions, external writes, credential access, and hidden backdoors.
- Agent scan: scan agent tool boundaries, memory poisoning, privilege escalation, and cross-session leakage.
- Infra scan: scan OpenClaw/AI infra component risks.

Landing actions for AutoRedTeam:

- Add `core/ai_surface/`, dedicated to static analysis of the MCP/skills/agent/plugin attack surface.
- Extend current security capability from traditional web/pentest to the AI agent supply chain.
- Add `mcp_surface_scan`, `skill_surface_scan`, and `agent_tool_boundary_scan`.

### P1: Vulnhuntr

Why: it is not a red-team platform, but its call-chain approach to "LLM automated vulnerability discovery" is strong.

Borrowable design:

- Start from remote user input entry points.
- Let the model request more context functions/classes/variables.
- Expand step by step to a complete source -> sink call chain.
- Run a second-pass analysis for the specific vulnerability type.
- Output a confidence score.

Note: Vulnhuntr is AGPL-3.0 — do not copy its code.

Landing actions for AutoRedTeam:

- Add `core/code_agent/`: entrypoint discovery, context expansion, source-sink trace, LLM verifier, confidence scoring.
- Output is only for authorized code auditing and defensive remediation — it must not generate weaponized exploits directly usable against third parties.

### P1: CAI / PentestGPT / Decepticon

Why: they are close to the "AI automated penetration agent" research direction, good for borrowing agent prompts, task state, and benchmark organization — not for copying attack implementations.

Borrowable design:

- PentestGPT: task tree, session, reasoning, benchmark.
- CAI: offensive/defensive two-way automation, prompt injection guardrails, MCP support, bug-bounty-ready benchmark.
- Decepticon: agents/backends/llm/middleware/sandbox/tools layering.

Landing actions for AutoRedTeam:

- Unify `RunState`: target, known information, plan, tool calls, evidence, next step, risk gates.
- Add `HumanGate`: pause for confirmation before high-risk actions.
- Add `BenchmarkHarness`: evaluate agent success rate, cost, false positives, and policy-violating actions using ranges/CTFs/labs.

## Product Roadmap, Re-prioritized for This Project

### 1. From "Tool Platform" to "Agent Platform"

AutoRedTeam today is more like a tool collection + MCP wrapper. The next step is to bring every tool under an agent runtime:

```text
Scenario
  -> Flow
    -> Task
      -> SubTask
        -> Action(tool_call / browser / shell / model_call)
          -> Artifact
          -> Evidence
          -> Finding
```

### 2. From "Imperative Calls" to "Declarative Scenarios"

Add `scenario.yaml`:

```yaml
name: authorized-ai-redteam
mode: dry-run
scope:
  allowed_targets:
    - http://127.0.0.1:8000
  blocked_targets:
    - 169.254.169.254
    - 127.0.0.1/admin
targets:
  - id: demo-agent
    type: http_agent
    endpoint: http://127.0.0.1:8000/chat
probes:
  - prompt_injection
  - tool_injection
  - data_exfiltration
  - rag_leakage
strategies:
  - encoding
  - homoglyph
  - multi_turn
scorers:
  - secret_leak_detector
  - unsafe_tool_call_detector
  - policy_bypass_detector
report:
  formats: [json, markdown, sarif]
gates:
  require_human_approval_for:
    - external_network
    - exploit
    - credential_access
    - persistence
```

### 3. From "Scan Results" to "Evidence / Scoring / Re-testing"

Unified output:

- `Attempt`: one probe/strategy/target combination.
- `Trace`: model input, model output, tool calls, errors, retries.
- `Score`: pass/fail, severity, confidence, evaluator, evidence excerpt.
- `Finding`: deduplicable, re-testable, exportable as SARIF/Markdown/JSON.

### 4. From "Exposed Dangerous Capabilities" to "Tiered Authorization"

Every action must carry:

- `risk_level`
- `requires_auth`
- `requires_human_gate`
- `allowed_in_dry_run`
- `network_policy`
- `artifact_policy`
- `cleanup_policy`

## Directions to Cut / Downgrade

This is not about deleting traditional security capabilities, but downgrading them to agent-callable tools:

- `exploit/lateral/persistence/c2/exfiltration` should not be default AI auto-execution paths.
- These capabilities should only be registered as `Action`s, defaulting to `dry_run`, with a human gate required before any real execution.
- The AI automated red-team main line should prioritize: AI app testing, MCP/skills/agent boundaries, authorized ranges, code auditing, and the reporting loop.

## Code-Copying Boundaries

Designs that can be borrowed:

- PentAGI's flow/task/action/artifact/memory/observability model.
- promptfoo's scenario configuration and plugin/strategy/assertion/report approach.
- garak/PyRIT's target/probe/strategy/scorer/executor layering.
- AI-Infra-Guard's MCP/skills/agent/infra scan categories.
- Vulnhuntr's call-chain context expansion and confidence score.
- Giskard/Inspect's agent eval, multi-turn, model-graded scoring.

Code that must not be copied:

- Implementations from AGPL/GPL/unclear-license projects.
- C2, persistence, detection-evasion, credential acquisition, exfiltration, or phishing execution implementations.
- Payloads and weaponized exploits directly usable against third-party targets.

## Final Ranking

The order most worth benchmarking against and "borrowing ideas from":

1. PentAGI: platform skeleton, sandbox, multi-agent, memory, observability, Web/API.
2. promptfoo: declarative AI red-teaming, CI, scoring, and reporting.
3. garak + PyRIT: LLM red-team plugin boundaries.
4. AI-Infra-Guard: MCP/skills/agent/AI infra security surface.
5. PentestGPT + CAI + Decepticon: AI automated penetration agent task flows and benchmarks.
6. Vulnhuntr: context expansion and confidence scoring for automated code vulnerability discovery.
7. Giskard + Inspect: evaluation, multi-turn, model-graded scoring, and agent eval.

The next thing to build is not more traditional detectors, but two foundation layers first:

- `core/agent_runtime/`: Flow/Task/Action/Artifact/Memory/Trace/HumanGate.
- `core/ai_redteam/`: Target/Probe/Strategy/Scorer/Scenario/Report.
