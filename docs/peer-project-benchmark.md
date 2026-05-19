# AutoRedTeam-Orchestrator AI 自动化红队同类项目对照

日期：2026-05-19

## 本轮口径

用户明确要求聚焦：

- AI 自动化红队
- AI 红队攻击 / LLM 红队
- AI 自动化渗透平台
- Agentic pentest / autonomous cyber agent

因此本轮不再把 Metasploit、Nuclei、ZAP、DefectDojo 这类传统高星安全项目放进主对照表。它们仍有工程参考价值，但不是“同类产品主样本”。

## 分析边界

- 本轮只做公开项目检索、仓库结构观察、许可证判断和架构对照。
- 不运行任何外部扫描、漏洞利用、C2、横向移动、持久化、钓鱼或数据外传能力。
- “抄”限定为借鉴架构、模块边界、元数据模型、评测/评分、沙箱、记忆、观测、报告和 UX。
- 第三方代码默认不直接复制。确需引入 MIT/BSD/Apache-2.0 小段通用代码时，必须记录来源、许可证、文件级归属和 NOTICE/PROVENANCE。
- GPL/AGPL/许可证不明项目只借鉴思路，不复制代码到当前仓库。

## 当前项目基线

AutoRedTeam-Orchestrator 当前定位是企业级 AI 红队编排平台，已有三类入口：

- CLI：`autort`，覆盖 scan、detect、exploit、cve-search、pentest、report、nuclei。
- SDK：`Scanner`、`Exploiter`、`AutoPentest`、`RedTeam`、`Reporter`。
- MCP：本地注册验证为 132 项能力，其中 122 tools、6 prompts、3 resources、1 resource template。

当前优势：

- 传统安全能力覆盖广：recon、detector、CVE、exploit、lateral、persistence、AD、C2、report、knowledge、MCTS、prompt。
- 已有 MCP/CLI/SDK 三层入口，适合做 AI 编排外壳。
- 本地测试面较大，非 slow/non-network 套件已验证过 1975 passed。

当前短板：

- AI 自动化红队的“任务闭环”不足：缺 planner、executor、critic、human gate、run state、artifact、cost、trace 的统一对象模型。
- 缺 agent 沙箱：当前有安全工具能力，但没有像 PentAGI/Decepticon 那种隔离执行、浏览器、命令、日志、工件的统一 agent runtime。
- 缺 AI red-team 专用 schema：prompt injection、tool injection、data exfiltration、jailbreak、agent overreach、MCP/skill 风险没有统一插件接口。
- 缺安全评测闭环：没有 promptfoo/garak/PyRIT/Giskard 那种 target、probe/plugin、strategy/converter、scorer/assertion、report 的标准链路。
- 缺企业级观测：没有 Langfuse/OTel/Grafana 级 trace、token、成本、失败率和工具调用审计指标。

## 主对照项目

数据来源：GitHub REST API + GitHub 仓库页面，检索时间为 2026-05-19。Stars 为当时 API/页面读取值，后续会变化。

| 项目 | Stars | 许可证 | 活跃度 | 类型 | 与本项目最相关的可抄点 |
| --- | ---: | --- | --- | --- | --- |
| [promptfoo](https://github.com/promptfoo/promptfoo) | 21381 | MIT | 2026-05-18 | LLM eval/red-team 平台 | 声明式配置、providers/assertions/plugins/strategies、CI/CD、结果视图、风险评分。 |
| [PentAGI](https://github.com/vxcontrol/pentagi) | 17005 | MIT | 2026-05-18 | 全自动 AI 渗透平台 | 多 Agent、沙箱 Docker、20+ 工具、长期记忆、知识图谱、Langfuse/Grafana/OTel、REST/GraphQL、Web UI。 |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) | 13170 | MIT | 2026-02-23 | LLM 渗透测试 Agent 框架 | pentest 任务树、reasoning/session 分离、prompt/tool 组织、benchmark、研究论文背书。 |
| [CAI](https://github.com/aliasrobotics/cai) | 8545 | NOASSERTION / MIT files | 2026-05-18 | Cybersecurity AI 框架 | offensive/defensive automation、prompt injection 防护、MCP 支持、benchmark/fluency、bug-bounty-ready 定位。 |
| [garak](https://github.com/NVIDIA/garak) | 7846 | Apache-2.0 | 2026-05-15 | LLM 漏洞扫描器 | probes/generators/detectors/evaluators/harnesses、攻击策略库、可扩展检测器。 |
| [Giskard OSS](https://github.com/Giskard-AI/giskard-oss) | 5357 | Apache-2.0 | 2026-05-18 | LLM Agent 评测库 | black-box agent/multi-step pipeline 包装、agent evaluation、rag evaluation、模块化包。 |
| [PurpleLlama](https://github.com/meta-llama/PurpleLlama) | 4180 | NOASSERTION | 2026-05-18 | LLM 安全评测集合 | CyberSecEval、visual prompt injection、spear phishing capability、autonomous offensive cyber operations 测试套件。 |
| [Decepticon](https://github.com/PurpleAILAB/Decepticon) | 3886 | Apache-2.0 | 2026-05-18 | Autonomous Hacking Agent | agents/backends/llm/middleware/sandbox/tools 分层，适合抄 agent runtime 结构。 |
| [PyRIT](https://github.com/microsoft/PyRIT) | 3851 | MIT | 2026-05-19 | 生成式 AI 风险识别框架 | prompt_target、prompt_converter、scenario、score、memory、dataset、executor。 |
| [AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | 3743 | Apache-2.0 | 2026-05-15 | 全栈 AI 红队平台 | OpenClaw scan、Agent scan、Skills scan、MCP scan、AI infra scan、LLM jailbreak evaluation。 |
| [Vulnhuntr](https://github.com/protectai/vulnhuntr) | 2660 | AGPL-3.0 | 2025-02-06 | LLM 代码漏洞发现 | 从远程输入到 server output 的 call-chain context expansion、二次分析、confidence score。AGPL，不复制代码。 |
| [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai) | 2076 | MIT | 2026-05-18 | LLM eval 框架 | prompt engineering、tool usage、multi-turn dialog、model-graded evals、200+ 预置评测。 |
| [AI Red Teaming Playground Labs](https://github.com/microsoft/AI-Red-Teaming-Playground-Labs) | 1938 | MIT | 2026-02-13 | AI 红队训练靶场 | challenge/lab 组织、Docker/K8s 部署、可训练和演示的 AI red-team lab。 |
| [Agentic Security](https://github.com/msoedov/agentic_security) | 1875 | Apache-2.0 | 2026-05-14 | Agentic LLM 漏洞扫描器 | attack_rules、probe_actor、probe_data、refusal_classifier、report_chart、MCP 集成。 |

## 最该抄谁

### P0：PentAGI

理由：它最像“AI 自动化渗透平台”，不是单纯 LLM eval。GitHub README 明确强调 autonomous penetration testing、Docker 沙箱、专业安全工具、长期记忆、知识图谱、Langfuse/Grafana 观测、REST/GraphQL API 和 Web UI。

本项目应抄的不是它的工具调用细节，而是平台骨架：

- `Flow -> Task -> SubTask -> Action -> Artifact -> Memory` 数据模型。
- Agent 分工：researcher、developer、executor、critic、reporter。
- 沙箱执行：命令、浏览器、工具、文件工件、网络出口策略统一由 runtime 管。
- 长期记忆：成功攻击路径、目标画像、工具输出、失败原因可复用。
- 知识图谱：target、service、vulnerability、credential、artifact、finding 的关系图。
- 观测：Langfuse 记录 LLM trace，OTel/Grafana 记录系统指标。

对 AutoRedTeam 的落地动作：

- 新增 `core/agent_runtime/`：flow、task、action、artifact、memory、sandbox、trace。
- 新增 `core/agent_roles/`：researcher、planner、executor、verifier、reporter。
- 把现有 MCP/CLI 工具封装成受控 `Action`，而不是让 Agent 直接随意调用危险函数。

### P0：promptfoo

理由：它最成熟地解决了“AI red-team 可配置、可复测、可进 CI”的问题。

可抄设计：

- `targets`：HTTP、OpenAI-compatible、custom provider、MCP target。
- `plugins`：prompt injection、data exfiltration、agentic overreach、tool abuse、RAG leakage。
- `strategies`：base64、hex、homoglyph、多语言、multi-turn、jailbreak variants。
- `assertions`：拒答质量、敏感数据泄露、越权工具调用、政策绕过。
- `report`：json、markdown、sarif、html、CI exit code。

对 AutoRedTeam 的落地动作：

- 新增 `config/ai_redteam.schema.yaml`。
- 新增 `core/ai_redteam/runner.py`，把 target/plugin/strategy/assertion/report 串起来。
- 新增 `autort ai-redteam run scenario.yaml` CLI。
- 新增 MCP tool：`ai_redteam_run_scenario`，默认 dry-run，需要显式授权真实调用外部目标。

### P0：garak + PyRIT

理由：它们是 LLM 红队插件边界最清楚的两个项目。

可抄合并模型：

- `Target`：被测模型、HTTP agent、browser agent、MCP agent、RAG app。
- `Probe`：要测什么风险。
- `Strategy/Converter`：怎么变形 payload。
- `Scorer/Detector`：怎么判断结果。
- `Memory/Dataset`：样本、历史结果、上下文。
- `Executor`：批量、并发、重试、成本控制。

对 AutoRedTeam 的落地动作：

- 新增 `core/ai_redteam/targets/`
- 新增 `core/ai_redteam/probes/`
- 新增 `core/ai_redteam/strategies/`
- 新增 `core/ai_redteam/scorers/`
- 新增 `core/ai_redteam/datasets/`
- 新增 `core/ai_redteam/executors/`

### P1：AI-Infra-Guard

理由：它是“AI 基础设施红队”方向最贴近当前趋势的样本，覆盖 Agent、Skills、MCP、AI infra 和 jailbreak evaluation。

可抄设计：

- MCP scan：扫描 MCP server 暴露工具、危险参数、越权调用、prompt/tool injection 面。
- Skills scan：扫描 Agent skills / 插件中的危险指令、外部写入、凭据访问、隐藏后门。
- Agent scan：扫描 agent 工具边界、记忆污染、权限升级、跨会话泄露。
- Infra scan：扫描 OpenClaw/AI infra 组件风险。

对 AutoRedTeam 的落地动作：

- 新增 `core/ai_surface/`，专门做 MCP/skills/agent/plugin 攻击面静态分析。
- 把当前安全能力从传统 web/pentest 扩展到 AI agent supply chain。
- 增加 `mcp_surface_scan`、`skill_surface_scan`、`agent_tool_boundary_scan`。

### P1：Vulnhuntr

理由：它不是红队平台，但在“LLM 自动漏洞发现”上有很强的 call-chain 思路。

可抄设计：

- 从远程用户输入入口开始。
- 让模型请求更多上下文函数/类/变量。
- 逐步扩展到完整 source -> sink call chain。
- 二次分析具体漏洞类型。
- 输出 confidence score。

注意：Vulnhuntr 是 AGPL-3.0，不复制代码。

对 AutoRedTeam 的落地动作：

- 新增 `core/code_agent/`：entrypoint discovery、context expansion、source-sink trace、LLM verifier、confidence scoring。
- 输出只给授权代码审计和防御修复，不生成可直接攻击第三方的 weaponized exploit。

### P1：CAI / PentestGPT / Decepticon

理由：它们贴近“AI 自动化渗透 agent”研究方向，适合抄 agent prompt、任务状态和 benchmark 组织，而不是复制攻击实现。

可抄设计：

- PentestGPT：任务树、session、reasoning、benchmark。
- CAI：offensive/defensive 双向自动化、prompt injection guardrails、MCP 支持、bug-bounty-ready benchmark。
- Decepticon：agents/backends/llm/middleware/sandbox/tools 分层。

对 AutoRedTeam 的落地动作：

- 统一 `RunState`：目标、已知信息、计划、工具调用、证据、下一步、风险门禁。
- 增加 `HumanGate`：高危动作前暂停确认。
- 增加 `BenchmarkHarness`：用靶场/CTF/lab 评测 agent 成功率、成本、误报和违规动作。

## 本项目应重排的产品路线

### 1. 从“工具平台”升级为“Agent 平台”

现在的 AutoRedTeam 更像工具集合 + MCP wrapper。下一步应把所有工具纳入 agent runtime：

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

### 2. 从“命令式调用”升级为“声明式场景”

新增 `scenario.yaml`：

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

### 3. 从“扫描结果”升级为“证据/评分/复测”

统一输出：

- `Attempt`：一次 probe/strategy/target 组合。
- `Trace`：模型输入、模型输出、工具调用、错误、重试。
- `Score`：通过/失败、严重度、confidence、evaluator、证据片段。
- `Finding`：可去重、可复测、可导出 SARIF/Markdown/JSON。

### 4. 从“危险能力暴露”升级为“分级授权”

每个 action 必须带：

- `risk_level`
- `requires_auth`
- `requires_human_gate`
- `allowed_in_dry_run`
- `network_policy`
- `artifact_policy`
- `cleanup_policy`

## 该删/该降级的方向

不是删掉传统安全能力，而是降级为 Agent 可调用工具：

- `exploit/lateral/persistence/c2/exfiltration` 不应该作为默认 AI 自动执行路径。
- 这些能力应只作为 `Action` 注册，默认 `dry_run`，真实执行前必须 human gate。
- AI 自动化红队主线应优先做：AI app 测试、MCP/skills/agent 边界、授权靶场、代码审计、报告闭环。

## 代码复制边界

可以抄设计：

- PentAGI 的 flow/task/action/artifact/memory/observability 模型。
- promptfoo 的 scenario 配置和 plugin/strategy/assertion/report 思路。
- garak/PyRIT 的 target/probe/strategy/scorer/executor 分层。
- AI-Infra-Guard 的 MCP/skills/agent/infra scan 分类。
- Vulnhuntr 的 call-chain context expansion 和 confidence score。
- Giskard/Inspect 的 agent eval、multi-turn、model-graded scoring。

不复制代码：

- AGPL/GPL/许可证不明项目实现。
- C2、持久化、规避检测、凭据获取、外传、钓鱼执行实现。
- 可直接攻击第三方目标的 payload 和 weaponized exploit。

## 最终排序

最值得对标和“抄思路”的顺序：

1. PentAGI：平台骨架、沙箱、多 Agent、记忆、观测、Web/API。
2. promptfoo：声明式 AI red-team、CI、评分和报告。
3. garak + PyRIT：LLM 红队插件边界。
4. AI-Infra-Guard：MCP/skills/agent/AI infra 安全面。
5. PentestGPT + CAI + Decepticon：AI 自动渗透 agent 任务流和 benchmark。
6. Vulnhuntr：代码漏洞自动发现的上下文扩展与 confidence scoring。
7. Giskard + Inspect：评测、multi-turn、model-graded scoring 和 agent eval。

下一步最该做的不是再堆传统 detector，而是先实现两个基础层：

- `core/agent_runtime/`：Flow/Task/Action/Artifact/Memory/Trace/HumanGate。
- `core/ai_redteam/`：Target/Probe/Strategy/Scorer/Scenario/Report。
