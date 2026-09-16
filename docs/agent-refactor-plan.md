# Agent 化重构方案（P1 / P2 / P3）与借用地图

本文档是 AutoRedTeam-Orchestrator 从「确定性 8 阶段流水线」转向「模型驱动工具层 + 证据门禁」的实施方案。

现状结论（基于源码核查，非推测）：

- 保留层：领域能力 106,529 行 / 232 文件 + 工具面 106 个 `@tool`（`handlers/` 7,992 行）。
- 替换层：AI / harness / 声明层 8,382 行 / 40 文件。
- 已写成但未接线的资产：`core/vuln_verifier/`（统计检验 + OOB 回调）、`core/knowledge/`（图谱存储）、`core/feedback/`（失败分析 + 策略调整）。
- 已确认的死代码：`core/engine_router.py`（零调用者）、`core/pipeline.py`（零 import）。

## 目标架构

```
L4 评测层     ai_redteam 从 dry-run 骨架 → 真 probe + ground truth（三家参照产品均无）
L3 证据层     vuln_verifier 接成强制门禁；无证据的 finding 由代码降级/拒收
L2 harness    模型驱动循环 + 上下文压缩 + HITL 审批 + 断点续跑 + 记忆回写
L1 工具层     106 个 tool + finding 级证据契约（沿用 verified / verification_confidence / evidence）
```

## 借用地图：抄什么、从哪抄、落到哪

### 判定原则（三层抄法）

| 层级 | 范围 | 许可约束 |
|---|---|---|
| ① 抄契约 | 数据模型、字段、接口形状、状态机 | 跨许可通用：契约不是表达，重写实现即可 |
| ② 抄控制流 | 循环结构、终止条件、门禁位置、压缩时机 | 跨许可通用：学结构，自己实现 |
| ③ 抄代码 | 直接复制实现 | **只在 MIT / Apache-2.0 下允许**，需保留声明 |

**硬约束**：`CyberStrikeus/CyberStrike` 是 AGPL-3.0，本项目是 MIT。**只允许 ① ②，一行代码都不能抄**，否则整个项目被传染。`AIPentest/CyberStrikeAI` 是 Apache-2.0，可抄代码但需保留版权声明（若复制实现，在文件头注明来源与许可）。`meta-blade` 是自有代码，无约束。

**第二个约束**：每个借来的东西必须落到一个「我们已经存在的模块」上。落不进去的，说明我们不需要它——不抄。

### 表格

| # | 借什么（思路/方法） | 来源与位置 | 层级 | 落到我们的哪里 | 怎么改 |
|---|---|---|---|---|---|
| 1 | **终态门禁对象**：终结不是「模型说完了」，而是一个结构化 Decision，含 `Finalizable` / `MissingChecks` / `RequireExecutionEvidence`，未通过则自动续跑 | CyberStrikeAI `internal/agentfinalizer/decision.go:29-150`（Apache-2.0） | ① 契约 | **P2**：报告生成前的 gate，读取 finding 级 `verified` / `evidence` | 新建 `core/evidence/` 门禁函数；缺证据的 finding 不出报告 |
| 2 | **缺证据由代码降级**：无 `execution_evidence` 就把 severity 压到 medium 并改名 `[UNCONFIRMED CANDIDATE]`，有证据则原位升级 confirmed | CyberStrike `packages/cyberstrike/src/tool/vulnerability.ts:62-127`（AGPL，仅学思路） | ② 控制流 | **P2**：同上 | 我们的降级依据比它强：不是「字段有没有填」，而是 `vuln_verifier` 的**真实重放结果** |
| 3 | **服务端必填字段校验**：入库前检查 9 个复现字段（target / reproduction_steps / evidence / impact …），缺失即拒绝 | CyberStrikeAI `internal/app/vulnerability_tools.go:157,284-290`（Apache-2.0） | ① 契约 | **P2**：finding 级证据字段的标准形状 | 沿用现有 `DetectionResult.evidence` 等字段，只补缺口（见下方设计修正记录） |
| 4 | **HITL 中间件**：`off \| approval \| review_edit` 三模式；同时拦 Invokable 与 Streamable；支持改参后放行；审批方可以是人也可以是独立审计模型 | CyberStrikeAI `hitl_middleware.go:42-77`（Apache-2.0） | ② 控制流 | **P3**：`utils/mcp_tooling._wrap_tool_func`（已有审计记录点，天然是中间件位置）+ `core/security/execution_mode.py` | 在工具包装器里加审批前置钩子，复用现有 `@require_*_auth` 分级作为触发条件 |
| 5 | **工具参数正则拦截**：执行前扫工具名 + 参数（含 JSON 字符串与百分号编码），命中即阻断 | CyberStrikeAI `internal/toolguard/toolguard.go:1-56`（Apache-2.0） | ② 控制流 | **P3**：`core/security/mcp_security.py` + 工具包装器 | 复用已有 `safe_executor`，把规则从「输入校验」扩展到「动作拦截」 |
| 6 | **上下文压缩三件套**：① 达 `max_total_tokens × 0.8` 触发摘要；② 超大工具结果落盘、只回预览；③ 剪枝历史工具输出 | CyberStrikeAI `eino_summarize.go:82-131` + `config.example.yaml:309-311`（Apache-2.0） | ② 控制流 | **P3**：harness（`meta-blade-agent/engine/core.py` 当前完全没有这一层） | 阈值配置化，不写死常数 |
| 7 | **惰性工具装载**：工具数 ≥20 时只常驻前 12 个 + 白名单，其余靠 `tool_search` 按需解锁（每个约 50 tokens） | CyberStrikeAI `config.example.yaml:303-306`；CyberStrike `lazy-registry.ts:36-40`（AGPL，仅学思路） | ② 控制流 | **P1 产出清单 → P3 落地**：我们 106 个工具远超阈值 | P1 的 lint 输出「建议常驻集」；P3 在 harness 侧按需注入 |
| 8 | **模型故障切换的两条铁律**：① 重试走指数退避（默认 4 次，上限 30s）；② **只在尚无可见输出时才切通道**，避免一轮输出拼接多个来源 | CyberStrikeAI `eino_model_resilience.go:217-231`（Apache-2.0）；meta-blade `providers/failover.py:31-81`（自有，已实现） | ② 控制流 | **P3**：`core/llm/provider.py`（P0 已修 key 回退，尚无重试/超时） | meta-blade 已有正确实现，直接复用其约束 |
| 9 | **跨会话事实图**：`project_facts` + 边关系，置信度 `confirmed \| tentative \| deprecated`，只把**索引**注入上下文而非全文 | CyberStrikeAI `internal/app/project_fact_tools.go:51-165` + `eino_summarize.go:459`（Apache-2.0） | ① 契约 | **P2/P3 接线**：`core/knowledge/`（`InMemoryGraphStore` + `SQLiteKnowledgeStore` 已存在，`add_entity` 目前**零外部调用**） | 不新建模块；给已有图谱补置信度字段 + 索引注入 |
| 10 | **幂等执行台账**：`tool_execution_id = sha256(session, request, call_id, name, args)` + 原子写 fsync，消息重投不重复执行副作用工具 | meta-blade `engine/core.py:595-606` + `JsonExecutionStore:107-120`（自有） | ① 契约 | **P3**：harness 的断点续跑 | 直接复用（抽成 `autort-engine` 时一并带走） |
| 11 | **取消时补齐悬空 tool_call**：取消后给缺失的 tool_call 补合成 tool 结果，保证下次可继续对话 | meta-blade `engine/core.py:405`（自有） | ② 控制流 | **P3**：harness | 直接复用 |
| 12 | **方法论即工具**：13 阶段不写死在代码里，而是作为 `methodology_status` 之类工具 + 提示文本，推进权在 LLM；前置条件只产出 blocking/warning violation | CyberStrike `methodology/{phase,methodology,validation}.ts`（AGPL，仅学思路） | ② 控制流 | **P3**：`core/orchestrator/` 的 `PHASE_ORDER` 枚举改成工具 + 提示 | 现有 `_should_skip_phase_v2` 的 6 条布尔规则 → 改成输出 violation 列表（不阻断，供模型判断） |
| 13 | **步数上限分级 + wrapUp 剥工具**：不同角色不同上限（orchestrator 40 / analyzer 20 / tester 60）；到顶的最后一轮直接删掉所有工具，逼模型输出纯文本 | CyberStrike `session/prompt.ts:648-654,733,896`（AGPL，仅学思路） | ② 控制流 | **P3**：harness 的终止条件 | meta-blade 现在只有 `max_iterations` + `max_iterations_exceeded → FAILED`（把超限当失败，而不是收尾） |
| 14 | **doom-loop / stuck 检测**：连续 3 次相同 (tool, args) 触发权限询问 | CyberStrike `session/processor.ts:21,167`（AGPL，仅学思路） | ② 控制流 | **P3**：harness | 纯逻辑，10 行量级 |
| 15 | **声明式扩展**：`tools/*.yaml`（命令 + 参数映射）、`skills/*/SKILL.md`（渐进披露）、`agents/*.md`（子代理）、`roles/*.yaml` | CyberStrikeAI 五个目录（Apache-2.0） | ① 契约 | **P1 起的工具契约** | 我们不引入 yaml 工具定义（Python 函数已是单一事实源），只借「子代理/角色用 markdown 声明」这一点 |
| 16 | **技能包签名与远端安装**：SKILL.md 走 Ed25519 验签，支持从远端拉取安装 | CyberStrike `skill/signing.ts:24` + `skill/discovery.ts:109-116`（AGPL，仅学思路） | ① 契约 | **P4（评测期）再定** | 与我们的 `ai_surface` 技能扫描天然配对：扫描 + 验签 |
| 17 | **成本与 token 细分**：区分 cache_read / cache_write，含 >200k 分档计价 | CyberStrike `provider/provider.ts:706` + `processor.ts:249-256`（AGPL，仅学思路） | ① 契约 | **P3**：token 统计 | 我们目前零 token 统计 |
| 18 | **token 使用落表**：prompt / completion / cached / reasoning 分别累加并落库 | CyberStrikeAI `eino_run_usage_accumulator.go:36-47`（Apache-2.0） | ① 契约 | **P3**：同上 | — |

### 明确不抄的

| 不抄的东西 | 原因 |
|---|---|
| CyberStrike 的 22 个 agent 与 proxy 流水线 | 领域是 bug-bounty / 代理流量分析，与我们的资产（106 个工具 + 验证器）不匹配；且 AGPL |
| CyberStrikeAI 的 Eino ADK / Go 编排 | 我们是 Python，且把控制层交给框架会挡住证据门禁的插点 |
| CyberStrikeAI 的 Shell 配方体系（`tools/*.yaml` 90 个） | 用 shell 命令做安全动作绕过我们的 Python 引擎与验证器，等于放弃 L3 |
| 任何评测框架 | 三家都没有，这是空白，抄不到 |
| 「把高危工具跑在服务进程里」的部署模型 | 两家参照产品都这么干（CSAI `exec.CommandContext`、CyberStrike 宿主 `spawn`），我们不要 |

## P1：工具契约标准化

| 项 | 内容 | 验收 |
|---|---|---|
| 1.1 | ~~`ToolResult` 增加 `evidence` / `confidence` / `verified`~~ → 改为：证据契约落在 **finding 级**，沿用领域既有约定（见下方设计修正记录） | 工具输出里的 `verified` / `verification_confidence` / `evidence` 在 MCP 边界不再被吞掉（回归测试：`test_handlers_ai` / `test_handlers_recon` / `test_handlers_orchestration`） |
| 1.2 | 新增工具契约 linter（`core/tooling/`），复用 `core.ai_surface` 的 AST 结果，追加契约规则 | `autort tools lint` 对自身仓库出报告：105 个工具、errors=0、55 个 warning（48 个高风险工具缺证据契约 + 7 个缺 Args 文档）= P2 工作清单 |
| 1.3 | 删除确认无消费者的死代码 `core/engine_router.py`、`core/pipeline.py` | 全仓 grep 零残留；测试全绿 |
| 1.4 | 停止 MCTS 假模拟的误导：`plan()` 输出标注 `probability_source` 与 `verified=false` | `test_handlers_mcts` 断言 `data.verified is False` 且含静态成功率表说明 |

## P2：证据门禁接线（已完成）

| 项 | 内容 | 验收 | 状态 |
|---|---|---|---|
| 2.1 | 证据条目复用领域已有的 `VerificationResult`，不新造格式 | `core/evidence/models.py` 的 `EvidenceItem` + 单测 | 完成 |
| 2.2 | 把 `batch_verify` / `OOBIntegratedVerifier` / 统计验证从死代码接成 MCP 工具 `verify_finding` | 验证器全部 mock 的单测；**真实靶机验证未做**（无授权靶机） | 完成（靶机验收待办） |
| 2.3 | 无证据 finding 由代码降级并标记，且区分“探测器自述”与“独立验证” | 集成测试：探测器风格 finding 被降级；经 `verify_finding` 后不被降级 | 完成 |
| 2.4 | 验证器暴露为 MCP tool，走完 manifest 注册与 profile 门禁 | manifest 142 项（tool 132）；profile 计数 safe 23 / scan 86 / active-lab 106 / full 142 | 完成 |

## P3：harness

设计见下方「P3 详细设计」；**尚未实施**。

## 设计修正记录

### 修正 1：证据契约不放在 `ToolResult` 信封层（P1.1）

最初的方案是给 `ToolResult` 加 `evidence` / `confidence` / `verified` 三个字段，并在 `ensure_tool_result` 里从字典结果中把它们提到信封层。实测后放弃，原因：

- 这三个名字**已经是领域词汇**：`confidence` 在 core/handlers 里出现 34 处、`evidence` 29 处、`verified` 14 处（如 `core/detectors/result.py` 的 `DetectionResult.evidence/verified/confidence`、`core/code_agent` 的 `confidence` 是 dict、WAF 检测的 `confidence` 是 0.9）。
- 在 `ensure_tool_result` 里提字段会把工具自身的输出字段从 `data` 里删掉，造成静默数据丢失。实测触发 2 个回归：`test_code_agent_expand_context_static_scan`（`KeyError: 'confidence'`）与 `test_waf_detect_found`。
- 项目里其实已有房内约定：`verify_and_exploit` 返回 `verified: bool` + `verification_confidence`，`DetectionResult` 用 `verified: bool` / `confidence: float`。

结论：证据契约以 **finding 级字段**为准（`verified` / `verification_confidence` / `evidence`），信封层不重复命名；门禁在 P2 读取 finding 字段。linter 同时接受两条路径（ToolResult 契约或输出里带证据字段）。

### 修正 2：`backends` 声明延后

「优先外部二进制、失败回退内置实现」在 P1 不实现：删除 `core/engine_router.py` 后没有消费者，按项目规则不为假想需求预留扩展点。等 harness 真正需要按后端选择时再建注册表。

### 修正 3：证据必须来自独立验证（provenance）

P2 初版把“报告里无证据的 finding 会被降级”当成卖点，但实现后 review 发现：门禁读的是 finding 自带的 `verified` / `confidence` / `evidence`，而 `core/detectors/` 里有 **67 处** detector 在做完一次语法/回显检查后就自行写上 `verified=True`（如 `core/detectors/access/open_redirect.py:206-214` 的 `confidence=0.90, verified=True`）。结果是探测器自述直接通过门禁，门禁退化成“字段填没填”，与参照产品无实质差别。

修正：`assess_finding` / `enforce_evidence_gate` 新增 `require_provenance: bool = True`，通过条件额外要求 provenance，满足任一即可：

- `finding["verified_by"]` 命中 `PROVENANCE_SOURCES`（`vuln_verifier` / `statistical_verifier` / `oob_callback` / `manual_review`）；
- 至少一条结构化 evidence 带非空 `method`（`core.vuln_verifier` 的 `VerificationResult` 经 `evidence_from_verification` 转换后会带上）。

限界（已写进代码）：门禁在进程内只能做保守判定，防不住故意伪造；它解决的是“探测器自述”与“验证器观测”混淆的问题，不是“谁能写 finding”的权限问题。

**行为后果（重要）**：默认开启后，**未经 `verify_finding` 的探测器 finding 一律被降级为 `[UNCONFIRMED]`，severity 封顶 medium**。这是我们想要的（那正是误报来源），但会显著改变现有报告观感；要旧行为时用 `require_provenance=False` 或 `ReportGenerator(require_evidence=False)`。

### 修正 4：OOB “未确认”不等于“已证伪”

`core/vuln_verifier/oob.py` 的四个 OOB 方法**恒返回 `is_vulnerable=False`**（源码注释即“需要回调确认”，行号 180/224/248/292）。初版 handler 用 `verified = any(is_positive(r) for r in results)`，把 OOB 未收到回调写成了 `contradicted`。修正为三态：仅 `confidence == "false_positive"` 才是 `False`；有正向结果才是 `True`；其余（含 OOB 无回调、无结果）为 `None`（unverified）。同时修正了 `_statistical_request_func` 吞异常导致“hang 被当成延迟”从而产出假 verified 的缺陷，并把统计请求超时绑到判定门槛（`expected_delay * 0.8`）。

## P3 详细设计

### 底座选择：vendor meta-blade 的 AgentEngine

抽到 `core/agent_engine/`，**不抽独立包**。理由（planner 对比结论）：

| 维度 | vendor 到 `core/agent_engine/` | 独立包 `autort-engine` |
|---|---|---|
| Python 版本 | 抽取时降级语法即可保持 3.10 | meta-blade 声明 `>=3.14`，发行包会把本项目（`>=3.10`）强行抬到 3.14 |
| 私有仓库耦合 | 单份本地代码 | 需先脱离 meta-blade 的私有 index 配置 |
| 发布成本 | 零 | 需 CI/版本/registry，改一行发两次版 |
| 双份代码分叉 | 有，用 `scripts/sync_agent_engine.py` + 记录上游 commit 收敛 | 更严重（两仓各自演化） |

### 抽取清单（必需）

| 抽出 | 来源 | 理由 |
|---|---|---|
| `engine/core.py` | `AgentEngine` / `EngineLimits` / `ToolExecutionResult` / `JsonExecutionStore` / `EngineResult` / `tool_execution_id` | 核心循环 + 幂等台账 + 取消补齐悬空 tool_call |
| `engine/tools.py` | `LocalToolExecutor` / `McpToolExecutor` / `CompositeToolExecutor` / `SubAgentToolExecutor` / `ToolBackend` | 工具组合与三种后端 |
| `providers/{base,failover,openai}.py` | `ModelMessage` / `NormalizedModelEvent` / `FailoverProvider` | 故障切换铁律“仅无可见输出才切” |
| `audit/trail.py` | `AuditTrail` | JSONL 审计 + 密钥脱敏 |
| `tools/definition.py` | `AgentTool` + `tool` 装饰器 | 工具元数据 |

**留在 meta-blade**：`private_task_executor.py`（RQ/queue/publisher 部署专属）、`consumer/`、`publisher/`、`storage/`、`tools/{oss_*,report_card_server,knowledge_tools,cvss_guide,todo_write}.py`、`subagent_registry.py`。
**最小依赖集**：stdlib + `mcp` + `httpx`；`EngineLimits` 是 dataclass，不依赖 pydantic。

目录：`core/agent_engine/{__init__,engine,limits,store,tools,audit}.py` + `providers/` + `context/compactor.py` + `guard/hitl.py` + `session/store.py`。

### 四个缺口的具体设计

| 缺口 | 落点 | 做法 | 验收 |
|---|---|---|---|
| 上下文压缩 | `context/compactor.py`，在 `run()` 每轮 `_model_turn` 前调用 | `CompactorConfig(max_total_tokens, trigger_ratio=0.8, tool_result_preview_bytes, keep_recent_tools)`；阈值读上轮 `turn.input_tokens`；超大工具结果落 `data/sessions/<sid>/harness/toolout/` 只回预览+路径+行数；剪枝必须**整块保留 assistant(tool_calls)+tool**，否则破坏取消补齐 | 假 provider 跑 60 轮 × 20KB 工具结果：不超限、落盘存在、tool_call 仍配对 |
| 危险动作审批门 | `core/security/hitl.py` + `utils/mcp_tooling._wrap_tool_func`（已有参数脱敏+审计，天然插点） | 三模式 `off/approval/review_edit`，模式读 `AUTORT_HITL_MODE`；触发等级复用现有三档装饰器（MODERATE→审批，DANGEROUS→审批+审阅，CRITICAL→强制人工）；拒绝返回 `is_error=True, reason="approval_required"` 并回灌模型；**异步审批不得阻塞事件循环**，必须有超时+默认 deny | 对 `@require_dangerous_auth` 工具注入 deny：函数体未执行、审计含 hitl 记录、模型收到 is_error |
| 工具异常降级 | `engine.py` 的 `_execute_tool` | 捕获非取消/非超时异常 → `ToolExecutionResult(..., is_error=True)` 回灌；**保留硬失败**：`CancelledError`、run 级 `TimeoutError`、provider error、`max_iterations_exceeded`、token 超限 | handler 抛 `ValueError` → 任务 `COMPLETED`，会话出现 is_error 消息，模型可换参重试 |
| 会话状态外置 | `session/store.py` 的 `JsonConversationStore` | 同 `JsonExecutionStore` 的 fsync + `os.replace` 模式；每消息一行含 request_id/iteration/role；恢复前用 `_close_cancelled_tool_calls` 补齐悬空 tool_call；幂等复用 `tool_execution_id` | 跑一轮→杀进程→重建：历史恢复且已完成 tool 不重执行 |

### 与 L1 / L3 的接口

- **L1 走进程内**：`register_all_handlers(mcp, counter, logger, profile=...)` 已支持进程内建 FastMCP；新增 `InProcessMcpToolExecutor(mcp)` 实现 `ToolBackend`（`list_tools()` / `call_tool()`），`McpToolExecutor` 只留跨进程。
- **L3 终结门禁**：新 `core/evidence/finalizer.py`，形状对照 CyberStrikeAI `decision.go:29-150` 的 `Finalizable/MissingChecks/RequireExecutionEvidence`；引擎返回 `COMPLETED` 前调用，`finalizable=False` 时把 `missing_checks` 当一条消息回灌续跑（受 `max_iterations` 限制）。门禁读 finding 级 `verified` / `verification_confidence` / `verifiable evidence`，不读信封层。

### 实施顺序（每步可独立交付验证）

| 步 | 内容 |
|---|---|
| 3.0 | vendor 抽取到 `core/agent_engine/`，降级 3.14 语法（PEP 695 `type` / `StrEnum` 是主要坑） |
| 3.1 | 工具异常降级 |
| 3.2 | 会话外置 |
| 3.3 | 审批门 |
| 3.4 | 上下文压缩 |
| 3.5 | 记忆回写 `core/knowledge` + token 统计 |
| 3.6 | L3 终结门禁接线 |

### 风险

- 3.14→3.10 语法降级是抽取第一坑，需逐文件改写并跑 mypy。
- 分叉：vendor 后与 meta-blade 各自演化，靠 sync 脚本 + 上游 commit 记录收敛。
- 压缩剪枝破坏 assistant(tool_calls)+tool 配对 → provider 直接拒绝历史。
- 门禁续跑与 `max_iterations` 冲突，需明确上限防死循环。

## 已知未决

- P3 需要决定 harness 是否 vendor 自 meta-blade（会引入私有仓库依赖），或抽独立包 `autort-engine`。
- 工具层的 `backends` 声明见上文「设计修正记录 修正 2」——当前不做。
- `core/mcts_planner.py` 的算法保留（可运行且有测试），只修输出语义；是否删除留待 P3 后评估。
