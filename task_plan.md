# AutoRedTeam-Orchestrator 项目分析计划

## 目标

对当前仓库做第一轮可验证项目分析，输出项目定位、架构结构、运行入口、依赖与测试状态、主要风险和下一步建议。

## 范围

- 本地仓库：`D:\A\github-project-public\AI-redteam\AutoRedTeam-Orchestrator`
- 只做本地静态分析和低风险验证。
- 不运行对外部目标有影响的扫描、攻击、爆破、C2 或远程写入动作。

## 非目标

- 不修改业务代码。
- 不推送 GitHub、不创建 PR、不改远程状态。
- 不接入生产凭据或真实目标。

## 阶段

| 阶段 | 状态 | 完成标准 |
| --- | --- | --- |
| 1. 项目结构与元数据 | complete | 确认语言、包管理、入口、目录和 README 描述 |
| 2. 依赖与配置面 | complete | 梳理 requirements、pyproject、配置样例和敏感边界 |
| 3. 核心调用链 | complete | 找到 CLI、orchestrator、handler、core 模块关系 |
| 4. 测试与质量门禁 | complete | 识别可运行测试命令并至少运行低风险验证 |
| 5. 风险与下一步 | complete | 汇总证据、风险、未完成项和建议执行顺序 |
| 6. 详细能力与边界矩阵 | complete | 产出 CLI/SDK/MCP/core 能力清单、危险等级、授权边界和可验证入口 |
| 7. 同类项目调研 | complete | 检索真实同类项目，记录许可证、能力差异和可借鉴设计，不直接复制不兼容代码 |
| 8. 仓库卫生与无用代码清理 | complete | 用静态引用、测试、入口和项目意图共同证明清理候选，做最小可逆改动 |
| 9. 回归验证与交付 | complete | 运行低风险测试/导入/注册验证，汇报完成项、未完成项和下一步 |
| 10. 高星同类项目对照 | complete | 用 GitHub 当前元数据筛选高星项目，形成可抄架构清单和代码复制边界 |
| 11. AI 自动化红队项目重筛 | complete | 将对照范围收窄到 AI 自动化红队、LLM 红队、AI 自动渗透平台和 Agentic pentest |
| 12. AI 红队基础层落地 | complete | 新增 agent runtime、AI red-team scenario/runner、dry-run CLI、示例配置和测试 |
| 13. AI 红队 MCP 接入 | complete | 将 dry-run runner 接入 MCP handler，形成 CLI + core + MCP 三层入口 |
| 14. AI 工具攻击面静态盘点 | complete | 新增 MCP/handler 静态扫描核心、CLI/MCP 入口和测试；只读解析，不执行工具 |

## 验收标准

- `findings.md` 中有证据化发现，而不是只写结论。
- `progress.md` 中记录已运行命令和结果。
- 最终回复包含：完成了什么、验证了什么、还剩什么、下一步是什么。

## 决策记录

- 2026-05-19：该仓库属于红队/安全编排工具，分析阶段禁止默认运行真实攻击、外部扫描、爆破或 C2 行为。
- 2026-05-19：用户要求检索同类项目并“抄思路、抄代码”。执行边界：可以借鉴架构、能力拆分、测试策略和 UX；第三方代码只有在许可证兼容、确有必要、保留来源和 NOTICE/PROVENANCE 时才可引入。默认不直接复制外部实现。
- 2026-05-19：用户要求删除无用代码。删除准入标准：必须同时满足“非公开入口、无静态引用或仅遗留引用、无测试依赖、无文档承诺或已有替代、删除后验证通过”。不删除高风险但当前未使用的能力模块，先标记为候选。
- 2026-05-19：高星项目对照结果落到 `docs/peer-project-benchmark.md`。当前优先级不是继续堆 detector，而是抄 Nuclei/promptfoo/garak/PyRIT/Atomic/Caldera/DefectDojo 的组织方式，先做能力元数据、声明式场景和 finding 生命周期。
- 2026-05-19：用户纠偏要求主要看 AI 自动化红队、AI 红队攻击、AI 自动化渗透平台。已将 `docs/peer-project-benchmark.md` 改为 AI 自动化红队专版，传统 Metasploit/Nuclei/ZAP/DefectDojo 只作为降权工程参考，不再进入主对照样本。
- 2026-05-19：第一批代码落地只实现 dry-run 与计划层，不执行真实目标调用、模型调用、shell、外部扫描或攻击工具。高风险能力后续只能作为带 `ActionPolicy`、`HumanGate` 和 scope policy 的受控 Action 接入。
- 2026-05-19：MCP 新增 `ai_redteam_run_scenario`，仅支持声明式场景 dry-run 计划；实测 MCP 注册工具数变为 133。README/README_EN 已同步工具数。
- 2026-05-19：AI surface 静态扫描只解析 handler 源码和装饰器，不导入 handler、不注册工具、不执行 payload。该能力用于发现缺失 auth/scope/human gate 的候选点，不能等同于动态安全验证。
