# AutoRedTeam-Orchestrator 分析进度

## 2026-05-19

### 当前状态

- 已克隆仓库到 `D:\A\github-project-public\AI-redteam\AutoRedTeam-Orchestrator`。
- 已确认当前分支为 `main`，远端为 `https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git`。
- 已初始化持久化状态文件：`task_plan.md`、`progress.md`、`findings.md`。

### 当前阶段

- 阶段 1：项目结构与元数据。

### 下一步

- 阅读 README、pyproject、requirements、CLI 入口和核心目录。
- 记录项目定位、模块边界、入口命令和测试命令。

### 阻塞点

- 暂无。

### 命令记录

| 命令/动作 | 结果 |
| --- | --- |
| `git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git AutoRedTeam-Orchestrator` | 成功 |
| `git status --short --branch` | `## main...origin/main` |
| `git remote -v` | origin 指向 Coff0xc/AutoRedTeam-Orchestrator |
| `rg --files` | 已确认 Python 项目结构、tests、core、handlers、payloads、templates 等目录 |
| 读取 `README.md`、`pyproject.toml`、`cli/main.py`、`autort/redteam.py` | 已确认项目定位、包元数据、CLI/MCP 入口和高风险红队能力边界 |
| 读取 `requirements*.txt`、`.env.example`、`config/config.yaml.example`、`.github/workflows` 列表 | 已确认依赖分层、配置占位符和 CI 文件存在 |
| 搜索密钥相关关键词 | 未发现真实密钥；发现 README/示例/CI 中的占位符和 secrets 引用 |
| 读取 `.github/workflows/ci.yml` | 已确认 lint/security/test/build 四类 job；pip-audit 和 detect-secrets 为非阻断 |
| 扫描非 ASCII 文件名 | 发现根目录 `.сlаudе-sесuritу-аudit-2026-04-07.md` 使用 Cyrillic 同形字符 |
| 读取混淆文件内容和字符码点 | 文件内容是依赖 CVE 审计记录；文件名中多个字符为 U+0441/U+0430/U+0435/U+0443 |
| `python --version` | Python 3.14.0，超出项目声明的 3.10-3.12 |
| `python -m pytest --version` | pytest 9.0.2 |
| `python -c "import autort; print(autort.__version__)"` | 输出 `3.1.0` |
| `python -m py_compile mcp_stdio_server.py` | 通过 |
| `python -m pytest --collect-only -q -m "not slow and not integration and not network"` | 收集 2019 项，排除 16 项，选中 2003 项 |
| `python -m pytest tests\\test_cli.py tests\\test_tool_result.py tests\\test_utils.py -q` | 61 passed |
| `python -m pytest tests\\test_sdk.py tests\\test_sarif.py tests\\test_recon_engine.py -q` | 127 passed |
| `python -m pytest tests\\test_rce_exploiter_security.py tests\\test_sandbox.py tests\\test_core_c2.py -q` | 82 passed |
| 仅调用 `register_all_tools()` | 成功注册 132 个 MCP 工具，未启动 server，未执行工具 |

### 阶段 1 已确认

- Python 3.10+，包名 `autoredteam-orchestrator`，版本 `3.1.0`。
- 安装入口包含 CLI `autort` 和 MCP server `autoredteam-mcp`。
- CLI 能触发侦察、检测、利用、自动渗透、报告、Nuclei 模板扫描。
- 仓库包含横向移动、C2、持久化、提权、凭据搜索等高风险能力，后续仅做静态分析和低风险本地验证。

### 阶段 2 初步结论

- README 推荐 requirements 安装，适合本仓库当前依赖面。
- `pyproject.toml` 打包依赖可能不足，尤其是 CLI 所需 `typer`。
- 配置样例没有硬编码真实凭据。
- CI 的 detect-secrets 是提示性质，不是阻断性质。

### 阶段 3 结论

- 项目主入口为三层：CLI `cli.main`、SDK `autort/*`、MCP `mcp_stdio_server.py` + `handlers/*`。
- 核心能力集中在 `core/*`，handler 层主要做 MCP 工具包装。
- MCP 注册实测 132 个工具，README 工具矩阵仍写 131。

### 阶段 4 结论

- 已完成低风险本地验证：语法、导入、测试收集、270 个测试、MCP 工具注册。
- 未运行全量测试，因为当前 Python 3.14 不在支持矩阵内，且全量套件包含大量安全能力测试，需要更接近 CI 的 Python 3.10-3.12 环境。

### 收尾状态

- `git status --short` 仅显示新增 `task_plan.md`、`progress.md`、`findings.md` 三个分析状态文件。
- `git diff --stat` 对已跟踪文件无输出，因为本轮没有修改既有项目代码。
- `logs/` 下出现本地运行日志，但当前未进入 git 未跟踪列表。

### 建议下一步

1. 在 Python 3.10/3.11/3.12 环境运行 CI 同款测试命令。
2. 修正文档工具数量不一致：README 工具矩阵从 131 对齐到实测 132。
3. 评估 `pyproject.toml` 是否应补齐 CLI/SDK 运行依赖，避免 `pip install .` 入口缺包。
4. 处理同形字符隐藏文件名，改为普通 ASCII 路径并标注审计来源。
5. 审查授权中间件是否覆盖 CLI、SDK、MCP 所有危险入口。

## 2026-05-19 深度能力/边界/清理任务

### 目标

- 详细分析 AutoRedTeam-Orchestrator 的能力面和能力边界。
- 检索同类项目，提炼可借鉴思路和实现方向。
- 在不引入许可证风险的前提下保持仓库卫生，清理有证据证明无用或误导的内容。

### 当前阶段

- 阶段 6：详细能力与边界矩阵。

### 执行边界

- 不运行真实外部扫描、攻击、爆破、C2、持久化、横向移动或 exfiltration。
- 第三方项目默认只借鉴设计和测试策略，不直接复制代码。
- 删除动作必须有引用分析和验证支撑。

### 本轮已做

- 已读取现有 `task_plan.md`、`progress.md`、`findings.md` 并延续计划。
- 已读取相关技能：`planning-with-files-zh`、`coff0xc-secure-code-appsec`、`coff0xc-software-engineering`。
- 已从 memory 确认用户偏好：复杂 repo 分析应建立并维护 `task_plan.md`、`progress.md`、`findings.md`。

### 能力盘点命令记录

| 命令/动作 | 结果 |
| --- | --- |
| 统计 `core/handlers/autort/cli/utils/tools/tests` Python 文件 | `core` 269、`handlers` 25、`autort` 6、`cli` 2、`utils` 16、`tools` 2、`tests` 77 |
| AST 扫描 `autort/cli/handlers` 顶层类与函数 | 确认 SDK 5 个类、CLI 主要命令、handler 注册函数 |
| 注册 MCP 并读取 manager | `122` tools、`6` prompts、`3` static resources、`1` resource template；计数器合计 `132` |
| AST 扫描 handler 装饰器 | 97 个显式 handler tool 函数；高危 lateral/persistence/AD/redteam/orchestration 多数带 dangerous/critical auth |
| 读取 `core/security/*` 与 `core/config/models.py` | 确认 auth mode、工具等级、目标验证、默认 blocked targets 和安全配置 |
| 搜索 legacy/deprecated/unused 线索 | 发现 `handlers/_detector_handlers_legacy.py` 未接入当前注册链；`mcp_security.py` 有测试和 README 引用，不应删除 |

### 同类项目调研记录

| 项目 | 来源 | 结论 |
| --- | --- | --- |
| Microsoft PyRIT | GitHub + 官方文档 | MIT；AI red-team 框架；可借鉴 target/converter/scorer/memory/scenario 结构 |
| promptfoo | GitHub | MIT；LLM eval/red-team CLI/library；可借鉴 declarative config、CI/CD 和结果视图 |
| NVIDIA garak | GitHub | Apache-2.0；LLM vulnerability scanner；可借鉴 probe 插件体系 |
| OWASP Nettacker | GitHub | Apache-2.0；自动化渗透/信息收集框架；可借鉴模块元数据和输出格式 |
| MITRE Caldera | GitHub | Apache-2.0；adversary emulation + plugin/C2/Web UI；可借鉴 core/plugin 和 ATT&CK 元数据 |
| Atomic Red Team | GitHub | MIT；ATT&CK 映射检测测试库；可借鉴 technique metadata 和 cleanup/dry-run 思路 |
| Faraday | GitHub | GPL-3.0；漏洞管理平台；不复制代码，只借鉴 workspace/finding lifecycle |
| Metasploit Framework | GitHub | README 指 BSD-style，但 GitHub license 检测复杂；不复制代码，只借鉴 module lifecycle |

### 清理与修复记录

| 动作 | 结果 |
| --- | --- |
| 删除 `handlers/_detector_handlers_legacy.py` | 已删除，当前 handler 测试通过 |
| 移动混淆审计文件 | 已移动到 `docs/security-audits/claude-security-audit-2026-04-07.md` |
| 清理 `__pycache__`、`.pytest_cache`、本地日志 | 已清理；测试后再次清理 |
| 清理 `data/operation_audit.jsonl`、`data/cve_storage.db`、`data/sessions/` | 已清理；`.gitignore` 新增 `data/operation_audit.jsonl` |
| 修正 README 工具计数 | 中文/英文 README 均改为 132 |
| 补齐 `pyproject.toml` CLI 依赖 | 新增 `typer>=0.9.0` |
| 修复 `SQLiVerifierMixin` stub 覆盖 | 委托 `BaseVerifier` 方法 |
| 修复测试 fixture 全局时间污染 | 增加 `_retry_sleep` hook，仅 patch HTTP retry sleep |

### 验证记录

| 命令 | 结果 |
| --- | --- |
| `python -m py_compile mcp_stdio_server.py cli\\main.py handlers\\__init__.py handlers\\detector_factory.py` | 通过 |
| `python -m pytest tests\\test_handlers_detector.py tests\\test_handlers_init.py tests\\test_cli.py tests\\test_tool_result.py -q` | 68 passed |
| MCP 注册计数 | `132`; 122 tools, 6 prompts, 3 resources, 1 template |
| `python -m pytest tests\\test_sdk.py tests\\test_sarif.py tests\\test_recon_engine.py tests\\test_mcp_security.py tests\\test_mcp_auth_middleware.py -q` | 235 passed |
| `python -m pytest tests\\test_core_concurrency.py::TestTokenBucket::test_refill_tokens tests\\test_core_concurrency.py::TestSlidingWindowRateLimiter::test_window_sliding tests\\test_core_concurrency.py::TestCircuitBreaker::test_half_open_state tests\\test_vuln_verifier_request_context.py -q` | 6 passed |
| `python -m pytest tests\\ -q -m "not slow and not integration and not network" --ignore=tests\\test_performance_integration.py --ignore=tests\\test_modules_jwt.py --maxfail=10` | 1975 passed, 2 deselected, 15 warnings |

## 2026-05-19 高星同类项目对照

### 本轮已做

- 用 GitHub REST API 查询当前同类项目 stars、forks、license、language、pushed_at、description。
- 将原始查询结果保存到本地忽略目录 `reports/github_peer_repos_2026-05-19.json`，该目录按 `.gitignore` 不入库。
- 新增 `docs/peer-project-benchmark.md`，沉淀同类项目对照、可借鉴结构、禁止复制边界和下一步优先级。

### 代表性 GitHub 指标

| 项目 | Stars | 许可证 | 结论 |
| --- | ---: | --- | --- |
| `rapid7/metasploit-framework` | 38203 | NOASSERTION | 只借鉴模块生命周期，不复制 exploit 代码 |
| `projectdiscovery/nuclei` | 28722 | MIT | 借鉴模板 DSL、matcher/extractor、evidence 输出 |
| `promptfoo/promptfoo` | 21371 | MIT | 借鉴声明式 red-team/eval 配置 |
| `redcanaryco/atomic-red-team` | 11963 | MIT | 借鉴 ATT&CK 技术元数据、prereq、cleanup、dry-run |
| `NVIDIA/garak` | 7843 | Apache-2.0 | 借鉴 probes/generators/detectors/evaluators 插件边界 |
| `mitre/caldera` | 6967 | Apache-2.0 | 借鉴 core/plugins、planners、abilities、adversaries |
| `DefectDojo/django-DefectDojo` | 4703 | BSD-3-Clause | 借鉴 finding 生命周期和 dedupe |
| `microsoft/PyRIT` | 3848 | MIT | 借鉴 target/converter/scorer/memory/dataset/executor 拆分 |

### 结论

- 当前项目能力覆盖已经很宽，最值得抄的是组织方式：能力元数据、声明式场景、AI red-team 插件边界、ATT&CK 元数据和 finding 生命周期。
- GPL 或许可证不明项目只借鉴产品/架构思路，不复制代码。
- 下一轮最建议先做 `capability_metadata` 和 `scenario schema`，再接 CLI/MCP/SDK。

## 2026-05-19 AI 自动化红队口径重筛

### 用户纠偏

- 用户明确要求主要看“AI 自动化红队、AI 红队攻击、AI 自动化渗透平台”的类似项目。
- 已将传统安全高星项目降权，不再把 Metasploit/Nuclei/ZAP/DefectDojo 作为主同类样本。

### 本轮已做

- 使用 GitHub Search API 以 `LLM red teaming`、`AI red team`、`autonomous pentesting`、`AI pentest`、`PentestGPT`、`cybersecurity agent`、`prompt injection red team` 等关键词重新筛选。
- 将原始搜索结果保存到本地忽略文件 `reports/github_ai_redteam_search_2026-05-19.json`。
- 对精选项目重新拉取 GitHub 元数据，并保存到本地忽略文件 `reports/github_ai_redteam_curated_2026-05-19.json`。
- 重写 `docs/peer-project-benchmark.md`，改成 AI 自动化红队专版。

### AI 自动化红队主样本

| 项目 | Stars | 许可证 | 类型 | 本项目应抄的重点 |
| --- | ---: | --- | --- | --- |
| `promptfoo/promptfoo` | 21381 | MIT | LLM eval/red-team 平台 | 声明式 red-team 配置、plugins/strategies/assertions、CI/report |
| `vxcontrol/pentagi` | 17005 | MIT | 全自动 AI 渗透平台 | 多 Agent、沙箱、长期记忆、知识图谱、观测、Web/API |
| `GreyDGL/PentestGPT` | 13170 | MIT | LLM 渗透测试 Agent | pentest 任务树、session/reasoning、benchmark |
| `aliasrobotics/cai` | 8545 | NOASSERTION/MIT files | Cybersecurity AI 框架 | offensive/defensive automation、MCP、benchmark、guardrails |
| `NVIDIA/garak` | 7846 | Apache-2.0 | LLM 漏洞扫描器 | probes/generators/detectors/evaluators 插件分层 |
| `Giskard-AI/giskard-oss` | 5357 | Apache-2.0 | LLM Agent 评测库 | agent/multi-step/RAG evaluation |
| `PurpleAILAB/Decepticon` | 3886 | Apache-2.0 | Autonomous Hacking Agent | agents/backends/llm/middleware/sandbox/tools 分层 |
| `microsoft/PyRIT` | 3851 | MIT | 生成式 AI 风险识别框架 | prompt_target/converter/scenario/score/memory/executor |
| `Tencent/AI-Infra-Guard` | 3743 | Apache-2.0 | AI 基础设施红队 | MCP/skills/agent/AI infra scan |
| `protectai/vulnhuntr` | 2660 | AGPL-3.0 | LLM 代码漏洞发现 | call-chain context expansion、confidence score；不复制代码 |
| `msoedov/agentic_security` | 1875 | Apache-2.0 | Agentic LLM 漏洞扫描器 | attack_rules、probe_actor、refusal_classifier、report_chart、MCP |

### 更新后的路线

- P0：抄 PentAGI 的 `agent_runtime` 平台骨架。
- P0：抄 promptfoo 的声明式 `scenario.yaml` 和 report/CI 结构。
- P0：抄 garak/PyRIT 的 `Target/Probe/Strategy/Scorer/Executor` 分层。
- P1：抄 AI-Infra-Guard 的 MCP/skills/agent 安全面。
- P1：抄 Vulnhuntr 的代码漏洞发现上下文扩展，但不复制 AGPL 代码。

## 2026-05-19 AI 红队基础层落地

### 本轮已做

- 新增 `core/agent_runtime/`：`Flow`、`Task`、`Action`、`ActionPolicy`、`Artifact`、`TraceEvent`、`HumanGate`、`AgentRunState`。
- 新增 `core/ai_redteam/`：`Scenario`、`Scope`、`Target`、`Probe`、`Strategy`、`Scorer`、`Attempt`、`Score`、`AIRedTeamRunner`。
- 新增 `config/ai_redteam.example.yaml`，采用 promptfoo/garak/PyRIT 风格的声明式场景。
- CLI 新增 `autort ai-redteam run <scenario>`，默认 dry-run，只生成 attempts、scores 和 trace，不请求目标、不调用模型、不跑 shell、不执行扫描器。
- 新增 `tests/test_ai_redteam_runtime.py` 覆盖策略阻断、场景加载、dry-run 计划、blocked target 和 CLI。
- 修复 `tests/conftest.py` 中 HTTP retry sleep fixture 的环境卡顿：Windows 上导入 `aiohttp` 会经 `platform.system()` 触发 WMI 查询卡住，已在该 fixture 内短暂 patch `platform.system`，避免无关测试 hang。

### 验证记录

| 命令 | 结果 |
| --- | --- |
| `python -m py_compile tests\\conftest.py core\\agent_runtime\\models.py core\\ai_redteam\\models.py core\\ai_redteam\\runner.py cli\\main.py` | 通过 |
| pytest wrapper: `tests/test_ai_redteam_runtime.py` | 6 passed |
| pytest wrapper: `tests/test_cli.py` | 11 passed |
| pytest wrapper: `tests/test_ai_redteam_runtime.py tests/test_cli.py` | 17 passed |
| `python -c "from core.ai_redteam import ..."` | 通过，示例场景生成 16 attempts、48 scores、16 trace events |
| `python -m cli.main ai-redteam run config\\ai_redteam.example.yaml` | 通过，输出 dry-run JSON；无目标调用 |

### 测试环境备注

- 直接 `python -m pytest ...` 在本机 Python 3.14 环境会被 `pyreadline3/readline` 或 `aiohttp -> platform.system() -> WMI` 卡住。
- 已用 `sys.modules['readline'] = None` 的 pytest wrapper 验证新增和相关 CLI 测试，这是当前环境下可复现的低风险验证方式。
- 仍有既有 `requests` 依赖版本警告：`urllib3/chardet/charset_normalizer doesn't match a supported version`。

## 2026-05-19 AI 红队 MCP 接入

### 本轮已做

- `handlers/ai_handlers.py` 新增 MCP 工具 `ai_redteam_run_scenario`。
- 工具支持两种输入：
  - `scenario`：直接传声明式场景字典。
  - `scenario_path`：读取本地 YAML/JSON 场景文件。
- 当前 MCP 工具仍只调用 `AIRedTeamRunner(...).run()` 的 dry-run 计划层；active 模式默认被 runner 阻断。
- `handlers/__init__.py` AI 工具数量从 3 更新为 4。
- `README.md`、`README_EN.md` 工具数从 132 更新为 133，AI 类工具数从 3 更新为 4。
- 新增 `tests/test_handlers_ai.py`，覆盖 AI handler 注册计数、dict 场景 dry-run、缺失输入错误。

### 验证记录

| 命令 | 结果 |
| --- | --- |
| `python -m py_compile handlers\\ai_handlers.py handlers\\__init__.py tests\\test_handlers_ai.py ...` | 通过 |
| pytest wrapper: `tests/test_handlers_ai.py tests/test_ai_redteam_runtime.py` | 9 passed |
| pytest wrapper: `tests/test_handlers_init.py tests/test_handlers_ai.py` | 20 passed |
| pytest wrapper: `tests/test_ai_redteam_runtime.py tests/test_cli.py tests/test_handlers_ai.py` | 20 passed |
| MCP 注册计数命令 | 通过，输出 `133`；其中 `ai=4` |

### 仓库卫生

- 已清理 `__pycache__`、`.pytest_cache` 和 `data/operation_audit.jsonl`。
- `reports/*.json` 检索结果仍按 `.gitignore` 忽略，不进入 git 状态。

## 2026-05-19 阶段 14：AI 工具攻击面静态盘点

### 本轮已做

- 新增 `core/ai_surface/`，用 AST 静态解析 handler 文件中的 `@tool` MCP 工具、装饰器、参数、调用名和风险词。
- 新增 CLI：`autort ai-surface scan --path handlers`，默认只读扫描，不导入或执行 handler。
- 新增 MCP 工具：`ai_surface_scan_handlers`，AI 工具计数从 4 更新到 5，总 MCP 注册计数从 133 更新到 134。
- 修复 CLI `_output` 在 Windows cp1252 stdout 下打印中文 JSON 触发 `UnicodeEncodeError` 的兼容问题。
- 补充测试：`tests/test_ai_surface.py`、`tests/test_handlers_ai.py`、`tests/test_cli.py`。

### 验证记录

| 命令 | 结果 |
| --- | --- |
| `python -m py_compile core\\ai_surface\\__init__.py core\\ai_surface\\models.py core\\ai_surface\\scanner.py handlers\\ai_handlers.py handlers\\__init__.py cli\\main.py tests\\test_ai_surface.py tests\\test_handlers_ai.py tests\\test_cli.py` | 通过 |
| pytest wrapper: `tests/test_ai_surface.py tests/test_handlers_ai.py tests/test_cli.py tests/test_handlers_init.py -q` | 35 passed |
| `python -m cli.main ai-surface scan --path handlers\\ai_handlers.py` | 通过；扫描 1 个文件、5 个工具 |
| MCP 注册计数命令 | 通过；总计 `134`，其中 `ai=5` |
| `scan_handler_surface('handlers')` 汇总 | 扫描 23 个 handler 文件、99 个静态工具定义；risk counts: info 0 / low 13 / moderate 28 / high 20 / critical 38；issue_count 13 |

### 当前边界

- 静态扫描结果是候选风险盘点，不代表真实漏洞确认。
- 不覆盖 factory 动态生成的每一个 detector 实例，只覆盖源码中的显式工具定义和工厂入口。
- 不执行真实目标请求、模型调用、shell、扫描器或利用器。
