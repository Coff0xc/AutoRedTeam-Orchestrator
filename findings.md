# AutoRedTeam-Orchestrator 分析发现

## 证据等级

- 已验证：来自本地文件、命令输出或实际运行结果。
- 推断：基于本地证据的合理判断。
- 未验证：尚未读取源码或运行验证。

## 初始发现

| 主题 | 证据等级 | 发现 |
| --- | --- | --- |
| 仓库状态 | 已验证 | 当前仓库位于 `D:\A\github-project-public\AI-redteam\AutoRedTeam-Orchestrator`，分支为 `main`，跟踪 `origin/main`。 |
| 技术栈 | 已验证 | 文件结构显示为 Python 项目，包含 `pyproject.toml`、`requirements*.txt`、`setup.cfg`、`tests/`。 |
| 安全边界 | 推断 | 仓库包含 redteam、pentest、exploiter、c2、payloads、wordlists 等能力，后续验证应避免对外部目标执行有影响动作。 |

## 阶段 1：项目结构与元数据

| 主题 | 证据等级 | 发现 |
| --- | --- | --- |
| 项目定位 | 已验证 | `README.md` 标题为 `AutoRedTeam-Orchestrator`，描述为“企业级 AI 红队编排平台”，强调 Python 引擎、MCP、SDK、CLI 三层接口。 |
| 版本与 Python | 已验证 | `README.md` 徽章和 `pyproject.toml` 均显示版本 `3.1.0`，`pyproject.toml` 要求 `requires-python = ">=3.10"`。 |
| 包元数据 | 已验证 | `pyproject.toml` 项目名为 `autoredteam-orchestrator`，许可证为 MIT，基础依赖包括 `mcp`、`requests`、`aiohttp`、`pyyaml`、`pydantic`。 |
| 命令入口 | 已验证 | `pyproject.toml` 声明 `autort = "cli.main:app"` 和 `autoredteam-mcp = "mcp_stdio_server:main"`。 |
| CLI 行为 | 已验证 | `cli/main.py` 使用 Typer，提供 `scan`、`detect`、`exploit`、`cve-search`、`pentest`、`report`、`nuclei` 等命令，并在执行子命令时显示授权测试免责声明。 |
| 高风险能力 | 已验证 | `autort/redteam.py` 暴露横向移动、C2 beacon、持久化、提权、凭据搜索等接口；分析阶段不应默认运行这些功能。 |

## 阶段 2：依赖与配置面

| 主题 | 证据等级 | 发现 |
| --- | --- | --- |
| 依赖安装路径 | 已验证 | README 快速开始使用 `pip install -r requirements.txt`；`requirements.txt` 包含 MCP、HTTP、LLM、安全工具集成、红队功能、报告和 CLI 依赖。 |
| 打包依赖缺口 | 推断 | `pyproject.toml` 的基础依赖只有 `mcp`、`requests`、`aiohttp`、`pyyaml`、`pydantic`；但 `cli/main.py` 直接导入 `typer`，`requirements.txt` 才包含 `typer`。如果用户用 `pip install .` 安装，CLI 入口可能缺依赖。 |
| 可选依赖分层 | 已验证 | `requirements-core.txt` 是 MCP 最小依赖；`requirements-dev.txt` 包含 pytest、black、isort、pylint、flake8、mypy、bandit、pre-commit；`requirements-optional.txt` 标注“当前未被代码使用，但保留以备将来扩展”。 |
| 配置样例 | 已验证 | `.env.example` 和 `config/config.yaml.example` 使用空值或 `your_*_here` 占位符，没有看到真实密钥。 |
| 目标安全边界 | 已验证 | `config/config.yaml.example` 包含 `allowed_targets`、`blocked_targets` 和 `dangerous_operations`，但尚未确认所有 CLI/MCP 路径都会强制执行这些限制。 |
| CI 密钥扫描 | 已验证 | `.github/workflows/ci.yml` 包含 detect-secrets 扫描入口，但命令输出显示使用 `|| true`，因此密钥扫描不会让 CI 失败。 |
| CI 安全扫描阻断性 | 已验证 | Bandit 步骤没有 `continue-on-error`，理论上会阻断；pip-audit 有一个 `continue-on-error: true` 步骤，另一个 `pip-audit --strict --desc 2>&1 || true` 也是非阻断。 |
| 混淆文件名 | 已验证 | 仓库根目录存在 `.сlаudе-sесuritу-аudit-2026-04-07.md`，文件名中 `с/а/е/у` 使用 Cyrillic 同形字符。内容是依赖 CVE 审计记录，但该记录本身未在本轮重新用 pip-audit 验证。 |

## 阶段 3：核心调用链

| 主题 | 证据等级 | 发现 |
| --- | --- | --- |
| SDK 导出 | 已验证 | `autort/__init__.py` 导出 `Scanner`、`Exploiter`、`AutoPentest`、`RedTeam`、`Reporter`，版本 `3.1.0`。 |
| Scanner 调用链 | 已验证 | `autort/scanner.py` 封装 `core.recon`、`core.detectors`、Nuclei engine 和 passive recon，目标校验优先使用 `utils.validators`。 |
| Exploiter 调用链 | 已验证 | `autort/exploiter.py` 封装 `core.exploit`、`core.cve`，支持单漏洞利用、自动利用、CVE 搜索和 CVE 自动利用。 |
| AutoPentest 调用链 | 已验证 | `autort/pentest.py` 封装 `core.orchestrator.orchestrator.AutoPentestOrchestrator`，默认流程包含 recon、vuln_scan、poc_exec、exploit、priv_esc、lateral、exfiltrate、report。 |
| MCP 调用链 | 已验证 | `mcp_stdio_server.py` 创建 `FastMCP("AutoRedTeam")`，通过 `handlers.register_all_handlers` 注册模块化工具。 |
| Handler 注册策略 | 已验证 | `handlers/__init__.py` 逐类注册 recon、detector、cve、api、cloud、supply_chain、redteam、orchestration、lateral、persistence、ad、session、report、ai、misc、external、parallel、knowledge、mcts、prompt、resource，并捕获单个模块注册失败以避免整体失败。 |
| 实际 MCP 工具数量 | 已验证 | 本地执行 `register_all_tools()` 未启动 server，实际 `_counter.total` 为 `132`。 |
| 文档数量不一致 | 已验证 | README 顶部徽章写 Tools 132；README 工具矩阵总计行写 131；本地注册结果为 132。 |

## 阶段 4：验证结果

| 命令 | 结果 | 备注 |
| --- | --- | --- |
| `python --version` | 通过 | 当前环境是 Python 3.14.0，超出项目声明的 3.10-3.12 支持范围。 |
| `python -m pytest --version` | 通过 | pytest 9.0.2。 |
| `python -c "import autort; print(autort.__version__)"` | 通过 | 输出 `3.1.0`。 |
| `python -m py_compile mcp_stdio_server.py` | 通过 | MCP server 主文件语法检查通过。 |
| `python -m pytest --collect-only -q -m "not slow and not integration and not network"` | 通过 | 收集 2019 项，排除 16 项，选中 2003 项；仅收集未执行。 |
| `python -m pytest tests\\test_cli.py tests\\test_tool_result.py tests\\test_utils.py -q` | 通过 | 61 passed。 |
| `python -m pytest tests\\test_sdk.py tests\\test_sarif.py tests\\test_recon_engine.py -q` | 通过 | 127 passed。 |
| `python -m pytest tests\\test_rce_exploiter_security.py tests\\test_sandbox.py tests\\test_core_c2.py -q` | 通过 | 82 passed。 |
| `python -c "from mcp_stdio_server import register_all_tools, _counter; register_all_tools(); print(_counter.total); print(_counter.counts)"` | 通过 | 注册 132 个 MCP 工具；未启动 server，未执行任何工具。 |

## 当前风险

| 严重度 | 主题 | 证据等级 | 风险 |
| --- | --- | --- | --- |
| 高 | 高风险功能默认暴露面 | 已验证 | CLI、SDK、MCP 覆盖 exploit、lateral、persistence、C2、credential、exfiltration 等能力；需要确保授权模式、目标范围和危险操作确认在所有入口一致生效。 |
| 中 | 打包依赖缺口 | 推断 | 如果用户按 Python 包方式 `pip install .` 安装，`pyproject.toml` 基础依赖可能不足以运行 CLI 或完整 SDK；README 推荐 requirements 安装可以规避。 |
| 中 | 混淆隐藏文件名 | 已验证 | 根目录同形字符文件容易绕过人工检查或自动化路径规则，建议改成普通 ASCII 文件名或移到 `docs/security-audits/`。 |
| 中 | CI 安全审计非完全阻断 | 已验证 | pip-audit 和 detect-secrets 当前非阻断，适合作为提示但不适合作为发布门禁。 |
| 低 | 文档数量漂移 | 已验证 | README 中工具数量既写 132 又写 131，和实际注册 132 不完全一致。 |
| 低 | 当前验证环境偏差 | 已验证 | 本机 Python 3.14.0 超出项目支持矩阵，因此本轮测试通过不能替代 3.10/3.11/3.12 CI 结论。 |

## 待确认问题

- 核心 orchestrator 与 handlers 的调用关系是什么。
- 全量测试在 Python 3.10/3.11/3.12 是否通过。
- 授权中间件是否覆盖 CLI、SDK、MCP 所有高风险入口。

## 阶段 6：详细能力与边界矩阵

### 分析准则

- 能力按入口分为 CLI、SDK、MCP handlers、core engine、配置/策略、测试覆盖。
- 边界按风险分为：安全本地、被动/只读、主动扫描、利用/执行、持久化/横向/C2/外传。
- 只有真实读取源码、注册工具或运行测试后才标记为“已验证”。

### 第三方代码使用边界

- 已确认用户希望参考同类项目；本轮会检索真实来源。
- 默认不复制第三方代码，避免许可证和 provenance 风险。
- 若后续确需引入外部代码，必须记录来源、许可证、文件级归属和 NOTICE/PROVENANCE。

### 能力总览

| 能力域 | 证据等级 | 本地证据 | 边界判断 |
| --- | --- | --- | --- |
| SDK | 已验证 | `autort/__init__.py` 导出 `Scanner`、`Exploiter`、`AutoPentest`、`RedTeam`、`Reporter`。 | 面向 Python 调用方；当前 SDK 层本身不强制 API Key。 |
| CLI | 已验证 | `cli/main.py` 提供 `scan`、`detect`、`exploit`、`cve-search`、`pentest`、`report`、`nuclei`、`tools`、`version`。 | 执行子命令显示免责声明；未确认 CLI 对所有高风险命令强制授权。 |
| MCP 工具 | 已验证 | 本地注册得到 `122` 个 FastMCP tools。 | MCP handler 层是主要授权保护面。 |
| MCP Prompt/Resource | 已验证 | 本地注册得到 6 prompts、3 static resources、1 resource template。 | 资源暴露应注意会话、配置和 payload 元数据脱敏。 |
| Recon | 已验证 | `recon_handlers.py` 注册 `full_recon`、`port_scan`、`fingerprint`、`subdomain_enum`、`dir_scan`、`dns_lookup`、`tech_detect`、`waf_detect`、`passive_subdomain_enum`。 | 侦察类工具主动/被动混合；端口、目录、子域名属于主动扫描边界。 |
| Detector | 已验证 | `detector_factory.py` 工厂注册 25 个专项扫描，加 `vuln_scan`、`nuclei_scan` 共 27 个检测工具。 | 漏洞检测会主动请求目标，应要求授权目标范围和速率。 |
| Exploit/编排 | 已验证 | `orchestration_handlers.py` 注册 `auto_pentest`、`exploit_vulnerability`、`exploit_by_cve`、`exploit_orchestrate`、`verify_and_exploit` 等。 | 多数已加 `require_critical_auth`；属于高风险，不应默认执行。 |
| Red team/post-exploit | 已验证 | `redteam_handlers.py` 注册 C2、payload obfuscation、WAF bypass、credential、privilege、post-exploit、exfiltration。 | 极高风险；MCP 层有 dangerous/critical auth，SDK 层仍需单独边界。 |
| Lateral/Persistence/AD | 已验证 | lateral 9 个、persistence 3 个、AD 3 个 handler 均加 `require_critical_auth`。 | 明确 L4，必须授权后才可运行。 |
| API/Cloud/Supply Chain | 已验证 | API 7 个、cloud 3 个、supply_chain 3 个 handler。 | API/Cloud 扫描可能触达真实资产；本轮不动态执行。 |
| Session/Report/Knowledge/MCTS | 已验证 | session 4、report 2、knowledge 3、MCTS 1。 | 报告/会话偏管理面；knowledge store/attack paths 有 dangerous/moderate auth。 |

### 边界与保护

| 保护面 | 证据等级 | 结论 |
| --- | --- | --- |
| MCP API Key 模式 | 已验证 | `core/security/mcp_auth_middleware.py` 默认 `AuthMode.STRICT`，`DISABLED` 仅允许测试环境设置。 |
| 高危 handler 装饰器 | 已验证 | lateral、persistence、AD、C2、exfiltration、exploit 编排等 handler 使用 `require_critical_auth` 或 `require_dangerous_auth`。 |
| 目标 SSRF/私网校验 | 已验证 | `core/security/mcp_security.py` 的 `InputValidator` 默认拒绝私有 IP、云元数据、DNS 解析到私网的 URL。 |
| 目标校验接入度 | 推断 | `core/security/mcp_security.py` 有完整 `MCPSecurityMiddleware.secure_tool`，但 `rg` 仅发现测试和资源中引用，未看到 handler 统一使用；handler 当前主要依赖 `handlers.error_handling.validate_inputs`。 |
| AuthManager 工具等级映射 | 已验证 | `core/security/auth_manager.py` 有 `TOOL_LEVELS`，但名称如 `sqli_detect`、`lateral_smb_exec` 与实际工具名 `sqli_scan`、`lateral_smb` 不完全一致；装饰器传入的 level 可弥补高危工具，但未映射工具默认按 MODERATE 处理。 |
| Orchestrator 默认外传 | 已验证 | `OrchestratorConfig(skip_exfiltrate=True)` 默认跳过 exfiltrate；但 `autort/pentest.py` 未显式传入该字段，依赖默认值。 |

### 仓库卫生候选

| 候选 | 证据等级 | 当前判断 |
| --- | --- | --- |
| `handlers/_detector_handlers_legacy.py` | 已验证 | 未被 `handlers/__init__.py` 导入；测试和注册路径使用 `handlers.detector_factory`。可作为删除候选，但需跑 handler 测试确认。 |
| `core/security/mcp_security.py` | 已验证/推断 | 有测试、README_EN 和 resource 引用；不能删。应评估是否接入 handler，而不是删除。 |
| Python `__pycache__` / `.pyc` | 已验证 | 本轮测试产生大量 `__pycache__` 和 `.pyc`，属于生成物，可清理。 |
| 混淆同形字符审计文件 | 已验证 | 根目录 `.сlаudе-sесuritу-аudit-2026-04-07.md` 文件名混淆；建议移动/重命名为 ASCII 路径。 |

## 阶段 7：同类项目调研

| 项目 | 证据等级 | 能力定位 | 许可证/可复制边界 | 可借鉴思路 |
| --- | --- | --- | --- | --- |
| Microsoft PyRIT | 已验证 | 官方文档描述为面向生成式 AI 系统的自动化和人工 AI red teaming 框架，支持 Scanner/GUI/Framework、target、converter、scorer、memory。 | GitHub 标注 MIT；可借鉴架构，复制代码仍需保留来源。 | 把 AI red-team 能力拆成 `target/converter/scorer/memory/scenario`，对本仓库的 `AIAnalyzer` 和 prompt handlers 更适合。 |
| promptfoo | 已验证 | README 描述为 CLI + library，用于 LLM app eval 和 red teaming/vulnerability scanning，强调 declarative configs、CI/CD、结果视图。 | GitHub 标注 MIT；可借鉴配置和报告结构，避免直接复制 TypeScript 实现。 | 补一个声明式 eval/redteam 配置层，把 payload、target、assertion、provider 和报告结果标准化。 |
| NVIDIA garak | 已验证 | README 描述为 LLM vulnerability scanner，probe 覆盖 hallucination、data leakage、prompt injection、misinformation、toxicity、jailbreak 等。 | GitHub 标注 Apache-2.0；引入代码需要 NOTICE/Apache 归属。 | 借鉴 `probe` 家族和插件命名，不把 LLM 安全混进传统 web detector。 |
| OWASP Nettacker | 已验证 | README 描述为 Python 自动化渗透测试/信息收集框架，模块化任务、并行扫描、多协议、HTML/JSON/CSV/text 输出。 | GitHub 标注 Apache-2.0；代码复制需 Apache 归属。 | 本仓库已有相近扫描面，应该加强模块元数据、速率/范围控制、输出格式一致性。 |
| MITRE Caldera | 已验证 | README 描述为自动化 adversary emulation 平台，核心系统 + plugins，含 async C2 server、REST API、Web UI。 | GitHub 标注 Apache-2.0；代码复制需 Apache 归属。 | 借鉴 core/plugins 分离、ATT&CK/TTP 元数据、agent 能力边界；不直接复制 C2/agent 代码。 |
| Atomic Red Team | 已验证 | README 描述为映射到 MITRE ATT&CK 的便携检测测试库。 | GitHub 标注 MIT；可借鉴测试用例元数据结构。 | 给危险能力加 `technique_id`、先决条件、执行器、cleanup、检测建议；默认 dry-run。 |
| Faraday Community | 已验证 | GitHub About 标注为开源漏洞管理平台。 | GitHub 标注 GPL-3.0；不复制代码进当前 MIT 仓库。 | 只借鉴“workspace / finding lifecycle / dedupe / asset inventory / vulnerability management”产品思路。 |
| Metasploit Framework | 已验证 | README 描述为 open-source tool，BSD-style license；目录体现 modules/plugins/scripts/db 等成熟结构。 | GitHub license 面板显示复杂/未知，README 指向 COPYING；不直接复制代码。 | 借鉴模块生命周期、metadata、rank/check/exploit/report 的接口分层。 |

### 调研结论

- 当前仓库“能力覆盖”已经很宽，下一步价值不是继续堆 detector，而是统一能力元数据、授权策略、结果 schema、声明式场景和报告/CI 输出。
- 第三方项目没有必要直接复制代码；许可证上 MIT/Apache 可兼容但需要 provenance，GPL 项目只能借鉴思路。
- 对本仓库最直接的工程动作：清理遗留 handler、规范隐藏审计文件、移除生成物、补齐能力边界文档，并把 `mcp_security.py` 的目标/风险检查接入实际 handler 链路。

## 阶段 8：已执行清理与修复

| 动作 | 证据等级 | 说明 |
| --- | --- | --- |
| 删除 legacy detector handler | 已验证 | 删除 `handlers/_detector_handlers_legacy.py`；当前注册链和测试均使用 `handlers/detector_factory.py`。 |
| 规范混淆审计文件名 | 已验证 | 将根目录同形字符文件移动为 `docs/security-audits/claude-security-audit-2026-04-07.md`。 |
| 清理生成物 | 已验证 | 删除 `__pycache__`、`.pytest_cache`、本地日志、`data/cve_storage.db`、`data/sessions/`、`data/operation_audit.jsonl`。 |
| 忽略本地审计日志 | 已验证 | `.gitignore` 新增 `data/operation_audit.jsonl`，避免 MCP/tooling 审计运行日志误入仓库。 |
| 修正文档工具数量 | 已验证 | README 中文/英文从 131 对齐到本地注册计数 132。 |
| 补齐打包依赖 | 已验证 | `pyproject.toml` 新增 `typer>=0.9.0`，避免安装包入口 `autort = "cli.main:app"` 缺少 CLI 依赖。 |
| 修复 SQLi verifier MRO 覆盖 | 已验证 | `SQLiVerifierMixin` 的 `_prepare_base_request`、`_request`、`_prepare_request` 改为委托 `BaseVerifier`，修复 request context 测试。 |
| 修复测试 fixture 污染全局时间 | 已验证 | `core/http/client.py` 新增 `_retry_sleep` hook，`tests/conftest.py` 只 patch 该 hook，不再把全局 `time.sleep` 变成 noop。 |

## 阶段 9：回归验证

| 命令 | 结果 | 备注 |
| --- | --- | --- |
| `python -m py_compile mcp_stdio_server.py cli\\main.py handlers\\__init__.py handlers\\detector_factory.py` | 通过 | 清理 legacy handler 后入口语法正常。 |
| `python -m pytest tests\\test_handlers_detector.py tests\\test_handlers_init.py tests\\test_cli.py tests\\test_tool_result.py -q` | 通过 | 68 passed。 |
| MCP 注册计数命令 | 通过 | 输出 `132`，细分为 122 tools、6 prompts、3 resources、1 template。 |
| `python -m pytest tests\\test_sdk.py tests\\test_sarif.py tests\\test_recon_engine.py tests\\test_mcp_security.py tests\\test_mcp_auth_middleware.py -q` | 通过 | 235 passed。 |
| 首次 CI 风格非 slow/non-network 测试 | 失败后修复 | 暴露 6 个既有问题：3 个时间测试因 fixture 污染，3 个 SQLi request context 因 mixin stub。 |
| 修复后目标失败用例 | 通过 | 6 passed。 |
| 修复后 CI 风格非 slow/non-network 测试 | 通过 | 1975 passed, 2 deselected, 15 warnings。 |

### 剩余风险

- 当前 Python 是 3.14.0，仍超出项目声明的 3.10-3.12；结果不能完全替代 CI 矩阵。
- 测试仍有 `requests` 依赖版本警告和 15 个 SSL verification disabled 警告，需要单独治理。
- `core/security/mcp_security.py` 的目标/风险中间件仍未统一接入 handler 链路，这是下一轮最有价值的边界修复。

## 阶段 10：高星同类项目对照

### 数据来源

- GitHub REST API 查询时间：2026-05-19。
- 原始结果保存在本地忽略文件 `reports/github_peer_repos_2026-05-19.json`。
- 对照文档：`docs/peer-project-benchmark.md`。

### 高星排序

| 项目 | Stars | 许可证 | 证据等级 | 对本项目的意义 |
| --- | ---: | --- | --- | --- |
| Metasploit Framework | 38203 | NOASSERTION | 已验证 | 利用模块生命周期标杆；只借鉴接口分层和 metadata。 |
| Nuclei | 28722 | MIT | 已验证 | 模板 DSL、matchers/extractors、evidence 和 reporting 值得优先仿。 |
| promptfoo | 21371 | MIT | 已验证 | 声明式 LLM red-team/eval 配置、provider/assertion/plugin 结构最适合 AI 层。 |
| ZAP | 15142 | Apache-2.0 | 已验证 | passive/active scan policy、session/context、插件体系可借鉴。 |
| Atomic Red Team | 11963 | MIT | 已验证 | ATT&CK 技术元数据、executor、prereq、cleanup、dry-run 是高危能力治理关键。 |
| garak | 7843 | Apache-2.0 | 已验证 | `probes/generators/detectors/evaluators/harnesses` 是 LLM 安全插件化参考。 |
| Caldera | 6967 | Apache-2.0 | 已验证 | core/plugins、planners、abilities、adversaries、agent/contact 模型可借鉴。 |
| DefectDojo | 4703 | BSD-3-Clause | 已验证 | finding import、dedupe、engagement、retest 生命周期可补齐报告闭环。 |
| PyRIT | 3848 | MIT | 已验证 | Python AI red-team 的 target/converter/scorer/memory/dataset/executor 拆分可直接仿设计。 |

### 差距判断

| 维度 | 当前项目 | 高星项目做法 | 建议 |
| --- | --- | --- | --- |
| 能力元数据 | 能力多，但 metadata 分散 | Atomic/Caldera/Metasploit 都强调 technique、platform、executor、cleanup、rank | 先做统一 capability metadata。 |
| 声明式场景 | 主要靠 CLI/MCP 调用 | promptfoo/Nuclei 以 config/template 驱动 | 新增 scenario schema，支持 CI 和复测。 |
| AI 安全插件边界 | AI handler 与传统工具边界不够清晰 | garak/PyRIT 拆成 probe/target/scorer/memory 等层 | 重构为 targets/probes/strategies/scorers。 |
| 检测证据模型 | 报告有基础能力 | Nuclei/ZAP 强调 matcher/extractor/evidence | 统一 finding/evidence schema。 |
| 风险生命周期 | 更像执行工具集合 | DefectDojo/Faraday 有 asset/finding/dedupe/retest | 补 finding lifecycle 和 dedupe key。 |

### 复制边界

- 可以抄：架构、字段思想、插件边界、测试策略、文档组织、报告生命周期。
- 需要归属：MIT/BSD/Apache-2.0 项目小段通用代码，必须加来源和许可证说明。
- 不复制：GPL 项目代码、不明许可证代码、C2/agent/钓鱼/持久化/规避检测/外传等进攻实现。

## 阶段 11：AI 自动化红队同类项目重筛

### 口径修正

| 主题 | 证据等级 | 发现 |
| --- | --- | --- |
| 用户目标 | 已验证 | 用户明确要求“主要看 AI自动化红队 ai红队攻击 ai自动化渗透平台的类似项目”。 |
| 主样本调整 | 已验证 | `docs/peer-project-benchmark.md` 已重写为 AI 自动化红队专版。 |
| 降权项目 | 推断 | Metasploit、Nuclei、ZAP、DefectDojo 等传统安全项目仍有工程参考价值，但不再作为主同类产品样本。 |

### AI 自动化红队主样本

| 项目 | Stars | 许可证 | 证据等级 | 可抄重点 |
| --- | ---: | --- | --- | --- |
| promptfoo | 21381 | MIT | 已验证 | 声明式 red-team/eval 配置、plugins/strategies/assertions、CI/report。 |
| PentAGI | 17005 | MIT | 已验证 | 全自动 AI 渗透平台骨架、多 Agent、沙箱、长期记忆、知识图谱、观测。 |
| PentestGPT | 13170 | MIT | 已验证 | 渗透测试任务树、session/reasoning 分离、benchmark。 |
| CAI | 8545 | NOASSERTION/MIT files | 已验证 | Cybersecurity AI automation、MCP、benchmark、guardrails。 |
| garak | 7846 | Apache-2.0 | 已验证 | probes/generators/detectors/evaluators/harnesses。 |
| Giskard OSS | 5357 | Apache-2.0 | 已验证 | LLM Agent / RAG evaluation。 |
| PurpleLlama | 4180 | NOASSERTION | 已验证 | CyberSecEval、prompt injection、offensive cyber capability eval。 |
| Decepticon | 3886 | Apache-2.0 | 已验证 | agents/backends/llm/middleware/sandbox/tools 分层。 |
| PyRIT | 3851 | MIT | 已验证 | prompt_target、prompt_converter、scenario、score、memory、executor。 |
| AI-Infra-Guard | 3743 | Apache-2.0 | 已验证 | MCP/skills/agent/AI infra scan。 |
| Vulnhuntr | 2660 | AGPL-3.0 | 已验证 | LLM code vuln discovery、call-chain context expansion；不复制代码。 |
| Agentic Security | 1875 | Apache-2.0 | 已验证 | attack_rules、probe_actor、refusal_classifier、MCP、report_chart。 |

### 对 AutoRedTeam-Orchestrator 的新判断

| 维度 | 当前项目 | 同类项目做法 | 结论 |
| --- | --- | --- | --- |
| 平台骨架 | 工具集合 + CLI/SDK/MCP | PentAGI 有 Flow/Agent/Sandbox/Memory/Observability/Web/API | 应先做 `core/agent_runtime/`。 |
| AI 红队执行 | prompt/AI handler 分散 | promptfoo/garak/PyRIT 有 Target/Probe/Strategy/Scorer/Executor | 应做 `core/ai_redteam/`。 |
| 自动渗透任务 | AutoPentest 有流程但 agent state 不强 | PentestGPT/CAI 有 session、reasoning、benchmark | 应统一 RunState 和 HumanGate。 |
| AI 基础设施安全 | 当前更偏传统 web/pentest | AI-Infra-Guard 覆盖 MCP/skills/agent/AI infra | 应新增 `core/ai_surface/`。 |
| 代码漏洞发现 | 有 detector，但缺 LLM call-chain agent | Vulnhuntr 重点做上下文扩展和 confidence score | 可做 `core/code_agent/`，但不复制 AGPL 代码。 |

### 最高优先级

1. `core/agent_runtime/`：Flow、Task、SubTask、Action、Artifact、Memory、Trace、HumanGate。
2. `core/ai_redteam/`：Target、Probe、Strategy、Scorer、Scenario、Report。
3. `core/ai_surface/`：MCP scan、Skills scan、Agent tool boundary scan、AI infra scan。
4. CLI 增加 `autort ai-redteam run scenario.yaml`，默认 dry-run。
5. MCP 增加 `ai_redteam_run_scenario`，真实外部目标必须 human gate。

## 阶段 12：AI 红队基础层落地

| 主题 | 证据等级 | 发现 |
| --- | --- | --- |
| Agent runtime | 已验证 | 已新增 `core/agent_runtime/`，提供 Flow/Task/Action/ActionPolicy/Artifact/Trace/HumanGate/AgentRunState，可序列化、无执行副作用。 |
| AI red-team schema | 已验证 | 已新增 `core/ai_redteam/`，支持声明式 Scenario、Target、Probe、Strategy、Scorer、Attempt、Score 和 dry-run runner。 |
| CLI 入口 | 已验证 | `autort ai-redteam run config\\ai_redteam.example.yaml` 可生成 dry-run JSON，示例场景产生 16 attempts、48 scores、16 trace events。 |
| 安全默认 | 已验证 | 当前 runner 不请求目标、不调用模型、不执行 shell、不触发扫描/利用工具；所有 action 均标记 `network_policy=deny`、`status=skipped`。 |
| 范围校验 | 已验证 | `Scenario.validate()` 会拒绝 blocked target，例如云元数据地址。 |
| 测试环境风险 | 已验证 | 本机直接 `python -m pytest` 会被 Windows WMI 查询卡住；使用禁用 readline 的 pytest wrapper 后相关测试稳定通过。 |

### 当前实现边界

- 已实现：计划层、策略层、dry-run、序列化输出、CLI 入口、示例配置、单元测试。
- 未实现：真实 target provider、模型 provider、payload 生成、scorer 执行、报告文件生成、MCP handler。
- 安全约束：真实 active 模式目前被 `AIRedTeamRunner(..., allow_active=False)` 阻断。

### 下一步

- 将 dry-run runner 接入 MCP handler：`ai_redteam_run_scenario`。
- 补 `core/ai_surface/`，扫描 MCP/skills/agent 工具边界。
- 后续 active runner 必须先接 HumanGate、scope policy、审计日志和 provider sandbox。

## 阶段 13：AI 红队 MCP 接入

| 主题 | 证据等级 | 发现 |
| --- | --- | --- |
| MCP 工具 | 已验证 | `handlers/ai_handlers.py` 新增 `ai_redteam_run_scenario`，支持 `scenario` dict 或 `scenario_path` 文件输入。 |
| 安全默认 | 已验证 | MCP 工具只调用 dry-run runner；无目标请求、无模型调用、无 shell、无扫描器/利用器执行。 |
| 工具计数 | 已验证 | MCP 注册计数命令输出 `133`，其中 `ai=4`。 |
| 文档同步 | 已验证 | `README.md` 与 `README_EN.md` 已从 132 更新到 133，AI 工具行从 3 更新到 4。 |
| 测试覆盖 | 已验证 | `tests/test_handlers_ai.py` 覆盖注册计数、dry-run 返回、缺失输入错误。 |

### 当前三层入口

| 层 | 入口 | 状态 |
| --- | --- | --- |
| Core | `core.ai_redteam.AIRedTeamRunner` | 已实现 dry-run |
| CLI | `autort ai-redteam run <scenario>` | 已实现 dry-run |
| MCP | `ai_redteam_run_scenario` | 已实现 dry-run |

### 下一步

- `core/ai_surface/`：MCP/skills/agent 工具边界扫描。
- `core/ai_redteam/scorers/`：先实现本地规则类 scorer，例如 secret pattern、unsafe tool call、policy bypass marker。
- `core/agent_runtime` 持久化：将 `AgentRunState` 输出落到 `data/runs/`，并默认脱敏。

## 阶段 14：AI 工具攻击面静态盘点

| 主题 | 证据等级 | 发现 |
| --- | --- | --- |
| 静态扫描核心 | 已验证 | `core/ai_surface/` 新增 `SurfaceFinding`、`SurfaceScanResult` 和 `scan_handler_surface()`，通过 AST 解析 handler 源码，不导入或执行目标模块。 |
| CLI 入口 | 已验证 | `python -m cli.main ai-surface scan --path handlers\\ai_handlers.py` 成功输出 JSON；扫描 1 个文件、5 个工具。 |
| MCP 入口 | 已验证 | `handlers/ai_handlers.py` 新增 `ai_surface_scan_handlers`，MCP 注册计数为 `134`，其中 `ai=5`。 |
| 风险盘点结果 | 已验证 | `scan_handler_surface('handlers')` 扫描 23 个 handler 文件、99 个静态工具定义；risk counts: low 13、moderate 28、high 20、critical 38；issue_count 13。 |
| 发现示例 | 已验证 | `handlers\\ai_handlers.py` 中 `attack_chain_plan` 和 `smart_payload` 被标记为 high 且无 dangerous auth，是下一轮可治理候选。 |
| Windows 输出兼容 | 已验证 | 修复 CLI `_output` 在 cp1252 stdout 下打印中文 JSON 的 `UnicodeEncodeError`，改为 UTF-8 fallback。 |

### 阶段 14 边界

- 该扫描器只给“候选风险”和“建议 gate”，不是漏洞证明。
- 动态 factory 生成工具不会逐个展开，只统计源码中的显式 `@tool` 函数。
- 后续若根据扫描结果收紧 auth，需要逐项确认产品可用性和测试覆盖。

## 阶段 15：AI handler 高风险授权收紧

| 主题 | 证据等级 | 发现 |
| --- | --- | --- |
| 高风险 AI 工具授权 | 已验证 | `attack_chain_plan` 与 `smart_payload` 已增加 `require_dangerous_auth`。 |
| 默认阻断 | 已验证 | 测试在 STRICT auth mode 且无 API key 时调用两个工具，均返回 `AUTH_REQUIRED`。 |
| 静态扫描修复效果 | 已验证 | `scan_handler_surface('handlers/ai_handlers.py')` 输出 `issue_count=0`，两个高风险工具均显示 `auth_level=dangerous`。 |
| 整体剩余问题 | 已验证 | `scan_handler_surface('handlers')` 的整体 issue_count 从 13 降至 10。 |

### 剩余候选

- 剩余 issue 需要逐个看上下文，不应机械加 auth；下一步优先检查是否为 target/url 参数缺少 `validate_inputs`，或 critical 工具缺少 critical auth。

## 阶段 16：Handler surface 剩余缺口清零

| 主题 | 证据等级 | 发现 |
| --- | --- | --- |
| 敏感知识图谱写入 | 已验证 | `kg_store` 支持 credential 等实体写入，已从 `require_moderate_auth` 升为 `require_critical_auth`。 |
| PoC 生成授权 | 已验证 | `cve_generate_poc` 已增加 `require_dangerous_auth`，避免无授权生成可复用 PoC 模板。 |
| 批量目标校验 | 已验证 | `validate_inputs` 支持 list/tuple/set 逐项校验，`credential_spray` 已接入 `targets="target"`。 |
| JWT target 校验 | 已验证 | `jwt_scan` 已对可选 `target` 参数接入目标校验。 |
| 静态扫描精度 | 已验证 | `core.ai_surface.scanner` 会忽略 `targets: Dict` 这类配置参数，避免把 exploit 配置误判为 URL 目标；read-only `poc_list` 降为 low 风险。 |
| 整体结果 | 已验证 | `scan_handler_surface('handlers')` 输出 `issue_count=0`。 |

### 验证

- `python -m py_compile ...` 通过。
- pytest wrapper 覆盖 `tests/test_ai_surface.py tests/test_handlers_lateral.py tests/test_handlers_cve.py tests/test_handlers_init.py -q`，结果 69 passed。

## 阶段 17：AI red-team eval/report 基础能力

| 主题 | 证据等级 | 发现 |
| --- | --- | --- |
| 组件 catalog | 已验证 | `core/ai_redteam/catalog.py` 定义内置 probes、strategies、scorers，与 promptfoo/garak/PyRIT 的插件分层对齐。 |
| Strategy 变换 | 已验证 | `core/ai_redteam/strategies.py` 支持 direct、encoding、homoglyph、multi_turn 的本地计划变换。 |
| 本地 scorer | 已验证 | `core/ai_redteam/scorers.py` 支持 secret/tool/policy/RAG marker 规则检测，不调用外部模型。 |
| Report/CI | 已验证 | `core/ai_redteam/report.py` 支持 Markdown report 和 CI threshold 判断。 |
| CLI | 已验证 | `autort ai-redteam run` 支持 `--format`、`--ci`、`--severity-threshold`；新增 `autort ai-redteam catalog`。 |

### 阶段 17 边界

- 当前 scorer 只评估本地文本样本或未来 target response，不负责生成攻击 payload。
- 当前 runner 仍是 dry-run，所有 target/model/tool 调用保持跳过。

### 验证

- pytest wrapper 覆盖 `tests/test_ai_redteam_components.py tests/test_ai_redteam_runtime.py tests/test_cli.py -q`，结果 24 passed。
- CLI smoke 覆盖 `ai-redteam catalog` 和 example scenario Markdown report。
