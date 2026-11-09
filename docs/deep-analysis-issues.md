# Issue 草稿（可直接提交到 Coff0xc/AutoRedTeam-Orchestrator）

> 依据 2026-11-08 对 596dbca (v3.1.0) 的分析。每条含证据、建议、验收标准，相互独立。

## 状态（2026-11-09）

五条都已在代码里闭环，原始问题描述保留作记录：

1. `ai-surface scan` 在仓库根和 `handlers/` 上与 manifest 对账，覆盖率写入 JSON summary 和 SARIF run properties。工厂工具按 `DetectorConfig` 名称计入，不再算漏报。
2. SARIF result 带 `properties.tool_name`，`ruleId` 按 `mcp_tool.auth-critical`、`mcp_tool.auth-missing`、`mcp_tool.factory`、`mcp_prompt`、`mcp_resource` 等风险类拆分。
3. 扫描器识别 `@mcp.prompt` / `@mcp.resource`（含 `name=`）和同步函数；`--exclude-tests` 默认开启。
4. CI mypy 不再指向已删除的 `core/container.py`。门禁改为 `core/result.py`、`core/capability_manifest.py`、`core/mcts_planner.py`、`core/ai_surface`、`core/agent_runtime`、`core/reporting/sarif.py`，并用 `--follow-imports=silent` 避免把历史错误算进这道门。`handlers/` 仍有约 200 个既有类型错误，没有整包放进阻断门禁。另增加 `windows-latest` 测试 job。
5. `core/__init__.py` 对 AI 引擎懒加载。只读命令的最小依赖是 `typer`，README 已写明。

---

## Issue 1 — feat(ai-surface): 用 capability manifest 对账静态扫描覆盖率

**标题**: ai-surface should reconcile scan results against the capability manifest and report static coverage

**正文**:

ai-surface 的 AST 扫描器（`core/ai_surface/scanner.py`）只识别两种模式：FastMCP `@mcp.tool()` 装饰器与 low-level `Tool(...)`/`list_tools` 构造。对仓库自身扫描得 109 条 findings，但 manifest（`core/capability_manifest.py`）定义了 142 个 surface。逐 handler 对账：

| handler | manifest | scanned | gap |
|---|---|---|---|
| detector | 28 | 2 | 26（detector_factory 动态生成，AST 不可见） |
| prompts | 6 | 0 | 6 |
| resources | 4 | 0 | 4 |
| 其余 19 个 handler | 104 | 104 | 0 |

静态覆盖率 106/142（74.6%），且该结构性盲区目前未在文档中披露。

**建议**: manifest 已是机器可读的单一事实来源。扫描完成后与 manifest 核对，在 SARIF `properties` 或 summary 输出 `static_coverage`（如 `106/142`）与不可见 surface 清单（按生成方式分组：factory-generated / prompt / resource）。detector_factory 生成的面可在 manifest 中带 locator 标注生成源，scanner 据此分类而非漏报。

**验收**: 扫描本仓库时报告 `106/142` 覆盖率并列出 36 个不可见 surface；`capability-maturity.md` 增加「cannot see factory-generated surfaces」披露。

---

## Issue 2 — fix(ai-surface): SARIF finding 缺少结构化工具标识，Code Scanning 分诊困难

**标题**: SARIF findings lack structured tool identity (single ruleId, no tool_name property)

**正文**:

对仓库自身扫描的 109 条 findings 全部挂在单一 `ruleId="mcp_tool"` 下（`tool.driver.rules` 仅 1 条）；`properties` 只有 `{confidence, param, payload, verified}`，无工具名；`message.text` 是 docstring 文本（如「AD枚举 - 枚举Active Directory对象」）。进 GitHub Code Scanning 后为一条规则下 109 个无结构告警，无法按工具名过滤、无法与 manifest/capability profile 对账。

**建议**:

- finding `properties` 增加 `tool_name`（取函数名，与 manifest `name` 对齐）；
- 或按风险域拆分为多条 rule（如 `mcp_tool.auth-missing` / `mcp_tool.high-risk` / `mcp_tool.network`），每条带独立 description——Code Scanning 的 rule 视图即可按类聚合。

**验收**: 任一 finding 可通过 `properties.tool_name` 定位到 manifest 中同名 surface；Code Scanning 界面可按 rule 分组过滤。

---

## Issue 3 — feat(ai-surface): 支持 prompt/resource surface 匹配与测试目录排除

**标题**: scanner misses prompt/resource surfaces entirely and flags test-file fixtures

**正文**:

两个盲区：

1. `kind: prompt`（6 个）与 `kind: resource`（4 个）surface 完全不被扫描——`_is_tool_decorator` 及 low-level 检测只覆盖 tool 类注册（`mcp.tool()` / `Tool(...)` / `list_tools`），`@mcp.prompt()` / `@mcp.resource()` 模式未实现。
2. 扫描仓库根目录时测试文件被当生产代码：`tests/test_capability_manifest.py` 的测试用假工具装饰器被报 2 条；另 `core/recon/js_analyzer.py` 1 条误报。

**建议**:

- 增加 prompt/resource 装饰器与构造模式的识别，finding 标注 kind；
- 增加 `--exclude-tests`（默认排除 `tests/`、`test_*.py`、`*_test.py`、`conftest.py`）或在 `scan.py` 的 `_iter_python_files` 内置测试过滤。

**验收**: 对本仓库扫描，prompts/resources 各产生 6/4 条带 kind 标注的 findings；`--exclude-tests` 后 tests/ 零误报。

---

## Issue 4 — ci: mypy 目标包含已删除文件；缺 Windows matrix

**标题**: CI mypy targets a deleted file (core/container.py) and there is no Windows job

**正文**:

1. `.github/workflows/ci.yml:38`：`mypy ... core/result.py core/container.py core/mcts_planner.py`——`core/container.py` 已在 v3.1.0 删除（CHANGELOG: "core/container.py (527-line unused DI framework)" 被移除），当前 CI 或空跑或报错；且 12 万行引擎层仅 3 个文件有类型检查。
2. README/AGENTS.md 均将 Windows 列为一等平台（pre-commit 有 `scripts/check_paths.py` 硬编码 Unix 路径检查），但全部 CI job 都在 ubuntu-latest。

**建议**:

- 立即从 mypy 目标移除 `core/container.py`；将 `core/result.py`、`core/capability_manifest.py`、`core/agent_runtime/*`、`handlers/` 纳入，逐步扩大；
- 增加 `windows-latest` job：至少跑 `pytest -m "not network and not slow"` 与 CLI/SDK smoke（`python -m cli.main capabilities manifest --profile safe`、`python -c "from autort import Scanner"`）。

**验收**: CI 绿；Windows job 在 windows-latest 上稳定通过（或明确标 allow-fail 并跟踪）。

---

## Issue 5 — docs: 「只读无网络」起步命令的最小依赖未说明

**标题**: "read-only, no network" quickstart commands need more deps than documented

**正文**:

README 的只读起步命令（`ai-surface scan`、`capabilities manifest`）实际 import 链：

```
cli/main.py:22        import typer
core/__init__.py:14   from core.ai_engine import ...   → pydantic
（ai-surface 配置解析还需要 pyyaml）
```

从源码 checkout 直接 `python -m cli.main ai-surface scan` 会 `ModuleNotFoundError: No module named 'typer'`，补 typer 后再缺 pydantic。README 快速开始只给了 `pip install -r requirements.txt`（全量依赖），未说明这些只读命令的最小集合。

**建议**（二选一）:

- 文档修复：快速开始注明最小集合 `pip install typer pydantic pyyaml`；
- 代码修复：仿照 v3.1.0 对 `utils/__init__.py` 的改造，把 `core/__init__.py` 的 eager import 改为 `__getattr__` 懒加载，让 `ai-surface` 路径不经过 `ai_engine`/`result` 的重依赖。

**验收**: 新 venv 仅装声明依赖后，只读命令可运行。

---

## 附：非 issue 备注

克隆时 4 个文件（`core/evasion/payload_obfuscator.py`、`core/exploit/exploiters/upload_exploiter.py`、`core/persistence/webshell_manager.py`、`core/post_exploit/advanced_techniques.py`）在 Windows Git Bash 下读取报 Permission denied；git mode 100644 正常、内容完整。属本地文件系统 ACL 残留（chmod 只读位），非仓库问题，无需提交。
