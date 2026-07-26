# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## 项目定位

AutoRedTeam-Orchestrator 是一个 Python 3.10+ 的授权安全测试 / AI 红队编排框架，提供三层入口：MCP server、Python SDK 和 Typer CLI。代码包含渗透测试、漏洞检测、C2、横向移动、持久化等双用途能力；所有实现和验证都应限定在授权安全测试、教育研究或本地 dry-run 场景内。

## 常用命令

### 安装

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

最小 MCP 运行依赖可用：

```bash
pip install -r requirements-core.txt
```

### 运行入口

```bash
python mcp_stdio_server.py --stdio
python -m cli.main --help
autort --help
```

常用 CLI：

```bash
autort scan http://target.com --full
autort detect http://target.com -c sqli,xss,ssrf
autort nuclei http://target.com --severity high,critical --tags cve
autort pentest http://target.com --phases recon,detect,exploit
autort ai-surface scan --path handlers --format sarif -o surface.sarif
autort ai-surface scan-mcp-config --path .mcp.json --format sarif
autort ai-redteam run scenario.yaml -o run.json
autort ai-redteam eval-run run.json
autort runtime-api serve --run-state run.json --host 127.0.0.1 --port 8765
autort sandbox docker-smoke
autort capabilities matrix
```

SDK smoke：

```bash
python -c "from autort import Scanner; print('OK')"
```

### 测试

```bash
pytest
pytest -m "not slow"
pytest tests/test_sdk.py
pytest tests/test_sdk.py::test_name
pytest --cov=core --cov=handlers --cov-report=html
```

`pyproject.toml` 已配置 `tests/`、`pytest-asyncio` auto mode、strict markers，以及 `slow`、`integration`、`e2e`、`network`、`unit`、`security` markers。`tests/conftest.py` 会在测试 session 中禁用 MCP auth 检查，避免 strict auth 阻断单元测试。

### 格式化与质量检查

```bash
black core/ handlers/ utils/ autort/ cli/
isort core/ handlers/ utils/ autort/ cli/
flake8 core/ handlers/ utils/
mypy core/ handlers/ utils/
pylint core handlers utils
bandit -r core handlers utils -c .bandit
pre-commit run --all-files
```

Black/isort 行宽为 100。`.pre-commit-config.yaml` 还包含 trailing whitespace、end-of-file、YAML/JSON、large file、merge conflict、private key 和 `scripts/check_paths.py` 的硬编码路径检查。

## 高层架构

### 入口层

- `mcp_stdio_server.py` 创建 `FastMCP("AutoRedTeam")`，调用 `handlers.register_all_handlers()` 注册 MCP tools/resources/prompts，并在启动时配置日志、显示法律声明和 auth 模式。
- `cli/main.py` 是 Typer CLI，命令封装 SDK 和 core 功能；主要命令包括 `scan`、`detect`、`exploit`、`cve-search`、`pentest`、`report`、`nuclei`，以及 `ai-redteam`、`ai-surface`、`code-agent`、`runtime-api`、`sandbox`、`capabilities` 子命令。
- `autort/` 是异步 Python SDK 门面：`Scanner`、`Exploiter`、`AutoPentest`、`RedTeam`、`Reporter`。它们尽量保持薄封装，将实际工作委托给 `core/`。

### MCP handler 层

`handlers/` 按能力域注册 MCP 工具：recon、detector、CVE、API security、cloud、supply chain、redteam、orchestration、lateral、persistence、AD、session、report、AI、external tools、parallel、knowledge、MCTS、prompts、resources。`handlers/__init__.py` 是统一注册顺序和容错边界；新增 MCP 工具通常应放入对应 handler 模块，并接入 `register_all_handlers()`。

### core 引擎层

- `core/recon/` 负责侦察流水线，包括 DNS、端口、指纹、技术栈、WAF、子域名、目录、被动侦察等；SDK 的 `Scanner.full_recon()` 调用 `StandardReconEngine`。
- `core/detectors/` 是漏洞检测体系。`DetectorFactory` 管理 detector 注册、创建、按类型/严重级别筛选；具体检测器按 access/auth/file/injection/misc/request 分组，结果模型在 `core/detectors/result.py`。
- `core/exploit/` 提供 exploit engine、具体 exploiter、纯 Python SQLi/扫描能力和 exploit orchestrator。
- `core/orchestrator/` 实现一键渗透阶段编排：RECON → VULN_SCAN → POC_EXEC → EXPLOIT → PRIV_ESC → LATERAL → EXFILTRATE → REPORT。`AutoPentestOrchestrator` 支持 checkpoint/resume、阶段状态和 runtime policy/sandbox gate。
- `core/agent_runtime/` 提供受控 AI red-team runtime primitives：run state、action policy、risk level、middleware、sandbox enforcement、observability、benchmark、只读 runtime API view 和进程内 registry。
- `core/engine_router.py` 在外部工具可用时优先选择 nmap/sqlmap/nuclei/ffuf 等后端，不可用时退回纯 Python 引擎；不要在调用侧重复实现后端选择逻辑。
- `core/config/` 使用 Pydantic 模型加载配置，优先级为环境变量（`AUTORT_` 等）→ `config/config.yaml`/`config.yml` → 默认值。
- `core/session/` 管理目标、HTTP session、上下文和持久化，用于扫描/编排结果和 resume。

### 配置与依赖分层

- `requirements-core.txt`：MCP server 最小可运行依赖。
- `requirements.txt`：核心功能依赖，包含 MCP、HTTP、LLM provider、recon/security tool integrations、crypto、config、reporting、CLI。
- `requirements-optional.txt`：当前注释说明为可选/未来扩展依赖，不要为普通任务默认安装或依赖其中包。
- `pyproject.toml` 同时定义 packaging metadata、console scripts、pytest/coverage/black/isort/mypy/pylint/vulture 配置。

## 开发注意事项

- 这是安全测试工具，`.bandit` 有大量针对红队场景的 skip；不要把这些 skip 当作普通应用安全基线，也不要未经需求扩大 skip 范围。
- 涉及 active scan、exploit、lateral、persistence、C2、exfiltrate 的代码或命令，只在明确授权、local fixture、mock、dry-run 或文档化测试目标上运行。
- 优先复用 SDK、`DetectorFactory`、`EngineRouter`、`RuntimePipeline` 和现有 handler 注册模式；避免在 CLI/MCP 层直接复制 core 逻辑。
- Windows 兼容性是项目关注点：pre-commit 会检查硬编码 Unix 路径；新增路径处理优先使用 `pathlib`。