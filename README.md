# AutoRedTeam-Orchestrator

AutoRedTeam-Orchestrator 是一个面向**授权安全测试、AI 红队评估和教育研究**的 Python 编排框架。

项目提供三种入口：

- **MCP Server**：供 Cursor、Windsurf、Kiro 等支持 MCP 的 AI 工具调用。
- **Python SDK**：通过 `autort` 包在 Python 代码中集成扫描、检测、编排和报告能力。
- **Typer CLI**：通过 `autort` 命令执行扫描、漏洞检测、编排、报告和 AI red-team 工作流。

> 本项目包含漏洞检测、利用验证、C2、横向移动、持久化等双用途能力。只能在明确授权、本地实验、CTF、教育研究或 dry-run 场景中使用。

---

## 功能概览

- 侦察：DNS、端口、指纹、技术栈、WAF、子域名、目录和被动侦察。
- 漏洞检测：SQLi、XSS、SSRF、RCE、XXE、SSTI、反序列化、JWT、GraphQL、CORS、WebSocket 等。
- CVE 工作流：CVE 搜索、PoC 辅助、自动化验证入口。
- 编排：RECON → VULN_SCAN → POC_EXEC → EXPLOIT → PRIV_ESC → LATERAL → EXFILTRATE → REPORT。
- AI red-team runtime：受控 run state、policy middleware、sandbox gate、只读 runtime API。
- 外部工具路由：nmap、sqlmap、nuclei、ffuf 可用时优先使用，不可用时回退到纯 Python 实现。
- 输出：JSON、HTML、SARIF、报告生成和会话持久化。

---

## 架构

```text
AI Editor / User
      |
      +-- MCP Server: mcp_stdio_server.py
      |
      +-- Python SDK: autort/
      |
      +-- CLI: cli/main.py
              |
              v
        handlers/        MCP tools/resources/prompts 注册层
              |
              v
        core/            侦察、检测、利用、编排、runtime、报告等核心能力
```

主要模块：

| 路径 | 说明 |
|------|------|
| `mcp_stdio_server.py` | MCP server 启动入口，创建 `FastMCP("AutoRedTeam")` 并注册 handlers。 |
| `handlers/` | MCP 工具注册层，按 recon、detector、CVE、redteam、orchestration、lateral 等能力拆分。 |
| `cli/main.py` | Typer CLI 入口，提供 `scan`、`detect`、`exploit`、`pentest` 等命令。 |
| `autort/` | Python SDK 门面，暴露 `Scanner`、`Exploiter`、`AutoPentest`、`RedTeam`、`Reporter`。 |
| `core/recon/` | 标准侦察引擎和端口、DNS、指纹、目录、子域名等能力。 |
| `core/detectors/` | 漏洞检测器体系和 `DetectorFactory`。 |
| `core/exploit/` | 利用引擎和具体 exploiter。 |
| `core/orchestrator/` | 自动化渗透阶段编排、checkpoint/resume、阶段状态管理。 |
| `core/agent_runtime/` | action policy、sandbox middleware、runtime state、只读 API。 |
| `core/engine_router.py` | 外部工具优先、纯 Python 回退的统一后端选择。 |
| `tests/` | 单元、集成、handler、SDK、CLI、安全相关测试。 |

---

## 安装

建议使用 Python 3.10+。

```bash
pip install -r requirements.txt
```

最小 MCP 运行依赖：

```bash
pip install -r requirements-core.txt
```

开发依赖：

```bash
pip install -r requirements-dev.txt
```

验证 SDK 是否可导入：

```bash
python -c "from autort import Scanner; print('OK')"
```

---

## MCP 使用

stdio 模式：

```bash
python mcp_stdio_server.py --stdio
```

普通启动：

```bash
python mcp_stdio_server.py
```

MCP 工具由 `handlers.register_all_handlers()` 统一注册。注册过程中单个 handler 失败会记录 warning 并继续加载其他 handler。

---

## CLI 使用

查看帮助：

```bash
autort --help
python -m cli.main --help
```

常用命令：

```bash
# 侦察
autort scan http://target.com --full

# 漏洞检测
autort detect http://target.com -c sqli,xss,ssrf

# Nuclei 扫描
autort nuclei http://target.com --severity high,critical --tags cve

# 一键编排
autort pentest http://target.com --phases recon,detect,exploit

# SARIF / CI 输出
autort detect http://target.com --ci --format sarif -o results.sarif

# 报告生成
autort report SESSION-ID --format html -o report.html

# AI red-team dry-run 场景
autort ai-redteam run scenario.yaml -o run.json
autort ai-redteam eval-run run.json

# 只读 runtime API
autort runtime-api serve --run-state run.json --host 127.0.0.1 --port 8765

# 沙箱诊断
autort sandbox docker-smoke

# 能力矩阵
autort capabilities matrix
```

---

## Python SDK 使用

```python
import asyncio
from autort import AutoPentest, Scanner

async def main():
    scanner = Scanner("http://target.com")

    recon = await scanner.full_recon()
    vulns = await scanner.detect_vulns(categories=["sqli", "xss", "ssrf"])

    pentest = AutoPentest("http://target.com")
    report = await pentest.run(phases=["recon", "vuln_scan", "report"])

    print(recon)
    print(vulns)
    print(report)

asyncio.run(main())
```

---

## 配置

常用环境变量：

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `AUTORT_SCAN_TIMEOUT` | `30` | 扫描超时时间。 |
| `AUTORT_HTTP_MAX_RETRIES` | `3` | HTTP 重试次数。 |
| `AUTORT_LLM_PROVIDER` | `none` | LLM provider，例如 `openai`、`anthropic`、`ollama`、`none`。 |
| `AUTORT_LLM_MODEL` | `auto` | LLM 模型名。 |
| `AUTORT_AUTH_MODE` | `strict` | MCP auth 模式：`strict`、`permissive`、`disabled`。 |

配置样例：

- `.env.example`
- `config/config.yaml.example`
- `config/external_tools.yaml.example`

---

## 测试

快速健康检查：

```bash
python -c "from autort import Scanner; print('OK')"
pytest tests/test_sdk.py tests/test_cli.py -q
pytest tests/test_handlers_*.py -q
```

常规测试：

```bash
pytest
pytest -m "not slow"
pytest tests/test_sdk.py
pytest tests/test_sdk.py::test_name
pytest --cov=core --cov=handlers --cov-report=html
```

针对 OOB DNS 集成测试 debug：

```bash
pytest tests/test_oob_server.py -q --tb=short
pytest tests/test_oob_server.py::TestOOBCallbackServerDNS -q --tb=long
```

最近一次本地 Windows / Python 3.11 验证结果：

- `python -c "from autort import Scanner; print('OK')"`：通过。
- `pytest tests/test_sdk.py tests/test_cli.py -q`：66 passed。
- `pytest tests/test_handlers_*.py -q`：186 passed。
- `pytest -m "not slow" -q`：2093 passed，3 个 `TestOOBCallbackServerDNS` 错误。
- 单独重跑 `tests/test_oob_server.py` 和 `TestOOBCallbackServerDNS`：通过。

初步判断：OOB DNS 错误更像全量测试时 UDP 端口、后台线程或服务就绪时序导致的 flaky，而不是稳定功能缺陷。

---

## 代码质量

```bash
black core/ handlers/ utils/ autort/ cli/
isort core/ handlers/ utils/ autort/ cli/
flake8 core/ handlers/ utils/
mypy core/ handlers/ utils/
pylint core handlers utils
bandit -r core handlers utils -c .bandit
pre-commit run --all-files
```

项目约定：

- Black / isort 行宽为 100。
- 路径处理优先使用 `pathlib`，避免硬编码 Unix 路径。
- 不要随意扩大 `.bandit` skip 范围。
- active scan、exploit、lateral、persistence、C2、exfiltrate 测试默认使用 mock、local fixture、dry-run 或明确授权目标。

---

## Debug 与优化建议

优先级建议：

1. **收敛 OOB DNS flaky**  
   DNS 集成测试使用随机端口、后台线程和 UDP 查询。建议 fixture 用主动探测替代固定 `sleep`，并在 `OOBCallbackServer.stop()` 后确认线程退出。

2. **修复跨平台硬编码路径**  
   外部工具 wrapper 应使用 `tempfile` / `pathlib` 生成平台无关路径，避免 Windows 环境下出现 `/tmp/...` 之类路径。

3. **分层 CI**  
   入口层优先跑 `test_sdk.py`、`test_cli.py`、`test_handlers_*.py`；全量 `pytest -m "not slow"` 作为较宽回归；网络、OOB、外部工具相关测试单独标记并隔离运行。

4. **降低 handler 静默降级风险**  
   `handlers.register_all_handlers()` 会捕获注册异常继续启动。建议继续覆盖每类 handler 的注册数量和关键工具名，避免功能缺失只停留在 warning。

5. **保持安全默认值**  
   高风险能力默认 dry-run / sandbox / policy gate。任何真实目标操作都需要明确授权。

---

## 安全边界

允许场景：

- 已授权渗透测试。
- 企业内部安全验证。
- 本地实验环境。
- CTF / 靶场。
- 教育研究。
- dry-run / mock / fixture 验证。

禁止场景：

- 未授权扫描或攻击。
- 对第三方目标进行真实 exploit、横向移动、持久化或数据外带。
- 绕过检测、隐藏痕迹或规避执法/安全系统。
- 破坏性操作、DoS、批量攻击或供应链投毒。

---

## 贡献

欢迎提交 issue 和 PR。建议提交前运行：

```bash
pytest tests/test_sdk.py tests/test_cli.py -q
pytest tests/test_handlers_*.py -q
pre-commit run --all-files
```

提交类型建议：

```text
feat: 新功能
fix: 修复
docs: 文档
test: 测试
refactor: 重构
security: 安全修复
```

---

## 许可证

MIT License。详见 `LICENSE`。

---

## 免责声明

本工具仅供**授权安全测试**和**教育研究**使用。使用者必须在获得目标系统所有者明确书面授权后方可进行测试。任何未经授权的使用均属违法行为，作者不承担任何因非法使用产生的法律责任。
