# AutoRedTeam-Orchestrator

**面向授权测试与 AI/MCP 攻击面审计的 local-first、MCP-native 安全自动化工作台。**

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-3.1.0-orange)
![Status](https://img.shields.io/badge/status-Beta%20%2F%20Research%20Preview-yellow)

**中文** · [English](README_EN.md) · [Русский](README_RU.md)

[能力成熟度](docs/capability-maturity.md) · [安全模型](docs/security-model.md) · [安全审计](docs/security-audits/)

> **Beta / Research Preview** — 优先支持静态分析、dry-run 与本地靶场。exploit、横向移动、持久化、C2、数据外传等高风险能力属于受限实验特性；policy 与 sandbox 元数据不等同于操作系统或容器级隔离。

## 目录

- [概述](#概述)
- [能力](#能力)
- [快速开始](#快速开始)
- [MCP Server 接入](#mcp-server-接入)
- [Python SDK](#python-sdk)
- [CLI 命令清单](#cli-命令清单)
- [配置与授权](#配置与授权)
- [AI/MCP 安全自审](#aimcp-安全自审)
- [设计思路与方案](#设计思路与方案)
- [安全与边界](#安全与边界)
- [许可与免责](#许可与免责)

## 概述

AutoRedTeam-Orchestrator 在单一代码库中提供可组合的安全能力，并通过三个入口暴露：**MCP Server**、**Python SDK** 与 **Typer CLI**。产品主线是 **AI 辅助的安全自动化**——让 AI 编辑器与 Agent 通过 MCP 使用受控的安全能力，并对 AI/MCP 系统自身的攻击面做静态审计。

适用于授权实验、安全自动化研发、AI/MCP 安全审计、CTF 与教学。**不是**开箱即用的企业平台、自主攻击 Agent 或生产级 C2。

## 能力

| 能力域 | 状态 | 边界 |
|---|---|---|
| 侦察与漏洞检测（JSON/SARIF） | Beta | 仅限授权目标；暂无公开准确率基准 |
| AI/MCP 攻击面静态自审 | Preview | 只读 AST → SARIF；覆盖 FastMCP 与 low-level SDK |
| CVE 情报与 PoC | Preview | NVD 同步、Nuclei 兼容执行 |
| 报告（JSON/SARIF/HTML） | Beta | HTML 转义加固进行中 |
| 编排 / 利用 / 后渗透 / C2 / 横向 / 持久化 | Restricted Experimental | 仅限一次性隔离靶场 |

完整定义见[能力成熟度](docs/capability-maturity.md)。

## 快速开始

单行安装（安装 `autort` 与 `autoredteam-mcp` 两个命令）：

```bash
pip install autoredteam-orchestrator                # PyPI
pipx install autoredteam-orchestrator               # 隔离环境
uvx --from autoredteam-orchestrator autort --help    # 免安装直接运行
```

等不及 PyPI 发布，从 Git 直装：

```bash
pip install "git+https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git"
uvx --from git+https://github.com/Coff0xc/AutoRedTeam-Orchestrator autort --help
```

从源码运行（开发）：

```bash
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator
pip install -r requirements.txt
python -m cli.main --help
```

只读、无网络的起步命令：

```bash
python -m cli.main ai-surface scan --path handlers --format sarif -o surface.sarif
python -m cli.main capabilities manifest --profile safe
```

## MCP Server 接入

MCP Server 把安全能力暴露为 MCP 工具，供 AI 编辑器或 Agent 调用。它是 local-first 的：无云端、无遥测，仅限受信本地 stdio。

### 启动服务

两种等价方式：

```bash
autoredteam-mcp --stdio                # 安装后的命令（PyPI / Git）
python -m mcp_stdio_server --stdio     # 源码 checkout 运行
```

`--stdio` 选择 stdio 传输，这正是 MCP 客户端（Claude Code、Cursor、Windsurf、Kiro 等）所用的方式。

### 接入 AI 编辑器

Claude Code、Cursor 等 MCP 客户端读取 `mcpServers` 键下的 JSON 配置。本项目最小 `.mcp.json`：

```json
{
  "mcpServers": {
    "autoredteam": {
      "command": "autoredteam-mcp",
      "args": ["--stdio"],
      "env": {
        "AUTORT_CAPABILITY_PROFILE": "safe",
        "AUTOREDTEAM_AUTH_MODE": "strict",
        "AUTOREDTEAM_API_KEY": "replace-with-a-real-key"
      }
    }
  }
}
```

`AUTORT_CAPABILITY_PROFILE` 决定注册哪些工具（见[能力档案](#能力档案)）。省略则回退到 fail-closed 的 `safe` 默认值。

### 档案选择

档案按以下顺序解析：显式参数 → `AUTORT_CAPABILITY_PROFILE` 环境变量 → `safe` 默认值。任何 `minimum_profile` 高于所选档案的工具都**不会注册**，任何未在 manifest 中分类的 surface 会在注册阶段 fail-closed（`CapabilityManifestError`）。

### 环境变量

| 变量 | 取值 | 默认 | 含义 |
|---|---|---|---|
| `AUTORT_CAPABILITY_PROFILE` | `safe` \| `scan` \| `active-lab` \| `full` | `safe` | 注册为 MCP 工具的能力层级 |
| `AUTOREDTEAM_AUTH_MODE` | `strict` \| `permissive` \| `disabled` | `strict` | 受保护工具的授权门禁 |
| `AUTOREDTEAM_API_KEY` | 任意字符串 | *(未设置)* | `strict` 模式校验的 API Key；`MCP_API_KEY` 为等价别名 |

## Python SDK

SDK 是 `core/` 引擎之上的薄异步封装，从源码 checkout 导入：

```python
from autort import Scanner, Exploiter, AutoPentest, RedTeam, Reporter
from autort import __version__        # 单源版本号，如 "3.1.0"
```

所有调用均为 async，返回 `dict`（少数扫描方法返回列表）。成功以 `"success": True` 标记；失败携带真实的 `"error"` 字符串，不吞异常。

### Scanner — 侦察与检测

```python
from autort import Scanner

scanner = Scanner("http://127.0.0.1:8000")

ports = await scanner.port_scan(ports="1-1000")          # 或 top=100
recon = await scanner.full_recon()                        # 完整 10 阶段侦察
vulns = await scanner.detect_vulns(categories=["sqli", "xss", "ssrf"])
nuclei = await scanner.nuclei_scan(tags=["cve"], severity=["high", "critical"])
```

关键方法：`full_recon()`、`port_scan(ports="1-1000", top=None)`、`detect_vulns(categories=None, config=None)`、`fingerprint()`、`waf_detect()`、`subdomain_enum(domain=None)`、`passive_recon(domain=None)`、`nuclei_scan(tags=None, severity=None, template_dir=None, concurrency=10, limit=None)`。

### Exploiter — 利用与 CVE 情报

```python
from autort import Exploiter

exploiter = Exploiter("http://127.0.0.1:8000")

cves = await exploiter.cve_search("Apache Log4j", severity="critical", has_poc=True)
```

`cve_search(keyword, severity=None, has_poc=None, limit=20)` 仅做情报查询，在 `safe` 档案即可用。`cve_exploit(cve)`、`auto_exploit(top_n=5)`、`exploit(vuln, **kwargs)` 需要 `active-lab`（及以上）、授权的一次性目标、隔离执行器与 API Key。

### AutoPentest — 一键编排

```python
from autort import AutoPentest

pentest = AutoPentest("http://127.0.0.1:8000", config={"timeout": 3600})
result = await pentest.run(phases=["recon", "vuln_scan"])   # 省略 phases 则跑完整流程
```

`run(phases=None)` 驱动 `RECON → VULN_SCAN → POC_EXEC → EXPLOIT → PRIV_ESC → LATERAL → EXFIL → REPORT` 流水线。`resume(session_id)` 续跑中断的会话；`status(session_id)` 读取实时状态。这是 `full` 档案能力，仅在隔离、授权的靶场运行。

### RedTeam — 后渗透（受限）

`RedTeam(config=None)` 聚合横向移动、C2、持久化、提权与凭据发现：`lateral_move(target, method="ssh", ...)`、`c2_start(host, port=443, protocol="https")`、`persist(target="", method="crontab", ...)`、`privesc(target, ...)`、`credential_find(...)`。所有方法返回 `{"success": bool, ...}`。它们属于 `full` 档案、需审批、隔离执行器的 surface，此处仅作目录列出，不写调用示例。

### Reporter — 报告

```python
from autort import Reporter

reporter = Reporter("session_id_here")
html_path = await reporter.generate(format="html")     # html | json | markdown | executive
findings = await reporter.export_findings(format="json")
```

## CLI 命令清单

Typer CLI 是本地分析的主入口，也是安装后的 `autort` 命令；源码下用 `python -m cli.main`。

### 顶层命令

| 命令 | 用途 | 示例（仅限授权目标） |
|---|---|---|
| `scan` | 端口扫描 / 完整侦察 | `autort scan http://127.0.0.1:8000 --full` |
| `detect` | 漏洞检测 | `autort detect http://127.0.0.1:8000 -c sqli,xss,ssrf --format sarif` |
| `exploit` | CVE / 自动利用 | `autort exploit http://127.0.0.1:8000 --cve CVE-2021-44228` |
| `cve-search` | CVE 情报 | `autort cve-search "Log4j" --severity critical --has-poc -n 20` |
| `pentest` | 一键编排 | `autort pentest http://127.0.0.1:8000 --phases recon,vuln_scan` |
| `report` | 生成报告 | `autort report <session-id> -f html` |
| `nuclei` | 纯 Python Nuclei 扫描 | `autort nuclei http://127.0.0.1:8000 -t cve,rce -s high,critical` |
| `tools` | 外部工具状态 | `autort tools` |
| `version` | 显示版本 | `autort version` |

`detect`（以及 `ai-*` 扫描器）的 CI 友好参数：`--ci` 输出精简摘要，并在发现达到 `--severity-threshold`（info/low/medium/high/critical）的项时返回非零退出码。

### 子命令组

| 分组 | 命令 | 用途 |
|---|---|---|
| `ai-redteam` | `run`、`catalog`、`convert`、`eval-run` | 声明式 AI 红队场景（默认 dry-run） |
| `ai-surface` | `scan`、`scan-mcp-config`、`scan-skills` | 静态 AI/MCP 攻击面盘点（只读） |
| `code-agent` | `expand` | 调用链上下文扩展（不执行代码） |
| `runtime-api` | `serve` | 只读本地 runtime API（`/api/runs`） |
| `sandbox` | `docker-smoke` | 本地 Docker 沙箱 smoke |
| `capabilities` | `matrix`、`readiness`、`manifest`、`profiles` | 能力 manifest 与覆盖 |
| `tools` | `lint` | MCP 工具契约检查（静态） |

只读、无网络的起步命令：

```bash
autort ai-surface scan --path handlers --format sarif -o surface.sarif
autort ai-surface scan-mcp-config --path .mcp.json
autort ai-surface scan-skills --path ./skills
autort capabilities profiles
autort capabilities manifest --profile safe
autort tools lint --path handlers
```

## 配置与授权

### 能力档案

档案是有序的暴露层级，每个继承上一个：

| 档案 | 包含 | 运行边界 |
|---|---|---|
| `safe` | 本地分析、dry-run、元数据、受控本地状态 | 受信本地进程；无目标网络访问或主机命令执行 |
| `scan` | `safe` + 授权侦察与漏洞扫描 | 需明确目标范围与外部网络控制 |
| `active-lab` | `scan` + 利用验证与攻击规划 | 需一次性靶场、独立审批、隔离执行器 |
| `full` | 全部 surface，含后渗透与受限研究特性 | 仅显式 opt-in 的隔离、授权、一次性环境 |

查看实时定义：

```bash
autort capabilities profiles              # 有序档案、继承关系、surface 数量
autort capabilities manifest -p scan      # 按档案过滤的完整 manifest
```

### 授权模式

授权通过装饰器按工具施加。由 `AUTOREDTEAM_AUTH_MODE` 选择，共三档：

| 模式 | 行为 |
|---|---|
| `strict`（默认） | 受保护工具要求有效 API Key（`AUTOREDTEAM_API_KEY` 或 `MCP_API_KEY`） |
| `permissive` | 记录警告但放行 |
| `disabled` | 不校验——仅在 `AUTOREDTEAM_ENV=test` 或设置 `PYTEST_CURRENT_TEST` 时生效 |

### 能力 manifest

manifest（`core/capability_manifest.py`）是每个暴露 MCP surface 的机器可读、单一事实来源。每条声明 `kind`、`name`、`handler`、`category`、`minimum_profile`、`risk`、`maturity`，以及必需控制——`auth_required`、`approval_required` 与 `executor`（`in-process` / `external-process` / `isolated-required`）。任何未分类的 surface 注册即 fail-closed。

`required_controls` 字段是**声明式**的：它们只控制 MCP schema 暴露，不负责强制。它们不替代认证、目标范围、独立审批或隔离执行器。

## AI/MCP 安全自审

对**你自己的仓库**做纯静态审计：盘点 MCP server 与 AI agent 工具的攻击面，结果以 `file:line` 精度进入 GitHub Code Scanning。无需 target、网络、secret 或授权。

作为 GitHub Action 在每个 PR 上运行（完整示例见 [`self-audit.example.yml`](.github/workflows/self-audit.example.yml)）：

```yaml
- uses: Coff0xc/AutoRedTeam-Orchestrator@v3.1
  with:
    mode: self-audit
    path: '.'
    severity-threshold: high
```

或本地运行：

```bash
python -m cli.main ai-surface scan --path . --format sarif        # MCP handler 工具面
python -m cli.main ai-surface scan-mcp-config --path .mcp.json    # 危险命令与明文 secret
python -m cli.main ai-surface scan-skills --path ./skills         # 高危指令标记
```

审计外部仓库时，以 `--auth-mode lenient` 抑制项目特化的授权判定。

## 设计思路与方案

- **一套引擎，三个入口。** 侦察、检测、利用、编排、CVE、AI 红队与 AI 攻击面逻辑都落在 `core/`；MCP Server、SDK（`autort/`）与 CLI（`cli/main.py`）都是同一引擎之上的薄适配层。能力只实现一次，而非三遍。
- **fail-closed 的 MCP 暴露。** 每个注册的 surface 必须在 capability manifest 中分类。未分类或超出所选档案的 surface 不会被静默暴露——注册即抛错。默认是最窄的 `safe` 档案，而非最宽的。
- **声明式暴露与强制授权分层。** 档案过滤「哪些工具对客户端存在」；授权决定「受保护工具能否运行」。二者刻意独立，避免改档案时意外放宽「谁能行动」。
- **本地优先、默认 dry-run。** 服务仅 stdio，信任本地进程。高风险能力默认 dry-run，仅在显式 opt-in 的隔离一次性靶场中离开 dry-run。
- **自审是一等公民。** 同一仓库自带对 MCP handler、MCP 客户端配置、skill/prompt 文件的只读扫描器，无需目标或网络即可审 AI/MCP 攻击面本身。

## 安全与边界

- MCP capability profile（`safe`/`scan`/`active-lab`/`full`）在注册阶段过滤工具，但不替代认证、目标范围、独立审批或隔离执行器。
- 高风险能力默认 dry-run，仅应在一次性隔离环境中启用。
- 认证由单个工具装饰器接入，尚未构成覆盖全部注册面的统一边界。

详见[安全模型](docs/security-model.md)与[能力成熟度](docs/capability-maturity.md)。

## 许可与免责

MIT License，见 [`LICENSE`](LICENSE)。

仅供明确授权的安全测试、内部验证、教育研究与本地实验使用。使用者须遵守适用法律并取得目标所有者的书面授权；禁止用于未授权的扫描、利用、持久化、数据外传或规避安全控制。
