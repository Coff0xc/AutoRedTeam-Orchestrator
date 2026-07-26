# AutoRedTeam-Orchestrator

**面向授权测试与 AI/MCP 攻击面审计的 local-first、MCP-native 安全自动化工作台。**

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-3.1.0-orange)
![Status](https://img.shields.io/badge/status-Beta%20%2F%20Research%20Preview-yellow)

**中文** · [English](README_EN.md) · [Русский](README_RU.md)

[能力成熟度](docs/capability-maturity.md) · [安全模型](docs/security-model.md) · [安全审计](docs/security-audits/)

> **Beta / Research Preview** — 优先支持静态分析、dry-run 与本地靶场。exploit、横向移动、持久化、C2、数据外传等高风险能力属于受限实验特性；policy 与 sandbox 元数据不等同于操作系统或容器级隔离。

## 概述

AutoRedTeam-Orchestrator 在单一代码库中提供可组合的安全能力，并通过三个入口暴露：MCP Server、Python SDK 与 Typer CLI。产品主线是 **AI 辅助的安全自动化**——让 AI 编辑器与 Agent 通过 MCP 使用受控的安全能力，并对 AI/MCP 系统自身的攻击面做静态审计。

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

## 入口

| 入口 | 路径 | 定位 |
|---|---|---|
| MCP Server | `mcp_stdio_server.py` | 默认 fail-closed `safe` profile；仅限受信本地 stdio |
| Python SDK | `autort/` | 从源码 checkout 使用 |
| Typer CLI | `cli/main.py` | 本地分析与开发主入口 |

授权扫描会产生网络行为，仅限 localhost、本地靶场或具有书面授权的目标：

```bash
python -m cli.main scan http://127.0.0.1:8000 --full
python -m cli.main detect http://127.0.0.1:8000 -c sqli,xss,ssrf
```

## 安全与边界

- MCP capability profile（`safe`/`scan`/`active-lab`/`full`）在注册阶段过滤工具，但不替代认证、目标范围、独立审批或隔离执行器。
- 高风险能力默认 dry-run，仅应在一次性隔离环境中启用。
- 认证由单个工具装饰器接入，尚未构成覆盖全部注册面的统一边界。

详见[安全模型](docs/security-model.md)与[能力成熟度](docs/capability-maturity.md)。

## 许可与免责

MIT License，见 [`LICENSE`](LICENSE)。

仅供明确授权的安全测试、内部验证、教育研究与本地实验使用。使用者须遵守适用法律并取得目标所有者的书面授权；禁止用于未授权的扫描、利用、持久化、数据外传或规避安全控制。
