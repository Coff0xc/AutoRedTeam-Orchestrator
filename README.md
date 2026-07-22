# AutoRedTeam-Orchestrator

**面向授权安全测试与 AI/MCP 工程团队的 local-first、MCP-native 安全自动化工作台。**

[English](README_EN.md) · [能力成熟度](docs/capability-maturity.md) ·
[安全模型](docs/security-model.md) · [安全审计](docs/security-audits/)

> **状态：Beta / Research Preview**
>
> 项目优先支持静态分析、dry-run、本地靶场和可审计研发工作流。
> 所有 active/high-risk 能力，包括 exploit、privilege escalation、lateral、AD、
> post-exploit、persistence、C2、credential、external-tool execution、stealth/evasion
> 和 exfiltration，均属于受限实验能力。
> Policy 或 sandbox metadata 本身不等于操作系统或容器隔离。

AutoRedTeam-Orchestrator 在同一代码库中提供相互重叠的 Python core capabilities，并通过
三种入口访问：

- **MCP Server**：为支持 MCP 的 AI Editor 和 Agent 暴露安全能力。
- **Python SDK**：在 Python 中组合侦察、检测、编排与报告。
- **Typer CLI**：运行本地分析、dry-run、扫描、报告和开发诊断。

项目当前最适合授权实验环境、安全自动化研发、AI/MCP 安全表面分析、CTF、教学和
本地 fixture；不是 turnkey enterprise platform，也不是自主攻击 Agent 或 production C2。

产品主线是 **AI-assisted security automation**：AI Editor 或 Agent 通过 MCP 使用受控的
安全能力。`ai-redteam` 子命令属于 **AI 系统红队评估** Preview 支线，目前只生成计划。

## 它是什么

- 一个 MCP-native 的安全能力适配与编排框架。
- 一个面向 AI Agent / MCP / Skill 的本地静态安全分析工作台。
- 一个可扩展的 Python detector、tool adapter、workflow 和 report 开发基础。
- 一个正在建设中的受控执行模型：policy、run state、trace、approval 和 artifact。

## 它不是什么

- 不是 Nmap、Nuclei、sqlmap、Burp/ZAP 或 Metasploit 的全面替代品。
- 不是已完成的 autonomous pentest platform。
- 不是多租户、远程共享或企业级 campaign 服务。
- 不是 production C2、隐蔽通信或规避检测产品。
- 当前 AI 系统红队评估 runner 是 **plan-only dry-run**，不会请求 scenario target、
  model、shell 或 tool。

## 安全优先的五分钟体验

当前推荐从源码 checkout 运行。Python 版本要求为 3.10+。

```bash
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator
pip install -r requirements.txt
python -m cli.main --help
```

### 1. 静态盘点 MCP / AI 工具边界

该命令只解析本地 Python 源码，不导入或执行 handler：

```bash
python -m cli.main ai-surface scan --path handlers -o surface.json
```

### 2. 验证 SDK 和 capability catalog

```bash
python -c "from autort import Scanner; print('SDK import OK')"
python -m cli.main ai-redteam catalog
```

### 3. 可选：生成 AI 系统红队评估 Preview 计划

仓库样例只指向 localhost；runner 只生成 attempts、scores 和 trace，不请求目标：

```bash
python -m cli.main ai-redteam run config/ai_redteam.example.yaml -o run.json
```

## 三种入口

| 入口 | 路径 | 当前定位 |
|---|---|---|
| MCP Server | `mcp_stdio_server.py` | Preview；仅限 trusted-local stdio 使用 |
| Python SDK | `autort/` | Beta；源码 checkout 下使用 |
| Typer CLI | `cli/main.py` | Beta；本地分析与开发主入口 |

常用的只读或 dry-run 命令：

```bash
python -m cli.main ai-surface scan --path handlers
python -m cli.main ai-redteam run config/ai_redteam.example.yaml
python -m cli.main ai-redteam catalog
python -m cli.main code-agent expand --path core
python -m cli.main capabilities manifest --profile safe
```

## 能力成熟度

| 能力 | 状态 | 边界 |
|---|---|---|
| SDK / CLI 基础入口 | Beta | 主要从源码 checkout 验证 |
| 侦察、检测、JSON/SARIF 输出 | Beta | 仅限明确授权目标；尚无公开准确率 benchmark |
| HTML 报告 | Preview | 不可信 finding 内容的 escaping 尚未完成安全加固 |
| Session storage | Preview | 基础持久化可用；orchestrator resume 仍是 Experimental |
| AI/MCP 静态表面扫描 | Preview | 只读 AST 分析 |
| MCP stdio | Preview | trusted-local only；认证尚不是全局统一边界 |
| AI 系统红队评估 scenario runner | Preview | plan-only dry-run，不调用目标或模型 |
| Agent runtime、policy、trace、本地 API | Preview | 主要是 plan-time governance metadata |
| 自动 pentest orchestrator | Experimental | 默认 dry-run；resume 尚未 release-certified |
| Docker executor | Experimental | 显式容器 executor 可降低暴露面，但不是完整安全边界 |
| 所有 active/high-risk operations | Restricted Experimental | 仅限一次性隔离靶场 |
| multi-user campaign / distributed execution | Planned | 尚无受支持契约 |

完整定义、已知限制和升级门槛见
[Capability Maturity](docs/capability-maturity.md)。

## 实际架构

```text
AI Editor / Operator
        |
        +-- MCP stdio --> capability profile --> handlers/-+
        |                                                  |
        +-- Python SDK ------ autort/ ----------------------+--> core/
        |                                                  |    recon
        +-- Typer CLI ------- cli/main.py ------------------+    detectors
                                                                  tools
Safe local paths:                                                reporting
  ai-surface -> read-only AST scan                               session
  ai-redteam -> plan-only dry-run

Orchestrated path:
  AutoPentestOrchestrator -> RuntimePipeline -> PhaseExecutor -> core
                            policy / trace       dry-run by default
```

重要边界：

- 部分 legacy SDK 和 handler 仍会直接调用 core，并不全部经过统一 runtime executor。
- `RuntimePipeline` 的 policy/sandbox decision 是治理记录，不自动创建容器。
- `EngineRouter` 目前不是 SDK、CLI、handler 的统一生产调用路径。
- MCP capability profile 会在注册阶段过滤 tools/resources/prompts，但不替代认证、target
  scope、独立审批或隔离 executor。
- MCP authentication 仍由单个工具 decorator 接入，不应视为覆盖所有已注册 surface 的全局边界。

更完整说明见 [Security Model](docs/security-model.md)。

## 授权扫描示例

以下命令会产生网络行为。只允许用于 localhost、本地靶场或具有书面授权的目标。

```bash
python -m cli.main scan http://127.0.0.1:8000 --full
python -m cli.main detect http://127.0.0.1:8000 -c sqli,xss,ssrf
python -m cli.main nuclei http://127.0.0.1:8000 --severity high,critical
python -m cli.main pentest http://127.0.0.1:8000 --phases recon,vuln_scan,report
```

高风险阶段不应在含真实凭据、源码或用户文件的工作站上运行。使用 disposable VM /
container、显式网络策略和独立审批。

## MCP 使用

stdio 启动：

```bash
python mcp_stdio_server.py --stdio
```

MCP server 默认使用 fail-closed 的 `safe` profile。可先查看 profile 定义与实际 manifest：

```bash
python -m cli.main capabilities profiles
python -m cli.main capabilities manifest --profile safe
```

| Profile | 注册边界 |
|---|---|
| `safe` | 本地静态分析、dry-run、元数据与受控本地状态；无目标网络或 host command |
| `scan` | `safe` 加授权侦察、漏洞扫描和外部扫描器 |
| `active-lab` | `scan` 加 exploit validation 与攻击规划；要求一次性隔离靶场和独立审批 |
| `full` | 全部 surface，包括后渗透、凭据、C2、持久化、规避和外传；仅限显式 opt-in |

未知 profile 会在任何 surface 注册前拒绝启动。profile 仅控制 MCP schema 暴露；它不会
把 in-process 调用自动移入容器，也不会替代书面授权、网络 allowlist 或 request-scoped RBAC。
`safe` 仍继承启动进程的文件权限；带 path 参数的本地分析工具可读取调用方指定的可访问
文件，因此只适用于受信本地 client。

当前 MCP 模型的安全假设：

- client 与 server 属于同一个受信本地用户；
- server 继承启动进程的文件和网络权限；
- 不通过远程、共享或多租户 transport 暴露；
- `AuthManager` 支持 key object，但当前没有稳定的 operator CLI provisioning contract；
- 因此不能只设置任意字符串，也不能依赖 API key 作为远程部署安全边界；
- 在统一注册层认证完成前，`strict` 不代表所有 tools/resources/prompts 都已受保护。

相关环境变量：

| 环境变量 | 说明 |
|---|---|
| `AUTOREDTEAM_AUTH_MODE` | `strict` 或 `permissive`；默认 `strict` |
| `AUTOREDTEAM_API_KEY` | MCP API key |
| `MCP_API_KEY` | MCP API key 的兼容变量 |
| `AUTORT_CAPABILITY_PROFILE` | `safe`、`scan`、`active-lab` 或 `full`；MCP 默认 `safe` |

## Python SDK

以下示例仅使用本地授权目标：

```python
import asyncio

from autort import Scanner


async def main() -> None:
    scanner = Scanner("http://127.0.0.1:8000")
    recon = await scanner.full_recon()
    findings = await scanner.detect_vulns(categories=["sqli", "xss", "ssrf"])
    print(recon)
    print(findings)


asyncio.run(main())
```

`AutoPentest` 当前默认继承 orchestrator 的 dry-run runtime 配置。所有主动或高风险
`Exploiter`、`RedTeam`、AD、post-exploit 和 external-tool API 都属于 restricted
experimental surface。

## 安装配置

### 依赖层级

```bash
# 最小 MCP 依赖
pip install -r requirements-core.txt

# 完整源码运行依赖
pip install -r requirements.txt

# 开发环境还需要额外安装（requirements-dev.txt 不包含完整运行依赖）
pip install -r requirements-dev.txt
```

当前建议使用源码 checkout；wheel 和容器发布物在通过 fresh-install 验证前不标记为
release-certified。

### LLM 配置

LLM integration 是可选能力：

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `AUTORT_LLM_PROVIDER` | `none` | `openai`、`anthropic` 或 `none`；其他 provider 为 Preview |
| `AUTORT_LLM_MODEL` | provider 默认值 | 模型名 |
| `AUTORT_LLM_API_KEY` | 空 | API key |
| `AUTORT_LLM_BASE_URL` | 空 | 自定义兼容 endpoint |

默认依赖只覆盖 OpenAI / Anthropic 直接 SDK 路径。Ollama、DeepSeek 和自定义
`base_url` 尚未完成统一依赖与端到端验证，不应视为稳定支持。

配置样例：

- `config/config.yaml.example`
- `config/external_tools.yaml.example`
- `config/ai_redteam.example.yaml`
- `.env.example`

## 验证与开发

先运行最窄检查，再扩大范围：

```bash
python -m pytest tests/test_sdk.py tests/test_cli.py -q
python -m pytest tests/test_mcp_server_smoke.py -q
```

质量检查：

```bash
black core/ handlers/ utils/ autort/ cli/
isort core/ handlers/ utils/ autort/ cli/
flake8 core/ handlers/ utils/
mypy core/ handlers/ utils/
bandit -r core handlers utils -c .bandit
pre-commit run --all-files
```

网络、OOB、Docker、外部工具和 active capability 应在隔离 job 中运行，不应混入普通
unit suite。

## 已知限制

- CI、Docker、wheel、package-data 和 Windows matrix 仍需完成 release hardening。
- MCP surface 已由 machine-readable manifest 统一分类，但 profile 尚未成为 CLI/SDK 的统一调用边界。
- Profile 在 handler 模块 import 后才过滤 surface，因此不是最小依赖或 import-side-effect 隔离器。
- MCP RBAC、scope、approval 和 executor 尚未形成全入口统一控制链。
- MCP key provisioning 尚无稳定 operator CLI contract。
- checkpoint/resume 与 bundled Nuclei template discovery 尚未 release-certified。
- HTML report renderer 尚未完成对不可信 finding 内容的 escaping hardening。
- AI 系统红队评估 scorer 目前主要记录 `not_run`，不是实际 target evaluation。
- `capabilities matrix` 是源码结构对照表，不是产品成熟度或 production-readiness 证明。
- MCTS、knowledge、agent roles 等属于 research surface。

详见 [Capability Maturity](docs/capability-maturity.md)。

## Roadmap

### Now

- 将 capability manifest 扩展为 MCP/CLI/SDK 共用的 request-time policy。
- 统一 principal、RBAC、target scope、action-bound approval、executor 和 audit。
- 修复 CI、Docker、wheel、package-data、version 和 resume contract。
- 统一 Finding、Artifact、Evidence、RunState 和 Report schema。

### Next

- 深化 AI/MCP surface policy lint、SARIF 和 CI integration。
- 增加真实 AI target adapter、response capture、scorer、baseline 和 regression。
- 建立持久化 evidence store、artifact provenance 和 retention。
- 提供统一 external-tool adapter SDK 与 conformance tests。

### Later

- 在真实运行数据基础上演进 MCTS、knowledge 和 multi-agent recommendation。
- multi-target campaign、Web UI、collaboration 和 distributed executor。

## 贡献

提交前建议运行：

```bash
python -m pytest tests/test_sdk.py tests/test_cli.py -q
python -m pytest tests/test_mcp_server_smoke.py -q
pre-commit run --all-files
```

安全问题请不要在公开 issue 中包含真实目标、凭据或利用数据。设计和安全边界变更应同步
更新 [Security Model](docs/security-model.md) 与
[Capability Maturity](docs/capability-maturity.md)。

## 许可证与免责声明

本项目使用 MIT License，详见 `LICENSE`。

本工具仅供明确授权的安全测试、内部验证、教育研究、本地实验和 dry-run 使用。使用者必须
遵守适用法律并取得目标所有者的书面授权。禁止将本项目用于未授权扫描、攻击、持久化、
数据外带、破坏性行为或规避执法与安全控制。
