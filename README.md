<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>企业级 AI 红队编排平台</b><br>
  <sub>纯 Python 引擎 | MCP + SDK + CLI 三层接口 | 全链路攻击自动化</sub>
</p>

<p align="center">
  <a href="README.md"><b>简体中文</b></a> ·
  <a href="README_EN.md">English</a>
</p>

<p align="center">
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/stargazers"><img src="https://img.shields.io/github/stars/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=gold" alt="Stars"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/network/members"><img src="https://img.shields.io/github/forks/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=silver" alt="Forks"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues"><img src="https://img.shields.io/github/issues/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=red" alt="Issues"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/commits/main"><img src="https://img.shields.io/github/last-commit/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github" alt="Last Commit"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.1.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/MCP-Native-00ADD8?style=flat-square" alt="MCP">
  <img src="https://img.shields.io/badge/Tools-132-FF6B6B?style=flat-square" alt="Tools">
  <img src="https://img.shields.io/badge/Tests-1980-4CAF50?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-社区-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/actions"><img src="https://img.shields.io/github/actions/workflow/status/Coff0xc/AutoRedTeam-Orchestrator/ci.yml?style=flat-square&logo=github-actions&logoColor=white&label=CI" alt="CI"></a>
</p>

---

## 为什么选择 AutoRedTeam？

**唯一不依赖外部工具的 AI 渗透测试框架。** 26 个漏洞检测器全部纯 Python 实现，外部工具（sqlmap/nuclei/ffuf）自动下载内置，无需手动安装。

```
┌──────────────────────────────────────────────────────────────────┐
│                AutoRedTeam-Orchestrator v3.1.0                   │
├──────────────────────────────────────────────────────────────────┤
│  ● 132 MCP 工具          ● 26 漏洞检测器     ● 1980 测试用例    │
│  ● 纯 Python Nuclei 引擎 ● MCTS 攻击规划     ● SQLite 知识图谱  │
│  ● LLM 增强决策          ● Docker 沙箱       ● SARIF CI/CD 集成 │
│  ● SDK + CLI + MCP 三层  ● 横向移动/C2/提权  ● OOB 误报验证     │
│  ● 生产级 C2 Server      ● 工具自动下载内置  ● LaZagne 凭据集成 │
│  ● PostExploit 执行层    ● 统一引擎路由器    ● 被动侦察 6 源    │
├──────────────────────────────────────────────────────────────────┤
│  三种使用方式:                                                    │
│    1. MCP — Cursor / Windsurf / Kiro / Claude Desktop / Claude Code │
│    2. SDK — from autort import Scanner, AutoPentest              │
│    3. CLI — autort scan / autort detect / autort pentest         │
└──────────────────────────────────────────────────────────────────┘
```

---

## 目录

- [快速开始](#快速开始)
- [三种使用方式](#三种使用方式)
- [架构总览](#架构总览)
- [工具矩阵](#工具矩阵)
- [核心能力](#核心能力)
- [MCP 配置](#mcp-配置)
- [CI/CD 集成](#cicd-集成)
- [配置说明](#配置说明)
- [开发指南](#开发指南)
- [路线图](#路线图)
- [贡献](#贡献)
- [许可证](#许可证)

---

## 快速开始

```bash
# 安装
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator
pip install -r requirements.txt

# 验证
python -c "from autort import Scanner; print('OK')"
```

---

## 三种使用方式

### 1. MCP — AI 编辑器集成

```bash
python mcp_stdio_server.py  # 启动 MCP 服务器
```

在 AI 编辑器中自然语言驱动：*"扫描 http://target.com 的 SQL 注入漏洞"*

### 2. Python SDK

```python
import asyncio
from autort import Scanner, Exploiter, AutoPentest

async def main():
    # 侦察 + 漏洞检测
    scanner = Scanner("http://target.com")
    recon = await scanner.full_recon()
    vulns = await scanner.detect_vulns(categories=["sqli", "xss", "ssrf"])

    # Nuclei 模板扫描 (185K+ 社区模板)
    nuclei_results = await scanner.nuclei_scan(
        severity=["high", "critical"], concurrency=20
    )

    # 一键自动化渗透
    pentest = AutoPentest("http://target.com")
    report = await pentest.run(phases=["recon", "detect", "exploit", "report"])

asyncio.run(main())
```

### 3. CLI 命令行

```bash
# 侦察
autort scan http://target.com --full

# 漏洞检测
autort detect http://target.com -c sqli,xss,ssrf

# Nuclei 扫描
autort nuclei http://target.com --severity high,critical --tags cve

# 一键渗透
autort pentest http://target.com --phases recon,detect,exploit

# CI 模式 (SARIF 输出 + 非零退出码)
autort detect http://target.com --ci --format sarif -o results.sarif

# 报告生成
autort report SESSION-ID --format html -o report.html
```

---

## 架构总览

```
                    ┌─────────────────────────────────────┐
                    │         AI Editor / User             │
                    │   (Cursor, Claude Code, CLI, SDK)    │
                    └──────────────┬──────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
         MCP (JSON-RPC)      Python SDK           Typer CLI
              │                    │                    │
              ▼                    ▼                    ▼
    ┌─────────────────────────────────────────────────────────┐
    │                    handlers/ (131 tools)                 │
    │   recon(8) detector(27) cve(8) exploit(12) lateral(9)   │
    │   redteam(14) ad(3) persistence(3) cloud(3) api(7) ... │
    └──────────────────────┬──────────────────────────────────┘
                           │
    ┌──────────────────────┼──────────────────────────────────┐
    │                   core/ Engine Layer                     │
    ├─────────────────────────────────────────────────────────┤
    │  detectors/    26 纯 Python 检测器 (SQLi/XSS/SSRF/RCE..)│
    │  exploit/      利用引擎 (SQLi/RCE/SSRF/XXE/SSTI/反序列化)│
    │  recon/        10 阶段侦察 (端口/DNS/指纹/子域名/目录...)│
    │  lateral/      横向移动 (SMB/SSH/WMI/WinRM/PsExec)      │
    │  c2/           C2 框架 (Beacon + DNS/HTTP/WS 隧道)       │
    │  orchestrator/ 编排器 (MCTS规划 + 8阶段流水线)            │
    │  nuclei_engine 纯 Python Nuclei 模板引擎                 │
    │  llm/          统一 LLM Provider (可选)                   │
    │  sandbox/      Docker 沙箱执行器 (可选)                   │
    │  knowledge/    SQLite 知识图谱 (17 实体类型)              │
    │  config/       Pydantic 统一配置                          │
    │  ...20+ 子包                                             │
    └─────────────────────────────────────────────────────────┘
```

---

## 工具矩阵

| 类别 | 数量 | 关键工具 |
|------|------|----------|
| **侦察** | 8 | `port_scan`, `subdomain_enum`, `fingerprint`, `waf_detect`, `dir_scan` |
| **漏洞检测** | 27 | `sqli_scan`, `xss_scan`, `ssrf_scan`, `rce_scan`, `nuclei_scan` + 22 种 |
| **CVE** | 8 | `cve_search`, `cve_auto_exploit`, `cve_generate_poc` |
| **利用** | 12 | `auto_pentest`, `exploit_vulnerability`, `exploit_by_cve` |
| **红队** | 14 | `c2_beacon_start`, `payload_obfuscate`, `waf_bypass`, `credential_find` |
| **横向移动** | 9 | `lateral_ssh`, `lateral_smb`, `lateral_wmi`, `lateral_winrm`, `lateral_psexec` |
| **AD 攻击** | 3 | `ad_enumerate`, `ad_kerberos_attack`, `ad_spn_scan` |
| **持久化** | 3 | `persistence_windows`, `persistence_linux`, `persistence_webshell` |
| **API 安全** | 7 | `jwt_scan`, `graphql_scan`, `websocket_scan`, `oauth_scan`, `cors_deep_scan` |
| **云安全** | 3 | `k8s_scan`, `grpc_scan`, `aws_scan` |
| **供应链** | 3 | `sbom_generate`, `dependency_audit`, `cicd_scan` |
| **外部工具** | 8 | `ext_nmap_scan`, `ext_nuclei_scan`, `ext_sqlmap_scan`, `ext_ffuf_fuzz` |
| **会话/报告/AI** | 9 | `session_create`, `generate_report`, `smart_analyze` |
| **知识图谱/MCTS** | 4 | `kg_store`, `kg_query`, `kg_attack_paths`, `plan_attack_path` |
| **并发/资源/提示** | 11 | `parallel_scan` + 4 MCP Resources + 6 MCP Prompts |
| **总计** | **131** | |

---

## 核心能力

### 纯 Python 检测引擎 (无外部依赖)

26 个检测器覆盖 OWASP Top 10+：

| 检测器 | 技术 | 精度 |
|--------|------|------|
| SQLi (错误/时间/布尔/UNION) | 60+ DB 错误模式, **双重时间验证**, 百分比阈值 | ~90% |
| XSS (反射/DOM/存储) | 精确反射匹配 + **基线对比排除自身标签** | ~85% |
| SSRF (云元数据/内部/协议) | AWS/GCP/Azure 元数据检测 + **基线响应对比** | ~85% |
| RCE (回显/时间) | OS 输出模式 + **双重验证** | ~95% |
| + SSTI, XXE, LFI, IDOR, CSRF, 反序列化, CRLF, 原型污染, 缓存投毒... | | |

### 误报过滤 (默认开启)

7 层过滤 + 3 种验证：

```
检测结果 → WAF检测 → 速率限制 → CAPTCHA → SPA识别 → 动态内容 → 错误页面
         → 统计验证 (Welch t-test) → 布尔盲注验证 → OOB 回调验证
```

### Nuclei 模板引擎

纯 Python 解析 Nuclei YAML 模板，无需 nuclei 二进制：

```bash
autort nuclei http://target.com --tags cve,rce --severity critical -n 1000
```

### LLM 增强 (可选)

```bash
# 启用 LLM 增强决策
export AUTORT_LLM_PROVIDER=ollama  # openai/anthropic/ollama/deepseek
export AUTORT_LLM_MODEL=llama3.1   # 本地模型, 数据不出本地

# LLM 不可用时自动退回纯规则引擎 — 零影响
```

### Docker 沙箱 (可选)

```python
# config/config.yaml
sandbox:
  enabled: true
  image: "python:3.12-slim"
  memory_limit: "512m"
```

---

## MCP 配置

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["E:/path/to/mcp_stdio_server.py"],
      "env": {"PYTHONIOENCODING": "utf-8"}
    }
  }
}
```

### Cursor

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/absolute/path/to/mcp_stdio_server.py"]
    }
  }
}
```

---

## CI/CD 集成

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [pull_request]
jobs:
  autort:
    runs-on: ubuntu-latest
    steps:
      - uses: Coff0xc/AutoRedTeam-Orchestrator@v3.1
        with:
          target: ${{ secrets.SCAN_TARGET }}
          severity-threshold: high
```

SARIF 结果自动上传到 GitHub Security tab。

---

## 配置说明

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `AUTORT_SCAN_TIMEOUT` | 30 | 扫描超时 (秒) |
| `AUTORT_HTTP_MAX_RETRIES` | 3 | HTTP 重试次数 |
| `AUTORT_LLM_PROVIDER` | none | LLM 提供者 (openai/anthropic/ollama/none) |
| `AUTORT_LLM_MODEL` | auto | LLM 模型名 |
| `AUTORT_AUTH_MODE` | strict | 认证模式 (strict/permissive/disabled) |

完整配置见 `.env.example` 和 `config/config.yaml`。

---

## 开发指南

```bash
# 安装开发依赖
pip install -r requirements-dev.txt

# 测试
pytest                          # 全量测试 (1963 cases)
pytest -m "not slow"            # 跳过慢速测试
pytest --cov=core --cov=handlers --cov-report=html  # 覆盖率报告

# 代码质量
black core/ handlers/ utils/ autort/ cli/
isort core/ handlers/ utils/ autort/ cli/
flake8 core/ handlers/ utils/
mypy core/ handlers/ utils/
```

---

## 路线图

- [x] v3.1.0 — SDK + CLI + LLM + Nuclei + 沙箱 + CI/CD + 精度优化
- [ ] v3.2.0 — Web Dashboard (React)
- [ ] v3.2.0 — 多 Agent 协作 (ReconAgent/ExploitAgent/ReportAgent)
- [ ] v3.3.0 — Playbook 系统 (预置攻击剧本)
- [ ] v3.3.0 — DVWA/Juice Shop 自动化基准测试

---

## 贡献

欢迎 PR！请遵循 [贡献指南](CONTRIBUTING.md)。

```bash
# 提交规范
feat: 新功能
fix: 修复
docs: 文档
refactor: 重构
test: 测试
security: 安全修复
```

---

## 许可证

[MIT License](LICENSE) - Coff0xc

---

## 免责声明

本工具仅供**授权安全测试**和**教育研究**使用。使用者必须在获得目标系统所有者明确书面授权后方可进行测试。任何未经授权的使用均属违法行为，作者不承担任何因非法使用而产生的法律责任。
