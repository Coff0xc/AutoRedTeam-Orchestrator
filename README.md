# 🔥 AutoRedTeam-Orchestrator

<div align="center">

[English](README_EN.md) | 简体中文

**AI 驱动的自动化红队编排框架**

*跨平台支持 Linux / Windows / macOS，集成 54 个 MCP 工具与 2000+ Payload*

[![OS](https://img.shields.io/badge/OS-Linux%20%7C%20Windows%20%7C%20macOS-557C94?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/Coff0xc/AutoRedTeam-Orchestrator)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-Native-00ADD8?style=for-the-badge)](https://modelcontextprotocol.io/)
[![Tools](https://img.shields.io/badge/Tools-54-FF6B6B?style=for-the-badge)](https://github.com/Coff0xc/AutoRedTeam-Orchestrator)
[![Payloads](https://img.shields.io/badge/Payloads-2000+-orange?style=for-the-badge)](https://github.com/Coff0xc/AutoRedTeam-Orchestrator)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.0.0-blue?style=for-the-badge)](CHANGELOG.md)

</div>

---

## 🎯 核心特性

<table>
<tr>
<td width="50%">

### 🤖 AI 原生
- 智能指纹识别与攻击链规划
- 历史反馈学习优化
- 自动选择工具与 Payload
- AI PoC 生成引擎

</td>
<td width="50%">

### ⚡ 全流程自动化
- 子域/端口/WAF/指纹扫描
- 漏洞发现与验证
- 一键生成专业报告
- 10 阶段标准侦察流程

</td>
</tr>
<tr>
<td width="50%">

### 🔴 红队增强
- 横向移动 (SMB/SSH/WMI)
- C2 通信 (Beacon/DNS/HTTP/WebSocket)
- 混淆免杀与隐蔽通信
- 持久化/凭证获取/AD 攻击

</td>
<td width="50%">

### 🛡️ 安全扩展
- API 安全 (JWT/CORS/GraphQL/WebSocket)
- 供应链安全 (SBOM/OSV/CI-CD)
- 云原生安全 (K8s/gRPC)
- CVE 情报多源同步

</td>
</tr>
</table>

---

## 📦 快速开始

### 安装

```bash
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator
pip install -r requirements.txt
```

### 运行 MCP 服务器

```bash
python mcp_stdio_server.py
```

### MCP 配置

<details>
<summary><b>Claude Desktop / Claude Code</b></summary>

配置文件：`~/.claude/mcp.json` 或 `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": { "PYTHONIOENCODING": "utf-8" }
    }
  }
}
```
</details>

<details>
<summary><b>Cursor</b></summary>

配置文件：`~/.cursor/mcp.json`

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"]
    }
  }
}
```
</details>

<details>
<summary><b>Windsurf</b></summary>

配置文件：`~/.codeium/windsurf/mcp_config.json`

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": { "PYTHONIOENCODING": "utf-8" }
    }
  }
}
```
</details>

<details>
<summary><b>Kiro</b></summary>

配置文件：`~/.kiro/mcp.json`

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"]
    }
  }
}
```
</details>

---

## 🛠️ 工具矩阵

| 类别 | 工具数 | 功能 |
|------|--------|------|
| **侦察 Recon** | 8 | 端口扫描、子域枚举、DNS查询、WAF检测、指纹识别、JS分析 |
| **漏洞检测** | 12 | SQLi、XSS、SSRF、XXE、SSTI、LFI、CSRF、命令注入、反序列化 |
| **Web 扫描** | 2 | 攻面发现、注入点抽取、编排式漏洞扫描 |
| **API 安全** | 7 | JWT测试、CORS绕过、GraphQL安全、WebSocket安全、安全头评分 |
| **供应链安全** | 3 | SBOM生成、依赖审计、CI/CD扫描 |
| **云原生安全** | 3 | K8s审计、gRPC测试、容器安全 |
| **红队工具** | 4 | 横向移动、C2通信、混淆免杀、持久化、凭证获取、AD攻击 |
| **CVE 情报** | 5 | 多源同步、PoC执行、AI生成 |
| **会话/报告/AI** | 10 | 会话管理、报告生成、AI决策辅助 |

> ⚠️ **注意**: 实际注册的 MCP 工具为 54 个，之前文档中的 "130+" 为统计错误。

---

## 💬 使用示例

在 AI 编辑器中直接对话：

```
🔍 "对 example.com 做完整侦察并输出报告"
🔍 "扫描 192.168.1.0/24 开放端口并识别服务"
🔍 "检查目标是否存在 Log4j/Shiro 漏洞"
🔍 "对目标 API 执行 JWT 安全扫描"
🔍 "生成项目的 SBOM 并扫描依赖漏洞"
🔍 "检测 K8s 集群中的特权容器"
🔍 "发现 example.com 的攻击面并提取注入点"
🔍 "对目标执行 Web 漏洞扫描 (SQLi/XSS/SSRF)"
```

---

## 📁 项目结构

```
AutoRedTeam-Orchestrator/
├── mcp_stdio_server.py      # MCP 服务器入口
├── tools/                   # MCP 工具定义 (13 模块)
│   ├── recon_tools.py       # 侦察工具
│   ├── vuln_tools.py        # 漏洞检测
│   ├── ai_tools.py          # AI 决策
│   ├── pentest_tools.py     # 渗透测试
│   ├── pipeline_tools.py    # 流水线工具
│   └── web_scan_tools.py    # Web 扫描编排
├── core/
│   ├── recon/               # 侦察引擎 (StandardReconEngine)
│   ├── pipeline.py          # 漏洞检测流水线
│   ├── c2/                  # C2 通信
│   ├── lateral/             # 横向移动
│   ├── evasion/             # 混淆免杀
│   ├── persistence/         # 持久化
│   ├── credential/          # 凭证获取
│   ├── ad/                  # AD 域渗透
│   └── cve/                 # CVE 情报
├── modules/
│   ├── api_security/        # API 安全
│   ├── supply_chain/        # 供应链安全
│   ├── cloud_security/      # 云原生安全
│   ├── web_scanner/         # Web 扫描引擎 (攻面发现/注入点建模)
│   └── smart_cache.py       # 智能缓存
├── wordlists/               # 安全测试字典 (目录/密码/用户名/子域名)
└── utils/                   # 工具函数
```

---

## 📋 更新日志

### v3.0.0 (2026-01-18) - 架构审计与修正

- **文档修正**: 工具数量从 130+ 修正为实际的 54 个
- **架构审计**: 完成全面代码审计，识别关键缺陷
- **已知问题**:
  - 测试覆盖率 <1%，需要补充
  - 多个核心模块在 v2.8 重构时已删除
  - `beacon.py` 存在线程安全问题

### v2.7.1 (2026-01-10) - Web 扫描引擎

- **Web Scanner 模块**: 攻面发现与注入点建模引擎
  - `web_discover`: 自动发现表单、链接、JS API 端点
  - `web_scan`: 编排式漏洞扫描，支持 SQLi/XSS/SSRF 等
- **内置字典**: 新增 wordlists 目录 (目录/密码/用户名/子域名)
- **工具模块**: 新增 `tools/web_scan_tools.py`

### v2.7.0 (2026-01-09) - 架构重构

- **模块化重构**: 拆分 mcp_stdio_server.py 为 12 个独立工具模块
- **统一注册**: ToolRegistry 集中管理工具注册
- **侦察引擎**: 合并为 StandardReconEngine (10 阶段)
- **流水线机制**: 指纹→POC→弱口令→攻击链自动化
- **缓存优化**: CacheType 枚举，向后兼容
- **代码精简**: 删除 4,351 行冗余代码

### v2.6.0 (2026-01-07) - API/供应链/云安全

- JWT/CORS/GraphQL/WebSocket 安全测试
- SBOM 生成 (CycloneDX/SPDX)
- K8s/gRPC 安全审计
- 54 个 MCP 工具

<details>
<summary>查看更多版本</summary>

### v2.5.0 (2026-01-06)
- CVE 多源同步与 AI PoC 生成
- C2 隐蔽通信增强
- 100+ 工具

</details>

---

## 🛤️ 路线图

- [ ] **P0: 补充测试覆盖率 (>70%)**
- [ ] **P0: 修复 beacon.py 线程安全问题**
- [ ] **P1: 完善 CI/CD 流水线**
- [ ] Web UI 界面
- [ ] 分布式扫描
- [ ] 更多云平台 (GCP/阿里云)
- [ ] AI 自动化漏洞利用
- [x] Red Team 全套工具
- [x] CVE 情报与 AI PoC
- [x] API/供应链/云安全
- [x] 架构模块化重构

---

## ⚖️ 免责声明

> 本工具仅用于**授权的安全测试与研究**。使用前请取得目标书面授权，遵守当地法律与职业道德。滥用后果自负。

---

## 🤝 联系方式

<div align="center">

[![Discord](https://img.shields.io/badge/Discord-Join-7289DA?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/PtVyrMvB)
[![Email](https://img.shields.io/badge/Email-Contact-EA4335?style=for-the-badge&logo=gmail&logoColor=white)](mailto:Coff0xc@protonmail.com)
[![Issues](https://img.shields.io/badge/Issues-Report-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues)

**Made with ❤️ by [Coff0xc](https://github.com/Coff0xc)**

</div>
