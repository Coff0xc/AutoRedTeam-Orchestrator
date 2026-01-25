<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>AI 驱动的自动化红队编排框架</b><br>
  <i>跨平台 · 74 MCP 工具 · 2000+ Payload · ATT&CK 全覆盖</i>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md">Русский</a> ·
  <a href="README_DE.md">Deutsch</a> ·
  <a href="README_FR.md">Français</a>
</p>

<p align="center">
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/stargazers"><img src="https://img.shields.io/github/stars/Coff0xc/AutoRedTeam-Orchestrator?style=for-the-badge&logo=github&color=gold" alt="Stars"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/network/members"><img src="https://img.shields.io/github/forks/Coff0xc/AutoRedTeam-Orchestrator?style=for-the-badge&logo=github&color=silver" alt="Forks"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues"><img src="https://img.shields.io/github/issues/Coff0xc/AutoRedTeam-Orchestrator?style=for-the-badge&logo=github&color=red" alt="Issues"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/commits/main"><img src="https://img.shields.io/github/last-commit/Coff0xc/AutoRedTeam-Orchestrator?style=for-the-badge&logo=github" alt="Last Commit"></a>
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
  <a href="https://modelcontextprotocol.io/"><img src="https://img.shields.io/badge/MCP-Native-00ADD8?style=for-the-badge&logo=protocol&logoColor=white" alt="MCP"></a>
  <a href="#"><img src="https://img.shields.io/badge/Tools-74-FF6B6B?style=for-the-badge&logo=toolbox&logoColor=white" alt="Tools"></a>
  <a href="#"><img src="https://img.shields.io/badge/Payloads-2000+-orange?style=for-the-badge&logo=artillery&logoColor=white" alt="Payloads"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License"></a>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-加入社区-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-文档-blue?style=for-the-badge&logo=gitbook&logoColor=white" alt="Wiki"></a>
</p>

---

## 📖 目录

- [核心特性](#-核心特性)
- [ATT&CK 覆盖矩阵](#️-attck-覆盖矩阵)
- [快速开始](#-快速开始)
- [MCP 配置](#-mcp-配置)
- [工具矩阵](#️-工具矩阵)
- [使用示例](#-使用示例)
- [架构设计](#-架构设计)
- [更新日志](#-更新日志)
- [路线图](#️-路线图)
- [贡献指南](#-贡献指南)
- [安全策略](#-安全策略)
- [致谢](#-致谢)
- [许可证](#-许可证)

---

## 🎯 核心特性

<table>
<tr>
<td width="50%">

### 🤖 AI 原生设计
- **智能指纹识别** - 自动识别目标技术栈
- **攻击链规划** - AI 驱动的攻击路径推荐
- **历史反馈学习** - 持续优化攻击策略
- **自动 Payload 选择** - 根据 WAF 智能变异
- **AI PoC 生成** - 基于漏洞描述生成利用代码

</td>
<td width="50%">

### ⚡ 全流程自动化
- **10 阶段侦察流程** - DNS/端口/指纹/WAF/JS分析
- **漏洞发现与验证** - 自动化扫描 + OOB 验证
- **智能利用编排** - 反馈循环 + 自动重试
- **一键专业报告** - JSON/HTML/Markdown 多格式
- **会话断点续传** - 支持中断恢复

</td>
</tr>
<tr>
<td width="50%">

### 🔴 Red Team 工具链
- **横向移动** - SMB/SSH/WMI/WinRM/PSExec
- **C2 通信** - Beacon + DNS/HTTP/WebSocket 隧道
- **混淆免杀** - XOR/AES/Base64 多层编码
- **持久化** - Windows 注册表/计划任务/Linux cron
- **凭证获取** - 内存提取/文件搜索
- **AD 攻击** - Kerberoasting/AS-REP Roasting

</td>
<td width="50%">

### 🛡️ 安全能力扩展
- **API 安全** - JWT/CORS/GraphQL/WebSocket/OAuth
- **供应链安全** - SBOM 生成/依赖审计/CI-CD 扫描
- **云原生安全** - K8s 审计/gRPC 测试/AWS 扫描
- **CVE 情报** - NVD/Nuclei/ExploitDB 多源同步
- **WAF 绕过** - 2000+ Payload 智能变异引擎

</td>
</tr>
</table>

---

## ⚔️ ATT&CK 覆盖矩阵

| 战术阶段 | 技术覆盖 | 工具数量 | 状态 |
|----------|----------|----------|------|
| **侦察 (Reconnaissance)** | 主动扫描、被动收集、OSINT | 12+ | ✅ 完整 |
| **资源开发 (Resource Development)** | Payload 生成、混淆编码 | 4+ | ✅ 完整 |
| **初始访问 (Initial Access)** | Web 漏洞利用、CVE 利用 | 19+ | ✅ 完整 |
| **执行 (Execution)** | 命令注入、代码执行 | 5+ | ✅ 完整 |
| **持久化 (Persistence)** | 注册表、计划任务、Webshell | 3+ | ✅ 完整 |
| **权限提升 (Privilege Escalation)** | UAC 绕过、令牌模拟 | 2+ | ⚠️ 部分 |
| **防御规避 (Defense Evasion)** | AMSI 绕过、ETW 绕过、混淆 | 4+ | ✅ 完整 |
| **凭证访问 (Credential Access)** | 内存提取、文件搜索 | 2+ | ✅ 完整 |
| **发现 (Discovery)** | 网络扫描、服务枚举 | 8+ | ✅ 完整 |
| **横向移动 (Lateral Movement)** | SMB/SSH/WMI/WinRM | 6+ | ✅ 完整 |
| **收集 (Collection)** | 数据聚合、敏感文件 | 2+ | ✅ 完整 |
| **命令与控制 (C2)** | HTTP/DNS/WebSocket 隧道 | 4+ | ✅ 完整 |
| **数据渗出 (Exfiltration)** | DNS/HTTP/ICMP 外带 | 3+ | ✅ 完整 |

---

## 📦 快速开始

### 系统要求

| 组件 | 要求 |
|------|------|
| **操作系统** | Windows 10+, Linux (Ubuntu 20.04+), macOS 12+ |
| **Python** | 3.10 或更高版本 |
| **内存** | 建议 4GB+ |
| **网络** | 出站 HTTP/HTTPS 访问 |

### 安装

```bash
# 克隆仓库
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 安装依赖
pip install -r requirements.txt

# 验证安装
python mcp_stdio_server.py --version
```

<details>
<summary><b>🔧 可选：最小化安装</b></summary>

```bash
# 仅核心依赖 (侦察 + 漏洞检测)
pip install -r requirements-core.txt

# 可选模块 (红队 + 云安全)
pip install -r requirements-optional.txt
```

</details>

<details>
<summary><b>🐳 Docker 部署</b></summary>

```bash
docker pull coff0xc/autoredteam:latest
docker run -it --rm coff0xc/autoredteam
```

</details>

### 启动服务

```bash
python mcp_stdio_server.py
```

---

## 🔧 MCP 配置

将以下配置添加到对应 AI 编辑器的 MCP 配置文件中：

<details>
<summary><b>📘 支持MCP的AI编辑器</b></summary>

**通用配置文件位置：**
- Windows: `%APPDATA%\<编辑器名称>\config.json`
- macOS: `~/Library/Application Support/<编辑器名称>/config.json`
- Linux: `~/.config/<编辑器名称>/config.json`

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
<summary><b>📗 Cursor</b></summary>

**配置文件：** `~/.cursor/mcp.json`

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
<summary><b>📙 Windsurf</b></summary>

**配置文件：** `~/.codeium/windsurf/mcp_config.json`

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
<summary><b>📕 Kiro</b></summary>

**配置文件：** `~/.kiro/mcp.json`

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

| 类别 | 数量 | 主要功能 | 关键工具 |
|------|------|----------|----------|
| **🔍 侦察** | 12+ | 信息收集与资产发现 | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` |
| **🐛 漏洞检测** | 19+ | OWASP Top 10 + 逻辑漏洞 | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` |
| **🌐 Web 扫描** | 4+ | 攻击面发现与漏洞编排 | `vuln_scan` `security_headers_scan` `cors_scan` `idor_scan` |
| **🔐 API 安全** | 11+ | 现代 API 安全测试 | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` |
| **📦 供应链** | 5+ | 依赖与构建安全 | `sbom_generate` `dependency_audit` `cicd_scan` |
| **☁️ 云原生** | 8+ | 容器与集群安全 | `k8s_scan` `grpc_scan` `aws_scan` |
| **🔴 红队** | 10+ | 后渗透与内网 | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` |
| **📋 CVE** | 6+ | 漏洞情报与利用 | `cve_search` `cve_sync` `poc_execute` |
| **🤖 自动化** | 5+ | 全自动渗透测试 | `auto_pentest` `smart_analyze` `attack_chain_plan` `waf_bypass` |

---

## 💬 使用示例

在 AI 编辑器中直接对话调用：

### 侦察与信息收集
```
🔍 "对 example.com 进行完整侦察并生成报告"
🔍 "扫描 192.168.1.0/24 网段的开放端口"
🔍 "枚举 example.com 的子域名"
🔍 "识别目标网站的技术栈和 WAF"
```

### 漏洞扫描与利用
```
🎯 "检测目标是否存在 SQL 注入漏洞"
🎯 "对目标 API 进行完整的安全扫描"
🎯 "搜索 Log4j 相关的 CVE 并执行 PoC"
🎯 "生成绕过 WAF 的 XSS Payload"
```

### 红队操作
```
🔴 "通过 SMB 在目标机器上执行命令"
🔴 "启动 C2 Beacon 连接到服务器"
🔴 "搜索目标系统中的敏感凭证"
🔴 "生成 AMSI 绕过代码"
```

### 自动化渗透
```
⚡ "对 https://target.com 执行全自动渗透测试"
⚡ "分析目标并生成攻击链建议"
⚡ "恢复之前中断的渗透测试会话"
```

---

## 🏗️ 架构设计

```
AutoRedTeam-Orchestrator/
├── 📄 mcp_stdio_server.py      # MCP 服务器入口 (74 工具注册)
│
├── 📂 handlers/                # MCP 工具处理器 (统一输出 Schema)
│   ├── recon.py               # 侦察工具
│   ├── detector.py            # 漏洞检测
│   └── redteam.py             # 红队工具
│
├── 📂 core/                    # 核心引擎
│   ├── recon/                 # 侦察引擎 (10 阶段流程)
│   │   ├── engine.py          # StandardReconEngine
│   │   ├── port_scanner.py    # 端口扫描
│   │   ├── subdomain.py       # 子域名枚举
│   │   └── fingerprint.py     # 指纹识别
│   ├── detectors/             # 漏洞检测器
│   │   ├── injection/         # 注入类 (SQLi/XSS/RCE/SSTI)
│   │   └── access/            # 访问控制 (SSRF/IDOR/路径遍历)
│   ├── exploit/               # 漏洞利用引擎
│   ├── c2/                    # C2 通信框架
│   ├── lateral/               # 横向移动 (SMB/SSH/WMI)
│   ├── evasion/               # 免杀与绕过
│   ├── persistence/           # 持久化模块
│   ├── credential/            # 凭证获取
│   └── cve/                   # CVE 情报管理
│
├── 📂 modules/                 # 功能模块
│   ├── api_security/          # API 安全测试
│   ├── cloud_security/        # 云安全审计
│   ├── supply_chain/          # 供应链安全
│   └── smart_payload_engine.py # 智能 Payload 引擎
│
├── 📂 wordlists/               # 内置字典库
│   ├── directories/           # 目录爆破
│   ├── passwords/             # 密码字典
│   └── subdomains/            # 子域名字典
│
└── 📂 utils/                   # 工具函数
    ├── http_client.py         # HTTP 客户端
    ├── report_generator.py    # 报告生成
    └── validators.py          # 输入验证
```

---

## 📋 更新日志

### v3.0.0 (2026-01-18) - 架构增强

- 🚀 **工具扩展**: MCP 工具数量达到 74 个
- 🔄 **反馈循环**: 新增智能利用编排器，失败自动调整重试
- 🛡️ **WAF 绕过**: 增强 Payload 变异引擎，支持 30+ 编码方式
- 📊 **报告优化**: 新增执行摘要与风险评分

### v2.8.0 (2026-01-15) - 安全加固

- 🔒 **输入验证**: 增强所有用户输入的安全检查
- ⚙️ **异常处理**: 统一异常体系，提升稳定性
- 🚄 **性能优化**: 改进并发控制与资源管理

<details>
<summary><b>查看更多版本</b></summary>

### v2.7.1 (2026-01-10) - Web 扫描引擎
- Web Scanner 模块：攻面发现与注入点建模
- 内置字典库：目录/密码/用户名/子域名

### v2.7.0 (2026-01-09) - 架构重构
- 模块化重构：12 个独立工具模块
- 侦察引擎：StandardReconEngine (10 阶段)
- 代码精简：删除 4,351 行冗余代码

### v2.6.0 (2026-01-07) - API/供应链/云安全
- JWT/CORS/GraphQL/WebSocket 安全测试
- SBOM 生成 (CycloneDX/SPDX)
- K8s/gRPC 安全审计

</details>

---

## 🛤️ 路线图

- [ ] 🖥️ Web UI 管理界面
- [ ] 🌐 分布式扫描集群
- [ ] ☁️ 更多云平台支持 (GCP/阿里云/腾讯云)
- [ ] 🤖 AI 自动化漏洞利用增强
- [ ] 📚 更多 CVE PoC 模板
- [ ] 🔌 Burp Suite 插件集成
- [x] ✅ Red Team 全套工具链
- [x] ✅ CVE 情报与 AI PoC 生成
- [x] ✅ API/供应链/云安全模块
- [x] ✅ 全自动渗透测试框架

---

## 🤝 贡献指南

我们欢迎所有形式的贡献！

1. **Fork** 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 **Pull Request**

详见 [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 🔒 安全策略

- 🚨 **负责任的披露**: 发现安全漏洞请通过 [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com) 联系
- ⚠️ **授权使用**: 本工具仅用于已授权的安全测试与研究
- 📜 **合规声明**: 使用前请确保遵守当地法律法规

详见 [SECURITY.md](SECURITY.md)

---

## 🙏 致谢

感谢以下开源项目的启发与参考：

- [Nuclei](https://github.com/projectdiscovery/nuclei) - 漏洞扫描引擎设计
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - SQL 注入检测思路
- [Impacket](https://github.com/fortra/impacket) - 网络协议实现
- [MCP Protocol](https://modelcontextprotocol.io/) - AI 工具协议标准

---

## 📜 许可证

本项目采用 **MIT 许可证** - 详见 [LICENSE](LICENSE) 文件

---

## ⚖️ 免责声明

> **警告**: 本工具仅用于**授权的安全测试与研究**。
>
> 在使用本工具对任何系统进行测试前，请确保：
> - 已获得目标系统所有者的**书面授权**
> - 遵守当地的**法律法规**
> - 符合**职业道德**标准
>
> 未经授权使用本工具可能违反法律。**开发者不对任何滥用行为承担责任**。

---

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Coff0xc">Coff0xc</a></b>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-加入社区-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="mailto:Coff0xc@protonmail.com"><img src="https://img.shields.io/badge/Email-联系作者-EA4335?style=for-the-badge&logo=gmail&logoColor=white" alt="Email"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues"><img src="https://img.shields.io/badge/Issues-问题反馈-181717?style=for-the-badge&logo=github&logoColor=white" alt="Issues"></a>
</p>
