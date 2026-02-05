<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>AI 驱动的自动化红队编排框架</b><br>
  <sub>跨平台 | 101 MCP 工具 | 2000+ Payload | ATT&CK 全覆盖 | 知识图谱增强</sub>
</p>

<p align="center">
  <a href="README.md"><b>简体中文</b></a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md">Русский</a> ·
  <a href="README_DE.md">Deutsch</a> ·
  <a href="README_FR.md">Français</a>
</p>

<p align="center">
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/stargazers"><img src="https://img.shields.io/github/stars/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=gold" alt="Stars"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/network/members"><img src="https://img.shields.io/github/forks/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=silver" alt="Forks"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues"><img src="https://img.shields.io/github/issues/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=red" alt="Issues"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/commits/main"><img src="https://img.shields.io/github/last-commit/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github" alt="Last Commit"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.0.2-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/MCP-Native-00ADD8?style=flat-square" alt="MCP">
  <img src="https://img.shields.io/badge/Tools-101-FF6B6B?style=flat-square" alt="Tools">
  <img src="https://img.shields.io/badge/Tests-1461-4CAF50?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-社区-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-文档-blue?style=flat-square&logo=gitbook&logoColor=white" alt="Wiki"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/actions"><img src="https://img.shields.io/github/actions/workflow/status/Coff0xc/AutoRedTeam-Orchestrator/ci.yml?style=flat-square&logo=github-actions&logoColor=white&label=CI" alt="CI"></a>
</p>

---

## 项目亮点

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     AutoRedTeam-Orchestrator v3.0.2                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  ● 101 MCP 工具       ● 2000+ Payload      ● 1461 测试用例                │
│  ● 10 阶段侦察        ● 19 漏洞检测器       ● 5 协议横向移动               │
│  ● MCTS 攻击规划      ● 知识图谱            ● AI PoC 生成                  │
│  ● OOB 误报过滤       ● 依赖注入容器        ● MCP 安全中间件               │
├─────────────────────────────────────────────────────────────────────────────┤
│  支持 AI 编辑器: Cursor | Windsurf | Kiro | Claude Desktop | VS Code      │
│                  | OpenCode | Claude Code                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [设计理念](#设计理念)
- [技术架构](#技术架构)
- [ATT&CK 覆盖矩阵](#attck-覆盖矩阵)
- [快速开始](#快速开始)
  - [系统要求](#系统要求)
  - [安装方式](#安装方式)
  - [验证安装](#验证安装)
- [MCP 配置](#mcp-配置)
- [工具矩阵](#工具矩阵-100-mcp-工具)
- [核心模块详解](#核心模块详解)
- [外部工具集成](#外部工具集成)
- [使用示例](#使用示例)
  - [命令行使用](#命令行使用)
  - [Python API 调用](#python-api-调用)
- [配置说明](#配置说明)
- [性能调优](#性能调优)
- [故障排查](#故障排查)
- [常见问题 (FAQ)](#常见问题-faq)
- [开发指南](#开发指南)
- [更新日志](#更新日志)
- [路线图](#路线图)
- [贡献指南](#贡献指南)
- [安全策略](#安全策略)
- [致谢](#致谢)
- [许可证](#许可证)
- [免责声明](#免责声明)

---

## 项目简介

**AutoRedTeam-Orchestrator** 是一个基于 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 的 AI 驱动自动化渗透测试框架。它将 101 个安全工具封装为 MCP 工具，可与支持 MCP 的 AI 编辑器 (Cursor, Windsurf, Kiro, Claude Desktop, OpenCode, Claude Code) 无缝集成，实现自然语言驱动的自动化安全测试。

### 为什么选择 AutoRedTeam-Orchestrator？

| 特性 | 传统工具 | AutoRedTeam |
|------|----------|-------------|
| **交互方式** | 命令行记忆 | 自然语言对话 |
| **学习成本** | 高 (需记忆大量参数) | 低 (AI 自动选择工具) |
| **工具整合** | 手动切换工具 | 101 工具统一接口 |
| **攻击链规划** | 人工规划 | **MCTS 算法 + 知识图谱** |
| **误报过滤** | 人工验证 | **OOB + 统计学验证** |
| **报告生成** | 手动编写 | 一键生成专业报告 |
| **会话管理** | 无 | 支持断点续传 |
| **安全性** | 各工具独立 | **MCP 安全中间件统一防护** |

### 与同类项目对比

| 特性 | AutoRedTeam | Nuclei | SQLMap | Metasploit |
|------|-------------|--------|--------|------------|
| AI 原生 | ✅ | ❌ | ❌ | ❌ |
| MCP 协议 | ✅ | ❌ | ❌ | ❌ |
| 自然语言交互 | ✅ | ❌ | ❌ | ❌ |
| MCTS 攻击规划 | ✅ | ❌ | ❌ | ❌ |
| 知识图谱 | ✅ | ❌ | ❌ | ❌ |
| 全链路自动化 | ✅ | 部分 | 部分 | 部分 |
| 误报过滤 | 多方法验证 | 基础 | 中等 | 基础 |

---

## 核心特性

<table>
<tr>
<td width="50%">

### AI 原生设计

- **智能指纹识别** - 自动识别目标技术栈 (CMS/框架/WAF)
- **MCTS 攻击规划** - 蒙特卡洛树搜索驱动的最优攻击路径
- **知识图谱** - 持久化攻击知识，支持跨会话学习
- **历史反馈学习** - 基于历史结果持续优化攻击策略
- **自动 Payload 选择** - 根据 WAF 类型智能选择/变异 Payload
- **AI PoC 生成** - 基于 CVE 描述自动生成漏洞利用代码

</td>
<td width="50%">

### 全流程自动化

- **10 阶段侦察流程** - DNS/端口/指纹/WAF/子域名/目录/JS分析
- **漏洞发现与验证** - 自动化扫描 + **多方法验证减少误报**
- **智能利用编排** - 反馈循环引擎 + 失败自动重试
- **一键专业报告** - JSON/HTML/Markdown 多格式输出
- **会话断点续传** - 支持中断恢复，不丢失扫描进度

</td>
</tr>
<tr>
<td width="50%">

### Red Team 工具链

- **横向移动** - SMB/SSH/WMI/WinRM/PSExec 5种协议
- **C2 通信** - Beacon + DNS/HTTP/WebSocket/ICMP 隧道
- **混淆免杀** - XOR/AES/Base64/自定义编码器
- **持久化** - Windows 注册表/计划任务/WMI/Linux cron/Webshell
- **凭证获取** - 内存提取/文件搜索/密码喷洒
- **AD 攻击** - Kerberoasting/AS-REP Roasting/SPN 扫描

</td>
<td width="50%">

### 安全能力扩展

- **API 安全** - JWT/CORS/GraphQL/WebSocket/OAuth 测试
- **供应链安全** - SBOM 生成/依赖审计/CI-CD 安全扫描
- **云原生安全** - K8s RBAC/Pod 安全/gRPC/AWS 配置审计
- **CVE 情报** - NVD/Nuclei/ExploitDB 多源同步
- **WAF 绕过** - 2000+ Payload + 30+ 编码方式智能变异

</td>
</tr>
</table>

---

## 设计理念

### 核心设计思想

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           设计哲学                                         │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│   1. AI 原生 (AI-Native)                                                   │
│      └─ 不是"AI 套壳"，而是从架构层面为 AI 设计                           │
│         └─ MCP 协议原生支持                                               │
│         └─ 自然语言驱动的工具选择                                         │
│         └─ MCTS 算法驱动的攻击规划                                        │
│                                                                            │
│   2. 可验证安全 (Verifiable Security)                                     │
│      └─ 多方法交叉验证降低误报                                            │
│         └─ 统计学验证 (差异显著性检验)                                    │
│         └─ 布尔盲注验证 (True/False 响应对比)                             │
│         └─ 时间盲注验证 (延迟检测)                                        │
│         └─ OOB 带外验证 (DNS/HTTP 回调)                                   │
│                                                                            │
│   3. 知识持久化 (Knowledge Persistence)                                   │
│      └─ 攻击知识不仅在会话内，更跨会话累积                                │
│         └─ 知识图谱存储目标、漏洞、凭证关系                               │
│         └─ 攻击路径成功率基于历史计算                                     │
│         └─ 相似目标识别加速新目标测试                                     │
│                                                                            │
│   4. 安全即设计 (Security by Design)                                      │
│      └─ 安全不是附加功能，是核心架构                                      │
│         └─ MCP 安全中间件：输入验证、速率限制、授权控制                   │
│         └─ TOCTOU 安全：原子操作、竞态防护                                │
│         └─ 内存安全：资源上限、自动清理                                   │
│                                                                            │
│   5. 可扩展架构 (Extensible Architecture)                                 │
│      └─ 依赖注入容器支持灵活的服务组合                                    │
│         └─ 模块化 Handler 设计                                            │
│         └─ 外部工具 YAML 配置化集成                                       │
│         └─ 检测器组合模式支持任意组合                                     │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### 技术决策说明

| 决策 | 选项 | 选择 | 理由 |
|------|------|------|------|
| **通信协议** | REST / gRPC / MCP | MCP | AI 编辑器原生支持，自然语言交互无缝 |
| **攻击规划** | 规则引擎 / MCTS / 强化学习 | MCTS | 在线规划，无需预训练，UCB1 平衡探索与利用 |
| **知识存储** | SQL / 图数据库 / 内存 | 内存图 + 可选 Neo4j | 零依赖启动，高性能查询，可选持久化 |
| **依赖管理** | 全局变量 / 依赖注入 | DI 容器 | 可测试性、可替换性、生命周期管理 |
| **并发模型** | 多线程 / asyncio / 混合 | asyncio 为主 | IO 密集型场景最优，Python 原生支持 |
| **哈希算法** | MD5 / SHA256 | SHA256 | 安全性更高，符合现代标准 |

---

## 技术架构

### 高层架构图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AI 编辑器层                                    │
│        Cursor  │  Windsurf  │  Kiro  │  Claude Desktop  │  VS Code         │
│        OpenCode │  Claude Code                                             │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ MCP Protocol (JSON-RPC over stdio)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MCP 服务器入口                                      │
│                      mcp_stdio_server.py                                   │
│                        (101 工具注册)                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                        MCP 安全中间件                                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│  │ 输入验证器  │  │ 速率限制器  │  │ 操作授权器  │  │ 安全装饰器  │       │
│  │ InputValid  │  │ RateLimiter │  │ OpAuthorize │  │ @secure_tool│       │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│   handlers/       │   │   core/           │   │   modules/        │
│   MCP 工具处理器  │   │   核心引擎        │   │   功能模块        │
├───────────────────┤   ├───────────────────┤   ├───────────────────┤
│ • recon_handlers  │   │ • recon/          │   │ • api_security/   │
│ • detector_hdlrs  │   │   10阶段侦察      │   │   JWT/CORS/GQL    │
│ • cve_handlers    │   │ • detectors/      │   │ • supply_chain/   │
│ • redteam_hdlrs   │   │   漏洞检测器      │   │   SBOM/依赖       │
│ • lateral_hdlrs   │   │ • mcts_planner    │   │ • cloud_security/ │
│ • external_hdlrs  │   │   MCTS攻击规划    │   │   K8s/gRPC/AWS    │
│ • ai_handlers     │   │ • knowledge/      │   │ • payload/        │
│ • session_hdlrs   │   │   知识图谱        │   │   2000+ Payload   │
└───────────────────┘   │ • container       │   └───────────────────┘
                        │   依赖注入        │
                        │ • c2/             │
                        │   C2 通信         │
                        │ • lateral/        │
                        │   横向移动        │
                        │ • cve/            │
                        │   CVE情报+PoC     │
                        └───────────────────┘
```

### 核心组件依赖图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            组件依赖关系                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   MCPSecurityMiddleware ──────┬──────────────────────────────────────────┐ │
│          │                    │                                          │ │
│          ▼                    ▼                                          │ │
│   ┌─────────────┐     ┌─────────────┐                                    │ │
│   │InputValidator│    │RateLimiter  │                                    │ │
│   │             │     │             │                                    │ │
│   │• 目标验证   │     │• 滑动窗口   │                                    │ │
│   │• 端口验证   │     │• 令牌桶     │                                    │ │
│   │• 路径验证   │     │• 突发限制   │                                    │ │
│   │• SSRF检测   │     │• 内存淘汰   │                                    │ │
│   └─────────────┘     └─────────────┘                                    │ │
│                                                                          │ │
│   Container (DI) ───────────────────────────────────────────────────────│ │
│          │                                                               │ │
│          ├── Singleton: KnowledgeManager                                │ │
│          ├── Singleton: MCTSPlanner                                     │ │
│          ├── Singleton: AdvancedVerifier                                │ │
│          ├── Scoped:    SessionManager                                  │ │
│          └── Transient: Detectors                                       │ │
│                                                                          │ │
│   MCTSPlanner ──────────────────────────────────────────────────────────│ │
│          │                                                               │ │
│          ├── ActionGenerator (动作生成)                                 │ │
│          ├── AttackSimulator (攻击模拟)                                 │ │
│          └── UCB1 算法 (探索-利用平衡)                                  │ │
│                                                                          │ │
│   KnowledgeManager ─────────────────────────────────────────────────────│ │
│          │                                                               │ │
│          ├── InMemoryGraphStore (图存储)                                │ │
│          ├── 实体: Target, Service, Vulnerability, Credential          │ │
│          ├── 关系: HOSTS, HAS_VULNERABILITY, OBTAINED_FROM             │ │
│          └── BFS 多路径发现                                             │ │
│                                                                          │ │
│   AdvancedVerifier ─────────────────────────────────────────────────────│ │
│          │                                                               │ │
│          ├── statistical_confirm (统计学验证)                           │ │
│          ├── boolean_blind_confirm (布尔盲注)                           │ │
│          ├── time_based_confirm (时间盲注)                              │ │
│          ├── oob_verify (OOB 验证)                                      │ │
│          └── multi_method_verify (多方法聚合)                           │ │
│                                                                          │ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 目录结构

```
AutoRedTeam-Orchestrator/
├── mcp_stdio_server.py          # MCP 服务器入口 (101 工具注册)
├── VERSION                      # 版本号文件
├── pyproject.toml               # 项目配置
├── requirements.txt             # 生产依赖
├── requirements-dev.txt         # 开发依赖
│
├── handlers/                    # MCP 工具处理器 (16 模块)
│   ├── recon_handlers.py        # 侦察工具 (8)
│   ├── detector_handlers.py     # 漏洞检测工具 (11)
│   ├── api_security_handlers.py # API安全工具 (7)
│   ├── supply_chain_handlers.py # 供应链安全工具 (3)
│   ├── cloud_security_handlers.py # 云安全工具 (3)
│   ├── cve_handlers.py          # CVE工具 (8)
│   ├── redteam_handlers.py      # 红队核心工具 (14)
│   ├── lateral_handlers.py      # 横向移动工具 (9)
│   ├── persistence_handlers.py  # 持久化工具 (3)
│   ├── ad_handlers.py           # AD攻击工具 (3)
│   ├── orchestration_handlers.py # 编排工具 (11)
│   ├── external_tools_handlers.py # 外部工具 (8)
│   ├── ai_handlers.py           # AI辅助工具 (3)
│   ├── session_handlers.py      # 会话工具 (4)
│   ├── report_handlers.py       # 报告工具 (2)
│   └── misc_handlers.py         # 杂项工具 (3)
│
├── core/                        # 核心引擎
│   ├── __init__.py              # 版本定义
│   │
│   ├── security/                # 安全组件 ⭐ v3.0.2 新增
│   │   └── mcp_security.py      # MCP 安全中间件
│   │
│   ├── container.py             # 依赖注入容器 ⭐ v3.0.2 新增
│   │
│   ├── mcts_planner.py          # MCTS 攻击规划器 ⭐ v3.0.2 新增
│   │
│   ├── knowledge/               # 知识图谱 ⭐ v3.0.2 新增
│   │   ├── __init__.py
│   │   ├── manager.py           # 知识管理器
│   │   └── models.py            # 数据模型
│   │
│   ├── recon/                   # 侦察引擎 (10 阶段 pipeline)
│   │   ├── engine.py            # StandardReconEngine
│   │   ├── phases.py            # 阶段定义与执行
│   │   ├── port_scanner.py      # 端口扫描
│   │   ├── subdomain.py         # 子域名枚举
│   │   ├── fingerprint.py       # 指纹识别
│   │   ├── waf_detect.py        # WAF 检测
│   │   └── directory.py         # 目录扫描
│   │
│   ├── detectors/               # 漏洞检测器
│   │   ├── base.py              # 基类 + 组合模式
│   │   ├── sqli.py              # SQL 注入
│   │   ├── xss.py               # XSS
│   │   ├── ssrf.py              # SSRF
│   │   ├── advanced_verifier.py # 高级验证器 ⭐ v3.0.2 增强
│   │   └── false_positive_filter.py # 误报过滤
│   │
│   ├── cve/                     # CVE 情报
│   │   ├── manager.py           # CVE 数据库管理
│   │   ├── poc_engine.py        # PoC 模板引擎
│   │   ├── auto_exploit.py      # 自动利用
│   │   ├── ai_poc_generator.py  # AI PoC 生成
│   │   └── update_manager.py    # 多源同步
│   │
│   ├── c2/                      # C2 通信框架
│   │   ├── beacon.py            # Beacon 实现
│   │   ├── protocol.py          # 协议定义
│   │   └── tunnels/             # DNS/HTTP/WS/ICMP 隧道
│   │
│   ├── lateral/                 # 横向移动
│   │   ├── smb.py               # SMB (PTH/PTT)
│   │   ├── ssh.py               # SSH + SFTP
│   │   ├── wmi.py               # WMI
│   │   ├── winrm.py             # WinRM
│   │   └── psexec.py            # PSExec
│   │
│   ├── evasion/                 # 免杀与混淆
│   │   └── payload_obfuscator.py
│   │
│   ├── persistence/             # 持久化
│   │   ├── windows_persistence.py
│   │   ├── linux_persistence.py
│   │   └── webshell_manager.py
│   │
│   ├── credential/              # 凭证获取
│   ├── ad/                      # AD 攻击
│   ├── session/                 # 会话管理
│   ├── tools/                   # 外部工具管理
│   └── exfiltration/            # 数据渗出
│
├── modules/                     # 功能模块
│   ├── api_security/            # API 安全
│   │   ├── jwt_security.py
│   │   ├── cors_security.py
│   │   ├── graphql_security.py
│   │   └── websocket_security.py
│   │
│   ├── supply_chain/            # 供应链安全
│   │   ├── sbom_generator.py
│   │   ├── dependency_scanner.py
│   │   └── cicd_security.py
│   │
│   ├── cloud_security/          # 云安全
│   │   ├── kubernetes_enhanced.py
│   │   └── aws_tools.py
│   │
│   └── payload/                 # Payload 引擎
│       ├── library.py           # 2000+ Payload
│       └── smart.py             # 智能选择
│
├── utils/                       # 工具函数
│   ├── logger.py                # 日志
│   ├── http_client.py           # HTTP 客户端
│   ├── validators.py            # 输入验证
│   ├── report_generator.py      # 报告生成
│   └── config.py                # 配置管理
│
├── wordlists/                   # 内置字典
│   ├── directories/             # 目录字典
│   ├── passwords/               # 密码字典
│   ├── usernames/               # 用户名字典
│   └── subdomains/              # 子域名字典
│
├── config/                      # 配置文件
│   └── external_tools.yaml      # 外部工具配置
│
├── tests/                       # 测试套件 (1461 测试用例)
│   ├── test_mcp_security.py     # MCP 安全测试 (62)
│   ├── test_container.py        # DI 容器测试 (39)
│   ├── test_mcts_planner.py     # MCTS 测试 (57)
│   ├── test_advanced_verifier.py # 验证器测试 (43)
│   ├── test_knowledge_manager.py # 知识图谱测试 (90)
│   └── ...
│
├── poc-templates/               # PoC 模板
├── templates/                   # 报告模板
└── scripts/                     # 工具脚本
```

---

## ATT&CK 覆盖矩阵

| 战术阶段 | 技术覆盖 | 工具数量 | 状态 |
|----------|----------|----------|------|
| 侦察 (Reconnaissance) | 主动扫描、被动收集、OSINT、JS分析 | 12+ | ✅ |
| 资源开发 (Resource Development) | Payload 生成、混淆编码、PoC生成 | 4+ | ✅ |
| 初始访问 (Initial Access) | Web 漏洞利用、CVE 利用、API 漏洞 | 19+ | ✅ |
| 执行 (Execution) | 命令注入、代码执行、反序列化 | 5+ | ✅ |
| 持久化 (Persistence) | 注册表、计划任务、Webshell、WMI | 3+ | ✅ |
| 权限提升 (Privilege Escalation) | UAC 绕过、令牌模拟、内核漏洞 | 2+ | ⚠️ |
| 防御规避 (Defense Evasion) | AMSI 绕过、ETW 绕过、混淆、流量变异 | 4+ | ✅ |
| 凭证访问 (Credential Access) | 内存提取、文件搜索、密码喷洒 | 2+ | ✅ |
| 发现 (Discovery) | 网络扫描、服务枚举、AD 枚举 | 8+ | ✅ |
| 横向移动 (Lateral Movement) | SMB/SSH/WMI/WinRM/PSExec | 9+ | ✅ |
| 收集 (Collection) | 数据聚合、敏感文件搜索 | 2+ | ✅ |
| 命令与控制 (C2) | HTTP/DNS/WebSocket/ICMP 隧道 | 4+ | ✅ |
| 数据渗出 (Exfiltration) | DNS/HTTP/ICMP/SMB + AES加密 | 4+ | ✅ |

---

## 快速开始

### 系统要求

| 组件 | 最低要求 | 推荐配置 |
|------|---------|----------|
| 操作系统 | Windows 10, Ubuntu 20.04, macOS 12 | Windows 11, Ubuntu 22.04, macOS 14 |
| Python | 3.10 | 3.11 或 3.12 |
| 内存 | 4GB | 8GB+ |
| 磁盘空间 | 500MB | 2GB+ (含 CVE 数据库) |
| 网络 | 可访问互联网 | 低延迟网络 |

### 安装方式

#### 方式一：标准安装 (推荐)

```bash
# 1. 克隆仓库
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. 创建虚拟环境 (推荐)
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 3. 安装依赖
pip install -r requirements.txt

# 4. 复制环境变量模板
cp .env.example .env
# 编辑 .env 填入你的 API 密钥

# 5. 启动服务
python mcp_stdio_server.py
```

#### 方式二：最小安装 (仅核心功能)

```bash
# 仅安装核心依赖 (侦察 + 漏洞检测)
pip install -r requirements-core.txt
```

#### 方式三：Docker 部署

```bash
docker pull ghcr.io/coff0xc/autoredteam:latest
docker run -it --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  ghcr.io/coff0xc/autoredteam
```

#### 方式四：开发环境

```bash
# 安装开发依赖 (测试、格式化、lint)
pip install -r requirements-dev.txt

# 安装 pre-commit 钩子
pre-commit install

# 运行测试
pytest tests/ -v
```

### 验证安装

```bash
# 检查版本
python mcp_stdio_server.py --version
# 输出: AutoRedTeam-Orchestrator v3.0.2

# 运行自检
python -c "from core import __version__; print(f'Core version: {__version__}')"

# 运行核心模块测试
pytest tests/test_mcp_security.py tests/test_container.py tests/test_mcts_planner.py tests/test_knowledge_manager.py tests/test_advanced_verifier.py -v
# 预期: 291+ passed
```

---

## MCP 配置

将以下配置添加到 AI 编辑器的 MCP 配置文件中：

### 配置文件位置

| 编辑器 | 配置文件路径 |
|--------|-------------|
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Kiro | `~/.kiro/mcp.json` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| VS Code (MCP 扩展) | `.vscode/mcp.json` |
| OpenCode | `~/.config/opencode/mcp.json` 或 `~/.opencode/mcp.json` |
| Claude Code | `~/.claude/mcp.json` |

### 配置示例

<details>
<summary><b>Cursor</b> - <code>~/.cursor/mcp.json</code></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/absolute/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Windsurf</b> - <code>~/.codeium/windsurf/mcp_config.json</code></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/absolute/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONPATH": "/absolute/path/to/AutoRedTeam-Orchestrator"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Kiro</b> - <code>~/.kiro/mcp.json</code></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/absolute/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"]
    }
  }
}
```

</details>

<details>
<summary><b>Claude Desktop</b></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/absolute/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

<details>
<summary><b>OpenCode</b> - <code>~/.config/opencode/mcp.json</code></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/absolute/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Claude Code</b> - <code>~/.claude/mcp.json</code></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/absolute/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Windows 路径示例</b></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["C:\\Users\\YourName\\AutoRedTeam-Orchestrator\\mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

---

## 工具矩阵 (101 MCP 工具)

| 类别 | 数量 | 关键工具 | 描述 |
|------|------|----------|------|
| **侦察** | 8 | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` `dir_scan` `dns_lookup` `tech_detect` | 信息收集与资产发现 |
| **漏洞检测** | 11 | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` `idor_scan` `path_traversal_scan` `cors_scan` `security_headers_scan` | OWASP Top 10 + 逻辑漏洞 |
| **API 安全** | 7 | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` `cors_deep_scan` `security_headers_score` | 现代 API 安全测试 |
| **供应链** | 3 | `sbom_generate` `dependency_audit` `cicd_scan` | SBOM/依赖/CI-CD 安全 |
| **云原生** | 3 | `k8s_scan` `grpc_scan` `aws_scan` | K8s/gRPC/AWS 安全审计 |
| **红队核心** | 14 | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` `payload_obfuscate` | 后渗透与内网 |
| **横向移动** | 9 | `lateral_ssh` `lateral_wmi` `lateral_winrm` `lateral_psexec` `lateral_ssh_tunnel` | 5种协议横向 |
| **持久化** | 3 | `persistence_windows` `persistence_linux` `persistence_webshell` | Windows/Linux/Web |
| **AD 攻击** | 3 | `ad_enumerate` `ad_kerberos_attack` `ad_spn_scan` | 域渗透全套 |
| **CVE** | 8 | `cve_search` `cve_sync` `cve_stats` `poc_execute` `poc_list` `cve_auto_exploit` `cve_exploit_with_desc` `cve_generate_poc` | CVE 情报 + AI PoC |
| **编排** | 11 | `auto_pentest` `pentest_resume` `pentest_status` `pentest_phase` `smart_analyze` `attack_chain_plan` | 自动化渗透 |
| **外部工具** | 8 | `ext_nmap_scan` `ext_nuclei_scan` `ext_sqlmap_scan` `ext_ffuf_fuzz` `ext_masscan_scan` `ext_tool_chain` `ext_tools_status` | 专业工具集成 |
| **AI 辅助** | 3 | `smart_payload` `ai_attack_chain` `smart_pentest` | 智能分析与决策 |
| **会话/报告** | 9 | `session_create` `session_status` `session_list` `session_complete` `generate_report` `export_findings` | 会话管理 + 报告 |

---

## 核心模块详解

### 1. MCP 安全中间件 (v3.0.2 新增)

**位置**: `core/security/mcp_security.py`

提供统一的安全防护层，所有 MCP 工具调用都经过此中间件：

```python
# 使用示例
from core.security.mcp_security import MCPSecurityMiddleware, RateLimitConfig

security = MCPSecurityMiddleware(
    rate_limit_config=RateLimitConfig(
        requests_per_minute=60,
        burst_limit=10,
    ),
    max_risk=RiskLevel.HIGH,
)

# 验证目标
result = security.validate_target("192.168.1.1")
if not result.valid:
    print(f"拒绝: {result.errors}")

# 装饰器方式保护工具
@security.secure_tool(operation="port_scan", rate_limit_key="scan")
async def port_scan(target: str):
    # ...
```

**核心功能**:
- **输入验证**: IP/域名/URL/CIDR/端口/路径验证，SSRF 检测
- **速率限制**: 滑动窗口 + 令牌桶，防止资源耗尽
- **操作授权**: 基于风险等级的操作控制
- **内存保护**: 自动清理过期数据，防止内存泄漏

### 2. MCTS 攻击规划器 (v3.0.2 新增)

**位置**: `core/mcts_planner.py`

使用蒙特卡洛树搜索算法规划最优攻击路径：

```python
from core.mcts_planner import MCTSPlanner, AttackState

planner = MCTSPlanner(exploration_weight=1.414, max_depth=10)

state = AttackState(
    target="192.168.1.100",
    target_type="linux_server",
    open_ports={22: "ssh", 80: "http"},
)

result = planner.plan(state, iterations=1000)
print(f"推荐动作: {result['recommended_actions']}")
# 输出: [Action(type=VULN_SCAN, target_port=80, confidence=0.85), ...]
```

**核心功能**:
- **UCB1 算法**: 平衡探索与利用
- **动作生成**: 根据状态智能生成可用动作
- **攻击模拟**: 模拟攻击执行预估成功率
- **路径提取**: 提取最优攻击路径序列

### 3. 知识图谱 (v3.0.2 新增)

**位置**: `core/knowledge/`

持久化存储攻击知识，支持跨会话学习：

```python
from core.knowledge import KnowledgeManager

km = KnowledgeManager()

# 存储目标
target_id = km.store_target("192.168.1.100", "linux_server")

# 存储服务
service_id = km.store_service(target_id, "nginx", 80)

# 存储漏洞
vuln_id = km.store_vulnerability(service_id, "CVE-2021-44228", "critical")

# 查找攻击路径
paths = km.get_attack_paths(target_id, credential_id)
for path in paths:
    print(f"成功率: {path.success_rate:.2%}")

# 查找相似目标
similar = km.find_similar_targets("192.168.1.100")
```

**核心功能**:
- **实体存储**: Target, Service, Vulnerability, Credential
- **关系建模**: HOSTS, HAS_VULNERABILITY, OBTAINED_FROM
- **BFS 路径发现**: 多路径发现支持
- **相似度匹配**: 同子网/同域名识别

### 4. 高级验证器 (v3.0.2 增强)

**位置**: `core/detectors/advanced_verifier.py`

多方法交叉验证降低误报率：

```python
from core.detectors.advanced_verifier import AdvancedVerifier

verifier = AdvancedVerifier(callback_server="oob.example.com")

# 多方法验证
results = verifier.multi_method_verify(
    url="http://target.com/api?id=1",
    vuln_type="sqli",
    request_func=make_request,
    methods=["statistical", "boolean_blind", "time_based"],
)

# 聚合结果
aggregated = verifier.aggregate_results(results)
print(f"状态: {aggregated.status}, 置信度: {aggregated.confidence:.2%}")
```

**验证方法**:
- **统计学验证**: 多次采样计算响应差异显著性
- **布尔盲注验证**: True/False 条件对比
- **时间盲注验证**: 延迟检测，网络抖动补偿
- **OOB 验证**: DNS/HTTP 带外回调确认

### 5. 依赖注入容器 (v3.0.2 新增)

**位置**: `core/container.py`

提供灵活的服务组合和生命周期管理：

```python
from core.container import Container, singleton, inject

container = Container()

# 注册服务
container.register_singleton(KnowledgeManager)
container.register_transient(SQLiDetector)

# 使用装饰器
@singleton
class ConfigManager:
    pass

# 注入依赖
config = inject(ConfigManager)

# 范围容器 (请求级别)
with container.create_scope() as scope:
    service = scope.resolve(RequestService)
```

**核心功能**:
- **生命周期**: Singleton, Scoped, Transient
- **自动注入**: 构造函数参数自动解析
- **循环检测**: 检测并报告循环依赖
- **资源释放**: Scoped 容器自动调用 dispose()

---

## 外部工具集成

支持集成本地安装的专业安全工具，实现更深度的检测能力：

| 工具 | 用途 | MCP 命令 | 安装要求 |
|------|------|----------|----------|
| **Nmap** | 端口扫描 + 服务识别 + NSE 脚本 | `ext_nmap_scan` | 系统 PATH 或配置路径 |
| **Nuclei** | 7000+ CVE/漏洞模板扫描 | `ext_nuclei_scan` | Go 编译或下载二进制 |
| **SQLMap** | 6种 SQL 注入技术 + WAF 绕过 | `ext_sqlmap_scan` | Python 脚本 |
| **ffuf** | 高速目录/参数模糊测试 | `ext_ffuf_fuzz` | Go 编译或下载二进制 |
| **Masscan** | 超高速大规模端口扫描 | `ext_masscan_scan` | 需要 root/管理员权限 |

### 配置外部工具

编辑 `config/external_tools.yaml`：

```yaml
# 工具基础目录
base_path: "/path/to/your/security-tools"

tools:
  nmap:
    enabled: true
    path: "${base_path}/nmap/nmap"
    default_args:
      quick: ["-sT", "-T4", "--open"]
      full: ["-sT", "-sV", "-sC", "-T4", "--open"]
      vuln: ["-sV", "--script=vuln"]

  nuclei:
    enabled: true
    path: "${base_path}/nuclei/nuclei"
    templates_path: "${base_path}/nuclei-templates"
    default_args:
      quick: ["-silent", "-severity", "critical,high"]
      cve: ["-silent", "-tags", "cve"]

  sqlmap:
    enabled: true
    path: "${base_path}/sqlmap/sqlmap.py"
    python_script: true
    default_args:
      detect: ["--batch", "--level=2", "--risk=1"]
      exploit: ["--batch", "--level=5", "--risk=3", "--dump"]

  ffuf:
    enabled: true
    path: "${base_path}/ffuf/ffuf"
    default_args:
      dir: ["-t", "50", "-fc", "404"]

  masscan:
    enabled: true
    path: "${base_path}/masscan/masscan"
    requires_root: true

# 工具链配置
chains:
  full_recon:
    - name: "masscan"
      args: ["--rate=10000", "-p1-10000"]
    - name: "nmap"
      args: ["-sV", "-sC"]
      depends_on: "masscan"

  vuln_scan:
    - name: "nuclei"
      args: ["-severity", "critical,high,medium"]
    - name: "sqlmap"
      condition: "has_params"
```

### 工具链编排

```bash
# 完整侦察链: masscan 快速发现 → nmap 详细识别
ext_tool_chain target="192.168.1.0/24" chain_name="full_recon"

# 漏洞扫描链: nuclei + sqlmap 联合检测
ext_tool_chain target="https://example.com" chain_name="vuln_scan"

# 检查外部工具状态
ext_tools_status
```

---

## 使用示例

### 命令行使用

在 AI 编辑器中直接对话调用：

#### 侦察与信息收集

```
# 完整侦察
"对 example.com 进行完整侦察并生成报告"

# 端口扫描
"扫描 192.168.1.0/24 网段的开放端口"

# 子域名枚举
"枚举 example.com 的所有子域名"

# 指纹识别
"识别目标网站的技术栈和 WAF"

# JS 分析
"分析目标网站 JavaScript 文件中的敏感信息"
```

#### 漏洞扫描

```
# SQL 注入
"检测 https://target.com/api?id=1 是否存在 SQL 注入"

# XSS 扫描
"扫描目标表单的 XSS 漏洞并生成 PoC"

# API 安全
"对目标 API 进行完整的 JWT/CORS/GraphQL 安全测试"

# CVE 搜索与利用
"搜索 Apache Log4j 相关的 CVE 并执行 PoC"
```

#### 红队操作

```
# 横向移动
"通过 SMB 在 192.168.1.100 上执行 whoami 命令"

# C2 通信
"启动 DNS 隧道连接到 c2.example.com"

# 持久化
"在 Windows 目标上建立计划任务持久化"

# AD 攻击
"对域控进行 Kerberoasting 攻击"
```

#### 自动化渗透

```
# 全自动渗透测试
"对 https://target.com 执行全自动渗透测试，生成详细报告"

# 智能攻击链
"分析目标并生成最优攻击链推荐"

# 断点续传
"恢复之前中断的渗透测试会话"
```

### Python API 调用

#### 基础用法

```python
import asyncio
from core.recon import StandardReconEngine, ReconConfig
from core.detectors import DetectorFactory

async def main():
    # 1. 侦察引擎
    config = ReconConfig(
        quick_mode=False,
        enable_js_analysis=True,
        max_threads=50
    )
    engine = StandardReconEngine("https://target.com", config)
    recon_result = await engine.run()
    print(f"发现 {len(recon_result.open_ports)} 个开放端口")

    # 2. 漏洞检测
    detector = DetectorFactory.create_composite(['sqli', 'xss', 'ssrf'])
    vuln_results = await detector.async_detect(
        url="https://target.com/api",
        params={'id': '1'}
    )

    for vuln in vuln_results:
        print(f"发现漏洞: {vuln.type} - {vuln.severity}")

asyncio.run(main())
```

#### MCTS 攻击规划

```python
from core.mcts_planner import MCTSPlanner, AttackState

# 创建规划器
planner = MCTSPlanner(exploration_weight=1.414, max_depth=10)

# 初始状态
state = AttackState(
    target="192.168.1.100",
    target_type="linux_server",
    open_ports={22: "ssh", 80: "http", 3306: "mysql"},
)

# 规划攻击
result = planner.plan(state, iterations=1000)

print(f"推荐攻击序列:")
for action, visits, reward in result['recommended_actions']:
    print(f"  - {action.type.value}: {action.target_port} (置信度: {reward:.2f})")
```

#### 知识图谱

```python
from core.knowledge import KnowledgeManager

km = KnowledgeManager()

# 构建知识
target_id = km.store_target("192.168.1.100", "linux_server")
service_id = km.store_service(target_id, "nginx", 80)
vuln_id = km.store_vulnerability(service_id, "CVE-2021-44228", "critical")

# 查询攻击路径
paths = km.get_attack_paths(target_id, vuln_id)
for path in paths:
    print(f"路径长度: {path.length}, 成功率: {path.success_rate:.2%}")

# 查找相似目标
similar = km.find_similar_targets("192.168.1.100", top_k=5)
for match in similar:
    print(f"相似目标: {match.entity.properties['target']}, 相似度: {match.score:.2f}")
```

#### 漏洞验证

```python
from core.detectors.advanced_verifier import AdvancedVerifier

verifier = AdvancedVerifier(callback_server="oob.example.com")

# 多方法验证
def make_request(url, payload):
    # 发送请求并返回 (响应内容, 状态码, 响应时间)
    ...

results = verifier.multi_method_verify(
    url="http://target.com/api?id=1",
    vuln_type="sqli",
    request_func=make_request,
    methods=["statistical", "boolean_blind", "time_based", "oob"],
)

# 聚合结果
aggregated = verifier.aggregate_results(results)
if aggregated.status.value == "confirmed":
    print(f"漏洞确认! 置信度: {aggregated.confidence:.2%}")
    for evidence in aggregated.evidence:
        print(f"  证据: {evidence}")
```

#### 横向移动

```python
from core.lateral import SMBLateralMove, SSHLateralMove

# SMB 横向
smb = SMBLateralMove(
    target="192.168.1.100",
    credential={"username": "admin", "password_hash": "aad3b435..."}
)
result = await smb.execute_command("whoami")

# SSH 隧道
ssh = SSHLateralMove(
    target="192.168.1.100",
    credential={"username": "root", "private_key_path": "/path/to/key"}
)
await ssh.create_tunnel(local_port=8080, remote_port=80)
```

#### CVE 自动利用

```python
from core.cve import CVEAutoExploit

exploit = CVEAutoExploit()

# 搜索并利用
results = await exploit.search_and_exploit(
    cve_id="CVE-2021-44228",
    target="https://target.com"
)

# AI 生成 PoC
poc_code = await exploit.generate_poc(
    cve_id="CVE-2024-12345",
    target_info={"os": "linux", "service": "nginx"}
)
```

#### 会话管理

```python
from core.session import SessionManager

manager = SessionManager()

# 创建会话
session_id = await manager.create_session(
    target="https://target.com",
    scan_type="full_pentest"
)

# 恢复会话
await manager.resume_session(session_id)

# 导出结果
await manager.export_findings(session_id, format="html")
```

---

## 配置说明

### 环境变量 (.env)

```bash
# ========== 安全配置 ==========
# 主密钥 (首次运行自动生成)
REDTEAM_MASTER_KEY=

# MCP 授权密钥 (可选)
AUTOREDTEAM_API_KEY=

# 授权模式: strict, permissive, disabled
AUTOREDTEAM_AUTH_MODE=permissive

# ========== API 密钥 ==========
# AI 分析
OPENAI_API_KEY=your_key
ANTHROPIC_API_KEY=your_key

# 侦察
SHODAN_API_KEY=your_key
CENSYS_API_ID=your_id
CENSYS_API_SECRET=your_secret

# CVE 情报
NVD_API_KEY=your_key
GITHUB_TOKEN=your_token

# ========== 代理设置 ==========
HTTP_PROXY=
HTTPS_PROXY=
SOCKS_PROXY=

# ========== 全局配置 ==========
VERIFY_SSL=false
RATE_LIMIT_DELAY=0.3
MAX_THREADS=50
REQUEST_TIMEOUT=10

# ========== 日志 ==========
LOG_LEVEL=INFO
LOG_FILE=logs/redteam.log
```

### pyproject.toml 可选依赖

```bash
# 仅安装特定功能
pip install autoredteam-orchestrator[ai]        # AI 功能
pip install autoredteam-orchestrator[recon]     # 侦察功能
pip install autoredteam-orchestrator[network]   # 网络功能
pip install autoredteam-orchestrator[reporting] # 报告功能
pip install autoredteam-orchestrator[dev]       # 开发依赖
```

---

## 性能调优

### 并发配置

```yaml
# config/performance.yaml
concurrency:
  max_threads: 100          # 最大线程数
  max_async_tasks: 200      # 最大异步任务
  connection_pool_size: 50  # 连接池大小

rate_limiting:
  requests_per_second: 50   # 每秒请求数
  burst_size: 100           # 突发请求数

timeouts:
  connect: 5                # 连接超时 (秒)
  read: 30                  # 读取超时
  total: 120                # 总超时
```

### 内存优化

```python
# 大规模扫描时使用流式处理
engine = StandardReconEngine(
    target="192.168.0.0/16",
    config=ReconConfig(
        streaming_mode=True,    # 启用流式处理
        batch_size=1000,        # 批处理大小
        memory_limit="2GB"      # 内存限制
    )
)
```

### 分布式扫描

```python
# 使用 Celery 分布式任务队列
from core.distributed import DistributedScanner

scanner = DistributedScanner(
    broker="redis://localhost:6379",
    workers=10
)
await scanner.scan_targets(["192.168.1.0/24", "192.168.2.0/24"])
```

---

## 故障排查

### 常见问题

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| MCP 服务器无法连接 | 路径错误或 Python 环境问题 | 检查配置中的绝对路径，确保使用正确的 Python 解释器 |
| 导入错误 | PYTHONPATH 未设置 | 在配置中添加 `PYTHONPATH` 环境变量 |
| 外部工具调用失败 | 工具未安装或路径错误 | 运行 `ext_tools_status` 检查工具状态 |
| CVE 数据库同步失败 | 网络问题或 API 限流 | 检查网络，配置 NVD_API_KEY 提高限流 |
| 扫描速度慢 | 并发配置过低 | 调整 `MAX_THREADS` 和 `RATE_LIMIT_DELAY` |
| 内存溢出 | 大规模扫描 | 启用 `streaming_mode`，设置 `memory_limit` |

### 调试模式

```bash
# 启用详细日志
LOG_LEVEL=DEBUG python mcp_stdio_server.py

# 检查语法错误
python -m py_compile mcp_stdio_server.py

# 运行单个测试
pytest tests/test_mcp_security.py::TestInputValidator -v
```

### 日志分析

```bash
# 查看最近错误
tail -f logs/redteam.log | grep ERROR

# 分析性能瓶颈
grep "elapsed" logs/redteam.log | sort -t: -k4 -n
```

---

## 常见问题 (FAQ)

<details>
<summary><b>Q: 如何在没有网络的环境中使用？</b></summary>

A:
1. 预先下载 CVE 数据库: `python core/cve/update_manager.py sync --offline-export`
2. 使用本地字典文件
3. 禁用需要网络的功能: `OFFLINE_MODE=true`

</details>

<details>
<summary><b>Q: 如何添加自定义检测器？</b></summary>

A:
1. 在 `core/detectors/` 创建新文件
2. 继承 `BaseDetector` 类
3. 实现 `detect()` 和 `async_detect()` 方法
4. 在 `handlers/detector_handlers.py` 注册 MCP 工具

```python
from core.detectors.base import BaseDetector

class CustomDetector(BaseDetector):
    async def async_detect(self, url, params):
        # 实现检测逻辑
        return VulnResult(...)
```

</details>

<details>
<summary><b>Q: 如何集成其他外部工具？</b></summary>

A:
1. 在 `config/external_tools.yaml` 添加工具配置
2. 在 `handlers/external_tools_handlers.py` 添加 MCP 工具函数
3. 使用 `core/tools/tool_manager.py` 的 `execute_tool()` 方法

</details>

<details>
<summary><b>Q: 如何处理 WAF 拦截？</b></summary>

A:
1. 使用 `smart_payload` 工具自动选择 WAF 绕过 Payload
2. 配置代理池: `PROXY_POOL=true`
3. 启用流量变异: `traffic_mutation=true`
4. 降低扫描速度: `RATE_LIMIT_DELAY=1.0`

</details>

<details>
<summary><b>Q: 支持哪些报告格式？</b></summary>

A:
- JSON (机器可读)
- HTML (带图表的可视化报告)
- Markdown (适合 Git/Wiki)
- PDF (需要安装 `reportlab`)
- DOCX (需要安装 `python-docx`)

</details>

<details>
<summary><b>Q: MCTS 规划器如何工作？</b></summary>

A:
MCTS (蒙特卡洛树搜索) 通过以下四个阶段规划攻击路径：

1. **Selection**: 从根节点使用 UCB1 算法选择最优路径
2. **Expansion**: 在叶节点扩展新的攻击动作
3. **Simulation**: 模拟执行攻击并评估收益
4. **Backpropagation**: 回传收益值更新路径上的节点

UCB1 公式: `UCB1 = Q/N + c * sqrt(ln(N_parent) / N)`

其中 `c = sqrt(2)` 是探索权重，平衡 "已知好的路径" 和 "未探索的路径"。

</details>

<details>
<summary><b>Q: 知识图谱如何减少重复工作？</b></summary>

A:
知识图谱通过以下机制减少重复工作：

1. **目标相似度**: 识别同子网/同域名的目标，复用漏洞信息
2. **攻击路径成功率**: 基于历史记录计算路径成功率
3. **凭证关联**: 自动关联凭证与可访问的目标
4. **动作历史学习**: 记录动作成功率，优化后续决策

</details>

---

## 开发指南

### 代码规范

```bash
# 格式化代码
black core/ modules/ handlers/ utils/
isort core/ modules/ handlers/ utils/

# 静态检查
pylint core/ modules/ handlers/ utils/
mypy core/ modules/ handlers/ utils/

# 运行测试
pytest tests/ -v --cov=core --cov-report=html
```

### 添加新的 MCP 工具

```python
# 1. 在 handlers/ 中添加处理器
# handlers/my_handlers.py

from mcp import tool

@tool()
async def my_new_tool(target: str, option: str = "default") -> dict:
    """工具描述

    Args:
        target: 目标地址
        option: 可选参数

    Returns:
        结果字典
    """
    # 实现逻辑
    return {"success": True, "data": ...}

# 2. 在 mcp_stdio_server.py 中导入
from handlers.my_handlers import my_new_tool
```

### 测试要求

- 所有新功能必须包含测试
- 测试覆盖率目标: >70%
- 使用 pytest fixtures 管理测试数据
- 标记慢测试: `@pytest.mark.slow`

---

## 更新日志

### v3.0.2 (开发中) - 架构加固

**新增模块** (已实现，待提交)
- **MCP 安全中间件** - 输入验证、速率限制、操作授权
- **依赖注入容器** - 生命周期管理、循环依赖检测
- **MCTS 攻击规划器** - UCB1 算法、攻击路径优化
- **知识图谱** - 实体关系存储、BFS 路径发现
- **高级验证器增强** - OOB 线程安全、SSTI payload

**安全修复**
- 修复 TOCTOU 竞态条件 (扩展锁范围)
- 修复 duration 授权过期逻辑
- 添加 SSRF 检测 (私有 IP 验证)
- 修复 Rate Limiter 内存泄漏 (max_keys 淘汰)
- 修复 DNS 注入 (token ID 清洗)
- MD5 → SHA256 哈希升级

**测试增强**
- 新增 291 测试用例 (mcp_security: 62, container: 39, mcts: 57, verifier: 43, knowledge: 90)
- 线程安全测试覆盖
- 集成测试工作流

### v3.0.1 (2026-01-30) - 质量加固

**新增**
- CVE 自动利用增强 (`cve_auto_exploit`, `cve_exploit_with_desc`, `cve_generate_poc`)
- AI PoC 生成器 (`core/cve/ai_poc_generator.py`)

**修复**
- 版本号统一 - 全面同步 VERSION/pyproject.toml/源码
- ToolCounter 修复 - 新增 external_tools/lateral/persistence/ad 类别
- 测试修复 - 更新过时的测试用例引用
- 线程安全 - beacon.py 状态管理添加 threading.Lock

**改进**
- CI/CD 强化 - lint 检查失败现阻止构建
- 测试覆盖率阈值提升至 50%
- 依赖版本约束 - 添加上界防止兼容性问题

### v3.0.0 (2026-01-18) - 架构增强

**新增**
- 外部工具集成 - 8 个外部工具 MCP 命令
- 工具链编排 - YAML 驱动的多工具组合
- Handler 模块化 - 16 个独立 Handler 模块

**改进**
- MCP 工具数量达到 100+
- 反馈循环引擎 - 智能利用编排器
- WAF 绕过 - 增强 Payload 变异引擎

<details>
<summary><b>查看更多版本</b></summary>

### v2.8.0 (2026-01-15) - 安全加固
- 输入验证增强、异常处理统一、性能优化

### v2.7.1 (2026-01-10) - Web 扫描引擎
- Web Scanner 模块、内置字典库

### v2.7.0 (2026-01-09) - 架构重构
- 模块化重构、StandardReconEngine

### v2.6.0 (2026-01-07) - API/供应链/云安全
- JWT/CORS/GraphQL/WebSocket 安全测试
- SBOM 生成、K8s/gRPC 安全审计

</details>

---

## 路线图

### 进行中
- [ ] v3.0.2 发布 (MCP 安全中间件、MCTS 规划器、知识图谱、DI 容器)
- [ ] Web UI 管理界面
- [ ] 分布式扫描集群

### 计划中
- [ ] 更多云平台支持 (GCP/阿里云/腾讯云)
- [ ] Burp Suite 插件集成
- [ ] 移动应用安全测试
- [ ] AI 自主攻击代理
- [ ] Neo4j 知识图谱后端

### 已完成 (v3.0.1)
- [x] Red Team 全套工具链
- [x] CVE 情报与 AI PoC 生成
- [x] API/供应链/云安全模块
- [x] 全自动渗透测试框架
- [x] 外部工具集成

---

## 贡献指南

我们欢迎任何形式的贡献！

### 快速开始

```bash
# 1. Fork 并克隆
git clone https://github.com/YOUR_USERNAME/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. 创建分支
git checkout -b feature/your-feature

# 3. 安装开发依赖
pip install -r requirements-dev.txt
pre-commit install

# 4. 开发并测试
pytest tests/ -v

# 5. 提交 PR
git push origin feature/your-feature
```

### 提交规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 格式：

- `feat:` 新功能
- `fix:` Bug 修复
- `docs:` 文档更新
- `refactor:` 重构
- `test:` 测试相关
- `chore:` 构建/工具
- `security:` 安全相关

### 代码审查标准

- 所有新代码必须包含测试
- 测试覆盖率不低于 70%
- 通过所有 lint 检查
- 无安全漏洞 (OWASP Top 10)
- 文档完整 (docstring + README 更新)

详见 [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 安全策略

- **负责任的披露**: 发现安全漏洞请通过 [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com) 联系
- **授权使用**: 本工具仅用于已授权的安全测试与研究
- **合规声明**: 使用前请确保遵守当地法律法规

详见 [SECURITY.md](SECURITY.md)

---

## 致谢

### 核心依赖

| 项目 | 用途 | 许可证 |
|------|------|--------|
| [MCP Protocol](https://modelcontextprotocol.io/) | AI 工具协议标准 | MIT |
| [aiohttp](https://github.com/aio-libs/aiohttp) | 异步 HTTP 客户端 | Apache-2.0 |
| [pydantic](https://github.com/pydantic/pydantic) | 数据验证 | MIT |
| [pytest](https://github.com/pytest-dev/pytest) | 测试框架 | MIT |

### 设计灵感

| 项目 | 启发点 |
|------|--------|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | 漏洞扫描引擎设计 |
| [SQLMap](https://github.com/sqlmapproject/sqlmap) | SQL 注入检测思路 |
| [Impacket](https://github.com/fortra/impacket) | 网络协议实现 |
| [Metasploit](https://github.com/rapid7/metasploit-framework) | 后渗透模块设计 |
| [Cobalt Strike](https://www.cobaltstrike.com/) | C2 通信架构 |

### 算法参考

| 算法 | 用途 | 参考 |
|------|------|------|
| UCB1 | MCTS 探索-利用平衡 | Auer et al., 2002 |
| BFS | 知识图谱路径发现 | - |
| Token Bucket | 速率限制 | - |
| Sliding Window | 速率限制 | - |

### 特别感谢

- 所有提交 Issue 和 PR 的贡献者
- 安全社区的反馈和建议
- Claude AI 在代码审查和优化中的协助

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Coff0xc/AutoRedTeam-Orchestrator&type=Date)](https://star-history.com/#Coff0xc/AutoRedTeam-Orchestrator&Date)

---

## 许可证

本项目采用 **MIT 许可证** - 详见 [LICENSE](LICENSE) 文件

```
MIT License

Copyright (c) 2026 Coff0xc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 免责声明

> **警告**: 本工具仅用于**授权的安全测试与研究**。
>
> 在使用本工具对任何系统进行测试前，请确保：
> - 已获得目标系统所有者的**书面授权**
> - 遵守当地的**法律法规**
> - 符合**职业道德**标准
>
> 未经授权使用本工具可能违反法律。**开发者不对任何滥用行为承担责任**。
>
> 本工具包含红队攻击功能（横向移动、C2 通信、持久化等），仅供：
> - 授权渗透测试
> - 安全研究与教育
> - CTF 竞赛
> - 防御能力验证
>
> **禁止用于任何非法目的。**

---

<p align="center">
  <img src="https://img.shields.io/badge/Built%20with-Python%20%26%20%E2%9D%A4-blue?style=for-the-badge" alt="Built with Python">
</p>

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Coff0xc">Coff0xc</a></b>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB">Discord</a> ·
  <a href="mailto:Coff0xc@protonmail.com">Email</a> ·
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues">Issues</a>
</p>

<p align="center">
  <sub>如果这个项目对你有帮助，请考虑给它一个 ⭐ Star！</sub>
</p>
