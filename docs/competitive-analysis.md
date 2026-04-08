# AutoRedTeam-Orchestrator 全面竞品分析报告

> 调研日期: 2026-04-08 | 覆盖 20+ 项目 | 含开源/商业/学术三类

---

## 一、竞品全景矩阵

### 1.1 开源项目（按 Stars 排序）

| # | 项目 | ⭐ Stars | 语言 | 架构类型 | LLM 支持 | 最后更新 |
|---|------|---------|------|----------|----------|----------|
| 1 | [Shannon Lite](https://github.com/KeygraphHQ/shannon) | **37,478** | TS | 白盒 AI pentester, 源码分析+浏览器自动化 | 多 LLM | 2026-04 |
| 2 | [Strix](https://github.com/usestrix/strix) | **23,255** | Python | 自主 AI hacker, CI/CD 集成, PoC 验证 | LiteLLM | 2026-04 |
| 3 | [PentAGI](https://github.com/vxcontrol/pentagi) | **14,495** | Go+React | 多Agent微服务, Docker沙箱, Neo4j知识图谱 | 多 LLM | 2026-04 |
| 4 | [PentestGPT](https://github.com/GreyDGL/PentestGPT) | **12,446** | Python | 先驱项目, USENIX 2024, CTF 86.5%成功率 | OpenAI | 2026-02 |
| 5 | [CAI](https://github.com/aliasrobotics/cai) | **7,861** | Python | 多Agent框架, 300+ LLM (LiteLLM), OpenTelemetry | LiteLLM | 2026-04 |
| 6 | [RedAmon](https://github.com/samugit83/redamon) | **1,720** | Python+Next.js | LangGraph编排, Neo4j攻击图, 38+工具, 自动修复PR | 400+ models | 2026-04 |
| 7 | [mcp-for-security](https://github.com/cyproxio/mcp-for-security) | **602** | TS | 纯 MCP wrapper (nmap/sqlmap/ffuf/masscan) | 无内置 | 2026-03 |
| 8 | [Pentest Copilot](https://github.com/bugbasesecurity/pentest-copilot) | **458** | JS | 浏览器AI助手, Kali攻击盒子 | 多 LLM | 2026-04 |
| 9 | [Pentest-Swarm-AI](https://github.com/Armur-Ai/Auto-Pentest-GPT-AI) | **218** | Go | Swarm Agent 协作, 实时攻击 | 多 LLM | 2026-03 |
| 10 | **AutoRedTeam** (Coff0xc) | **203** | Python | 纯Python引擎, 101+ MCP工具, MCTS规划 | 无内置 | 2026-04 |
| 11 | [VulnBot](https://github.com/KHenryAegis/VulnBot) | **156** | Python | 学术多Agent (arXiv:2501.13411) | 研究用 | 2025-04 |
| 12 | [AI-OPS](https://github.com/antoninOLorenzo/AI-OPS) | **127** | Python | 开源LLM AI助手, Ollama | 开源 LLM | 2026-04 |
| 13 | [PentestThinkingMCP](https://github.com/ibrahimsaleem/PentestThinkingMCP) | **29** | JS | MCTS+Beam Search推理 (LIMA论文) | 无 | 2025-08 |

### 1.2 商业/企业产品

| 产品 | 定位 | 核心差异 | 目标用户 |
|------|------|----------|----------|
| **[Escape](https://escape.tech)** | API & 业务逻辑测试 | AI理解认证/角色/状态, BOLA/IDOR检测 | 企业AppSec |
| **[XBOW](https://xbow.com)** | 对抗性利用链 | exploit chain + PoC验证深度 | 高级红队 |
| **[NodeZero (Horizon3)](https://horizon3.ai)** | 自主网络渗透 | 证明攻击路径+修复验证 | 企业安全团队 |
| **[Pentera](https://pentera.io)** | 安全验证平台 | 跨层自动化安全验证 | 大型企业 |
| **[Penligent](https://penligent.ai)** | Agentic红队 | 安全模式(不破坏生产), 完整攻击工作流 | Red Team/MSSP |
| **[ImmuniWeb](https://immuniweb.com)** | 零误报保证 | 合同级零FP SLA + 暗网监控 | 合规驱动 |
| **[Cobalt](https://cobalt.io)** | PtaaS (渗透即服务) | AI+人类混合测试 | FinTech/SaaS |
| **[Aikido](https://aikido.dev)** | 开发者安全 | 可达性分析 (Reachability Analysis) | DevSecOps |

### 1.3 学术/研究项目

| 项目 | 论文 | 核心贡献 |
|------|------|----------|
| **PentestGPT** | USENIX Security 2024 | 首个LLM渗透测试Agent论文, CTF 86.5% |
| **VulnBot** | arXiv:2501.13411 | 多Agent协作渗透框架 |
| **LIMA** | arXiv (PentestThinkingMCP) | LLM + MCP Server 自动渗透 |
| **HackingBuddyGPT** | IPA Lab | 教育导向, 自适应技能指导 |
| **AutoPentest-DRL** | 学术 | 强化学习渗透 (实验性) |

---

## 二、多维度对比分析

### 2.1 架构对比

| 维度 | Shannon | Strix | PentAGI | CAI | RedAmon | AutoRedTeam |
|------|---------|-------|---------|-----|---------|-------------|
| **Agent模式** | 单Agent白盒 | 单Agent+CI/CD | 多Agent微服务 | 多Agent协作 | 双Agent管道 | 单Agent+MCTS |
| **执行隔离** | 浏览器沙箱 | Docker | Docker沙箱 | Docker | Kali Docker | ✅ OPT-1 Docker |
| **知识存储** | — | — | Neo4j+pgvector | OpenTelemetry | Neo4j(17节点) | ✅ OPT-2 SQLite |
| **LLM支持** | 多LLM | LiteLLM | 多provider | LiteLLM(300+) | 400+ models | ❌ 无内置 |
| **检测引擎** | 源码分析 | Nuclei+Caido | 外部工具 | MCP+外部 | Nuclei(185K) | ✅ 24+自研+OPT-3 |
| **扫描方式** | 白盒(源码) | 黑盒+灰盒 | 黑盒 | 黑盒 | 黑盒 | 黑盒 |
| **CI/CD集成** | ✅ GitHub Actions | ✅ 原生 | ❌ | ❌ | ❌ | ❌ |
| **Web UI** | ✅ | ✅ | ✅ React | ❌ CLI | ✅ Next.js | ❌ CLI only |
| **纯Python引擎** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 独有优势 |

### 2.2 功能覆盖对比

| 能力 | Shannon | Strix | PentAGI | CAI | RedAmon | AutoRedTeam |
|------|---------|-------|---------|-----|---------|-------------|
| 侦察 | ✅ | ✅ | ✅ | ✅ | ✅ 并行5工具 | ✅ 10阶段 |
| 漏洞检测 | ✅ 源码级 | ✅ Nuclei | ✅ | ✅ | ✅ 185K规则 | ✅ 24+检测器 |
| 漏洞利用 | ✅ 真实exploit | ✅ PoC | ✅ Metasploit | ✅ | ✅ | ✅ 自研引擎 |
| 横向移动 | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ SMB/SSH/WMI/WinRM/PsExec |
| C2通信 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Beacon+Tunnels |
| 持久化 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Win/Linux/Webshell |
| 提权 | ❌ | ❌ | ✅ 部分 | ✅ | ❌ | ✅ SUID/Sudo/UAC |
| 数据外泄 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ HTTP/DNS/ICMP/SMB |
| AD攻击 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Kerberos/LDAP |
| 报告生成 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ HTML/JSON/MD |
| 自动修复 | ❌ | ✅ 修复建议 | ❌ | ❌ | ✅ 生成PR | ❌ |

### 2.3 技术栈对比

| 维度 | PentAGI | CAI | RedAmon | AutoRedTeam |
|------|---------|-----|---------|-------------|
| 后端 | Go | Python | Python | Python |
| 前端 | React/TS | — | Next.js/TS | — (CLI) |
| 数据库 | PostgreSQL+Neo4j | — | Neo4j | SQLite (新增) |
| 消息队列 | ✅ | — | — | — |
| 可观测性 | Grafana/Prometheus/Jaeger | OpenTelemetry | — | logging |
| 容器化 | Docker Compose | Docker | Docker Compose | 可选 Docker |
| 部署复杂度 | 高 (4+服务) | 中 | 高 (Neo4j+Kali) | **低 (pip install)** |

---

## 三、AutoRedTeam 独特优势 (其他项目不具备)

### 3.1 ✅ 纯 Python 渗透引擎 (唯一)
- 24+ 自研漏洞检测器, 不依赖 nmap/sqlmap/nuclei 二进制
- 完整 exploit 引擎: SQLi/RCE/SSRF/XXE/SSTI/反序列化 利用
- 可在 **无任何外部工具** 的环境运行 (Windows/CI/受限环境)

### 3.2 ✅ 全链路红队覆盖 (最全)
- 从侦察→漏洞检测→利用→横向移动→C2→持久化→提权→数据外泄→报告
- **横向移动+C2+持久化+AD攻击**: 竞品中无一项目同时覆盖

### 3.3 ✅ MCP 深度集成 (最多工具)
- 101+ MCP 注册工具 (竞品最多约 150, 但多为外部工具 wrapper)
- 自研工具: 不是包装外部二进制, 而是纯 Python 实现

### 3.4 ✅ MCTS 攻击路径规划
- UCB1 算法优化攻击路径
- 比简单 pipeline 更智能的攻击决策

### 3.5 ✅ 轻量部署
- `pip install` 即用, 无需 Docker/Neo4j/PostgreSQL
- 在 Windows/Linux/macOS 上均可运行

---

## 四、关键差距 + 优化路线

### 4.1 已完成优化 (v3.1.0)

| 差距 | 竞品参照 | 优化 | 状态 |
|------|----------|------|------|
| 无沙箱隔离 | PentAGI | OPT-1: Docker sandbox | ✅ 已完成 |
| 内存知识图谱 | RedAmon | OPT-2: SQLite + 17 实体 | ✅ 已完成 |
| payload 数量不足 | RedAmon (185K) | OPT-3: Nuclei YAML 引擎 | ✅ 已完成 |
| 配置散落 | — | Pydantic 统一配置 | ✅ 已完成 |
| 无 SDK/CLI | — | autort SDK + typer CLI | ✅ 已完成 |

### 4.2 下一步优化建议 (按优先级)

#### P0: 必做 — 缩小与头部的核心差距

| # | 优化项 | 竞品参照 | 预估工作量 | 预期效果 |
|---|--------|----------|------------|----------|
| **OPT-4** | **LLM Provider 集成 (LiteLLM)** | CAI(300+ models), PentAGI(多provider) | 2-3天 | 支持 OpenAI/Anthropic/Ollama, 让 AI 决策引擎真正驱动扫描 |
| **OPT-5** | **多Agent编排 (ReconAgent/ExploitAgent/ReportAgent)** | PentAGI(专业化Agent), CAI(多Agent协作) | 3-5天 | 多Agent协作, 各司其职 |
| **OPT-6** | **CI/CD 集成 (GitHub Actions)** | Strix(原生CI/CD), Shannon(GitHub Actions) | 1-2天 | `autort` 可在 PR 中自动扫描 |

#### P1: 重要 — 建立差异化壁垒

| # | 优化项 | 说明 | 预估工作量 |
|---|--------|------|------------|
| **OPT-7** | **可观测性 (结构化日志 + 指标)** | JSON logging + scan duration metrics + `autort stats` | 1-2天 |
| **OPT-8** | **Findings 数据库 (SQLite)** | 持久化所有发现, 去重, 趋势分析, export | 1-2天 |
| **OPT-9** | **自动修复建议生成** | 参考 RedAmon CypherFix, 为每个漏洞生成修复代码 | 2-3天 |
| **OPT-10** | **攻击面可视化** | 知识图谱 → D3.js/Mermaid 可视化, HTML报告中嵌入 | 1-2天 |

#### P2: 加分 — 提升开源影响力

| # | 优化项 | 说明 |
|---|--------|------|
| **OPT-11** | Web Dashboard (React/Vue) | 参考 PentAGI/RedAmon |
| **OPT-12** | Playbook 系统 | 参考 PentestAgent 的预置攻击剧本 |
| **OPT-13** | 基准测试套件 | 在 DVWA/Juice Shop 上的自动化基准 |

---

## 五、竞争定位建议

### 当前定位
> "纯 Python 的全链路红队 MCP 框架 — 唯一不依赖外部工具的 AI 渗透测试引擎"

### 建议调整为
> "企业级 AI 红队编排平台 — 纯 Python 引擎 + MCP 协议 + SDK/CLI 三层接口，
> 从侦察到数据外泄的完整攻击链自动化，pip install 即用"

### 核心叙事
竞品要么**依赖外部工具** (PentAGI/RedAmon/Strix 都需要 nmap/nuclei/sqlmap)，
要么**只做单一环节** (Shannon 只做 Web, Escape 只做 API)。
AutoRedTeam 是唯一 **自研全链路引擎** 的项目，且 **最轻量** 。

---

## Sources

### 开源项目
- [Shannon Lite](https://github.com/KeygraphHQ/shannon) — 37.5K⭐
- [Strix](https://github.com/usestrix/strix) — 23.3K⭐
- [PentAGI](https://github.com/vxcontrol/pentagi) — 14.5K⭐
- [PentestGPT](https://github.com/GreyDGL/PentestGPT) — 12.4K⭐
- [CAI](https://github.com/aliasrobotics/cai) — 7.9K⭐
- [RedAmon](https://github.com/samugit83/redamon) — 1.7K⭐
- [mcp-for-security](https://github.com/cyproxio/mcp-for-security) — 602⭐
- [Pentest Copilot](https://github.com/bugbasesecurity/pentest-copilot) — 458⭐
- [Pentest-Swarm-AI](https://github.com/Armur-Ai/Auto-Pentest-GPT-AI) — 218⭐
- [VulnBot](https://github.com/KHenryAegis/VulnBot) — 156⭐
- [AI-OPS](https://github.com/antoninOLorenzo/AI-OPS) — 127⭐
- [awesome-ai-pentest](https://github.com/insidetrust/awesome-ai-pentest)
- [awesome-cybersecurity-agentic-ai](https://github.com/raphabot/awesome-cybersecurity-agentic-ai)

### 行业分析
- [Top 10 Open-Source AI Agent Penetration Testing Projects](https://blog.spark42.tech/top-10-open-source-ai-agent-penetration-testing-projects/)
- [Pentest AI Tools in 2026 — What Actually Works](https://www.penligent.ai/hackinglabs/pentest-ai-tools-in-2026-what-actually-works-what-breaks/)
- [Best 7 AI Pentesting Tools in 2026](https://escape.tech/blog/best-ai-pentesting-tools/)
- [Best AI Pentesting Tools 2026 — StackHawk](https://www.stackhawk.com/blog/ai-pentesting-tools/)
- [8 Open-Source AI Pentest Tools 2026 — Ostorlab](https://blog.ostorlab.co/8-open-source-ai-pentest-tools-2026.html)
- [Top 10 AI Pentest Tools — SOCRadar](https://socradar.io/blog/top-10-ai-pentest-tools-2025/)
