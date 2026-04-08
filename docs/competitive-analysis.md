# AutoRedTeam-Orchestrator 竞品分析 + 优化方案

## 竞品全景

| 项目 | ⭐ Stars | 语言 | 核心差异 | 最后更新 |
|------|---------|------|----------|----------|
| **PentAGI** (vxcontrol) | **14.5K** | Go+React | 微服务架构, Neo4j知识图谱, pgvector语义记忆, Docker沙箱, 20+工具 | 2026-04-08 |
| **RedAmon** (samugit83) | **1.7K** | Python+Next.js | LangGraph编排, Neo4j攻击图, 38+工具, 185K检测规则, 自动修复PR | 2026-04-07 |
| **mcp-for-security** (cyproxio) | **602** | TypeScript | 纯MCP wrapper (nmap/sqlmap/ffuf/masscan), 轻量 | 2026-03-30 |
| **AutoRedTeam** (Coff0xc) | **203** | Python | 纯Python引擎, 101+ MCP工具, MCTS规划, 24+检测器 | 2026-03-23 |
| **PentestThinkingMCP** | **29** | JavaScript | MCTS+Beam Search推理, 学术项目(LIMA论文) | 2025-08-30 |

## 差距分析: AutoRedTeam vs 头部项目

### vs PentAGI (14.5K⭐) — 最大差距

| 维度 | PentAGI | AutoRedTeam | 差距 |
|------|---------|-------------|------|
| **沙箱隔离** | Docker容器执行所有操作 | 直接在宿主机运行 | 🔴 严重: 安全风险 |
| **知识图谱** | Neo4j + pgvector | 内存 dict + BFS | 🟡 功能弱 |
| **多Agent协作** | 专业化Agent (Pentester/Coder/Installer) | 单Agent | 🔴 缺失 |
| **UI** | React Web Dashboard | 无 (仅MCP/CLI) | 🟡 体验差 |
| **可观测性** | Grafana/Prometheus/Jaeger/LangFuse | logging.info | 🟡 运维弱 |
| **多LLM支持** | OpenAI/Anthropic/Gemini/Bedrock/Ollama | 无内置LLM调用 | 🟡 灵活性差 |
| **纯Python引擎** | 依赖外部工具 | ✅ 自研24+检测器 | 🟢 我们优势 |

### vs RedAmon (1.7K⭐) — 最接近的竞品

| 维度 | RedAmon | AutoRedTeam | 差距 |
|------|---------|-------------|------|
| **攻击图** | Neo4j 17种节点类型, 持久化 | 内存知识图谱 | 🟡 |
| **自动修复** | CypherFix生成PR | 无 | 🔴 差异化功能 |
| **检测规则** | 185,000+ (基于Nuclei模板) | ~1500 payload | 🟡 数量级差距 |
| **项目设置** | 196+ 可配置参数 via UI | config.yaml | 🟡 |
| **容器化** | Docker Compose 一键部署 | pip install | 🟢 我们更轻量 |
| **纯Python扫描** | 依赖外部 nmap/nuclei | ✅ 自研引擎 | 🟢 我们优势 |

## AutoRedTeam 的独特优势

1. **纯Python渗透引擎** — 无需 nmap/sqlmap/nuclei 等外部依赖即可工作 (24+ 检测器全部自研)
2. **轻量部署** — `pip install` 即用, 无需 Docker/Neo4j/PostgreSQL
3. **MCP原生** — 深度集成MCP协议, 101+ 工具, AI编辑器直接调用
4. **MCTS攻击规划** — UCB1算法优化攻击路径 (与PentestThinkingMCP类似但集成更深)
5. **全链路覆盖** — Recon → Detect → Exploit → Lateral → Persist → Exfil → Report

## 优化方案: 缩小差距 + 放大优势

### 高优先级 (差异化 + 快速见效)

#### OPT-1: Docker 沙箱执行器
**差距**: PentAGI/RedAmon 都在容器中执行, 我们在宿主机
**方案**: 新增 `core/sandbox/` 包
- `DockerExecutor`: 将危险操作(端口扫描、exploit)委托给Docker容器
- `SandboxConfig`: 可选启用 (默认关闭保持轻量)
- 对 `core/recon/port_scanner.py` 和 `core/exploit/` 提供沙箱封装

#### OPT-2: 攻击面图谱持久化
**差距**: 内存知识图谱 vs Neo4j
**方案**: 增强 `core/knowledge/manager.py`
- 添加 SQLite 后端 (零依赖持久化)
- 实体类型对齐 RedAmon 的 17 种 (当前只有 4 种)
- 添加 `export_graph()` → JSON/DOT 格式可视化

#### OPT-3: Nuclei 模板集成
**差距**: 1500 payload vs 185K+ 检测规则
**方案**: 新增 `core/detectors/nuclei_engine.py`
- 解析 Nuclei YAML 模板 (纯Python, 不依赖nuclei二进制)
- 支持从 projectdiscovery/nuclei-templates 加载
- 与现有 DetectorFactory 集成

### 中优先级 (架构增强)

#### OPT-4: Multi-Agent 编排
**方案**: 新增 `core/agents/` 包
- 基于现有 `core/orchestrator/decision.py` 扩展
- 定义 Agent 角色: ReconAgent, ExploitAgent, ReportAgent
- Agent 间通过 knowledge graph 共享发现

#### OPT-5: 结构化 Findings 数据库
**方案**: 新增 `core/findings/` 包
- SQLite 存储所有发现 (替代 session 内存存储)
- 支持去重、严重性排序、趋势分析
- `autort findings list/export/dedupe` CLI 命令

#### OPT-6: 可观测性
**方案**: 在 `utils/logger.py` 基础上添加
- 结构化 JSON 日志 (可选)
- 扫描耗时指标 (per-detector, per-phase)
- `autort stats` 命令展示历史扫描统计

### 低优先级 (未来路线)

- OPT-7: Web Dashboard (React/Vue)
- OPT-8: 多 LLM Provider 支持 (LiteLLM 集成)
- OPT-9: 自动修复建议生成 (类 RedAmon CypherFix)
