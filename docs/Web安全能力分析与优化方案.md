# Web 安全能力分析与优化方案

> 本文档整合了 AutoRedTeam-Orchestrator 项目的 Web 安全能力路线图、实施清单和历史草案。

## 1. 项目概述

AutoRedTeam-Orchestrator 是基于 MCP (Model Context Protocol) 的 AI 驱动自动化渗透测试框架，提供 130+ 纯 Python 安全工具。

**核心特性**:
- 覆盖 OWASP Top 10
- API 安全测试 (JWT/CORS/GraphQL/WebSocket)
- 供应链安全 (SBOM/依赖扫描/CI-CD)
- 云原生安全 (K8s/gRPC)

## 2. 当前架构

### 2.1 工具分类

```
tools/
├── config_tools.py      # 配置管理
├── recon_tools.py       # 信息收集
├── vuln_tools.py        # 漏洞检测
├── payload_tools.py     # Payload 生成
├── session_tools.py     # 会话管理
├── task_tools.py        # 任务队列
├── cve_tools.py         # CVE 情报
├── ai_tools.py          # AI 决策
├── pentest_tools.py     # 渗透测试
├── external_tools.py    # 外部工具集成
├── pipeline_tools.py    # 流水线工具
└── web_scan_tools.py    # Web 扫描工具
```

### 2.2 核心模块

```
core/
├── tool_registry.py     # 工具注册表
├── session_manager.py   # 会话管理器
├── c2/                  # C2 通道
├── evasion/             # 免杀混淆
├── stealth/             # 流量混淆
├── exploit/             # 漏洞利用
├── persistence/         # 持久化
├── credential/          # 凭证提取
├── ad/                  # AD 域渗透
└── cve/                 # CVE 情报引擎
```

## 3. 已识别的问题

### 3.1 架构问题

1. **依赖地狱**: 40+ 依赖但部分未使用 (openai/anthropic/langchain/redis/mongodb)
2. **模块职责混乱**: 声称"纯 Python"但依赖外部工具 (nmap/nikto/metasploit)
3. **代码重复**: 130+ 工具存在大量重复逻辑

### 3.2 配置不一致

1. **代理配置冲突**: `_common.py` 使用 `url` 字段,`config_tools.py` 使用 `http/https` 字段
2. **ToolRegistry 空转**: MCP 工具未同步到 Registry,导致 `registry_stats` 返回空
3. **字典路径 Linux 偏向**: 默认路径 `/usr/share/...`,Windows 用户无法使用
4. **文档引用缺失**: 引用 `docs/Web安全能力分析与优化方案.md` 但目录不存在

### 3.3 安全问题

1. **危险功能缺乏保护**: C2/持久化/免杀功能无授权验证
2. **错误处理粗糙**: 大量 `except Exception` 捕获所有异常
3. **硬编码敏感信息**: 临时文件未安全清理

### 3.4 性能问题

1. **异步实现不完整**: 大部分工具仍是同步阻塞
2. **任务队列容量有限**: 仅 3 个 worker
3. **无超时/重试/熔断机制**

## 4. 优化方案

### 4.1 已完成的优化 (v2.7.1)

#### P0: 修复代理配置冲突 ✅
- 统一 `PROXY_CONFIG` 结构为 `{"enabled": bool, "http": str, "https": str}`
- 移除 `config_tools.py` 中重复的 `get_proxies()` 函数
- 文件: `tools/_common.py:54-58`

#### P1: 修复 ToolRegistry 空转 ✅
- 在 `mcp_stdio_server.py` 中添加工具同步逻辑
- 将 MCP 注册的工具同步到 ToolRegistry
- 修复 `registry_stats/registry_search` 返回空的问题
- 文件: `mcp_stdio_server.py:40-59`

#### P2: 修复字典路径 Linux 偏向 ✅
- 将字典路径改为项目内相对路径
- 从 `/usr/share/...` 改为 `wordlists/*.txt`
- 支持 Windows/Linux/macOS 跨平台
- 文件: `config/config.yaml:50-55`

#### P3: 补充缺失的文档目录 ✅
- 创建 `docs/` 目录
- 添加本文档 `Web安全能力分析与优化方案.md`

### 4.2 待优化项 (Roadmap)

#### 短期优化 (v2.8)

1. **依赖清理**
   - 移除未使用的 AI 库 (openai/anthropic/langchain)
   - 移除未使用的数据库库 (redis/mongodb/sqlalchemy)
   - 保留核心依赖: requests/aiohttp/paramiko/dnspython

2. **测试覆盖**
   - 为核心工具添加单元测试
   - 集成 pytest + coverage
   - 目标覆盖率: 60%+

3. **错误处理规范**
   - 定义统一的错误类型
   - 避免 `except Exception`
   - 添加错误日志

#### 中期优化 (v2.9)

1. **异步改造**
   - 核心扫描工具改为 async/await
   - 使用 aiohttp 替代 requests
   - 提升并发性能

2. **模块解耦**
   - 外部工具作为可选插件
   - 核心引擎与工具适配器分离
   - 支持动态加载

3. **安全加固**
   - 添加授权中间件
   - 实现审计日志
   - 敏感操作二次确认

#### 长期优化 (v3.0)

1. **架构重构**
   - 统一扫描器基类
   - 插件化架构
   - 微服务化部署

2. **AI 能力增强**
   - 真正的 AI 决策引擎 (非规则引擎)
   - 自适应 Payload 生成
   - 智能攻击链规划

3. **企业级特性**
   - 分布式扫描
   - 任务调度系统
   - Web 管理界面

## 5. Web 扫描工具设计 (6.1 节)

### 5.1 攻面发现 (web_discover)

**功能**:
- 爬取目标网站
- 提取表单/链接/API 端点
- 识别注入点

**实现**: `tools/web_scan_tools.py`

### 5.2 编排式扫描 (web_scan)

**功能**:
- 自动发现注入点
- 执行 SQLi/XSS/SSRF 等检测
- 支持高级扫描 (CSRF/XXE/反序列化)

**模式**:
- `quick`: 快速扫描 (SQLi/XSS)
- `standard`: 标准扫描 (+ SSRF/命令注入)
- `deep`: 深度扫描 (+ CSRF/XXE/反序列化)

## 6. 贡献指南

### 6.1 添加新工具

1. 在 `tools/` 或 `modules/` 下实现工具函数
2. 使用 `@mcp.tool()` 装饰器注册
3. 在对应的 `register_*_tools()` 函数中注册
4. 添加单元测试

### 6.2 代码规范

- 跨平台兼容: 使用 `os.path.join()` / `pathlib.Path`
- 编码规范: 文件操作指定 `encoding='utf-8'`
- 错误处理: 使用具体异常类型
- 异步兼容: 使用 Python 3.10+ asyncio API

## 7. 参考资料

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [MCP Protocol](https://modelcontextprotocol.io/)
- [项目 README](../README.md)
- [CLAUDE.md](../CLAUDE.md)

---

**文档版本**: v2.7.1
**最后更新**: 2026-01-12
**维护者**: AutoRedTeam-Orchestrator Team
