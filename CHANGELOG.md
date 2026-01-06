# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.0] - 2026-01-06

### Added

#### CVE情报管理系统
- **YAML PoC引擎**: Nuclei兼容的PoC模板解析和执行
- **CVE多源同步**: 支持NVD、Nuclei、Exploit-DB三大数据源
- **CVE订阅管理器**: 关键词/严重性/产品过滤订阅
- **AI PoC生成器**: 基于CVE描述自动生成PoC模板

#### C2隐蔽通信
- **WebSocket隧道**: XOR/AES加密的WebSocket隧道通信
- **分块传输器**: 大文件分块传输和重组
- **代理链执行器**: 多级代理链路由

#### 前端安全分析
- **JS分析引擎**: API端点、路由、敏感信息提取
- **Source Map泄露检测**: 自动检测.map文件泄露

#### MCP工具
- 新增12个MCP工具（CVE/隧道/JS分析）
- v2.5工具注册模块

### Changed
- 工具总数从80+提升到100+
- 优化异步扫描性能

### Security
- 修复130个bare except语句
- 更新asyncio API兼容Python 3.10+
- 移除冗余的旧版服务器文件
- 清理过时的TYPE_CHECKING导入

## [2.4.0] - 2026-01-05

### Added
- ATT&CK全流程覆盖
- 持久化模块（Windows/Linux）
- 凭证收集模块
- AD域渗透模块

## [2.3.0] - 2026-01-04

### Added
- Red Team横向移动工具（SMB/SSH/WMI）
- C2通信模块（Beacon/DNS隧道/HTTP隧道）
- 混淆免杀模块（XOR/AES/Shellcode加载器）
- 隐蔽通信模块（JA3伪造/代理池）
- 纯Python漏洞利用（SQLi/端口扫描）

### Security
- SSL验证统一配置
- 危险字符过滤增强
- CI依赖扫描集成

## [2.2.0] - 2026-01-03

### Added
- OOB带外检测
- 会话管理器
- Payload变异引擎
- 统计学漏洞验证

## [2.1.0] - 2026-01-02

### Added
- AI智能化模块
- 性能监控
- 智能缓存
- 任务队列

## [2.0.0] - 2026-01-01

### Added
- MCP协议支持
- 80+安全工具集成
- 2000+ Payload库
- Nuclei模板集成

---

For older versions, see [GitHub Releases](https://github.com/Coff0xc/AutoRedTeam-Orchestrator/releases).
