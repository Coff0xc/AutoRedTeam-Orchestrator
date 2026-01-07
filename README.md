# 🔥 AutoRedTeam-Orchestrator
[English](README_EN.md)

> AI 驱动的自动化红队编排框架，跨平台支持 Linux / Windows，集成 130+ 安全工具与 2000+ Payload。原生 MCP，可在 Windsurf / Cursor / Claude Desktop / Kiro 中直接调用。

<p align="center">
  <img src="https://img.shields.io/badge/OS-Linux%20%26%20Windows-557C94?style=for-the-badge&logo=linux&logoColor=white" alt="Cross Platform"/>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/MCP-Native-00ADD8?style=for-the-badge" alt="MCP"/>
  <img src="https://img.shields.io/badge/Tools-130+-FF6B6B?style=for-the-badge" alt="Tools"/>
  <img src="https://img.shields.io/badge/Payloads-2000+-orange?style=for-the-badge" alt="Payloads"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

> 当前版本：2.6.0（详见 CHANGELOG 与 VERSION）

---

## 🧭 项目概览（不精简版）
- AI 原生：智能指纹识别、攻击链规划、历史反馈学习、自动选工具与 Payload；通过 `modules/ai_decision_engine.py`、`core/attack_chain.py` 驱动。
- 全流程自动化：子域/端口/WAF/指纹 → 漏洞发现/验证 → 报告，核心逻辑见 `auto_recon.py`、`core/complete_recon_toolkit.py`、`modules/async_scanner.py`。
- 红队增强：横向移动（SMB/SSH/WMI）、C2（Beacon/DNS/HTTP/WebSocket）、混淆免杀、隐蔽通信、持久化、凭证获取、AD 攻击，分布于 `core/lateral/*`、`core/c2/*`、`core/evasion/*`、`core/stealth/*`、`core/persistence/*`、`core/credential/*`、`core/ad/*`。
- 安全扩展：API 安全（JWT/CORS/Headers/GraphQL/WebSocket）、供应链（CycloneDX/SPDX SBOM、OSV 审计、CI/CD 扫描）、云原生（K8s/gRPC），对应 `modules/api_security_*`、`modules/supply_chain_*`、`modules/cloud_security_*`。
- 性能可靠：异步扫描/HTTP 连接池/任务队列/多层缓存/性能监控/响应过滤，见 `modules/async_http_pool.py`、`modules/async_scanner.py`、`utils/task_queue.py`、`modules/smart_cache.py`、`modules/performance_monitor.py`、`core/response_filter.py`。
- 资源丰富：Nuclei 11997+ 模板（`modules/vuln_scan/nuclei_tools.py`）、2000+ Payload（`modules/mega_payloads.py`、`modules/smart_payload_engine.py`）、JS 分析器（`modules/js_analyzer.py`）、AI PoC 生成与 CVE 多源同步（`core/cve/*`）。

---

## 🛠️ 功能矩阵（完整列举）
### 侦察 Recon
- 全自动/深度侦察：`auto_recon.py`、`core/complete_recon_toolkit.py`、`modules/recon/web_recon_tools.py`
- 端口/服务：`modules/recon/nmap_tools.py`、`modules/network/service_tools.py`
- 子域/DNS/OSINT：`modules/recon/subdomain_tools.py`、`modules/recon/dns_tools.py`、`modules/recon/osint_tools.py`
- WAF/指纹：`modules/component_fingerprint.py`、`modules/vuln_scan/vuln_search.py`
- JS/前端分析：`modules/js_analyzer.py`

### 漏洞扫描
- Nuclei/Nikto/SSL：`modules/vuln_scan/nuclei_tools.py`、`modules/vuln_scan/nikto_tools.py`、`modules/vuln_scan/ssl_tools.py`
- 深度漏洞（Shiro/Log4j/SQLi/XSS 等）：`modules/enhanced_detector_tools.py`、`modules/vuln_scan/*`、`modules/web_attack/xss_tools.py`、`modules/web_attack/sqli_tools.py`
- XSS/XXE/Fuzz：`modules/web_attack/advanced_xss.py`、`modules/web_attack/xxe_tools.py`、`modules/web_attack/fuzzing_tools.py`

### API / 供应链 / 云
- API 安全：`modules/api_security_tools.py`、`modules/api_security/graphql_security.py`、`modules/api_security/websocket_security.py`、`modules/enhanced_detectors/*`（JWT/CORS/Headers）
- 供应链：`modules/supply_chain_tools.py`、`modules/supply_chain/sbom_generator.py`、`modules/supply_chain/dependency_scanner.py`、`modules/supply_chain/cicd_security.py`
- 云安全：`modules/cloud_security_tools.py`、`modules/cloud_security/kubernetes_enhanced.py`、`modules/cloud_security/grpc_security.py`、`modules/cloud/*`

### 漏洞利用 / Payload
- Payload 查询与生成：`modules/mega_payloads.py`、`modules/smart_payload_engine.py`、`modules/smart_payload_selector.py`
- EXP/PoC：`modules/exploit_templates.py`、`modules/exploit/reverse_shell.py`、`modules/exploit/msf_tools.py`
- 纯 Python SQLi/扫描：`core/exploit/pure_sqli.py`、`core/exploit/pure_scanner.py`

### 红队行动 / 后渗透
- 横向移动：`core/lateral/smb_lateral.py`、`core/lateral/ssh_lateral.py`、`core/lateral/wmi_lateral.py`
- C2 与隐蔽通信：`core/c2/beacon.py`、`core/c2/tunnels.py`、`core/c2/websocket_tunnel.py`、`core/stealth/*`
- 混淆/免杀：`core/evasion/payload_obfuscator.py`
- 持久化：`core/persistence/windows_persistence.py`、`core/persistence/linux_persistence.py`、`core/persistence/webshell_manager.py`
- 凭证与 AD：`core/credential/credential_dumper.py`、`core/credential/password_finder.py`、`core/ad/ad_enum.py`、`core/ad/kerberos_attack.py`
- 提权与主机枚举：`modules/post_exploit/privesc_tools.py`、`modules/post_exploit/enum_tools.py`

### 报告 / 调度 / 监控
- 报告：`utils/report_generator.py`，支持 JSON/HTML/PDF/Markdown（结合模板与前端）
- 任务队列：`utils/task_queue.py`
- 性能监控：`modules/performance_monitor.py`
- 缓存系统：`modules/smart_cache.py`
- 输出美化：`utils/terminal_output.py`、`utils/terminal_display.py`

### CVE 子系统
- 多源同步：`core/cve/update_manager.py`（NVD/Nuclei/Exploit-DB）
- 订阅过滤：`core/cve/subscription_manager.py`
- AI PoC 生成：`core/cve/ai_poc_generator.py`
- MCP 接入：`core/cve/mcp_integration.py`

---

## ⚡ 快速开始（Linux / Windows）
### 1) 克隆与依赖
```bash
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# Linux / WSL 推荐
chmod +x setup.sh
sudo ./setup.sh                 # 安装外部工具
pip install -r requirements.txt # Python 依赖
cp config/config.yaml.example config/config.yaml
# nuclei -update-templates      # 可选：更新模板
```

Windows：
- 运行 `pip install -r requirements.txt`。
- 外部工具（nmap/nuclei/subfinder 等）需手动安装或在 WSL 中执行；MCP 服务器与纯 Python 引擎（如纯 SQLi、CVE 系统）可在 Windows 直接运行。

### 2) 快速体验（示例命令）
```bash
python auto_recon.py https://example.com            # 一键智能侦察
python mcp_stdio_server.py                          # 作为 MCP 服务器
python core/cve/update_manager.py sync              # CVE 多源同步
python core/cve/update_manager.py search "Log4j"    # CVE 搜索
python core/cve/ai_poc_generator.py --help          # AI PoC 生成
```

---

## 🚀 使用方式
### MCP（推荐，跨平台）
```bash
./setup_windsurf_mcp.sh   # 自动写入 Windsurf MCP 配置
# Cursor/Claude/Kiro 可参照 MCP_CONFIG_GUIDE.md 配置 mcp_stdio_server.py
```
在编辑器对话中直接下发自然语言：
- "对 example.com 做完整侦察并输出报告"
- "扫描 192.168.1.0/24 开放端口并识别服务"
- "检查 https://target.com 是否存在 Log4j/Shiro"
- "对目标 API 执行 JWT 安全扫描"
- "生成项目的 SBOM 并扫描依赖漏洞"
- "检测 K8s 集群中的特权容器"

### 独立 HTTP 服务
```bash
python main.py -H 0.0.0.0 -p 5000
# 浏览 http://localhost:5000/tools 查看工具列表
```

---

## 🔧 配置示例（config/config.yaml）
```yaml
server: {host: "127.0.0.1", port: 5000}
ai: {provider: "openai", model: "gpt-4", api_key: ""}
scanning: {default_threads: 10, default_delay: 100, rate_limit: 150}
api_keys: {shodan: "", censys_id: "", censys_secret: "", virustotal: ""}
wordlists:
  directories: "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
  passwords: "/usr/share/wordlists/rockyou.txt"
  subdomains: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
```

---

## 🗂️ 目录速览
```
main.py / mcp_stdio_server.py / auto_recon.py / mcp_tools.py
core/
  attack_chain.py, tool_chain.py, intelligent_recon_engine.py, complete_recon_toolkit.py
  response_filter.py, session_manager.py, mega_payload_library.py, tool_registry.py
  c2/          - C2通信 (Beacon/DNS/HTTP/WebSocket隧道)
  lateral/     - 横向移动 (SMB/SSH/WMI)
  evasion/     - 混淆免杀
  stealth/     - 隐蔽通信
  persistence/ - 持久化
  credential/  - 凭证获取
  ad/          - AD域渗透
  cve/         - CVE情报与PoC引擎
  exploit/     - 漏洞利用
modules/
  async_scanner.py, async_http_pool.py, ai_decision_engine.py, adaptive_payload_engine.py
  performance_monitor.py, smart_cache.py, optimization_tools.py
  api_security/    - JWT/CORS/GraphQL/WebSocket安全
  supply_chain/    - SBOM/依赖扫描/CI-CD安全
  cloud_security/  - K8s/gRPC安全
  enhanced_detectors/ - 高级漏洞检测器
  recon/, vuln_scan/, web_attack/, exploit/, network/, post_exploit/
  mega_payloads.py, smart_payload_selector.py, smart_payload_engine.py, js_analyzer.py
payloads/complete_payload_db.json
utils/ (report_generator.py, task_queue.py, tool_checker.py, terminal_output.py)
config/, templates/, poc-templates/, scripts/, tests/
```

---

## ✨ 版本亮点

### v2.6.0（2026-01-07）- API安全与云原生安全增强
- **API安全增强**：
  - JWT 高级测试：None算法/算法混淆/弱密钥/KID注入
  - CORS 深度检测：30+ Origin 绕过技术
  - 安全头评分：基于 OWASP 指南的加权评分系统
  - GraphQL 安全：内省/批量DoS/深层嵌套/别名重载检测
  - WebSocket 安全：Origin绕过/CSWSH/认证绕过/压缩攻击
- **供应链安全**：
  - SBOM 生成：支持 CycloneDX/SPDX 标准格式
  - 依赖漏洞扫描：集成 OSV API，支持 PyPI/npm/Go/Maven
  - CI/CD 安全扫描：检测 GitHub Actions/GitLab CI/Jenkins 配置风险
- **云原生安全**：
  - K8s 安全审计：特权容器/hostPath/RBAC/NetworkPolicy/Secrets 检测
  - K8s Manifest 扫描：YAML 配置文件安全分析
  - gRPC 安全测试：反射API/TLS配置/认证绕过检测
- **工具总数**：130+（新增 40+ API/供应链/云原生工具）

### v2.5.0（2026-01-06）
- CVE 情报与 PoC：多源同步（NVD/Nuclei/Exploit-DB）、订阅过滤、AI PoC 生成、YAML PoC 引擎，新增多项 MCP 工具。
- C2 隐蔽通信：WebSocket 隧道、分块传输、代理链。
- 前端安全：JS 分析、Source Map 泄露检测。
- 工具扩展：100+ 工具，MCP 注册增强。
- 性能与安全：异步扫描优化，清理裸 `except`，Python 3.10+ 兼容性修复。

---

## 🛤️ 路线图
- [ ] Web UI
- [ ] 分布式扫描
- [ ] 更多云平台（GCP/阿里云）
- [ ] AI 自动化漏洞利用
- [x] Red Team 横向/C2/免杀/隐蔽/持久化/凭证/AD
- [x] CVE 多源同步与 AI PoC
- [x] API/供应链/云安全扩展
- [x] 性能监控、智能缓存、响应过滤

---

## ⚖️ 合规声明
仅用于授权的安全测试与研究；使用前请取得目标书面授权，遵守当地法律与职业道德。滥用后果自负。

---

## 🤝 贡献与联系
- 欢迎提交 Issue / PR（见 CONTRIBUTING.md、CODE_OF_CONDUCT.md）。
- Discord: https://discord.gg/PtVyrMvB
- Email: Coff0xc@protonmail.com
- Issues: https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues
