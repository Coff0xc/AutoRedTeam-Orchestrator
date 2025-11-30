# 🔥 AutoRedTeam-Orchestrator

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux"/>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/MCP-Protocol-00ADD8?style=for-the-badge" alt="MCP"/>
  <img src="https://img.shields.io/badge/Tools-60+-FF6B6B?style=for-the-badge" alt="Tools"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

<p align="center">
  <b>🤖 AI驱动的自动化渗透测试框架 | 基于 Model Context Protocol (MCP) 架构</b>
</p>

---

## 📖 简介

**AutoRedTeam-Orchestrator** 是一个集成了 **60+ 安全工具** 的智能化渗透测试平台。通过 MCP 协议与 AI 编辑器（Windsurf / Cursor / Claude Desktop）无缝集成，实现 **AI 驱动的自动化红队作业**。

只需用自然语言描述目标，AI 就能自动选择工具、执行侦察、发现漏洞、推荐攻击路径。

### 🎯 为什么选择这个项目？

- ✅ **开箱即用** - 一键安装所有依赖工具
- ✅ **AI 原生** - 专为 LLM 设计的工具接口
- ✅ **全流程覆盖** - 从侦察到漏洞利用完整链路
- ✅ **实战导向** - 内置 Shiro/Log4j/Fastjson 等实战 Payload

---

## ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🤖 **AI 智能驱动** | 基于 LLM 的智能侦察、攻击路径规划、漏洞验证 |
| 🔍 **全自动侦察** | 一键完成子域名、端口、指纹、WAF、漏洞全流程扫描 |
| ☢️ **Nuclei 集成** | 11997+ 漏洞检测模板，覆盖最新 CVE |
| 💉 **Payload 库** | 内置 Shiro/Log4j/Fastjson/SQLi/XSS/RCE 实战 Payload |
| 🧠 **组件识别** | 自动识别 Web 技术栈并推荐对应 Payload |
| 📊 **智能报告** | 自动生成 HTML/Markdown/JSON 格式报告 |
| 🔗 **MCP 协议** | 原生支持 Windsurf/Cursor/Claude Desktop |

---

## 🛠️ 工具清单

### 🔍 侦察模块 (Reconnaissance)

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 🔥 智能打点 | `auto_recon` | AI驱动的全自动化渗透测试 |
| ⚡ 快速侦察 | `quick_recon` | 一键执行基础信息收集 |
| 🧠 深度侦察 | `intelligent_recon` | 包含JS分析的智能深度侦察 |
| 🔄 完整流程 | `complete_recon_workflow` | 10阶段全流程自动化侦察 |
| 🌐 子域名枚举 | `subdomain_enum` | Subfinder 子域名发现 |
| 📡 DNS枚举 | `dns_enum` | DNS 记录查询 (A/AAAA/MX/NS/TXT) |
| 🔍 端口扫描 | `nmap_scan` | Nmap 端口与服务识别 |
| 📋 Whois查询 | `whois_lookup` | 域名/IP 注册信息查询 |
| 🌍 TheHarvester | `theharvester` | 邮箱、子域名等 OSINT 收集 |
| 🔎 Google Dork | `google_dork` | 生成高级搜索语法 |

### ☢️ 漏洞扫描 (Vulnerability Scanning)

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| ☢️ Nuclei全量 | `nuclei_full` / `nuclei_complete_scan` | 11997+ 模板完整扫描 |
| 🎯 CVE专项 | `nuclei_cve` | 针对性 CVE 漏洞扫描 |
| 💣 深度漏扫 | `deep_vuln_scan` | Shiro/Log4j/SQL注入 检测 |
| 🔬 Nikto扫描 | `nikto_scan` | Web 服务器漏洞扫描 |
| ⚡ XSS扫描 | `xss_scan` | XSS 漏洞自动检测 |
| 💉 SQL注入 | `sqli_test` | SQLMap 自动化检测 |
| 🔐 SSL扫描 | `sslscan` / `testssl` | SSL/TLS 配置安全检测 |
| ✅ 漏洞验证 | `verify_vuln` | 自动验证漏洞真实性 |

### 🔎 指纹识别 (Fingerprinting)

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 🔎 Web指纹 | `whatweb` | Web 技术栈识别 |
| 🛡️ WAF检测 | `wafw00f` | Web 应用防火墙识别 |
| 🧩 组件识别 | `identify_tech` | 智能组件识别 + Payload 推荐 |
| 🌐 HTTP探测 | `httpx_probe` | HTTP 服务批量探测 |
| 🛡️ WAF绕过 | `waf_bypass_test` | 检测 WAF 并提供绕过建议 |

### 📁 目录扫描 (Directory Bruteforce)

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 📁 目录扫描 | `dir_scan` | Gobuster 目录发现 |
| ⚡ Ffuf | `ffuf` | 快速 Web Fuzzer |
| 🔨 Gobuster | `gobuster` | 目录/DNS/VHost 爆破 |

### 💉 漏洞利用 (Exploitation)

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 💉 获取Payload | `get_payloads` | SQLi/XSS/LFI/RCE/SSRF/XXE Payload |
| 📚 Payload库 | `query_payload_library` | 查询完整 Payload 库 |
| 🎯 获取EXP | `get_exploit` | CVE/框架/中间件漏洞利用代码 |
| 📋 列出EXP | `list_exploits` | 列出所有可用漏洞利用模板 |
| 🐚 反弹Shell | `reverse_shell` | 生成 Bash/Python/PHP/NC/PowerShell |
| ⚔️ MSF载荷 | `msfvenom` | Metasploit Payload 生成 |
| 🔍 Searchsploit | `searchsploit` | Exploit-DB 漏洞搜索 |
| 🔍 MSF搜索 | `msf_search` | Metasploit 模块搜索 |
| 🔑 默认口令 | `default_credential_test` | OA/CMS 默认口令检测 |
| 📄 SQLi Payload | `sqli_payload` | 生成 SQL 注入 Payload |

### 📜 JS分析 (JavaScript Analysis)

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 📜 JS源码分析 | `js_source_analysis` | API端点/敏感信息/Webpack还原 |

### 🔐 密码攻击 (Password Attacks)

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 🔓 密码爆破 | `brute_force` | SSH/FTP/MySQL/RDP/SMB 爆破 |
| 🔨 CrackMapExec | `crackmapexec` | 网络渗透和后渗透 |

### 🐧 后渗透 (Post Exploitation)

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 🐧 LinPEAS | `linpeas` | Linux 权限提升枚举 |
| 🪟 WinPEAS | `winpeas` | Windows 权限提升枚举 |
| 📋 LinEnum | `linenum` | Linux 枚举脚本 |
| 🪟 Windows枚举 | `windows_enum` | Windows 系统信息收集 |
| 💡 内核漏洞 | `linux_exploit_suggester` | Linux 内核漏洞建议 |

### ☁️ 云安全 (Cloud Security)

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| ☁️ AWS枚举 | `aws_enum` | AWS 资源枚举 |
| ☁️ Azure枚举 | `azure_enum` | Azure 资源枚举 |
| 🪣 S3扫描 | `s3_scanner` | S3 存储桶权限检测 |
| ☸️ K8s扫描 | `kube_hunter` | Kubernetes 安全扫描 |

### 🔧 网络服务 (Network Services)

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 📁 SMB枚举 | `smb_enum` | SMB 共享和用户枚举 |
| 📡 SNMP Walk | `snmp_walk` | SNMP 信息收集 |
| 📋 LDAP枚举 | `ldap_enum` | LDAP 信息收集 |
| 🔐 SSH审计 | `ssh_audit` | SSH 服务器安全审计 |
| 🔄 Zone Transfer | `zone_transfer` | DNS 区域传送测试 |
| 🧠 智能服务分析 | `smart_service_scan` | 根据端口自动选择扫描策略 |

### 📊 报告与工具 (Utilities)

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 📊 生成报告 | `generate_report` | 生成 JSON/HTML/Markdown 报告 |
| 📈 Payload统计 | `payload_stats` | 查看 Payload 库统计信息 |
| 🔧 系统检查 | `system_check` | 检查所有工具可用性 |
| 🛠️ 工具推荐 | `recon_tools_recommend` | 根据场景推荐最佳工具组合 |
| 🔍 CVE搜索 | `cve_search` | 搜索 CVE 漏洞信息 |
| 🤖 AI攻击规划 | `ai_attack_plan` | AI 生成攻击计划 |

---

## 📦 安装

### 前置要求

- **操作系统**: Kali Linux 2023+ (推荐) / Ubuntu / Debian
- **Python**: 3.10+
- **权限**: 部分工具需要 root 权限

### 快速安装

```bash
# 1. 克隆仓库
git clone https://github.com/YOUR_USERNAME/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. 运行安装脚本 (自动安装所有依赖工具)
chmod +x setup.sh
sudo ./setup.sh

# 3. 安装 Python 依赖
pip install -r requirements.txt

# 4. 复制配置文件
cp config/config.yaml.example config/config.yaml
```

### 手动安装依赖工具

```bash
sudo apt update && sudo apt install -y \
    nmap nikto gobuster ffuf sqlmap \
    whatweb wafw00f dnsutils whois \
    smbclient snmp hydra seclists

# 安装 Go 工具
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 更新 Nuclei 模板
nuclei -update-templates
```

---

## 🚀 使用方法

### 方式一：作为 MCP 服务器（推荐）

#### 1. 配置 Windsurf

运行自动配置脚本：
```bash
./setup_windsurf_mcp.sh
```

或手动编辑 `~/.codeium/windsurf/mcp_config.json`：
```json
{
  "mcpServers": {
    "ai-redteam": {
      "command": "python",
      "args": ["/path/to/ai-recon-mcp/main.py"]
    }
  }
}
```

#### 2. 配置 Cursor

编辑 `~/.cursor/mcp.json`：
```json
{
  "mcpServers": {
    "ai-redteam": {
      "command": "python",
      "args": ["/path/to/ai-recon-mcp/main.py"]
    }
  }
}
```

#### 3. 配置 Claude Desktop

编辑 `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) 或 `%APPDATA%\Claude\claude_desktop_config.json` (Windows)：
```json
{
  "mcpServers": {
    "ai-redteam": {
      "command": "python",
      "args": ["/path/to/ai-recon-mcp/main.py"]
    }
  }
}
```

#### 4. 开始使用

在 AI 编辑器中用自然语言对话：

```
对 example.com 进行全面安全侦察
```

```
扫描 192.168.1.0/24 的开放端口和服务
```

```
检测 https://target.com 是否存在 Log4j 和 Shiro 漏洞
```

```
给我生成针对 MySQL 的 SQL 注入 Payload
```

### 方式二：独立 HTTP 服务器

```bash
python main.py -H 0.0.0.0 -p 5000
```

访问 `http://localhost:5000/tools` 查看所有可用工具。

---

## ⚙️ 配置说明

编辑 `config/config.yaml`：

```yaml
# 服务器配置
server:
  host: "127.0.0.1"
  port: 5000

# AI配置 (可选，用于智能分析)
ai:
  provider: "openai"      # openai / anthropic / local
  model: "gpt-4"
  api_key: ""             # 或使用环境变量 OPENAI_API_KEY

# 扫描配置
scanning:
  default_threads: 10     # 默认线程数
  default_delay: 100      # 默认延迟 (ms)
  rate_limit: 150         # 速率限制

# OSINT API密钥 (可选)
api_keys:
  shodan: ""              # SHODAN_API_KEY
  censys_id: ""           # CENSYS_API_ID
  censys_secret: ""       # CENSYS_API_SECRET
  virustotal: ""          # VT_API_KEY

# 字典路径
wordlists:
  directories: "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
  passwords: "/usr/share/wordlists/rockyou.txt"
  subdomains: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
```

---

## 📁 项目结构

```
AutoRedTeam-Orchestrator/
├── main.py                     # 🚀 主入口
├── mcp_tools.py                # 🔧 MCP 工具定义 (60+ tools)
├── auto_recon.py               # 🤖 智能侦察引擎
├── requirements.txt            # 📦 Python 依赖
├── setup.sh                    # ⚙️ 安装脚本
├── setup_windsurf_mcp.sh       # 🔗 Windsurf 配置脚本
│
├── config/
│   ├── config.yaml.example     # 配置模板
│   └── config.yaml             # 实际配置 (gitignore)
│
├── core/
│   ├── mcp_server.py           # MCP 服务器核心
│   ├── ai_engine.py            # AI 引擎集成
│   ├── attack_chain.py         # 攻击链规划
│   ├── intelligent_recon_engine.py  # 智能侦察引擎
│   ├── deep_vuln_scanner.py    # 深度漏扫引擎
│   ├── mega_payload_library.py # Payload 库
│   └── session_manager.py      # 会话管理
│
├── modules/
│   ├── recon/                  # 🔍 侦察模块
│   │   ├── nmap_tools.py
│   │   ├── subdomain_tools.py
│   │   ├── dns_tools.py
│   │   └── osint_tools.py
│   │
│   ├── vuln_scan/              # ☢️ 漏洞扫描
│   │   ├── nuclei_tools.py
│   │   ├── nikto_tools.py
│   │   └── ssl_tools.py
│   │
│   ├── web_attack/             # 💉 Web 攻击
│   │   ├── sqli_tools.py
│   │   ├── xss_tools.py
│   │   ├── dir_tools.py
│   │   └── fuzzing_tools.py
│   │
│   ├── exploit/                # 🎯 漏洞利用
│   │   ├── msf_tools.py
│   │   └── reverse_shell.py
│   │
│   ├── post_exploit/           # 🐧 后渗透
│   │   ├── privesc_tools.py
│   │   └── enum_tools.py
│   │
│   ├── cloud/                  # ☁️ 云安全
│   │   ├── aws_tools.py
│   │   ├── azure_tools.py
│   │   └── k8s_tools.py
│   │
│   ├── network/                # 🔧 网络服务
│   │   ├── smb_tools.py
│   │   ├── brute_force.py
│   │   └── service_tools.py
│   │
│   ├── payload_library.py      # Payload 管理
│   ├── nuclei_integration.py   # Nuclei 集成
│   └── vuln_verifier.py        # 漏洞验证
│
├── payloads/
│   └── complete_payload_db.json  # 完整 Payload 数据库
│
├── utils/
│   ├── logger.py               # 日志工具
│   ├── report_generator.py     # 报告生成
│   ├── terminal_output.py      # 终端输出美化
│   └── tool_checker.py         # 工具检查
│
├── data/                       # 会话数据
├── logs/                       # 日志文件
└── reports/                    # 扫描报告输出
```

---

## 💡 使用示例

### 快速侦察

```python
# 在 AI 编辑器中直接对话
"对 target.com 进行快速侦察"

# 或调用工具
quick_recon(target="target.com", include_subdomains=True, include_ports=True)
```

### 深度漏洞扫描

```python
# Shiro/Log4j/SQL注入 检测
deep_vuln_scan(target="https://target.com", dnslog="xxx.dnslog.cn")

# Nuclei 全量扫描
nuclei_complete_scan(target="https://target.com", preset="full")
```

### 获取 Payload

```python
# SQL 注入 Payload
get_payloads(vuln_type="sqli", dbms="mysql", category="union")

# 查询 Payload 库
query_payload_library(payload_type="shiro")
query_payload_library(payload_type="log4j")
```

### 生成反弹 Shell

```python
reverse_shell(type="bash", lhost="10.0.0.1", lport=4444)
reverse_shell(type="python", lhost="10.0.0.1", lport=4444)
```

---

## 🔒 安全声明

⚠️ **重要提示**

1. 本工具**仅供授权的安全测试和研究使用**
2. 在使用前，请确保已获得目标系统所有者的**书面授权**
3. 未经授权对系统进行渗透测试是**违法行为**
4. 开发者不对任何滥用行为承担责任
5. 请遵守当地法律法规和道德准则

---

## 🗺️ 路线图

- [x] 60+ 安全工具集成
- [x] Nuclei 11997+ 模板支持
- [x] Shiro/Log4j/Fastjson Payload 库
- [x] 智能侦察引擎
- [x] MCP 协议支持
- [ ] Web UI 界面
- [ ] 分布式扫描支持
- [ ] 更多云平台支持 (GCP/Alibaba Cloud)
- [ ] AI 自动化漏洞利用

---

## 📄 许可证

本项目采用 [MIT License](LICENSE)

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

---

## 📮 联系方式

如有问题，请提交 [Issue](https://github.com/YOUR_USERNAME/AutoRedTeam-Orchestrator/issues)

---

<p align="center">
  <b>⭐ 如果这个项目对你有帮助，请给一个 Star！</b>
</p>
