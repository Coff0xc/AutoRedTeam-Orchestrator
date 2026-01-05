# 🔥 AutoRedTeam-Orchestrator

**[中文](README.md)** | [English](README_EN.md)

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux"/>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/MCP-Protocol-00ADD8?style=for-the-badge" alt="MCP"/>
  <img src="https://img.shields.io/badge/Tools-80+-FF6B6B?style=for-the-badge" alt="Tools"/>
  <img src="https://img.shields.io/badge/Payloads-2000+-orange?style=for-the-badge" alt="Payloads"/>
  <img src="https://img.shields.io/badge/AI-Powered-blueviolet?style=for-the-badge" alt="AI Powered"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

<p align="center">
  <b>🤖 AI驱动的自动化渗透测试框架 | 基于 Model Context Protocol (MCP) 架构</b>
</p>

---

## 📖 简介

**AutoRedTeam-Orchestrator** 是一个集成了 **80+ 安全工具** 和 **2000+ Payload** 的智能化渗透测试平台。通过 MCP 协议与 AI 编辑器（Windsurf / Cursor / Claude Desktop / Kiro）无缝集成，实现 **AI 驱动的自动化红队作业**。

只需用自然语言描述目标，AI 就能自动选择工具、执行侦察、发现漏洞、推荐攻击路径。

### 🎯 为什么选择这个项目？

- ✅ **开箱即用** - 一键安装所有依赖工具
- ✅ **AI 原生** - 专为 LLM 设计的工具接口
- ✅ **全流程覆盖** - 从侦察到漏洞利用完整链路
- ✅ **实战导向** - 内置 Shiro/Log4j/Fastjson 等实战 Payload
- ✅ **智能选择** - 根据目标指纹自动选择最优 Payload
- ✅ **自动编排** - 工具链自动编排，无需手动调用

---

## ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🤖 **AI 智能驱动** | 基于 LLM 的智能侦察、攻击路径规划、漏洞验证 |
| 🧠 **AI 决策引擎** | 智能攻击推荐、攻击链规划、历史学习优化 |
| ⚡ **异步高性能** | 异步扫描引擎，性能提升 5-10 倍 |
| 🔍 **全自动侦察** | 一键完成子域名、端口、指纹、WAF、漏洞全流程扫描 |
| ☢️ **Nuclei 集成** | 11997+ 漏洞检测模板，覆盖最新 CVE |
| 💉 **Payload 库** | 2000+ Payload，含 SQLi/XSS/NoSQL/GraphQL/WAF绕过 |
| 🧠 **智能选择** | 根据目标指纹自动选择最优 Payload |
| 🔗 **漏洞关联分析** | 自动分析漏洞关联，推荐利用链 |
| 📊 **智能报告** | 自动生成 HTML/PDF/Markdown/JSON 格式报告 |
| 🔗 **MCP 协议** | 原生支持 Windsurf/Cursor/Claude Desktop/Kiro |
| ⚡ **任务队列** | 后台异步执行，支持大规模扫描任务 |
| 📈 **性能监控** | 实时监控工具执行性能，识别瓶颈 |

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
| 📊 生成报告 | `generate_report` | 生成 JSON/HTML/PDF/Markdown 报告 |
| 📈 Payload统计 | `payload_stats` | 查看 Payload 库统计信息 |
| 🔧 系统检查 | `system_check` | 检查所有工具可用性 |
| 🛠️ 工具推荐 | `recon_tools_recommend` | 根据场景推荐最佳工具组合 |
| 🔍 CVE搜索 | `cve_search` | 搜索 CVE 漏洞信息 |
| 🤖 AI攻击规划 | `ai_attack_plan` | AI 生成攻击计划 |

### ⚡ 任务队列 (Task Queue)

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 📤 提交任务 | `task_submit` | 提交后台异步任务 |
| 📋 任务状态 | `task_status` | 查询任务执行状态 |
| ❌ 取消任务 | `task_cancel` | 取消等待中的任务 |
| 📜 任务列表 | `task_list` | 列出所有任务 |

### 🧠 AI 智能化 (AI Intelligence) 🆕

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 🎯 智能攻击建议 | `ai_suggest_attack` | 基于目标特征推荐最优攻击路径 |
| 🔗 攻击链规划 | `ai_attack_chain` | 生成多条可能的攻击路径 |
| 📝 结果记录 | `ai_record_result` | 记录攻击结果用于AI学习 |
| 🧠 智能渗透 | `smart_pentest` | 集成AI决策的智能渗透测试 |

### 📈 性能监控 (Performance) 🆕

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 📊 性能摘要 | `perf_summary` | 获取性能监控摘要 |
| 🔍 瓶颈识别 | `perf_bottlenecks` | 识别性能瓶颈 |
| 📋 工具统计 | `perf_tool_stats` | 获取工具执行统计 |
| 📜 执行记录 | `perf_recent` | 获取最近执行记录 |

### 💾 智能缓存 (Smart Cache) 🆕

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 📊 缓存统计 | `cache_stats` | 获取缓存统计信息 |
| 🧹 清理缓存 | `cache_cleanup` | 清理过期缓存 |
| 🗑️ 清空缓存 | `cache_clear` | 清空指定类型缓存 |

### 🔴 Red Team 横向移动 (Lateral Movement) 🆕

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 🖥️ SMB执行 | `lateral_smb_exec` | SMB远程命令执行 (Pass-the-Hash) |
| 📤 SMB上传 | `lateral_smb_upload` | SMB文件上传到远程主机 |
| 🐧 SSH执行 | `lateral_ssh_exec` | SSH远程命令执行 |
| 🔗 SSH隧道 | `lateral_ssh_tunnel` | SSH端口转发/SOCKS代理 |
| 🪟 WMI执行 | `lateral_wmi_exec` | WMI远程命令执行 |
| 📋 WMI查询 | `lateral_wmi_query` | WMI系统信息查询 |

### 📡 Red Team C2通信 (Command & Control) 🆕

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 📶 Beacon启动 | `c2_beacon_start` | 启动C2 Beacon客户端 |
| 🌐 DNS隧道 | `c2_dns_tunnel` | DNS隧道数据外传 |
| 🔒 HTTP隧道 | `c2_http_tunnel` | HTTP隧道数据外传 |

### 🎭 Red Team 混淆免杀 (Evasion) 🆕

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 🔐 Payload混淆 | `evasion_obfuscate_payload` | XOR/AES/Base64 Payload混淆 |
| 🐍 Python混淆 | `evasion_obfuscate_python` | Python代码变量/字符串混淆 |
| 💉 Shellcode加载 | `evasion_shellcode_loader` | 生成Shellcode加载器 |

### 🥷 Red Team 隐蔽通信 (Stealth) 🆕

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 🌐 隐蔽请求 | `stealth_request` | JA3指纹伪造/浏览器模拟 |
| 🔄 代理池 | `stealth_proxy_pool` | 代理池管理和轮换 |

### ⚔️ Red Team 纯Python漏洞利用 (Pure Python Exploit) 🆕

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 💉 SQLi检测 | `exploit_sqli_detect` | 纯Python SQL注入检测 (无需sqlmap) |
| 📊 SQLi提取 | `exploit_sqli_extract` | SQL注入数据库数据提取 |
| 🔍 端口扫描 | `exploit_port_scan` | 纯Python端口扫描 (无需nmap) |
| 🎯 服务识别 | `exploit_service_detect` | 服务指纹识别 |
| 🌐 网络扫描 | `exploit_network_scan` | 网段存活主机发现 |

### 🎯 Red Team 综合工具 (Combined Tools) 🆕

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 🔍 综合侦察 | `redteam_recon` | 端口+WAF+指纹综合侦察 |
| 🔗 横向链 | `redteam_lateral_chain` | 批量横向移动执行 |

### 🔒 Red Team 持久化 (Persistence) 🆕

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 🪟 Windows持久化 | `persistence_windows` | 注册表/计划任务/服务/WMI/BITS |
| 🐧 Linux持久化 | `persistence_linux` | Crontab/Systemd/Bashrc/SSH/LD_PRELOAD |
| 🐚 Webshell生成 | `persistence_webshell` | PHP/JSP/ASPX/冰蝎/哥斯拉兼容 |

### 🔑 Red Team 凭证收集 (Credential Access) 🆕

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 💾 凭证提取 | `credential_dump` | WiFi/浏览器/注册表/Shadow凭证 |
| 🔍 敏感信息搜索 | `credential_find_secrets` | 密码/API密钥/私钥/Token搜索 |

### 🏰 Red Team AD域渗透 (Active Directory) 🆕

| 工具 | 命令 | 功能描述 |
|------|------|----------|
| 📋 AD枚举 | `ad_enumerate` | 用户/组/计算机/GPO/信任关系 |
| ⚔️ Kerberos攻击 | `ad_kerberos_attack` | AS-REP Roasting/密码喷洒 |
| 🎯 SPN扫描 | `ad_spn_scan` | Kerberoasting目标发现 |

---

## 📦 安装

### 前置要求

- **操作系统**: Kali Linux 2023+ (推荐) / Ubuntu / Debian
- **Python**: 3.10+
- **权限**: 部分工具需要 root 权限

### 快速安装

```bash
# 1. 克隆仓库
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
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
│   ├── tool_chain.py           # 🆕 工具链自动编排
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
│   ├── mega_payloads.py        # 🆕 超级Payload库 (2000+)
│   ├── smart_payload_selector.py  # 🆕 智能Payload选择器
│   ├── ai_decision_engine.py   # 🆕 AI决策引擎
│   ├── async_scanner.py        # 🆕 异步扫描引擎
│   ├── adaptive_payload_engine.py  # 🆕 自适应Payload引擎
│   ├── vuln_correlation_engine.py  # 🆕 漏洞关联分析
│   ├── smart_cache.py          # 🆕 智能缓存系统
│   ├── performance_monitor.py  # 🆕 性能监控
│   ├── async_http_pool.py      # 🆕 异步HTTP连接池
│   ├── optimization_tools.py   # 🆕 优化模块MCP集成
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

- [x] 80+ 安全工具集成
- [x] Nuclei 11997+ 模板支持
- [x] 2000+ Payload 库
- [x] 智能侦察引擎
- [x] MCP 协议支持
- [x] 🆕 智能 Payload 选择器
- [x] 🆕 工具链自动编排
- [x] 🆕 WAF 绕过 Payload (100+)
- [x] 🆕 NoSQL/GraphQL/JSON 注入支持
- [x] 🆕 任务队列系统 (后台异步执行)
- [x] 🆕 PDF 报告格式 (支持中文)
- [x] 🆕 AI 决策引擎 (智能攻击推荐)
- [x] 🆕 异步扫描引擎 (性能提升 5-10x)
- [x] 🆕 漏洞关联分析 (利用链推荐)
- [x] 🆕 智能缓存系统
- [x] 🆕 性能监控模块
- [x] 🆕 Red Team 横向移动 (SMB/SSH/WMI)
- [x] 🆕 C2 通信模块 (Beacon/DNS隧道/HTTP隧道)
- [x] 🆕 混淆免杀模块 (XOR/AES/Shellcode)
- [x] 🆕 隐蔽通信模块 (JA3指纹/代理池)
- [x] 🆕 纯Python漏洞利用 (无需外部工具)
- [x] 🆕 持久化模块 (Windows/Linux/Webshell)
- [x] 🆕 凭证收集模块 (浏览器/WiFi/敏感文件)
- [x] 🆕 AD域渗透模块 (LDAP枚举/Kerberos攻击)
- [ ] Web UI 界面
- [ ] 分布式扫描支持
- [ ] 更多云平台支持 (GCP/Alibaba Cloud)
- [ ] AI 自动化漏洞利用

---

## 📝 更新日志

### v2.5.0 (2026-01-06)

#### 🆕 ATT&CK 全流程覆盖 (持久化/凭证/AD域渗透)

- **持久化模块** (`core/persistence/`)
  - Windows持久化: 注册表Run、计划任务、服务、WMI订阅、启动文件夹、屏保、BITS作业
  - Linux持久化: Crontab、Systemd服务/定时器、Bashrc/Profile、SSH密钥、LD_PRELOAD、init.d、rc.local
  - Webshell生成: PHP/JSP/ASPX/Python多类型、冰蝎/哥斯拉兼容、内存马
  - 新增 MCP 工具: `persistence_windows`, `persistence_linux`, `persistence_webshell`

- **凭证收集模块** (`core/credential/`)
  - 凭证提取: Windows WiFi/凭据管理器/注册表(PuTTY/WinSCP)、Linux Shadow、SSH密钥、Chrome/Firefox密码
  - 敏感信息搜索: 密码/API密钥/私钥/数据库连接/JWT/Webhook URL、Git历史扫描
  - 新增 MCP 工具: `credential_dump`, `credential_find_secrets`

- **AD域渗透模块** (`core/ad/`)
  - LDAP枚举: 用户/组/计算机/SPN/GPO/信任关系、域管理员发现
  - Kerberos攻击: AS-REP Roasting、密码喷洒、用户枚举
  - 新增 MCP 工具: `ad_enumerate`, `ad_kerberos_attack`, `ad_spn_scan`

- **ATT&CK 覆盖率提升至 95%+**
  - TA0003 持久化: 8种Windows技术 + 12种Linux技术
  - TA0006 凭证访问: 8种凭证源 + 敏感文件搜索
  - TA0007 发现: LDAP枚举 + Kerberos用户枚举

### v2.4.0 (2026-01-06)

#### 🆕 Red Team 高级功能 (真实攻防对抗增强)

- **横向移动模块** (`core/lateral/`)
  - SMB横向移动: Pass-the-Hash、文件上传下载、psexec/smbexec
  - SSH横向移动: 密码/密钥认证、端口转发、SOCKS代理
  - WMI横向移动: 远程命令执行、WQL系统查询
  - 新增 MCP 工具: `lateral_smb_exec`, `lateral_ssh_exec`, `lateral_wmi_exec` 等

- **C2通信模块** (`core/c2/`)
  - 轻量级Beacon: HTTP/HTTPS回连、任务分发、结果上报
  - DNS隧道: 数据外传、XOR加密、分块传输
  - ICMP隧道: 隐蔽通道通信
  - HTTP隧道: Body/Cookie/Header隐写
  - 新增 MCP 工具: `c2_beacon_start`, `c2_dns_tunnel`, `c2_http_tunnel`

- **混淆免杀模块** (`core/evasion/`)
  - Payload混淆: XOR/AES/Base64/ROT13/Unicode编码
  - Python代码混淆: 变量重命名、字符串混淆、垃圾代码
  - Shellcode加载器: Windows/Linux加载器生成
  - PowerShell混淆: Base64编码、字符串拼接、反引号混淆
  - 新增 MCP 工具: `evasion_obfuscate_payload`, `evasion_obfuscate_python`, `evasion_shellcode_loader`

- **隐蔽通信模块** (`core/stealth/`)
  - 流量混淆: 请求人性化、Header变异、参数混淆
  - 代理池管理: 多协议支持、自动验证、智能轮换
  - 指纹伪造: JA3/TLS指纹、浏览器Profile模拟
  - 新增 MCP 工具: `stealth_request`, `stealth_proxy_pool`

- **纯Python漏洞利用** (`core/exploit/`)
  - SQL注入引擎: Union/Error/Blind检测、WAF绕过、数据提取
  - 端口扫描器: 异步扫描、服务指纹识别
  - 网络扫描: 存活主机发现、批量扫描
  - 新增 MCP 工具: `exploit_sqli_detect`, `exploit_port_scan`, `exploit_network_scan`

- **综合工具**
  - Red Team侦察: 端口+WAF+指纹综合检测
  - 横向移动链: 批量目标命令执行
  - 新增 MCP 工具: `redteam_recon`, `redteam_lateral_chain`

#### 📦 文件变更
- 新增: `core/lateral/smb_lateral.py` (~600行)
- 新增: `core/lateral/ssh_lateral.py` (~550行)
- 新增: `core/lateral/wmi_lateral.py` (~520行)
- 新增: `core/c2/beacon.py` (~500行)
- 新增: `core/c2/tunnels.py` (~450行)
- 新增: `core/evasion/payload_obfuscator.py` (~750行)
- 新增: `core/stealth/traffic_mutator.py` (~550行)
- 新增: `core/stealth/proxy_pool.py` (~650行)
- 新增: `core/stealth/fingerprint_spoofer.py` (~500行)
- 新增: `core/exploit/pure_sqli.py` (~700行)
- 新增: `core/exploit/pure_scanner.py` (~600行)
- 新增: `modules/redteam_tools.py` (~1100行)
- 修改: `mcp_stdio_server.py` (+Red Team工具注册)
- 修改: `CLAUDE.md` (+新工具文档)

#### ⚠️ 可选依赖
- `impacket`: SMB/WMI高级功能 (Pass-the-Hash)
- `paramiko`: SSH高级功能 (隧道)
- `pycryptodome`: AES加密支持

---

### v2.3.0 (2026-01-05)

#### 🆕 性能优化与智能化增强

- **AI 决策引擎** (`modules/ai_decision_engine.py`)
  - 智能攻击推荐：基于目标特征自动推荐最优攻击路径
  - 攻击链规划：生成多条可能的攻击路径
  - 历史学习：记录攻击结果，持续优化推荐算法
  - 新增 MCP 工具: `ai_suggest_attack`, `ai_attack_chain`, `ai_record_result`

- **异步扫描引擎** (`modules/async_scanner.py`)
  - 异步端口扫描：性能提升 5-10 倍
  - 异步目录扫描：并发 HTTP 请求
  - 异步子域名扫描：批量 DNS 解析
  - 异步漏洞扫描：并发漏洞检测

- **自适应 Payload 引擎** (`modules/adaptive_payload_engine.py`)
  - 基于反馈学习的 Payload 选择
  - WAF 绕过变异：8 种变异方法
  - 成功率统计与排序
  - 探索-利用平衡算法

- **漏洞关联分析引擎** (`modules/vuln_correlation_engine.py`)
  - 漏洞关联图谱：定义漏洞间因果关系
  - 利用链推荐：自动匹配可用利用链
  - 风险评分：综合评估目标风险等级
  - 下一步测试建议

- **智能缓存系统** (`modules/smart_cache.py`)
  - 多层 LRU 缓存：DNS/技术栈/CVE/Payload/侦察结果
  - TTL 管理：自动过期清理
  - 持久化存储：跨会话缓存复用
  - 新增 MCP 工具: `cache_stats`, `cache_cleanup`, `cache_clear`

- **性能监控模块** (`modules/performance_monitor.py`)
  - 执行统计：工具调用次数、成功率、耗时
  - 瓶颈识别：自动识别慢速和不可靠工具
  - 性能报告：实时监控摘要
  - 新增 MCP 工具: `perf_summary`, `perf_bottlenecks`, `perf_tool_stats`

- **异步 HTTP 连接池** (`modules/async_http_pool.py`)
  - 连接复用：减少连接建立开销
  - 速率限制：令牌桶算法防止触发 WAF
  - 自动重试：失败请求自动重试
  - 域名级别统计

#### 📦 文件变更
- 新增: `modules/ai_decision_engine.py` (~390行)
- 新增: `modules/async_scanner.py` (~440行)
- 新增: `modules/adaptive_payload_engine.py` (~380行)
- 新增: `modules/vuln_correlation_engine.py` (~410行)
- 新增: `modules/smart_cache.py` (~340行)
- 新增: `modules/performance_monitor.py` (~350行)
- 新增: `modules/async_http_pool.py` (~390行)
- 新增: `modules/optimization_tools.py` (~480行)
- 新增: `test_optimization.py` (~300行)
- 修改: `mcp_stdio_server.py` (+优化模块集成)

---

### v2.2.0 (2025-01-05)

#### 🆕 渗透测试增强 (Phase 2)

- **OOB带外检测模块** (`modules/oob_detector.py`)
  - 集成 Interactsh / DNSLog 平台
  - 支持盲 SSRF/XXE/SQLi/RCE 检测
  - 自动生成唯一回调URL，轮询检测交互
  - 新增 MCP 工具: `oob_detect`

- **HTTP会话管理器** (`core/session_manager.py`)
  - 支持登录态渗透测试
  - 自动提取 CSRF Token
  - Cookie/Token/认证状态管理
  - 新增 MCP 工具: `session_create`, `session_login`, `session_request`, `session_context`

- **Payload变异器** (`modules/smart_payload_engine.py`)
  - 8种变异方法: 大小写混淆/URL编码/双重编码/注释分割/Unicode/十六进制/字符串拼接/空白符替换
  - WAF特定绕过策略 (Cloudflare/AWS WAF/ModSecurity/Imperva)
  - 新增 MCP 工具: `smart_payload`

- **统计学漏洞验证器** (`modules/vuln_verifier.py`)
  - 多轮测试降低误报率
  - 置信度评分 (80%+确认/60%+可疑/40%-可能误报)
  - 新增 MCP 工具: `verify_vuln`

#### 📦 文件变更
- 新增: `modules/oob_detector.py` (~390行)
- 修改: `core/session_manager.py` (+280行)
- 修改: `modules/smart_payload_engine.py` (+230行)
- 修改: `modules/vuln_verifier.py` (+230行)
- 修改: `mcp_stdio_server.py` (+130行)

---

### v2.1.0 (2025-01-05)

#### 🆕 新增功能
- **任务队列系统** (`utils/task_queue.py`)
  - 轻量级内存任务队列，3个后台worker
  - 支持后台异步执行耗时扫描任务
  - 新增 MCP 工具: `task_submit`, `task_status`, `task_cancel`, `task_list`
  - 无需外部依赖 (Redis/Celery)

- **报告格式扩展**
  - 新增 HTML 专业报告格式 (暗色主题)
  - 新增 PDF 报告格式 (支持中文)
  - 跨平台中文字体自动检测 (Windows/macOS/Linux)
  - `generate_report(target, format="pdf")` 支持 4 种格式

#### 📦 文件变更
- 新增: `utils/task_queue.py`
- 修改: `mcp_stdio_server.py` (+320行)

### v2.0.0 (2025-01-02)

#### 🆕 新增功能
- **智能 Payload 选择器** (`modules/smart_payload_selector.py`)
  - 自动检测 WAF 类型 (Cloudflare/AWS/ModSecurity/Akamai等)
  - 自动检测数据库类型 (MySQL/MSSQL/PostgreSQL/MongoDB等)
  - 根据目标指纹自动选择最优 Payload
  - Payload 成功率统计和排序

- **工具链自动编排** (`core/tool_chain.py`)
  - 工具依赖图 (DAG) 管理
  - 条件触发机制 (根据端口自动添加工具)
  - 异步执行器
  - 预定义工具链 (web_recon/full_recon/vuln_scan/internal_recon)

- **Payload 库大幅扩展** (`modules/mega_payloads.py`)
  - WAF 绕过 Payload (100+): Unicode/双重URL/十六进制/注释混淆
  - NoSQL 注入 (80+): MongoDB/Redis/CouchDB/Elasticsearch
  - GraphQL 注入 (40+): 内省查询/批量查询/DoS
  - JSON 注入 (30+): 类型混淆/原型污染/JWT相关

#### 🔧 Bug 修复
- 修复 `intelligent_recon_engine.py` 中 `self.session` 未定义导致的崩溃
- 添加外部工具 (subfinder/nmap) 存在性检查
- 改进错误处理，替换空 `except: pass` 为具体异常类型

#### 📦 文件变更
- 新增: `modules/smart_payload_selector.py`
- 新增: `core/tool_chain.py`
- 修改: `core/intelligent_recon_engine.py`
- 修改: `modules/mega_payloads.py`
- 删除: `core/deep_vuln_scanner.py` (功能合并)
- 删除: `core/full_vuln_scanner.py` (功能合并)
- 删除: `modules/payload_library.py` (被 mega_payloads.py 替代)

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

- 📧 Email: Coff0xc@protonmail.com
- 🐛 Issue: [GitHub Issues](https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues)

---

<p align="center">
  <b>⭐ 如果这个项目对你有帮助，请给一个 Star！</b>
</p>
