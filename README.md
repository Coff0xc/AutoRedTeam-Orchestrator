# 🔥 AI Red Team MCP Server

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white"/>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/MCP-Protocol-00ADD8?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
</p>

<p align="center">
  <b>AI驱动的自动化渗透测试框架，基于 Model Context Protocol (MCP) 架构</b>
</p>

---

## 📖 简介

AI Red Team MCP Server 是一个集成了 60+ 安全工具的智能化渗透测试平台，通过 MCP 协议与 AI 编辑器（Windsurf/Cursor）无缝集成，实现 AI 驱动的自动化红队作业。

### ✨ 核心特性

- 🤖 **AI 智能驱动** - 基于 LLM 的智能侦察、攻击路径规划
- 🔍 **全自动侦察** - 一键完成子域名、端口、指纹、漏洞扫描
- 🎯 **Nuclei 集成** - 11997+ 漏洞模板，覆盖最新 CVE
- 💉 **Payload 库** - 内置 Shiro/Log4j/SQLi/XSS/RCE 等实战 Payload
- 📊 **智能报告** - 自动生成 HTML/Markdown/JSON 格式报告
- 🔗 **MCP 协议** - 原生支持 Windsurf/Cursor 等 AI 编辑器

---

## 🛠️ 工具列表

### 侦察模块
| 工具 | 功能 | 描述 |
|------|------|------|
| `auto_recon` | 🔥 智能打点 | AI驱动的全自动化渗透测试 |
| `quick_recon` | ⚡ 快速侦察 | 一键执行基础信息收集 |
| `intelligent_recon` | 🧠 深度侦察 | 包含JS分析的智能侦察 |
| `subdomain_enum` | 🌐 子域名枚举 | subfinder 子域名发现 |
| `dns_enum` | 📡 DNS枚举 | DNS记录查询 |
| `nmap_scan` | 🔍 端口扫描 | Nmap 端口与服务识别 |

### 漏洞扫描
| 工具 | 功能 | 描述 |
|------|------|------|
| `nuclei_full` | ☢️ Nuclei全量 | 11997+ 模板完整扫描 |
| `nuclei_cve` | 🎯 CVE专项 | 针对性CVE漏洞扫描 |
| `deep_vuln_scan` | 💣 深度漏扫 | Shiro/Log4j/SQLi检测 |
| `nikto_scan` | 🔬 Web扫描 | Nikto Web服务器扫描 |
| `xss_scan` | ⚡ XSS扫描 | XSS漏洞检测 |
| `sqli_test` | 💉 SQL注入 | SQLMap自动化检测 |

### 指纹识别
| 工具 | 功能 | 描述 |
|------|------|------|
| `whatweb` | 🔎 Web指纹 | Web技术栈识别 |
| `wafw00f` | 🛡️ WAF检测 | Web应用防火墙识别 |
| `identify_tech` | 🧩 组件识别 | 智能组件识别+Payload推荐 |
| `httpx_probe` | 🌐 HTTP探测 | HTTP服务探测 |

### 目录扫描
| 工具 | 功能 | 描述 |
|------|------|------|
| `dir_scan` | 📁 目录扫描 | Gobuster目录发现 |
| `ffuf` | ⚡ Fuzzing | 快速Web Fuzzer |
| `gobuster` | 🔨 暴力扫描 | 目录/DNS/VHost爆破 |

### 漏洞利用
| 工具 | 功能 | 描述 |
|------|------|------|
| `get_payloads` | 💉 获取Payload | SQLi/XSS/RCE等Payload |
| `get_exploit` | 🎯 获取EXP | CVE/框架漏洞利用代码 |
| `reverse_shell` | 🐚 反弹Shell | 生成各类反弹Shell |
| `msfvenom` | ⚔️ MSF载荷 | Metasploit Payload生成 |

### 后渗透
| 工具 | 功能 | 描述 |
|------|------|------|
| `linpeas` | 🐧 Linux提权 | Linux权限提升枚举 |
| `winpeas` | 🪟 Windows提权 | Windows权限提升枚举 |
| `linux_exploit_suggester` | 💡 内核漏洞 | Linux内核漏洞建议 |

---

## 📦 安装

### 前置要求

- **操作系统**: Kali Linux 2023+ (推荐)
- **Python**: 3.10+
- **权限**: 部分工具需要 root 权限

### 快速安装

```bash
# 克隆仓库
git clone https://github.com/YOUR_USERNAME/ai-recon-mcp.git
cd ai-recon-mcp

# 运行安装脚本 (自动安装依赖工具)
chmod +x setup.sh
sudo ./setup.sh

# 安装 Python 依赖
pip install -r requirements.txt

# 复制配置文件
cp config/config.yaml.example config/config.yaml
```

### 依赖工具

安装脚本会自动安装以下工具，也可手动安装：

```bash
sudo apt update && sudo apt install -y \
    nmap nikto gobuster ffuf sqlmap \
    whatweb wafw00f subfinder httpx \
    nuclei crackmapexec hydra
```

---

## 🚀 使用方法

### 1. 启动 MCP 服务器

```bash
python main.py
```

### 2. 配置 AI 编辑器

#### Windsurf 配置

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

#### Cursor 配置

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

### 3. 开始使用

在 AI 编辑器中，直接对话即可：

```
对 example.com 进行全面侦察
```

```
扫描 192.168.1.0/24 的开放端口
```

```
检测 https://target.com 是否存在 Log4j 漏洞
```

---

## 📝 配置说明

编辑 `config/config.yaml`：

```yaml
# AI配置 (可选)
ai:
  provider: "openai"
  api_key: ""  # 或使用环境变量 OPENAI_API_KEY

# 扫描配置
scanning:
  default_threads: 10
  rate_limit: 150

# API密钥 (可选，用于OSINT)
api_keys:
  shodan: ""      # SHODAN_API_KEY
  censys_id: ""   # CENSYS_API_ID
  virustotal: ""  # VT_API_KEY
```

---

## 📁 项目结构

```
ai-recon-mcp/
├── main.py                 # 主入口
├── mcp_tools.py            # MCP工具定义 (60+ tools)
├── auto_recon.py           # 智能侦察引擎
├── config/
│   └── config.yaml.example # 配置模板
├── core/
│   ├── mcp_server.py       # MCP服务器核心
│   ├── ai_engine.py        # AI引擎
│   └── attack_chain.py     # 攻击链规划
├── modules/
│   ├── recon/              # 侦察模块
│   ├── vuln/               # 漏洞扫描
│   ├── exploit/            # 漏洞利用
│   └── post/               # 后渗透
├── payloads/               # Payload库
├── utils/                  # 工具函数
└── reports/                # 扫描报告输出
```

---

## 🔒 安全声明

⚠️ **重要提示**

- 本工具**仅供授权的安全测试和研究使用**
- 在使用前，请确保已获得目标系统所有者的**书面授权**
- 未经授权对系统进行渗透测试是**违法行为**
- 开发者不对任何滥用行为承担责任

---

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

## 📮 联系方式

如有问题，请提交 [Issue](https://github.com/YOUR_USERNAME/ai-recon-mcp/issues)
