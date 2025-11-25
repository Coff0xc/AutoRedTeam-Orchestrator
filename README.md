# 🎯 AutoRedTeam-Orchestrator

**AI驱动的全自动红队渗透测试智能体**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-orange.svg)](https://modelcontextprotocol.io/)

> 不是简单的自动化脚本，而是一个具备"思考能力"的AI智能体。给它一个域名，它还你一份经过AI验证的、去除误报的专业渗透测试报告。

---

## ✨ 核心特性

### 🧠 AI驱动决策引擎
- **智能规划** - AI分析目标特征，动态制定攻击策略
- **误报过滤** - 自动识别并过滤50%+的误报
- **威胁分析** - 评估漏洞的真实威胁等级
- **链式攻击** - 自动执行深度利用链（SQLi→Shell, SSRF→内网）

### 💪 强大的Payload库
- **本地库**: 683条精选Payload (SQLi/XSS/LFI/RCE/SSRF/XXE/SSTI/Auth)
- **在线源**: 10,000+条Payload自动下载 (PayloadsAllTheThings/SecLists/fuzzdb)
- **智能优化**: 根据WAF检测和技术栈自动选择最优Payload

### 🔍 全方位资产发现
- **8个OSINT数据源** (5免费 + 3付费API)
- **多维度收集** (证书透明度/被动DNS/历史IP/JS解析/Web爬虫)

### ⚔️ 智能攻击引擎
- **Payload优化器** - 根据环境自动选择攻击载荷
- **链式攻击** - 15种自动化利用链
- **历史学习** - 记录成功Payload，优先使用高成功率载荷

### 🤖 MCP协议集成
- **9个工具封装** - AI可直接调用
- **自然语言交互** - 在Claude中对话即可使用

---

## 🚀 快速开始

### 一键安装

```bash
cd /home/kali/Desktop/AutoRedTeam-Orchestrator
sudo ./install.sh
source ~/.zshrc
python main.py check-tools
```

### 手动安装

```bash
# 1. Python依赖
pip install -r requirements.txt

# 2. 系统工具
sudo apt install nmap

# 3. Go工具
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# 4. 更新模板
nuclei -update-templates

# 5. 配置PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc
```

---

## 💻 使用方式

### 方式1：命令行模式

```bash
# 基本扫描
python main.py scan example.com

# 保存报告
python main.py scan example.com -o report.json

# 详细输出
python main.py scan example.com -v

# 检查工具
python main.py check-tools
```

### 方式2：MCP服务器模式（推荐）

**1. 配置Claude Desktop**

编辑 `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "autored-team": {
      "command": "python",
      "args": ["/home/kali/Desktop/AutoRedTeam-Orchestrator/mcp_server.py"],
      "env": {
        "PYTHONPATH": "/home/kali/Desktop/AutoRedTeam-Orchestrator"
      }
    }
  }
}
```

**2. 重启Claude Desktop**

**3. 在Claude中使用**

```
你：帮我扫描 example.com 的子域名
AI：[调用工具] 发现12个子域名...

你：对 dev.example.com 进行漏洞扫描
AI：[调用工具] 发现3个高危漏洞...
```

---

## 🤖 MCP工具列表

| 工具名 | 功能 | 参数 |
|--------|------|------|
| `redteam_scan` | 全自动红队扫描 | target, timeout |
| `subdomain_enum` | 子域名枚举 | domain |
| `port_scan` | 端口扫描 | target, ports |
| `vuln_scan` | 漏洞扫描 | target, severity |
| `web_fingerprint` | Web指纹识别 | url |
| `osint_gather` | OSINT情报收集 | domain |
| `service_exploit` | 服务漏洞检测 | host, port, service |
| `check_tools` | 检查工具状态 | - |
| `get_payloads` | 获取攻击Payload | vuln_type, limit |

---

## 🏗️ 项目架构

```
AutoRedTeam-Orchestrator/
├── main.py                      # CLI入口
├── mcp_server.py                # MCP服务器
├── install.sh                   # 一键安装
├── requirements.txt             # 依赖
├── config/settings.yaml         # 配置
├── core/                        # 核心模块
│   ├── ai_brain.py              # AI决策引擎
│   ├── attack_engine.py         # 攻击引擎
│   ├── advanced_attack_engine.py # 高级攻击引擎
│   └── payloads/                # Payload库(683条)
├── modules/                     # 功能模块
│   ├── recon/                   # 资产发现
│   │   ├── subdomain.py
│   │   ├── asset_discovery.py
│   │   └── osint_sources.py     # 8个OSINT源
│   ├── mapping/                 # 资产测绘
│   │   ├── port_scanner.py
│   │   ├── fingerprint.py       # 指纹识别
│   │   └── service_enum.py
│   ├── attack/                  # 攻击模块
│   └── verify/                  # 验证模块
└── templates/                   # 报告模板
```

### 工作流程

```
Phase 1: 资产发现 → Subfinder + OSINT(8源)
Phase 2: 资产测绘 → Nmap + httpx + 指纹识别
Phase 3: 漏洞扫描 → Nuclei + 智能Payload + 链式攻击
Phase 4: AI验证  → 误报过滤 + 威胁评估 + 报告生成
```

---

## ⚙️ 配置说明

编辑 `config/settings.yaml`:

```yaml
# OSINT数据源（可选）
osint:
  shodan_key: ""
  virustotal_key: ""
  securitytrails_key: ""

# AI引擎（可选）
ai_engine:
  openai:
    api_key: ""  # 或设置环境变量 OPENAI_API_KEY
  anthropic:
    api_key: ""  # 或设置环境变量 ANTHROPIC_API_KEY

# 性能配置
performance:
  max_concurrent_scans: 5
  rate_limit: 100
  timeout: 300
```

---

## 🛠️ 必需工具

| 工具 | 用途 | 安装 |
|------|------|------|
| nmap | 端口扫描 | `sudo apt install nmap` |
| subfinder | 子域名枚举 | `go install ...` |
| nuclei | 漏洞扫描 | `go install ...` |
| httpx | HTTP探测 | `go install ...` |
| dnsx | DNS解析 | `go install ...` |

---

## ❓ 常见问题

### Q: 工具未找到
```bash
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
```

### Q: MCP连接失败
```bash
# 查看日志
tail -f /tmp/autored_mcp.log

# 测试服务器
python mcp_server.py
```

### Q: 扫描超时
```bash
python main.py scan example.com --timeout 600
```

---

## 📊 性能指标

- 子域名发现: ~100个/分钟
- 端口扫描: ~1000端口/分钟
- 漏洞扫描: 150 req/s
- OSINT查询: 8源并行
- 误报过滤: ~50%

---

## 🛡️ 免责声明

本工具仅供**授权的安全测试**和**教育目的**使用。未经授权的渗透测试是违法的。使用者必须遵守当地法律法规，对使用本工具造成的任何后果自行承担责任。

---

## 📝 许可证

MIT License - 查看 [LICENSE](LICENSE) 文件

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

**让AI成为你的红队队友！** 🎯
