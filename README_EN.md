# 🔥 AutoRedTeam-Orchestrator

[中文](README.md) | **English**

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux"/>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/MCP-Protocol-00ADD8?style=for-the-badge" alt="MCP"/>
  <img src="https://img.shields.io/badge/Tools-52+-FF6B6B?style=for-the-badge" alt="Tools"/>
  <img src="https://img.shields.io/badge/Payloads-2000+-orange?style=for-the-badge" alt="Payloads"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

<p align="center">
  <b>🤖 AI-Driven Automated Penetration Testing Framework | Based on Model Context Protocol (MCP) Architecture</b>
</p>

---

## 📖 Introduction

**AutoRedTeam-Orchestrator** is an intelligent penetration testing platform integrating **52+ security tools** and **2000+ payloads**. Through seamless integration with AI editors (Windsurf / Cursor / Claude Desktop) via MCP protocol, it enables **AI-driven automated red team operations**.

Simply describe your target in natural language, and the AI will automatically select tools, perform reconnaissance, discover vulnerabilities, and recommend attack paths.

### 🎯 Why Choose This Project?

- ✅ **Ready to Use** - One-click installation of all dependencies
- ✅ **AI Native** - Tool interfaces designed specifically for LLMs
- ✅ **Full Coverage** - Complete workflow from reconnaissance to exploitation
- ✅ **Combat-Oriented** - Built-in practical payloads for Shiro/Log4j/Fastjson
- ✅ **Smart Selection** - Automatically selects optimal payloads based on target fingerprints
- ✅ **Auto Orchestration** - Automated tool chain orchestration without manual invocation

---

## ✨ Core Features

| Feature | Description |
|---------|-------------|
| 🤖 **AI-Driven Intelligence** | LLM-based intelligent reconnaissance, attack path planning, vulnerability verification |
| 🔍 **Fully Automated Recon** | One-click complete workflow: subdomain, port, fingerprint, WAF, vulnerability scanning |
| ☢️ **Nuclei Integration** | 11997+ vulnerability detection templates covering latest CVEs |
| 💉 **Payload Library** | 2000+ payloads including SQLi/XSS/NoSQL/GraphQL/WAF bypass |
| 🧠 **Smart Selection** | Automatically selects optimal payloads based on target fingerprints |
| 🔗 **Tool Chain Orchestration** | Automated tool chain: port scan → service identification → vulnerability scan |
| 📊 **Smart Reports** | Auto-generate HTML/Markdown/JSON format reports |
| 🔗 **MCP Protocol** | Native support for Windsurf/Cursor/Claude Desktop |

---

## 🛠️ Tool List

### 🔍 Reconnaissance Module

| Tool | Command | Description |
|------|---------|-------------|
| 🔥 Smart Recon | `auto_recon` | AI-driven fully automated penetration testing |
| ⚡ Quick Recon | `quick_recon` | One-click basic information gathering |
| 🧠 Deep Recon | `intelligent_recon` | Intelligent deep reconnaissance with JS analysis |
| 🔄 Complete Workflow | `complete_recon_workflow` | 10-stage fully automated reconnaissance |
| 🌐 Subdomain Enum | `subdomain_enum` | Subfinder subdomain discovery |
| 📡 DNS Enum | `dns_enum` | DNS record query (A/AAAA/MX/NS/TXT) |
| 🔍 Port Scan | `nmap_scan` | Nmap port and service identification |
| 📋 Whois Lookup | `whois_lookup` | Domain/IP registration information query |
| 🌍 TheHarvester | `theharvester` | Email, subdomain OSINT collection |
| 🔎 Google Dork | `google_dork` | Generate advanced search syntax |

### ☢️ Vulnerability Scanning

| Tool | Command | Description |
|------|---------|-------------|
| ☢️ Nuclei Full | `nuclei_full` / `nuclei_complete_scan` | Complete scan with 11997+ templates |
| 🎯 CVE Specific | `nuclei_cve` | Targeted CVE vulnerability scanning |
| 💣 Deep Vuln Scan | `deep_vuln_scan` | Shiro/Log4j/SQL injection detection |
| 🔬 Nikto Scan | `nikto_scan` | Web server vulnerability scanning |
| ⚡ XSS Scan | `xss_scan` | Automated XSS vulnerability detection |
| 💉 SQL Injection | `sqli_test` | SQLMap automated detection |
| 🔐 SSL Scan | `sslscan` / `testssl` | SSL/TLS configuration security testing |
| ✅ Vuln Verify | `verify_vuln` | Automatically verify vulnerability authenticity |

### 🔎 Fingerprinting

| Tool | Command | Description |
|------|---------|-------------|
| 🔎 Web Fingerprint | `whatweb` | Web technology stack identification |
| 🛡️ WAF Detection | `wafw00f` | Web application firewall identification |
| 🧩 Component ID | `identify_tech` | Smart component identification + payload recommendation |
| 🌐 HTTP Probe | `httpx_probe` | Batch HTTP service probing |
| 🛡️ WAF Bypass | `waf_bypass_test` | Detect WAF and provide bypass suggestions |

### 📁 Directory Bruteforce

| Tool | Command | Description |
|------|---------|-------------|
| 📁 Dir Scan | `dir_scan` | Gobuster directory discovery |
| ⚡ Ffuf | `ffuf` | Fast web fuzzer |
| 🔨 Gobuster | `gobuster` | Directory/DNS/VHost bruteforce |

### 💉 Exploitation

| Tool | Command | Description |
|------|---------|-------------|
| 💉 Get Payloads | `get_payloads` | SQLi/XSS/LFI/RCE/SSRF/XXE payloads |
| 📚 Payload Library | `query_payload_library` | Query complete payload library |
| 🎯 Get Exploit | `get_exploit` | CVE/framework/middleware exploit code |
| 📋 List Exploits | `list_exploits` | List all available exploit templates |
| 🐚 Reverse Shell | `reverse_shell` | Generate Bash/Python/PHP/NC/PowerShell |
| ⚔️ MSF Payload | `msfvenom` | Metasploit payload generation |
| 🔍 Searchsploit | `searchsploit` | Exploit-DB vulnerability search |
| 🔍 MSF Search | `msf_search` | Metasploit module search |
| 🔑 Default Creds | `default_credential_test` | OA/CMS default credential testing |
| 📄 SQLi Payload | `sqli_payload` | Generate SQL injection payloads |

### 📜 JavaScript Analysis

| Tool | Command | Description |
|------|---------|-------------|
| 📜 JS Source Analysis | `js_source_analysis` | API endpoints/sensitive info/Webpack restoration |

### 🔐 Password Attacks

| Tool | Command | Description |
|------|---------|-------------|
| 🔓 Brute Force | `brute_force` | SSH/FTP/MySQL/RDP/SMB bruteforce |
| 🔨 CrackMapExec | `crackmapexec` | Network penetration and post-exploitation |

### 🐧 Post Exploitation

| Tool | Command | Description |
|------|---------|-------------|
| 🐧 LinPEAS | `linpeas` | Linux privilege escalation enumeration |
| 🪟 WinPEAS | `winpeas` | Windows privilege escalation enumeration |
| 📋 LinEnum | `linenum` | Linux enumeration script |
| 🪟 Windows Enum | `windows_enum` | Windows system information gathering |
| 💡 Kernel Exploit | `linux_exploit_suggester` | Linux kernel exploit suggestions |

### ☁️ Cloud Security

| Tool | Command | Description |
|------|---------|-------------|
| ☁️ AWS Enum | `aws_enum` | AWS resource enumeration |
| ☁️ Azure Enum | `azure_enum` | Azure resource enumeration |
| 🪣 S3 Scanner | `s3_scanner` | S3 bucket permission testing |
| ☸️ K8s Scan | `kube_hunter` | Kubernetes security scanning |

### 🔧 Network Services

| Tool | Command | Description |
|------|---------|-------------|
| 📁 SMB Enum | `smb_enum` | SMB share and user enumeration |
| 📡 SNMP Walk | `snmp_walk` | SNMP information gathering |
| 📋 LDAP Enum | `ldap_enum` | LDAP information gathering |
| 🔐 SSH Audit | `ssh_audit` | SSH server security audit |
| 🔄 Zone Transfer | `zone_transfer` | DNS zone transfer testing |
| 🧠 Smart Service Scan | `smart_service_scan` | Auto-select scan strategy based on ports |

### 📊 Reports & Utilities

| Tool | Command | Description |
|------|---------|-------------|
| 📊 Generate Report | `generate_report` | Generate JSON/HTML/Markdown reports |
| 📈 Payload Stats | `payload_stats` | View payload library statistics |
| 🔧 System Check | `system_check` | Check all tool availability |
| 🛠️ Tool Recommend | `recon_tools_recommend` | Recommend best tool combinations by scenario |
| 🔍 CVE Search | `cve_search` | Search CVE vulnerability information |
| 🤖 AI Attack Plan | `ai_attack_plan` | AI-generated attack plan |

---

## 📦 Installation

### Prerequisites

- **Operating System**: Kali Linux 2023+ (recommended) / Ubuntu / Debian
- **Python**: 3.10+
- **Permissions**: Some tools require root privileges

### Quick Installation

```bash
# 1. Clone repository
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. Run installation script (auto-install all dependencies)
chmod +x setup.sh
sudo ./setup.sh

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Copy configuration file
cp config/config.yaml.example config/config.yaml
```

### Manual Dependency Installation

```bash
sudo apt update && sudo apt install -y \
    nmap nikto gobuster ffuf sqlmap \
    whatweb wafw00f dnsutils whois \
    smbclient snmp hydra seclists

# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update Nuclei templates
nuclei -update-templates
```

---

## 🚀 Usage

### Method 1: As MCP Server (Recommended)

#### 1. Configure Windsurf

Run auto-configuration script:
```bash
./setup_windsurf_mcp.sh
```

Or manually edit `~/.codeium/windsurf/mcp_config.json`:
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

#### 2. Configure Cursor

Edit `~/.cursor/mcp.json`:
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

#### 3. Configure Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):
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

#### 4. Start Using

Chat with natural language in AI editor:

```
Perform comprehensive security reconnaissance on example.com
```

```
Scan 192.168.1.0/24 for open ports and services
```

```
Check if https://target.com has Log4j and Shiro vulnerabilities
```

```
Generate SQL injection payloads for MySQL
```

### Method 2: Standalone HTTP Server

```bash
python main.py -H 0.0.0.0 -p 5000
```

Visit `http://localhost:5000/tools` to view all available tools.

---

## ⚙️ Configuration

Edit `config/config.yaml`:

```yaml
# Server configuration
server:
  host: "127.0.0.1"
  port: 5000

# AI configuration (optional, for intelligent analysis)
ai:
  provider: "openai"      # openai / anthropic / local
  model: "gpt-4"
  api_key: ""             # or use environment variable OPENAI_API_KEY

# Scanning configuration
scanning:
  default_threads: 10     # Default threads
  default_delay: 100      # Default delay (ms)
  rate_limit: 150         # Rate limit

# OSINT API keys (optional)
api_keys:
  shodan: ""              # SHODAN_API_KEY
  censys_id: ""           # CENSYS_API_ID
  censys_secret: ""       # CENSYS_API_SECRET
  virustotal: ""          # VT_API_KEY

# Wordlist paths
wordlists:
  directories: "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
  passwords: "/usr/share/wordlists/rockyou.txt"
  subdomains: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
```

---

## 📁 Project Structure

```
AutoRedTeam-Orchestrator/
├── main.py                     # 🚀 Main entry
├── mcp_tools.py                # 🔧 MCP tool definitions (60+ tools)
├── auto_recon.py               # 🤖 Intelligent reconnaissance engine
├── requirements.txt            # 📦 Python dependencies
├── setup.sh                    # ⚙️ Installation script
├── setup_windsurf_mcp.sh       # 🔗 Windsurf configuration script
│
├── config/
│   ├── config.yaml.example     # Configuration template
│   └── config.yaml             # Actual configuration (gitignore)
│
├── core/
│   ├── mcp_server.py           # MCP server core
│   ├── ai_engine.py            # AI engine integration
│   ├── attack_chain.py         # Attack chain planning
│   ├── intelligent_recon_engine.py  # Intelligent reconnaissance engine
│   ├── tool_chain.py           # 🆕 Tool chain auto-orchestration
│   ├── mega_payload_library.py # Payload library
│   └── session_manager.py      # Session management
│
├── modules/
│   ├── recon/                  # 🔍 Reconnaissance modules
│   │   ├── nmap_tools.py
│   │   ├── subdomain_tools.py
│   │   ├── dns_tools.py
│   │   └── osint_tools.py
│   │
│   ├── vuln_scan/              # ☢️ Vulnerability scanning
│   │   ├── nuclei_tools.py
│   │   ├── nikto_tools.py
│   │   └── ssl_tools.py
│   │
│   ├── web_attack/             # 💉 Web attacks
│   │   ├── sqli_tools.py
│   │   ├── xss_tools.py
│   │   ├── dir_tools.py
│   │   └── fuzzing_tools.py
│   │
│   ├── exploit/                # 🎯 Exploitation
│   │   ├── msf_tools.py
│   │   └── reverse_shell.py
│   │
│   ├── post_exploit/           # 🐧 Post-exploitation
│   │   ├── privesc_tools.py
│   │   └── enum_tools.py
│   │
│   ├── cloud/                  # ☁️ Cloud security
│   │   ├── aws_tools.py
│   │   ├── azure_tools.py
│   │   └── k8s_tools.py
│   │
│   ├── network/                # 🔧 Network services
│   │   ├── smb_tools.py
│   │   ├── brute_force.py
│   │   └── service_tools.py
│   │
│   ├── mega_payloads.py        # 🆕 Mega payload library (2000+)
│   ├── smart_payload_selector.py  # 🆕 Smart payload selector
│   ├── nuclei_integration.py   # Nuclei integration
│   └── vuln_verifier.py        # Vulnerability verifier
│
├── payloads/
│   └── complete_payload_db.json  # Complete payload database
│
├── utils/
│   ├── logger.py               # Logging utilities
│   ├── report_generator.py     # Report generation
│   ├── terminal_output.py      # Terminal output beautification
│   └── tool_checker.py         # Tool checker
│
├── data/                       # Session data
├── logs/                       # Log files
└── reports/                    # Scan report output
```

---

## 💡 Usage Examples

### Quick Reconnaissance

```python
# Direct conversation in AI editor
"Perform quick reconnaissance on target.com"

# Or call tool directly
quick_recon(target="target.com", include_subdomains=True, include_ports=True)
```

### Deep Vulnerability Scanning

```python
# Shiro/Log4j/SQL injection detection
deep_vuln_scan(target="https://target.com", dnslog="xxx.dnslog.cn")

# Nuclei full scan
nuclei_complete_scan(target="https://target.com", preset="full")
```

### Get Payloads

```python
# SQL injection payloads
get_payloads(vuln_type="sqli", dbms="mysql", category="union")

# Query payload library
query_payload_library(payload_type="shiro")
query_payload_library(payload_type="log4j")
```

### Generate Reverse Shell

```python
reverse_shell(type="bash", lhost="10.0.0.1", lport=4444)
reverse_shell(type="python", lhost="10.0.0.1", lport=4444)
```

---

## 🔒 Security Statement

⚠️ **Important Notice**

1. This tool is **for authorized security testing and research purposes only**
2. Before use, ensure you have obtained **written authorization** from the target system owner
3. Unauthorized penetration testing of systems is **illegal**
4. Developers are not responsible for any misuse
5. Please comply with local laws, regulations, and ethical guidelines

---

## 🗺️ Roadmap

- [x] 52+ security tool integration
- [x] Nuclei 11997+ template support
- [x] 2000+ payload library
- [x] Intelligent reconnaissance engine
- [x] MCP protocol support
- [x] 🆕 Smart payload selector
- [x] 🆕 Tool chain auto-orchestration
- [x] 🆕 WAF bypass payloads (100+)
- [x] 🆕 NoSQL/GraphQL/JSON injection support
- [ ] Web UI interface
- [ ] Distributed scanning support
- [ ] More cloud platform support (GCP/Alibaba Cloud)
- [ ] AI automated exploitation

---

## 📝 Changelog

### v2.0.0 (2025-01-02)

#### 🆕 New Features
- **Smart Payload Selector** (`modules/smart_payload_selector.py`)
  - Auto-detect WAF types (Cloudflare/AWS/ModSecurity/Akamai, etc.)
  - Auto-detect database types (MySQL/MSSQL/PostgreSQL/MongoDB, etc.)
  - Auto-select optimal payloads based on target fingerprints
  - Payload success rate statistics and ranking

- **Tool Chain Auto-Orchestration** (`core/tool_chain.py`)
  - Tool dependency graph (DAG) management
  - Conditional trigger mechanism (auto-add tools based on ports)
  - Async executor
  - Predefined tool chains (web_recon/full_recon/vuln_scan/internal_recon)

- **Payload Library Expansion** (`modules/mega_payloads.py`)
  - WAF bypass payloads (100+): Unicode/double URL/hex/comment obfuscation
  - NoSQL injection (80+): MongoDB/Redis/CouchDB/Elasticsearch
  - GraphQL injection (40+): introspection queries/batch queries/DoS
  - JSON injection (30+): type confusion/prototype pollution/JWT-related

#### 🔧 Bug Fixes
- Fixed crash caused by undefined `self.session` in `intelligent_recon_engine.py`
- Added existence checks for external tools (subfinder/nmap)
- Improved error handling, replaced empty `except: pass` with specific exception types

#### 📦 File Changes
- Added: `modules/smart_payload_selector.py`
- Added: `core/tool_chain.py`
- Modified: `core/intelligent_recon_engine.py`
- Modified: `modules/mega_payloads.py`
- Removed: `core/deep_vuln_scanner.py` (functionality merged)
- Removed: `core/full_vuln_scanner.py` (functionality merged)
- Removed: `modules/payload_library.py` (replaced by mega_payloads.py)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE)

---

## 🤝 Contributing

Issues and Pull Requests are welcome!

1. Fork this repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Submit Pull Request

---

## 📮 Contact

- 📧 Email: Coff0xc@protonmail.com
- 🐛 Issue: [GitHub Issues](https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues)

---

<p align="center">
  <b>⭐ If this project helps you, please give it a Star!</b>
</p>
