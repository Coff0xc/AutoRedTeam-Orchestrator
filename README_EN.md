<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>AI-Driven Automated Red Team Orchestration Framework</b><br>
  <i>Cross-platform · 74 MCP Tools · 2000+ Payloads · Full ATT&CK Coverage</i>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md">Русский</a> ·
  <a href="README_DE.md">Deutsch</a> ·
  <a href="README_FR.md">Français</a>
</p>

<p align="center">
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/stargazers"><img src="https://img.shields.io/github/stars/Coff0xc/AutoRedTeam-Orchestrator?style=for-the-badge&logo=github&color=gold" alt="Stars"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/network/members"><img src="https://img.shields.io/github/forks/Coff0xc/AutoRedTeam-Orchestrator?style=for-the-badge&logo=github&color=silver" alt="Forks"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues"><img src="https://img.shields.io/github/issues/Coff0xc/AutoRedTeam-Orchestrator?style=for-the-badge&logo=github&color=red" alt="Issues"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/commits/main"><img src="https://img.shields.io/github/last-commit/Coff0xc/AutoRedTeam-Orchestrator?style=for-the-badge&logo=github" alt="Last Commit"></a>
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
  <a href="https://modelcontextprotocol.io/"><img src="https://img.shields.io/badge/MCP-Native-00ADD8?style=for-the-badge&logo=protocol&logoColor=white" alt="MCP"></a>
  <a href="#"><img src="https://img.shields.io/badge/Tools-74-FF6B6B?style=for-the-badge&logo=toolbox&logoColor=white" alt="Tools"></a>
  <a href="#"><img src="https://img.shields.io/badge/Payloads-2000+-orange?style=for-the-badge&logo=artillery&logoColor=white" alt="Payloads"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License"></a>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Join_Community-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-Documentation-blue?style=for-the-badge&logo=gitbook&logoColor=white" alt="Wiki"></a>
</p>

---

## 📖 Table of Contents

- [Core Features](#-core-features)
- [ATT&CK Coverage Matrix](#️-attck-coverage-matrix)
- [Quick Start](#-quick-start)
- [MCP Configuration](#-mcp-configuration)
- [Tool Matrix](#️-tool-matrix)
- [Usage Examples](#-usage-examples)
- [Architecture](#-architecture)
- [Changelog](#-changelog)
- [Roadmap](#️-roadmap)
- [Contributing](#-contributing)
- [Security Policy](#-security-policy)
- [Acknowledgments](#-acknowledgments)
- [License](#-license)

---

## 🎯 Core Features

<table>
<tr>
<td width="50%">

### 🤖 AI-Native Design
- **Smart Fingerprinting** - Auto-detect target tech stack
- **Attack Chain Planning** - AI-driven attack path recommendations
- **Historical Feedback Learning** - Continuous strategy optimization
- **Auto Payload Selection** - WAF-aware intelligent mutation
- **AI PoC Generation** - Generate exploit code from CVE descriptions

</td>
<td width="50%">

### ⚡ Full Automation
- **10-Phase Recon Pipeline** - DNS/Port/Fingerprint/WAF/JS analysis
- **Vulnerability Discovery & Verification** - Auto scan + OOB validation
- **Smart Exploitation Orchestration** - Feedback loop + auto retry
- **One-Click Professional Reports** - JSON/HTML/Markdown formats
- **Session Checkpoint Recovery** - Resume interrupted scans

</td>
</tr>
<tr>
<td width="50%">

### 🔴 Red Team Toolkit
- **Lateral Movement** - SMB/SSH/WMI/WinRM/PSExec
- **C2 Communication** - Beacon + DNS/HTTP/WebSocket tunnels
- **Evasion & Obfuscation** - XOR/AES/Base64 multi-layer encoding
- **Persistence** - Windows Registry/Scheduled Tasks/Linux cron
- **Credential Access** - Memory extraction/File search
- **AD Attacks** - Kerberoasting/AS-REP Roasting

</td>
<td width="50%">

### 🛡️ Security Extensions
- **API Security** - JWT/CORS/GraphQL/WebSocket/OAuth
- **Supply Chain Security** - SBOM generation/Dependency audit/CI-CD scan
- **Cloud Native Security** - K8s audit/gRPC testing/AWS scanning
- **CVE Intelligence** - NVD/Nuclei/ExploitDB multi-source sync
- **WAF Bypass** - 2000+ payload smart mutation engine

</td>
</tr>
</table>

---

## ⚔️ ATT&CK Coverage Matrix

| Tactic | Techniques Covered | Tool Count | Status |
|--------|-------------------|------------|--------|
| **Reconnaissance** | Active Scanning, Passive Collection, OSINT | 12+ | ✅ Complete |
| **Resource Development** | Payload Generation, Obfuscation | 4+ | ✅ Complete |
| **Initial Access** | Web Exploitation, CVE Exploits | 19+ | ✅ Complete |
| **Execution** | Command Injection, Code Execution | 5+ | ✅ Complete |
| **Persistence** | Registry, Scheduled Tasks, Webshell | 3+ | ✅ Complete |
| **Privilege Escalation** | UAC Bypass, Token Impersonation | 2+ | ⚠️ Partial |
| **Defense Evasion** | AMSI Bypass, ETW Bypass, Obfuscation | 4+ | ✅ Complete |
| **Credential Access** | Memory Extraction, File Search | 2+ | ✅ Complete |
| **Discovery** | Network Scanning, Service Enumeration | 8+ | ✅ Complete |
| **Lateral Movement** | SMB/SSH/WMI/WinRM | 6+ | ✅ Complete |
| **Collection** | Data Aggregation, Sensitive Files | 2+ | ✅ Complete |
| **Command & Control** | HTTP/DNS/WebSocket Tunnels | 4+ | ✅ Complete |
| **Exfiltration** | DNS/HTTP/ICMP Exfil | 3+ | ✅ Complete |

---

## 📦 Quick Start

### System Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Windows 10+, Linux (Ubuntu 20.04+), macOS 12+ |
| **Python** | 3.10 or higher |
| **Memory** | 4GB+ recommended |
| **Network** | Outbound HTTP/HTTPS access |

### Installation

```bash
# Clone repository
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# Install dependencies
pip install -r requirements.txt

# Verify installation
python mcp_stdio_server.py --version
```

<details>
<summary><b>🔧 Optional: Minimal Installation</b></summary>

```bash
# Core dependencies only (Recon + Vulnerability Detection)
pip install -r requirements-core.txt

# Optional modules (Red Team + Cloud Security)
pip install -r requirements-optional.txt
```

</details>

<details>
<summary><b>🐳 Docker Deployment</b></summary>

```bash
docker pull coff0xc/autoredteam:latest
docker run -it --rm coff0xc/autoredteam
```

</details>

### Start Service

```bash
python mcp_stdio_server.py
```

---

## 🔧 MCP Configuration

Add the following configuration to your AI editor's MCP config file:

<details>
<summary><b>📘 MCP-Compatible AI Editors</b></summary>

**General config file location:**
- Windows: `%APPDATA%\<EditorName>\config.json`
- macOS: `~/Library/Application Support/<EditorName>/config.json`
- Linux: `~/.config/<EditorName>/config.json`

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": { "PYTHONIOENCODING": "utf-8" }
    }
  }
}
```

</details>

<details>
<summary><b>📗 Cursor</b></summary>

**Config file:** `~/.cursor/mcp.json`

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"]
    }
  }
}
```

</details>

<details>
<summary><b>📙 Windsurf</b></summary>

**Config file:** `~/.codeium/windsurf/mcp_config.json`

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": { "PYTHONIOENCODING": "utf-8" }
    }
  }
}
```

</details>

<details>
<summary><b>📕 Kiro</b></summary>

**Config file:** `~/.kiro/mcp.json`

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"]
    }
  }
}
```

</details>

---

## 🛠️ Tool Matrix

| Category | Count | Main Functions | Key Tools |
|----------|-------|----------------|-----------|
| **🔍 Recon** | 12+ | Information gathering & asset discovery | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` |
| **🐛 Vuln Detection** | 19+ | OWASP Top 10 + Logic vulnerabilities | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` |
| **🌐 Web Scanning** | 4+ | Attack surface discovery & vuln orchestration | `vuln_scan` `security_headers_scan` `cors_scan` `idor_scan` |
| **🔐 API Security** | 11+ | Modern API security testing | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` |
| **📦 Supply Chain** | 5+ | Dependency & build security | `sbom_generate` `dependency_audit` `cicd_scan` |
| **☁️ Cloud Native** | 8+ | Container & cluster security | `k8s_scan` `grpc_scan` `aws_scan` |
| **🔴 Red Team** | 10+ | Post-exploitation & internal network | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` |
| **📋 CVE** | 6+ | Vulnerability intelligence & exploitation | `cve_search` `cve_sync` `poc_execute` |
| **🤖 Automation** | 5+ | Fully automated penetration testing | `auto_pentest` `smart_analyze` `attack_chain_plan` `waf_bypass` |

---

## 💬 Usage Examples

Chat directly in AI editors to invoke tools:

### Reconnaissance & Information Gathering
```
🔍 "Perform full reconnaissance on example.com and generate a report"
🔍 "Scan open ports on 192.168.1.0/24 network"
🔍 "Enumerate subdomains for example.com"
🔍 "Identify target website's tech stack and WAF"
```

### Vulnerability Scanning & Exploitation
```
🎯 "Check if target is vulnerable to SQL injection"
🎯 "Run a complete security scan on target API"
🎯 "Search for Log4j related CVEs and execute PoC"
🎯 "Generate WAF-bypassing XSS payloads"
```

### Red Team Operations
```
🔴 "Execute command on target machine via SMB"
🔴 "Start C2 Beacon connection to server"
🔴 "Search for sensitive credentials on target system"
🔴 "Generate AMSI bypass code"
```

### Automated Penetration Testing
```
⚡ "Run full automated penetration test on https://target.com"
⚡ "Analyze target and generate attack chain recommendations"
⚡ "Resume the previously interrupted pentest session"
```

---

## 🏗️ Architecture

```
AutoRedTeam-Orchestrator/
├── 📄 mcp_stdio_server.py      # MCP Server Entry (74 tools registered)
│
├── 📂 handlers/                # MCP Tool Handlers (unified output schema)
│   ├── recon.py               # Recon tools
│   ├── detector.py            # Vulnerability detection
│   └── redteam.py             # Red team tools
│
├── 📂 core/                    # Core Engines
│   ├── recon/                 # Recon Engine (10-phase pipeline)
│   ├── detectors/             # Vulnerability Detectors
│   ├── exploit/               # Exploitation Engine
│   ├── c2/                    # C2 Communication Framework
│   ├── lateral/               # Lateral Movement (SMB/SSH/WMI)
│   ├── evasion/               # Evasion & Bypass
│   ├── persistence/           # Persistence Modules
│   ├── credential/            # Credential Access
│   └── cve/                   # CVE Intelligence Management
│
├── 📂 modules/                 # Feature Modules
│   ├── api_security/          # API Security Testing
│   ├── cloud_security/        # Cloud Security Auditing
│   ├── supply_chain/          # Supply Chain Security
│   └── smart_payload_engine.py # Smart Payload Engine
│
├── 📂 wordlists/               # Built-in Dictionaries
│
└── 📂 utils/                   # Utility Functions
```

---

## 📋 Changelog

### v3.0.0 (2026-01-18) - Architecture Enhancement

- 🚀 **Tool Expansion**: MCP tools now at 74
- 🔄 **Feedback Loop**: New intelligent exploitation orchestrator with auto-retry
- 🛡️ **WAF Bypass**: Enhanced payload mutation engine with 30+ encoding methods
- 📊 **Report Optimization**: Added executive summary & risk scoring

### v2.8.0 (2026-01-15) - Security Hardening

- 🔒 **Input Validation**: Enhanced security checks for all user inputs
- ⚙️ **Exception Handling**: Unified exception system for improved stability
- 🚄 **Performance**: Improved concurrency control & resource management

<details>
<summary><b>View more versions</b></summary>

### v2.7.1 (2026-01-10) - Web Scanner Engine
- Web Scanner module: Attack surface discovery & injection point modeling
- Built-in wordlists: directories/passwords/usernames/subdomains

### v2.7.0 (2026-01-09) - Architecture Refactoring
- Modular refactoring: 12 independent tool modules
- Recon engine: StandardReconEngine (10 phases)
- Code cleanup: Removed 4,351 lines of redundant code

### v2.6.0 (2026-01-07) - API/Supply Chain/Cloud Security
- JWT/CORS/GraphQL/WebSocket security testing
- SBOM generation (CycloneDX/SPDX)
- K8s/gRPC security audit

</details>

---

## 🛤️ Roadmap

- [ ] 🖥️ Web UI Management Interface
- [ ] 🌐 Distributed Scanning Cluster
- [ ] ☁️ More Cloud Platforms (GCP/Alibaba Cloud/Tencent Cloud)
- [ ] 🤖 Enhanced AI Automated Exploitation
- [ ] 📚 More CVE PoC Templates
- [ ] 🔌 Burp Suite Plugin Integration
- [x] ✅ Full Red Team Toolkit
- [x] ✅ CVE Intelligence & AI PoC Generation
- [x] ✅ API/Supply Chain/Cloud Security Modules
- [x] ✅ Fully Automated Penetration Testing Framework

---

## 🤝 Contributing

We welcome all forms of contributions!

1. **Fork** this repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Submit a **Pull Request**

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## 🔒 Security Policy

- 🚨 **Responsible Disclosure**: Report security vulnerabilities to [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com)
- ⚠️ **Authorized Use Only**: This tool is for authorized security testing and research only
- 📜 **Compliance**: Ensure compliance with local laws before use

See [SECURITY.md](SECURITY.md) for details.

---

## 🙏 Acknowledgments

Thanks to these open source projects for inspiration:

- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner engine design
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - SQL injection detection approach
- [Impacket](https://github.com/fortra/impacket) - Network protocol implementation
- [MCP Protocol](https://modelcontextprotocol.io/) - AI tool protocol standard

---

## 📜 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

---

## ⚖️ Disclaimer

> **WARNING**: This tool is for **authorized security testing and research only**.
>
> Before using this tool to test any system, ensure:
> - You have **written authorization** from the system owner
> - You comply with **local laws and regulations**
> - You follow **professional ethics** standards
>
> Unauthorized use may violate the law. **The developers are not responsible for any misuse**.

---

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Coff0xc">Coff0xc</a></b>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Join_Community-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="mailto:Coff0xc@protonmail.com"><img src="https://img.shields.io/badge/Email-Contact-EA4335?style=for-the-badge&logo=gmail&logoColor=white" alt="Email"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues"><img src="https://img.shields.io/badge/Issues-Report-181717?style=for-the-badge&logo=github&logoColor=white" alt="Issues"></a>
</p>
