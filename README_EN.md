# 🔥 AutoRedTeam-Orchestrator

<div align="center">

[简体中文](README.md) | English

**AI-Driven Automated Red Team Orchestration Framework**

*Cross-platform support for Linux / Windows / macOS, with 130+ security tools and 2000+ payloads*

[![OS](https://img.shields.io/badge/OS-Linux%20%7C%20Windows%20%7C%20macOS-557C94?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/Coff0xc/AutoRedTeam-Orchestrator)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-Native-00ADD8?style=for-the-badge)](https://modelcontextprotocol.io/)
[![Tools](https://img.shields.io/badge/Tools-130+-FF6B6B?style=for-the-badge)](https://github.com/Coff0xc/AutoRedTeam-Orchestrator)
[![Payloads](https://img.shields.io/badge/Payloads-2000+-orange?style=for-the-badge)](https://github.com/Coff0xc/AutoRedTeam-Orchestrator)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.7.0-blue?style=for-the-badge)](CHANGELOG.md)

</div>

---

## 🎯 Key Features

<table>
<tr>
<td width="50%">

### 🤖 AI Native
- Intelligent fingerprinting & attack chain planning
- Historical feedback learning
- Auto tool & payload selection
- AI PoC generation engine

</td>
<td width="50%">

### ⚡ Full Automation
- Subdomain/Port/WAF/Fingerprint scanning
- Vulnerability discovery & verification
- One-click professional reports
- 10-phase standard recon workflow

</td>
</tr>
<tr>
<td width="50%">

### 🔴 Red Team Enhanced
- Lateral movement (SMB/SSH/WMI)
- C2 communication (Beacon/DNS/HTTP/WebSocket)
- Obfuscation & evasion
- Persistence/Credential/AD attacks

</td>
<td width="50%">

### 🛡️ Security Extensions
- API Security (JWT/CORS/GraphQL/WebSocket)
- Supply Chain (SBOM/OSV/CI-CD)
- Cloud Native (K8s/gRPC)
- CVE intelligence multi-source sync

</td>
</tr>
</table>

---

## 📦 Quick Start

### Installation

```bash
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator
pip install -r requirements.txt
```

### Run MCP Server

```bash
python mcp_stdio_server.py
```

### MCP Configuration

<details>
<summary><b>Claude Desktop / Claude Code</b></summary>

Config file: `~/.claude/mcp.json` or `%APPDATA%\Claude\claude_desktop_config.json`

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
<summary><b>Cursor</b></summary>

Config file: `~/.cursor/mcp.json`

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
<summary><b>Windsurf</b></summary>

Config file: `~/.codeium/windsurf/mcp_config.json`

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
<summary><b>Kiro</b></summary>

Config file: `~/.kiro/mcp.json`

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

| Category | Count | Features |
|----------|-------|----------|
| **Recon** | 12+ | Port scan, subdomain enum, DNS query, WAF detection, fingerprinting, JS analysis |
| **Vuln Detection** | 19+ | SQLi, XSS, SSRF, XXE, SSTI, LFI, CSRF, command injection, deserialization |
| **API Security** | 11+ | JWT testing, CORS bypass, GraphQL security, WebSocket security, security headers |
| **Supply Chain** | 9+ | SBOM generation, dependency audit, CI/CD scanning |
| **Cloud Native** | 11+ | K8s audit, gRPC testing, container security |
| **Red Team** | 29+ | Lateral movement, C2, obfuscation, persistence, credential, AD attacks |
| **CVE Intel** | 6+ | Multi-source sync, PoC execution, AI generation |
| **Payload** | 4+ | Smart mutation, WAF bypass, 2000+ payload library |

---

## 💬 Usage Examples

Chat directly in AI editors:

```
🔍 "Perform full recon on example.com and generate report"
🔍 "Scan 192.168.1.0/24 for open ports and identify services"
🔍 "Check target for Log4j/Shiro vulnerabilities"
🔍 "Run JWT security scan on target API"
🔍 "Generate SBOM and scan for dependency vulnerabilities"
🔍 "Detect privileged containers in K8s cluster"
```

---

## 📁 Project Structure

```
AutoRedTeam-Orchestrator/
├── mcp_stdio_server.py      # MCP server entry
├── tools/                   # MCP tool definitions (12 modules)
│   ├── recon_tools.py       # Recon tools
│   ├── vuln_tools.py        # Vuln detection
│   ├── ai_tools.py          # AI decision
│   ├── pentest_tools.py     # Pentest tools
│   └── pipeline_tools.py    # Pipeline tools
├── core/
│   ├── recon/               # Recon engine (StandardReconEngine)
│   ├── pipeline.py          # Vulnerability pipeline
│   ├── c2/                  # C2 communication
│   ├── lateral/             # Lateral movement
│   ├── evasion/             # Obfuscation
│   ├── persistence/         # Persistence
│   ├── credential/          # Credential harvesting
│   ├── ad/                  # AD attacks
│   └── cve/                 # CVE intelligence
├── modules/
│   ├── api_security/        # API security
│   ├── supply_chain/        # Supply chain security
│   ├── cloud_security/      # Cloud native security
│   └── smart_cache.py       # Smart cache
└── utils/                   # Utilities
```

---

## 📋 Changelog

### v2.7.0 (2026-01-09) - Architecture Refactoring

- **Modular refactoring**: Split mcp_stdio_server.py into 12 independent tool modules
- **Unified registration**: ToolRegistry for centralized tool management
- **Recon engine**: Merged into StandardReconEngine (10 phases)
- **Pipeline mechanism**: Fingerprint→POC→Weak password→Attack chain automation
- **Cache optimization**: CacheType enum with backward compatibility
- **Code cleanup**: Removed 4,351 lines of redundant code

### v2.6.0 (2026-01-07) - API/Supply Chain/Cloud Security

- JWT/CORS/GraphQL/WebSocket security testing
- SBOM generation (CycloneDX/SPDX)
- K8s/gRPC security audit
- 130+ tools

<details>
<summary>View more versions</summary>

### v2.5.0 (2026-01-06)
- CVE multi-source sync & AI PoC generation
- Enhanced C2 covert communication
- 100+ tools

</details>

---

## 🛤️ Roadmap

- [ ] Web UI
- [ ] Distributed scanning
- [ ] More cloud platforms (GCP/Alibaba Cloud)
- [ ] AI automated exploitation
- [x] Full Red Team toolkit
- [x] CVE intelligence & AI PoC
- [x] API/Supply Chain/Cloud security
- [x] Modular architecture refactoring

---

## ⚖️ Disclaimer

> This tool is for **authorized security testing and research only**. Obtain written authorization before testing any target. Comply with local laws and professional ethics. Misuse is at your own risk.

---

## 🤝 Contact

<div align="center">

[![Discord](https://img.shields.io/badge/Discord-Join-7289DA?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/PtVyrMvB)
[![Email](https://img.shields.io/badge/Email-Contact-EA4335?style=for-the-badge&logo=gmail&logoColor=white)](mailto:Coff0xc@protonmail.com)
[![Issues](https://img.shields.io/badge/Issues-Report-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues)

**Made with ❤️ by [Coff0xc](https://github.com/Coff0xc)**

</div>
