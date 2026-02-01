<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>AI-Driven Automated Red Team Orchestration Framework</b><br>
  <sub>Cross-platform | 101 MCP Tools | 2000+ Payloads | Full ATT&CK Coverage | Knowledge Graph Enhanced</sub>
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
  <img src="https://img.shields.io/badge/Tools-101-FF6B6B?style=flat-square" alt="Tools">
  <img src="https://img.shields.io/badge/Tests-1461-4CAF50?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Community-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-Docs-blue?style=flat-square&logo=gitbook&logoColor=white" alt="Wiki"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/actions"><img src="https://img.shields.io/github/actions/workflow/status/Coff0xc/AutoRedTeam-Orchestrator/ci.yml?style=flat-square&logo=github-actions&logoColor=white&label=CI" alt="CI"></a>
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/demo.gif" alt="Demo" width="700">
</p>

## Highlights

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     AutoRedTeam-Orchestrator v3.0.1                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  ● 101 MCP Tools       ● 2000+ Payloads     ● 1461 Test Cases              │
│  ● 10-Phase Recon      ● 19 Vuln Detectors  ● 5-Protocol Lateral           │
│  ● MCTS Attack Planner ● Knowledge Graph    ● AI PoC Generation            │
│  ● OOB False Positive  ● DI Container       ● MCP Security Middleware      │
├─────────────────────────────────────────────────────────────────────────────┤
│  Supported AI Editors: Cursor | Windsurf | Kiro | Claude Desktop | VS Code │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Table of Contents

- [Overview](#overview)
- [Core Features](#core-features)
- [Design Philosophy](#design-philosophy)
- [Architecture](#architecture)
- [ATT&CK Coverage Matrix](#attck-coverage-matrix)
- [Quick Start](#quick-start)
  - [System Requirements](#system-requirements)
  - [Installation](#installation)
  - [Verify Installation](#verify-installation)
- [MCP Configuration](#mcp-configuration)
- [Tool Matrix](#tool-matrix-101-mcp-tools)
- [Core Modules](#core-modules)
- [External Tool Integration](#external-tool-integration)
- [Usage Examples](#usage-examples)
  - [Natural Language Commands](#natural-language-commands)
  - [Python API](#python-api)
- [Configuration](#configuration)
- [Performance Tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Development Guide](#development-guide)
- [Changelog](#changelog)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security Policy](#security-policy)
- [Acknowledgments](#acknowledgments)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Overview

**AutoRedTeam-Orchestrator** is an AI-driven automated penetration testing framework built on the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). It wraps 101 security tools as MCP tools, enabling seamless integration with MCP-compatible AI editors (Cursor, Windsurf, Kiro, Claude Desktop) for natural language-driven security testing.

### Why AutoRedTeam-Orchestrator?

| Feature | Traditional Tools | AutoRedTeam |
|---------|-------------------|-------------|
| **Interaction** | CLI memorization | Natural language chat |
| **Learning Curve** | High (many parameters) | Low (AI selects tools) |
| **Tool Integration** | Manual switching | 101 tools unified interface |
| **Attack Planning** | Manual | **MCTS Algorithm + Knowledge Graph** |
| **False Positive Reduction** | Manual verification | **OOB + Statistical Verification** |
| **Reporting** | Manual writing | One-click professional reports |
| **Session Management** | None | Checkpoint/resume support |
| **Security** | Per-tool | **MCP Security Middleware unified protection** |

### Comparison with Similar Projects

| Feature | AutoRedTeam | Nuclei | SQLMap | Metasploit |
|---------|-------------|--------|--------|------------|
| AI Native | ✅ | ❌ | ❌ | ❌ |
| MCP Protocol | ✅ | ❌ | ❌ | ❌ |
| Natural Language | ✅ | ❌ | ❌ | ❌ |
| MCTS Attack Planning | ✅ | ❌ | ❌ | ❌ |
| Knowledge Graph | ✅ | ❌ | ❌ | ❌ |
| Full Automation | ✅ | Partial | Partial | Partial |
| False Positive Filter | Multi-method | Basic | Medium | Basic |

---

## Core Features

<table>
<tr>
<td width="50%">

### AI-Native Design

- **Smart Fingerprinting** - Auto-detect target tech stack (CMS/frameworks/WAF)
- **MCTS Attack Planning** - Monte Carlo Tree Search driven optimal attack paths
- **Knowledge Graph** - Persistent attack knowledge with cross-session learning
- **Historical Feedback Learning** - Continuous strategy optimization
- **Auto Payload Selection** - WAF-aware intelligent mutation
- **AI PoC Generation** - Generate exploit code from CVE descriptions

</td>
<td width="50%">

### Full Automation

- **10-Phase Recon Pipeline** - DNS/Port/Fingerprint/WAF/Subdomain/Directory/JS analysis
- **Vulnerability Discovery & Verification** - Auto scan + **multi-method validation**
- **Smart Exploitation Orchestration** - Feedback loop engine + auto retry
- **One-Click Professional Reports** - JSON/HTML/Markdown formats
- **Session Checkpoint Recovery** - Resume interrupted scans

</td>
</tr>
<tr>
<td width="50%">

### Red Team Toolkit

- **Lateral Movement** - SMB/SSH/WMI/WinRM/PSExec (5 protocols)
- **C2 Communication** - Beacon + DNS/HTTP/WebSocket/ICMP tunnels
- **Evasion & Obfuscation** - XOR/AES/Base64/custom encoders
- **Persistence** - Windows Registry/Scheduled Tasks/WMI/Linux cron/Webshell
- **Credential Access** - Memory extraction/File search/Password spray
- **AD Attacks** - Kerberoasting/AS-REP Roasting/SPN scan

</td>
<td width="50%">

### Security Extensions

- **API Security** - JWT/CORS/GraphQL/WebSocket/OAuth testing
- **Supply Chain Security** - SBOM generation/Dependency audit/CI-CD scan
- **Cloud Native Security** - K8s RBAC/Pod security/gRPC/AWS audit
- **CVE Intelligence** - NVD/Nuclei/ExploitDB multi-source sync
- **WAF Bypass** - 2000+ payloads + 30+ encoding methods

</td>
</tr>
</table>

---

## Design Philosophy

### Core Design Principles

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           Design Philosophy                                 │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│   1. AI-Native                                                             │
│      └─ Not "AI wrapper", but architecturally designed for AI              │
│         └─ Native MCP protocol support                                     │
│         └─ Natural language driven tool selection                          │
│         └─ MCTS algorithm driven attack planning                           │
│                                                                            │
│   2. Verifiable Security                                                   │
│      └─ Multi-method cross-validation to reduce false positives            │
│         └─ Statistical verification (significance testing)                 │
│         └─ Boolean blind verification (True/False response comparison)     │
│         └─ Time-based blind verification (delay detection)                 │
│         └─ OOB verification (DNS/HTTP callback)                            │
│                                                                            │
│   3. Knowledge Persistence                                                 │
│      └─ Attack knowledge persists across sessions                          │
│         └─ Knowledge graph stores target, vuln, credential relationships   │
│         └─ Attack path success rates calculated from history               │
│         └─ Similar target identification accelerates new target testing    │
│                                                                            │
│   4. Security by Design                                                    │
│      └─ Security is core architecture, not add-on                          │
│         └─ MCP Security Middleware: input validation, rate limiting        │
│         └─ TOCTOU Safety: atomic operations, race condition protection     │
│         └─ Memory Safety: resource limits, auto cleanup                    │
│                                                                            │
│   5. Extensible Architecture                                               │
│      └─ Dependency injection container for flexible service composition    │
│         └─ Modular Handler design                                          │
│         └─ External tools YAML configuration                               │
│         └─ Detector composite pattern for arbitrary combinations           │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### Technical Decision Matrix

| Decision | Options | Choice | Rationale |
|----------|---------|--------|-----------|
| **Communication** | REST / gRPC / MCP | MCP | Native AI editor support, seamless NLP interaction |
| **Attack Planning** | Rule Engine / MCTS / RL | MCTS | Online planning, no pre-training, UCB1 exploration-exploitation |
| **Knowledge Storage** | SQL / Graph DB / Memory | Memory Graph + Optional Neo4j | Zero-dependency startup, high-perf queries, optional persistence |
| **Dependency Mgmt** | Globals / DI | DI Container | Testability, replaceability, lifecycle management |
| **Concurrency** | Threading / asyncio / Hybrid | asyncio primary | Optimal for IO-bound, native Python support |
| **Hashing** | MD5 / SHA256 | SHA256 | Higher security, modern standard |

---

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AI Editor Layer                                │
│        Cursor  │  Windsurf  │  Kiro  │  Claude Desktop  │  VS Code         │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ MCP Protocol (JSON-RPC over stdio)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MCP Server Entry                                    │
│                      mcp_stdio_server.py                                   │
│                        (101 tools registered)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                        MCP Security Middleware                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│  │ Input Valid │  │ Rate Limiter│  │ Op Authorize│  │ @secure_tool│       │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│   handlers/       │   │   core/           │   │   modules/        │
│   MCP Handlers    │   │   Core Engines    │   │   Feature Modules │
├───────────────────┤   ├───────────────────┤   ├───────────────────┤
│ • recon_handlers  │   │ • recon/          │   │ • api_security/   │
│ • detector_hdlrs  │   │   10-phase recon  │   │   JWT/CORS/GQL    │
│ • cve_handlers    │   │ • detectors/      │   │ • supply_chain/   │
│ • redteam_hdlrs   │   │   Vuln detectors  │   │   SBOM/Deps       │
│ • lateral_hdlrs   │   │ • mcts_planner    │   │ • cloud_security/ │
│ • external_hdlrs  │   │   MCTS planning   │   │   K8s/gRPC/AWS    │
│ • ai_handlers     │   │ • knowledge/      │   │ • payload/        │
│ • session_hdlrs   │   │   Knowledge graph │   │   2000+ Payloads  │
└───────────────────┘   │ • container       │   └───────────────────┘
                        │   DI Container    │
                        │ • c2/             │
                        │   C2 Comms        │
                        │ • lateral/        │
                        │   Lateral Move    │
                        │ • cve/            │
                        │   CVE Intel+PoC   │
                        └───────────────────┘
```

### Directory Structure

```
AutoRedTeam-Orchestrator/
├── mcp_stdio_server.py          # MCP Server Entry (101 tools registered)
├── VERSION                      # Version file
├── pyproject.toml               # Project config
├── requirements.txt             # Production dependencies
├── requirements-dev.txt         # Development dependencies
│
├── handlers/                    # MCP Tool Handlers (16 modules)
│   ├── recon_handlers.py        # Recon tools (8)
│   ├── detector_handlers.py     # Vuln detection tools (11)
│   ├── api_security_handlers.py # API security tools (7)
│   ├── supply_chain_handlers.py # Supply chain tools (3)
│   ├── cloud_security_handlers.py # Cloud security tools (3)
│   ├── cve_handlers.py          # CVE tools (8)
│   ├── redteam_handlers.py      # Red team core tools (14)
│   ├── lateral_handlers.py      # Lateral movement tools (9)
│   ├── persistence_handlers.py  # Persistence tools (3)
│   ├── ad_handlers.py           # AD attack tools (3)
│   ├── orchestration_handlers.py # Orchestration tools (11)
│   ├── external_tools_handlers.py # External tools (8)
│   ├── ai_handlers.py           # AI assisted tools (3)
│   ├── session_handlers.py      # Session tools (4)
│   ├── report_handlers.py       # Report tools (2)
│   └── misc_handlers.py         # Misc tools (3)
│
├── core/                        # Core Engines
│   ├── __init__.py              # Version definition
│   │
│   ├── security/                # Security Components ⭐ v3.0.2
│   │   └── mcp_security.py      # MCP Security Middleware
│   │
│   ├── container.py             # DI Container ⭐ v3.0.2
│   │
│   ├── mcts_planner.py          # MCTS Attack Planner ⭐ v3.0.2
│   │
│   ├── knowledge/               # Knowledge Graph ⭐ v3.0.2
│   │   ├── __init__.py
│   │   ├── manager.py           # Knowledge Manager
│   │   └── models.py            # Data Models
│   │
│   ├── recon/                   # Recon Engine (10-phase pipeline)
│   ├── detectors/               # Vulnerability Detectors
│   ├── cve/                     # CVE Intelligence
│   ├── c2/                      # C2 Communication Framework
│   ├── lateral/                 # Lateral Movement
│   ├── evasion/                 # Evasion & Obfuscation
│   ├── persistence/             # Persistence Mechanisms
│   ├── credential/              # Credential Access
│   ├── ad/                      # AD Attacks
│   ├── session/                 # Session Management
│   ├── tools/                   # External Tool Management
│   └── exfiltration/            # Data Exfiltration
│
├── modules/                     # Feature Modules
│   ├── api_security/            # API Security
│   ├── supply_chain/            # Supply Chain Security
│   ├── cloud_security/          # Cloud Security
│   └── payload/                 # Payload Engine
│
├── utils/                       # Utility Functions
├── wordlists/                   # Built-in Wordlists
├── config/                      # Configuration Files
├── tests/                       # Test Suite (1461 test cases)
├── poc-templates/               # PoC Templates
├── templates/                   # Report Templates
├── scripts/                     # Utility Scripts
└── docs/                        # Documentation
```

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

# Run tests
pytest tests/ -v
```

### Verify Installation

```bash
# Check version
python mcp_stdio_server.py --version
# Output: AutoRedTeam-Orchestrator v3.0.1

# Run self-check
python -c "from core import __version__; print(f'Core version: {__version__}')"

# Run core module tests
pytest tests/test_mcp_security.py tests/test_container.py tests/test_mcts_planner.py tests/test_knowledge_manager.py tests/test_advanced_verifier.py -v
# Expected: 291+ passed
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

## Tool Matrix (101 MCP Tools)

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

## Core Modules

### 1. MCP Security Middleware (v3.0.2)

**Location**: `core/security/mcp_security.py`

Provides unified security protection layer for all MCP tool calls:

```python
from core.security.mcp_security import MCPSecurityMiddleware, RateLimitConfig

security = MCPSecurityMiddleware(
    rate_limit_config=RateLimitConfig(
        requests_per_minute=60,
        burst_limit=10,
    ),
    max_risk=RiskLevel.HIGH,
)

# Validate target
result = security.validate_target("192.168.1.1")
if not result.valid:
    print(f"Rejected: {result.errors}")

# Decorator protection
@security.secure_tool(operation="port_scan", rate_limit_key="scan")
async def port_scan(target: str):
    # ...
```

**Core Features**:
- **Input Validation**: IP/Domain/URL/CIDR/Port/Path validation, SSRF detection
- **Rate Limiting**: Sliding window + Token bucket, resource exhaustion prevention
- **Operation Authorization**: Risk-level based operation control
- **Memory Protection**: Auto cleanup of expired data, memory leak prevention

### 2. MCTS Attack Planner (v3.0.2)

**Location**: `core/mcts_planner.py`

Uses Monte Carlo Tree Search algorithm to plan optimal attack paths:

```python
from core.mcts_planner import MCTSPlanner, AttackState

planner = MCTSPlanner(exploration_weight=1.414, max_depth=10)

state = AttackState(
    target="192.168.1.100",
    target_type="linux_server",
    open_ports={22: "ssh", 80: "http"},
)

result = planner.plan(state, iterations=1000)
print(f"Recommended actions: {result['recommended_actions']}")
```

**Core Features**:
- **UCB1 Algorithm**: Balances exploration and exploitation
- **Action Generation**: Intelligently generates available actions based on state
- **Attack Simulation**: Simulates attack execution to estimate success rates
- **Path Extraction**: Extracts optimal attack path sequences

### 3. Knowledge Graph (v3.0.2)

**Location**: `core/knowledge/`

Persistent storage for attack knowledge with cross-session learning:

```python
from core.knowledge import KnowledgeManager

km = KnowledgeManager()

# Store target
target_id = km.store_target("192.168.1.100", "linux_server")

# Store service
service_id = km.store_service(target_id, "nginx", 80)

# Store vulnerability
vuln_id = km.store_vulnerability(service_id, "CVE-2021-44228", "critical")

# Find attack paths
paths = km.get_attack_paths(target_id, credential_id)

# Find similar targets
similar = km.find_similar_targets("192.168.1.100")
```

**Core Features**:
- **Entity Storage**: Target, Service, Vulnerability, Credential
- **Relationship Modeling**: HOSTS, HAS_VULNERABILITY, OBTAINED_FROM
- **BFS Path Discovery**: Multi-path discovery support
- **Similarity Matching**: Same-subnet/same-domain identification

### 4. Advanced Verifier (v3.0.2 Enhanced)

**Location**: `core/detectors/advanced_verifier.py`

Multi-method cross-validation to reduce false positive rates:

```python
from core.detectors.advanced_verifier import AdvancedVerifier

verifier = AdvancedVerifier(callback_server="oob.example.com")

results = verifier.multi_method_verify(
    url="http://target.com/api?id=1",
    vuln_type="sqli",
    request_func=make_request,
    methods=["statistical", "boolean_blind", "time_based"],
)

aggregated = verifier.aggregate_results(results)
print(f"Status: {aggregated.status}, Confidence: {aggregated.confidence:.2%}")
```

**Verification Methods**:
- **Statistical Verification**: Multi-sample response difference significance
- **Boolean Blind Verification**: True/False condition comparison
- **Time-based Blind Verification**: Delay detection with network jitter compensation
- **OOB Verification**: DNS/HTTP out-of-band callback confirmation

### 5. Dependency Injection Container (v3.0.2)

**Location**: `core/container.py`

Flexible service composition and lifecycle management:

```python
from core.container import Container, singleton, inject

container = Container()

# Register services
container.register_singleton(KnowledgeManager)
container.register_transient(SQLiDetector)

# Use decorators
@singleton
class ConfigManager:
    pass

# Inject dependencies
config = inject(ConfigManager)

# Scoped container (request-level)
with container.create_scope() as scope:
    service = scope.resolve(RequestService)
```

**Core Features**:
- **Lifecycle**: Singleton, Scoped, Transient
- **Auto Injection**: Constructor parameter auto-resolution
- **Cycle Detection**: Detect and report circular dependencies
- **Resource Cleanup**: Scoped containers auto-call dispose()

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

  sqlmap:
    enabled: true
    path: "${base_path}/sqlmap/sqlmap.py"
    python_script: true

  ffuf:
    enabled: true
    path: "${base_path}/ffuf/ffuf"

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

#### MCTS Attack Planning

```python
from core.mcts_planner import MCTSPlanner, AttackState

planner = MCTSPlanner(exploration_weight=1.414, max_depth=10)

state = AttackState(
    target="192.168.1.100",
    target_type="linux_server",
    open_ports={22: "ssh", 80: "http", 3306: "mysql"},
)

result = planner.plan(state, iterations=1000)

print(f"Recommended attack sequence:")
for action, visits, reward in result['recommended_actions']:
    print(f"  - {action.type.value}: {action.target_port} (confidence: {reward:.2f})")
```

#### Knowledge Graph

```python
from core.knowledge import KnowledgeManager

km = KnowledgeManager()

# Build knowledge
target_id = km.store_target("192.168.1.100", "linux_server")
service_id = km.store_service(target_id, "nginx", 80)
vuln_id = km.store_vulnerability(service_id, "CVE-2021-44228", "critical")

# Query attack paths
paths = km.get_attack_paths(target_id, vuln_id)
for path in paths:
    print(f"Path length: {path.length}, Success rate: {path.success_rate:.2%}")

# Find similar targets
similar = km.find_similar_targets("192.168.1.100", top_k=5)
for match in similar:
    print(f"Similar target: {match.entity.properties['target']}, Score: {match.score:.2f}")
```

---

## Configuration

### Environment Variables (.env)

```bash
# ========== Security ==========
REDTEAM_MASTER_KEY=
AUTOREDTEAM_API_KEY=
AUTOREDTEAM_AUTH_MODE=permissive

# ========== API Keys ==========
OPENAI_API_KEY=your_key
ANTHROPIC_API_KEY=your_key
SHODAN_API_KEY=your_key
CENSYS_API_ID=your_id
CENSYS_API_SECRET=your_secret
NVD_API_KEY=your_key
GITHUB_TOKEN=your_token

# ========== Proxy ==========
HTTP_PROXY=
HTTPS_PROXY=
SOCKS_PROXY=

# ========== Global ==========
VERIFY_SSL=false
RATE_LIMIT_DELAY=0.3
MAX_THREADS=50
REQUEST_TIMEOUT=10

# ========== Logging ==========
LOG_LEVEL=INFO
LOG_FILE=logs/redteam.log
```

---

## Performance Tuning

### Concurrency Configuration

```yaml
# config/performance.yaml
concurrency:
  max_threads: 100
  max_async_tasks: 200
  connection_pool_size: 50

rate_limiting:
  requests_per_second: 50
  burst_size: 100

timeouts:
  connect: 5
  read: 30
  total: 120
```

### Memory Optimization

```python
engine = StandardReconEngine(
    target="192.168.0.0/16",
    config=ReconConfig(
        streaming_mode=True,
        batch_size=1000,
        memory_limit="2GB"
    )
)
```

---

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| MCP server won't connect | Path error or Python env issue | Check absolute path, verify Python interpreter |
| Import errors | PYTHONPATH not set | Add `PYTHONPATH` env variable |
| External tool fails | Tool not installed or path error | Run `ext_tools_status` |
| CVE sync fails | Network or API rate limit | Check network, configure NVD_API_KEY |
| Slow scanning | Low concurrency config | Adjust `MAX_THREADS` and `RATE_LIMIT_DELAY` |
| Out of memory | Large-scale scan | Enable `streaming_mode`, set `memory_limit` |

### Debug Mode

```bash
LOG_LEVEL=DEBUG python mcp_stdio_server.py
python -m py_compile mcp_stdio_server.py
pytest tests/test_mcp_security.py::TestInputValidator -v
```

---

## FAQ

<details>
<summary><b>Q: How to use in offline environments?</b></summary>

1. Pre-download CVE database: `python core/cve/update_manager.py sync --offline-export`
2. Use local wordlist files
3. Disable network features: `OFFLINE_MODE=true`

</details>

<details>
<summary><b>Q: How to add custom detectors?</b></summary>

1. Create new file in `core/detectors/`
2. Inherit `BaseDetector` class
3. Implement `detect()` and `async_detect()` methods
4. Register MCP tool in `handlers/detector_handlers.py`

</details>

<details>
<summary><b>Q: How does MCTS planner work?</b></summary>

MCTS plans attack paths through four phases:

1. **Selection**: UCB1 algorithm selects optimal path from root
2. **Expansion**: Expand new attack actions at leaf nodes
3. **Simulation**: Simulate attack execution and evaluate rewards
4. **Backpropagation**: Propagate rewards back to update path nodes

UCB1 formula: `UCB1 = Q/N + c * sqrt(ln(N_parent) / N)`

Where `c = sqrt(2)` is exploration weight, balancing "known good paths" and "unexplored paths".

</details>

<details>
<summary><b>Q: How does Knowledge Graph reduce duplicate work?</b></summary>

1. **Target Similarity**: Identify same-subnet/same-domain targets, reuse vuln info
2. **Attack Path Success Rates**: Calculate path success rates from history
3. **Credential Association**: Auto-associate credentials with accessible targets
4. **Action History Learning**: Record action success rates, optimize future decisions

</details>

---

## Development Guide

### Code Standards

```bash
# Format code
black core/ modules/ handlers/ utils/
isort core/ modules/ handlers/ utils/

# Static analysis
pylint core/ modules/ handlers/ utils/
mypy core/ modules/ handlers/ utils/

# Run tests
pytest tests/ -v --cov=core --cov-report=html
```

### Adding New MCP Tools

```python
# 1. Add handler in handlers/
# handlers/my_handlers.py

from mcp import tool

@tool()
async def my_new_tool(target: str, option: str = "default") -> dict:
    """Tool description

    Args:
        target: Target address
        option: Optional parameter

    Returns:
        Result dictionary
    """
    return {"success": True, "data": ...}

# 2. Import in mcp_stdio_server.py
from handlers.my_handlers import my_new_tool
```

---

## Changelog

### v3.0.2 (In Development) - Architecture Hardening

**New Modules** (Implemented, pending release)
- **MCP Security Middleware** - Input validation, rate limiting, operation authorization
- **DI Container** - Lifecycle management, circular dependency detection
- **MCTS Attack Planner** - UCB1 algorithm, attack path optimization
- **Knowledge Graph** - Entity relationship storage, BFS path discovery
- **Advanced Verifier Enhancement** - OOB thread safety, SSTI payloads

**Security Fixes**
- Fixed TOCTOU race conditions (extended lock scope)
- Fixed duration authorization expiry logic
- Added SSRF detection (private IP validation)
- Fixed Rate Limiter memory leak (max_keys eviction)
- Fixed DNS injection (token ID sanitization)
- MD5 → SHA256 hash upgrade

**Test Enhancement**
- Added 291 test cases (mcp_security: 62, container: 39, mcts: 57, verifier: 43, knowledge: 90)
- Thread safety test coverage
- Integration test workflows

### v3.0.1 (2026-01-30) - Quality Hardening

**Added**
- CVE auto-exploit enhancement (`cve_auto_exploit`, `cve_exploit_with_desc`, `cve_generate_poc`)
- AI PoC generator (`core/cve/ai_poc_generator.py`)

**Fixed**
- Version sync - Unified VERSION/pyproject.toml/source code
- ToolCounter fix - Added external_tools/lateral/persistence/ad categories
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

---

## Roadmap

### In Progress

- [ ] v3.0.2 Release (MCP Security Middleware, MCTS Planner, Knowledge Graph, DI Container)
- [ ] Web UI management interface
- [ ] Distributed scanning cluster

### Planned

- [ ] More cloud platforms (GCP/Alibaba Cloud/Tencent Cloud)
- [ ] Burp Suite plugin integration
- [ ] Mobile app security testing
- [ ] AI autonomous attack agent
- [ ] Neo4j knowledge graph backend

### Completed (v3.0.1)

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
- `security:` Security related

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Security Policy

- **Responsible Disclosure**: Report security vulnerabilities to [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com)
- **Authorized Use Only**: This tool is for authorized security testing and research only
- **Compliance**: Ensure compliance with local laws before use

See [SECURITY.md](SECURITY.md) for details.

---

## Acknowledgments

### Core Dependencies

| Project | Purpose | License |
|---------|---------|---------|
| [MCP Protocol](https://modelcontextprotocol.io/) | AI tool protocol standard | MIT |
| [aiohttp](https://github.com/aio-libs/aiohttp) | Async HTTP client | Apache-2.0 |
| [pydantic](https://github.com/pydantic/pydantic) | Data validation | MIT |
| [pytest](https://github.com/pytest-dev/pytest) | Testing framework | MIT |

### Design Inspiration

| Project | Inspiration |
|---------|-------------|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability scanner engine design |
| [SQLMap](https://github.com/sqlmapproject/sqlmap) | SQL injection detection approach |
| [Impacket](https://github.com/fortra/impacket) | Network protocol implementation |
| [Metasploit](https://github.com/rapid7/metasploit-framework) | Post-exploitation module design |

### Algorithm References

| Algorithm | Purpose | Reference |
|-----------|---------|-----------|
| UCB1 | MCTS exploration-exploitation balance | Auer et al., 2002 |
| BFS | Knowledge graph path discovery | - |
| Token Bucket | Rate limiting | - |
| Sliding Window | Rate limiting | - |

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Coff0xc/AutoRedTeam-Orchestrator&type=Date)](https://star-history.com/#Coff0xc/AutoRedTeam-Orchestrator&Date)

---

## License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 Coff0xc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

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
>
> This tool contains red team attack capabilities (lateral movement, C2 communication, persistence, etc.), intended only for:
> - Authorized penetration testing
> - Security research and education
> - CTF competitions
> - Defensive capability validation
>
> **Prohibited for any illegal purposes.**

---

<p align="center">
  <img src="https://img.shields.io/badge/Built%20with-Python%20%26%20%E2%9D%A4-blue?style=for-the-badge" alt="Built with Python">
</p>

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Coff0xc">Coff0xc</a></b>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB">Discord</a> ·
  <a href="mailto:Coff0xc@protonmail.com">Email</a> ·
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues">Issues</a>
</p>

<p align="center">
  <sub>If this project helps you, please consider giving it a ⭐ Star!</sub>
</p>
