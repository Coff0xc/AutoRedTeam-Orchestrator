# 🔥 AutoRedTeam-Orchestrator

[中文](README.md)

> AI-driven automated red-team orchestration framework, cross-platform (Linux / Windows), integrating 130+ security tools and 2000+ payloads. MCP-native for Windsurf / Cursor / Claude Desktop / Kiro.

<p align="center">
  <img src="https://img.shields.io/badge/OS-Linux%20%26%20Windows-557C94?style=for-the-badge&logo=linux&logoColor=white" alt="Cross Platform"/>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/MCP-Native-00ADD8?style=for-the-badge" alt="MCP"/>
  <img src="https://img.shields.io/badge/Tools-130+-FF6B6B?style=for-the-badge" alt="Tools"/>
  <img src="https://img.shields.io/badge/Payloads-2000+-orange?style=for-the-badge" alt="Payloads"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

> Current version: 2.6.0 (see CHANGELOG and VERSION)

---

## 🧭 Overview

- **AI-first**: Intelligent fingerprinting, attack-chain planning, history-aware recommendations, auto payload/tool selection via `modules/ai_decision_engine.py`, `core/attack_chain.py`.
- **End-to-end automation**: Subdomain/port/WAF/fingerprint → vulnerability discovery/verification → reporting (`core/recon/standard.py`, `modules/async_scanner.py`).
- **Red-team modules**: Lateral movement (SMB/SSH/WMI), C2 (Beacon/DNS/HTTP/WebSocket), obfuscation/evasion, stealth traffic, persistence, credentials, AD attacks.
- **Security extensions**: API security (JWT/CORS/Headers/GraphQL/WebSocket), supply chain (CycloneDX/SPDX SBOM, OSV audit, CI/CD scan), cloud native (K8s/gRPC).
- **Performance**: Async scanner, HTTP pool, task queue, multi-layer cache, performance monitor, response filter.
- **Rich resources**: Nuclei 11997+ templates, 2000+ payloads, JS analyzer, AI PoC generator, CVE multi-source sync.

---

## 🛠️ Capability Matrix

### Recon

- Auto/Deep recon: `core/recon/standard.py`, `modules/recon/web_recon_tools.py`
- Port/Service: `modules/recon/nmap_tools.py`, `modules/network/service_tools.py`
- Subdomain/DNS/OSINT: `modules/recon/subdomain_tools.py`, `modules/recon/dns_tools.py`
- WAF/Fingerprint: `modules/component_fingerprint.py`
- JS/Frontend: `modules/js_analyzer.py`

### Vulnerability Scanning

- Nuclei/Nikto/SSL: `modules/vuln_scan/nuclei_tools.py`, `modules/vuln_scan/ssl_tools.py`
- Deep vulns (Shiro/Log4j/SQLi/XSS): `modules/enhanced_detector_tools.py`, `modules/web_attack/*`

### API / Supply Chain / Cloud

- API security: `modules/api_security_tools.py`, `modules/api_security/graphql_security.py`, `modules/api_security/websocket_security.py`
- Supply chain: `modules/supply_chain_tools.py`, `modules/supply_chain/sbom_generator.py`, `modules/supply_chain/dependency_scanner.py`
- Cloud: `modules/cloud_security_tools.py`, `modules/cloud_security/kubernetes_enhanced.py`, `modules/cloud_security/grpc_security.py`

### Red Team / Post-exploitation

- Lateral movement: `core/lateral/smb_lateral.py`, `core/lateral/ssh_lateral.py`, `core/lateral/wmi_lateral.py`
- C2 & stealth: `core/c2/beacon.py`, `core/c2/tunnels.py`, `core/c2/websocket_tunnel.py`
- Evasion: `core/evasion/payload_obfuscator.py`
- Persistence: `core/persistence/windows_persistence.py`, `core/persistence/linux_persistence.py`
- Credentials & AD: `core/credential/credential_dumper.py`, `core/ad/ad_enum.py`, `core/ad/kerberos_attack.py`

### CVE Subsystem

- Multi-source sync: `core/cve/update_manager.py` (NVD/Nuclei/Exploit-DB)
- AI PoC generation: `core/cve/ai_poc_generator.py`

---

## ⚡ Quick Start

### 1) Clone & Install

```bash
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# Install Python dependencies
pip install -r requirements.txt
cp config/config.yaml.example config/config.yaml
```

**External Tools:**

- Linux/WSL: Use package manager to install `nmap`, `nuclei`, `subfinder`, etc.
- Windows: Manual install or use WSL; MCP server runs natively.

### 2) Quick Test

```bash
python mcp_stdio_server.py
python core/cve/update_manager.py sync
```

---

## 🚀 MCP Configuration

### Claude Desktop / Claude Code

Config path:

- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json` or `~/.claude/mcp.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

### Cursor

Config path: `~/.cursor/mcp.json`

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

### Windsurf

Config path: `~/.codeium/windsurf/mcp_config.json`

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

### Kiro

Config path: `~/.kiro/mcp.json`

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

### Usage Examples

Natural language commands in editor:

- "Perform full recon on example.com and generate a report"
- "Scan 192.168.1.0/24 for open ports"
- "Check <https://target.com> for Log4j/Shiro vulnerabilities"
- "Run JWT security scan on the target API"
- "Generate SBOM and scan dependencies for vulnerabilities"
- "Detect privileged containers in K8s cluster"

---

## 🗂️ Directory Structure

```
mcp_stdio_server.py              # MCP server entry
core/
  recon/       - Recon engine (StandardReconEngine)
  c2/          - C2 (Beacon/DNS/HTTP/WebSocket tunnel)
  lateral/     - Lateral movement (SMB/SSH/WMI)
  evasion/     - Obfuscation/evasion
  stealth/     - Stealth communication
  persistence/ - Persistence
  credential/  - Credential harvesting
  ad/          - AD attacks
  cve/         - CVE intel & PoC engine
  exploit/     - Exploitation
modules/
  api_security/    - JWT/CORS/GraphQL/WebSocket security
  supply_chain/    - SBOM/dependency scan/CI-CD security
  cloud_security/  - K8s/gRPC security
  enhanced_detectors/ - Advanced vulnerability detectors
  recon/, vuln_scan/, web_attack/, exploit/
tools/           - MCP tool definitions
utils/, config/, templates/, tests/
```

---

## ✨ Version Highlights

### v2.6.0 (2026-01-07) - API & Cloud Native Security

- **API Security**:
  - JWT: None algorithm / algorithm confusion / weak secret / KID injection
  - CORS: 30+ Origin bypass techniques
  - Security headers: OWASP-based weighted scoring system
  - GraphQL: Introspection / batch DoS / deep nesting / alias overload
  - WebSocket: Origin bypass / CSWSH / auth bypass / compression attack
- **Supply Chain Security**:
  - SBOM: CycloneDX/SPDX format support
  - Dependency scan: OSV API integration (PyPI/npm/Go/Maven)
  - CI/CD scan: GitHub Actions/GitLab CI/Jenkins risk detection
- **Cloud Native Security**:
  - K8s audit: Privileged containers / hostPath / RBAC / NetworkPolicy / Secrets
  - K8s manifest scan: YAML config security analysis
  - gRPC: Reflection API / TLS config / auth bypass
- **Total tools**: 130+ (40+ new API/supply chain/cloud tools)

### v2.5.0 (2026-01-06)

- CVE intel & PoC: Multi-source sync, AI PoC generation, YAML PoC engine
- C2 stealth: WebSocket tunnel, chunked transfer, proxy chain
- Frontend security: JS analyzer, source map leak detection
- 100+ tools, async scan optimization

---

## 🛤️ Roadmap

- [ ] Web UI
- [ ] Distributed scanning
- [ ] More clouds (GCP/Alibaba Cloud)
- [ ] AI automated exploitation
- [x] Red-team modules (lateral/C2/evasion/persistence/creds/AD)
- [x] CVE multi-source sync & AI PoC
- [x] API / supply chain / cloud extensions

---

## ⚖️ Legal

Authorized security testing/research only. Obtain written consent, follow local law and ethics. Misuse is prohibited.

---

## 🤝 Contributing & Contact

- PRs/Issues welcome (see CONTRIBUTING.md, CODE_OF_CONDUCT.md)
- Discord: <https://discord.gg/PtVyrMvB>
- Email: <Coff0xc@protonmail.com>
- Issues: <https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues>
