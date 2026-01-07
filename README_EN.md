# 🔥 AutoRedTeam-Orchestrator
[中文](README.md)

> AI-driven automated red-team orchestration, cross-platform (Linux / Windows), integrating 100+ security tools and 2000+ payloads. MCP-native for Windsurf / Cursor / Claude Desktop / Kiro.

<p align="center">
  <img src="https://img.shields.io/badge/OS-Linux%20%26%20Windows-557C94?style=for-the-badge&logo=linux&logoColor=white" alt="Cross Platform"/>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/MCP-Native-00ADD8?style=for-the-badge" alt="MCP"/>
  <img src="https://img.shields.io/badge/Tools-100+-FF6B6B?style=for-the-badge" alt="Tools"/>
  <img src="https://img.shields.io/badge/Payloads-2000+-orange?style=for-the-badge" alt="Payloads"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

> Current version: 2.5.0 (see CHANGELOG and VERSION)

---

## 🧭 Overview (full)
- AI-first: intelligent fingerprinting, attack-chain planning, history-aware recommendations, auto payload/tool selection (see `modules/ai_decision_engine.py`, `core/attack_chain.py`).
- End-to-end automation: subdomain/port/WAF/fingerprint → vulnerability discovery/verification → reporting (`auto_recon.py`, `core/complete_recon_toolkit.py`, `modules/async_scanner.py`).
- Red-team modules: lateral (SMB/SSH/WMI), C2 (Beacon/DNS/HTTP/WebSocket), obfuscation/evasion, stealth traffic, persistence, credentials, AD attacks (`core/lateral/*`, `core/c2/*`, `core/evasion/*`, `core/stealth/*`, `core/persistence/*`, `core/credential/*`, `core/ad/*`).
- Extensions: API security (JWT/CORS/Headers/GraphQL/WebSocket), supply chain (CycloneDX/SPDX SBOM, OSV audit, CI/CD scan), cloud (K8s/gRPC) via `modules/api_security_*`, `modules/supply_chain_*`, `modules/cloud_security_*`.
- Speed & reliability: async scanner/HTTP pool/task queue/multi-layer cache/performance monitor/response filter (`modules/async_http_pool.py`, `modules/async_scanner.py`, `utils/task_queue.py`, `modules/smart_cache.py`, `modules/performance_monitor.py`, `core/response_filter.py`).
- Rich resources: Nuclei 11997+ templates, 2000+ payloads, JS analyzer, AI PoC generator, CVE multi-source sync (`modules/mega_payloads.py`, `modules/smart_payload_engine.py`, `modules/js_analyzer.py`, `core/cve/*`).

---

## 🛠️ Capability Matrix
### Recon
- Auto/Deep recon: `auto_recon.py`, `core/complete_recon_toolkit.py`, `modules/recon/web_recon_tools.py`
- Port/Service: `modules/recon/nmap_tools.py`, `modules/network/service_tools.py`
- Subdomain/DNS/OSINT: `modules/recon/subdomain_tools.py`, `modules/recon/dns_tools.py`, `modules/recon/osint_tools.py`
- WAF/Fingerprint: `modules/component_fingerprint.py`, `modules/vuln_scan/vuln_search.py`
- JS/Frontend: `modules/js_analyzer.py`

### Vulnerability Scanning
- Nuclei/Nikto/SSL: `modules/vuln_scan/nuclei_tools.py`, `modules/vuln_scan/nikto_tools.py`, `modules/vuln_scan/ssl_tools.py`
- Deep vulns (Shiro/Log4j/SQLi/XSS etc.): `modules/enhanced_detector_tools.py`, `modules/vuln_scan/*`, `modules/web_attack/xss_tools.py`, `modules/web_attack/sqli_tools.py`
- XSS/XXE/Fuzz: `modules/web_attack/advanced_xss.py`, `modules/web_attack/xxe_tools.py`, `modules/web_attack/fuzzing_tools.py`

### API / Supply Chain / Cloud
- API security: `modules/api_security_tools.py`, `modules/api_security/graphql_security.py`, `modules/api_security/websocket_security.py`, `modules/enhanced_detectors/*`
- Supply chain: `modules/supply_chain_tools.py`, `modules/supply_chain/sbom_generator.py`, `modules/supply_chain/dependency_scanner.py`, `modules/supply_chain/cicd_security.py`
- Cloud: `modules/cloud_security_tools.py`, `modules/cloud_security/kubernetes_enhanced.py`, `modules/cloud_security/grpc_security.py`, `modules/cloud/*`

### Exploitation / Payloads
- Payload query & generation: `modules/mega_payloads.py`, `modules/smart_payload_engine.py`, `modules/smart_payload_selector.py`
- Exploit/PoC: `modules/exploit_templates.py`, `modules/exploit/reverse_shell.py`, `modules/exploit/msf_tools.py`
- Pure Python SQLi/scan: `core/exploit/pure_sqli.py`, `core/exploit/pure_scanner.py`

### Red Team / Post-exploitation
- Lateral movement: `core/lateral/smb_lateral.py`, `core/lateral/ssh_lateral.py`, `core/lateral/wmi_lateral.py`
- C2 & stealth: `core/c2/beacon.py`, `core/c2/tunnels.py`, `core/c2/websocket_tunnel.py`, `core/stealth/*`
- Evasion/obfuscation: `core/evasion/payload_obfuscator.py`
- Persistence: `core/persistence/windows_persistence.py`, `core/persistence/linux_persistence.py`, `core/persistence/webshell_manager.py`
- Credentials & AD: `core/credential/credential_dumper.py`, `core/credential/password_finder.py`, `core/ad/ad_enum.py`, `core/ad/kerberos_attack.py`
- Privilege/host enum: `modules/post_exploit/privesc_tools.py`, `modules/post_exploit/enum_tools.py`

### Reporting / Orchestration / Monitoring
- Reports: `utils/report_generator.py` (JSON/HTML/PDF/Markdown with templates)
- Task queue: `utils/task_queue.py`
- Performance: `modules/performance_monitor.py`
- Cache: `modules/smart_cache.py`
- Output polish: `utils/terminal_output.py`, `utils/terminal_display.py`

### CVE Subsystem
- Multi-source sync: `core/cve/update_manager.py` (NVD/Nuclei/Exploit-DB)
- Subscription filtering: `core/cve/subscription_manager.py`
- AI PoC generation: `core/cve/ai_poc_generator.py`
- MCP integration: `core/cve/mcp_integration.py`

---

## ⚡ Quick Start (Linux / Windows)
### 1) Clone & Dependencies
```bash
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# Linux / WSL recommended
chmod +x setup.sh
sudo ./setup.sh                 # external tools
pip install -r requirements.txt # Python deps
cp config/config.yaml.example config/config.yaml
# nuclei -update-templates      # optional
```

Windows:
- Run `pip install -r requirements.txt`.
- External tools (nmap/nuclei/subfinder, etc.) need manual install or WSL; MCP server and pure Python engines (pure SQLi, CVE system) run natively on Windows.

### 2) Quick taste
```bash
python auto_recon.py https://example.com            # smart recon
python mcp_stdio_server.py                          # MCP server
python core/cve/update_manager.py sync              # CVE sync
python core/cve/update_manager.py search "Log4j"    # CVE search
python core/cve/ai_poc_generator.py --help          # AI PoC
```

---

## 🚀 Usage
### MCP (recommended, cross-platform)
```bash
./setup_windsurf_mcp.sh   # auto-config for Windsurf
# see MCP_CONFIG_GUIDE.md for Cursor/Claude/Kiro pointing to mcp_stdio_server.py
```
Use natural language in the editor:
- “Perform full recon on example.com and generate a report”
- “Scan 192.168.1.0/24 for open ports and services”
- “Check https://target.com for Log4j/Shiro”

### Standalone HTTP
```bash
python main.py -H 0.0.0.0 -p 5000
# browse http://localhost:5000/tools
```

---

## 🔧 Configuration (config/config.yaml)
```yaml
server: {host: "127.0.0.1", port: 5000}
ai: {provider: "openai", model: "gpt-4", api_key: ""}
scanning: {default_threads: 10, default_delay: 100, rate_limit: 150}
api_keys: {shodan: "", censys_id: "", censys_secret: "", virustotal: ""}
wordlists:
  directories: "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
  passwords: "/usr/share/wordlists/rockyou.txt"
  subdomains: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
```

---

## 🗂️ Structure (excerpt)
```
main.py / mcp_stdio_server.py / auto_recon.py / mcp_tools.py
core/
  attack_chain.py, tool_chain.py, intelligent_recon_engine.py, complete_recon_toolkit.py
  response_filter.py, session_manager.py, mega_payload_library.py, tool_registry.py
  c2/, lateral/, evasion/, stealth/, persistence/, credential/, ad/, cve/, exploit/
modules/
  async_scanner.py, async_http_pool.py, ai_decision_engine.py, adaptive_payload_engine.py
  performance_monitor.py, smart_cache.py, optimization_tools.py
  recon/, vuln_scan/, web_attack/, exploit/, api_security/, cloud_security/, supply_chain/
  mega_payloads.py, smart_payload_selector.py, smart_payload_engine.py
payloads/complete_payload_db.json
utils/ (report_generator.py, task_queue.py, tool_checker.py, terminal_output.py)
config/, templates/, poc-templates/, scripts/, tests/
```

---

## ✨ Highlights in 2.5.0 (2026-01-06)
- CVE intel & PoC: multi-source sync (NVD/Nuclei/Exploit-DB), subscription filtering, AI PoC generation, YAML PoC engine, new MCP tools.
- C2 stealth: WebSocket tunnel, chunked transfer, proxy chain.
- Frontend security: JS analyzer, source map leak detection.
- Tooling: 100+ tools, enhanced MCP registration.
- Reliability: async scan improvements, cleaned bare `except`, Python 3.10+ compatibility fixes.

---

## 🛤️ Roadmap
- [ ] Web UI
- [ ] Distributed scanning
- [ ] More clouds (GCP/Alibaba Cloud)
- [ ] AI automated exploitation
- [x] Red-team modules (lateral/C2/evasion/stealth/persistence/creds/AD)
- [x] CVE multi-source sync & AI PoC
- [x] API / supply chain / cloud extensions
- [x] Performance monitor, smart cache, response filter

---

## ⚖️ Legal
Authorized security testing/research only. Obtain written consent, follow local law and ethics. Misuse is prohibited.

---

## 🤝 Contributing & Contact
- PRs/Issues welcome (see CONTRIBUTING.md, CODE_OF_CONDUCT.md).
- Email: Coff0xc@protonmail.com
- Issues: https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues
```
