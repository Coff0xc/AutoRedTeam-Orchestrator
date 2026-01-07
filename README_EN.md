# 🔥 AutoRedTeam-Orchestrator
[中文](README.md)

> AI-driven automated red-team orchestration with 155+ tools, 2000+ payloads, 95%+ MITRE ATT&CK coverage. Native MCP for Windsurf / Cursor / Claude Desktop / Kiro.

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux"/>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/MCP-Native-00ADD8?style=for-the-badge" alt="MCP"/>
  <img src="https://img.shields.io/badge/Tools-155+-FF6B6B?style=for-the-badge" alt="Tools"/>
  <img src="https://img.shields.io/badge/Payloads-2000+-orange?style=for-the-badge" alt="Payloads"/>
  <img src="https://img.shields.io/badge/ATT%26CK-95%25+-red?style=for-the-badge" alt="ATT&CK Coverage"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

---

## 🧭 Overview
- AI-first: fingerprinting, attack-chain planning, history-aware recommendations, auto payload/tool selection.
- End-to-end automation: subdomains/ports/WAF/fingerprints → vuln discovery & verification → reporting.
- Red-team modules: lateral (SMB/SSH/WMI), C2 (Beacon/DNS/HTTP), obfuscation/evasion, stealth traffic, persistence, credential harvesting, AD attacks.
- Extensions: API security (JWT/CORS/Headers/GraphQL/WebSocket), supply chain (CycloneDX/SPDX SBOM, OSV audit, CI/CD scan), cloud (K8s/gRPC).
- Speed & reliability: async scanner, multi-layer cache, performance monitor, task queue, response de-dup & false-positive filter.
- Rich resources: Nuclei 11997+ templates, practical payloads (Shiro/Log4j/Fastjson), 100+ WAF bypass, NoSQL/GraphQL/JSON injections.

---

## 🛠️ Feature Overview (selected commands)
| Area | Capability | Commands |
| --- | --- | --- |
| 🔎 Recon | Auto/Deep recon, fingerprint/WAF | `auto_recon` `intelligent_recon` `complete_recon_workflow` `identify_tech` |
| 🛡️ Vulnerability | Nuclei full/CVE, Shiro/Log4j/SQLi/XSS, SSL | `nuclei_complete_scan` `nuclei_cve` `deep_vuln_scan` `xss_scan` `sslscan` |
| 🧩 API / Supply Chain / Cloud | JWT/CORS/Headers/GraphQL/WebSocket; SBOM/audit/CI-CD; K8s/gRPC | `jwt_full_scan` `cors_bypass_test` `graphql_full_scan` `websocket_full_scan` `sbom_generate` `dependency_audit` `cicd_security_scan` `k8s_full_scan` `grpc_full_scan` |
| 🎯 Exploitation & Payloads | Payload query/gen, exploit fetch, reverse shell, MSF | `get_payloads` `query_payload_library` `get_exploit` `reverse_shell` `msfvenom` |
| 🕵️ Red Team | Lateral/C2/evasion/stealth/persistence/creds/AD | `lateral_smb_exec` `lateral_ssh_exec` `c2_beacon_start` `evasion_obfuscate_payload` `stealth_proxy_pool` `persistence_windows` `credential_dump` `ad_kerberos_attack` |
| 📑 Reporting & Ops | Reports, task queue, perf/cache | `generate_report` `task_submit` `task_status` `perf_summary` `cache_stats` |
| 🔍 Utilities | CVE search, AI attack plan, smart service scan | `cve_search` `ai_attack_plan` `smart_service_scan` |

---

## ⚡ Quick Start
```bash
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

chmod +x setup.sh && sudo ./setup.sh   # install external deps
pip install -r requirements.txt
cp config/config.yaml.example config/config.yaml
# nuclei -update-templates             # optional
```

- Requirements: Kali/Ubuntu/Debian, Python 3.10+, root for some tools.
- Optional: `impacket` (SMB/WMI), `paramiko` (SSH tunnel), `pycryptodome` (AES).

---

## 🚀 Usage
### MCP (recommended)
```bash
./setup_windsurf_mcp.sh   # auto-configure MCP
```
Examples in editor chat:
- “Perform full recon on example.com and output a report”
- “Scan 192.168.1.0/24 for open ports and services”
- “Check https://target.com for Log4j/Shiro”

### Standalone HTTP
```bash
python main.py -H 0.0.0.0 -p 5000
# browse http://localhost:5000/tools
```

---

## 🔧 Configuration
Edit `config/config.yaml`:
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
core/ (attack_chain, tool_chain, intelligent_recon_engine, response_filter,
      c2/, lateral/, evasion/, stealth/, persistence/, credential/, ad/, cve/)
modules/ (async_scanner, ai_decision_engine, adaptive_payload_engine,
          enhanced_detector_tools, api_security_tools, supply_chain_tools,
          cloud_security_tools, smart_payload_selector, mega_payloads,
          vuln_correlation_engine, performance_monitor, smart_cache, nuclei_tools, ...)
payloads/complete_payload_db.json
utils/ (report_generator.py, task_queue.py, tool_checker.py)
config/, setup.sh, setup_windsurf_mcp.sh
```

---

## ✨ What’s New in v2.6.0 (2026-01-07)
- API security: JWT/CORS/headers/GraphQL/WebSocket full scans.
- Supply chain: CycloneDX/SPDX SBOM, OSV audit, CI/CD config scan.
- Cloud: K8s (privileged/HostPath/RBAC/NetworkPolicy/Secrets); gRPC (reflection/TLS/auth).
- Response filter: SPA false-positive check, 404 baselines, de-dup; fixes `sensitive_scan` / `auth_bypass_detect`.
- Tool count 155+, ATT&CK coverage 95%+.

---

## 🛤️ Roadmap
- [ ] Web UI
- [ ] Distributed scanning
- [ ] More clouds (GCP/Alibaba Cloud)
- [ ] AI automated exploitation
- [x] Red-team modules (lateral/C2/evasion/stealth/persistence/creds/AD)
- [x] API / supply chain / cloud extensions
- [x] Performance monitor & smart cache

---

## ⚖️ Legal
Authorized security testing/research only; obtain written consent; follow laws/ethics; misuse is prohibited.

---

## 🤝 Contributing & Contact
- PRs/Issues welcome.
- Email: Coff0xc@protonmail.com
- Issues: https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues
```
