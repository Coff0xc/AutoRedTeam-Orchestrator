<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>KI-gesteuertes automatisiertes Red Team Orchestrierungs-Framework</b><br>
  <i>Plattformübergreifend · 74 MCP-Tools · 2000+ Payloads · Vollständige ATT&CK-Abdeckung</i>
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
  <a href="LICENSE"><img src="https://img.shields.io/badge/Lizenz-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License"></a>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Community_beitreten-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-Dokumentation-blue?style=for-the-badge&logo=gitbook&logoColor=white" alt="Wiki"></a>
</p>

---

## 📖 Inhaltsverzeichnis

- [Kernfunktionen](#-kernfunktionen)
- [ATT&CK-Abdeckungsmatrix](#️-attck-abdeckungsmatrix)
- [Schnellstart](#-schnellstart)
- [MCP-Konfiguration](#-mcp-konfiguration)
- [Tool-Matrix](#️-tool-matrix)
- [Verwendungsbeispiele](#-verwendungsbeispiele)
- [Architektur](#-architektur)
- [Änderungsprotokoll](#-änderungsprotokoll)
- [Roadmap](#️-roadmap)
- [Beitragsrichtlinien](#-beitragsrichtlinien)
- [Sicherheitsrichtlinie](#-sicherheitsrichtlinie)
- [Danksagungen](#-danksagungen)
- [Lizenz](#-lizenz)

---

## 🎯 Kernfunktionen

<table>
<tr>
<td width="50%">

### 🤖 KI-natives Design
- **Intelligentes Fingerprinting** - Automatische Erkennung des Tech-Stacks
- **Angriffsketten-Planung** - KI-gesteuerte Angriffspfad-Empfehlungen
- **Historisches Feedback-Lernen** - Kontinuierliche Strategieoptimierung
- **Automatische Payload-Auswahl** - WAF-bewusste intelligente Mutation
- **KI-PoC-Generierung** - Exploit-Code aus CVE-Beschreibungen generieren

</td>
<td width="50%">

### ⚡ Vollautomatisierung
- **10-Phasen-Aufklärungs-Pipeline** - DNS/Port/Fingerprint/WAF/JS-Analyse
- **Schwachstellenerkennung & Verifizierung** - Auto-Scan + OOB-Validierung
- **Intelligente Exploit-Orchestrierung** - Feedback-Schleife + Auto-Retry
- **Ein-Klick-Profi-Berichte** - JSON/HTML/Markdown-Formate
- **Sitzungs-Checkpoint-Wiederherstellung** - Unterbrochene Scans fortsetzen

</td>
</tr>
<tr>
<td width="50%">

### 🔴 Red Team Toolkit
- **Laterale Bewegung** - SMB/SSH/WMI/WinRM/PSExec
- **C2-Kommunikation** - Beacon + DNS/HTTP/WebSocket-Tunnel
- **Umgehung & Verschleierung** - XOR/AES/Base64 Multi-Layer-Kodierung
- **Persistenz** - Windows Registry/Geplante Aufgaben/Linux cron
- **Credential-Zugriff** - Speicherextraktion/Dateisuche
- **AD-Angriffe** - Kerberoasting/AS-REP Roasting

</td>
<td width="50%">

### 🛡️ Sicherheitserweiterungen
- **API-Sicherheit** - JWT/CORS/GraphQL/WebSocket/OAuth
- **Supply-Chain-Sicherheit** - SBOM-Generierung/Abhängigkeits-Audit/CI-CD-Scan
- **Cloud-Native-Sicherheit** - K8s-Audit/gRPC-Tests/AWS-Scanning
- **CVE-Intelligence** - NVD/Nuclei/ExploitDB Multi-Quellen-Sync
- **WAF-Bypass** - 2000+ Payload intelligente Mutations-Engine

</td>
</tr>
</table>

---

## ⚔️ ATT&CK-Abdeckungsmatrix

| Taktik | Abgedeckte Techniken | Tool-Anzahl | Status |
|--------|---------------------|-------------|--------|
| **Aufklärung** | Aktives Scanning, Passive Sammlung, OSINT | 12+ | ✅ Vollständig |
| **Ressourcenentwicklung** | Payload-Generierung, Verschleierung | 4+ | ✅ Vollständig |
| **Initialer Zugriff** | Web-Exploitation, CVE-Exploits | 19+ | ✅ Vollständig |
| **Ausführung** | Command Injection, Code-Ausführung | 5+ | ✅ Vollständig |
| **Persistenz** | Registry, Geplante Aufgaben, Webshell | 3+ | ✅ Vollständig |
| **Privilegien-Eskalation** | UAC-Bypass, Token-Impersonation | 2+ | ⚠️ Teilweise |
| **Verteidigungsumgehung** | AMSI-Bypass, ETW-Bypass, Verschleierung | 4+ | ✅ Vollständig |
| **Credential-Zugriff** | Speicherextraktion, Dateisuche | 2+ | ✅ Vollständig |
| **Erkundung** | Netzwerk-Scanning, Service-Enumeration | 8+ | ✅ Vollständig |
| **Laterale Bewegung** | SMB/SSH/WMI/WinRM | 6+ | ✅ Vollständig |
| **Sammlung** | Datenaggregation, Sensible Dateien | 2+ | ✅ Vollständig |
| **Command & Control** | HTTP/DNS/WebSocket-Tunnel | 4+ | ✅ Vollständig |
| **Exfiltration** | DNS/HTTP/ICMP-Exfil | 3+ | ✅ Vollständig |

---

## 📦 Schnellstart

### Systemanforderungen

| Komponente | Anforderung |
|------------|-------------|
| **OS** | Windows 10+, Linux (Ubuntu 20.04+), macOS 12+ |
| **Python** | 3.10 oder höher |
| **Speicher** | 4GB+ empfohlen |
| **Netzwerk** | Ausgehender HTTP/HTTPS-Zugriff |

### Installation

```bash
# Repository klonen
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# Abhängigkeiten installieren
pip install -r requirements.txt

# Installation verifizieren
python mcp_stdio_server.py --version
```

<details>
<summary><b>🔧 Optional: Minimale Installation</b></summary>

```bash
# Nur Kernabhängigkeiten (Aufklärung + Schwachstellenerkennung)
pip install -r requirements-core.txt

# Optionale Module (Red Team + Cloud-Sicherheit)
pip install -r requirements-optional.txt
```

</details>

<details>
<summary><b>🐳 Docker-Deployment</b></summary>

```bash
docker pull coff0xc/autoredteam:latest
docker run -it --rm coff0xc/autoredteam
```

</details>

### Service starten

```bash
python mcp_stdio_server.py
```

---

## 🔧 MCP-Konfiguration

Fügen Sie die folgende Konfiguration zur MCP-Konfigurationsdatei Ihres KI-Editors hinzu:

<details>
<summary><b>📘 MCP-kompatible KI-Editoren</b></summary>

**Speicherort der Konfigurationsdatei:**
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

**Konfigurationsdatei:** `~/.cursor/mcp.json`

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

**Konfigurationsdatei:** `~/.codeium/windsurf/mcp_config.json`

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

**Konfigurationsdatei:** `~/.kiro/mcp.json`

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

## 🛠️ Tool-Matrix

| Kategorie | Anzahl | Hauptfunktionen | Wichtige Tools |
|-----------|--------|-----------------|----------------|
| **🔍 Aufklärung** | 12+ | Informationssammlung & Asset-Discovery | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` |
| **🐛 Schwachstellen-Erkennung** | 19+ | OWASP Top 10 + Logik-Schwachstellen | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` |
| **🌐 Web-Scanning** | 4+ | Angriffsflächen-Discovery & Schwachstellen-Orchestrierung | `vuln_scan` `security_headers_scan` `cors_scan` `idor_scan` |
| **🔐 API-Sicherheit** | 11+ | Moderne API-Sicherheitstests | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` |
| **📦 Supply Chain** | 5+ | Abhängigkeits- & Build-Sicherheit | `sbom_generate` `dependency_audit` `cicd_scan` |
| **☁️ Cloud Native** | 8+ | Container- & Cluster-Sicherheit | `k8s_scan` `grpc_scan` `aws_scan` |
| **🔴 Red Team** | 10+ | Post-Exploitation & internes Netzwerk | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` |
| **📋 CVE** | 6+ | Schwachstellen-Intelligence & Exploitation | `cve_search` `cve_sync` `poc_execute` |
| **🤖 Automatisierung** | 5+ | Vollautomatische Penetrationstests | `auto_pentest` `smart_analyze` `attack_chain_plan` `waf_bypass` |

---

## 💬 Verwendungsbeispiele

Chatten Sie direkt in KI-Editoren, um Tools aufzurufen:

### Aufklärung & Informationssammlung
```
🔍 "Führe vollständige Aufklärung auf example.com durch und erstelle einen Bericht"
🔍 "Scanne offene Ports im Netzwerk 192.168.1.0/24"
🔍 "Enumeriere Subdomains für example.com"
🔍 "Identifiziere Tech-Stack und WAF der Zielwebsite"
```

### Schwachstellen-Scanning & Exploitation
```
🎯 "Prüfe ob Ziel für SQL-Injection anfällig ist"
🎯 "Führe vollständigen Sicherheits-Scan der Ziel-API durch"
🎯 "Suche nach Log4j-bezogenen CVEs und führe PoC aus"
🎯 "Generiere WAF-umgehende XSS-Payloads"
```

### Red Team Operationen
```
🔴 "Führe Befehl auf Zielmaschine via SMB aus"
🔴 "Starte C2 Beacon-Verbindung zum Server"
🔴 "Suche sensible Credentials auf Zielsystem"
🔴 "Generiere AMSI-Bypass-Code"
```

### Automatisierte Penetrationstests
```
⚡ "Führe vollautomatischen Penetrationstest auf https://target.com durch"
⚡ "Analysiere Ziel und generiere Angriffsketten-Empfehlungen"
⚡ "Setze zuvor unterbrochene Pentest-Sitzung fort"
```

---

## 🏗️ Architektur

```
AutoRedTeam-Orchestrator/
├── 📄 mcp_stdio_server.py      # MCP Server Entry (74 Tools registriert)
│
├── 📂 handlers/                # MCP Tool Handler (einheitliches Output-Schema)
│   ├── recon.py               # Aufklärungs-Tools
│   ├── detector.py            # Schwachstellen-Erkennung
│   └── redteam.py             # Red Team Tools
│
├── 📂 core/                    # Kern-Engines
│   ├── recon/                 # Aufklärungs-Engine (10-Phasen-Pipeline)
│   ├── detectors/             # Schwachstellen-Detektoren
│   ├── exploit/               # Exploitation-Engine
│   ├── c2/                    # C2-Kommunikations-Framework
│   ├── lateral/               # Laterale Bewegung (SMB/SSH/WMI)
│   ├── evasion/               # Umgehung & Bypass
│   ├── persistence/           # Persistenz-Module
│   ├── credential/            # Credential-Zugriff
│   └── cve/                   # CVE-Intelligence-Management
│
├── 📂 modules/                 # Feature-Module
│   ├── api_security/          # API-Sicherheitstests
│   ├── cloud_security/        # Cloud-Sicherheits-Audit
│   ├── supply_chain/          # Supply-Chain-Sicherheit
│   └── smart_payload_engine.py # Smart Payload Engine
│
├── 📂 wordlists/               # Integrierte Wörterbücher
│
└── 📂 utils/                   # Hilfsfunktionen
```

---

## 📋 Änderungsprotokoll

### v3.0.0 (2026-01-18) - Architektur-Verbesserung

- 🚀 **Tool-Erweiterung**: MCP-Tools jetzt bei 74
- 🔄 **Feedback-Schleife**: Neuer intelligenter Exploitation-Orchestrator mit Auto-Retry
- 🛡️ **WAF-Bypass**: Verbesserte Payload-Mutations-Engine mit 30+ Kodierungsmethoden
- 📊 **Bericht-Optimierung**: Executive Summary & Risikobewertung hinzugefügt

### v2.8.0 (2026-01-15) - Sicherheits-Härtung

- 🔒 **Input-Validierung**: Verbesserte Sicherheitsprüfungen für alle Benutzereingaben
- ⚙️ **Ausnahmebehandlung**: Einheitliches Ausnahmesystem für verbesserte Stabilität
- 🚄 **Performance**: Verbesserte Parallelitätskontrolle & Ressourcenverwaltung

---

## 🛤️ Roadmap

- [ ] 🖥️ Web UI Management-Oberfläche
- [ ] 🌐 Verteilter Scan-Cluster
- [ ] ☁️ Weitere Cloud-Plattformen (GCP/Alibaba Cloud/Tencent Cloud)
- [ ] 🤖 Verbesserte KI-automatisierte Exploitation
- [ ] 📚 Weitere CVE PoC-Vorlagen
- [ ] 🔌 Burp Suite Plugin-Integration
- [x] ✅ Vollständiges Red Team Toolkit
- [x] ✅ CVE-Intelligence & KI-PoC-Generierung
- [x] ✅ API/Supply Chain/Cloud-Sicherheitsmodule
- [x] ✅ Vollautomatisiertes Penetrationstest-Framework

---

## 🤝 Beitragsrichtlinien

Wir begrüßen alle Formen von Beiträgen!

1. **Fork** dieses Repository
2. Erstellen Sie einen Feature-Branch (`git checkout -b feature/AmazingFeature`)
3. Committen Sie Ihre Änderungen (`git commit -m 'Add AmazingFeature'`)
4. Pushen Sie zum Branch (`git push origin feature/AmazingFeature`)
5. Erstellen Sie einen **Pull Request**

Details siehe [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 🔒 Sicherheitsrichtlinie

- 🚨 **Verantwortungsvolle Offenlegung**: Melden Sie Sicherheitslücken an [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com)
- ⚠️ **Nur autorisierte Nutzung**: Dieses Tool ist nur für autorisierte Sicherheitstests und Forschung
- 📜 **Compliance**: Stellen Sie die Einhaltung lokaler Gesetze vor der Nutzung sicher

Details siehe [SECURITY.md](SECURITY.md)

---

## 🙏 Danksagungen

Dank an diese Open-Source-Projekte für die Inspiration:

- [Nuclei](https://github.com/projectdiscovery/nuclei) - Schwachstellen-Scanner-Engine-Design
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - SQL-Injection-Erkennungsansatz
- [Impacket](https://github.com/fortra/impacket) - Netzwerkprotokoll-Implementierung
- [MCP Protocol](https://modelcontextprotocol.io/) - KI-Tool-Protokollstandard

---

## 📜 Lizenz

Dieses Projekt ist unter der **MIT-Lizenz** lizenziert - siehe [LICENSE](LICENSE) Datei für Details

---

## ⚖️ Haftungsausschluss

> **WARNUNG**: Dieses Tool ist **nur für autorisierte Sicherheitstests und Forschung**.
>
> Bevor Sie dieses Tool zum Testen eines Systems verwenden, stellen Sie sicher:
> - Sie haben **schriftliche Genehmigung** vom Systembesitzer
> - Sie halten **lokale Gesetze und Vorschriften** ein
> - Sie befolgen **berufsethische** Standards
>
> Unbefugte Nutzung kann gegen das Gesetz verstoßen. **Die Entwickler sind nicht verantwortlich für Missbrauch**.

---

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Coff0xc">Coff0xc</a></b>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Community_beitreten-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="mailto:Coff0xc@protonmail.com"><img src="https://img.shields.io/badge/Email-Kontakt-EA4335?style=for-the-badge&logo=gmail&logoColor=white" alt="Email"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues"><img src="https://img.shields.io/badge/Issues-Melden-181717?style=for-the-badge&logo=github&logoColor=white" alt="Issues"></a>
</p>
