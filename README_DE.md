<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>KI-gesteuertes automatisiertes Red Team Orchestrierung Framework</b><br>
  <sub>Plattformuebergreifend | 100+ MCP Tools | 2000+ Payloads | Vollstaendige ATT&CK Abdeckung</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md">Русский</a> ·
  <a href="README_DE.md"><b>Deutsch</b></a> ·
  <a href="README_FR.md">Francais</a>
</p>

<p align="center">
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/stargazers"><img src="https://img.shields.io/github/stars/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=gold" alt="Stars"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/network/members"><img src="https://img.shields.io/github/forks/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=silver" alt="Forks"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues"><img src="https://img.shields.io/github/issues/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=red" alt="Issues"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/commits/main"><img src="https://img.shields.io/github/last-commit/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github" alt="Letzter Commit"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.0.1-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/MCP-Native-00ADD8?style=flat-square" alt="MCP">
  <img src="https://img.shields.io/badge/Tools-100+-FF6B6B?style=flat-square" alt="Tools">
  <img src="https://img.shields.io/badge/Lizenz-MIT-green?style=flat-square" alt="Lizenz">
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Community-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-Dokumentation-blue?style=flat-square&logo=gitbook&logoColor=white" alt="Wiki"></a>
</p>

---

## Inhaltsverzeichnis

- [Projektuebersicht](#projektuebersicht)
- [Kernfunktionen](#kernfunktionen)
- [ATT&CK Abdeckungsmatrix](#attck-abdeckungsmatrix)
- [Schnellstart](#schnellstart)
  - [Systemanforderungen](#systemanforderungen)
  - [Installationsmethoden](#installationsmethoden)
  - [Installation ueberpruefen](#installation-ueberpruefen)
- [MCP Konfiguration](#mcp-konfiguration)
- [Tool-Matrix](#tool-matrix-100-mcp-tools)
- [Externe Tool-Integration](#externe-tool-integration)
- [Anwendungsbeispiele](#anwendungsbeispiele)
  - [Befehlszeilen-Nutzung](#befehlszeilen-nutzung)
  - [Python API Aufrufe](#python-api-aufrufe)
- [Architektur](#architektur)
- [Konfiguration](#konfiguration)
- [Leistungsoptimierung](#leistungsoptimierung)
- [Fehlerbehebung](#fehlerbehebung)
- [FAQ](#faq)
- [Aenderungsprotokoll](#aenderungsprotokoll)
- [Roadmap](#roadmap)
- [Beitragsrichtlinien](#beitragsrichtlinien)
- [Sicherheitsrichtlinie](#sicherheitsrichtlinie)
- [Danksagungen](#danksagungen)
- [Lizenz](#lizenz)
- [Haftungsausschluss](#haftungsausschluss)

---

## Projektuebersicht

**AutoRedTeam-Orchestrator** ist ein KI-gesteuertes automatisiertes Penetrationstest-Framework basierend auf dem [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). Es kapselt 100+ Sicherheitstools als MCP-Tools und ermoeglicht nahtlose Integration mit MCP-kompatiblen KI-Editoren (Cursor, Windsurf, Kiro, Claude Desktop) fuer natuerlichsprachliche automatisierte Sicherheitstests.

### Warum AutoRedTeam-Orchestrator?

| Merkmal | Traditionelle Tools | AutoRedTeam |
|---------|---------------------|-------------|
| **Interaktion** | Befehlszeilen-Memorierung | Natuerlichsprachlicher Dialog |
| **Lernkurve** | Hoch (viele Parameter) | Niedrig (KI waehlt Tools) |
| **Tool-Integration** | Manuelles Wechseln | 100+ Tools vereinheitlicht |
| **Angriffsketten-Planung** | Manuelle Planung | KI-Empfehlungen |
| **Berichtserstellung** | Manuelles Schreiben | Ein-Klick professionelle Berichte |
| **Sitzungsverwaltung** | Keine | Checkpoint/Resume Unterstuetzung |

---

## Kernfunktionen

<table>
<tr>
<td width="50%">

**KI-natives Design**
- **Intelligente Fingerabdruckerkennung** - Automatische Erkennung des Ziel-Technologie-Stacks (CMS/Frameworks/WAF)
- **Angriffsketten-Planung** - KI-gesteuerte Angriffspfad-Empfehlungen
- **Historisches Feedback-Lernen** - Kontinuierliche Strategieoptimierung basierend auf Ergebnissen
- **Automatische Payload-Auswahl** - WAF-bewusste intelligente Payload-Mutation
- **KI PoC-Generierung** - Automatische Exploit-Code-Generierung basierend auf CVE-Beschreibungen

</td>
<td width="50%">

**Vollstaendige Prozessautomatisierung**
- **10-Phasen Aufklaerungsablauf** - DNS/Port/Fingerabdruck/WAF/Subdomain/Verzeichnis/JS-Analyse
- **Schwachstellenerkennung & Verifizierung** - Automatisiertes Scannen + OOB-Verifizierung zur Reduzierung von False Positives
- **Intelligente Exploit-Orchestrierung** - Feedback-Loop-Engine + automatische Fehlerwiederholung
- **Ein-Klick professionelle Berichte** - JSON/HTML/Markdown Multi-Format-Ausgabe
- **Sitzungs-Checkpoint/Resume** - Unterstuetzt Unterbrechungs-Wiederherstellung ohne Scan-Fortschrittsverlust

</td>
</tr>
<tr>
<td width="50%">

**Red Team Toolchain**
- **Laterale Bewegung** - SMB/SSH/WMI/WinRM/PSExec 5 Protokolle
- **C2 Kommunikation** - Beacon + DNS/HTTP/WebSocket/ICMP Tunnel
- **Verschleierung/Evasion** - XOR/AES/Base64/Benutzerdefinierte Encoder
- **Persistenz** - Windows Registry/Geplante Tasks/WMI/Linux cron/Webshell
- **Credential-Zugriff** - Speicherextraktion/Dateisuche/Passwort-Spraying
- **AD Angriffe** - Kerberoasting/AS-REP Roasting/SPN Scanning

</td>
<td width="50%">

**Sicherheitsfaehigkeits-Erweiterung**
- **API-Sicherheit** - JWT/CORS/GraphQL/WebSocket/OAuth Tests
- **Supply Chain Sicherheit** - SBOM-Generierung/Abhaengigkeits-Audit/CI-CD Sicherheits-Scan
- **Cloud-Native Sicherheit** - K8s RBAC/Pod-Sicherheit/gRPC/AWS Konfigurations-Audit
- **CVE Intelligence** - NVD/Nuclei/ExploitDB Multi-Source-Sync
- **WAF Bypass** - 2000+ Payloads + 30+ Encoding-Methoden intelligente Mutation

</td>
</tr>
</table>

---

## ATT&CK Abdeckungsmatrix

| Taktische Phase | Technik-Abdeckung | Tool-Anzahl | Status |
|-----------------|-------------------|-------------|--------|
| Aufklaerung (Reconnaissance) | Aktives Scannen, Passive Sammlung, OSINT, JS-Analyse | 12+ | ✅ |
| Ressourcenentwicklung (Resource Development) | Payload-Generierung, Verschleierungs-Encoding, PoC-Generierung | 4+ | ✅ |
| Erstzugang (Initial Access) | Web-Schwachstellen-Exploitation, CVE-Exploitation, API-Schwachstellen | 19+ | ✅ |
| Ausfuehrung (Execution) | Befehlsinjektion, Code-Ausfuehrung, Deserialisierung | 5+ | ✅ |
| Persistenz (Persistence) | Registry, Geplante Tasks, Webshell, WMI | 3+ | ✅ |
| Privilegieneskalation (Privilege Escalation) | UAC Bypass, Token-Impersonation, Kernel-Exploits | 2+ | ⚠️ |
| Verteidigungsumgehung (Defense Evasion) | AMSI Bypass, ETW Bypass, Verschleierung, Traffic-Mutation | 4+ | ✅ |
| Credential-Zugriff (Credential Access) | Speicherextraktion, Dateisuche, Passwort-Spraying | 2+ | ✅ |
| Entdeckung (Discovery) | Netzwerk-Scan, Service-Enumeration, AD-Enumeration | 8+ | ✅ |
| Laterale Bewegung (Lateral Movement) | SMB/SSH/WMI/WinRM/PSExec | 9+ | ✅ |
| Sammlung (Collection) | Datenaggregation, Sensible Dateisuche | 2+ | ✅ |
| Befehl & Kontrolle (C2) | HTTP/DNS/WebSocket/ICMP Tunnel | 4+ | ✅ |
| Datenexfiltration (Exfiltration) | DNS/HTTP/ICMP/SMB + AES-Verschluesselung | 4+ | ✅ |

---

## Schnellstart

### Systemanforderungen

| Komponente | Mindestanforderung | Empfohlen |
|------------|-------------------|-----------|
| Betriebssystem | Windows 10, Ubuntu 20.04, macOS 12 | Windows 11, Ubuntu 22.04, macOS 14 |
| Python | 3.10 | 3.11 oder 3.12 |
| Speicher | 4GB | 8GB+ |
| Festplattenspeicher | 500MB | 2GB+ (inkl. CVE-Datenbank) |
| Netzwerk | Internetzugang | Niedrige Latenz |

### Installationsmethoden

#### Methode 1: Standard-Installation (Empfohlen)

```bash
# 1. Repository klonen
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. Virtuelle Umgebung erstellen (empfohlen)
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 3. Abhaengigkeiten installieren
pip install -r requirements.txt

# 4. Umgebungsvariablen-Vorlage kopieren
cp .env.example .env
# .env bearbeiten und API-Schluessel eintragen

# 5. Service starten
python mcp_stdio_server.py
```

#### Methode 2: Minimal-Installation (nur Kernfunktionen)

```bash
# Nur Kernabhaengigkeiten installieren (Aufklaerung + Schwachstellen-Erkennung)
pip install -r requirements-core.txt
```

#### Methode 3: Docker Deployment

```bash
docker pull coff0xc/autoredteam:latest
docker run -it --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  coff0xc/autoredteam
```

#### Methode 4: Entwicklungsumgebung

```bash
# Entwicklungsabhaengigkeiten installieren (Tests, Formatierung, Lint)
pip install -r requirements-dev.txt

# Pre-commit Hooks installieren
pre-commit install
```

### Installation ueberpruefen

```bash
# Version pruefen
python mcp_stdio_server.py --version
# Ausgabe: AutoRedTeam-Orchestrator v3.0.1

# Selbsttest ausfuehren
python -c "from core import __version__; print(f'Core version: {__version__}')"

# Tests ausfuehren (Entwicklungsumgebung)
pytest tests/ -v --tb=short
```

---

## MCP Konfiguration

Fuegen Sie die folgende Konfiguration zur MCP-Konfigurationsdatei Ihres KI-Editors hinzu:

### Konfigurationsdatei-Pfade

| Editor | Konfigurationsdatei-Pfad |
|--------|-------------------------|
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Kiro | `~/.kiro/mcp.json` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| VS Code (MCP Erweiterung) | `.vscode/mcp.json` |

### Konfigurationsbeispiele

<details>
<summary><b>Cursor</b> - <code>~/.cursor/mcp.json</code></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/absoluter/pfad/zu/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
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
      "args": ["/absoluter/pfad/zu/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONPATH": "/absoluter/pfad/zu/AutoRedTeam-Orchestrator"
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
      "args": ["/absoluter/pfad/zu/AutoRedTeam-Orchestrator/mcp_stdio_server.py"]
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
      "args": ["/absoluter/pfad/zu/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Windows Pfadbeispiel</b></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["C:\\Users\\IhrName\\AutoRedTeam-Orchestrator\\mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

---

## Tool-Matrix (100+ MCP Tools)

| Kategorie | Anzahl | Schluessel-Tools | Beschreibung |
|-----------|--------|-----------------|--------------|
| **Aufklaerung** | 8 | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` `dir_scan` `dns_lookup` `tech_detect` | Informationssammlung & Asset-Erkennung |
| **Schwachstellen-Erkennung** | 11 | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` `idor_scan` `path_traversal_scan` `cors_scan` `security_headers_scan` | OWASP Top 10 + Logik-Schwachstellen |
| **API-Sicherheit** | 7 | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` `cors_deep_scan` `security_headers_score` | Moderne API-Sicherheitstests |
| **Supply Chain** | 3 | `sbom_generate` `dependency_audit` `cicd_scan` | SBOM/Abhaengigkeiten/CI-CD Sicherheit |
| **Cloud-Native** | 3 | `k8s_scan` `grpc_scan` `aws_scan` | K8s/gRPC/AWS Sicherheits-Audit |
| **Red Team Kern** | 14 | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` `payload_obfuscate` | Post-Exploitation & Internes Netzwerk |
| **Laterale Bewegung** | 9 | `lateral_ssh` `lateral_wmi` `lateral_winrm` `lateral_psexec` `lateral_ssh_tunnel` | 5 Protokolle Laterale Bewegung |
| **Persistenz** | 3 | `persistence_windows` `persistence_linux` `persistence_webshell` | Windows/Linux/Web |
| **AD Angriffe** | 3 | `ad_enumerate` `ad_kerberos_attack` `ad_spn_scan` | Vollstaendige Domain-Penetration |
| **CVE** | 8 | `cve_search` `cve_sync` `cve_stats` `poc_execute` `poc_list` `cve_auto_exploit` `cve_exploit_with_desc` `cve_generate_poc` | CVE Intelligence + KI PoC |
| **Orchestrierung** | 11 | `auto_pentest` `pentest_resume` `pentest_status` `pentest_phase` `smart_analyze` `attack_chain_plan` | Automatisierte Penetration |
| **Externe Tools** | 8 | `ext_nmap_scan` `ext_nuclei_scan` `ext_sqlmap_scan` `ext_ffuf_fuzz` `ext_masscan_scan` `ext_tool_chain` `ext_tools_status` | Professionelle Tool-Integration |
| **KI-Assistenz** | 3 | `smart_payload` `ai_attack_chain` `smart_pentest` | Intelligente Analyse & Entscheidung |
| **Sitzung/Bericht** | 9 | `session_create` `session_status` `session_list` `session_complete` `generate_report` `export_findings` | Sitzungsverwaltung + Berichte |

---

## Externe Tool-Integration

Unterstuetzt die Integration lokal installierter professioneller Sicherheitstools fuer erweiterte Erkennungsfaehigkeiten:

| Tool | Verwendung | MCP Befehl | Installationsanforderung |
|------|-----------|------------|--------------------------|
| **Nmap** | Port-Scan + Service-Erkennung + NSE-Skripte | `ext_nmap_scan` | System PATH oder konfigurierter Pfad |
| **Nuclei** | 7000+ CVE/Schwachstellen-Vorlagen-Scan | `ext_nuclei_scan` | Go kompiliert oder Binaer-Download |
| **SQLMap** | 6 SQL-Injection-Techniken + WAF Bypass | `ext_sqlmap_scan` | Python-Skript |
| **ffuf** | Hochgeschwindigkeits-Verzeichnis/Parameter-Fuzzing | `ext_ffuf_fuzz` | Go kompiliert oder Binaer-Download |
| **Masscan** | Ultra-Hochgeschwindigkeits-Massen-Port-Scan | `ext_masscan_scan` | Erfordert root/Administrator-Rechte |

### Externe Tools konfigurieren

Bearbeiten Sie `config/external_tools.yaml`:

```yaml
# Tool-Basisverzeichnis
base_path: "/pfad/zu/ihren/security-tools"

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

# Tool-Chain Konfiguration
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

### Tool-Chain Orchestrierung

```bash
# Vollstaendige Aufklaerungskette: masscan schnelle Erkennung -> nmap detaillierte Identifikation
ext_tool_chain target="192.168.1.0/24" chain_name="full_recon"

# Schwachstellen-Scan-Kette: nuclei + sqlmap kombinierte Erkennung
ext_tool_chain target="https://example.com" chain_name="vuln_scan"

# Externe Tool-Status pruefen
ext_tools_status
```

---

## Anwendungsbeispiele

### Befehlszeilen-Nutzung

Direkte Konversationsaufrufe im KI-Editor:

#### Aufklaerung & Informationssammlung

```
# Vollstaendige Aufklaerung
"Fuehre eine vollstaendige Aufklaerung auf example.com durch und generiere einen Bericht"

# Port-Scan
"Scanne das 192.168.1.0/24 Netzwerksegment nach offenen Ports"

# Subdomain-Enumeration
"Enumeriere alle Subdomains von example.com"

# Fingerabdruckerkennung
"Identifiziere den Technologie-Stack und WAF der Zielwebsite"

# JS-Analyse
"Analysiere JavaScript-Dateien der Zielwebsite auf sensible Informationen"
```

#### Schwachstellen-Scan

```
# SQL-Injection
"Erkenne ob https://target.com/api?id=1 eine SQL-Injection-Schwachstelle hat"

# XSS-Scan
"Scanne das Zielformular auf XSS-Schwachstellen und generiere PoC"

# API-Sicherheit
"Fuehre vollstaendige JWT/CORS/GraphQL-Sicherheitstests auf der Ziel-API durch"

# CVE-Suche und Exploitation
"Suche Apache Log4j bezogene CVEs und fuehre PoC aus"
```

#### Red Team Operationen

```
# Laterale Bewegung
"Fuehre whoami-Befehl auf 192.168.1.100 ueber SMB aus"

# C2 Kommunikation
"Starte DNS-Tunnel-Verbindung zu c2.example.com"

# Persistenz
"Etabliere geplante Task-Persistenz auf Windows-Ziel"

# AD Angriffe
"Fuehre Kerberoasting-Angriff auf Domain Controller durch"
```

#### Automatisierte Penetration

```
# Vollautomatisierter Penetrationstest
"Fuehre vollautomatisierten Penetrationstest auf https://target.com durch, generiere detaillierten Bericht"

# Intelligente Angriffskette
"Analysiere Ziel und generiere optimale Angriffsketten-Empfehlung"

# Checkpoint/Resume
"Setze zuvor unterbrochene Penetrationstest-Sitzung fort"
```

### Python API Aufrufe

#### Grundlegende Verwendung

```python
import asyncio
from core.recon import StandardReconEngine, ReconConfig
from core.detectors import DetectorFactory

async def main():
    # 1. Aufklaeruns-Engine
    config = ReconConfig(
        quick_mode=False,
        enable_js_analysis=True,
        max_threads=50
    )
    engine = StandardReconEngine("https://target.com", config)
    recon_result = await engine.run()
    print(f"Gefunden {len(recon_result.open_ports)} offene Ports")

    # 2. Schwachstellen-Erkennung
    detector = DetectorFactory.create_composite(['sqli', 'xss', 'ssrf'])
    vuln_results = await detector.async_detect(
        url="https://target.com/api",
        params={'id': '1'}
    )

    for vuln in vuln_results:
        print(f"Schwachstelle gefunden: {vuln.type} - {vuln.severity}")

asyncio.run(main())
```

#### Laterale Bewegung

```python
from core.lateral import SMBLateralMove, SSHLateralMove

# SMB Lateral
smb = SMBLateralMove(
    target="192.168.1.100",
    credential={"username": "admin", "password_hash": "aad3b435..."}
)
result = await smb.execute_command("whoami")

# SSH Tunnel
ssh = SSHLateralMove(
    target="192.168.1.100",
    credential={"username": "root", "private_key_path": "/pfad/zum/key"}
)
await ssh.create_tunnel(local_port=8080, remote_port=80)
```

#### CVE Automatische Exploitation

```python
from core.cve import CVEAutoExploit

exploit = CVEAutoExploit()

# Suchen und Exploiten
results = await exploit.search_and_exploit(
    cve_id="CVE-2021-44228",
    target="https://target.com"
)

# KI PoC generieren
poc_code = await exploit.generate_poc(
    cve_id="CVE-2024-12345",
    target_info={"os": "linux", "service": "nginx"}
)
```

#### Sitzungsverwaltung

```python
from core.session import SessionManager

manager = SessionManager()

# Sitzung erstellen
session_id = await manager.create_session(
    target="https://target.com",
    scan_type="full_pentest"
)

# Sitzung fortsetzen
await manager.resume_session(session_id)

# Ergebnisse exportieren
await manager.export_findings(session_id, format="html")
```

---

## Architektur

```
AutoRedTeam-Orchestrator/
├── mcp_stdio_server.py       # MCP Server Einstiegspunkt (100+ Tools registriert)
│
├── handlers/                 # MCP Tool Handler (16 Module)
│   ├── recon_handlers.py           # Aufklaerung-Tools (8)
│   ├── detector_handlers.py        # Schwachstellen-Erkennungs-Tools (11)
│   ├── api_security_handlers.py    # API-Sicherheits-Tools (7)
│   ├── supply_chain_handlers.py    # Supply Chain Sicherheits-Tools (3)
│   ├── cloud_security_handlers.py  # Cloud-Sicherheits-Tools (3)
│   ├── cve_handlers.py             # CVE-Tools (8)
│   ├── redteam_handlers.py         # Red Team Kern-Tools (14)
│   ├── lateral_handlers.py         # Laterale Bewegungs-Tools (9)
│   ├── persistence_handlers.py     # Persistenz-Tools (3)
│   ├── ad_handlers.py              # AD-Angriffs-Tools (3)
│   ├── orchestration_handlers.py   # Orchestrierungs-Tools (11)
│   ├── external_tools_handlers.py  # Externe Tools (8)
│   ├── ai_handlers.py              # KI-Assistenz-Tools (3)
│   ├── session_handlers.py         # Sitzungs-Tools (4)
│   ├── report_handlers.py          # Berichts-Tools (2)
│   └── misc_handlers.py            # Verschiedene Tools (3)
│
├── core/                     # Kern-Engines
│   ├── recon/               # Aufklaerung-Engine (10-Phasen Pipeline)
│   ├── detectors/           # Schwachstellen-Detektoren
│   ├── cve/                 # CVE Intelligence
│   ├── c2/                  # C2 Kommunikations-Framework
│   ├── lateral/             # Laterale Bewegung
│   ├── evasion/             # Evasion & Verschleierung
│   ├── persistence/         # Persistenz
│   ├── credential/          # Credential-Zugriff
│   ├── ad/                  # AD-Angriffe
│   ├── session/             # Sitzungsverwaltung
│   ├── tools/               # Externe Tool-Verwaltung
│   └── security/            # Sicherheitskomponenten
│
├── modules/                  # Funktionsmodule
│   ├── api_security/        # API-Sicherheit
│   ├── supply_chain/        # Supply Chain Sicherheit
│   ├── cloud_security/      # Cloud-Sicherheit
│   └── payload/             # Payload-Engine
│
├── utils/                    # Hilfsfunktionen
├── wordlists/                # Eingebaute Woerterbucher
├── config/                   # Konfigurationsdateien
└── tests/                    # Test-Suite (1075 Testfaelle)
```

---

## Konfiguration

### Umgebungsvariablen (.env)

```bash
# ========== Sicherheitskonfiguration ==========
REDTEAM_MASTER_KEY=
AUTOREDTEAM_API_KEY=
AUTOREDTEAM_AUTH_MODE=permissive

# ========== API-Schluessel ==========
OPENAI_API_KEY=ihr_key
ANTHROPIC_API_KEY=ihr_key
SHODAN_API_KEY=ihr_key
CENSYS_API_ID=ihre_id
CENSYS_API_SECRET=ihr_secret
NVD_API_KEY=ihr_key
GITHUB_TOKEN=ihr_token

# ========== Proxy-Einstellungen ==========
HTTP_PROXY=
HTTPS_PROXY=
SOCKS_PROXY=

# ========== Globale Konfiguration ==========
VERIFY_SSL=false
RATE_LIMIT_DELAY=0.3
MAX_THREADS=50
REQUEST_TIMEOUT=10

# ========== Protokollierung ==========
LOG_LEVEL=INFO
LOG_FILE=logs/redteam.log
```

---

## Leistungsoptimierung

### Parallelitaetskonfiguration

```yaml
# config/performance.yaml
concurrency:
  max_threads: 100          # Maximale Thread-Anzahl
  max_async_tasks: 200      # Maximale asynchrone Tasks
  connection_pool_size: 50  # Verbindungspool-Groesse

rate_limiting:
  requests_per_second: 50   # Anfragen pro Sekunde
  burst_size: 100           # Burst-Anfragen

timeouts:
  connect: 5                # Verbindungs-Timeout (Sekunden)
  read: 30                  # Lese-Timeout
  total: 120                # Gesamt-Timeout
```

### Speicheroptimierung

```python
# Stream-Verarbeitung fuer Gross-Scans verwenden
engine = StandardReconEngine(
    target="192.168.0.0/16",
    config=ReconConfig(
        streaming_mode=True,    # Stream-Verarbeitung aktivieren
        batch_size=1000,        # Batch-Groesse
        memory_limit="2GB"      # Speicherlimit
    )
)
```

---

## Fehlerbehebung

### Haeufige Probleme

| Problem | Ursache | Loesung |
|---------|--------|--------|
| MCP Server kann nicht verbinden | Pfadfehler oder Python-Umgebungsproblem | Absoluten Pfad in Konfiguration pruefen, korrekten Python-Interpreter sicherstellen |
| Import-Fehler | PYTHONPATH nicht gesetzt | `PYTHONPATH` Umgebungsvariable in Konfiguration hinzufuegen |
| Externe Tool-Aufruf fehlgeschlagen | Tool nicht installiert oder Pfadfehler | `ext_tools_status` ausfuehren um Tool-Status zu pruefen |
| CVE-Datenbank-Sync fehlgeschlagen | Netzwerkproblem oder API-Rate-Limiting | Netzwerk pruefen, NVD_API_KEY konfigurieren fuer hoehere Limits |
| Langsame Scan-Geschwindigkeit | Parallelitaetskonfiguration zu niedrig | `MAX_THREADS` und `RATE_LIMIT_DELAY` anpassen |
| Speicherueberlauf | Gross-Scan | `streaming_mode` aktivieren, `memory_limit` setzen |

### Debug-Modus

```bash
# Detaillierte Protokollierung aktivieren
LOG_LEVEL=DEBUG python mcp_stdio_server.py

# Syntaxfehler pruefen
python -m py_compile mcp_stdio_server.py

# Einzelnen Test ausfuehren
pytest tests/test_recon.py::test_port_scan -v
```

---

## FAQ

<details>
<summary><b>F: Wie verwende ich es in einer Offline-Umgebung?</b></summary>

A:
1. CVE-Datenbank vorab herunterladen: `python core/cve/update_manager.py sync --offline-export`
2. Lokale Woerterbuchdateien verwenden
3. Netzwerkabhaengige Funktionen deaktivieren: `OFFLINE_MODE=true`

</details>

<details>
<summary><b>F: Wie fuege ich einen benutzerdefinierten Detektor hinzu?</b></summary>

A:
1. Neue Datei in `core/detectors/` erstellen
2. Von `BaseDetector` Klasse erben
3. `detect()` und `async_detect()` Methoden implementieren
4. MCP-Tool in `handlers/detector_handlers.py` registrieren

</details>

<details>
<summary><b>F: Wie integriere ich andere externe Tools?</b></summary>

A:
1. Tool-Konfiguration in `config/external_tools.yaml` hinzufuegen
2. MCP-Tool-Funktion in `handlers/external_tools_handlers.py` hinzufuegen
3. `execute_tool()` Methode von `core/tools/tool_manager.py` verwenden

</details>

<details>
<summary><b>F: Wie gehe ich mit WAF-Blockierung um?</b></summary>

A:
1. `smart_payload` Tool fuer automatische WAF-Bypass Payload-Auswahl verwenden
2. Proxy-Pool konfigurieren: `PROXY_POOL=true`
3. Traffic-Mutation aktivieren: `traffic_mutation=true`
4. Scan-Geschwindigkeit reduzieren: `RATE_LIMIT_DELAY=1.0`

</details>

<details>
<summary><b>F: Welche Berichtsformate werden unterstuetzt?</b></summary>

A:
- JSON (maschinenlesbar)
- HTML (visualisierter Bericht mit Diagrammen)
- Markdown (geeignet fuer Git/Wiki)
- PDF (erfordert `reportlab` Installation)
- DOCX (erfordert `python-docx` Installation)

</details>

---

## Aenderungsprotokoll

### v3.0.1 (2026-01-30) - Qualitaetshaertung

**Neu**
- CVE automatische Exploitation-Verbesserung (`cve_auto_exploit`, `cve_exploit_with_desc`, `cve_generate_poc`)
- KI PoC Generator (`core/cve/ai_poc_generator.py`)

**Behoben**
- Versionsnummer-Vereinheitlichung - Vollstaendige Synchronisation VERSION/pyproject.toml/Quellcode
- ToolCounter Korrektur - Neue external_tools/lateral/persistence/ad Kategorien hinzugefuegt
- Test-Korrekturen - Veraltete Testreferenzen aktualisiert
- Thread-Sicherheit - beacon.py Zustandsverwaltung threading.Lock hinzugefuegt

**Verbessert**
- CI/CD-Haertung - Lint-Pruefungsfehler blockieren jetzt Build
- Testabdeckungs-Schwellenwert auf 50% erhoeht
- Abhaengigkeitsversions-Constraints - Obere Grenzen zur Vermeidung von Kompatibilitaetsproblemen hinzugefuegt

### v3.0.0 (2026-01-18) - Architektur-Erweiterung

**Neu**
- Externe Tool-Integration - 8 externe Tool MCP-Befehle
- Tool-Chain Orchestrierung - YAML-gesteuerte Multi-Tool-Kombination
- Handler-Modularisierung - 16 unabhaengige Handler-Module

**Verbessert**
- MCP-Tool-Anzahl erreicht 100+
- Feedback-Loop-Engine - Intelligenter Exploitation-Orchestrator
- WAF-Bypass - Erweiterte Payload-Mutations-Engine

---

## Roadmap

### In Arbeit
- [ ] Web UI Verwaltungsoberflaeche
- [ ] Verteilter Scan-Cluster

### Geplant
- [ ] Mehr Cloud-Plattform-Unterstuetzung (GCP/Alibaba Cloud/Tencent Cloud)
- [ ] Burp Suite Plugin-Integration
- [ ] Mobile App Sicherheitstests
- [ ] KI-autonomer Angriffs-Agent

### Abgeschlossen
- [x] Red Team vollstaendige Toolchain
- [x] CVE Intelligence & KI PoC Generierung
- [x] API/Supply Chain/Cloud-Sicherheitsmodule
- [x] Vollautomatisiertes Penetrationstest-Framework
- [x] Externe Tool-Integration

---

## Beitragsrichtlinien

Wir begruessen Beitraege jeder Art!

### Schnellstart

```bash
# 1. Fork und Klonen
git clone https://github.com/IHR_USERNAME/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. Branch erstellen
git checkout -b feature/ihre-funktion

# 3. Entwicklungsabhaengigkeiten installieren
pip install -r requirements-dev.txt
pre-commit install

# 4. Entwickeln und Testen
pytest tests/ -v

# 5. PR einreichen
git push origin feature/ihre-funktion
```

### Commit-Konvention

Verwenden Sie [Conventional Commits](https://www.conventionalcommits.org/) Format:

- `feat:` Neue Funktion
- `fix:` Bug-Korrektur
- `docs:` Dokumentations-Aktualisierung
- `refactor:` Refactoring
- `test:` Test-bezogen
- `chore:` Build/Tools

Siehe [CONTRIBUTING.md](CONTRIBUTING.md)

---

## Sicherheitsrichtlinie

- **Verantwortungsvolle Offenlegung**: Bei Sicherheitsluecken kontaktieren Sie uns unter [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com)
- **Autorisierte Verwendung**: Dieses Tool ist nur fuer autorisierte Sicherheitstests und Forschung
- **Compliance-Erklaerung**: Stellen Sie sicher, dass Sie lokale Gesetze und Vorschriften einhalten

Siehe [SECURITY.md](SECURITY.md)

---

## Danksagungen

- [Nuclei](https://github.com/projectdiscovery/nuclei) - Schwachstellen-Scan-Engine Design
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - SQL-Injection-Erkennungsansatz
- [Impacket](https://github.com/fortra/impacket) - Netzwerkprotokoll-Implementierung
- [MCP Protocol](https://modelcontextprotocol.io/) - KI-Tool-Protokollstandard

---

## Lizenz

Dieses Projekt ist lizenziert unter der **MIT-Lizenz** - siehe [LICENSE](LICENSE) Datei

---

## Haftungsausschluss

> **Warnung**: Dieses Tool ist nur fuer **autorisierte Sicherheitstests und Forschung**.
>
> Bevor Sie dieses Tool verwenden, um ein System zu testen, stellen Sie sicher, dass:
> - Sie die **schriftliche Genehmigung** des Systemeigners haben
> - Sie lokale **Gesetze und Vorschriften** einhalten
> - Sie **berufsethische** Standards erfuellen
>
> Nicht autorisierte Verwendung dieses Tools kann gegen Gesetze verstossen. **Die Entwickler sind nicht verantwortlich fuer Missbrauch**.

---

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Coff0xc">Coff0xc</a></b>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB">Discord</a> ·
  <a href="mailto:Coff0xc@protonmail.com">Email</a> ·
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues">Issues</a>
</p>
