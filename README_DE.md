<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>KI-gesteuertes automatisiertes Red Team Orchestrierung Framework</b><br>
  <sub>Plattformübergreifend | 101 MCP Tools | 2000+ Payloads | Vollständige ATT&CK Abdeckung | Knowledge Graph</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md">Русский</a> ·
  <a href="README_DE.md"><b>Deutsch</b></a> ·
  <a href="README_FR.md">Français</a>
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
  <img src="https://img.shields.io/badge/Tools-101-FF6B6B?style=flat-square" alt="Tools">
  <img src="https://img.shields.io/badge/Tests-1461-4CAF50?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/Lizenz-MIT-green?style=flat-square" alt="Lizenz">
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Community-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-Dokumentation-blue?style=flat-square&logo=gitbook&logoColor=white" alt="Wiki"></a>
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
│  ● 101 MCP Tools       ● 2000+ Payloads     ● 1461 Testfälle              │
│  ● 10-Phasen Recon     ● 19 Vuln-Detektoren ● 5-Protokoll Lateral         │
│  ● MCTS Angriffsplaner ● Knowledge Graph    ● KI PoC-Generierung          │
│  ● OOB False Positive  ● DI Container       ● MCP Security Middleware     │
├─────────────────────────────────────────────────────────────────────────────┤
│  Unterstützte KI-Editoren: Cursor | Windsurf | Kiro | Claude Desktop | VS Code │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Inhaltsverzeichnis

- [Projektübersicht](#projektübersicht)
- [Kernfunktionen](#kernfunktionen)
- [Design-Philosophie](#design-philosophie)
- [Architektur](#architektur)
- [ATT&CK Abdeckungsmatrix](#attck-abdeckungsmatrix)
- [Schnellstart](#schnellstart)
  - [Systemanforderungen](#systemanforderungen)
  - [Installation](#installation)
  - [Installation überprüfen](#installation-überprüfen)
- [MCP Konfiguration](#mcp-konfiguration)
- [Tool-Matrix](#tool-matrix-101-mcp-tools)
- [Kernmodule](#kernmodule)
- [Externe Tool-Integration](#externe-tool-integration)
- [Anwendungsbeispiele](#anwendungsbeispiele)
  - [Natürlichsprachliche Befehle](#natürlichsprachliche-befehle)
  - [Python API](#python-api)
- [Konfiguration](#konfiguration)
- [Leistungsoptimierung](#leistungsoptimierung)
- [Fehlerbehebung](#fehlerbehebung)
- [FAQ](#faq)
- [Entwicklungsanleitung](#entwicklungsanleitung)
- [Änderungsprotokoll](#änderungsprotokoll)
- [Roadmap](#roadmap)
- [Beitragsrichtlinien](#beitragsrichtlinien)
- [Sicherheitsrichtlinie](#sicherheitsrichtlinie)
- [Danksagungen](#danksagungen)
- [Lizenz](#lizenz)
- [Haftungsausschluss](#haftungsausschluss)

---

## Projektübersicht

**AutoRedTeam-Orchestrator** ist ein KI-gesteuertes automatisiertes Penetrationstest-Framework basierend auf dem [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). Es kapselt 101 Sicherheitstools als MCP-Tools und ermöglicht nahtlose Integration mit MCP-kompatiblen KI-Editoren (Cursor, Windsurf, Kiro, Claude Desktop) für natürlichsprachliche automatisierte Sicherheitstests.

### Warum AutoRedTeam-Orchestrator?

| Merkmal | Traditionelle Tools | AutoRedTeam |
|---------|---------------------|-------------|
| **Interaktion** | Befehlszeilen-Memorierung | Natürlichsprachlicher Dialog |
| **Lernkurve** | Hoch (viele Parameter) | Niedrig (KI wählt Tools) |
| **Tool-Integration** | Manuelles Wechseln | 101 Tools vereinheitlichte Schnittstelle |
| **Angriffsplanung** | Manuelle Planung | **MCTS Algorithmus + Knowledge Graph** |
| **False-Positive-Reduktion** | Manuelle Verifizierung | **OOB + Statistische Verifizierung** |
| **Berichtserstellung** | Manuelles Schreiben | Ein-Klick professionelle Berichte |
| **Sitzungsverwaltung** | Keine | Checkpoint/Resume Unterstützung |
| **Sicherheit** | Pro Tool | **MCP Security Middleware einheitlicher Schutz** |

### Vergleich mit ähnlichen Projekten

| Merkmal | AutoRedTeam | Nuclei | SQLMap | Metasploit |
|---------|-------------|--------|--------|------------|
| KI-nativ | ✅ | ❌ | ❌ | ❌ |
| MCP-Protokoll | ✅ | ❌ | ❌ | ❌ |
| Natürliche Sprache | ✅ | ❌ | ❌ | ❌ |
| MCTS Angriffsplanung | ✅ | ❌ | ❌ | ❌ |
| Knowledge Graph | ✅ | ❌ | ❌ | ❌ |
| Vollautomatisierung | ✅ | Teilweise | Teilweise | Teilweise |
| False-Positive-Filter | Multi-Methoden | Einfach | Mittel | Einfach |

---

## Kernfunktionen

<table>
<tr>
<td width="50%">

### KI-natives Design

- **Intelligente Fingerabdruckerkennung** - Automatische Erkennung des Ziel-Technologie-Stacks (CMS/Frameworks/WAF)
- **MCTS Angriffsplanung** - Monte Carlo Tree Search gesteuerter optimaler Angriffspfad
- **Knowledge Graph** - Persistente Angriffswissensbank mit sitzungsübergreifendem Lernen
- **Historisches Feedback-Lernen** - Kontinuierliche Strategieoptimierung
- **Automatische Payload-Auswahl** - WAF-bewusste intelligente Mutation
- **KI PoC-Generierung** - Exploit-Code-Generierung aus CVE-Beschreibungen

</td>
<td width="50%">

### Vollständige Automatisierung

- **10-Phasen Aufklärungspipeline** - DNS/Port/Fingerabdruck/WAF/Subdomain/Verzeichnis/JS-Analyse
- **Schwachstellenerkennung & Verifizierung** - Automatisches Scannen + **Multi-Methoden-Validierung**
- **Intelligente Exploit-Orchestrierung** - Feedback-Loop-Engine + automatische Fehlerwiederholung
- **Ein-Klick professionelle Berichte** - JSON/HTML/Markdown Formate
- **Sitzungs-Checkpoint/Resume** - Unterbrochene Scans nahtlos fortsetzen

</td>
</tr>
<tr>
<td width="50%">

### Red Team Toolkit

- **Laterale Bewegung** - SMB/SSH/WMI/WinRM/PSExec (5 Protokolle)
- **C2 Kommunikation** - Beacon + DNS/HTTP/WebSocket/ICMP Tunnel
- **Verschleierung & Evasion** - XOR/AES/Base64/benutzerdefinierte Encoder
- **Persistenz** - Windows Registry/Geplante Tasks/WMI/Linux cron/Webshell
- **Credential-Zugriff** - Speicherextraktion/Dateisuche/Passwort-Spraying
- **AD-Angriffe** - Kerberoasting/AS-REP Roasting/SPN Scanning

</td>
<td width="50%">

### Sicherheitserweiterungen

- **API-Sicherheit** - JWT/CORS/GraphQL/WebSocket/OAuth Tests
- **Supply Chain Sicherheit** - SBOM-Generierung/Abhängigkeits-Audit/CI-CD Scan
- **Cloud-Native Sicherheit** - K8s RBAC/Pod-Sicherheit/gRPC/AWS Audit
- **CVE Intelligence** - NVD/Nuclei/ExploitDB Multi-Source-Sync
- **WAF Bypass** - 2000+ Payloads + 30+ Encoding-Methoden

</td>
</tr>
</table>

---

## Design-Philosophie

### Grundlegende Design-Prinzipien

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           Design-Philosophie                               │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│   1. KI-Native                                                             │
│      └─ Kein "KI-Wrapper", sondern architektonisch für KI konzipiert      │
│         └─ Native MCP-Protokollunterstützung                               │
│         └─ Natürlichsprachliche Tool-Auswahl                              │
│         └─ MCTS-Algorithmus gesteuerte Angriffsplanung                    │
│                                                                            │
│   2. Verifizierbare Sicherheit                                            │
│      └─ Multi-Methoden-Kreuzvalidierung zur False-Positive-Reduktion      │
│         └─ Statistische Verifizierung (Signifikanztests)                  │
│         └─ Boolean-Blind-Verifizierung (True/False Antwortvergleich)      │
│         └─ Zeitbasierte Blind-Verifizierung (Verzögerungserkennung)       │
│         └─ OOB-Verifizierung (DNS/HTTP Callback)                          │
│                                                                            │
│   3. Wissens-Persistenz                                                    │
│      └─ Angriffswissen bleibt sitzungsübergreifend erhalten              │
│         └─ Knowledge Graph speichert Ziel-, Schwachstellen-, Credential-  │
│            Beziehungen                                                     │
│         └─ Angriffspfad-Erfolgsraten aus Historie berechnet               │
│         └─ Ähnliche Zielerkennung beschleunigt neue Ziel-Tests            │
│                                                                            │
│   4. Security by Design                                                    │
│      └─ Sicherheit ist Kernarchitektur, nicht Ergänzung                   │
│         └─ MCP Security Middleware: Eingabevalidierung, Rate Limiting     │
│         └─ TOCTOU-Sicherheit: Atomare Operationen, Race-Condition-Schutz │
│         └─ Speichersicherheit: Ressourcenlimits, automatische Bereinigung │
│                                                                            │
│   5. Erweiterbare Architektur                                              │
│      └─ Dependency Injection Container für flexible Service-Komposition   │
│         └─ Modulares Handler-Design                                        │
│         └─ Externe Tools YAML-Konfiguration                               │
│         └─ Detektor-Composite-Pattern für beliebige Kombinationen         │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### Technische Entscheidungsmatrix

| Entscheidung | Optionen | Wahl | Begründung |
|--------------|----------|------|------------|
| **Kommunikation** | REST / gRPC / MCP | MCP | Native KI-Editor-Unterstützung, nahtlose NLP-Interaktion |
| **Angriffsplanung** | Regel-Engine / MCTS / RL | MCTS | Online-Planung, kein Vortraining, UCB1 Exploration-Exploitation |
| **Wissensspeicher** | SQL / Graph DB / Speicher | Memory Graph + Optionales Neo4j | Keine Abhängigkeit beim Start, Hochleistungsabfragen, optionale Persistenz |
| **Abhängigkeitsverwaltung** | Globale / DI | DI Container | Testbarkeit, Austauschbarkeit, Lebenszyklus-Management |
| **Parallelität** | Threading / asyncio / Hybrid | asyncio primär | Optimal für IO-gebundene Operationen, native Python-Unterstützung |
| **Hashing** | MD5 / SHA256 | SHA256 | Höhere Sicherheit, moderner Standard |

---

## Architektur

### Übergeordnete Architektur

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              KI-Editor-Schicht                              │
│        Cursor  │  Windsurf  │  Kiro  │  Claude Desktop  │  VS Code         │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ MCP Protokoll (JSON-RPC über stdio)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MCP Server Einstiegspunkt                           │
│                      mcp_stdio_server.py                                   │
│                        (101 Tools registriert)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                        MCP Security Middleware                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│  │ Eingabe-Val.│  │ Rate Limiter│  │ Op-Autoris. │  │ @secure_tool│       │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│   handlers/       │   │   core/           │   │   modules/        │
│   MCP Handler     │   │   Kern-Engines    │   │   Feature-Module  │
├───────────────────┤   ├───────────────────┤   ├───────────────────┤
│ • recon_handlers  │   │ • recon/          │   │ • api_security/   │
│ • detector_hdlrs  │   │   10-Phasen Recon │   │   JWT/CORS/GQL    │
│ • cve_handlers    │   │ • detectors/      │   │ • supply_chain/   │
│ • redteam_hdlrs   │   │   Vuln-Detektoren │   │   SBOM/Deps       │
│ • lateral_hdlrs   │   │ • mcts_planner    │   │ • cloud_security/ │
│ • external_hdlrs  │   │   MCTS Planung    │   │   K8s/gRPC/AWS    │
│ • ai_handlers     │   │ • knowledge/      │   │ • payload/        │
│ • session_hdlrs   │   │   Knowledge Graph │   │   2000+ Payloads  │
└───────────────────┘   │ • container       │   └───────────────────┘
                        │   DI Container    │
                        │ • c2/             │
                        │   C2 Komm.        │
                        │ • lateral/        │
                        │   Lat. Bewegung   │
                        │ • cve/            │
                        │   CVE Intel+PoC   │
                        └───────────────────┘
```

### Verzeichnisstruktur

```
AutoRedTeam-Orchestrator/
├── mcp_stdio_server.py          # MCP Server Einstiegspunkt (101 Tools registriert)
├── VERSION                      # Versionsdatei
├── pyproject.toml               # Projektkonfiguration
├── requirements.txt             # Produktionsabhängigkeiten
├── requirements-dev.txt         # Entwicklungsabhängigkeiten
│
├── handlers/                    # MCP Tool Handler (16 Module)
│   ├── recon_handlers.py        # Aufklärungs-Tools (8)
│   ├── detector_handlers.py     # Schwachstellen-Erkennungs-Tools (11)
│   ├── api_security_handlers.py # API-Sicherheits-Tools (7)
│   ├── supply_chain_handlers.py # Supply Chain Sicherheits-Tools (3)
│   ├── cloud_security_handlers.py # Cloud-Sicherheits-Tools (3)
│   ├── cve_handlers.py          # CVE-Tools (8)
│   ├── redteam_handlers.py      # Red Team Kern-Tools (14)
│   ├── lateral_handlers.py      # Laterale Bewegungs-Tools (9)
│   ├── persistence_handlers.py  # Persistenz-Tools (3)
│   ├── ad_handlers.py           # AD-Angriffs-Tools (3)
│   ├── orchestration_handlers.py # Orchestrierungs-Tools (11)
│   ├── external_tools_handlers.py # Externe Tools (8)
│   ├── ai_handlers.py           # KI-Assistenz-Tools (3)
│   ├── session_handlers.py      # Sitzungs-Tools (4)
│   ├── report_handlers.py       # Berichts-Tools (2)
│   └── misc_handlers.py         # Verschiedene Tools (3)
│
├── core/                        # Kern-Engines
│   ├── __init__.py              # Versionsdefinition
│   │
│   ├── security/                # Sicherheitskomponenten ⭐ v3.0.2
│   │   └── mcp_security.py      # MCP Security Middleware
│   │
│   ├── container.py             # DI Container ⭐ v3.0.2
│   │
│   ├── mcts_planner.py          # MCTS Angriffsplaner ⭐ v3.0.2
│   │
│   ├── knowledge/               # Knowledge Graph ⭐ v3.0.2
│   │   ├── __init__.py
│   │   ├── manager.py           # Knowledge Manager
│   │   └── models.py            # Datenmodelle
│   │
│   ├── recon/                   # Aufklärungs-Engine (10-Phasen Pipeline)
│   ├── detectors/               # Schwachstellen-Detektoren
│   ├── cve/                     # CVE Intelligence
│   ├── c2/                      # C2 Kommunikations-Framework
│   ├── lateral/                 # Laterale Bewegung
│   ├── evasion/                 # Evasion & Verschleierung
│   ├── persistence/             # Persistenz-Mechanismen
│   ├── credential/              # Credential-Zugriff
│   ├── ad/                      # AD-Angriffe
│   ├── session/                 # Sitzungsverwaltung
│   ├── tools/                   # Externe Tool-Verwaltung
│   └── exfiltration/            # Datenexfiltration
│
├── modules/                     # Feature-Module
│   ├── api_security/            # API-Sicherheit
│   ├── supply_chain/            # Supply Chain Sicherheit
│   ├── cloud_security/          # Cloud-Sicherheit
│   └── payload/                 # Payload-Engine
│
├── utils/                       # Hilfsfunktionen
├── wordlists/                   # Eingebaute Wörterbücher
├── config/                      # Konfigurationsdateien
├── tests/                       # Test-Suite (1461 Testfälle)
├── poc-templates/               # PoC-Vorlagen
├── templates/                   # Berichtsvorlagen
├── scripts/                     # Hilfsskripte
└── docs/                        # Dokumentation
```

---

## ATT&CK Abdeckungsmatrix

| Taktik | Abgedeckte Techniken | Tool-Anzahl | Status |
|--------|---------------------|-------------|--------|
| Aufklärung | Aktives Scannen, Passive Sammlung, OSINT, JS-Analyse | 12+ | ✅ |
| Ressourcenentwicklung | Payload-Generierung, Verschleierung, PoC-Generierung | 4+ | ✅ |
| Erstzugang | Web-Schwachstellen-Exploitation, CVE-Exploits, API-Schwachstellen | 19+ | ✅ |
| Ausführung | Befehlsinjektion, Code-Ausführung, Deserialisierung | 5+ | ✅ |
| Persistenz | Registry, Geplante Tasks, Webshell, WMI | 3+ | ✅ |
| Privilegieneskalation | UAC Bypass, Token-Impersonation, Kernel-Exploits | 2+ | ⚠️ |
| Verteidigungsumgehung | AMSI Bypass, ETW Bypass, Verschleierung, Traffic-Mutation | 4+ | ✅ |
| Credential-Zugriff | Speicherextraktion, Dateisuche, Passwort-Spraying | 2+ | ✅ |
| Entdeckung | Netzwerk-Scan, Service-Enumeration, AD-Enumeration | 8+ | ✅ |
| Laterale Bewegung | SMB/SSH/WMI/WinRM/PSExec | 9+ | ✅ |
| Sammlung | Datenaggregation, Sensible Dateisuche | 2+ | ✅ |
| Befehl & Kontrolle | HTTP/DNS/WebSocket/ICMP Tunnel | 4+ | ✅ |
| Exfiltration | DNS/HTTP/ICMP/SMB + AES-Verschlüsselung | 4+ | ✅ |

---

## Schnellstart

### Systemanforderungen

| Komponente | Mindestanforderung | Empfohlen |
|------------|-------------------|-----------|
| Betriebssystem | Windows 10, Ubuntu 20.04, macOS 12 | Windows 11, Ubuntu 22.04, macOS 14 |
| Python | 3.10 | 3.11 oder 3.12 |
| Arbeitsspeicher | 4GB | 8GB+ |
| Festplatte | 500MB | 2GB+ (inkl. CVE-Datenbank) |
| Netzwerk | Internetzugang | Niedrige Latenz |

### Installation

#### Option 1: Standard-Installation (Empfohlen)

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

# 3. Abhängigkeiten installieren
pip install -r requirements.txt

# 4. Umgebungsvariablen-Vorlage kopieren
cp .env.example .env
# .env bearbeiten und API-Schlüssel eintragen

# 5. Service starten
python mcp_stdio_server.py
```

#### Option 2: Minimal-Installation (nur Kern)

```bash
# Nur Kernabhängigkeiten installieren (Aufklärung + Schwachstellen-Erkennung)
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

#### Option 4: Entwicklungsumgebung

```bash
# Entwicklungsabhängigkeiten installieren (Tests, Formatierung, Lint)
pip install -r requirements-dev.txt

# Pre-commit Hooks installieren
pre-commit install

# Tests ausführen
pytest tests/ -v
```

### Installation überprüfen

```bash
# Version prüfen
python mcp_stdio_server.py --version
# Ausgabe: AutoRedTeam-Orchestrator v3.0.1

# Selbsttest ausführen
python -c "from core import __version__; print(f'Core version: {__version__}')"

# Kernmodul-Tests ausführen
pytest tests/test_mcp_security.py tests/test_container.py tests/test_mcts_planner.py tests/test_knowledge_manager.py tests/test_advanced_verifier.py -v
# Erwartet: 291+ passed
```

---

## MCP Konfiguration

Fügen Sie die folgende Konfiguration zur MCP-Konfigurationsdatei Ihres KI-Editors hinzu:

### Konfigurationsdatei-Pfade

| Editor | Konfigurationspfad |
|--------|-------------------|
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

## Tool-Matrix (101 MCP Tools)

| Kategorie | Anzahl | Schlüssel-Tools | Beschreibung |
|-----------|--------|-----------------|--------------|
| **Aufklärung** | 8 | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` `dir_scan` `dns_lookup` `tech_detect` | Informationssammlung & Asset-Erkennung |
| **Schwachstellen-Erkennung** | 11 | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` `idor_scan` `path_traversal_scan` `cors_scan` `security_headers_scan` | OWASP Top 10 + Logik-Schwachstellen |
| **API-Sicherheit** | 7 | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` `cors_deep_scan` `security_headers_score` | Moderne API-Sicherheitstests |
| **Supply Chain** | 3 | `sbom_generate` `dependency_audit` `cicd_scan` | SBOM/Abhängigkeiten/CI-CD Sicherheit |
| **Cloud-Native** | 3 | `k8s_scan` `grpc_scan` `aws_scan` | K8s/gRPC/AWS Sicherheits-Audit |
| **Red Team Kern** | 14 | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` `payload_obfuscate` | Post-Exploitation & internes Netzwerk |
| **Laterale Bewegung** | 9 | `lateral_ssh` `lateral_wmi` `lateral_winrm` `lateral_psexec` `lateral_ssh_tunnel` | 5-Protokoll laterale Bewegung |
| **Persistenz** | 3 | `persistence_windows` `persistence_linux` `persistence_webshell` | Windows/Linux/Web |
| **AD-Angriffe** | 3 | `ad_enumerate` `ad_kerberos_attack` `ad_spn_scan` | Vollständige Domain-Penetration |
| **CVE** | 8 | `cve_search` `cve_sync` `cve_stats` `poc_execute` `poc_list` `cve_auto_exploit` `cve_exploit_with_desc` `cve_generate_poc` | CVE Intelligence + KI PoC |
| **Orchestrierung** | 11 | `auto_pentest` `pentest_resume` `pentest_status` `pentest_phase` `smart_analyze` `attack_chain_plan` | Automatisierte Penetration |
| **Externe Tools** | 8 | `ext_nmap_scan` `ext_nuclei_scan` `ext_sqlmap_scan` `ext_ffuf_fuzz` `ext_masscan_scan` `ext_tool_chain` `ext_tools_status` | Professionelle Tool-Integration |
| **KI-Assistenz** | 3 | `smart_payload` `ai_attack_chain` `smart_pentest` | Intelligente Analyse |
| **Sitzung/Berichte** | 9 | `session_create` `session_status` `session_list` `session_complete` `generate_report` `export_findings` | Sitzungsverwaltung + Berichte |

---

## Kernmodule

### 1. MCP Security Middleware (v3.0.2)

**Speicherort**: `core/security/mcp_security.py`

Bietet eine einheitliche Sicherheitsschutzschicht für alle MCP-Tool-Aufrufe:

```python
from core.security.mcp_security import MCPSecurityMiddleware, RateLimitConfig

security = MCPSecurityMiddleware(
    rate_limit_config=RateLimitConfig(
        requests_per_minute=60,
        burst_limit=10,
    ),
    max_risk=RiskLevel.HIGH,
)

# Ziel validieren
result = security.validate_target("192.168.1.1")
if not result.valid:
    print(f"Abgelehnt: {result.errors}")

# Decorator-Schutz
@security.secure_tool(operation="port_scan", rate_limit_key="scan")
async def port_scan(target: str):
    # ...
```

**Kernfunktionen**:
- **Eingabevalidierung**: IP/Domain/URL/CIDR/Port/Pfad-Validierung, SSRF-Erkennung
- **Rate Limiting**: Schiebefenster + Token Bucket, Ressourcenerschöpfungs-Prävention
- **Operationsautorisierung**: Risikobasierte Operationssteuerung
- **Speicherschutz**: Automatische Bereinigung abgelaufener Daten, Speicherleck-Prävention

### 2. MCTS Angriffsplaner (v3.0.2)

**Speicherort**: `core/mcts_planner.py`

Verwendet den Monte Carlo Tree Search Algorithmus zur Planung optimaler Angriffspfade:

```python
from core.mcts_planner import MCTSPlanner, AttackState

planner = MCTSPlanner(exploration_weight=1.414, max_depth=10)

state = AttackState(
    target="192.168.1.100",
    target_type="linux_server",
    open_ports={22: "ssh", 80: "http"},
)

result = planner.plan(state, iterations=1000)
print(f"Empfohlene Aktionen: {result['recommended_actions']}")
```

**Kernfunktionen**:
- **UCB1 Algorithmus**: Balance zwischen Exploration und Exploitation
- **Aktionsgenerierung**: Intelligente Generierung verfügbarer Aktionen basierend auf dem Zustand
- **Angriffssimulation**: Simuliert Angriffsausführung zur Schätzung der Erfolgsraten
- **Pfadextraktion**: Extraktion optimaler Angriffspfad-Sequenzen

### 3. Knowledge Graph (v3.0.2)

**Speicherort**: `core/knowledge/`

Persistente Speicherung von Angriffswissen mit sitzungsübergreifendem Lernen:

```python
from core.knowledge import KnowledgeManager

km = KnowledgeManager()

# Ziel speichern
target_id = km.store_target("192.168.1.100", "linux_server")

# Service speichern
service_id = km.store_service(target_id, "nginx", 80)

# Schwachstelle speichern
vuln_id = km.store_vulnerability(service_id, "CVE-2021-44228", "critical")

# Angriffspfade finden
paths = km.get_attack_paths(target_id, credential_id)

# Ähnliche Ziele finden
similar = km.find_similar_targets("192.168.1.100")
```

**Kernfunktionen**:
- **Entitätsspeicherung**: Ziel, Service, Schwachstelle, Credential
- **Beziehungsmodellierung**: HOSTS, HAS_VULNERABILITY, OBTAINED_FROM
- **BFS Pfadsuche**: Unterstützung für Multi-Pfad-Entdeckung
- **Ähnlichkeitsabgleich**: Erkennung gleicher Subnetze/Domains

### 4. Erweiterter Verifizierer (v3.0.2 Verbesserung)

**Speicherort**: `core/detectors/advanced_verifier.py`

Multi-Methoden-Kreuzvalidierung zur Reduzierung der False-Positive-Rate:

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
print(f"Status: {aggregated.status}, Konfidenz: {aggregated.confidence:.2%}")
```

**Verifizierungsmethoden**:
- **Statistische Verifizierung**: Multi-Sample Antwortdifferenz-Signifikanz
- **Boolean-Blind-Verifizierung**: True/False Bedingungsvergleich
- **Zeitbasierte Blind-Verifizierung**: Verzögerungserkennung mit Netzwerk-Jitter-Kompensation
- **OOB-Verifizierung**: DNS/HTTP Out-of-Band Callback-Bestätigung

### 5. Dependency Injection Container (v3.0.2)

**Speicherort**: `core/container.py`

Flexible Service-Komposition und Lebenszyklus-Management:

```python
from core.container import Container, singleton, inject

container = Container()

# Services registrieren
container.register_singleton(KnowledgeManager)
container.register_transient(SQLiDetector)

# Dekoratoren verwenden
@singleton
class ConfigManager:
    pass

# Abhängigkeiten injizieren
config = inject(ConfigManager)

# Scoped Container (Request-Ebene)
with container.create_scope() as scope:
    service = scope.resolve(RequestService)
```

**Kernfunktionen**:
- **Lebenszyklus**: Singleton, Scoped, Transient
- **Automatische Injektion**: Automatische Auflösung von Konstruktorparametern
- **Zykluserkennung**: Erkennung und Meldung zirkulärer Abhängigkeiten
- **Ressourcenbereinigung**: Scoped Container ruft automatisch dispose() auf

---

## Externe Tool-Integration

Unterstützung für die Integration lokal installierter professioneller Sicherheitstools:

| Tool | Verwendungszweck | MCP Befehl | Anforderung |
|------|-----------------|------------|-------------|
| **Nmap** | Port-Scan + Service-Erkennung + NSE-Skripte | `ext_nmap_scan` | System PATH oder konfigurierter Pfad |
| **Nuclei** | 7000+ CVE/Schwachstellen-Vorlagen-Scan | `ext_nuclei_scan` | Go-Binärdatei |
| **SQLMap** | 6 SQL-Injection-Techniken + WAF Bypass | `ext_sqlmap_scan` | Python-Skript |
| **ffuf** | Hochgeschwindigkeits-Verzeichnis/Parameter-Fuzzing | `ext_ffuf_fuzz` | Go-Binärdatei |
| **Masscan** | Ultra-Hochgeschwindigkeits-Massen-Port-Scan | `ext_masscan_scan` | Erfordert root/Administrator |

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
# Vollständige Aufklärungskette: masscan schnelle Erkennung → nmap detaillierte Identifikation
ext_tool_chain target="192.168.1.0/24" chain_name="full_recon"

# Schwachstellen-Scan-Kette: nuclei + sqlmap kombinierte Erkennung
ext_tool_chain target="https://example.com" chain_name="vuln_scan"

# Externe Tool-Status prüfen
ext_tools_status
```

---

## Anwendungsbeispiele

### Natürlichsprachliche Befehle

Chatten Sie direkt in KI-Editoren, um Tools aufzurufen:

#### Aufklärung & Informationssammlung

```
# Vollständige Aufklärung
"Führe eine vollständige Aufklärung auf example.com durch und generiere einen Bericht"

# Port-Scan
"Scanne das 192.168.1.0/24 Netzwerk nach offenen Ports"

# Subdomain-Enumeration
"Enumeriere alle Subdomains von example.com"

# Fingerabdruckerkennung
"Identifiziere den Technologie-Stack und die WAF der Zielwebsite"

# JS-Analyse
"Analysiere JavaScript-Dateien der Zielwebsite auf sensible Informationen"
```

#### Schwachstellen-Scan

```
# SQL-Injection
"Prüfe ob https://target.com/api?id=1 anfällig für SQL-Injection ist"

# XSS-Scan
"Scanne Zielformulare auf XSS-Schwachstellen und generiere PoC"

# API-Sicherheit
"Führe vollständige JWT/CORS/GraphQL-Sicherheitstests auf der Ziel-API durch"

# CVE-Suche und Exploitation
"Suche Apache Log4j bezogene CVEs und führe PoC aus"
```

#### Red Team Operationen

```
# Laterale Bewegung
"Führe whoami-Befehl auf 192.168.1.100 über SMB aus"

# C2 Kommunikation
"Starte DNS-Tunnel-Verbindung zu c2.example.com"

# Persistenz
"Etabliere geplante Task-Persistenz auf Windows-Ziel"

# AD-Angriffe
"Führe Kerberoasting-Angriff auf Domain Controller durch"
```

#### Automatisierte Penetrationstests

```
# Vollautomatisierter Penetrationstest
"Führe vollautomatisierten Penetrationstest auf https://target.com durch mit detailliertem Bericht"

# Intelligente Angriffskette
"Analysiere Ziel und generiere optimale Angriffsketten-Empfehlungen"

# Sitzung fortsetzen
"Setze zuvor unterbrochene Penetrationstest-Sitzung fort"
```

### Python API

#### Grundlegende Verwendung

```python
import asyncio
from core.recon import StandardReconEngine, ReconConfig
from core.detectors import DetectorFactory

async def main():
    # 1. Aufklärungs-Engine
    config = ReconConfig(
        quick_mode=False,
        enable_js_analysis=True,
        max_threads=50
    )
    engine = StandardReconEngine("https://target.com", config)
    recon_result = await engine.run()
    print(f"{len(recon_result.open_ports)} offene Ports gefunden")

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

#### MCTS Angriffsplanung

```python
from core.mcts_planner import MCTSPlanner, AttackState

planner = MCTSPlanner(exploration_weight=1.414, max_depth=10)

state = AttackState(
    target="192.168.1.100",
    target_type="linux_server",
    open_ports={22: "ssh", 80: "http", 3306: "mysql"},
)

result = planner.plan(state, iterations=1000)

print(f"Empfohlene Angriffssequenz:")
for action, visits, reward in result['recommended_actions']:
    print(f"  - {action.type.value}: {action.target_port} (Konfidenz: {reward:.2f})")
```

#### Knowledge Graph

```python
from core.knowledge import KnowledgeManager

km = KnowledgeManager()

# Wissen aufbauen
target_id = km.store_target("192.168.1.100", "linux_server")
service_id = km.store_service(target_id, "nginx", 80)
vuln_id = km.store_vulnerability(service_id, "CVE-2021-44228", "critical")

# Angriffspfade abfragen
paths = km.get_attack_paths(target_id, vuln_id)
for path in paths:
    print(f"Pfadlänge: {path.length}, Erfolgsrate: {path.success_rate:.2%}")

# Ähnliche Ziele finden
similar = km.find_similar_targets("192.168.1.100", top_k=5)
for match in similar:
    print(f"Ähnliches Ziel: {match.entity.properties['target']}, Bewertung: {match.score:.2f}")
```

---

## Konfiguration

### Umgebungsvariablen (.env)

```bash
# ========== Sicherheit ==========
REDTEAM_MASTER_KEY=
AUTOREDTEAM_API_KEY=
AUTOREDTEAM_AUTH_MODE=permissive

# ========== API-Schlüssel ==========
OPENAI_API_KEY=ihr_schluessel
ANTHROPIC_API_KEY=ihr_schluessel
SHODAN_API_KEY=ihr_schluessel
CENSYS_API_ID=ihre_id
CENSYS_API_SECRET=ihr_secret
NVD_API_KEY=ihr_schluessel
GITHUB_TOKEN=ihr_token

# ========== Proxy ==========
HTTP_PROXY=
HTTPS_PROXY=
SOCKS_PROXY=

# ========== Global ==========
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

### Parallelitätskonfiguration

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

### Speicheroptimierung

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

## Fehlerbehebung

| Problem | Ursache | Lösung |
|---------|---------|--------|
| MCP Server verbindet nicht | Pfadfehler oder Python-Umgebungsproblem | Absoluten Pfad prüfen, Python-Interpreter verifizieren |
| Import-Fehler | PYTHONPATH nicht gesetzt | `PYTHONPATH` Umgebungsvariable hinzufügen |
| Externes Tool schlägt fehl | Tool nicht installiert oder Pfadfehler | `ext_tools_status` ausführen |
| CVE-Sync fehlgeschlagen | Netzwerk oder API-Rate-Limit | Netzwerk prüfen, NVD_API_KEY konfigurieren |
| Langsame Scans | Niedrige Parallelitätskonfiguration | `MAX_THREADS` und `RATE_LIMIT_DELAY` anpassen |
| Speicherüberlauf | Groß-Scan | `streaming_mode` aktivieren, `memory_limit` setzen |

### Debug-Modus

```bash
LOG_LEVEL=DEBUG python mcp_stdio_server.py
python -m py_compile mcp_stdio_server.py
pytest tests/test_mcp_security.py::TestInputValidator -v
```

---

## FAQ

<details>
<summary><b>F: Wie verwende ich es in einer Offline-Umgebung?</b></summary>

1. CVE-Datenbank vorab herunterladen: `python core/cve/update_manager.py sync --offline-export`
2. Lokale Wörterbuchdateien verwenden
3. Netzwerkfunktionen deaktivieren: `OFFLINE_MODE=true`

</details>

<details>
<summary><b>F: Wie füge ich benutzerdefinierte Detektoren hinzu?</b></summary>

1. Neue Datei in `core/detectors/` erstellen
2. Von `BaseDetector` Klasse erben
3. `detect()` und `async_detect()` Methoden implementieren
4. MCP-Tool in `handlers/detector_handlers.py` registrieren

</details>

<details>
<summary><b>F: Wie funktioniert der MCTS Planer?</b></summary>

MCTS plant Angriffspfade in vier Phasen:

1. **Selektion**: UCB1 Algorithmus wählt optimalen Pfad ab Wurzel
2. **Expansion**: Neue Angriffsaktionen an Blattknoten erweitern
3. **Simulation**: Angriffsausführung simulieren und Belohnungen bewerten
4. **Rückpropagation**: Belohnungen zurückpropagieren um Pfadknoten zu aktualisieren

UCB1-Formel: `UCB1 = Q/N + c * sqrt(ln(N_parent) / N)`

Wobei `c = sqrt(2)` das Explorationsgewicht ist, das "bekannt gute Pfade" und "unerforschte Pfade" ausbalanciert.

</details>

<details>
<summary><b>F: Wie reduziert der Knowledge Graph doppelte Arbeit?</b></summary>

1. **Zielähnlichkeit**: Erkennung von Zielen im gleichen Subnetz/gleicher Domain, Wiederverwendung von Schwachstelleninformationen
2. **Angriffspfad-Erfolgsraten**: Berechnung der Pfad-Erfolgsraten aus der Historie
3. **Credential-Verknüpfung**: Automatische Verknüpfung von Credentials mit erreichbaren Zielen
4. **Aktionshistorie-Lernen**: Aufzeichnung von Aktionserfolgsraten, Optimierung zukünftiger Entscheidungen

</details>

<details>
<summary><b>F: Wie integriere ich weitere externe Tools?</b></summary>

1. Tool-Konfiguration in `config/external_tools.yaml` hinzufügen
2. MCP-Tool-Funktion in `handlers/external_tools_handlers.py` hinzufügen
3. `execute_tool()` Methode von `core/tools/tool_manager.py` verwenden

</details>

<details>
<summary><b>F: Wie gehe ich mit WAF-Blockierung um?</b></summary>

1. `smart_payload` Tool für automatische WAF-Bypass Payload-Auswahl verwenden
2. Proxy-Pool konfigurieren: `PROXY_POOL=true`
3. Traffic-Mutation aktivieren: `traffic_mutation=true`
4. Scan-Geschwindigkeit reduzieren: `RATE_LIMIT_DELAY=1.0`

</details>

<details>
<summary><b>F: Welche Berichtsformate werden unterstützt?</b></summary>

- JSON (maschinenlesbar)
- HTML (visualisierter Bericht mit Diagrammen)
- Markdown (geeignet für Git/Wiki)
- PDF (erfordert `reportlab` Installation)
- DOCX (erfordert `python-docx` Installation)

</details>

---

## Entwicklungsanleitung

### Code-Standards

```bash
# Code formatieren
black core/ modules/ handlers/ utils/
isort core/ modules/ handlers/ utils/

# Statische Analyse
pylint core/ modules/ handlers/ utils/
mypy core/ modules/ handlers/ utils/

# Tests ausführen
pytest tests/ -v --cov=core --cov-report=html
```

### Neue MCP-Tools hinzufügen

```python
# 1. Handler in handlers/ hinzufügen
# handlers/my_handlers.py

from mcp import tool

@tool()
async def my_new_tool(target: str, option: str = "default") -> dict:
    """Tool-Beschreibung

    Args:
        target: Zieladresse
        option: Optionaler Parameter

    Returns:
        Ergebnis-Dictionary
    """
    return {"success": True, "data": ...}

# 2. Import in mcp_stdio_server.py
from handlers.my_handlers import my_new_tool
```

---

## Änderungsprotokoll

### v3.0.2 (In Entwicklung) - Architekturhärtung

**Neue Module** (Implementiert, Release ausstehend)
- **MCP Security Middleware** - Eingabevalidierung, Rate Limiting, Operationsautorisierung
- **DI Container** - Lebenszyklus-Management, zirkuläre Abhängigkeitserkennung
- **MCTS Angriffsplaner** - UCB1 Algorithmus, Angriffspfad-Optimierung
- **Knowledge Graph** - Entitäts-Beziehungsspeicher, BFS Pfadsuche
- **Erweiterte Verifizierer-Verbesserung** - OOB Thread-Sicherheit, SSTI Payloads

**Sicherheitskorrekturen**
- TOCTOU Race Conditions behoben (erweiterter Lock-Scope)
- Dauer-Autorisierungs-Ablauflogik korrigiert
- SSRF-Erkennung hinzugefügt (Private-IP-Validierung)
- Rate Limiter Speicherleck behoben (max_keys Eviction)
- DNS-Injektion behoben (Token-ID-Sanitisierung)
- MD5 → SHA256 Hash-Upgrade

**Test-Erweiterung**
- 291 Testfälle hinzugefügt (mcp_security: 62, container: 39, mcts: 57, verifier: 43, knowledge: 90)
- Thread-Sicherheits-Testabdeckung
- Integrations-Test-Workflows

### v3.0.1 (2026-01-30) - Qualitätshärtung

**Hinzugefügt**
- CVE automatische Exploitation-Verbesserung (`cve_auto_exploit`, `cve_exploit_with_desc`, `cve_generate_poc`)
- KI PoC Generator (`core/cve/ai_poc_generator.py`)

**Behoben**
- Versionsynchronisation - Vereinheitlichung VERSION/pyproject.toml/Quellcode
- ToolCounter Korrektur - external_tools/lateral/persistence/ad Kategorien hinzugefügt
- Thread-Sicherheit - threading.Lock für beacon.py Zustandsverwaltung hinzugefügt

**Verbessert**
- CI/CD-Härtung - Lint-Fehler blockieren jetzt Builds
- Testabdeckungs-Schwellenwert auf 50% erhöht
- Abhängigkeits-Constraints - Obere Grenzen hinzugefügt

### v3.0.0 (2026-01-18) - Architektur-Erweiterung

**Hinzugefügt**
- Externe Tool-Integration - 8 externe Tool MCP-Befehle
- Tool-Chain Orchestrierung - YAML-gesteuerte Multi-Tool-Kombination
- Handler-Modularisierung - 16 unabhängige Handler-Module

---

## Roadmap

### In Arbeit

- [ ] v3.0.2 Release (MCP Security Middleware, MCTS Planer, Knowledge Graph, DI Container)
- [ ] Web UI Verwaltungsoberfläche
- [ ] Verteilter Scan-Cluster

### Geplant

- [ ] Weitere Cloud-Plattformen (GCP/Alibaba Cloud/Tencent Cloud)
- [ ] Burp Suite Plugin-Integration
- [ ] Mobile App Sicherheitstests
- [ ] KI-autonomer Angriffs-Agent
- [ ] Neo4j Knowledge Graph Backend

### Abgeschlossen (v3.0.1)

- [x] Vollständiges Red Team Toolkit
- [x] CVE Intelligence & KI PoC-Generierung
- [x] API/Supply Chain/Cloud Sicherheitsmodule
- [x] Vollautomatisiertes Penetrationstest-Framework
- [x] Externe Tool-Integration

---

## Beitragsrichtlinien

Wir begrüßen Beiträge jeder Art!

### Schnellstart

```bash
# 1. Fork und Klonen
git clone https://github.com/IHR_USERNAME/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. Branch erstellen
git checkout -b feature/ihre-funktion

# 3. Entwicklungsabhängigkeiten installieren
pip install -r requirements-dev.txt
pre-commit install

# 4. Entwickeln und Testen
pytest tests/ -v

# 5. PR einreichen
git push origin feature/ihre-funktion
```

### Commit-Konvention

Verwenden Sie das [Conventional Commits](https://www.conventionalcommits.org/) Format:

- `feat:` Neue Funktion
- `fix:` Fehlerbehebung
- `docs:` Dokumentation
- `refactor:` Refactoring
- `test:` Tests
- `chore:` Build/Tools
- `security:` Sicherheitsbezogen

Siehe [CONTRIBUTING.md](CONTRIBUTING.md) für Details.

---

## Sicherheitsrichtlinie

- **Verantwortungsvolle Offenlegung**: Melden Sie Sicherheitslücken an [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com)
- **Nur autorisierte Nutzung**: Dieses Tool ist ausschließlich für autorisierte Sicherheitstests und Forschung
- **Compliance**: Stellen Sie vor der Nutzung die Einhaltung lokaler Gesetze sicher

Siehe [SECURITY.md](SECURITY.md) für Details.

---

## Danksagungen

### Kernabhängigkeiten

| Projekt | Zweck | Lizenz |
|---------|-------|--------|
| [MCP Protocol](https://modelcontextprotocol.io/) | KI-Tool-Protokollstandard | MIT |
| [aiohttp](https://github.com/aio-libs/aiohttp) | Asynchroner HTTP-Client | Apache-2.0 |
| [pydantic](https://github.com/pydantic/pydantic) | Datenvalidierung | MIT |
| [pytest](https://github.com/pytest-dev/pytest) | Test-Framework | MIT |

### Design-Inspiration

| Projekt | Inspiration |
|---------|------------|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Schwachstellen-Scanner-Engine-Design |
| [SQLMap](https://github.com/sqlmapproject/sqlmap) | SQL-Injection-Erkennungsansatz |
| [Impacket](https://github.com/fortra/impacket) | Netzwerkprotokoll-Implementierung |
| [Metasploit](https://github.com/rapid7/metasploit-framework) | Post-Exploitation-Modul-Design |

### Algorithmus-Referenzen

| Algorithmus | Zweck | Referenz |
|-------------|-------|----------|
| UCB1 | MCTS Exploration-Exploitation Balance | Auer et al., 2002 |
| BFS | Knowledge Graph Pfadsuche | - |
| Token Bucket | Rate Limiting | - |
| Sliding Window | Rate Limiting | - |

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Coff0xc/AutoRedTeam-Orchestrator&type=Date)](https://star-history.com/#Coff0xc/AutoRedTeam-Orchestrator&Date)

---

## Lizenz

Dieses Projekt ist lizenziert unter der **MIT-Lizenz** - siehe [LICENSE](LICENSE) Datei für Details.

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

## Haftungsausschluss

> **WARNUNG**: Dieses Tool ist ausschließlich für **autorisierte Sicherheitstests und Forschung** bestimmt.
>
> Stellen Sie vor der Nutzung dieses Tools zum Testen eines Systems sicher, dass Sie:
> - Eine **schriftliche Genehmigung** des Systemeigentümers haben
> - **Lokale Gesetze und Vorschriften** einhalten
> - **Berufsethische** Standards befolgen
>
> Nicht autorisierte Nutzung kann gegen Gesetze verstoßen. **Die Entwickler sind nicht verantwortlich für jeglichen Missbrauch**.
>
> Dieses Tool enthält Red Team Angriffsfähigkeiten (Laterale Bewegung, C2 Kommunikation, Persistenz usw.), die ausschließlich für folgende Zwecke bestimmt sind:
> - Autorisierte Penetrationstests
> - Sicherheitsforschung und -ausbildung
> - CTF-Wettbewerbe
> - Validierung von Verteidigungsfähigkeiten
>
> **Nutzung für illegale Zwecke ist strengstens untersagt.**

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
  <sub>Wenn Ihnen dieses Projekt hilft, erwägen Sie bitte einen ⭐ Stern!</sub>
</p>
