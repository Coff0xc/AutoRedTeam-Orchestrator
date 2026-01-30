<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>Framework d'Orchestration Red Team Automatise Pilote par l'IA</b><br>
  <sub>Multiplateforme | 100+ Outils MCP | 2000+ Payloads | Couverture ATT&CK Complete</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md">Русский</a> ·
  <a href="README_DE.md">Deutsch</a> ·
  <a href="README_FR.md"><b>Francais</b></a>
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
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Communaute-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-Documentation-blue?style=flat-square&logo=gitbook&logoColor=white" alt="Wiki"></a>
</p>

---

## Table des Matieres

- [Presentation du Projet](#presentation-du-projet)
- [Fonctionnalites Principales](#fonctionnalites-principales)
- [Matrice de Couverture ATT&CK](#matrice-de-couverture-attck)
- [Demarrage Rapide](#demarrage-rapide)
  - [Configuration Requise](#configuration-requise)
  - [Methodes d'Installation](#methodes-dinstallation)
  - [Verification de l'Installation](#verification-de-linstallation)
- [Configuration MCP](#configuration-mcp)
- [Matrice des Outils (100+ Outils MCP)](#matrice-des-outils-100-outils-mcp)
- [Integration des Outils Externes](#integration-des-outils-externes)
- [Exemples d'Utilisation](#exemples-dutilisation)
  - [Utilisation en Ligne de Commande](#utilisation-en-ligne-de-commande)
  - [Appels API Python](#appels-api-python)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Optimisation des Performances](#optimisation-des-performances)
- [Depannage](#depannage)
- [Questions Frequentes (FAQ)](#questions-frequentes-faq)
- [Journal des Modifications](#journal-des-modifications)
- [Feuille de Route](#feuille-de-route)
- [Guide de Contribution](#guide-de-contribution)
- [Politique de Securite](#politique-de-securite)
- [Remerciements](#remerciements)
- [Licence](#licence)
- [Avertissement](#avertissement)

---

## Presentation du Projet

**AutoRedTeam-Orchestrator** est un framework de tests de penetration automatises pilote par l'IA, base sur le [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). Il encapsule plus de 100 outils de securite en tant qu'outils MCP, pouvant s'integrer de maniere transparente avec les editeurs IA compatibles MCP (Cursor, Windsurf, Kiro, Claude Desktop), permettant des tests de securite automatises pilotes par le langage naturel.

### Pourquoi Choisir AutoRedTeam-Orchestrator ?

| Caracteristique | Outils Traditionnels | AutoRedTeam |
|-----------------|---------------------|-------------|
| **Mode d'Interaction** | Memorisation en ligne de commande | Conversation en langage naturel |
| **Courbe d'Apprentissage** | Elevee (nombreux parametres a memoriser) | Faible (l'IA selectionne automatiquement les outils) |
| **Integration des Outils** | Changement manuel d'outils | Interface unifiee pour 100+ outils |
| **Planification des Chaines d'Attaque** | Planification manuelle | Recommandations intelligentes par l'IA |
| **Generation de Rapports** | Redaction manuelle | Generation de rapports professionnels en un clic |
| **Gestion des Sessions** | Aucune | Prise en charge de la reprise apres interruption |

---

## Fonctionnalites Principales

<table>
<tr>
<td width="50%">

**Conception Native IA**
- **Identification Intelligente des Empreintes** - Identification automatique de la pile technologique cible (CMS/Framework/WAF)
- **Planification des Chaines d'Attaque** - Recommandations de chemins d'attaque pilotees par l'IA
- **Apprentissage par Retour d'Experience** - Optimisation continue des strategies d'attaque basee sur l'historique
- **Selection Automatique des Payloads** - Selection/mutation intelligente des Payloads selon le type de WAF
- **Generation PoC par IA** - Generation automatique de code d'exploitation basee sur les descriptions CVE

</td>
<td width="50%">

**Automatisation Bout en Bout**
- **Pipeline de Reconnaissance en 10 Phases** - DNS/Ports/Empreintes/WAF/Sous-domaines/Repertoires/Analyse JS
- **Decouverte et Verification des Vulnerabilites** - Scan automatise + verification OOB pour reduire les faux positifs
- **Orchestration Intelligente de l'Exploitation** - Moteur de boucle de retroaction + nouvelles tentatives automatiques en cas d'echec
- **Rapports Professionnels en Un Clic** - Sortie multi-format JSON/HTML/Markdown
- **Reprise de Session Apres Interruption** - Prise en charge de la recuperation apres interruption, sans perte de progression

</td>
</tr>
<tr>
<td width="50%">

**Chaine d'Outils Red Team**
- **Mouvement Lateral** - 5 protocoles SMB/SSH/WMI/WinRM/PSExec
- **Communication C2** - Beacon + tunnels DNS/HTTP/WebSocket/ICMP
- **Obfuscation et Evasion** - Encodeurs XOR/AES/Base64/personnalises
- **Persistance** - Registre Windows/Taches planifiees/WMI/Linux cron/Webshell
- **Obtention de Credentials** - Extraction memoire/Recherche de fichiers/Password spraying
- **Attaques AD** - Kerberoasting/AS-REP Roasting/Scan SPN

</td>
<td width="50%">

**Extension des Capacites de Securite**
- **Securite API** - Tests JWT/CORS/GraphQL/WebSocket/OAuth
- **Securite de la Chaine d'Approvisionnement** - Generation SBOM/Audit des dependances/Scan securite CI-CD
- **Securite Cloud Native** - K8s RBAC/Securite Pod/gRPC/Audit configuration AWS
- **Intelligence CVE** - Synchronisation multi-sources NVD/Nuclei/ExploitDB
- **Contournement WAF** - 2000+ Payloads + 30+ methodes d'encodage avec mutation intelligente

</td>
</tr>
</table>

---

## Matrice de Couverture ATT&CK

| Phase Tactique | Techniques Couvertes | Nombre d'Outils | Statut |
|----------------|---------------------|-----------------|--------|
| Reconnaissance | Scan actif, Collecte passive, OSINT, Analyse JS | 12+ | ✅ |
| Developpement de Ressources | Generation de Payload, Encodage d'obfuscation, Generation PoC | 4+ | ✅ |
| Acces Initial | Exploitation de vulnerabilites Web, Exploitation CVE, Vulnerabilites API | 19+ | ✅ |
| Execution | Injection de commandes, Execution de code, Deserialisation | 5+ | ✅ |
| Persistance | Registre, Taches planifiees, Webshell, WMI | 3+ | ✅ |
| Elevation de Privileges | Contournement UAC, Impersonation de tokens, Vulnerabilites noyau | 2+ | ⚠️ |
| Evasion de Defense | Contournement AMSI, Contournement ETW, Obfuscation, Mutation du trafic | 4+ | ✅ |
| Acces aux Credentials | Extraction memoire, Recherche de fichiers, Password spraying | 2+ | ✅ |
| Decouverte | Scan reseau, Enumeration de services, Enumeration AD | 8+ | ✅ |
| Mouvement Lateral | SMB/SSH/WMI/WinRM/PSExec | 9+ | ✅ |
| Collecte | Agregation de donnees, Recherche de fichiers sensibles | 2+ | ✅ |
| Commande et Controle (C2) | Tunnels HTTP/DNS/WebSocket/ICMP | 4+ | ✅ |
| Exfiltration de Donnees | DNS/HTTP/ICMP/SMB + chiffrement AES | 4+ | ✅ |

---

## Demarrage Rapide

### Configuration Requise

| Composant | Minimum Requis | Configuration Recommandee |
|-----------|---------------|---------------------------|
| Systeme d'Exploitation | Windows 10, Ubuntu 20.04, macOS 12 | Windows 11, Ubuntu 22.04, macOS 14 |
| Python | 3.10 | 3.11 ou 3.12 |
| Memoire | 4 Go | 8 Go+ |
| Espace Disque | 500 Mo | 2 Go+ (avec base de donnees CVE) |
| Reseau | Acces Internet | Reseau faible latence |

### Methodes d'Installation

#### Methode 1 : Installation Standard (Recommandee)

```bash
# 1. Cloner le depot
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. Creer un environnement virtuel (recommande)
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 3. Installer les dependances
pip install -r requirements.txt

# 4. Copier le modele de variables d'environnement
cp .env.example .env
# Editer .env pour ajouter vos cles API

# 5. Demarrer le service
python mcp_stdio_server.py
```

#### Methode 2 : Installation Minimale (Fonctionnalites de Base Uniquement)

```bash
# Installer uniquement les dependances de base (reconnaissance + detection de vulnerabilites)
pip install -r requirements-core.txt
```

#### Methode 3 : Deploiement Docker

```bash
docker pull coff0xc/autoredteam:latest
docker run -it --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  coff0xc/autoredteam
```

#### Methode 4 : Environnement de Developpement

```bash
# Installer les dependances de developpement (tests, formatage, lint)
pip install -r requirements-dev.txt

# Installer les hooks pre-commit
pre-commit install
```

### Verification de l'Installation

```bash
# Verifier la version
python mcp_stdio_server.py --version
# Sortie: AutoRedTeam-Orchestrator v3.0.1

# Executer l'auto-verification
python -c "from core import __version__; print(f'Version Core: {__version__}')"

# Executer les tests (environnement de developpement)
pytest tests/ -v --tb=short
```

---

## Configuration MCP

Ajoutez la configuration suivante au fichier de configuration MCP de votre editeur IA :

### Emplacement des Fichiers de Configuration

| Editeur | Chemin du Fichier de Configuration |
|---------|-----------------------------------|
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Kiro | `~/.kiro/mcp.json` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| VS Code (Extension MCP) | `.vscode/mcp.json` |

### Exemples de Configuration

<details>
<summary><b>Cursor</b> - <code>~/.cursor/mcp.json</code></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/chemin/absolu/vers/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
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
      "args": ["/chemin/absolu/vers/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONPATH": "/chemin/absolu/vers/AutoRedTeam-Orchestrator"
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
      "args": ["/chemin/absolu/vers/AutoRedTeam-Orchestrator/mcp_stdio_server.py"]
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
      "args": ["/chemin/absolu/vers/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Exemple de Chemin Windows</b></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["C:\\Users\\VotreNom\\AutoRedTeam-Orchestrator\\mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

---

## Matrice des Outils (100+ Outils MCP)

| Categorie | Nombre | Outils Cles | Description |
|-----------|--------|-------------|-------------|
| **Reconnaissance** | 8 | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` `dir_scan` `dns_lookup` `tech_detect` | Collecte d'informations et decouverte d'actifs |
| **Detection de Vulnerabilites** | 11 | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` `idor_scan` `path_traversal_scan` `cors_scan` `security_headers_scan` | OWASP Top 10 + Vulnerabilites logiques |
| **Securite API** | 7 | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` `cors_deep_scan` `security_headers_score` | Tests de securite API modernes |
| **Chaine d'Approvisionnement** | 3 | `sbom_generate` `dependency_audit` `cicd_scan` | Securite SBOM/Dependances/CI-CD |
| **Cloud Native** | 3 | `k8s_scan` `grpc_scan` `aws_scan` | Audit securite K8s/gRPC/AWS |
| **Noyau Red Team** | 14 | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` `payload_obfuscate` | Post-exploitation et reseau interne |
| **Mouvement Lateral** | 9 | `lateral_ssh` `lateral_wmi` `lateral_winrm` `lateral_psexec` `lateral_ssh_tunnel` | Mouvement lateral sur 5 protocoles |
| **Persistance** | 3 | `persistence_windows` `persistence_linux` `persistence_webshell` | Windows/Linux/Web |
| **Attaques AD** | 3 | `ad_enumerate` `ad_kerberos_attack` `ad_spn_scan` | Suite complete de penetration de domaine |
| **CVE** | 8 | `cve_search` `cve_sync` `cve_stats` `poc_execute` `poc_list` `cve_auto_exploit` `cve_exploit_with_desc` `cve_generate_poc` | Intelligence CVE + PoC IA |
| **Orchestration** | 11 | `auto_pentest` `pentest_resume` `pentest_status` `pentest_phase` `smart_analyze` `attack_chain_plan` | Tests de penetration automatises |
| **Outils Externes** | 8 | `ext_nmap_scan` `ext_nuclei_scan` `ext_sqlmap_scan` `ext_ffuf_fuzz` `ext_masscan_scan` `ext_tool_chain` `ext_tools_status` | Integration d'outils professionnels |
| **Assistance IA** | 3 | `smart_payload` `ai_attack_chain` `smart_pentest` | Analyse et decision intelligentes |
| **Session/Rapports** | 9 | `session_create` `session_status` `session_list` `session_complete` `generate_report` `export_findings` | Gestion des sessions + Rapports |

---

## Integration des Outils Externes

Prise en charge de l'integration d'outils de securite professionnels installes localement pour des capacites de detection plus approfondies :

| Outil | Utilisation | Commande MCP | Prerequis d'Installation |
|-------|-------------|--------------|-------------------------|
| **Nmap** | Scan de ports + Identification de services + Scripts NSE | `ext_nmap_scan` | PATH systeme ou chemin configure |
| **Nuclei** | 7000+ modeles de scan CVE/vulnerabilites | `ext_nuclei_scan` | Compilation Go ou binaire telecharge |
| **SQLMap** | 6 techniques d'injection SQL + Contournement WAF | `ext_sqlmap_scan` | Script Python |
| **ffuf** | Fuzzing haute vitesse de repertoires/parametres | `ext_ffuf_fuzz` | Compilation Go ou binaire telecharge |
| **Masscan** | Scan de ports a grande echelle ultra-rapide | `ext_masscan_scan` | Necessite droits root/administrateur |

### Configuration des Outils Externes

Editez `config/external_tools.yaml` :

```yaml
# Repertoire de base des outils
base_path: "/chemin/vers/vos/outils-securite"

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

# Configuration des chaines d'outils
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

### Orchestration des Chaines d'Outils

```bash
# Chaine de reconnaissance complete: decouverte rapide masscan -> identification detaillee nmap
ext_tool_chain target="192.168.1.0/24" chain_name="full_recon"

# Chaine de scan de vulnerabilites: detection combinee nuclei + sqlmap
ext_tool_chain target="https://example.com" chain_name="vuln_scan"

# Verifier le statut des outils externes
ext_tools_status
```

---

## Exemples d'Utilisation

### Utilisation en Ligne de Commande

Appelez directement par conversation dans votre editeur IA :

#### Reconnaissance et Collecte d'Informations

```
# Reconnaissance complete
"Effectuer une reconnaissance complete sur example.com et generer un rapport"

# Scan de ports
"Scanner les ports ouverts sur le segment reseau 192.168.1.0/24"

# Enumeration des sous-domaines
"Enumerer tous les sous-domaines de example.com"

# Identification d'empreinte
"Identifier la pile technologique et le WAF du site cible"

# Analyse JS
"Analyser les informations sensibles dans les fichiers JavaScript du site cible"
```

#### Scan de Vulnerabilites

```
# Injection SQL
"Detecter si https://target.com/api?id=1 est vulnerable a l'injection SQL"

# Scan XSS
"Scanner les vulnerabilites XSS du formulaire cible et generer un PoC"

# Securite API
"Effectuer un test de securite complet JWT/CORS/GraphQL sur l'API cible"

# Recherche et exploitation CVE
"Rechercher les CVE lies a Apache Log4j et executer un PoC"
```

#### Operations Red Team

```
# Mouvement lateral
"Executer la commande whoami sur 192.168.1.100 via SMB"

# Communication C2
"Demarrer un tunnel DNS vers c2.example.com"

# Persistance
"Etablir une persistance par tache planifiee sur la cible Windows"

# Attaque AD
"Effectuer une attaque Kerberoasting sur le controleur de domaine"
```

#### Tests de Penetration Automatises

```
# Test de penetration entierement automatise
"Effectuer un test de penetration entierement automatise sur https://target.com et generer un rapport detaille"

# Chaine d'attaque intelligente
"Analyser la cible et generer des recommandations de chaine d'attaque optimale"

# Reprise apres interruption
"Reprendre la session de test de penetration precedemment interrompue"
```

### Appels API Python

#### Utilisation de Base

```python
import asyncio
from core.recon import StandardReconEngine, ReconConfig
from core.detectors import DetectorFactory

async def main():
    # 1. Moteur de reconnaissance
    config = ReconConfig(
        quick_mode=False,
        enable_js_analysis=True,
        max_threads=50
    )
    engine = StandardReconEngine("https://target.com", config)
    recon_result = await engine.run()
    print(f"Decouverts {len(recon_result.open_ports)} ports ouverts")

    # 2. Detection de vulnerabilites
    detector = DetectorFactory.create_composite(['sqli', 'xss', 'ssrf'])
    vuln_results = await detector.async_detect(
        url="https://target.com/api",
        params={'id': '1'}
    )

    for vuln in vuln_results:
        print(f"Vulnerabilite decouverte: {vuln.type} - {vuln.severity}")

asyncio.run(main())
```

#### Mouvement Lateral

```python
from core.lateral import SMBLateralMove, SSHLateralMove

# Mouvement lateral SMB
smb = SMBLateralMove(
    target="192.168.1.100",
    credential={"username": "admin", "password_hash": "aad3b435..."}
)
result = await smb.execute_command("whoami")

# Tunnel SSH
ssh = SSHLateralMove(
    target="192.168.1.100",
    credential={"username": "root", "private_key_path": "/chemin/vers/cle"}
)
await ssh.create_tunnel(local_port=8080, remote_port=80)
```

#### Exploitation Automatique CVE

```python
from core.cve import CVEAutoExploit

exploit = CVEAutoExploit()

# Rechercher et exploiter
results = await exploit.search_and_exploit(
    cve_id="CVE-2021-44228",
    target="https://target.com"
)

# Generer un PoC par IA
poc_code = await exploit.generate_poc(
    cve_id="CVE-2024-12345",
    target_info={"os": "linux", "service": "nginx"}
)
```

#### Gestion des Sessions

```python
from core.session import SessionManager

manager = SessionManager()

# Creer une session
session_id = await manager.create_session(
    target="https://target.com",
    scan_type="full_pentest"
)

# Reprendre une session
await manager.resume_session(session_id)

# Exporter les resultats
await manager.export_findings(session_id, format="html")
```

---

## Architecture

```
AutoRedTeam-Orchestrator/
├── mcp_stdio_server.py       # Point d'entree du serveur MCP (100+ outils enregistres)
│
├── handlers/                 # Gestionnaires d'outils MCP (16 modules)
│   ├── recon_handlers.py           # Outils de reconnaissance (8)
│   ├── detector_handlers.py        # Outils de detection de vulnerabilites (11)
│   ├── api_security_handlers.py    # Outils de securite API (7)
│   ├── supply_chain_handlers.py    # Outils de securite chaine d'approvisionnement (3)
│   ├── cloud_security_handlers.py  # Outils de securite cloud (3)
│   ├── cve_handlers.py             # Outils CVE (8)
│   ├── redteam_handlers.py         # Outils noyau Red Team (14)
│   ├── lateral_handlers.py         # Outils de mouvement lateral (9)
│   ├── persistence_handlers.py     # Outils de persistance (3)
│   ├── ad_handlers.py              # Outils d'attaque AD (3)
│   ├── orchestration_handlers.py   # Outils d'orchestration (11)
│   ├── external_tools_handlers.py  # Outils externes (8)
│   ├── ai_handlers.py              # Outils d'assistance IA (3)
│   ├── session_handlers.py         # Outils de session (4)
│   ├── report_handlers.py          # Outils de rapport (2)
│   └── misc_handlers.py            # Outils divers (3)
│
├── core/                     # Moteurs principaux
│   ├── recon/               # Moteur de reconnaissance (pipeline 10 phases)
│   │   ├── engine.py        # StandardReconEngine
│   │   ├── phases.py        # Definitions des phases
│   │   ├── port_scanner.py  # Scan de ports
│   │   ├── subdomain.py     # Enumeration des sous-domaines
│   │   ├── fingerprint.py   # Identification d'empreinte
│   │   ├── waf_detect.py    # Detection WAF
│   │   └── directory.py     # Scan de repertoires
│   │
│   ├── detectors/           # Detecteurs de vulnerabilites
│   │   ├── base.py          # Classe de base + Pattern composite
│   │   ├── sqli.py          # Injection SQL
│   │   ├── xss.py           # XSS
│   │   ├── ssrf.py          # SSRF
│   │   └── ...
│   │
│   ├── cve/                 # Intelligence CVE
│   │   ├── manager.py       # Gestionnaire de base de donnees CVE
│   │   ├── poc_engine.py    # Moteur de templates PoC
│   │   ├── auto_exploit.py  # Exploitation automatique
│   │   ├── ai_poc_generator.py  # Generateur PoC IA
│   │   └── update_manager.py    # Synchronisation multi-sources
│   │
│   ├── c2/                  # Framework de communication C2
│   │   ├── beacon.py        # Implementation Beacon
│   │   ├── protocol.py      # Definition du protocole
│   │   └── tunnels/         # Tunnels DNS/HTTP/WS/ICMP
│   │
│   ├── lateral/             # Mouvement lateral
│   │   ├── smb.py           # SMB (PTH/PTT)
│   │   ├── ssh.py           # SSH + SFTP
│   │   ├── wmi.py           # WMI
│   │   ├── winrm.py         # WinRM
│   │   └── psexec.py        # PSExec
│   │
│   ├── evasion/             # Evasion et obfuscation
│   │   └── payload_obfuscator.py
│   │
│   ├── persistence/         # Persistance
│   │   ├── windows_persistence.py
│   │   ├── linux_persistence.py
│   │   └── webshell_manager.py
│   │
│   ├── credential/          # Obtention de credentials
│   ├── ad/                  # Attaques AD
│   ├── session/             # Gestion des sessions
│   ├── tools/               # Gestion des outils externes
│   └── security/            # Composants de securite
│
├── modules/                  # Modules fonctionnels
│   ├── api_security/        # Securite API
│   │   ├── jwt_security.py
│   │   ├── cors_security.py
│   │   ├── graphql_security.py
│   │   └── websocket_security.py
│   │
│   ├── supply_chain/        # Securite chaine d'approvisionnement
│   │   ├── sbom_generator.py
│   │   ├── dependency_scanner.py
│   │   └── cicd_security.py
│   │
│   ├── cloud_security/      # Securite cloud
│   │   ├── kubernetes_enhanced.py
│   │   └── aws_tools.py
│   │
│   └── payload/             # Moteur de Payload
│       ├── library.py       # 2000+ Payloads
│       └── smart.py         # Selection intelligente
│
├── utils/                    # Fonctions utilitaires
│   ├── logger.py            # Journalisation
│   ├── http_client.py       # Client HTTP
│   ├── validators.py        # Validation des entrees
│   ├── report_generator.py  # Generation de rapports
│   └── config.py            # Gestion de la configuration
│
├── wordlists/                # Dictionnaires integres
│   ├── directories/         # Dictionnaires de repertoires
│   ├── passwords/           # Dictionnaires de mots de passe
│   ├── usernames/           # Dictionnaires de noms d'utilisateur
│   └── subdomains/          # Dictionnaires de sous-domaines
│
├── config/                   # Fichiers de configuration
│   └── external_tools.yaml  # Configuration des outils externes
│
├── tests/                    # Suite de tests (1075 cas de test)
└── docs/                     # Documentation
```

---

## Configuration

### Variables d'Environnement (.env)

```bash
# ========== Configuration de Securite ==========
# Cle principale (generee automatiquement au premier lancement)
REDTEAM_MASTER_KEY=

# Cle d'autorisation MCP (optionnelle)
AUTOREDTEAM_API_KEY=

# Mode d'autorisation: strict, permissive, disabled
AUTOREDTEAM_AUTH_MODE=permissive

# ========== Cles API ==========
# Analyse IA
OPENAI_API_KEY=votre_cle
ANTHROPIC_API_KEY=votre_cle

# Reconnaissance
SHODAN_API_KEY=votre_cle
CENSYS_API_ID=votre_id
CENSYS_API_SECRET=votre_secret

# Intelligence CVE
NVD_API_KEY=votre_cle
GITHUB_TOKEN=votre_token

# ========== Configuration Proxy ==========
HTTP_PROXY=
HTTPS_PROXY=
SOCKS_PROXY=

# ========== Configuration Globale ==========
VERIFY_SSL=false
RATE_LIMIT_DELAY=0.3
MAX_THREADS=50
REQUEST_TIMEOUT=10

# ========== Journalisation ==========
LOG_LEVEL=INFO
LOG_FILE=logs/redteam.log
```

### Dependances Optionnelles pyproject.toml

```bash
# Installer uniquement des fonctionnalites specifiques
pip install autoredteam-orchestrator[ai]        # Fonctionnalites IA
pip install autoredteam-orchestrator[recon]     # Fonctionnalites de reconnaissance
pip install autoredteam-orchestrator[network]   # Fonctionnalites reseau
pip install autoredteam-orchestrator[reporting] # Fonctionnalites de rapport
pip install autoredteam-orchestrator[dev]       # Dependances de developpement
```

---

## Optimisation des Performances

### Configuration de la Concurrence

```yaml
# config/performance.yaml
concurrency:
  max_threads: 100          # Nombre maximum de threads
  max_async_tasks: 200      # Nombre maximum de taches asynchrones
  connection_pool_size: 50  # Taille du pool de connexions

rate_limiting:
  requests_per_second: 50   # Requetes par seconde
  burst_size: 100           # Nombre de requetes en rafale

timeouts:
  connect: 5                # Timeout de connexion (secondes)
  read: 30                  # Timeout de lecture
  total: 120                # Timeout total
```

### Optimisation de la Memoire

```python
# Utiliser le traitement en flux pour les scans a grande echelle
engine = StandardReconEngine(
    target="192.168.0.0/16",
    config=ReconConfig(
        streaming_mode=True,    # Activer le traitement en flux
        batch_size=1000,        # Taille du lot
        memory_limit="2GB"      # Limite de memoire
    )
)
```

### Scan Distribue

```python
# Utiliser la file de taches distribuee Celery
from core.distributed import DistributedScanner

scanner = DistributedScanner(
    broker="redis://localhost:6379",
    workers=10
)
await scanner.scan_targets(["192.168.1.0/24", "192.168.2.0/24"])
```

---

## Depannage

### Problemes Courants

| Probleme | Cause | Solution |
|----------|-------|----------|
| Le serveur MCP ne peut pas se connecter | Chemin incorrect ou probleme d'environnement Python | Verifier le chemin absolu dans la configuration, s'assurer d'utiliser le bon interpreteur Python |
| Erreurs d'importation | PYTHONPATH non defini | Ajouter la variable d'environnement `PYTHONPATH` dans la configuration |
| Echec de l'appel des outils externes | Outil non installe ou chemin incorrect | Executer `ext_tools_status` pour verifier le statut des outils |
| Echec de synchronisation de la base CVE | Probleme reseau ou limitation de debit API | Verifier le reseau, configurer NVD_API_KEY pour augmenter la limite |
| Scan lent | Configuration de concurrence trop faible | Ajuster `MAX_THREADS` et `RATE_LIMIT_DELAY` |
| Depassement de memoire | Scan a grande echelle | Activer `streaming_mode`, definir `memory_limit` |

### Mode Debogage

```bash
# Activer les logs detailles
LOG_LEVEL=DEBUG python mcp_stdio_server.py

# Verifier les erreurs de syntaxe
python -m py_compile mcp_stdio_server.py

# Executer un seul test
pytest tests/test_recon.py::test_port_scan -v
```

### Analyse des Logs

```bash
# Voir les erreurs recentes
tail -f logs/redteam.log | grep ERROR

# Analyser les goulots d'etranglement de performance
grep "elapsed" logs/redteam.log | sort -t: -k4 -n
```

---

## Questions Frequentes (FAQ)

<details>
<summary><b>Q: Comment utiliser dans un environnement sans reseau ?</b></summary>

R:
1. Telecharger prealablement la base de donnees CVE: `python core/cve/update_manager.py sync --offline-export`
2. Utiliser les fichiers de dictionnaire locaux
3. Desactiver les fonctionnalites necessitant le reseau: `OFFLINE_MODE=true`

</details>

<details>
<summary><b>Q: Comment ajouter un detecteur personnalise ?</b></summary>

R:
1. Creer un nouveau fichier dans `core/detectors/`
2. Heriter de la classe `BaseDetector`
3. Implementer les methodes `detect()` et `async_detect()`
4. Enregistrer l'outil MCP dans `handlers/detector_handlers.py`

```python
from core.detectors.base import BaseDetector

class CustomDetector(BaseDetector):
    async def async_detect(self, url, params):
        # Implementer la logique de detection
        return VulnResult(...)
```

</details>

<details>
<summary><b>Q: Comment integrer d'autres outils externes ?</b></summary>

R:
1. Ajouter la configuration de l'outil dans `config/external_tools.yaml`
2. Ajouter la fonction d'outil MCP dans `handlers/external_tools_handlers.py`
3. Utiliser la methode `execute_tool()` de `core/tools/tool_manager.py`

</details>

<details>
<summary><b>Q: Comment gerer le blocage par WAF ?</b></summary>

R:
1. Utiliser l'outil `smart_payload` pour selectionner automatiquement les Payloads de contournement WAF
2. Configurer un pool de proxies: `PROXY_POOL=true`
3. Activer la mutation du trafic: `traffic_mutation=true`
4. Reduire la vitesse de scan: `RATE_LIMIT_DELAY=1.0`

</details>

<details>
<summary><b>Q: Quels formats de rapport sont pris en charge ?</b></summary>

R:
- JSON (lisible par machine)
- HTML (rapport visuel avec graphiques)
- Markdown (adapte pour Git/Wiki)
- PDF (necessite l'installation de `reportlab`)
- DOCX (necessite l'installation de `python-docx`)

</details>

---

## Journal des Modifications

### v3.0.1 (2026-01-30) - Renforcement de la Qualite

**Nouveautes**
- Amelioration de l'exploitation automatique CVE (`cve_auto_exploit`, `cve_exploit_with_desc`, `cve_generate_poc`)
- Generateur PoC IA (`core/cve/ai_poc_generator.py`)

**Corrections**
- Unification des numeros de version - Synchronisation complete VERSION/pyproject.toml/code source
- Correction ToolCounter - Ajout des categories external_tools/lateral/persistence/ad
- Correction des tests - Mise a jour des references de tests obsoletes
- Securite des threads - Ajout de threading.Lock pour la gestion d'etat de beacon.py

**Ameliorations**
- Renforcement CI/CD - L'echec de la verification lint bloque maintenant le build
- Seuil de couverture de test augmente a 50%
- Contraintes de version des dependances - Ajout de bornes superieures pour eviter les problemes de compatibilite

### v3.0.0 (2026-01-18) - Amelioration de l'Architecture

**Nouveautes**
- Integration des outils externes - 8 commandes MCP pour outils externes
- Orchestration des chaines d'outils - Combinaison multi-outils pilotee par YAML
- Modularisation des Handlers - 16 modules Handler independants

**Ameliorations**
- Nombre d'outils MCP atteint 100+
- Moteur de boucle de retroaction - Orchestrateur d'exploitation intelligent
- Contournement WAF - Moteur de mutation de Payload ameliore

<details>
<summary><b>Voir plus de versions</b></summary>

### v2.8.0 (2026-01-15) - Renforcement de la Securite
- Amelioration de la validation des entrees, unification de la gestion des exceptions, optimisation des performances

### v2.7.1 (2026-01-10) - Moteur de Scan Web
- Module Web Scanner, bibliotheque de dictionnaires integree

### v2.7.0 (2026-01-09) - Refactorisation de l'Architecture
- Refactorisation modulaire, StandardReconEngine

### v2.6.0 (2026-01-07) - API/Chaine d'Approvisionnement/Securite Cloud
- Tests de securite JWT/CORS/GraphQL/WebSocket
- Generation SBOM, audit de securite K8s/gRPC

</details>

---

## Feuille de Route

### En Cours
- [ ] Interface Web de gestion
- [ ] Cluster de scan distribue

### Planifie
- [ ] Support de plus de plateformes cloud (GCP/Alibaba Cloud/Tencent Cloud)
- [ ] Integration du plugin Burp Suite
- [ ] Tests de securite des applications mobiles
- [ ] Agent d'attaque autonome IA

### Complete
- [x] Chaine d'outils Red Team complete
- [x] Intelligence CVE et generation PoC IA
- [x] Modules API/Chaine d'Approvisionnement/Securite Cloud
- [x] Framework de test de penetration entierement automatise
- [x] Integration des outils externes

---

## Guide de Contribution

Nous accueillons toute forme de contribution !

### Demarrage Rapide

```bash
# 1. Fork et cloner
git clone https://github.com/VOTRE_NOM/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. Creer une branche
git checkout -b feature/votre-fonctionnalite

# 3. Installer les dependances de developpement
pip install -r requirements-dev.txt
pre-commit install

# 4. Developper et tester
pytest tests/ -v

# 5. Soumettre une PR
git push origin feature/votre-fonctionnalite
```

### Convention de Commits

Utilisez le format [Conventional Commits](https://www.conventionalcommits.org/) :

- `feat:` Nouvelle fonctionnalite
- `fix:` Correction de bug
- `docs:` Mise a jour de documentation
- `refactor:` Refactorisation
- `test:` Relatif aux tests
- `chore:` Build/Outils

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour plus de details

---

## Politique de Securite

- **Divulgation Responsable** : Pour signaler une vulnerabilite de securite, contactez [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com)
- **Utilisation Autorisee** : Cet outil est destine uniquement aux tests de securite et a la recherche autorises
- **Declaration de Conformite** : Assurez-vous de respecter les lois et reglementations locales avant utilisation

Voir [SECURITY.md](SECURITY.md) pour plus de details

---

## Remerciements

- [Nuclei](https://github.com/projectdiscovery/nuclei) - Conception du moteur de scan de vulnerabilites
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - Approche de detection d'injection SQL
- [Impacket](https://github.com/fortra/impacket) - Implementation des protocoles reseau
- [MCP Protocol](https://modelcontextprotocol.io/) - Standard de protocole d'outils IA

---

## Licence

Ce projet est sous licence **MIT** - voir le fichier [LICENSE](LICENSE) pour plus de details

---

## Avertissement

> **Attention** : Cet outil est destine uniquement aux **tests de securite et a la recherche autorises**.
>
> Avant d'utiliser cet outil pour tester tout systeme, assurez-vous de :
> - Avoir obtenu une **autorisation ecrite** du proprietaire du systeme cible
> - Respecter les **lois et reglementations** locales
> - Adherer aux standards **d'ethique professionnelle**
>
> L'utilisation non autorisee de cet outil peut etre illegale. **Les developpeurs declinent toute responsabilite en cas d'utilisation abusive**.

---

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Coff0xc">Coff0xc</a></b>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB">Discord</a> ·
  <a href="mailto:Coff0xc@protonmail.com">Email</a> ·
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues">Issues</a>
</p>
