<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>Framework d'Orchestration Red Team Automatisé Piloté par l'IA</b><br>
  <sub>Multiplateforme | 101 Outils MCP | 2000+ Payloads | Couverture ATT&CK Complète | Graphe de Connaissances</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md">Русский</a> ·
  <a href="README_DE.md">Deutsch</a> ·
  <a href="README_FR.md"><b>Français</b></a>
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
  <img src="https://img.shields.io/badge/Outils-101-FF6B6B?style=flat-square" alt="Outils">
  <img src="https://img.shields.io/badge/Tests-1461-4CAF50?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/Licence-MIT-green?style=flat-square" alt="Licence">
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Communauté-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-Documentation-blue?style=flat-square&logo=gitbook&logoColor=white" alt="Wiki"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/actions"><img src="https://img.shields.io/github/actions/workflow/status/Coff0xc/AutoRedTeam-Orchestrator/ci.yml?style=flat-square&logo=github-actions&logoColor=white&label=CI" alt="CI"></a>
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/demo.gif" alt="Démonstration" width="700">
</p>

## Points Forts

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     AutoRedTeam-Orchestrator v3.0.1                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  ● 101 Outils MCP      ● 2000+ Payloads      ● 1461 Cas de Test             │
│  ● Recon 10 Phases     ● 19 Détecteurs Vuln  ● Latéral 5 Protocoles         │
│  ● Planificateur MCTS  ● Graphe Connaiss.    ● Génération PoC IA            │
│  ● Vérif. Faux Positif ● Conteneur DI        ● Middleware Sécurité MCP      │
├─────────────────────────────────────────────────────────────────────────────┤
│  Éditeurs IA Supportés: Cursor | Windsurf | Kiro | Claude Desktop | VS Code │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Table des Matières

- [Présentation du Projet](#présentation-du-projet)
- [Fonctionnalités Principales](#fonctionnalités-principales)
- [Philosophie de Conception](#philosophie-de-conception)
- [Architecture](#architecture)
- [Matrice de Couverture ATT&CK](#matrice-de-couverture-attck)
- [Démarrage Rapide](#démarrage-rapide)
  - [Configuration Requise](#configuration-requise)
  - [Méthodes d'Installation](#méthodes-dinstallation)
  - [Vérification de l'Installation](#vérification-de-linstallation)
- [Configuration MCP](#configuration-mcp)
- [Matrice des Outils (101 Outils MCP)](#matrice-des-outils-101-outils-mcp)
- [Modules Principaux](#modules-principaux)
- [Intégration des Outils Externes](#intégration-des-outils-externes)
- [Exemples d'Utilisation](#exemples-dutilisation)
  - [Commandes en Langage Naturel](#commandes-en-langage-naturel)
  - [API Python](#api-python)
- [Configuration](#configuration)
- [Optimisation des Performances](#optimisation-des-performances)
- [Dépannage](#dépannage)
- [Questions Fréquentes (FAQ)](#questions-fréquentes-faq)
- [Guide de Développement](#guide-de-développement)
- [Journal des Modifications](#journal-des-modifications)
- [Feuille de Route](#feuille-de-route)
- [Guide de Contribution](#guide-de-contribution)
- [Politique de Sécurité](#politique-de-sécurité)
- [Remerciements](#remerciements)
- [Licence](#licence)
- [Avertissement](#avertissement)

---

## Présentation du Projet

**AutoRedTeam-Orchestrator** est un framework de tests de pénétration automatisés piloté par l'IA, basé sur le [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). Il encapsule 101 outils de sécurité en tant qu'outils MCP, permettant une intégration transparente avec les éditeurs IA compatibles MCP (Cursor, Windsurf, Kiro, Claude Desktop) pour des tests de sécurité automatisés pilotés par le langage naturel.

### Pourquoi Choisir AutoRedTeam-Orchestrator ?

| Caractéristique | Outils Traditionnels | AutoRedTeam |
|-----------------|---------------------|-------------|
| **Mode d'Interaction** | Mémorisation en ligne de commande | Conversation en langage naturel |
| **Courbe d'Apprentissage** | Élevée (nombreux paramètres à mémoriser) | Faible (l'IA sélectionne automatiquement les outils) |
| **Intégration des Outils** | Changement manuel d'outils | Interface unifiée pour 101 outils |
| **Planification d'Attaque** | Manuelle | **Algorithme MCTS + Graphe de Connaissances** |
| **Réduction Faux Positifs** | Vérification manuelle | **Vérification OOB + Statistique** |
| **Génération de Rapports** | Rédaction manuelle | Rapports professionnels en un clic |
| **Gestion des Sessions** | Aucune | Support de reprise après interruption |
| **Sécurité** | Par outil | **Middleware Sécurité MCP protection unifiée** |

### Comparaison avec les Projets Similaires

| Caractéristique | AutoRedTeam | Nuclei | SQLMap | Metasploit |
|-----------------|-------------|--------|--------|------------|
| IA Native | ✅ | ❌ | ❌ | ❌ |
| Protocole MCP | ✅ | ❌ | ❌ | ❌ |
| Langage Naturel | ✅ | ❌ | ❌ | ❌ |
| Planification MCTS | ✅ | ❌ | ❌ | ❌ |
| Graphe de Connaissances | ✅ | ❌ | ❌ | ❌ |
| Automatisation Complète | ✅ | Partielle | Partielle | Partielle |
| Filtre Faux Positifs | Multi-méthodes | Basique | Moyen | Basique |

---

## Fonctionnalités Principales

<table>
<tr>
<td width="50%">

### Conception Native IA

- **Identification Intelligente des Empreintes** - Identification automatique de la pile technologique cible (CMS/Framework/WAF)
- **Planification d'Attaque MCTS** - Chemins d'attaque optimaux pilotés par Monte Carlo Tree Search
- **Graphe de Connaissances** - Connaissances d'attaque persistantes avec apprentissage inter-sessions
- **Apprentissage par Retour d'Expérience** - Optimisation continue des stratégies d'attaque
- **Sélection Automatique des Payloads** - Mutation intelligente consciente du WAF
- **Génération PoC par IA** - Génération de code d'exploitation à partir des descriptions CVE

</td>
<td width="50%">

### Automatisation Complète

- **Pipeline de Reconnaissance 10 Phases** - DNS/Ports/Empreintes/WAF/Sous-domaines/Répertoires/Analyse JS
- **Découverte et Vérification des Vulnérabilités** - Scan automatisé + **validation multi-méthodes**
- **Orchestration Intelligente de l'Exploitation** - Moteur de boucle de rétroaction + nouvelles tentatives automatiques
- **Rapports Professionnels en Un Clic** - Formats JSON/HTML/Markdown
- **Reprise de Session Après Interruption** - Récupération des scans interrompus

</td>
</tr>
<tr>
<td width="50%">

### Chaîne d'Outils Red Team

- **Mouvement Latéral** - SMB/SSH/WMI/WinRM/PSExec (5 protocoles)
- **Communication C2** - Beacon + tunnels DNS/HTTP/WebSocket/ICMP
- **Évasion et Obfuscation** - Encodeurs XOR/AES/Base64/personnalisés
- **Persistance** - Registre Windows/Tâches planifiées/WMI/Linux cron/Webshell
- **Accès aux Credentials** - Extraction mémoire/Recherche de fichiers/Password spray
- **Attaques AD** - Kerberoasting/AS-REP Roasting/Scan SPN

</td>
<td width="50%">

### Extensions de Sécurité

- **Sécurité API** - Tests JWT/CORS/GraphQL/WebSocket/OAuth
- **Sécurité Chaîne d'Approvisionnement** - Génération SBOM/Audit dépendances/Scan CI-CD
- **Sécurité Cloud Native** - K8s RBAC/Sécurité Pod/gRPC/Audit AWS
- **Intelligence CVE** - Synchronisation multi-sources NVD/Nuclei/ExploitDB
- **Contournement WAF** - 2000+ payloads + 30+ méthodes d'encodage

</td>
</tr>
</table>

---

## Philosophie de Conception

### Principes de Conception Fondamentaux

```
┌────────────────────────────────────────────────────────────────────────────┐
│                         Philosophie de Conception                          │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│   1. IA Native                                                             │
│      └─ Pas un "wrapper IA", mais architecturé pour l'IA                   │
│         └─ Support natif du protocole MCP                                  │
│         └─ Sélection d'outils pilotée par langage naturel                  │
│         └─ Planification d'attaque pilotée par algorithme MCTS             │
│                                                                            │
│   2. Sécurité Vérifiable                                                   │
│      └─ Validation croisée multi-méthodes pour réduire les faux positifs   │
│         └─ Vérification statistique (tests de significativité)             │
│         └─ Vérification aveugle booléenne (comparaison True/False)         │
│         └─ Vérification aveugle temporelle (détection de délai)            │
│         └─ Vérification OOB (callback DNS/HTTP)                            │
│                                                                            │
│   3. Persistance des Connaissances                                         │
│      └─ Connaissances d'attaque persistantes entre sessions                │
│         └─ Graphe stockant cible, vuln, relations credentials              │
│         └─ Taux de succès des chemins calculés depuis l'historique         │
│         └─ Identification de cibles similaires accélère nouveaux tests     │
│                                                                            │
│   4. Sécurité par Conception                                               │
│      └─ La sécurité est l'architecture principale, pas un ajout            │
│         └─ Middleware Sécurité MCP: validation entrée, limitation débit    │
│         └─ Sécurité TOCTOU: opérations atomiques, protection race          │
│         └─ Sécurité Mémoire: limites ressources, nettoyage auto            │
│                                                                            │
│   5. Architecture Extensible                                               │
│      └─ Conteneur d'injection de dépendances pour composition flexible     │
│         └─ Conception Handler modulaire                                    │
│         └─ Configuration YAML des outils externes                          │
│         └─ Pattern composite détecteur pour combinaisons arbitraires       │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### Matrice de Décisions Techniques

| Décision | Options | Choix | Justification |
|----------|---------|-------|---------------|
| **Communication** | REST / gRPC / MCP | MCP | Support natif éditeur IA, interaction NLP transparente |
| **Planification Attaque** | Moteur Règles / MCTS / RL | MCTS | Planification en ligne, pas de pré-entraînement, exploration-exploitation UCB1 |
| **Stockage Connaissances** | SQL / Graph DB / Mémoire | Graphe Mémoire + Neo4j Optionnel | Démarrage sans dépendance, requêtes haute perf, persistance optionnelle |
| **Gestion Dépendances** | Globales / DI | Conteneur DI | Testabilité, remplaçabilité, gestion cycle de vie |
| **Concurrence** | Threading / asyncio / Hybride | asyncio principal | Optimal pour IO-bound, support Python natif |
| **Hachage** | MD5 / SHA256 | SHA256 | Sécurité supérieure, standard moderne |

---

## Architecture

### Architecture Haut Niveau

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Couche Éditeur IA                                 │
│        Cursor  │  Windsurf  │  Kiro  │  Claude Desktop  │  VS Code         │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ Protocole MCP (JSON-RPC via stdio)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Point d'Entrée Serveur MCP                          │
│                      mcp_stdio_server.py                                    │
│                        (101 outils enregistrés)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                        Middleware Sécurité MCP                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Valid Entrée│  │ Limit Débit │  │ Autori Opér │  │ @secure_tool│        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│   handlers/       │   │   core/           │   │   modules/        │
│   Handlers MCP    │   │   Moteurs Core    │   │   Modules Fonct.  │
├───────────────────┤   ├───────────────────┤   ├───────────────────┤
│ • recon_handlers  │   │ • recon/          │   │ • api_security/   │
│ • detector_hdlrs  │   │   recon 10-phases │   │   JWT/CORS/GQL    │
│ • cve_handlers    │   │ • detectors/      │   │ • supply_chain/   │
│ • redteam_hdlrs   │   │   Détect vuln     │   │   SBOM/Deps       │
│ • lateral_hdlrs   │   │ • mcts_planner    │   │ • cloud_security/ │
│ • external_hdlrs  │   │   Planif MCTS     │   │   K8s/gRPC/AWS    │
│ • ai_handlers     │   │ • knowledge/      │   │ • payload/        │
│ • session_hdlrs   │   │   Graphe connais. │   │   2000+ Payloads  │
└───────────────────┘   │ • container       │   └───────────────────┘
                        │   Conteneur DI    │
                        │ • c2/             │
                        │   Comm C2         │
                        │ • lateral/        │
                        │   Mouv Latéral    │
                        │ • cve/            │
                        │   Intel CVE+PoC   │
                        └───────────────────┘
```

### Structure des Répertoires

```
AutoRedTeam-Orchestrator/
├── mcp_stdio_server.py          # Point d'entrée Serveur MCP (101 outils enregistrés)
├── VERSION                      # Fichier de version
├── pyproject.toml               # Configuration projet
├── requirements.txt             # Dépendances production
├── requirements-dev.txt         # Dépendances développement
│
├── handlers/                    # Handlers Outils MCP (16 modules)
│   ├── recon_handlers.py        # Outils reconnaissance (8)
│   ├── detector_handlers.py     # Outils détection vuln (11)
│   ├── api_security_handlers.py # Outils sécurité API (7)
│   ├── supply_chain_handlers.py # Outils chaîne approvisionnement (3)
│   ├── cloud_security_handlers.py # Outils sécurité cloud (3)
│   ├── cve_handlers.py          # Outils CVE (8)
│   ├── redteam_handlers.py      # Outils noyau Red Team (14)
│   ├── lateral_handlers.py      # Outils mouvement latéral (9)
│   ├── persistence_handlers.py  # Outils persistance (3)
│   ├── ad_handlers.py           # Outils attaque AD (3)
│   ├── orchestration_handlers.py # Outils orchestration (11)
│   ├── external_tools_handlers.py # Outils externes (8)
│   ├── ai_handlers.py           # Outils assistance IA (3)
│   ├── session_handlers.py      # Outils session (4)
│   ├── report_handlers.py       # Outils rapport (2)
│   └── misc_handlers.py         # Outils divers (3)
│
├── core/                        # Moteurs Principaux
│   ├── __init__.py              # Définition version
│   │
│   ├── security/                # Composants Sécurité ⭐ v3.0.2
│   │   └── mcp_security.py      # Middleware Sécurité MCP
│   │
│   ├── container.py             # Conteneur DI ⭐ v3.0.2
│   │
│   ├── mcts_planner.py          # Planificateur Attaque MCTS ⭐ v3.0.2
│   │
│   ├── knowledge/               # Graphe de Connaissances ⭐ v3.0.2
│   │   ├── __init__.py
│   │   ├── manager.py           # Gestionnaire Connaissances
│   │   └── models.py            # Modèles de Données
│   │
│   ├── recon/                   # Moteur Reconnaissance (pipeline 10 phases)
│   ├── detectors/               # Détecteurs de Vulnérabilités
│   ├── cve/                     # Intelligence CVE
│   ├── c2/                      # Framework Communication C2
│   ├── lateral/                 # Mouvement Latéral
│   ├── evasion/                 # Évasion et Obfuscation
│   ├── persistence/             # Mécanismes de Persistance
│   ├── credential/              # Accès aux Credentials
│   ├── ad/                      # Attaques AD
│   ├── session/                 # Gestion des Sessions
│   ├── tools/                   # Gestion Outils Externes
│   └── exfiltration/            # Exfiltration de Données
│
├── modules/                     # Modules Fonctionnels
│   ├── api_security/            # Sécurité API
│   ├── supply_chain/            # Sécurité Chaîne Approvisionnement
│   ├── cloud_security/          # Sécurité Cloud
│   └── payload/                 # Moteur de Payload
│
├── utils/                       # Fonctions Utilitaires
├── wordlists/                   # Dictionnaires Intégrés
├── config/                      # Fichiers de Configuration
├── tests/                       # Suite de Tests (1461 cas de test)
├── poc-templates/               # Templates PoC
├── templates/                   # Templates de Rapport
├── scripts/                     # Scripts Utilitaires
└── docs/                        # Documentation
```

---

## Matrice de Couverture ATT&CK

| Tactique | Techniques Couvertes | Nombre d'Outils | Statut |
|----------|---------------------|-----------------|--------|
| Reconnaissance | Scan actif, Collecte passive, OSINT, Analyse JS | 12+ | ✅ |
| Développement de Ressources | Génération Payload, Obfuscation, Génération PoC | 4+ | ✅ |
| Accès Initial | Exploitation Web, Exploits CVE, Vulnérabilités API | 19+ | ✅ |
| Exécution | Injection de commandes, Exécution de code, Désérialisation | 5+ | ✅ |
| Persistance | Registre, Tâches planifiées, Webshell, WMI | 3+ | ✅ |
| Élévation de Privilèges | Bypass UAC, Usurpation de tokens, Exploits noyau | 2+ | ⚠️ |
| Évasion de Défense | Bypass AMSI, Bypass ETW, Obfuscation, Mutation trafic | 4+ | ✅ |
| Accès aux Credentials | Extraction mémoire, Recherche fichiers, Password spray | 2+ | ✅ |
| Découverte | Scan réseau, Énumération services, Énumération AD | 8+ | ✅ |
| Mouvement Latéral | SMB/SSH/WMI/WinRM/PSExec | 9+ | ✅ |
| Collection | Agrégation données, Recherche fichiers sensibles | 2+ | ✅ |
| Commande & Contrôle | Tunnels HTTP/DNS/WebSocket/ICMP | 4+ | ✅ |
| Exfiltration | DNS/HTTP/ICMP/SMB + Chiffrement AES | 4+ | ✅ |

---

## Démarrage Rapide

### Configuration Requise

| Composant | Minimum | Recommandé |
|-----------|---------|------------|
| OS | Windows 10, Ubuntu 20.04, macOS 12 | Windows 11, Ubuntu 22.04, macOS 14 |
| Python | 3.10 | 3.11 ou 3.12 |
| Mémoire | 4 Go | 8 Go+ |
| Disque | 500 Mo | 2 Go+ (avec base de données CVE) |
| Réseau | Accès Internet | Faible latence |

### Méthodes d'Installation

#### Méthode 1 : Installation Standard (Recommandée)

```bash
# 1. Cloner le dépôt
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. Créer un environnement virtuel (recommandé)
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Copier le modèle de variables d'environnement
cp .env.example .env
# Éditer .env pour ajouter vos clés API

# 5. Démarrer le service
python mcp_stdio_server.py
```

#### Méthode 2 : Installation Minimale (Fonctionnalités de Base Uniquement)

```bash
# Installer uniquement les dépendances de base (reconnaissance + détection de vulnérabilités)
pip install -r requirements-core.txt
```

#### Méthode 3 : Déploiement Docker

```bash
docker pull coff0xc/autoredteam:latest
docker run -it --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  coff0xc/autoredteam
```

#### Méthode 4 : Environnement de Développement

```bash
# Installer les dépendances de développement (tests, formatage, lint)
pip install -r requirements-dev.txt

# Installer les hooks pre-commit
pre-commit install

# Exécuter les tests
pytest tests/ -v
```

### Vérification de l'Installation

```bash
# Vérifier la version
python mcp_stdio_server.py --version
# Sortie: AutoRedTeam-Orchestrator v3.0.1

# Exécuter l'auto-vérification
python -c "from core import __version__; print(f'Version Core: {__version__}')"

# Exécuter les tests des modules principaux
pytest tests/test_mcp_security.py tests/test_container.py tests/test_mcts_planner.py tests/test_knowledge_manager.py tests/test_advanced_verifier.py -v
# Attendu: 291+ passed
```

---

## Configuration MCP

Ajoutez la configuration suivante au fichier de configuration MCP de votre éditeur IA :

### Emplacement des Fichiers de Configuration

| Éditeur | Chemin du Fichier de Configuration |
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

## Matrice des Outils (101 Outils MCP)

| Catégorie | Nombre | Outils Clés | Description |
|-----------|--------|-------------|-------------|
| **Reconnaissance** | 8 | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` `dir_scan` `dns_lookup` `tech_detect` | Collecte d'informations et découverte d'actifs |
| **Détection de Vulnérabilités** | 11 | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` `idor_scan` `path_traversal_scan` `cors_scan` `security_headers_scan` | OWASP Top 10 + Failles logiques |
| **Sécurité API** | 7 | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` `cors_deep_scan` `security_headers_score` | Tests de sécurité API modernes |
| **Chaîne d'Approvisionnement** | 3 | `sbom_generate` `dependency_audit` `cicd_scan` | Sécurité SBOM/Dépendances/CI-CD |
| **Cloud Native** | 3 | `k8s_scan` `grpc_scan` `aws_scan` | Audit sécurité K8s/gRPC/AWS |
| **Noyau Red Team** | 14 | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` `payload_obfuscate` | Post-exploitation et réseau interne |
| **Mouvement Latéral** | 9 | `lateral_ssh` `lateral_wmi` `lateral_winrm` `lateral_psexec` `lateral_ssh_tunnel` | Mouvement latéral 5 protocoles |
| **Persistance** | 3 | `persistence_windows` `persistence_linux` `persistence_webshell` | Windows/Linux/Web |
| **Attaques AD** | 3 | `ad_enumerate` `ad_kerberos_attack` `ad_spn_scan` | Pentest domaine complet |
| **CVE** | 8 | `cve_search` `cve_sync` `cve_stats` `poc_execute` `poc_list` `cve_auto_exploit` `cve_exploit_with_desc` `cve_generate_poc` | Intelligence CVE + PoC IA |
| **Orchestration** | 11 | `auto_pentest` `pentest_resume` `pentest_status` `pentest_phase` `smart_analyze` `attack_chain_plan` | Tests de pénétration automatisés |
| **Outils Externes** | 8 | `ext_nmap_scan` `ext_nuclei_scan` `ext_sqlmap_scan` `ext_ffuf_fuzz` `ext_masscan_scan` `ext_tool_chain` `ext_tools_status` | Intégration outils professionnels |
| **Assistance IA** | 3 | `smart_payload` `ai_attack_chain` `smart_pentest` | Analyse intelligente |
| **Session/Rapports** | 9 | `session_create` `session_status` `session_list` `session_complete` `generate_report` `export_findings` | Gestion sessions + rapports |

---

## Modules Principaux

### 1. Middleware Sécurité MCP (v3.0.2)

**Emplacement**: `core/security/mcp_security.py`

Fournit une couche de protection sécurité unifiée pour tous les appels d'outils MCP :

```python
from core.security.mcp_security import MCPSecurityMiddleware, RateLimitConfig

security = MCPSecurityMiddleware(
    rate_limit_config=RateLimitConfig(
        requests_per_minute=60,
        burst_limit=10,
    ),
    max_risk=RiskLevel.HIGH,
)

# Valider la cible
result = security.validate_target("192.168.1.1")
if not result.valid:
    print(f"Rejeté: {result.errors}")

# Protection par décorateur
@security.secure_tool(operation="port_scan", rate_limit_key="scan")
async def port_scan(target: str):
    # ...
```

**Fonctionnalités Principales**:
- **Validation d'Entrée**: Validation IP/Domaine/URL/CIDR/Port/Chemin, détection SSRF
- **Limitation de Débit**: Fenêtre glissante + Token bucket, prévention épuisement ressources
- **Autorisation d'Opération**: Contrôle d'opération basé sur le niveau de risque
- **Protection Mémoire**: Nettoyage automatique des données expirées, prévention fuites mémoire

### 2. Planificateur d'Attaque MCTS (v3.0.2)

**Emplacement**: `core/mcts_planner.py`

Utilise l'algorithme Monte Carlo Tree Search pour planifier les chemins d'attaque optimaux :

```python
from core.mcts_planner import MCTSPlanner, AttackState

planner = MCTSPlanner(exploration_weight=1.414, max_depth=10)

state = AttackState(
    target="192.168.1.100",
    target_type="linux_server",
    open_ports={22: "ssh", 80: "http"},
)

result = planner.plan(state, iterations=1000)
print(f"Actions recommandées: {result['recommended_actions']}")
```

**Fonctionnalités Principales**:
- **Algorithme UCB1**: Équilibre exploration et exploitation
- **Génération d'Actions**: Génère intelligemment les actions disponibles selon l'état
- **Simulation d'Attaque**: Simule l'exécution d'attaque pour estimer les taux de succès
- **Extraction de Chemin**: Extrait les séquences de chemins d'attaque optimaux

### 3. Graphe de Connaissances (v3.0.2)

**Emplacement**: `core/knowledge/`

Stockage persistant des connaissances d'attaque avec apprentissage inter-sessions :

```python
from core.knowledge import KnowledgeManager

km = KnowledgeManager()

# Stocker la cible
target_id = km.store_target("192.168.1.100", "linux_server")

# Stocker le service
service_id = km.store_service(target_id, "nginx", 80)

# Stocker la vulnérabilité
vuln_id = km.store_vulnerability(service_id, "CVE-2021-44228", "critical")

# Trouver les chemins d'attaque
paths = km.get_attack_paths(target_id, credential_id)

# Trouver les cibles similaires
similar = km.find_similar_targets("192.168.1.100")
```

**Fonctionnalités Principales**:
- **Stockage d'Entités**: Cible, Service, Vulnérabilité, Credential
- **Modélisation des Relations**: HOSTS, HAS_VULNERABILITY, OBTAINED_FROM
- **Découverte de Chemins BFS**: Support de découverte multi-chemins
- **Correspondance de Similarité**: Identification même-sous-réseau/même-domaine

### 4. Vérificateur Avancé (v3.0.2 Amélioré)

**Emplacement**: `core/detectors/advanced_verifier.py`

Validation croisée multi-méthodes pour réduire les taux de faux positifs :

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
print(f"Statut: {aggregated.status}, Confiance: {aggregated.confidence:.2%}")
```

**Méthodes de Vérification**:
- **Vérification Statistique**: Significativité des différences de réponse multi-échantillons
- **Vérification Aveugle Booléenne**: Comparaison des conditions True/False
- **Vérification Aveugle Temporelle**: Détection de délai avec compensation de gigue réseau
- **Vérification OOB**: Confirmation de callback DNS/HTTP hors bande

### 5. Conteneur d'Injection de Dépendances (v3.0.2)

**Emplacement**: `core/container.py`

Composition flexible de services et gestion du cycle de vie :

```python
from core.container import Container, singleton, inject

container = Container()

# Enregistrer les services
container.register_singleton(KnowledgeManager)
container.register_transient(SQLiDetector)

# Utiliser les décorateurs
@singleton
class ConfigManager:
    pass

# Injecter les dépendances
config = inject(ConfigManager)

# Conteneur scopé (niveau requête)
with container.create_scope() as scope:
    service = scope.resolve(RequestService)
```

**Fonctionnalités Principales**:
- **Cycle de Vie**: Singleton, Scoped, Transient
- **Injection Automatique**: Résolution automatique des paramètres du constructeur
- **Détection de Cycles**: Détecte et signale les dépendances circulaires
- **Nettoyage Ressources**: Les conteneurs scopés appellent automatiquement dispose()

---

## Intégration des Outils Externes

Support pour l'intégration d'outils de sécurité professionnels installés localement :

| Outil | Usage | Commande MCP | Prérequis |
|-------|-------|--------------|-----------|
| **Nmap** | Scan de ports + Détection de services + Scripts NSE | `ext_nmap_scan` | PATH système ou chemin configuré |
| **Nuclei** | 7000+ templates de scan CVE/vulnérabilités | `ext_nuclei_scan` | Binaire Go |
| **SQLMap** | 6 techniques d'injection SQL + Bypass WAF | `ext_sqlmap_scan` | Script Python |
| **ffuf** | Fuzzing haute vitesse répertoires/paramètres | `ext_ffuf_fuzz` | Binaire Go |
| **Masscan** | Scan de ports à grande échelle ultra-rapide | `ext_masscan_scan` | Nécessite root/admin |

### Configurer les Outils Externes

Éditez `config/external_tools.yaml` :

```yaml
# Répertoire de base des outils
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

# Configuration des chaînes d'outils
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

### Orchestration des Chaînes d'Outils

```bash
# Chaîne de recon complète: découverte rapide masscan -> identification détaillée nmap
ext_tool_chain target="192.168.1.0/24" chain_name="full_recon"

# Chaîne de scan de vulnérabilités: détection combinée nuclei + sqlmap
ext_tool_chain target="https://example.com" chain_name="vuln_scan"

# Vérifier le statut des outils externes
ext_tools_status
```

---

## Exemples d'Utilisation

### Commandes en Langage Naturel

Conversez directement dans les éditeurs IA pour invoquer les outils :

#### Reconnaissance et Collecte d'Informations

```
# Reconnaissance complète
"Effectuer une reconnaissance complète sur example.com et générer un rapport"

# Scan de ports
"Scanner les ports ouverts sur le réseau 192.168.1.0/24"

# Énumération des sous-domaines
"Énumérer tous les sous-domaines de example.com"

# Identification d'empreinte
"Identifier la pile technologique et le WAF du site web cible"

# Analyse JS
"Analyser les fichiers JavaScript du site cible pour trouver des informations sensibles"
```

#### Scan de Vulnérabilités

```
# Injection SQL
"Vérifier si https://target.com/api?id=1 est vulnérable à l'injection SQL"

# Scan XSS
"Scanner les formulaires cibles pour les vulnérabilités XSS et générer un PoC"

# Sécurité API
"Effectuer un test de sécurité complet JWT/CORS/GraphQL sur l'API cible"

# Recherche et exploitation CVE
"Rechercher les CVE liés à Apache Log4j et exécuter le PoC"
```

#### Opérations Red Team

```
# Mouvement latéral
"Exécuter la commande whoami sur 192.168.1.100 via SMB"

# Communication C2
"Démarrer une connexion tunnel DNS vers c2.example.com"

# Persistance
"Établir une persistance par tâche planifiée sur la cible Windows"

# Attaques AD
"Effectuer une attaque Kerberoasting contre le contrôleur de domaine"
```

#### Tests de Pénétration Automatisés

```
# Test de pénétration entièrement automatisé
"Exécuter un test de pénétration entièrement automatisé sur https://target.com avec rapport détaillé"

# Chaîne d'attaque intelligente
"Analyser la cible et générer des recommandations de chaîne d'attaque optimale"

# Reprendre une session
"Reprendre la session de test de pénétration précédemment interrompue"
```

### API Python

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
    print(f"Découverts {len(recon_result.open_ports)} ports ouverts")

    # 2. Détection de vulnérabilités
    detector = DetectorFactory.create_composite(['sqli', 'xss', 'ssrf'])
    vuln_results = await detector.async_detect(
        url="https://target.com/api",
        params={'id': '1'}
    )

    for vuln in vuln_results:
        print(f"Vulnérabilité découverte: {vuln.type} - {vuln.severity}")

asyncio.run(main())
```

#### Planification d'Attaque MCTS

```python
from core.mcts_planner import MCTSPlanner, AttackState

planner = MCTSPlanner(exploration_weight=1.414, max_depth=10)

state = AttackState(
    target="192.168.1.100",
    target_type="linux_server",
    open_ports={22: "ssh", 80: "http", 3306: "mysql"},
)

result = planner.plan(state, iterations=1000)

print(f"Séquence d'attaque recommandée:")
for action, visits, reward in result['recommended_actions']:
    print(f"  - {action.type.value}: {action.target_port} (confiance: {reward:.2f})")
```

#### Graphe de Connaissances

```python
from core.knowledge import KnowledgeManager

km = KnowledgeManager()

# Construire les connaissances
target_id = km.store_target("192.168.1.100", "linux_server")
service_id = km.store_service(target_id, "nginx", 80)
vuln_id = km.store_vulnerability(service_id, "CVE-2021-44228", "critical")

# Interroger les chemins d'attaque
paths = km.get_attack_paths(target_id, vuln_id)
for path in paths:
    print(f"Longueur du chemin: {path.length}, Taux de succès: {path.success_rate:.2%}")

# Trouver les cibles similaires
similar = km.find_similar_targets("192.168.1.100", top_k=5)
for match in similar:
    print(f"Cible similaire: {match.entity.properties['target']}, Score: {match.score:.2f}")
```

---

## Configuration

### Variables d'Environnement (.env)

```bash
# ========== Sécurité ==========
REDTEAM_MASTER_KEY=
AUTOREDTEAM_API_KEY=
AUTOREDTEAM_AUTH_MODE=permissive

# ========== Clés API ==========
OPENAI_API_KEY=votre_cle
ANTHROPIC_API_KEY=votre_cle
SHODAN_API_KEY=votre_cle
CENSYS_API_ID=votre_id
CENSYS_API_SECRET=votre_secret
NVD_API_KEY=votre_cle
GITHUB_TOKEN=votre_token

# ========== Proxy ==========
HTTP_PROXY=
HTTPS_PROXY=
SOCKS_PROXY=

# ========== Global ==========
VERIFY_SSL=false
RATE_LIMIT_DELAY=0.3
MAX_THREADS=50
REQUEST_TIMEOUT=10

# ========== Journalisation ==========
LOG_LEVEL=INFO
LOG_FILE=logs/redteam.log
```

---

## Optimisation des Performances

### Configuration de la Concurrence

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

### Optimisation de la Mémoire

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

## Dépannage

| Problème | Cause | Solution |
|----------|-------|----------|
| Serveur MCP ne se connecte pas | Erreur de chemin ou problème d'env Python | Vérifier le chemin absolu, vérifier l'interpréteur Python |
| Erreurs d'import | PYTHONPATH non défini | Ajouter la variable d'environnement `PYTHONPATH` |
| Échec outil externe | Outil non installé ou erreur de chemin | Exécuter `ext_tools_status` |
| Échec sync CVE | Réseau ou limitation API | Vérifier le réseau, configurer NVD_API_KEY |
| Scan lent | Config concurrence faible | Ajuster `MAX_THREADS` et `RATE_LIMIT_DELAY` |
| Dépassement mémoire | Scan à grande échelle | Activer `streaming_mode`, définir `memory_limit` |

### Mode Débogage

```bash
LOG_LEVEL=DEBUG python mcp_stdio_server.py
python -m py_compile mcp_stdio_server.py
pytest tests/test_mcp_security.py::TestInputValidator -v
```

---

## Questions Fréquentes (FAQ)

<details>
<summary><b>Q: Comment utiliser dans un environnement hors ligne ?</b></summary>

1. Télécharger préalablement la base CVE: `python core/cve/update_manager.py sync --offline-export`
2. Utiliser les fichiers de dictionnaire locaux
3. Désactiver les fonctionnalités réseau: `OFFLINE_MODE=true`

</details>

<details>
<summary><b>Q: Comment ajouter des détecteurs personnalisés ?</b></summary>

1. Créer un nouveau fichier dans `core/detectors/`
2. Hériter de la classe `BaseDetector`
3. Implémenter les méthodes `detect()` et `async_detect()`
4. Enregistrer l'outil MCP dans `handlers/detector_handlers.py`

</details>

<details>
<summary><b>Q: Comment fonctionne le planificateur MCTS ?</b></summary>

MCTS planifie les chemins d'attaque en quatre phases :

1. **Sélection**: L'algorithme UCB1 sélectionne le chemin optimal depuis la racine
2. **Expansion**: Étend les nouvelles actions d'attaque aux nœuds feuilles
3. **Simulation**: Simule l'exécution de l'attaque et évalue les récompenses
4. **Rétropropagation**: Propage les récompenses pour mettre à jour les nœuds du chemin

Formule UCB1: `UCB1 = Q/N + c * sqrt(ln(N_parent) / N)`

Où `c = sqrt(2)` est le poids d'exploration, équilibrant "chemins connus bons" et "chemins inexplorés".

</details>

<details>
<summary><b>Q: Comment le Graphe de Connaissances réduit-il le travail redondant ?</b></summary>

1. **Similarité de Cibles**: Identifie les cibles même-sous-réseau/même-domaine, réutilise les infos de vulnérabilité
2. **Taux de Succès des Chemins**: Calcule les taux de succès des chemins depuis l'historique
3. **Association de Credentials**: Associe automatiquement les credentials aux cibles accessibles
4. **Apprentissage Historique**: Enregistre les taux de succès des actions, optimise les décisions futures

</details>

---

## Guide de Développement

### Standards de Code

```bash
# Formater le code
black core/ modules/ handlers/ utils/
isort core/ modules/ handlers/ utils/

# Analyse statique
pylint core/ modules/ handlers/ utils/
mypy core/ modules/ handlers/ utils/

# Exécuter les tests
pytest tests/ -v --cov=core --cov-report=html
```

### Ajouter de Nouveaux Outils MCP

```python
# 1. Ajouter un handler dans handlers/
# handlers/my_handlers.py

from mcp import tool

@tool()
async def my_new_tool(target: str, option: str = "default") -> dict:
    """Description de l'outil

    Args:
        target: Adresse cible
        option: Paramètre optionnel

    Returns:
        Dictionnaire de résultats
    """
    return {"success": True, "data": ...}

# 2. Importer dans mcp_stdio_server.py
from handlers.my_handlers import my_new_tool
```

---

## Journal des Modifications

### v3.0.2 (En Développement) - Renforcement de l'Architecture

**Nouveaux Modules** (Implémentés, en attente de release)
- **Middleware Sécurité MCP** - Validation d'entrée, limitation de débit, autorisation d'opération
- **Conteneur DI** - Gestion du cycle de vie, détection de dépendances circulaires
- **Planificateur d'Attaque MCTS** - Algorithme UCB1, optimisation des chemins d'attaque
- **Graphe de Connaissances** - Stockage des relations d'entités, découverte de chemins BFS
- **Amélioration Vérificateur Avancé** - Sécurité thread OOB, payloads SSTI

**Corrections de Sécurité**
- Correction des conditions de course TOCTOU (portée de verrou étendue)
- Correction de la logique d'expiration d'autorisation de durée
- Ajout de la détection SSRF (validation IP privée)
- Correction de la fuite mémoire du Rate Limiter (éviction max_keys)
- Correction de l'injection DNS (assainissement de l'ID du token)
- Migration MD5 → SHA256

**Amélioration des Tests**
- Ajout de 291 cas de test (mcp_security: 62, container: 39, mcts: 57, verifier: 43, knowledge: 90)
- Couverture des tests de sécurité thread
- Workflows de tests d'intégration

### v3.0.1 (2026-01-30) - Renforcement de la Qualité

**Ajouté**
- Amélioration auto-exploit CVE (`cve_auto_exploit`, `cve_exploit_with_desc`, `cve_generate_poc`)
- Générateur PoC IA (`core/cve/ai_poc_generator.py`)

**Corrigé**
- Sync de version - Unification VERSION/pyproject.toml/code source
- Correction ToolCounter - Ajout des catégories external_tools/lateral/persistence/ad
- Sécurité thread - Ajout de threading.Lock pour la gestion d'état de beacon.py

**Amélioré**
- Application CI/CD - Les échecs de lint bloquent maintenant les builds
- Seuil de couverture de test augmenté à 50%
- Contraintes de dépendances - Ajout de bornes supérieures

### v3.0.0 (2026-01-18) - Amélioration de l'Architecture

**Ajouté**
- Intégration outils externes - 8 commandes MCP pour outils externes
- Orchestration des chaînes d'outils - Combinaisons multi-outils pilotées par YAML
- Modularisation des Handlers - 16 modules Handler indépendants

---

## Feuille de Route

### En Cours

- [ ] Release v3.0.2 (Middleware Sécurité MCP, Planificateur MCTS, Graphe de Connaissances, Conteneur DI)
- [ ] Interface Web de gestion
- [ ] Cluster de scan distribué

### Planifié

- [ ] Plus de plateformes cloud (GCP/Alibaba Cloud/Tencent Cloud)
- [ ] Intégration du plugin Burp Suite
- [ ] Tests de sécurité des applications mobiles
- [ ] Agent d'attaque autonome IA
- [ ] Backend Neo4j pour le graphe de connaissances

### Complété (v3.0.1)

- [x] Chaîne d'outils Red Team complète
- [x] Intelligence CVE et génération PoC IA
- [x] Modules API/Chaîne d'Approvisionnement/Sécurité Cloud
- [x] Framework de test de pénétration entièrement automatisé
- [x] Intégration des outils externes

---

## Guide de Contribution

Nous accueillons toute forme de contribution !

### Démarrage Rapide

```bash
# 1. Fork et cloner
git clone https://github.com/VOTRE_NOM/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. Créer une branche
git checkout -b feature/votre-fonctionnalite

# 3. Installer les dépendances de développement
pip install -r requirements-dev.txt
pre-commit install

# 4. Développer et tester
pytest tests/ -v

# 5. Soumettre une PR
git push origin feature/votre-fonctionnalite
```

### Convention de Commits

Utilisez le format [Conventional Commits](https://www.conventionalcommits.org/) :

- `feat:` Nouvelle fonctionnalité
- `fix:` Correction de bug
- `docs:` Documentation
- `refactor:` Refactorisation
- `test:` Tests
- `chore:` Build/Outils
- `security:` Lié à la sécurité

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour plus de détails.

---

## Politique de Sécurité

- **Divulgation Responsable**: Signaler les vulnérabilités de sécurité à [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com)
- **Utilisation Autorisée Uniquement**: Cet outil est destiné uniquement aux tests de sécurité et à la recherche autorisés
- **Conformité**: Assurez-vous de respecter les lois locales avant utilisation

Voir [SECURITY.md](SECURITY.md) pour plus de détails.

---

## Remerciements

### Dépendances Principales

| Projet | Usage | Licence |
|--------|-------|---------|
| [MCP Protocol](https://modelcontextprotocol.io/) | Standard de protocole d'outils IA | MIT |
| [aiohttp](https://github.com/aio-libs/aiohttp) | Client HTTP asynchrone | Apache-2.0 |
| [pydantic](https://github.com/pydantic/pydantic) | Validation de données | MIT |
| [pytest](https://github.com/pytest-dev/pytest) | Framework de test | MIT |

### Sources d'Inspiration

| Projet | Inspiration |
|--------|-------------|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Conception du moteur de scanner de vulnérabilités |
| [SQLMap](https://github.com/sqlmapproject/sqlmap) | Approche de détection d'injection SQL |
| [Impacket](https://github.com/fortra/impacket) | Implémentation des protocoles réseau |
| [Metasploit](https://github.com/rapid7/metasploit-framework) | Conception des modules post-exploitation |

### Références d'Algorithmes

| Algorithme | Usage | Référence |
|------------|-------|-----------|
| UCB1 | Équilibre exploration-exploitation MCTS | Auer et al., 2002 |
| BFS | Découverte de chemins graphe de connaissances | - |
| Token Bucket | Limitation de débit | - |
| Sliding Window | Limitation de débit | - |

---

## Historique des Étoiles

[![Star History Chart](https://api.star-history.com/svg?repos=Coff0xc/AutoRedTeam-Orchestrator&type=Date)](https://star-history.com/#Coff0xc/AutoRedTeam-Orchestrator&Date)

---

## Licence

Ce projet est sous licence **MIT** - voir le fichier [LICENSE](LICENSE) pour plus de détails.

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

## Avertissement

> **ATTENTION**: Cet outil est destiné **uniquement aux tests de sécurité et à la recherche autorisés**.
>
> Avant d'utiliser cet outil pour tester tout système, assurez-vous d'avoir :
> - Une **autorisation écrite** du propriétaire du système
> - Le respect des **lois et réglementations** locales
> - L'adhésion aux standards **d'éthique professionnelle**
>
> L'utilisation non autorisée peut être illégale. **Les développeurs ne sont pas responsables de toute utilisation abusive**.
>
> Cet outil contient des capacités d'attaque Red Team (mouvement latéral, communication C2, persistance, etc.), destinées uniquement à :
> - Tests de pénétration autorisés
> - Recherche en sécurité et éducation
> - Compétitions CTF
> - Validation des capacités défensives
>
> **Interdit pour tout usage illégal.**

---

<p align="center">
  <img src="https://img.shields.io/badge/Construit%20avec-Python%20%26%20%E2%9D%A4-blue?style=for-the-badge" alt="Construit avec Python">
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
  <sub>Si ce projet vous aide, pensez à lui donner une ⭐ Étoile !</sub>
</p>
