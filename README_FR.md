<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>Framework d'Orchestration Red Team Automatisé Piloté par IA</b><br>
  <i>Multi-plateforme · 74 Outils MCP · 2000+ Payloads · Couverture ATT&CK Complète</i>
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
  <a href="#"><img src="https://img.shields.io/badge/Outils-74-FF6B6B?style=for-the-badge&logo=toolbox&logoColor=white" alt="Tools"></a>
  <a href="#"><img src="https://img.shields.io/badge/Payloads-2000+-orange?style=for-the-badge&logo=artillery&logoColor=white" alt="Payloads"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/Licence-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License"></a>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Rejoindre_la_Communauté-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-Documentation-blue?style=for-the-badge&logo=gitbook&logoColor=white" alt="Wiki"></a>
</p>

---

## 📖 Table des Matières

- [Fonctionnalités Principales](#-fonctionnalités-principales)
- [Matrice de Couverture ATT&CK](#️-matrice-de-couverture-attck)
- [Démarrage Rapide](#-démarrage-rapide)
- [Configuration MCP](#-configuration-mcp)
- [Matrice des Outils](#️-matrice-des-outils)
- [Exemples d'Utilisation](#-exemples-dutilisation)
- [Architecture](#-architecture)
- [Journal des Modifications](#-journal-des-modifications)
- [Feuille de Route](#️-feuille-de-route)
- [Guide de Contribution](#-guide-de-contribution)
- [Politique de Sécurité](#-politique-de-sécurité)
- [Remerciements](#-remerciements)
- [Licence](#-licence)

---

## 🎯 Fonctionnalités Principales

<table>
<tr>
<td width="50%">

### 🤖 Conception Native IA
- **Empreinte Intelligente** - Détection automatique de la stack technologique
- **Planification de Chaîne d'Attaque** - Recommandations de chemins d'attaque par IA
- **Apprentissage par Feedback** - Optimisation continue de la stratégie
- **Sélection Auto de Payload** - Mutation intelligente consciente du WAF
- **Génération PoC par IA** - Génération de code d'exploit à partir de descriptions CVE

</td>
<td width="50%">

### ⚡ Automatisation Complète
- **Pipeline de Reconnaissance 10 Phases** - Analyse DNS/Port/Empreinte/WAF/JS
- **Découverte & Vérification de Vulnérabilités** - Scan auto + validation OOB
- **Orchestration d'Exploitation Intelligente** - Boucle de feedback + retry auto
- **Rapports Professionnels en Un Clic** - Formats JSON/HTML/Markdown
- **Récupération de Point de Contrôle** - Reprise des scans interrompus

</td>
</tr>
<tr>
<td width="50%">

### 🔴 Boîte à Outils Red Team
- **Mouvement Latéral** - SMB/SSH/WMI/WinRM/PSExec
- **Communication C2** - Beacon + Tunnels DNS/HTTP/WebSocket
- **Évasion & Obfuscation** - Encodage multi-couches XOR/AES/Base64
- **Persistance** - Registre Windows/Tâches Planifiées/Linux cron
- **Accès aux Identifiants** - Extraction mémoire/Recherche de fichiers
- **Attaques AD** - Kerberoasting/AS-REP Roasting

</td>
<td width="50%">

### 🛡️ Extensions de Sécurité
- **Sécurité API** - JWT/CORS/GraphQL/WebSocket/OAuth
- **Sécurité de la Chaîne d'Approvisionnement** - Génération SBOM/Audit des dépendances/Scan CI-CD
- **Sécurité Cloud Native** - Audit K8s/Tests gRPC/Scan AWS
- **Intelligence CVE** - Synchronisation multi-sources NVD/Nuclei/ExploitDB
- **Contournement WAF** - Moteur de mutation intelligent 2000+ payloads

</td>
</tr>
</table>

---

## ⚔️ Matrice de Couverture ATT&CK

| Tactique | Techniques Couvertes | Nombre d'Outils | Statut |
|----------|---------------------|-----------------|--------|
| **Reconnaissance** | Scan Actif, Collecte Passive, OSINT | 12+ | ✅ Complet |
| **Développement de Ressources** | Génération de Payload, Obfuscation | 4+ | ✅ Complet |
| **Accès Initial** | Exploitation Web, Exploits CVE | 19+ | ✅ Complet |
| **Exécution** | Injection de Commandes, Exécution de Code | 5+ | ✅ Complet |
| **Persistance** | Registre, Tâches Planifiées, Webshell | 3+ | ✅ Complet |
| **Élévation de Privilèges** | Contournement UAC, Usurpation de Token | 2+ | ⚠️ Partiel |
| **Évasion de Défense** | Contournement AMSI, Contournement ETW, Obfuscation | 4+ | ✅ Complet |
| **Accès aux Identifiants** | Extraction Mémoire, Recherche de Fichiers | 2+ | ✅ Complet |
| **Découverte** | Scan Réseau, Énumération de Services | 8+ | ✅ Complet |
| **Mouvement Latéral** | SMB/SSH/WMI/WinRM | 6+ | ✅ Complet |
| **Collecte** | Agrégation de Données, Fichiers Sensibles | 2+ | ✅ Complet |
| **Commande & Contrôle** | Tunnels HTTP/DNS/WebSocket | 4+ | ✅ Complet |
| **Exfiltration** | Exfiltration DNS/HTTP/ICMP | 3+ | ✅ Complet |

---

## 📦 Démarrage Rapide

### Configuration Requise

| Composant | Exigence |
|-----------|----------|
| **OS** | Windows 10+, Linux (Ubuntu 20.04+), macOS 12+ |
| **Python** | 3.10 ou supérieur |
| **Mémoire** | 4GB+ recommandé |
| **Réseau** | Accès HTTP/HTTPS sortant |

### Installation

```bash
# Cloner le dépôt
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# Installer les dépendances
pip install -r requirements.txt

# Vérifier l'installation
python mcp_stdio_server.py --version
```

<details>
<summary><b>🔧 Optionnel : Installation Minimale</b></summary>

```bash
# Dépendances principales uniquement (Reconnaissance + Détection de Vulnérabilités)
pip install -r requirements-core.txt

# Modules optionnels (Red Team + Sécurité Cloud)
pip install -r requirements-optional.txt
```

</details>

<details>
<summary><b>🐳 Déploiement Docker</b></summary>

```bash
docker pull coff0xc/autoredteam:latest
docker run -it --rm coff0xc/autoredteam
```

</details>

### Démarrer le Service

```bash
python mcp_stdio_server.py
```

---

## 🔧 Configuration MCP

Ajoutez la configuration suivante au fichier de configuration MCP de votre éditeur IA :

<details>
<summary><b>📘 Éditeurs IA compatibles MCP</b></summary>

**Emplacement du fichier de configuration :**
- Windows : `%APPDATA%\<NomEditeur>\config.json`
- macOS : `~/Library/Application Support/<NomEditeur>/config.json`
- Linux : `~/.config/<NomEditeur>/config.json`

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

**Fichier de configuration :** `~/.cursor/mcp.json`

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

**Fichier de configuration :** `~/.codeium/windsurf/mcp_config.json`

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

**Fichier de configuration :** `~/.kiro/mcp.json`

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

## 🛠️ Matrice des Outils

| Catégorie | Nombre | Fonctions Principales | Outils Clés |
|-----------|--------|----------------------|-------------|
| **🔍 Reconnaissance** | 12+ | Collecte d'infos & découverte d'actifs | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` |
| **🐛 Détection de Vulnérabilités** | 19+ | OWASP Top 10 + Vulnérabilités logiques | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` |
| **🌐 Scan Web** | 4+ | Découverte de surface d'attaque & orchestration | `vuln_scan` `security_headers_scan` `cors_scan` `idor_scan` |
| **🔐 Sécurité API** | 11+ | Tests de sécurité API modernes | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` |
| **📦 Chaîne d'Approvisionnement** | 5+ | Sécurité des dépendances & build | `sbom_generate` `dependency_audit` `cicd_scan` |
| **☁️ Cloud Native** | 8+ | Sécurité des conteneurs & clusters | `k8s_scan` `grpc_scan` `aws_scan` |
| **🔴 Red Team** | 10+ | Post-exploitation & réseau interne | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` |
| **📋 CVE** | 6+ | Intelligence de vulnérabilités & exploitation | `cve_search` `cve_sync` `poc_execute` |
| **🤖 Automatisation** | 5+ | Tests de pénétration entièrement automatisés | `auto_pentest` `smart_analyze` `attack_chain_plan` `waf_bypass` |

---

## 💬 Exemples d'Utilisation

Discutez directement dans les éditeurs IA pour invoquer les outils :

### Reconnaissance & Collecte d'Informations
```
🔍 "Effectuer une reconnaissance complète sur example.com et générer un rapport"
🔍 "Scanner les ports ouverts sur le réseau 192.168.1.0/24"
🔍 "Énumérer les sous-domaines pour example.com"
🔍 "Identifier la stack technologique et le WAF du site cible"
```

### Scan & Exploitation de Vulnérabilités
```
🎯 "Vérifier si la cible est vulnérable à l'injection SQL"
🎯 "Exécuter un scan de sécurité complet sur l'API cible"
🎯 "Rechercher les CVE liés à Log4j et exécuter le PoC"
🎯 "Générer des payloads XSS contournant le WAF"
```

### Opérations Red Team
```
🔴 "Exécuter une commande sur la machine cible via SMB"
🔴 "Démarrer une connexion C2 Beacon vers le serveur"
🔴 "Rechercher des identifiants sensibles sur le système cible"
🔴 "Générer du code de contournement AMSI"
```

### Tests de Pénétration Automatisés
```
⚡ "Exécuter un test de pénétration entièrement automatisé sur https://target.com"
⚡ "Analyser la cible et générer des recommandations de chaîne d'attaque"
⚡ "Reprendre la session de pentest précédemment interrompue"
```

---

## 🏗️ Architecture

```
AutoRedTeam-Orchestrator/
├── 📄 mcp_stdio_server.py      # Point d'entrée du serveur MCP (74 outils enregistrés)
│
├── 📂 handlers/                # Gestionnaires d'outils MCP (schéma de sortie unifié)
│   ├── recon.py               # Outils de reconnaissance
│   ├── detector.py            # Détection de vulnérabilités
│   └── redteam.py             # Outils Red Team
│
├── 📂 core/                    # Moteurs principaux
│   ├── recon/                 # Moteur de reconnaissance (pipeline 10 phases)
│   ├── detectors/             # Détecteurs de vulnérabilités
│   ├── exploit/               # Moteur d'exploitation
│   ├── c2/                    # Framework de communication C2
│   ├── lateral/               # Mouvement latéral (SMB/SSH/WMI)
│   ├── evasion/               # Évasion & contournement
│   ├── persistence/           # Modules de persistance
│   ├── credential/            # Accès aux identifiants
│   └── cve/                   # Gestion de l'intelligence CVE
│
├── 📂 modules/                 # Modules de fonctionnalités
│   ├── api_security/          # Tests de sécurité API
│   ├── cloud_security/        # Audit de sécurité cloud
│   ├── supply_chain/          # Sécurité de la chaîne d'approvisionnement
│   └── smart_payload_engine.py # Moteur de payload intelligent
│
├── 📂 wordlists/               # Dictionnaires intégrés
│
└── 📂 utils/                   # Fonctions utilitaires
```

---

## 📋 Journal des Modifications

### v3.0.0 (2026-01-18) - Amélioration de l'Architecture

- 🚀 **Extension des Outils** : Les outils MCP atteignent maintenant 74
- 🔄 **Boucle de Feedback** : Nouvel orchestrateur d'exploitation intelligent avec retry automatique
- 🛡️ **Contournement WAF** : Moteur de mutation de payload amélioré avec 30+ méthodes d'encodage
- 📊 **Optimisation des Rapports** : Ajout du résumé exécutif et de l'évaluation des risques

### v2.8.0 (2026-01-15) - Renforcement de la Sécurité

- 🔒 **Validation des Entrées** : Vérifications de sécurité améliorées pour toutes les entrées utilisateur
- ⚙️ **Gestion des Exceptions** : Système d'exceptions unifié pour une meilleure stabilité
- 🚄 **Performance** : Amélioration du contrôle de la concurrence et de la gestion des ressources

---

## 🛤️ Feuille de Route

- [ ] 🖥️ Interface de Gestion Web UI
- [ ] 🌐 Cluster de Scan Distribué
- [ ] ☁️ Plus de Plateformes Cloud (GCP/Alibaba Cloud/Tencent Cloud)
- [ ] 🤖 Exploitation Automatisée par IA Améliorée
- [ ] 📚 Plus de Templates PoC CVE
- [ ] 🔌 Intégration du Plugin Burp Suite
- [x] ✅ Boîte à Outils Red Team Complète
- [x] ✅ Intelligence CVE & Génération PoC par IA
- [x] ✅ Modules API/Chaîne d'Approvisionnement/Sécurité Cloud
- [x] ✅ Framework de Tests de Pénétration Entièrement Automatisés

---

## 🤝 Guide de Contribution

Nous accueillons toutes les formes de contributions !

1. **Fork** ce dépôt
2. Créez une branche de fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. Validez vos modifications (`git commit -m 'Add AmazingFeature'`)
4. Poussez vers la branche (`git push origin feature/AmazingFeature`)
5. Soumettez une **Pull Request**

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour les détails

---

## 🔒 Politique de Sécurité

- 🚨 **Divulgation Responsable** : Signalez les vulnérabilités de sécurité à [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com)
- ⚠️ **Utilisation Autorisée Uniquement** : Cet outil est destiné uniquement aux tests de sécurité autorisés et à la recherche
- 📜 **Conformité** : Assurez-vous de respecter les lois locales avant utilisation

Voir [SECURITY.md](SECURITY.md) pour les détails

---

## 🙏 Remerciements

Merci à ces projets open source pour l'inspiration :

- [Nuclei](https://github.com/projectdiscovery/nuclei) - Conception du moteur de scanner de vulnérabilités
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - Approche de détection d'injection SQL
- [Impacket](https://github.com/fortra/impacket) - Implémentation de protocoles réseau
- [MCP Protocol](https://modelcontextprotocol.io/) - Standard de protocole d'outils IA

---

## 📜 Licence

Ce projet est sous licence **MIT** - voir le fichier [LICENSE](LICENSE) pour les détails

---

## ⚖️ Avertissement

> **ATTENTION** : Cet outil est destiné **uniquement aux tests de sécurité autorisés et à la recherche**.
>
> Avant d'utiliser cet outil pour tester tout système, assurez-vous :
> - D'avoir une **autorisation écrite** du propriétaire du système
> - De respecter les **lois et réglementations locales**
> - De suivre les standards **d'éthique professionnelle**
>
> L'utilisation non autorisée peut enfreindre la loi. **Les développeurs ne sont pas responsables de toute utilisation abusive**.

---

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Coff0xc">Coff0xc</a></b>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Rejoindre_la_Communauté-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="mailto:Coff0xc@protonmail.com"><img src="https://img.shields.io/badge/Email-Contact-EA4335?style=for-the-badge&logo=gmail&logoColor=white" alt="Email"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues"><img src="https://img.shields.io/badge/Issues-Signaler-181717?style=for-the-badge&logo=github&logoColor=white" alt="Issues"></a>
</p>
