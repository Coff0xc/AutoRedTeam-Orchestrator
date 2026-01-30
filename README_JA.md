<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>AI 駆動の自動レッドチームオーケストレーションフレームワーク</b><br>
  <sub>クロスプラットフォーム | 100+ MCP ツール | 2000+ Payload | ATT&CK 全面カバー</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md"><b>日本語</b></a> ·
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
  <img src="https://img.shields.io/badge/Tools-100+-FF6B6B?style=flat-square" alt="Tools">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-コミュニティ-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-ドキュメント-blue?style=flat-square&logo=gitbook&logoColor=white" alt="Wiki"></a>
</p>

---

## 目次

- [プロジェクト概要](#プロジェクト概要)
- [コア機能](#コア機能)
- [ATT&CK カバレッジマトリックス](#attck-カバレッジマトリックス)
- [クイックスタート](#クイックスタート)
  - [システム要件](#システム要件)
  - [インストール方法](#インストール方法)
  - [インストール確認](#インストール確認)
- [MCP 設定](#mcp-設定)
- [ツールマトリックス (100+ MCP ツール)](#ツールマトリックス-100-mcp-ツール)
- [外部ツール統合](#外部ツール統合)
- [使用例](#使用例)
  - [コマンドライン使用](#コマンドライン使用)
  - [Python API 呼び出し](#python-api-呼び出し)
- [アーキテクチャ設計](#アーキテクチャ設計)
- [設定説明](#設定説明)
- [パフォーマンスチューニング](#パフォーマンスチューニング)
- [トラブルシューティング](#トラブルシューティング)
- [よくある質問 (FAQ)](#よくある質問-faq)
- [更新履歴](#更新履歴)
- [ロードマップ](#ロードマップ)
- [コントリビューションガイド](#コントリビューションガイド)
- [セキュリティポリシー](#セキュリティポリシー)
- [謝辞](#謝辞)
- [ライセンス](#ライセンス)
- [免責事項](#免責事項)

---

## プロジェクト概要

**AutoRedTeam-Orchestrator** は、[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) に基づく AI 駆動の自動化ペネトレーションテストフレームワークです。100 以上のセキュリティツールを MCP ツールとしてカプセル化し、MCP 対応 AI エディタ (Cursor, Windsurf, Kiro, Claude Desktop) とシームレスに統合することで、自然言語駆動の自動化セキュリティテストを実現します。

### なぜ AutoRedTeam-Orchestrator を選ぶのか？

| 特徴 | 従来のツール | AutoRedTeam |
|------|-------------|-------------|
| **インタラクション方式** | コマンドライン暗記 | 自然言語対話 |
| **学習コスト** | 高い（大量のパラメータ暗記が必要） | 低い（AI が自動的にツールを選択） |
| **ツール統合** | 手動でツール切り替え | 100+ ツールの統一インターフェース |
| **攻撃チェーン計画** | 手動計画 | AI インテリジェント推奨 |
| **レポート生成** | 手動作成 | ワンクリックで専門レポート生成 |
| **セッション管理** | なし | チェックポイント復元対応 |

---

## コア機能

<table>
<tr>
<td width="50%">

**AI ネイティブ設計**
- **インテリジェントフィンガープリント** - ターゲット技術スタック (CMS/フレームワーク/WAF) の自動識別
- **攻撃チェーン計画** - AI 駆動の攻撃パス推奨
- **履歴フィードバック学習** - 過去の結果に基づく攻撃戦略の継続的最適化
- **自動 Payload 選択** - WAF タイプに応じたインテリジェントな Payload の選択・変異
- **AI PoC 生成** - CVE 説明に基づく脆弱性エクスプロイトコードの自動生成

</td>
<td width="50%">

**フルプロセス自動化**
- **10 段階偵察パイプライン** - DNS/ポート/フィンガープリント/WAF/サブドメイン/ディレクトリ/JS 分析
- **脆弱性発見と検証** - 自動スキャン + OOB 検証による誤検知低減
- **インテリジェントエクスプロイトオーケストレーション** - フィードバックループエンジン + 失敗時自動リトライ
- **ワンクリック専門レポート** - JSON/HTML/Markdown マルチフォーマット出力
- **セッションチェックポイント復元** - 中断からの再開、スキャン進捗の保持

</td>
</tr>
<tr>
<td width="50%">

**Red Team ツールチェーン**
- **ラテラルムーブメント** - SMB/SSH/WMI/WinRM/PSExec 5 プロトコル
- **C2 通信** - Beacon + DNS/HTTP/WebSocket/ICMP トンネル
- **難読化・回避** - XOR/AES/Base64/カスタムエンコーダー
- **永続化** - Windows レジストリ/スケジュールタスク/WMI/Linux cron/Webshell
- **認証情報取得** - メモリ抽出/ファイル検索/パスワードスプレー
- **AD 攻撃** - Kerberoasting/AS-REP Roasting/SPN スキャン

</td>
<td width="50%">

**セキュリティ機能拡張**
- **API セキュリティ** - JWT/CORS/GraphQL/WebSocket/OAuth テスト
- **サプライチェーンセキュリティ** - SBOM 生成/依存関係監査/CI-CD セキュリティスキャン
- **クラウドネイティブセキュリティ** - K8s RBAC/Pod セキュリティ/gRPC/AWS 設定監査
- **CVE インテリジェンス** - NVD/Nuclei/ExploitDB マルチソース同期
- **WAF バイパス** - 2000+ Payload + 30 以上のエンコード方式によるインテリジェント変異

</td>
</tr>
</table>

---

## ATT&CK カバレッジマトリックス

| 戦術フェーズ | 技術カバレッジ | ツール数 | 状態 |
|-------------|--------------|----------|------|
| 偵察 (Reconnaissance) | アクティブスキャン、パッシブ収集、OSINT、JS 分析 | 12+ | ✅ |
| リソース開発 (Resource Development) | Payload 生成、難読化エンコーディング、PoC 生成 | 4+ | ✅ |
| 初期アクセス (Initial Access) | Web 脆弱性エクスプロイト、CVE エクスプロイト、API 脆弱性 | 19+ | ✅ |
| 実行 (Execution) | コマンドインジェクション、コード実行、デシリアライゼーション | 5+ | ✅ |
| 永続化 (Persistence) | レジストリ、スケジュールタスク、Webshell、WMI | 3+ | ✅ |
| 権限昇格 (Privilege Escalation) | UAC バイパス、トークン偽装、カーネル脆弱性 | 2+ | ⚠️ |
| 防御回避 (Defense Evasion) | AMSI バイパス、ETW バイパス、難読化、トラフィック変異 | 4+ | ✅ |
| 認証情報アクセス (Credential Access) | メモリ抽出、ファイル検索、パスワードスプレー | 2+ | ✅ |
| 探索 (Discovery) | ネットワークスキャン、サービス列挙、AD 列挙 | 8+ | ✅ |
| ラテラルムーブメント (Lateral Movement) | SMB/SSH/WMI/WinRM/PSExec | 9+ | ✅ |
| 収集 (Collection) | データ集約、機密ファイル検索 | 2+ | ✅ |
| コマンド＆コントロール (C2) | HTTP/DNS/WebSocket/ICMP トンネル | 4+ | ✅ |
| データ持ち出し (Exfiltration) | DNS/HTTP/ICMP/SMB + AES 暗号化 | 4+ | ✅ |

---

## クイックスタート

### システム要件

| コンポーネント | 最低要件 | 推奨構成 |
|---------------|---------|---------|
| オペレーティングシステム | Windows 10, Ubuntu 20.04, macOS 12 | Windows 11, Ubuntu 22.04, macOS 14 |
| Python | 3.10 | 3.11 または 3.12 |
| メモリ | 4GB | 8GB+ |
| ディスク容量 | 500MB | 2GB+ (CVE データベースを含む) |
| ネットワーク | インターネットアクセス可能 | 低レイテンシーネットワーク |

### インストール方法

#### 方法 1：標準インストール（推奨）

```bash
# 1. リポジトリをクローン
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. 仮想環境を作成（推奨）
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 3. 依存関係をインストール
pip install -r requirements.txt

# 4. 環境変数テンプレートをコピー
cp .env.example .env
# .env を編集して API キーを入力

# 5. サービスを起動
python mcp_stdio_server.py
```

#### 方法 2：最小インストール（コア機能のみ）

```bash
# コア依存関係のみインストール（偵察 + 脆弱性検出）
pip install -r requirements-core.txt
```

#### 方法 3：Docker デプロイ

```bash
docker pull coff0xc/autoredteam:latest
docker run -it --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  coff0xc/autoredteam
```

#### 方法 4：開発環境

```bash
# 開発依存関係をインストール（テスト、フォーマット、lint）
pip install -r requirements-dev.txt

# pre-commit フックをインストール
pre-commit install
```

### インストール確認

```bash
# バージョン確認
python mcp_stdio_server.py --version
# 出力: AutoRedTeam-Orchestrator v3.0.1

# セルフチェック実行
python -c "from core import __version__; print(f'Core version: {__version__}')"

# テスト実行（開発環境）
pytest tests/ -v --tb=short
```

---

## MCP 設定

AI エディタの MCP 設定ファイルに以下の設定を追加してください：

### 設定ファイルの場所

| エディタ | 設定ファイルパス |
|---------|----------------|
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Kiro | `~/.kiro/mcp.json` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| VS Code (MCP 拡張) | `.vscode/mcp.json` |

### 設定例

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
<summary><b>Windows パス例</b></summary>

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

## ツールマトリックス (100+ MCP ツール)

| カテゴリ | 数量 | 主要ツール | 説明 |
|---------|------|-----------|------|
| **偵察** | 8 | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` `dir_scan` `dns_lookup` `tech_detect` | 情報収集とアセット発見 |
| **脆弱性検出** | 11 | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` `idor_scan` `path_traversal_scan` `cors_scan` `security_headers_scan` | OWASP Top 10 + ロジック脆弱性 |
| **API セキュリティ** | 7 | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` `cors_deep_scan` `security_headers_score` | モダン API セキュリティテスト |
| **サプライチェーン** | 3 | `sbom_generate` `dependency_audit` `cicd_scan` | SBOM/依存関係/CI-CD セキュリティ |
| **クラウドネイティブ** | 3 | `k8s_scan` `grpc_scan` `aws_scan` | K8s/gRPC/AWS セキュリティ監査 |
| **レッドチームコア** | 14 | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` `payload_obfuscate` | ポストエクスプロイトと内部ネットワーク |
| **ラテラルムーブメント** | 9 | `lateral_ssh` `lateral_wmi` `lateral_winrm` `lateral_psexec` `lateral_ssh_tunnel` | 5 プロトコルによるラテラルムーブメント |
| **永続化** | 3 | `persistence_windows` `persistence_linux` `persistence_webshell` | Windows/Linux/Web |
| **AD 攻撃** | 3 | `ad_enumerate` `ad_kerberos_attack` `ad_spn_scan` | ドメインペネトレーション一式 |
| **CVE** | 8 | `cve_search` `cve_sync` `cve_stats` `poc_execute` `poc_list` `cve_auto_exploit` `cve_exploit_with_desc` `cve_generate_poc` | CVE インテリジェンス + AI PoC |
| **オーケストレーション** | 11 | `auto_pentest` `pentest_resume` `pentest_status` `pentest_phase` `smart_analyze` `attack_chain_plan` | 自動化ペネトレーション |
| **外部ツール** | 8 | `ext_nmap_scan` `ext_nuclei_scan` `ext_sqlmap_scan` `ext_ffuf_fuzz` `ext_masscan_scan` `ext_tool_chain` `ext_tools_status` | プロフェッショナルツール統合 |
| **AI 支援** | 3 | `smart_payload` `ai_attack_chain` `smart_pentest` | インテリジェント分析と意思決定 |
| **セッション/レポート** | 9 | `session_create` `session_status` `session_list` `session_complete` `generate_report` `export_findings` | セッション管理 + レポート |

---

## 外部ツール統合

ローカルにインストールされたプロフェッショナルセキュリティツールの統合をサポートし、より深い検出能力を実現します：

| ツール | 用途 | MCP コマンド | インストール要件 |
|--------|------|-------------|-----------------|
| **Nmap** | ポートスキャン + サービス識別 + NSE スクリプト | `ext_nmap_scan` | システム PATH またはパス設定 |
| **Nuclei** | 7000+ CVE/脆弱性テンプレートスキャン | `ext_nuclei_scan` | Go コンパイルまたはバイナリダウンロード |
| **SQLMap** | 6 種の SQL インジェクション技術 + WAF バイパス | `ext_sqlmap_scan` | Python スクリプト |
| **ffuf** | 高速ディレクトリ/パラメータファジング | `ext_ffuf_fuzz` | Go コンパイルまたはバイナリダウンロード |
| **Masscan** | 超高速大規模ポートスキャン | `ext_masscan_scan` | root/管理者権限が必要 |

### 外部ツールの設定

`config/external_tools.yaml` を編集してください：

```yaml
# ツールのベースディレクトリ
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

# ツールチェーン設定
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

### ツールチェーンオーケストレーション

```bash
# 完全偵察チェーン: masscan 高速発見 → nmap 詳細識別
ext_tool_chain target="192.168.1.0/24" chain_name="full_recon"

# 脆弱性スキャンチェーン: nuclei + sqlmap 連携検出
ext_tool_chain target="https://example.com" chain_name="vuln_scan"

# 外部ツールの状態確認
ext_tools_status
```

---

## 使用例

### コマンドライン使用

AI エディタで直接対話してツールを呼び出します：

#### 偵察と情報収集

```
# 完全偵察
「example.com に対する完全な偵察を実行してレポートを生成」

# ポートスキャン
「192.168.1.0/24 ネットワークのオープンポートをスキャン」

# サブドメイン列挙
「example.com のすべてのサブドメインを列挙」

# フィンガープリント識別
「ターゲットウェブサイトの技術スタックと WAF を識別」

# JS 分析
「ターゲットウェブサイトの JavaScript ファイルから機密情報を分析」
```

#### 脆弱性スキャン

```
# SQL インジェクション
「https://target.com/api?id=1 に SQL インジェクションが存在するか検出」

# XSS スキャン
「ターゲットフォームの XSS 脆弱性をスキャンして PoC を生成」

# API セキュリティ
「ターゲット API に対する完全な JWT/CORS/GraphQL セキュリティテストを実施」

# CVE 検索とエクスプロイト
「Apache Log4j 関連の CVE を検索して PoC を実行」
```

#### レッドチーム操作

```
# ラテラルムーブメント
「SMB 経由で 192.168.1.100 上で whoami コマンドを実行」

# C2 通信
「c2.example.com への DNS トンネル接続を開始」

# 永続化
「Windows ターゲットにスケジュールタスクによる永続化を確立」

# AD 攻撃
「ドメインコントローラーに対して Kerberoasting 攻撃を実行」
```

#### 自動化ペネトレーション

```
# 全自動ペネトレーションテスト
「https://target.com に対して全自動ペネトレーションテストを実行し、詳細レポートを生成」

# インテリジェント攻撃チェーン
「ターゲットを分析して最適な攻撃チェーン推奨を生成」

# チェックポイント復元
「以前中断されたペネトレーションテストセッションを再開」
```

### Python API 呼び出し

#### 基本的な使用方法

```python
import asyncio
from core.recon import StandardReconEngine, ReconConfig
from core.detectors import DetectorFactory

async def main():
    # 1. 偵察エンジン
    config = ReconConfig(
        quick_mode=False,
        enable_js_analysis=True,
        max_threads=50
    )
    engine = StandardReconEngine("https://target.com", config)
    recon_result = await engine.run()
    print(f"{len(recon_result.open_ports)} 個のオープンポートを発見")

    # 2. 脆弱性検出
    detector = DetectorFactory.create_composite(['sqli', 'xss', 'ssrf'])
    vuln_results = await detector.async_detect(
        url="https://target.com/api",
        params={'id': '1'}
    )

    for vuln in vuln_results:
        print(f"脆弱性を発見: {vuln.type} - {vuln.severity}")

asyncio.run(main())
```

#### ラテラルムーブメント

```python
from core.lateral import SMBLateralMove, SSHLateralMove

# SMB ラテラルムーブメント
smb = SMBLateralMove(
    target="192.168.1.100",
    credential={"username": "admin", "password_hash": "aad3b435..."}
)
result = await smb.execute_command("whoami")

# SSH トンネル
ssh = SSHLateralMove(
    target="192.168.1.100",
    credential={"username": "root", "private_key_path": "/path/to/key"}
)
await ssh.create_tunnel(local_port=8080, remote_port=80)
```

#### CVE 自動エクスプロイト

```python
from core.cve import CVEAutoExploit

exploit = CVEAutoExploit()

# 検索とエクスプロイト
results = await exploit.search_and_exploit(
    cve_id="CVE-2021-44228",
    target="https://target.com"
)

# AI による PoC 生成
poc_code = await exploit.generate_poc(
    cve_id="CVE-2024-12345",
    target_info={"os": "linux", "service": "nginx"}
)
```

#### セッション管理

```python
from core.session import SessionManager

manager = SessionManager()

# セッションの作成
session_id = await manager.create_session(
    target="https://target.com",
    scan_type="full_pentest"
)

# セッションの再開
await manager.resume_session(session_id)

# 結果のエクスポート
await manager.export_findings(session_id, format="html")
```

---

## アーキテクチャ設計

```
AutoRedTeam-Orchestrator/
├── mcp_stdio_server.py       # MCP サーバーエントリ (100+ ツール登録)
│
├── handlers/                 # MCP ツールハンドラー (16 モジュール)
│   ├── recon_handlers.py           # 偵察ツール (8)
│   ├── detector_handlers.py        # 脆弱性検出ツール (11)
│   ├── api_security_handlers.py    # API セキュリティツール (7)
│   ├── supply_chain_handlers.py    # サプライチェーンセキュリティツール (3)
│   ├── cloud_security_handlers.py  # クラウドセキュリティツール (3)
│   ├── cve_handlers.py             # CVE ツール (8)
│   ├── redteam_handlers.py         # レッドチームコアツール (14)
│   ├── lateral_handlers.py         # ラテラルムーブメントツール (9)
│   ├── persistence_handlers.py     # 永続化ツール (3)
│   ├── ad_handlers.py              # AD 攻撃ツール (3)
│   ├── orchestration_handlers.py   # オーケストレーションツール (11)
│   ├── external_tools_handlers.py  # 外部ツール (8)
│   ├── ai_handlers.py              # AI 支援ツール (3)
│   ├── session_handlers.py         # セッションツール (4)
│   ├── report_handlers.py          # レポートツール (2)
│   └── misc_handlers.py            # その他のツール (3)
│
├── core/                     # コアエンジン
│   ├── recon/               # 偵察エンジン (10 段階パイプライン)
│   │   ├── engine.py        # StandardReconEngine
│   │   ├── phases.py        # フェーズ定義
│   │   ├── port_scanner.py  # ポートスキャン
│   │   ├── subdomain.py     # サブドメイン列挙
│   │   ├── fingerprint.py   # フィンガープリント識別
│   │   ├── waf_detect.py    # WAF 検出
│   │   └── directory.py     # ディレクトリスキャン
│   │
│   ├── detectors/           # 脆弱性検出器
│   │   ├── base.py          # 基底クラス + コンポジットパターン
│   │   ├── sqli.py          # SQL インジェクション
│   │   ├── xss.py           # XSS
│   │   ├── ssrf.py          # SSRF
│   │   └── ...
│   │
│   ├── cve/                 # CVE インテリジェンス
│   │   ├── manager.py       # CVE データベース管理
│   │   ├── poc_engine.py    # PoC テンプレートエンジン
│   │   ├── auto_exploit.py  # 自動エクスプロイト
│   │   ├── ai_poc_generator.py  # AI PoC 生成
│   │   └── update_manager.py    # マルチソース同期
│   │
│   ├── c2/                  # C2 通信フレームワーク
│   │   ├── beacon.py        # Beacon 実装
│   │   ├── protocol.py      # プロトコル定義
│   │   └── tunnels/         # DNS/HTTP/WS/ICMP トンネル
│   │
│   ├── lateral/             # ラテラルムーブメント
│   │   ├── smb.py           # SMB (PTH/PTT)
│   │   ├── ssh.py           # SSH + SFTP
│   │   ├── wmi.py           # WMI
│   │   ├── winrm.py         # WinRM
│   │   └── psexec.py        # PSExec
│   │
│   ├── evasion/             # 回避と難読化
│   │   └── payload_obfuscator.py
│   │
│   ├── persistence/         # 永続化
│   │   ├── windows_persistence.py
│   │   ├── linux_persistence.py
│   │   └── webshell_manager.py
│   │
│   ├── credential/          # 認証情報取得
│   ├── ad/                  # AD 攻撃
│   ├── session/             # セッション管理
│   ├── tools/               # 外部ツール管理
│   └── security/            # セキュリティコンポーネント
│
├── modules/                  # 機能モジュール
│   ├── api_security/        # API セキュリティ
│   │   ├── jwt_security.py
│   │   ├── cors_security.py
│   │   ├── graphql_security.py
│   │   └── websocket_security.py
│   │
│   ├── supply_chain/        # サプライチェーンセキュリティ
│   │   ├── sbom_generator.py
│   │   ├── dependency_scanner.py
│   │   └── cicd_security.py
│   │
│   ├── cloud_security/      # クラウドセキュリティ
│   │   ├── kubernetes_enhanced.py
│   │   └── aws_tools.py
│   │
│   └── payload/             # Payload エンジン
│       ├── library.py       # 2000+ Payload
│       └── smart.py         # インテリジェント選択
│
├── utils/                    # ユーティリティ関数
│   ├── logger.py            # ロギング
│   ├── http_client.py       # HTTP クライアント
│   ├── validators.py        # 入力バリデーション
│   ├── report_generator.py  # レポート生成
│   └── config.py            # 設定管理
│
├── wordlists/                # 内蔵辞書
│   ├── directories/         # ディレクトリ辞書
│   ├── passwords/           # パスワード辞書
│   ├── usernames/           # ユーザー名辞書
│   └── subdomains/          # サブドメイン辞書
│
├── config/                   # 設定ファイル
│   └── external_tools.yaml  # 外部ツール設定
│
├── tests/                    # テストスイート (1075 テストケース)
└── docs/                     # ドキュメント
```

---

## 設定説明

### 環境変数 (.env)

```bash
# ========== セキュリティ設定 ==========
# マスターキー（初回実行時に自動生成）
REDTEAM_MASTER_KEY=

# MCP 認証キー（オプション）
AUTOREDTEAM_API_KEY=

# 認証モード: strict, permissive, disabled
AUTOREDTEAM_AUTH_MODE=permissive

# ========== API キー ==========
# AI 分析
OPENAI_API_KEY=your_key
ANTHROPIC_API_KEY=your_key

# 偵察
SHODAN_API_KEY=your_key
CENSYS_API_ID=your_id
CENSYS_API_SECRET=your_secret

# CVE インテリジェンス
NVD_API_KEY=your_key
GITHUB_TOKEN=your_token

# ========== プロキシ設定 ==========
HTTP_PROXY=
HTTPS_PROXY=
SOCKS_PROXY=

# ========== グローバル設定 ==========
VERIFY_SSL=false
RATE_LIMIT_DELAY=0.3
MAX_THREADS=50
REQUEST_TIMEOUT=10

# ========== ロギング ==========
LOG_LEVEL=INFO
LOG_FILE=logs/redteam.log
```

### pyproject.toml オプション依存関係

```bash
# 特定機能のみインストール
pip install autoredteam-orchestrator[ai]        # AI 機能
pip install autoredteam-orchestrator[recon]     # 偵察機能
pip install autoredteam-orchestrator[network]   # ネットワーク機能
pip install autoredteam-orchestrator[reporting] # レポート機能
pip install autoredteam-orchestrator[dev]       # 開発依存関係
```

---

## パフォーマンスチューニング

### 並行処理設定

```yaml
# config/performance.yaml
concurrency:
  max_threads: 100          # 最大スレッド数
  max_async_tasks: 200      # 最大非同期タスク数
  connection_pool_size: 50  # コネクションプールサイズ

rate_limiting:
  requests_per_second: 50   # 1 秒あたりのリクエスト数
  burst_size: 100           # バーストリクエスト数

timeouts:
  connect: 5                # 接続タイムアウト（秒）
  read: 30                  # 読み取りタイムアウト
  total: 120                # 合計タイムアウト
```

### メモリ最適化

```python
# 大規模スキャン時のストリーミング処理
engine = StandardReconEngine(
    target="192.168.0.0/16",
    config=ReconConfig(
        streaming_mode=True,    # ストリーミング処理を有効化
        batch_size=1000,        # バッチ処理サイズ
        memory_limit="2GB"      # メモリ制限
    )
)
```

### 分散スキャン

```python
# Celery 分散タスクキューを使用
from core.distributed import DistributedScanner

scanner = DistributedScanner(
    broker="redis://localhost:6379",
    workers=10
)
await scanner.scan_targets(["192.168.1.0/24", "192.168.2.0/24"])
```

---

## トラブルシューティング

### よくある問題

| 問題 | 原因 | 解決方法 |
|------|------|---------|
| MCP サーバーに接続できない | パスの誤りまたは Python 環境の問題 | 設定内の絶対パスを確認し、正しい Python インタープリターを使用していることを確認 |
| インポートエラー | PYTHONPATH が未設定 | 設定に `PYTHONPATH` 環境変数を追加 |
| 外部ツール呼び出しの失敗 | ツール未インストールまたはパスの誤り | `ext_tools_status` を実行してツール状態を確認 |
| CVE データベース同期の失敗 | ネットワーク問題または API レート制限 | ネットワークを確認し、NVD_API_KEY を設定してレート制限を緩和 |
| スキャン速度が遅い | 並行処理設定が低すぎる | `MAX_THREADS` と `RATE_LIMIT_DELAY` を調整 |
| メモリオーバーフロー | 大規模スキャン | `streaming_mode` を有効化し、`memory_limit` を設定 |

### デバッグモード

```bash
# 詳細ログを有効化
LOG_LEVEL=DEBUG python mcp_stdio_server.py

# 構文エラーの確認
python -m py_compile mcp_stdio_server.py

# 単体テストの実行
pytest tests/test_recon.py::test_port_scan -v
```

### ログ分析

```bash
# 最近のエラーを表示
tail -f logs/redteam.log | grep ERROR

# パフォーマンスボトルネックの分析
grep "elapsed" logs/redteam.log | sort -t: -k4 -n
```

---

## よくある質問 (FAQ)

<details>
<summary><b>Q: ネットワークのない環境で使用するには？</b></summary>

A:
1. CVE データベースを事前にダウンロード: `python core/cve/update_manager.py sync --offline-export`
2. ローカル辞書ファイルを使用
3. ネットワークが必要な機能を無効化: `OFFLINE_MODE=true`

</details>

<details>
<summary><b>Q: カスタム検出器を追加するには？</b></summary>

A:
1. `core/detectors/` に新しいファイルを作成
2. `BaseDetector` クラスを継承
3. `detect()` と `async_detect()` メソッドを実装
4. `handlers/detector_handlers.py` に MCP ツールを登録

```python
from core.detectors.base import BaseDetector

class CustomDetector(BaseDetector):
    async def async_detect(self, url, params):
        # 検出ロジックを実装
        return VulnResult(...)
```

</details>

<details>
<summary><b>Q: 他の外部ツールを統合するには？</b></summary>

A:
1. `config/external_tools.yaml` にツール設定を追加
2. `handlers/external_tools_handlers.py` に MCP ツール関数を追加
3. `core/tools/tool_manager.py` の `execute_tool()` メソッドを使用

</details>

<details>
<summary><b>Q: WAF によるブロックに対処するには？</b></summary>

A:
1. `smart_payload` ツールを使用して WAF バイパス Payload を自動選択
2. プロキシプールを設定: `PROXY_POOL=true`
3. トラフィック変異を有効化: `traffic_mutation=true`
4. スキャン速度を低下: `RATE_LIMIT_DELAY=1.0`

</details>

<details>
<summary><b>Q: どのレポートフォーマットに対応していますか？</b></summary>

A:
- JSON（機械可読）
- HTML（チャート付きビジュアルレポート）
- Markdown（Git/Wiki 向け）
- PDF（`reportlab` のインストールが必要）
- DOCX（`python-docx` のインストールが必要）

</details>

---

## 更新履歴

### v3.0.1 (2026-01-30) - 品質強化

**追加**
- CVE 自動エクスプロイト強化 (`cve_auto_exploit`, `cve_exploit_with_desc`, `cve_generate_poc`)
- AI PoC ジェネレーター (`core/cve/ai_poc_generator.py`)

**修正**
- バージョン番号統一 - VERSION/pyproject.toml/ソースコード全体で同期
- ToolCounter 修正 - external_tools/lateral/persistence/ad カテゴリを追加
- テスト修正 - 古くなったテストケース参照を更新
- スレッドセーフティ - beacon.py の状態管理に threading.Lock を追加

**改善**
- CI/CD 強化 - lint チェック失敗でビルドをブロック
- テストカバレッジ閾値を 50% に引き上げ
- 依存関係バージョン制約 - 互換性問題防止のため上限を追加

### v3.0.0 (2026-01-18) - アーキテクチャ強化

**追加**
- 外部ツール統合 - 8 つの外部ツール MCP コマンド
- ツールチェーンオーケストレーション - YAML 駆動のマルチツール組み合わせ
- Handler モジュール化 - 16 の独立 Handler モジュール

**改善**
- MCP ツール数が 100+ に到達
- フィードバックループエンジン - インテリジェントエクスプロイトオーケストレーター
- WAF バイパス - Payload 変異エンジンの強化

<details>
<summary><b>以前のバージョンを表示</b></summary>

### v2.8.0 (2026-01-15) - セキュリティ強化
- 入力バリデーション強化、例外処理の統一、パフォーマンス最適化

### v2.7.1 (2026-01-10) - Web スキャンエンジン
- Web Scanner モジュール、内蔵辞書ライブラリ

### v2.7.0 (2026-01-09) - アーキテクチャリファクタリング
- モジュール化リファクタリング、StandardReconEngine

### v2.6.0 (2026-01-07) - API/サプライチェーン/クラウドセキュリティ
- JWT/CORS/GraphQL/WebSocket セキュリティテスト
- SBOM 生成、K8s/gRPC セキュリティ監査

</details>

---

## ロードマップ

### 進行中
- [ ] Web UI 管理インターフェース
- [ ] 分散スキャンクラスター

### 計画中
- [ ] 追加クラウドプラットフォーム対応 (GCP/Alibaba Cloud/Tencent Cloud)
- [ ] Burp Suite プラグイン統合
- [ ] モバイルアプリケーションセキュリティテスト
- [ ] AI 自律攻撃エージェント

### 完了
- [x] Red Team フルツールチェーン
- [x] CVE インテリジェンスと AI PoC 生成
- [x] API/サプライチェーン/クラウドセキュリティモジュール
- [x] 全自動ペネトレーションテストフレームワーク
- [x] 外部ツール統合

---

## コントリビューションガイド

あらゆる形式のコントリビューションを歓迎します！

### クイックスタート

```bash
# 1. Fork してクローン
git clone https://github.com/YOUR_USERNAME/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. ブランチを作成
git checkout -b feature/your-feature

# 3. 開発依存関係をインストール
pip install -r requirements-dev.txt
pre-commit install

# 4. 開発とテスト
pytest tests/ -v

# 5. PR を提出
git push origin feature/your-feature
```

### コミット規約

[Conventional Commits](https://www.conventionalcommits.org/) フォーマットを使用：

- `feat:` 新機能
- `fix:` バグ修正
- `docs:` ドキュメント更新
- `refactor:` リファクタリング
- `test:` テスト関連
- `chore:` ビルド/ツール

詳細は [CONTRIBUTING.md](CONTRIBUTING.md) を参照

---

## セキュリティポリシー

- **責任ある開示**: セキュリティ脆弱性を発見した場合は [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com) までご連絡ください
- **許可された使用**: 本ツールは許可されたセキュリティテストと研究のみに使用してください
- **コンプライアンス**: 使用前に現地の法律法規を遵守していることをご確認ください

詳細は [SECURITY.md](SECURITY.md) を参照

---

## 謝辞

- [Nuclei](https://github.com/projectdiscovery/nuclei) - 脆弱性スキャンエンジン設計
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - SQL インジェクション検出のアプローチ
- [Impacket](https://github.com/fortra/impacket) - ネットワークプロトコル実装
- [MCP Protocol](https://modelcontextprotocol.io/) - AI ツールプロトコル標準

---

## ライセンス

本プロジェクトは **MIT ライセンス** の下でライセンスされています - 詳細は [LICENSE](LICENSE) ファイルを参照

---

## 免責事項

> **警告**: 本ツールは**許可されたセキュリティテストと研究**のみに使用してください。
>
> 本ツールを使用してシステムをテストする前に、以下を確認してください：
> - ターゲットシステム所有者からの**書面による許可**を取得していること
> - 現地の**法律法規**を遵守していること
> - **職業倫理**基準に従っていること
>
> 許可なく本ツールを使用することは法律に違反する可能性があります。**開発者はいかなる悪用についても責任を負いません**。

---

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Coff0xc">Coff0xc</a></b>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB">Discord</a> ·
  <a href="mailto:Coff0xc@protonmail.com">Email</a> ·
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues">Issues</a>
</p>
