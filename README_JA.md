<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>AI駆動の自動レッドチームオーケストレーションフレームワーク</b><br>
  <i>クロスプラットフォーム · 74 MCPツール · 2000+ ペイロード · ATT&CK完全対応</i>
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
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License"></a>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-コミュニティ参加-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-ドキュメント-blue?style=for-the-badge&logo=gitbook&logoColor=white" alt="Wiki"></a>
</p>

---

## 📖 目次

- [主な機能](#-主な機能)
- [ATT&CKカバレッジマトリックス](#️-attckカバレッジマトリックス)
- [クイックスタート](#-クイックスタート)
- [MCP設定](#-mcp設定)
- [ツールマトリックス](#️-ツールマトリックス)
- [使用例](#-使用例)
- [アーキテクチャ](#-アーキテクチャ)
- [更新履歴](#-更新履歴)
- [ロードマップ](#️-ロードマップ)
- [貢献ガイド](#-貢献ガイド)
- [セキュリティポリシー](#-セキュリティポリシー)
- [謝辞](#-謝辞)
- [ライセンス](#-ライセンス)

---

## 🎯 主な機能

<table>
<tr>
<td width="50%">

### 🤖 AIネイティブ設計
- **スマートフィンガープリント** - ターゲット技術スタックの自動検出
- **攻撃チェーン計画** - AI駆動の攻撃パス推奨
- **履歴フィードバック学習** - 継続的な戦略最適化
- **自動ペイロード選択** - WAF対応のインテリジェント変異
- **AI PoC生成** - CVE説明から攻撃コードを生成

</td>
<td width="50%">

### ⚡ フルオートメーション
- **10フェーズ偵察パイプライン** - DNS/ポート/フィンガープリント/WAF/JS分析
- **脆弱性発見と検証** - 自動スキャン + OOB検証
- **スマート攻撃オーケストレーション** - フィードバックループ + 自動リトライ
- **ワンクリック専門レポート** - JSON/HTML/Markdownフォーマット
- **セッションチェックポイント復元** - 中断されたスキャンの再開

</td>
</tr>
<tr>
<td width="50%">

### 🔴 レッドチームツールキット
- **横方向移動** - SMB/SSH/WMI/WinRM/PSExec
- **C2通信** - Beacon + DNS/HTTP/WebSocketトンネル
- **回避と難読化** - XOR/AES/Base64多層エンコーディング
- **永続化** - Windowsレジストリ/スケジュールタスク/Linux cron
- **認証情報アクセス** - メモリ抽出/ファイル検索
- **AD攻撃** - Kerberoasting/AS-REP Roasting

</td>
<td width="50%">

### 🛡️ セキュリティ拡張
- **APIセキュリティ** - JWT/CORS/GraphQL/WebSocket/OAuth
- **サプライチェーンセキュリティ** - SBOM生成/依存関係監査/CI-CDスキャン
- **クラウドネイティブセキュリティ** - K8s監査/gRPCテスト/AWSスキャン
- **CVEインテリジェンス** - NVD/Nuclei/ExploitDB多ソース同期
- **WAFバイパス** - 2000+ペイロードスマート変異エンジン

</td>
</tr>
</table>

---

## ⚔️ ATT&CKカバレッジマトリックス

| 戦術 | カバー技術 | ツール数 | 状態 |
|------|-----------|----------|------|
| **偵察** | アクティブスキャン、パッシブ収集、OSINT | 12+ | ✅ 完了 |
| **リソース開発** | ペイロード生成、難読化 | 4+ | ✅ 完了 |
| **初期アクセス** | Web攻撃、CVE攻撃 | 19+ | ✅ 完了 |
| **実行** | コマンドインジェクション、コード実行 | 5+ | ✅ 完了 |
| **永続化** | レジストリ、スケジュールタスク、Webshell | 3+ | ✅ 完了 |
| **権限昇格** | UACバイパス、トークン偽装 | 2+ | ⚠️ 部分的 |
| **防御回避** | AMSIバイパス、ETWバイパス、難読化 | 4+ | ✅ 完了 |
| **認証情報アクセス** | メモリ抽出、ファイル検索 | 2+ | ✅ 完了 |
| **発見** | ネットワークスキャン、サービス列挙 | 8+ | ✅ 完了 |
| **横方向移動** | SMB/SSH/WMI/WinRM | 6+ | ✅ 完了 |
| **収集** | データ集約、機密ファイル | 2+ | ✅ 完了 |
| **C2** | HTTP/DNS/WebSocketトンネル | 4+ | ✅ 完了 |
| **データ流出** | DNS/HTTP/ICMP流出 | 3+ | ✅ 完了 |

---

## 📦 クイックスタート

### システム要件

| コンポーネント | 要件 |
|----------------|------|
| **OS** | Windows 10+, Linux (Ubuntu 20.04+), macOS 12+ |
| **Python** | 3.10以上 |
| **メモリ** | 4GB+推奨 |
| **ネットワーク** | アウトバウンドHTTP/HTTPSアクセス |

### インストール

```bash
# リポジトリをクローン
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 依存関係をインストール
pip install -r requirements.txt

# インストールを確認
python mcp_stdio_server.py --version
```

<details>
<summary><b>🔧 オプション：最小インストール</b></summary>

```bash
# コア依存関係のみ（偵察 + 脆弱性検出）
pip install -r requirements-core.txt

# オプションモジュール（レッドチーム + クラウドセキュリティ）
pip install -r requirements-optional.txt
```

</details>

<details>
<summary><b>🐳 Dockerデプロイ</b></summary>

```bash
docker pull coff0xc/autoredteam:latest
docker run -it --rm coff0xc/autoredteam
```

</details>

### サービス起動

```bash
python mcp_stdio_server.py
```

---

## 🔧 MCP設定

AIエディタのMCP設定ファイルに以下の設定を追加：

<details>
<summary><b>📘 MCP対応AIエディタ</b></summary>

**一般的な設定ファイルの場所：**
- Windows: `%APPDATA%\<エディタ名>\config.json`
- macOS: `~/Library/Application Support/<エディタ名>/config.json`
- Linux: `~/.config/<エディタ名>/config.json`

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

**設定ファイル：** `~/.cursor/mcp.json`

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

**設定ファイル：** `~/.codeium/windsurf/mcp_config.json`

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

**設定ファイル：** `~/.kiro/mcp.json`

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

## 🛠️ ツールマトリックス

| カテゴリ | 数 | 主な機能 | 主要ツール |
|----------|-----|----------|------------|
| **🔍 偵察** | 12+ | 情報収集とアセット発見 | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` |
| **🐛 脆弱性検出** | 19+ | OWASP Top 10 + ロジック脆弱性 | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` |
| **🌐 Webスキャン** | 4+ | 攻撃面発見と脆弱性オーケストレーション | `vuln_scan` `security_headers_scan` `cors_scan` `idor_scan` |
| **🔐 APIセキュリティ** | 11+ | 現代APIセキュリティテスト | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` |
| **📦 サプライチェーン** | 5+ | 依存関係とビルドセキュリティ | `sbom_generate` `dependency_audit` `cicd_scan` |
| **☁️ クラウドネイティブ** | 8+ | コンテナとクラスタセキュリティ | `k8s_scan` `grpc_scan` `aws_scan` |
| **🔴 レッドチーム** | 10+ | ポストエクスプロイトと内部ネットワーク | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` |
| **📋 CVE** | 6+ | 脆弱性インテリジェンスと攻撃 | `cve_search` `cve_sync` `poc_execute` |
| **🤖 自動化** | 5+ | 完全自動ペネトレーションテスト | `auto_pentest` `smart_analyze` `attack_chain_plan` `waf_bypass` |

---

## 💬 使用例

AIエディタで直接チャットしてツールを呼び出す：

### 偵察と情報収集
```
🔍 「example.comの完全な偵察を実行してレポートを生成」
🔍 「192.168.1.0/24ネットワークの開いているポートをスキャン」
🔍 「example.comのサブドメインを列挙」
🔍 「ターゲットウェブサイトの技術スタックとWAFを識別」
```

### 脆弱性スキャンと攻撃
```
🎯 「ターゲットがSQLインジェクションに脆弱かどうかをチェック」
🎯 「ターゲットAPIの完全なセキュリティスキャンを実行」
🎯 「Log4j関連のCVEを検索してPoCを実行」
🎯 「WAFバイパスXSSペイロードを生成」
```

### レッドチーム操作
```
🔴 「SMB経由でターゲットマシンでコマンドを実行」
🔴 「サーバーへのC2 Beacon接続を開始」
🔴 「ターゲットシステムで機密認証情報を検索」
🔴 「AMSIバイパスコードを生成」
```

### 自動ペネトレーションテスト
```
⚡ 「https://target.comに対して完全な自動ペネトレーションテストを実行」
⚡ 「ターゲットを分析して攻撃チェーンの推奨を生成」
⚡ 「以前に中断されたペンテストセッションを再開」
```

---

## 🏗️ アーキテクチャ

```
AutoRedTeam-Orchestrator/
├── 📄 mcp_stdio_server.py      # MCPサーバーエントリ（74ツール登録）
│
├── 📂 handlers/                # MCPツールハンドラー（統一出力スキーマ）
│   ├── recon.py               # 偵察ツール
│   ├── detector.py            # 脆弱性検出
│   └── redteam.py             # レッドチームツール
│
├── 📂 core/                    # コアエンジン
│   ├── recon/                 # 偵察エンジン（10フェーズパイプライン）
│   ├── detectors/             # 脆弱性検出器
│   ├── exploit/               # 攻撃エンジン
│   ├── c2/                    # C2通信フレームワーク
│   ├── lateral/               # 横方向移動（SMB/SSH/WMI）
│   ├── evasion/               # 回避とバイパス
│   ├── persistence/           # 永続化モジュール
│   ├── credential/            # 認証情報アクセス
│   └── cve/                   # CVEインテリジェンス管理
│
├── 📂 modules/                 # 機能モジュール
│   ├── api_security/          # APIセキュリティテスト
│   ├── cloud_security/        # クラウドセキュリティ監査
│   ├── supply_chain/          # サプライチェーンセキュリティ
│   └── smart_payload_engine.py # スマートペイロードエンジン
│
├── 📂 wordlists/               # 内蔵辞書
│
└── 📂 utils/                   # ユーティリティ関数
```

---

## 📋 更新履歴

### v3.0.0 (2026-01-18) - アーキテクチャ強化

- 🚀 **ツール拡張**: MCPツールが74に
- 🔄 **フィードバックループ**: 自動リトライ付きスマート攻撃オーケストレーター
- 🛡️ **WAFバイパス**: 30+エンコーディングメソッド付きペイロード変異エンジン強化
- 📊 **レポート最適化**: エグゼクティブサマリーとリスクスコアリング追加

### v2.8.0 (2026-01-15) - セキュリティ強化

- 🔒 **入力検証**: すべてのユーザー入力に対するセキュリティチェック強化
- ⚙️ **例外処理**: 安定性向上のための統一例外システム
- 🚄 **パフォーマンス**: 並行性制御とリソース管理の改善

---

## 🛤️ ロードマップ

- [ ] 🖥️ Web UI管理インターフェース
- [ ] 🌐 分散スキャンクラスタ
- [ ] ☁️ その他のクラウドプラットフォーム（GCP/Alibaba Cloud/Tencent Cloud）
- [ ] 🤖 AI自動攻撃強化
- [ ] 📚 その他のCVE PoCテンプレート
- [ ] 🔌 Burp Suiteプラグイン統合
- [x] ✅ フルレッドチームツールキット
- [x] ✅ CVEインテリジェンスとAI PoC生成
- [x] ✅ API/サプライチェーン/クラウドセキュリティモジュール
- [x] ✅ 完全自動ペネトレーションテストフレームワーク

---

## 🤝 貢献ガイド

すべての形式の貢献を歓迎します！

1. このリポジトリを**Fork**する
2. 機能ブランチを作成 (`git checkout -b feature/AmazingFeature`)
3. 変更をコミット (`git commit -m 'Add AmazingFeature'`)
4. ブランチにプッシュ (`git push origin feature/AmazingFeature`)
5. **Pull Request**を提出

詳細は [CONTRIBUTING.md](CONTRIBUTING.md) を参照

---

## 🔒 セキュリティポリシー

- 🚨 **責任ある開示**: セキュリティ脆弱性は [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com) に報告してください
- ⚠️ **許可された使用のみ**: このツールは許可されたセキュリティテストと研究専用です
- 📜 **コンプライアンス**: 使用前に現地の法律を確認してください

詳細は [SECURITY.md](SECURITY.md) を参照

---

## 🙏 謝辞

インスピレーションを与えてくれたオープンソースプロジェクトに感謝：

- [Nuclei](https://github.com/projectdiscovery/nuclei) - 脆弱性スキャナエンジン設計
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - SQLインジェクション検出アプローチ
- [Impacket](https://github.com/fortra/impacket) - ネットワークプロトコル実装
- [MCP Protocol](https://modelcontextprotocol.io/) - AIツールプロトコル標準

---

## 📜 ライセンス

このプロジェクトは **MITライセンス** の下でライセンスされています - 詳細は [LICENSE](LICENSE) ファイルを参照

---

## ⚖️ 免責事項

> **警告**: このツールは**許可されたセキュリティテストと研究専用**です。
>
> このツールを使用してシステムをテストする前に、以下を確認してください：
> - システム所有者からの**書面による許可**を取得
> - **現地の法律と規制**を遵守
> - **職業倫理**基準に従う
>
> 許可されていない使用は法律に違反する可能性があります。**開発者は誤用について責任を負いません**。

---

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Coff0xc">Coff0xc</a></b>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-コミュニティ参加-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="mailto:Coff0xc@protonmail.com"><img src="https://img.shields.io/badge/Email-お問い合わせ-EA4335?style=for-the-badge&logo=gmail&logoColor=white" alt="Email"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues"><img src="https://img.shields.io/badge/Issues-問題報告-181717?style=for-the-badge&logo=github&logoColor=white" alt="Issues"></a>
</p>
