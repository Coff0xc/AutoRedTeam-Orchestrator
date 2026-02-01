<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>AI 駆動の自動レッドチームオーケストレーションフレームワーク</b><br>
  <sub>クロスプラットフォーム | 101 MCP ツール | 2000+ Payload | ATT&CK 全面カバー | ナレッジグラフ強化</sub>
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
  <img src="https://img.shields.io/badge/Tools-101-FF6B6B?style=flat-square" alt="Tools">
  <img src="https://img.shields.io/badge/Tests-1461-4CAF50?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-コミュニティ-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-ドキュメント-blue?style=flat-square&logo=gitbook&logoColor=white" alt="Wiki"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/actions"><img src="https://img.shields.io/github/actions/workflow/status/Coff0xc/AutoRedTeam-Orchestrator/ci.yml?style=flat-square&logo=github-actions&logoColor=white&label=CI" alt="CI"></a>
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/demo.gif" alt="Demo" width="700">
</p>

## ハイライト

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     AutoRedTeam-Orchestrator v3.0.1                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  ● 101 MCP ツール      ● 2000+ Payload      ● 1461 テストケース            │
│  ● 10 段階偵察         ● 19 脆弱性検出器    ● 5 プロトコルラテラル         │
│  ● MCTS 攻撃プランナー ● ナレッジグラフ     ● AI PoC 生成                  │
│  ● OOB 誤検知低減      ● DI コンテナ        ● MCP セキュリティミドルウェア │
├─────────────────────────────────────────────────────────────────────────────┤
│  対応 AI エディタ: Cursor | Windsurf | Kiro | Claude Desktop | VS Code     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 目次

- [プロジェクト概要](#プロジェクト概要)
- [コア機能](#コア機能)
- [設計思想](#設計思想)
- [アーキテクチャ](#アーキテクチャ)
- [ATT&CK カバレッジマトリックス](#attck-カバレッジマトリックス)
- [クイックスタート](#クイックスタート)
  - [システム要件](#システム要件)
  - [インストール方法](#インストール方法)
  - [インストール確認](#インストール確認)
- [MCP 設定](#mcp-設定)
- [ツールマトリックス (101 MCP ツール)](#ツールマトリックス-101-mcp-ツール)
- [コアモジュール](#コアモジュール)
- [外部ツール統合](#外部ツール統合)
- [使用例](#使用例)
  - [自然言語コマンド](#自然言語コマンド)
  - [Python API](#python-api)
- [設定説明](#設定説明)
- [パフォーマンスチューニング](#パフォーマンスチューニング)
- [トラブルシューティング](#トラブルシューティング)
- [よくある質問 (FAQ)](#よくある質問-faq)
- [開発ガイド](#開発ガイド)
- [更新履歴](#更新履歴)
- [ロードマップ](#ロードマップ)
- [コントリビューションガイド](#コントリビューションガイド)
- [セキュリティポリシー](#セキュリティポリシー)
- [謝辞](#謝辞)
- [ライセンス](#ライセンス)
- [免責事項](#免責事項)

---

## プロジェクト概要

**AutoRedTeam-Orchestrator** は、[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) に基づく AI 駆動の自動化ペネトレーションテストフレームワークです。101 のセキュリティツールを MCP ツールとしてカプセル化し、MCP 対応 AI エディタ (Cursor, Windsurf, Kiro, Claude Desktop) とシームレスに統合することで、自然言語駆動の自動化セキュリティテストを実現します。

### なぜ AutoRedTeam-Orchestrator を選ぶのか？

| 特徴 | 従来のツール | AutoRedTeam |
|------|-------------|-------------|
| **インタラクション方式** | コマンドライン暗記 | 自然言語対話 |
| **学習コスト** | 高い（大量のパラメータ暗記が必要） | 低い（AI が自動的にツールを選択） |
| **ツール統合** | 手動でツール切り替え | 101 ツールの統一インターフェース |
| **攻撃計画** | 手動計画 | **MCTS アルゴリズム + ナレッジグラフ** |
| **誤検知低減** | 手動検証 | **OOB + 統計的検証** |
| **レポート生成** | 手動作成 | ワンクリックで専門レポート生成 |
| **セッション管理** | なし | チェックポイント復元対応 |
| **セキュリティ** | ツールごとに異なる | **MCP セキュリティミドルウェアで統一保護** |

### 類似プロジェクトとの比較

| 特徴 | AutoRedTeam | Nuclei | SQLMap | Metasploit |
|------|-------------|--------|--------|------------|
| AI ネイティブ | ✅ | ❌ | ❌ | ❌ |
| MCP プロトコル | ✅ | ❌ | ❌ | ❌ |
| 自然言語対応 | ✅ | ❌ | ❌ | ❌ |
| MCTS 攻撃計画 | ✅ | ❌ | ❌ | ❌ |
| ナレッジグラフ | ✅ | ❌ | ❌ | ❌ |
| 完全自動化 | ✅ | 部分的 | 部分的 | 部分的 |
| 誤検知フィルター | マルチメソッド | 基本 | 中程度 | 基本 |

---

## コア機能

<table>
<tr>
<td width="50%">

### AI ネイティブ設計

- **インテリジェントフィンガープリント** - ターゲット技術スタック (CMS/フレームワーク/WAF) の自動識別
- **MCTS 攻撃計画** - モンテカルロ木探索駆動の最適攻撃パス
- **ナレッジグラフ** - セッション間学習による永続的な攻撃知識
- **履歴フィードバック学習** - 攻撃戦略の継続的最適化
- **自動 Payload 選択** - WAF 対応インテリジェント変異
- **AI PoC 生成** - CVE 説明からエクスプロイトコードを生成

</td>
<td width="50%">

### フルプロセス自動化

- **10 段階偵察パイプライン** - DNS/ポート/フィンガープリント/WAF/サブドメイン/ディレクトリ/JS 分析
- **脆弱性発見と検証** - 自動スキャン + **マルチメソッド検証**
- **インテリジェントエクスプロイトオーケストレーション** - フィードバックループエンジン + 自動リトライ
- **ワンクリック専門レポート** - JSON/HTML/Markdown フォーマット
- **セッションチェックポイント復元** - 中断からの再開

</td>
</tr>
<tr>
<td width="50%">

### Red Team ツールチェーン

- **ラテラルムーブメント** - SMB/SSH/WMI/WinRM/PSExec（5 プロトコル）
- **C2 通信** - Beacon + DNS/HTTP/WebSocket/ICMP トンネル
- **難読化・回避** - XOR/AES/Base64/カスタムエンコーダー
- **永続化** - Windows レジストリ/スケジュールタスク/WMI/Linux cron/Webshell
- **認証情報取得** - メモリ抽出/ファイル検索/パスワードスプレー
- **AD 攻撃** - Kerberoasting/AS-REP Roasting/SPN スキャン

</td>
<td width="50%">

### セキュリティ機能拡張

- **API セキュリティ** - JWT/CORS/GraphQL/WebSocket/OAuth テスト
- **サプライチェーンセキュリティ** - SBOM 生成/依存関係監査/CI-CD スキャン
- **クラウドネイティブセキュリティ** - K8s RBAC/Pod セキュリティ/gRPC/AWS 監査
- **CVE インテリジェンス** - NVD/Nuclei/ExploitDB マルチソース同期
- **WAF バイパス** - 2000+ Payload + 30 以上のエンコード方式

</td>
</tr>
</table>

---

## 設計思想

### コア設計原則

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              設計思想                                       │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│   1. AI ネイティブ                                                         │
│      └─「AI ラッパー」ではなく、アーキテクチャレベルで AI 向けに設計       │
│         └─ ネイティブ MCP プロトコルサポート                               │
│         └─ 自然言語駆動のツール選択                                        │
│         └─ MCTS アルゴリズム駆動の攻撃計画                                 │
│                                                                            │
│   2. 検証可能なセキュリティ                                                │
│      └─ マルチメソッドクロス検証で誤検知を低減                             │
│         └─ 統計的検証（有意性検定）                                        │
│         └─ Boolean ブラインド検証（True/False レスポンス比較）             │
│         └─ 時間ベースブラインド検証（遅延検出）                            │
│         └─ OOB 検証（DNS/HTTP コールバック）                               │
│                                                                            │
│   3. ナレッジの永続化                                                      │
│      └─ 攻撃知識がセッション間で永続化                                     │
│         └─ ナレッジグラフがターゲット、脆弱性、認証情報の関係を保存        │
│         └─ 攻撃パス成功率を履歴から計算                                    │
│         └─ 類似ターゲット識別で新規ターゲットテストを加速                  │
│                                                                            │
│   4. セキュリティ・バイ・デザイン                                          │
│      └─ セキュリティはコアアーキテクチャであり、後付けではない             │
│         └─ MCP セキュリティミドルウェア：入力検証、レート制限              │
│         └─ TOCTOU 安全性：アトミック操作、競合状態保護                     │
│         └─ メモリ安全性：リソース制限、自動クリーンアップ                  │
│                                                                            │
│   5. 拡張可能なアーキテクチャ                                              │
│      └─ 依存性注入コンテナによる柔軟なサービス構成                         │
│         └─ モジュラー Handler 設計                                         │
│         └─ 外部ツール YAML 設定                                            │
│         └─ Detector コンポジットパターンで任意の組み合わせ                 │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### 技術的意思決定マトリックス

| 決定事項 | オプション | 選択 | 理由 |
|----------|-----------|------|------|
| **通信** | REST / gRPC / MCP | MCP | AI エディタネイティブサポート、シームレスな NLP インタラクション |
| **攻撃計画** | ルールエンジン / MCTS / RL | MCTS | オンライン計画、事前学習不要、UCB1 による探索-活用バランス |
| **知識保存** | SQL / Graph DB / メモリ | メモリグラフ + オプション Neo4j | 依存関係ゼロ起動、高性能クエリ、オプションの永続化 |
| **依存関係管理** | グローバル / DI | DI コンテナ | テスト容易性、置換可能性、ライフサイクル管理 |
| **並行処理** | スレッド / asyncio / ハイブリッド | asyncio 主体 | IO バウンドに最適、Python ネイティブサポート |
| **ハッシュ** | MD5 / SHA256 | SHA256 | より高いセキュリティ、現代の標準 |

---

## アーキテクチャ

### ハイレベルアーキテクチャ

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AI エディタ層                                  │
│        Cursor  │  Windsurf  │  Kiro  │  Claude Desktop  │  VS Code         │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ MCP プロトコル (JSON-RPC over stdio)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MCP サーバーエントリ                                │
│                      mcp_stdio_server.py                                   │
│                        (101 ツール登録)                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                        MCP セキュリティミドルウェア                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│  │ 入力検証    │  │ レート制限  │  │ 操作認可    │  │ @secure_tool│       │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│   handlers/       │   │   core/           │   │   modules/        │
│   MCP ハンドラー  │   │   コアエンジン    │   │   機能モジュール  │
├───────────────────┤   ├───────────────────┤   ├───────────────────┤
│ • recon_handlers  │   │ • recon/          │   │ • api_security/   │
│ • detector_hdlrs  │   │   10 段階偵察     │   │   JWT/CORS/GQL    │
│ • cve_handlers    │   │ • detectors/      │   │ • supply_chain/   │
│ • redteam_hdlrs   │   │   脆弱性検出      │   │   SBOM/Deps       │
│ • lateral_hdlrs   │   │ • mcts_planner    │   │ • cloud_security/ │
│ • external_hdlrs  │   │   MCTS 計画       │   │   K8s/gRPC/AWS    │
│ • ai_handlers     │   │ • knowledge/      │   │ • payload/        │
│ • session_hdlrs   │   │   ナレッジグラフ  │   │   2000+ Payload   │
└───────────────────┘   │ • container       │   └───────────────────┘
                        │   DI コンテナ     │
                        │ • c2/             │
                        │   C2 通信         │
                        │ • lateral/        │
                        │   ラテラル移動    │
                        │ • cve/            │
                        │   CVE インテル    │
                        └───────────────────┘
```

### ディレクトリ構造

```
AutoRedTeam-Orchestrator/
├── mcp_stdio_server.py          # MCP サーバーエントリ (101 ツール登録)
├── VERSION                      # バージョンファイル
├── pyproject.toml               # プロジェクト設定
├── requirements.txt             # 本番依存関係
├── requirements-dev.txt         # 開発依存関係
│
├── handlers/                    # MCP ツールハンドラー (16 モジュール)
│   ├── recon_handlers.py        # 偵察ツール (8)
│   ├── detector_handlers.py     # 脆弱性検出ツール (11)
│   ├── api_security_handlers.py # API セキュリティツール (7)
│   ├── supply_chain_handlers.py # サプライチェーンツール (3)
│   ├── cloud_security_handlers.py # クラウドセキュリティツール (3)
│   ├── cve_handlers.py          # CVE ツール (8)
│   ├── redteam_handlers.py      # レッドチームコアツール (14)
│   ├── lateral_handlers.py      # ラテラルムーブメントツール (9)
│   ├── persistence_handlers.py  # 永続化ツール (3)
│   ├── ad_handlers.py           # AD 攻撃ツール (3)
│   ├── orchestration_handlers.py # オーケストレーションツール (11)
│   ├── external_tools_handlers.py # 外部ツール (8)
│   ├── ai_handlers.py           # AI 支援ツール (3)
│   ├── session_handlers.py      # セッションツール (4)
│   ├── report_handlers.py       # レポートツール (2)
│   └── misc_handlers.py         # その他のツール (3)
│
├── core/                        # コアエンジン
│   ├── __init__.py              # バージョン定義
│   │
│   ├── security/                # セキュリティコンポーネント ⭐ v3.0.2
│   │   └── mcp_security.py      # MCP セキュリティミドルウェア
│   │
│   ├── container.py             # DI コンテナ ⭐ v3.0.2
│   │
│   ├── mcts_planner.py          # MCTS 攻撃プランナー ⭐ v3.0.2
│   │
│   ├── knowledge/               # ナレッジグラフ ⭐ v3.0.2
│   │   ├── __init__.py
│   │   ├── manager.py           # ナレッジマネージャー
│   │   └── models.py            # データモデル
│   │
│   ├── recon/                   # 偵察エンジン（10 段階パイプライン）
│   ├── detectors/               # 脆弱性検出器
│   ├── cve/                     # CVE インテリジェンス
│   ├── c2/                      # C2 通信フレームワーク
│   ├── lateral/                 # ラテラルムーブメント
│   ├── evasion/                 # 難読化・回避
│   ├── persistence/             # 永続化メカニズム
│   ├── credential/              # 認証情報取得
│   ├── ad/                      # AD 攻撃
│   ├── session/                 # セッション管理
│   ├── tools/                   # 外部ツール管理
│   └── exfiltration/            # データ持ち出し
│
├── modules/                     # 機能モジュール
│   ├── api_security/            # API セキュリティ
│   ├── supply_chain/            # サプライチェーンセキュリティ
│   ├── cloud_security/          # クラウドセキュリティ
│   └── payload/                 # Payload エンジン
│
├── utils/                       # ユーティリティ関数
├── wordlists/                   # 内蔵辞書
├── config/                      # 設定ファイル
├── tests/                       # テストスイート (1461 テストケース)
├── poc-templates/               # PoC テンプレート
├── templates/                   # レポートテンプレート
├── scripts/                     # ユーティリティスクリプト
└── docs/                        # ドキュメント
```

---

## ATT&CK カバレッジマトリックス

| 戦術フェーズ | 技術カバレッジ | ツール数 | 状態 |
|-------------|--------------|----------|------|
| 偵察 (Reconnaissance) | アクティブスキャン、パッシブ収集、OSINT、JS 分析 | 12+ | ✅ |
| リソース開発 (Resource Development) | Payload 生成、難読化、PoC 生成 | 4+ | ✅ |
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
| ネットワーク | インターネットアクセス可能 | 低レイテンシー |

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

# テスト実行
pytest tests/ -v
```

### インストール確認

```bash
# バージョン確認
python mcp_stdio_server.py --version
# 出力: AutoRedTeam-Orchestrator v3.0.1

# セルフチェック実行
python -c "from core import __version__; print(f'Core version: {__version__}')"

# コアモジュールテスト実行
pytest tests/test_mcp_security.py tests/test_container.py tests/test_mcts_planner.py tests/test_knowledge_manager.py tests/test_advanced_verifier.py -v
# 期待される結果: 291+ passed
```

---

## MCP 設定

AI エディタの MCP 設定ファイルに以下の設定を追加してください。

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

## ツールマトリックス (101 MCP ツール)

| カテゴリ | 数量 | 主要ツール | 説明 |
|---------|------|-----------|------|
| **偵察** | 8 | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` `dir_scan` `dns_lookup` `tech_detect` | 情報収集とアセット発見 |
| **脆弱性検出** | 11 | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` `idor_scan` `path_traversal_scan` `cors_scan` `security_headers_scan` | OWASP Top 10 + ロジック脆弱性 |
| **API セキュリティ** | 7 | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` `cors_deep_scan` `security_headers_score` | モダン API セキュリティテスト |
| **サプライチェーン** | 3 | `sbom_generate` `dependency_audit` `cicd_scan` | SBOM/依存関係/CI-CD セキュリティ |
| **クラウドネイティブ** | 3 | `k8s_scan` `grpc_scan` `aws_scan` | K8s/gRPC/AWS セキュリティ監査 |
| **レッドチームコア** | 14 | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` `payload_obfuscate` | ポストエクスプロイトと内部ネットワーク |
| **ラテラルムーブメント** | 9 | `lateral_ssh` `lateral_wmi` `lateral_winrm` `lateral_psexec` `lateral_ssh_tunnel` | 5 プロトコルによるラテラル |
| **永続化** | 3 | `persistence_windows` `persistence_linux` `persistence_webshell` | Windows/Linux/Web |
| **AD 攻撃** | 3 | `ad_enumerate` `ad_kerberos_attack` `ad_spn_scan` | ドメインペネトレーション一式 |
| **CVE** | 8 | `cve_search` `cve_sync` `cve_stats` `poc_execute` `poc_list` `cve_auto_exploit` `cve_exploit_with_desc` `cve_generate_poc` | CVE インテリジェンス + AI PoC |
| **オーケストレーション** | 11 | `auto_pentest` `pentest_resume` `pentest_status` `pentest_phase` `smart_analyze` `attack_chain_plan` | 自動化ペネトレーション |
| **外部ツール** | 8 | `ext_nmap_scan` `ext_nuclei_scan` `ext_sqlmap_scan` `ext_ffuf_fuzz` `ext_masscan_scan` `ext_tool_chain` `ext_tools_status` | プロフェッショナルツール統合 |
| **AI 支援** | 3 | `smart_payload` `ai_attack_chain` `smart_pentest` | インテリジェント分析 |
| **セッション/レポート** | 9 | `session_create` `session_status` `session_list` `session_complete` `generate_report` `export_findings` | セッション管理 + レポート |

---

## コアモジュール

### 1. MCP セキュリティミドルウェア (v3.0.2)

**場所**: `core/security/mcp_security.py`

すべての MCP ツール呼び出しに統一的なセキュリティ保護層を提供します。

```python
from core.security.mcp_security import MCPSecurityMiddleware, RateLimitConfig

security = MCPSecurityMiddleware(
    rate_limit_config=RateLimitConfig(
        requests_per_minute=60,
        burst_limit=10,
    ),
    max_risk=RiskLevel.HIGH,
)

# ターゲット検証
result = security.validate_target("192.168.1.1")
if not result.valid:
    print(f"拒否: {result.errors}")

# デコレーター保護
@security.secure_tool(operation="port_scan", rate_limit_key="scan")
async def port_scan(target: str):
    # ...
```

**コア機能**:
- **入力検証**: IP/ドメイン/URL/CIDR/ポート/パス検証、SSRF 検出
- **レート制限**: スライディングウィンドウ + トークンバケット、リソース枯渇防止
- **操作認可**: リスクレベルベースの操作制御
- **メモリ保護**: 期限切れデータの自動クリーンアップ、メモリリーク防止

### 2. MCTS 攻撃プランナー (v3.0.2)

**場所**: `core/mcts_planner.py`

モンテカルロ木探索アルゴリズムを使用して最適な攻撃パスを計画します。

```python
from core.mcts_planner import MCTSPlanner, AttackState

planner = MCTSPlanner(exploration_weight=1.414, max_depth=10)

state = AttackState(
    target="192.168.1.100",
    target_type="linux_server",
    open_ports={22: "ssh", 80: "http"},
)

result = planner.plan(state, iterations=1000)
print(f"推奨アクション: {result['recommended_actions']}")
```

**コア機能**:
- **UCB1 アルゴリズム**: 探索と活用のバランス
- **アクション生成**: 状態に基づいて利用可能なアクションをインテリジェントに生成
- **攻撃シミュレーション**: 攻撃実行をシミュレートして成功率を推定
- **パス抽出**: 最適な攻撃パスシーケンスを抽出

### 3. ナレッジグラフ (v3.0.2)

**場所**: `core/knowledge/`

セッション間学習を可能にする攻撃知識の永続的ストレージ。

```python
from core.knowledge import KnowledgeManager

km = KnowledgeManager()

# ターゲットを保存
target_id = km.store_target("192.168.1.100", "linux_server")

# サービスを保存
service_id = km.store_service(target_id, "nginx", 80)

# 脆弱性を保存
vuln_id = km.store_vulnerability(service_id, "CVE-2021-44228", "critical")

# 攻撃パスを検索
paths = km.get_attack_paths(target_id, credential_id)

# 類似ターゲットを検索
similar = km.find_similar_targets("192.168.1.100")
```

**コア機能**:
- **エンティティストレージ**: ターゲット、サービス、脆弱性、認証情報
- **関係モデリング**: HOSTS, HAS_VULNERABILITY, OBTAINED_FROM
- **BFS パス発見**: マルチパス発見サポート
- **類似性マッチング**: 同一サブネット/同一ドメイン識別

### 4. 高度検証器 (v3.0.2 強化)

**場所**: `core/detectors/advanced_verifier.py`

マルチメソッドクロス検証により誤検知率を低減します。

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
print(f"状態: {aggregated.status}, 信頼度: {aggregated.confidence:.2%}")
```

**検証メソッド**:
- **統計的検証**: マルチサンプルレスポンス差分の有意性
- **Boolean ブラインド検証**: True/False 条件比較
- **時間ベースブラインド検証**: ネットワークジッターを考慮した遅延検出
- **OOB 検証**: DNS/HTTP アウトオブバンドコールバック確認

### 5. 依存性注入コンテナ (v3.0.2)

**場所**: `core/container.py`

柔軟なサービス構成とライフサイクル管理。

```python
from core.container import Container, singleton, inject

container = Container()

# サービス登録
container.register_singleton(KnowledgeManager)
container.register_transient(SQLiDetector)

# デコレーター使用
@singleton
class ConfigManager:
    pass

# 依存性注入
config = inject(ConfigManager)

# スコープコンテナ（リクエストレベル）
with container.create_scope() as scope:
    service = scope.resolve(RequestService)
```

**コア機能**:
- **ライフサイクル**: Singleton, Scoped, Transient
- **自動注入**: コンストラクタパラメータの自動解決
- **循環検出**: 循環依存の検出と報告
- **リソースクリーンアップ**: スコープコンテナが dispose() を自動呼び出し

---

## 外部ツール統合

ローカルにインストールされたプロフェッショナルセキュリティツールの統合をサポートします。

| ツール | 用途 | MCP コマンド | 要件 |
|--------|------|-------------|------|
| **Nmap** | ポートスキャン + サービス検出 + NSE スクリプト | `ext_nmap_scan` | システム PATH または設定パス |
| **Nuclei** | 7000+ CVE/脆弱性テンプレートスキャン | `ext_nuclei_scan` | Go バイナリ |
| **SQLMap** | 6 種の SQL インジェクション技術 + WAF バイパス | `ext_sqlmap_scan` | Python スクリプト |
| **ffuf** | 高速ディレクトリ/パラメータファジング | `ext_ffuf_fuzz` | Go バイナリ |
| **Masscan** | 超高速大規模ポートスキャン | `ext_masscan_scan` | root/管理者権限が必要 |

### 外部ツールの設定

`config/external_tools.yaml` を編集してください。

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

### 自然言語コマンド

AI エディタで直接対話してツールを呼び出します。

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

### Python API

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

#### MCTS 攻撃計画

```python
from core.mcts_planner import MCTSPlanner, AttackState

planner = MCTSPlanner(exploration_weight=1.414, max_depth=10)

state = AttackState(
    target="192.168.1.100",
    target_type="linux_server",
    open_ports={22: "ssh", 80: "http", 3306: "mysql"},
)

result = planner.plan(state, iterations=1000)

print(f"推奨攻撃シーケンス:")
for action, visits, reward in result['recommended_actions']:
    print(f"  - {action.type.value}: {action.target_port} (信頼度: {reward:.2f})")
```

#### ナレッジグラフ

```python
from core.knowledge import KnowledgeManager

km = KnowledgeManager()

# 知識を構築
target_id = km.store_target("192.168.1.100", "linux_server")
service_id = km.store_service(target_id, "nginx", 80)
vuln_id = km.store_vulnerability(service_id, "CVE-2021-44228", "critical")

# 攻撃パスをクエリ
paths = km.get_attack_paths(target_id, vuln_id)
for path in paths:
    print(f"パス長: {path.length}, 成功率: {path.success_rate:.2%}")

# 類似ターゲットを検索
similar = km.find_similar_targets("192.168.1.100", top_k=5)
for match in similar:
    print(f"類似ターゲット: {match.entity.properties['target']}, スコア: {match.score:.2f}")
```

---

## 設定説明

### 環境変数 (.env)

```bash
# ========== セキュリティ ==========
REDTEAM_MASTER_KEY=
AUTOREDTEAM_API_KEY=
AUTOREDTEAM_AUTH_MODE=permissive

# ========== API キー ==========
OPENAI_API_KEY=your_key
ANTHROPIC_API_KEY=your_key
SHODAN_API_KEY=your_key
CENSYS_API_ID=your_id
CENSYS_API_SECRET=your_secret
NVD_API_KEY=your_key
GITHUB_TOKEN=your_token

# ========== プロキシ ==========
HTTP_PROXY=
HTTPS_PROXY=
SOCKS_PROXY=

# ========== グローバル ==========
VERIFY_SSL=false
RATE_LIMIT_DELAY=0.3
MAX_THREADS=50
REQUEST_TIMEOUT=10

# ========== ロギング ==========
LOG_LEVEL=INFO
LOG_FILE=logs/redteam.log
```

---

## パフォーマンスチューニング

### 並行処理設定

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

### メモリ最適化

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

## トラブルシューティング

| 問題 | 原因 | 解決方法 |
|------|------|---------|
| MCP サーバーに接続できない | パスの誤りまたは Python 環境の問題 | 絶対パスを確認し、Python インタープリターを検証 |
| インポートエラー | PYTHONPATH が未設定 | `PYTHONPATH` 環境変数を追加 |
| 外部ツール呼び出しの失敗 | ツール未インストールまたはパスの誤り | `ext_tools_status` を実行 |
| CVE 同期の失敗 | ネットワークまたは API レート制限 | ネットワークを確認し、NVD_API_KEY を設定 |
| スキャン速度が遅い | 並行処理設定が低い | `MAX_THREADS` と `RATE_LIMIT_DELAY` を調整 |
| メモリオーバーフロー | 大規模スキャン | `streaming_mode` を有効化し、`memory_limit` を設定 |

### デバッグモード

```bash
LOG_LEVEL=DEBUG python mcp_stdio_server.py
python -m py_compile mcp_stdio_server.py
pytest tests/test_mcp_security.py::TestInputValidator -v
```

---

## よくある質問 (FAQ)

<details>
<summary><b>Q: オフライン環境で使用するには？</b></summary>

1. CVE データベースを事前にダウンロード: `python core/cve/update_manager.py sync --offline-export`
2. ローカル辞書ファイルを使用
3. ネットワーク機能を無効化: `OFFLINE_MODE=true`

</details>

<details>
<summary><b>Q: カスタム検出器を追加するには？</b></summary>

1. `core/detectors/` に新しいファイルを作成
2. `BaseDetector` クラスを継承
3. `detect()` と `async_detect()` メソッドを実装
4. `handlers/detector_handlers.py` に MCP ツールを登録

</details>

<details>
<summary><b>Q: MCTS プランナーはどのように機能しますか？</b></summary>

MCTS は 4 つのフェーズを通じて攻撃パスを計画します。

1. **選択**: UCB1 アルゴリズムがルートから最適なパスを選択
2. **展開**: リーフノードで新しい攻撃アクションを展開
3. **シミュレーション**: 攻撃実行をシミュレートして報酬を評価
4. **逆伝播**: 報酬を逆伝播してパスノードを更新

UCB1 式: `UCB1 = Q/N + c * sqrt(ln(N_parent) / N)`

`c = sqrt(2)` が探索重みで、「既知の良いパス」と「未探索のパス」のバランスを取ります。

</details>

<details>
<summary><b>Q: ナレッジグラフはどのように重複作業を削減しますか？</b></summary>

1. **ターゲット類似性**: 同一サブネット/同一ドメインのターゲットを識別し、脆弱性情報を再利用
2. **攻撃パス成功率**: 履歴からパス成功率を計算
3. **認証情報関連付け**: 認証情報とアクセス可能なターゲットを自動関連付け
4. **アクション履歴学習**: アクション成功率を記録し、将来の決定を最適化

</details>

---

## 開発ガイド

### コード標準

```bash
# コードフォーマット
black core/ modules/ handlers/ utils/
isort core/ modules/ handlers/ utils/

# 静的解析
pylint core/ modules/ handlers/ utils/
mypy core/ modules/ handlers/ utils/

# テスト実行
pytest tests/ -v --cov=core --cov-report=html
```

### 新しい MCP ツールの追加

```python
# 1. handlers/ にハンドラーを追加
# handlers/my_handlers.py

from mcp import tool

@tool()
async def my_new_tool(target: str, option: str = "default") -> dict:
    """ツールの説明

    Args:
        target: ターゲットアドレス
        option: オプションパラメータ

    Returns:
        結果辞書
    """
    return {"success": True, "data": ...}

# 2. mcp_stdio_server.py でインポート
from handlers.my_handlers import my_new_tool
```

---

## 更新履歴

### v3.0.2 (開発中) - アーキテクチャ強化

**新モジュール**（実装済み、リリース保留）
- **MCP セキュリティミドルウェア** - 入力検証、レート制限、操作認可
- **DI コンテナ** - ライフサイクル管理、循環依存検出
- **MCTS 攻撃プランナー** - UCB1 アルゴリズム、攻撃パス最適化
- **ナレッジグラフ** - エンティティ関係ストレージ、BFS パス発見
- **高度検証器強化** - OOB スレッドセーフティ、SSTI ペイロード

**セキュリティ修正**
- TOCTOU 競合状態を修正（ロック範囲を拡張）
- 期間認可有効期限ロジックを修正
- SSRF 検出を追加（プライベート IP 検証）
- レートリミッターメモリリークを修正（max_keys エビクション）
- DNS インジェクションを修正（トークン ID サニタイズ）
- MD5 → SHA256 ハッシュアップグレード

**テスト強化**
- 291 テストケースを追加（mcp_security: 62, container: 39, mcts: 57, verifier: 43, knowledge: 90）
- スレッドセーフティテストカバレッジ
- 統合テストワークフロー

### v3.0.1 (2026-01-30) - 品質強化

**追加**
- CVE 自動エクスプロイト強化（`cve_auto_exploit`, `cve_exploit_with_desc`, `cve_generate_poc`）
- AI PoC ジェネレーター（`core/cve/ai_poc_generator.py`）

**修正**
- バージョン同期 - VERSION/pyproject.toml/ソースコード統一
- ToolCounter 修正 - external_tools/lateral/persistence/ad カテゴリを追加
- スレッドセーフティ - beacon.py の状態管理に threading.Lock を追加

**改善**
- CI/CD 強化 - lint 失敗でビルドをブロック
- テストカバレッジ閾値を 50% に引き上げ
- 依存関係制約 - 上限を追加

### v3.0.0 (2026-01-18) - アーキテクチャ強化

**追加**
- 外部ツール統合 - 8 つの外部ツール MCP コマンド
- ツールチェーンオーケストレーション - YAML 駆動のマルチツール組み合わせ
- Handler モジュール化 - 16 の独立 Handler モジュール

---

## ロードマップ

### 進行中

- [ ] v3.0.2 リリース（MCP セキュリティミドルウェア、MCTS プランナー、ナレッジグラフ、DI コンテナ）
- [ ] Web UI 管理インターフェース
- [ ] 分散スキャンクラスター

### 計画中

- [ ] 追加クラウドプラットフォーム対応（GCP/Alibaba Cloud/Tencent Cloud）
- [ ] Burp Suite プラグイン統合
- [ ] モバイルアプリケーションセキュリティテスト
- [ ] AI 自律攻撃エージェント
- [ ] Neo4j ナレッジグラフバックエンド

### 完了 (v3.0.1)

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
- `docs:` ドキュメント
- `refactor:` リファクタリング
- `test:` テスト
- `chore:` ビルド/ツール
- `security:` セキュリティ関連

詳細は [CONTRIBUTING.md](CONTRIBUTING.md) を参照

---

## セキュリティポリシー

- **責任ある開示**: セキュリティ脆弱性を [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com) に報告
- **許可された使用**: 本ツールは許可されたセキュリティテストと研究のみに使用
- **コンプライアンス**: 使用前に現地の法律を遵守していることを確認

詳細は [SECURITY.md](SECURITY.md) を参照

---

## 謝辞

### コア依存関係

| プロジェクト | 用途 | ライセンス |
|-------------|------|-----------|
| [MCP Protocol](https://modelcontextprotocol.io/) | AI ツールプロトコル標準 | MIT |
| [aiohttp](https://github.com/aio-libs/aiohttp) | 非同期 HTTP クライアント | Apache-2.0 |
| [pydantic](https://github.com/pydantic/pydantic) | データ検証 | MIT |
| [pytest](https://github.com/pytest-dev/pytest) | テストフレームワーク | MIT |

### 設計インスピレーション

| プロジェクト | インスピレーション |
|-------------|-------------------|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | 脆弱性スキャナエンジン設計 |
| [SQLMap](https://github.com/sqlmapproject/sqlmap) | SQL インジェクション検出アプローチ |
| [Impacket](https://github.com/fortra/impacket) | ネットワークプロトコル実装 |
| [Metasploit](https://github.com/rapid7/metasploit-framework) | ポストエクスプロイトモジュール設計 |

### アルゴリズム参照

| アルゴリズム | 用途 | 参照 |
|-------------|------|------|
| UCB1 | MCTS 探索-活用バランス | Auer et al., 2002 |
| BFS | ナレッジグラフパス発見 | - |
| Token Bucket | レート制限 | - |
| Sliding Window | レート制限 | - |

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Coff0xc/AutoRedTeam-Orchestrator&type=Date)](https://star-history.com/#Coff0xc/AutoRedTeam-Orchestrator&Date)

---

## ライセンス

本プロジェクトは **MIT ライセンス** の下でライセンスされています - 詳細は [LICENSE](LICENSE) ファイルを参照

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

## 免責事項

> **警告**: 本ツールは**許可されたセキュリティテストと研究**のみに使用してください。
>
> 本ツールを使用してシステムをテストする前に、以下を確認してください：
> - ターゲットシステム所有者からの**書面による許可**を取得していること
> - 現地の**法律法規**を遵守していること
> - **職業倫理**基準に従っていること
>
> 許可なく本ツールを使用することは法律に違反する可能性があります。**開発者はいかなる悪用についても責任を負いません**。
>
> 本ツールにはレッドチーム攻撃機能（ラテラルムーブメント、C2 通信、永続化など）が含まれており、以下の目的でのみ使用してください：
> - 許可されたペネトレーションテスト
> - セキュリティ研究と教育
> - CTF 競技
> - 防御能力の検証
>
> **いかなる違法な目的での使用も禁止されています。**

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
  <sub>このプロジェクトがお役に立ちましたら、⭐ Star をご検討ください！</sub>
</p>
