# PluginSpector

[English](README.en.md) | [日本語](README.md)

**Claude Code プラグインおよび AI エージェントスキル向けのセキュリティスキャナー。** インストール前に脆弱性、悪意のあるパターン、セキュリティリスクを検出します。

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## 概要

Claude Code プラグインや AI エージェントスキル(Codex CLI や Gemini CLI などでも利用される)は、暗黙の信頼のもとでほとんど検証されずに実行されます。エージェントスキルに関する調査では、**26.1% に脆弱性が含まれ**、**5.2% に悪意のある意図が疑われる**ことが報告されています。

PluginSpector は「このプラグイン/スキルはインストールしても安全か?」という問いに答えるためのツールです。単体のスキルのスキャンに加えて、Claude Code プラグインを実行可能なケーパビリティグラフ(マニフェスト、フック、MCP/LSP 設定、エージェント、bin/、モニター)として解析します。

## ドキュメント

- **[開発ガイド](docs/DEVELOPMENT.md)**(英語)— アーキテクチャ、パッケージ構成、アナライザーパイプラインの拡張方法。

## 特徴

- **多様な入力形式**: Git リポジトリ、URL、zip ファイル、ディレクトリ、単一ファイルをスキャン可能
- **21 カテゴリ・81 種類の脆弱性パターン**: プロンプトインジェクション、データ漏洩、権限昇格、サプライチェーン、過剰なエージェンシー、出力処理、システムプロンプト漏洩、メモリポイズニング、ツール誤用、暴走エージェント、トリガー悪用、危険なコード(AST)、テイント解析、YARA シグネチャ、MCP 最小権限、MCP ツールポイズニング、そして **Claude Code プラグイン**専用解析(マニフェスト/構造、フック、MCP/LSP 設定、エージェント、bin/、モニター、依存関係、コンポーネント間のケーパビリティ相関)
- **2 段階解析**: 高速な静的解析 + オプションの LLM によるセマンティック評価
- **リアルタイム脆弱性検索**: SC4 が [OSV.dev](https://osv.dev) に問い合わせてリアルタイムの CVE 情報を取得し、オフライン時は自動でフォールバック
- **複数の出力形式**: ターミナル、JSON、Markdown、SARIF レポート
- **リスクスコアリング**: 0〜100 のスコアと深刻度ラベル、明確な推奨アクション

## クイックスタート

### インストール

最初に仮想環境を作成して有効化してください(`make` の各ターゲットは仮想環境が有効化されていることを前提としています)。**uv** または **pip** を使用できます。Makefile は `uv` が利用可能であればそれを使用し、なければ `pip` を使用します。

```bash
# リポジトリをクローン
git clone https://github.com/f4ah6o/PluginSpector.git
cd PluginSpector

# 仮想環境を作成して有効化
uv venv .venv && source .venv/bin/activate
# または: python3 -m venv .venv && source .venv/bin/activate

# 本番用にインストール
make install

# または開発用依存関係も含めてインストール
make install-dev
```

### Docker(Python 不要)

付属の [Dockerfile](Dockerfile) からローカルでビルドすることで、Python をインストールせずに PluginSpector を実行できます。イメージは Docker 公式の Python `3.12-slim-bookworm` イメージをベースにしています。

**イメージのビルド:**

```bash
make docker-build
# または: docker build -t skillspector .
```

**ローカルディレクトリのスキャン**: カレントディレクトリをコンテナの作業ディレクトリ `/scan` にマウントします。

```bash
docker run --rm -v "$PWD:/scan" skillspector scan ./my-skill/ --no-llm
```

**LLM 解析を使う場合**: ローカルの `.env` ファイルで認証情報を渡します。

```bash
cat > .env <<'EOF'
SKILLSPECTOR_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
EOF
```

```bash
docker run --rm \
  -v "$PWD:/scan" \
  --env-file .env \
  skillspector scan ./my-skill/
```

または、シェル環境から直接認証情報を渡すこともできます。

```bash
docker run --rm \
  -v "$PWD:/scan" \
  -e SKILLSPECTOR_PROVIDER=anthropic \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  skillspector scan ./my-skill/
```

**レポートをホストファイルシステムに書き出す**: マウントしたディレクトリに書き込みます。

```bash
docker run --rm \
  -v "$PWD:/scan" \
  skillspector scan ./my-skill/ --no-llm --format json --output report.json
```

**繰り返し静的スキャンを行う場合のエイリアス例:**

```bash
alias skillspector-docker='docker run --rm -v "$PWD:/scan" skillspector'
skillspector-docker scan ./my-skill/ --no-llm
```

### 基本的な使い方

```bash
# ローカルのスキルディレクトリをスキャン
skillspector scan ./my-skill/

# 単一の SKILL.md ファイルをスキャン
skillspector scan ./SKILL.md

# Git リポジトリをスキャン
skillspector scan https://github.com/user/my-skill

# zip ファイルをスキャン
skillspector scan ./my-skill.zip
```

### 出力形式

```bash
# ターミナル出力(デフォルト) - 整形された表示
skillspector scan ./my-skill/

# JSON 出力 - 機械可読
skillspector scan ./my-skill/ --format json --output report.json

# Markdown 出力 - ドキュメント用
skillspector scan ./my-skill/ --format markdown --output report.md

# SARIF 出力 - CI/CD 連携や IDE ツール用
skillspector scan ./my-skill/ --format sarif --output report.sarif
```

### LLM 解析

最良の結果を得るには、セマンティック解析用に OpenAI 互換の LLM エンドポイントを設定してください。`SKILLSPECTOR_PROVIDER` でプロバイダーを選択します。各プロバイダーは独自のデフォルトモデルを内蔵しています。PluginSpector はローカルの OpenAI 互換サーバー(Ollama、vLLM、llama.cpp)やマネージド推論ゲートウェイにも対応しています。

| プロバイダー (`SKILLSPECTOR_PROVIDER`) | 認証情報の環境変数 | エンドポイント | デフォルトモデル |
| ---------- | ---- | ---- | ---- |
| `openai` | `OPENAI_API_KEY`(任意で `OPENAI_BASE_URL`) | api.openai.com(または任意の OpenAI 互換 URL) | `gpt-5.4` |
| `anthropic` | `ANTHROPIC_API_KEY` | api.anthropic.com | `claude-opus-4-6` |
| `nv_build` | `NVIDIA_INFERENCE_KEY` | build.nvidia.com | `deepseek-ai/deepseek-v4-flash` |

`nv_build` と `anthropic` では、`meta_analyzer` ノード(検出結果のフィルタリング・拡充パス)だけデフォルトより上位のモデル(それぞれ `deepseek-ai/deepseek-v4-pro`、`claude-sonnet-4-6`)に切り替わります。それ以外の LLM 呼び出しは各プロバイダーの基本デフォルトモデルを使用します。

```bash
# 標準の OpenAI
export SKILLSPECTOR_PROVIDER=openai
export OPENAI_API_KEY=sk-...
skillspector scan ./my-skill/

# Anthropic
export SKILLSPECTOR_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
skillspector scan ./my-skill/

# NVIDIA build.nvidia.com
export SKILLSPECTOR_PROVIDER=nv_build
export NVIDIA_INFERENCE_KEY=nvapi-...
skillspector scan ./my-skill/

# ローカルの Ollama や任意の OpenAI 互換エンドポイント
export SKILLSPECTOR_PROVIDER=openai
export OPENAI_API_KEY=ollama
export OPENAI_BASE_URL=http://localhost:11434/v1
export SKILLSPECTOR_MODEL=llama3.1:8b
skillspector scan ./my-skill/

# プロバイダーのデフォルトモデルを上書き
export SKILLSPECTOR_MODEL=gpt-5.2
skillspector scan ./my-skill/

# LLM 解析をスキップ(高速、静的解析のみ)
skillspector scan ./my-skill/ --no-llm
```

## 脆弱性パターン

PluginSpector は **21 カテゴリ・81 種類の脆弱性パターン**を検出します。

### プロンプトインジェクション (5 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| P1 | 指示の上書き | HIGH | 安全制約を無視させる指示 |
| P2 | 隠れた指示 | HIGH | コメントや不可視テキストに埋め込まれた悪意のある指示 |
| P3 | 漏洩用コマンド | HIGH | コンテキストを外部に送信させる指示 |
| P4 | 挙動操作 | MEDIUM | エージェントの判断を密かに変える指示 |
| P5 | 有害コンテンツ | CRITICAL | 物理的な害を及ぼす可能性がある指示 |

### データ漏洩 (4 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| E1 | 外部送信 | MEDIUM | 外部 URL へのデータ送信 |
| E2 | 環境変数収集 | HIGH | API キーやシークレットの収集 |
| E3 | ファイルシステム探索 | MEDIUM | 機密ファイルを探すディレクトリスキャン |
| E4 | コンテキスト漏洩 | HIGH | 会話コンテキストの外部送信 |

### 権限昇格 (3 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| PE1 | 過剰な権限要求 | LOW | 機能に対して不必要に広いアクセス権限の要求 |
| PE2 | sudo/root の実行 | MEDIUM | システム権限の昇格呼び出し |
| PE3 | 認証情報アクセス | HIGH | SSH 鍵、トークン、パスワードの読み取り |

### サプライチェーン (6 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| SC1 | バージョン未固定の依存関係 | LOW | パッケージにバージョン制約がない |
| SC2 | 外部スクリプトの取得実行 | HIGH | curl \| bash などのリモートコード実行 |
| SC3 | コードの難読化 | HIGH | Base64/16 進エンコードされたコードの実行 |
| SC4 | 既知の脆弱性を持つ依存関係 | HIGH | 既知の CVE を持つ依存関係(OSV.dev によるリアルタイム検索) |
| SC5 | メンテナンス放棄された依存関係 | MEDIUM | セキュリティ更新のないメンテナンスされていないパッケージ |
| SC6 | タイポスクワッティング | HIGH | 有名パッケージに似せたパッケージ名 |

### 過剰なエージェンシー (4 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| EA1 | 無制限なツールアクセス | HIGH | 制約のない無制限なツールアクセス |
| EA2 | 自律的な意思決定 | HIGH | 人間の確認なしに行われる影響度の高い判断 |
| EA3 | スコープクリープ | MEDIUM | 明記された目的を超える機能 |
| EA4 | 無制限なリソースアクセス | MEDIUM | リソース消費に対するレート制限・上限がない |

### 出力処理 (3 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| OH1 | 未検証の出力インジェクション | HIGH | サニタイズされずに使用されるモデル出力 |
| OH2 | クロスコンテキスト出力 | MEDIUM | 検証なしに信頼境界を越えて流れる出力 |
| OH3 | 無制限の出力 | MEDIUM | 出力サイズや生成レートに上限がない |

### システムプロンプト漏洩 (3 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| P6 | 直接的な漏洩 | HIGH | システムプロンプトや内部ルールを露出させる指示 |
| P7 | 間接的な抽出 | MEDIUM | 言い換え・翻訳・サイドチャネルによる抽出 |
| P8 | ツール経由の漏洩 | HIGH | ファイル書き込みやネットワークリクエストによるシステムプロンプトの漏洩 |

### メモリポイズニング (3 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| MP1 | 永続的なコンテキスト注入 | HIGH | 複数回のやり取りに渡って残存することを意図したコンテンツ |
| MP2 | コンテキストウィンドウの圧迫 | MEDIUM | 安全制約を押し出す無意味な埋め草コンテンツ |
| MP3 | メモリ操作 | HIGH | エージェントのメモリや保存状態への改ざん |

### ツール誤用 (3 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| TM1 | ツールパラメータの悪用 | HIGH | 意図しない動作を起こすパラメータの作り込み(shell=True、--force など) |
| TM2 | チェイニングの悪用 | HIGH | 個別の安全チェックを回避するツールの連鎖 |
| TM3 | 安全でないデフォルト値 | MEDIUM | 過度に許容的なデフォルト設定(TLS 無効化、認証なしなど) |

### 暴走エージェント (2 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| RA1 | 自己改変 | CRITICAL | 実行時に自身のコードや設定を変更する |
| RA2 | セッションの永続化 | HIGH | cron ジョブや起動スクリプトによる不正な永続化 |

### トリガー悪用 (3 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| TR1 | 過度に広いトリガー | MEDIUM | よく使われる単語にマッチするトリガーパターン |
| TR2 | コマンド乗っ取り型トリガー | HIGH | 組み込みコマンドや他のスキルを乗っ取るトリガー |
| TR3 | キーワード釣り型トリガー | MEDIUM | 起動頻度の最大化を狙った汎用的なトリガー |

### ビヘイビア AST 解析 (8 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| AST1 | exec() 呼び出し | CRITICAL | 任意コード実行を可能にする直接の exec() |
| AST2 | eval() 呼び出し | HIGH | 任意の式を評価する直接の eval() |
| AST3 | 動的インポート | HIGH | 実行時に任意のモジュールを読み込む \_\_import\_\_() |
| AST4 | subprocess 呼び出し | HIGH | subprocess による外部コマンド実行 |
| AST5 | os.system / exec 系 | HIGH | os モジュール経由のシェルコマンド実行 |
| AST6 | compile() 呼び出し | MEDIUM | 文字列からのコードオブジェクト生成 |
| AST7 | 動的 getattr() | MEDIUM | リテラルでない属性名による任意の属性アクセス |
| AST8 | 危険な実行チェーン | CRITICAL | exec/eval と動的なソース(ネットワーク、エンコードデータ)の組み合わせ |

### テイント解析 (5 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| TT1 | 直接的なテイントフロー | HIGH | サニタイズなしにソースからシンクへ直接流れるデータ |
| TT2 | 変数経由のテイントフロー | MEDIUM | 中間変数を経由してソースからシンクへ流れるデータ |
| TT3 | 認証情報漏洩チェーン | CRITICAL | 認証情報(環境変数、シークレット)がネットワーク出力シンクへ流れる |
| TT4 | ファイル読み取りからの漏洩 | HIGH | ファイル内容がネットワーク出力シンクへ流れる |
| TT5 | 外部入力からのコード実行 | CRITICAL | ネットワークやユーザー入力が exec/eval/subprocess シンクへ流れる |

### YARA シグネチャ (4 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| YR1 | マルウェアの一致 | CRITICAL | 既知のマルウェアシグネチャに一致する YARA ルール |
| YR2 | Web シェルの一致 | CRITICAL | Web シェルパターンに一致する YARA ルール |
| YR3 | クリプトマイナーの一致 | HIGH | クリプトマイニングの兆候に一致する YARA ルール |
| YR4 | ハックツール/エクスプロイトの一致 | HIGH | ハックツールやエクスプロイトコードに一致する YARA ルール |

### MCP 最小権限 (4 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| LP1 | 未宣言のケーパビリティ | HIGH | 宣言された権限に記載されていないケーパビリティをコードが使用 |
| LP2 | ワイルドカード権限 | MEDIUM | 権限リストにワイルドカード(\*、all、full、any)が含まれる |
| LP3 | 権限宣言の欠落 | MEDIUM | permissions フィールドがないのに検出可能なケーパビリティを持つコードがある |
| LP4 | 過剰宣言された権限 | LOW | 権限が宣言されているが対応するコードのケーパビリティが見つからない |

### MCP ツールポイズニング (4 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| TP1 | 隠れた指示 | HIGH | メタデータに隠された指示(HTML コメント、ゼロ幅文字、base64、データ URI) |
| TP2 | Unicode による偽装 | HIGH | ツールメタデータ内のホモグリフ、RTL オーバーライド、混在スクリプト識別子 |
| TP3 | パラメータ説明への注入 | MEDIUM | パラメータ定義内の注入パターン(上書き、システムトークン、悪意あるデフォルト値) |
| TP4 | 説明と挙動の不一致 | MEDIUM | 宣言されたツールの説明が実際のコードの挙動と一致しない(LLM 解析による検出) |

### Claude プラグイン構造 (3 パターン)

スキャン対象が Claude Code プラグイン(`.claude-plugin/plugin.json` で検出)の場合、PluginSpector はプラグインをケーパビリティグラフとして解析し、以下のプラグイン専用ルールを適用します。

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| CP001 | 無効なプラグインマニフェスト | MEDIUM | `plugin.json` が不正な形式、必須フィールドの欠落、または型が誤っている |
| CP002 | コンポーネントパスの脱出 | HIGH | 宣言されたコンポーネントパスがプラグインルートの外を指す(パストラバーサル) |
| CP003 | シンボリックリンクの脱出 | HIGH | プラグイン内のシンボリックリンクがプラグインルート外のターゲットを指す |

### Claude フック (4 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| HK001 | フックによるシェル実行 | MEDIUM | フックがシェルコマンドを実行する |
| HK002 | フックによる外部 HTTP 通信 | HIGH | フックが外部 HTTP エンドポイントを呼び出す |
| HK003 | ライフサイクルフックによる外部コマンド | HIGH | 自動的なライフサイクルフック(SessionStart など)が外部コマンドを実行する |
| HK004 | フックによるダウンロード即実行 | CRITICAL | フックがリモートコードをダウンロードして実行する(例: `curl ... \| sh`) |

### Claude MCP/LSP 設定 (3 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| MCP001 | バージョン未固定のランタイムパッケージ | HIGH | MCP サーバーがバージョン未固定のパッケージを実行する(例: `npx -y`、`uvx`) |
| MCP002 | MCP 設定への埋め込みシークレット | CRITICAL | シークレット(API キー/トークン/パスワード)が MCP 設定に直接埋め込まれている |
| MCP003 | 安全でない MCP トランスポート | HIGH | リモートの MCP エンドポイントが安全でない `http://` トランスポートを使用 |

### Claude コンポーネント (4 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| AG001 | 広範なエージェント権限 | MEDIUM | エージェントが広範な Bash や書き込み権限を宣言している |
| BIN001 | bin コマンドのシャドーイング | HIGH | `bin/` 内のエントリが一般的なコマンド(git、node、python など)を上書きする |
| MON001 | 永続的なバックグラウンドモニター | MEDIUM | モニターが永続的なバックグラウンド実行を開始する |
| DEP001 | バージョン未固定のプラグイン依存関係 | MEDIUM | プラグインの依存関係が不変のリビジョンに固定されていない |

### ケーパビリティ相関 (3 パターン)

| ID | パターン | 深刻度 | 説明 |
|----|---------|----------|-------------|
| CC001 | シークレットアクセス + ネットワーク送信 | HIGH | コンポーネントがシークレットへのアクセスとネットワーク送信を両方行う |
| CC002 | 自動起動 + プロセス実行 | HIGH | 自動的に起動するコンポーネントがプロセスを実行する |
| CC003 | バックグラウンド実行 + ネットワークアクセス | HIGH | バックグラウンドコンポーネントが外部ネットワークにアクセスする |

検出されるすべてのパターンは上記の表にまとめられています。

## リスクスコアリング

### スコアの計算方法

- **CRITICAL の問題**: +50 点
- **HIGH の問題**: +25 点
- **MEDIUM の問題**: +10 点
- **LOW の問題**: +5 点
- **実行可能なスクリプトがある場合**: 1.3 倍の乗数

### 深刻度レベル

| スコア | 深刻度 | 推奨アクション |
|-------|----------|----------------|
| 0-20 | LOW | SAFE(安全) |
| 21-50 | MEDIUM | CAUTION(注意) |
| 51-80 | HIGH | DO NOT INSTALL(インストール非推奨) |
| 81-100 | CRITICAL | DO NOT INSTALL(インストール非推奨) |

## 出力例

### ターミナル出力

```
 SkillSpector Security Report  v2.1.5

Skill: suspicious-skill
Target Type: standalone-skill
Source: ./suspicious-skill/
Scanned: 2026-01-29 10:30:00 UTC

        Risk Assessment
 Metric          Value
 Score           78/100
 Severity        HIGH
 Recommendation  DO NOT INSTALL

        Components (3)
 File              Type      Lines  Executable
 SKILL.md          markdown    142  No
 scripts/sync.py   python       87  Yes
 requirements.txt  text          3  No

Issues (2)

  HIGH: E2 - Code accesses environment variables that may contain secrets...
    Location: scripts/sync.py:23
    Confidence: 94%
    Remediation: Avoid reading sensitive env vars (API keys, tokens) unless...

  HIGH: E1 - Data is being sent to an external URL. This could be legitima...
    Location: scripts/sync.py:45
    Confidence: 89%
    Remediation: Verify the destination URL is trusted and necessary. Remo...

Executable scripts: Yes
```

## 設定

### 環境変数

| 変数 | 説明 | 必須/任意 |
|----------|-------------|----------|
| `SKILLSPECTOR_PROVIDER` | 有効な LLM プロバイダー: `openai`、`anthropic`、`nv_build` のいずれか。各プロバイダーは独自の `model_registry.yaml` とデフォルトモデルを持つ(上記の LLM 解析の表を参照)。未設定時は `nv_build`。 | 任意 |
| `NVIDIA_INFERENCE_KEY` | `nv_build` プロバイダー(build.nvidia.com)の認証情報。 | `SKILLSPECTOR_PROVIDER=nv_build` で LLM 解析を行う場合は必須 |
| `OPENAI_API_KEY` | OpenAI プロバイダー(`SKILLSPECTOR_PROVIDER=openai`)の認証情報。有効なプロバイダーが認証情報を返さない場合の第 2 階層フォールバックとしても使用される。 | `SKILLSPECTOR_PROVIDER=openai` で LLM 解析を行う場合は必須 |
| `OPENAI_BASE_URL` | OpenAI エンドポイントを上書き(例: Ollama を指定)。 | 任意 |
| `ANTHROPIC_API_KEY` | Anthropic プロバイダー(`SKILLSPECTOR_PROVIDER=anthropic`)の認証情報。 | `SKILLSPECTOR_PROVIDER=anthropic` で LLM 解析を行う場合は必須 |
| `SKILLSPECTOR_MODEL` | 有効なプロバイダーのデフォルトモデルを上書き。各プロバイダーのデフォルトは LLM 解析の表を参照。 | 任意 |
| `SKILLSPECTOR_MODEL_REGISTRY` | プロバイダーごとに内蔵された YAML レジストリ(`src/skillspector/providers/<provider>/model_registry.yaml`)を、任意のパスで上書き。 | 任意 |
| `SKILLSPECTOR_LOG_LEVEL` | ログレベル: `DEBUG`、`INFO`、`WARNING`、`ERROR`(デフォルト: `WARNING`)。 | 任意 |

### CLI オプション

```bash
skillspector scan --help

Options:
  -f, --format [terminal|json|markdown|sarif]  出力形式 [default: terminal]
  -o, --output PATH                            出力ファイルパス
  --no-llm                                     LLM 解析をスキップ(静的解析のみ)
  --yara-rules-dir PATH                        組み込みルールに加えて読み込む追加 YARA ルール(.yar/.yara)のディレクトリ
  -V, --verbose                                詳細な進行状況を表示
  --help                                        このメッセージを表示して終了

skillspector --version  # または -v: インストール済みバージョンを表示して終了
```

## 開発

### セットアップ

すべての `make` ターゲットは、仮想環境がすでに作成・有効化されていることを前提としています。Makefile は **uv** が利用可能であればそれを使用し、なければ **pip** を使用します。

```bash
# クローン、venv 作成、有効化、開発用依存関係のインストール
git clone https://github.com/f4ah6o/PluginSpector.git
cd PluginSpector
uv venv .venv && source .venv/bin/activate
# または: python3 -m venv .venv && source .venv/bin/activate
make install-dev

# テストを実行
make test

# カバレッジ付きでテストを実行
make test-cov

# リンターを実行
make lint

# コードを整形
make format
```

## 仕組み

PluginSpector は 2 段階の検出パイプラインを使用します。

### ステージ 1: 静的解析
- 11 種類の静的アナライザーによる高速な正規表現ベースのパターンマッチング
- 危険な呼び出し(exec、eval、subprocess など)を検出する AST ベースのビヘイビア解析
- 依存関係の既知 CVE を OSV.dev でリアルタイム検索
- スキル内のすべてのファイルをスキャン
- 高い再現率(ほとんどの問題を検出)
- 中程度の精度(誤検知が一部発生)

### ステージ 2: LLM によるセマンティック解析(オプション)
- コンテキストと意図を評価
- 誤検知をフィルタリング
- 人が読める形式の説明を提供
- 精度を約 87% まで向上

LLM プロンプトには、悪意のあるスキルが解析結果を操作できないようにするためのジェイルブレイク対策が含まれています。

## リアルタイム脆弱性検索 (SC4)

SC4 は [OSV.dev](https://osv.dev) API を使用して、PyPI と npm にまたがる数万件のアドバイザリを含む Open Source Vulnerabilities データベース全体と依存関係を照合します。

- **API キー不要** — OSV.dev は無料かつ認証不要です。
- **バッチクエリ** — すべての依存関係を 1 回の HTTP 呼び出しでチェックします。
- **自動フォールバック** — OSV.dev に到達できない場合(エアギャップ環境/オフライン)、組み込みの小規模なフォールバックリストが使用されます。
- **キャッシュ** — セッション中の重複した API 呼び出しを避けるため、結果はメモリ上に 1 時間キャッシュされます。

このツールはリアルタイムの脆弱性データを取得するために `api.osv.dev` への外向き HTTPS アクセスを必要とします。アクセスできない場合、検出結果は静的フォールバックリストに限定されます。

## 制限事項

- **英語以外のコンテンツ**: 他言語のパターンを見逃す可能性があります
- **画像ベースの攻撃**: 画像内のテキストは解析できません
- **暗号化/バイナリコード**: コンパイル済みまたは暗号化されたコンテンツは解析できません
- **実行時の挙動**: 静的解析のみで、動的実行は行いません
- **オフライン時の SC4**: `api.osv.dev` へのネットワークアクセスがない場合、SC4 は小規模な静的フォールバックリストを使用します

## 研究背景

「Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale」(Liu et al., 2026)の研究に基づいています。

- **データセット**: 主要マーケットプレイスの 42,447 件のスキル
- **脆弱性あり**: 26.1% が少なくとも 1 件の脆弱性を含む
- **高深刻度**: 5.2% に悪意のある意図が疑われる
- **主要な発見**: 実行可能スクリプトを含むスキルは脆弱である可能性が 2.12 倍高い

## Python API との統合

```python
from skillspector import graph

# LangGraph ワークフローを呼び出す
result = graph.invoke({
    "input_path": "/path/to/skill",
    "output_format": "json",   # terminal, json, markdown, sarif のいずれか
    "use_llm": True,           # 静的解析のみの場合は False
})

# 結果にアクセス
print(f"Risk Score: {result['risk_score']}/100")
print(f"Severity: {result['risk_severity']}")
print(f"Recommendation: {result['risk_recommendation']}")

for finding in result["filtered_findings"]:
    print(f"[{finding['severity']}] {finding['rule_id']}: {finding['message']}")
```

## ライセンス

Apache License 2.0 — 詳細は [LICENSE](LICENSE) を参照してください。

## コントリビューション

コントリビューションを歓迎します!コントリビューションガイドラインをお読みのうえ、プルリクエストを送ってください。

## サポート

- **Issues**: [GitHub Issues](https://github.com/f4ah6o/PluginSpector/issues)
