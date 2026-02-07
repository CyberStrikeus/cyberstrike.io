<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike logo" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>AIを活用した自律型ペネトレーションテストエージェントフレームワーク。</strong></p>
<p align="center">
  <a href="https://cyberstrike.io/discord"><img alt="Discord" src="https://img.shields.io/discord/1391832426048651334?style=flat-square&label=discord" /></a>
  <a href="https://www.npmjs.com/package/cyberstrike"><img alt="npm" src="https://img.shields.io/npm/v/cyberstrike?style=flat-square" /></a>
  <a href="https://github.com/CyberStrikeus/cyberstrike.io/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/CyberStrikeus/cyberstrike.io?style=flat-square" /></a>
  <a href="https://github.com/CyberStrikeus/cyberstrike.io/blob/dev/LICENSE"><img alt="License" src="https://img.shields.io/github/license/CyberStrikeus/cyberstrike.io?style=flat-square" /></a>
</p>

<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.zht.md">繁體中文</a> |
  <a href="README.ko.md">한국어</a> |
  <a href="README.de.md">Deutsch</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.fr.md">Français</a> |
  <a href="README.it.md">Italiano</a> |
  <a href="README.da.md">Dansk</a> |
  <a href="README.ja.md">日本語</a> |
  <a href="README.pl.md">Polski</a> |
  <a href="README.ru.md">Русский</a> |
  <a href="README.ar.md">العربية</a> |
  <a href="README.no.md">Norsk</a> |
  <a href="README.br.md">Português (Brasil)</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/CyberStrikeus/docs/main/public/docs/images/gifs/g01-first-run.gif" alt="CyberStrike Demo" width="700">
</p>

---

## CyberStrikeとは？

CyberStrikeは、自律型エージェントを使用してセキュリティ評価を実行する、オープンソースのAI駆動型ペネトレーションテストフレームワークです。15以上のAIプロバイダーと特化したセキュリティテストエージェントを統合し、脆弱性の自動検出を実現します。

## インストール

```bash
# クイックインストール
curl -fsSL https://cyberstrike.io/install | bash

# パッケージマネージャー
npm i -g cyberstrike@latest        # または bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS & Linux (推奨)

# ソースから
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

### デスクトップアプリ

macOS、Windows、Linux向けに提供されています。[リリースページ](https://github.com/CyberStrikeus/cyberstrike.io/releases)または[cyberstrike.io/download](https://cyberstrike.io/download)からダウンロードできます。

| プラットフォーム      | ダウンロード                              |
| --------------------- | ---------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg`  |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`      |
| Windows               | `cyberstrike-desktop-windows-x64.exe`     |
| Linux                 | `.deb`, `.rpm`, または AppImage          |

## ペンテストエージェント

CyberStrikeには4つの特化したペネトレーションテストエージェントが含まれています：

### web-application
OWASP/WSTG手法に従ったWebアプリケーションセキュリティテスト：
- OWASP Top 10 (A01-A10) カバレッジ
- 12カテゴリーにわたる120以上のWSTGテストケース
- SQLインジェクション、XSS、CSRF、XXE、SSTI検出
- APIセキュリティテスト（REST、GraphQL）
- 認証と認可のバイパス

### cloud-security
クラウドインフラストラクチャのセキュリティ評価：
- AWS（IAM、S3、EC2、Lambda、RDS）
- Azure（AD、Blob Storage、RBAC、Key Vault）
- GCP（IAM、GCS、Compute、Cloud Functions）
- CISベンチマーク準拠チェック
- クラウド権限昇格パス

### internal-network
内部ネットワークとActive Directoryのスペシャリスト：
- ネットワーク列挙とサービス探索
- AD攻撃（Kerberoasting、AS-REP Roasting）
- 認証情報攻撃（パスワードスプレー、Pass-the-Hash）
- 横展開（DCOM、WMI、PSExec）
- 権限昇格（Windows、Linux、ドメイン）

### bug-hunter
バグバウンティハンティング手法：
- アセット検出とサブドメイン列挙
- 履歴データ分析（Wayback、GAU）
- エンドポイントとシークレットのためのJavaScript分析
- 最大の影響のための脆弱性チェーン
- プラットフォーム戦略（HackerOne、Bugcrowd）

## ナレッジベース

`knowledge/web-application/`に組み込まれたWSTG（Webセキュリティテストガイド）チェックリスト：

| カテゴリ    | テスト数 | 説明                     |
|-------------|---------|-------------------------|
| WSTG-INFO   | 10      | 情報収集                 |
| WSTG-CONF   | 13      | 構成テスト               |
| WSTG-IDNT   | 5       | アイデンティティ管理      |
| WSTG-ATHN   | 11      | 認証テスト               |
| WSTG-AUTHZ  | 7       | 認可テスト               |
| WSTG-SESS   | 11      | セッション管理           |
| WSTG-INPV   | 29      | 入力検証                 |
| WSTG-ERRH   | 2       | エラー処理               |
| WSTG-CRYP   | 4       | 暗号化                   |
| WSTG-BUSL   | 10      | ビジネスロジック         |
| WSTG-CLNT   | 14      | クライアントサイドテスト |
| WSTG-APIT   | 4       | APIテスト                |

**合計：120以上の自動テストケース**

## 使用方法

```bash
# Webアプリケーションペンテストを開始
cyberstrike --agent web-application
> "WSTG-INPV-05に従ってhttps://target.comのSQLインジェクションをテスト"

# 偵察を実行
cyberstrike --agent bug-hunter
> "target.comのサブドメインを列挙"

# クラウドセキュリティ監査
cyberstrike --agent cloud-security
> "S3バケットの誤設定についてAWSアカウントを監査"

# 内部ネットワークペンテスト
cyberstrike --agent internal-network
> "ドメインに対してKerberoasting攻撃を実行"
```

## ツール統合

CyberStrikeエージェントは業界標準のセキュリティツールを活用します：

| カテゴリ   | ツール                                |
|------------|--------------------------------------|
| ネットワーク | nmap, masscan, netcat                |
| Web        | nuclei, sqlmap, ffuf, nikto, burp    |
| クラウド    | prowler, scoutsuite, pacu            |
| AD/Windows | bloodhound, netexec, kerbrute        |
| 偵察       | subfinder, amass, httpx, gau         |
| OSINT      | theHarvester, shodan, censys         |

### MCP Kali統合

CyberStrikeには、動的ツールローディングを通じて100以上のKali Linuxツールへのアクセスを提供するMCPサーバー（`packages/mcp-kali`）が含まれており、セッションあたり150K以上のトークンを節約します。

## アーキテクチャ

- **ランタイム**: 高速実行のためのBun
- **言語**: 型安全性のためのTypeScript
- **UI**: ターミナルインターフェースのためのSolid.js + TUI
- **AI**: 15以上のプロバイダーサポート（Anthropic、OpenAI、Google、Azure、AWS Bedrock など）を持つVercel AI SDK
- **MCP**: 拡張可能なツール統合のためのModel Context Protocol

## ドキュメント

完全なドキュメントは[docs.cyberstrike.io](https://docs.cyberstrike.io)で入手できます。

## コントリビュート

貢献に興味がありますか？プルリクエストを送信する前に、[コントリビュートガイド](./CONTRIBUTING.md)をお読みください。

## ライセンス

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">Website</a> |
  <a href="https://docs.cyberstrike.io">Docs</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
