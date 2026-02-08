<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike logo" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>AI驅動的自主滲透測試代理框架。</strong></p>
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
  <img src="packages/web/src/assets/lander/screenshot.jpg" alt="CyberStrike TUI" width="700">
</p>

---

## 什麼是 CyberStrike？

CyberStrike 是一個開源的 AI 滲透測試框架，透過自主代理執行安全評估。它整合了 15+ 種 AI 提供商與專業化的安全測試代理，可自動化探索漏洞。

## 安裝

```bash
# 快速安裝
curl -fsSL https://cyberstrike.io/install | bash

# 套件管理器
npm i -g cyberstrike@latest        # 或 bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS 和 Linux（推薦）

# 從原始碼安裝
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

### 桌面應用程式

提供 macOS、Windows 和 Linux 版本。可從 [發布頁面](https://github.com/CyberStrikeus/cyberstrike.io/releases) 或 [cyberstrike.io/download](https://cyberstrike.io/download) 下載。

| 平台                  | 下載檔案                                 |
| --------------------- | ---------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg`  |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`      |
| Windows               | `cyberstrike-desktop-windows-x64.exe`     |
| Linux                 | `.deb`、`.rpm` 或 AppImage              |

## 滲透測試代理

CyberStrike 包含 4 個專業化的滲透測試代理：

### web-application
遵循 OWASP/WSTG 方法論的 Web 應用程式安全測試：
- 涵蓋 OWASP Top 10 (A01-A10)
- 12 個類別中的 120+ WSTG 測試案例
- SQL 注入、XSS、CSRF、XXE、SSTI 檢測
- API 安全測試（REST、GraphQL）
- 身分驗證與授權繞過

### cloud-security
雲端基礎設施安全評估：
- AWS（IAM、S3、EC2、Lambda、RDS）
- Azure（AD、Blob Storage、RBAC、Key Vault）
- GCP（IAM、GCS、Compute、Cloud Functions）
- CIS 基準合規性檢查
- 雲端權限提升路徑

### internal-network
內部網路與 Active Directory 專家：
- 網路列舉與服務探索
- AD 攻擊（Kerberoasting、AS-REP Roasting）
- 憑證攻擊（密碼噴灑、Pass-the-Hash）
- 橫向移動（DCOM、WMI、PSExec）
- 權限提升（Windows、Linux、網域）

### bug-hunter
漏洞賞金獵捕方法論：
- 資產探索與子網域列舉
- 歷史資料分析（Wayback、GAU）
- JavaScript 分析以找出端點與機密
- 漏洞鏈結以達成最大影響
- 平台策略（HackerOne、Bugcrowd）

## 知識庫

內建的 WSTG（Web 安全測試指南）檢查清單位於 `knowledge/web-application/`：

| 類別        | 測試數量 | 描述            |
|-------------|---------|------------------------|
| WSTG-INFO   | 10      | 資訊收集  |
| WSTG-CONF   | 13      | 設定測試  |
| WSTG-IDNT   | 5       | 身分管理    |
| WSTG-ATHN   | 11      | 身分驗證測試 |
| WSTG-AUTHZ  | 7       | 授權測試  |
| WSTG-SESS   | 11      | 會話管理     |
| WSTG-INPV   | 29      | 輸入驗證       |
| WSTG-ERRH   | 2       | 錯誤處理         |
| WSTG-CRYP   | 4       | 加密           |
| WSTG-BUSL   | 10      | 業務邏輯         |
| WSTG-CLNT   | 14      | 客戶端測試    |
| WSTG-APIT   | 4       | API 測試            |

**總計：120+ 自動化測試案例**

## 使用方法

```bash
# 啟動 Web 應用程式滲透測試
cyberstrike --agent web-application
> "依照 WSTG-INPV-05 測試 https://target.com 的 SQL 注入漏洞"

# 執行偵察
cyberstrike --agent bug-hunter
> "列舉 target.com 的子網域"

# 雲端安全稽核
cyberstrike --agent cloud-security
> "稽核我的 AWS 帳戶是否有 S3 儲存貯體設定錯誤"

# 內部網路滲透測試
cyberstrike --agent internal-network
> "對網域執行 Kerberoasting 攻擊"
```

## 工具整合

CyberStrike 代理利用業界標準安全工具：

| 類別       | 工具                                |
|------------|--------------------------------------|
| 網路       | nmap、masscan、netcat                |
| Web        | nuclei、sqlmap、ffuf、nikto、burp    |
| 雲端       | prowler、scoutsuite、pacu            |
| AD/Windows | bloodhound、netexec、kerbrute        |
| 偵察       | subfinder、amass、httpx、gau         |
| OSINT      | theHarvester、shodan、censys         |

### MCP Kali 整合

CyberStrike 包含一個 MCP 伺服器（`packages/mcp-kali`），透過動態工具載入機制存取 100+ 種 Kali Linux 工具，每次會話節省 150K+ 令牌。

## 架構

- **執行環境**：Bun 快速執行
- **語言**：TypeScript 提供型別安全
- **UI**：Solid.js + TUI 終端介面
- **AI**：Vercel AI SDK，支援 15+ 種提供商（Anthropic、OpenAI、Google、Azure、AWS Bedrock 等）
- **MCP**：模型上下文協定（Model Context Protocol），支援可擴充的工具整合

## 文件

完整文件請參閱 [docs.cyberstrike.io](https://docs.cyberstrike.io)。

## 貢獻

有興趣參與貢獻嗎？在提交 Pull Request 之前，請先閱讀我們的[貢獻指南](./CONTRIBUTING.md)。

## 授權

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">Website</a> |
  <a href="https://docs.cyberstrike.io">Docs</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
