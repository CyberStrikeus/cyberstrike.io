<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike logo" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>AI驱动的自主渗透测试代理框架。</strong></p>
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

## 什么是CyberStrike？

CyberStrike 是一个开源的、AI驱动的渗透测试框架，使用自主代理执行安全评估。它集成了15+个AI提供商和专业的安全测试代理，用于自动化漏洞发现。

## 安装

```bash
# 快速安装
curl -fsSL https://cyberstrike.io/install | bash

# 包管理器
npm i -g cyberstrike@latest        # 或 bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS 和 Linux（推荐）

# 从源码安装
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

## 桌面应用

适用于 macOS、Windows 和 Linux。从[发布页面](https://github.com/CyberStrikeus/cyberstrike.io/releases)下载或访问 [cyberstrike.io/download](https://cyberstrike.io/download)。

| 平台              | 下载                                 |
| --------------------- | ---------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg`  |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`      |
| Windows               | `cyberstrike-desktop-windows-x64.exe`     |
| Linux                 | `.deb`、`.rpm` 或 AppImage              |

## 渗透测试代理

CyberStrike 包含4个专业的渗透测试代理：

### web-application
遵循 OWASP/WSTG 方法论的Web应用程序安全测试：
- OWASP Top 10（A01-A10）覆盖
- 跨12个类别的120+个WSTG测试用例
- SQL注入、XSS、CSRF、XXE、SSTI 检测
- API安全测试（REST、GraphQL）
- 认证和授权绕过

### cloud-security
云基础设施安全评估：
- AWS（IAM、S3、EC2、Lambda、RDS）
- Azure（AD、Blob Storage、RBAC、Key Vault）
- GCP（IAM、GCS、Compute、Cloud Functions）
- CIS基准合规性检查
- 云权限提升路径

### internal-network
内部网络和Active Directory专家：
- 网络枚举和服务发现
- AD攻击（Kerberoasting、AS-REP Roasting）
- 凭证攻击（密码喷射、Pass-the-Hash）
- 横向移动（DCOM、WMI、PSExec）
- 权限提升（Windows、Linux、域）

### bug-hunter
漏洞赏金猎人方法论：
- 资产发现和子域名枚举
- 历史数据分析（Wayback、GAU）
- JavaScript分析以查找端点和密钥
- 漏洞链以实现最大影响
- 平台策略（HackerOne、Bugcrowd）

## 知识库

内置的WSTG（Web安全测试指南）检查清单位于 `knowledge/web-application/`：

| 类别    | 测试数 | 描述            |
|-------------|-------|------------------------|
| WSTG-INFO   | 10    | 信息收集  |
| WSTG-CONF   | 13    | 配置测试  |
| WSTG-IDNT   | 5     | 身份管理    |
| WSTG-ATHN   | 11    | 认证测试 |
| WSTG-AUTHZ  | 7     | 授权测试  |
| WSTG-SESS   | 11    | 会话管理     |
| WSTG-INPV   | 29    | 输入验证       |
| WSTG-ERRH   | 2     | 错误处理         |
| WSTG-CRYP   | 4     | 密码学           |
| WSTG-BUSL   | 10    | 业务逻辑         |
| WSTG-CLNT   | 14    | 客户端测试    |
| WSTG-APIT   | 4     | API测试            |

**总计：120+个自动化测试用例**

## 使用方法

```bash
# 启动Web应用程序渗透测试
cyberstrike --agent web-application
> "测试 https://target.com 的SQL注入漏洞，遵循 WSTG-INPV-05"

# 运行侦察
cyberstrike --agent bug-hunter
> "枚举 target.com 的子域名"

# 云安全审计
cyberstrike --agent cloud-security
> "审计我的AWS账户是否存在S3存储桶配置错误"

# 内部网络渗透测试
cyberstrike --agent internal-network
> "对域执行Kerberoasting攻击"
```

## 工具集成

CyberStrike 代理利用行业标准的安全工具：

| 类别   | 工具                                |
|------------|--------------------------------------|
| 网络    | nmap、masscan、netcat                |
| Web        | nuclei、sqlmap、ffuf、nikto、burp    |
| 云      | prowler、scoutsuite、pacu            |
| AD/Windows | bloodhound、netexec、kerbrute        |
| 侦察      | subfinder、amass、httpx、gau         |
| OSINT      | theHarvester、shodan、censys         |

### MCP Kali 集成

CyberStrike 包含一个MCP服务器（`packages/mcp-kali`），通过动态工具加载访问100+个Kali Linux工具，每个会话节省150K+个令牌。

## 架构

- **运行时**: Bun，快速执行
- **语言**: TypeScript，类型安全
- **UI**: Solid.js + TUI 终端界面
- **AI**: Vercel AI SDK，支持15+个提供商（Anthropic、OpenAI、Google、Azure、AWS Bedrock 等）
- **MCP**: 模型上下文协议，可扩展的工具集成

## 文档

完整文档请访问 [docs.cyberstrike.io](https://docs.cyberstrike.io)。

## 贡献

有兴趣贡献吗？在提交Pull Request之前，请阅读我们的[贡献指南](./CONTRIBUTING.md)。

## 许可证

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">网站</a> |
  <a href="https://docs.cyberstrike.io">文档</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
