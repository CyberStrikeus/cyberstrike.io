<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike logo" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>AI-powered autonomous penetration testing agent framework.</strong></p>
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

## What is CyberStrike?

CyberStrike is an open-source, AI-powered penetration testing framework that uses autonomous agents to perform security assessments. It integrates 15+ AI providers with specialized security testing agents for automated vulnerability discovery.

## Installation

```bash
# Quick install
curl -fsSL https://cyberstrike.io/install | bash

# Package managers
npm i -g cyberstrike@latest        # or bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS & Linux (recommended)

# From source
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

### Desktop App

Available for macOS, Windows, and Linux. Download from the [releases page](https://github.com/CyberStrikeus/cyberstrike.io/releases) or [cyberstrike.io/download](https://cyberstrike.io/download).

| Platform              | Download                                 |
| --------------------- | ---------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg`  |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`      |
| Windows               | `cyberstrike-desktop-windows-x64.exe`     |
| Linux                 | `.deb`, `.rpm`, or AppImage              |

## Pentest Agents

CyberStrike includes 4 specialized penetration testing agents:

### web-application
Web application security testing following OWASP/WSTG methodology:
- OWASP Top 10 (A01-A10) coverage
- 120+ WSTG test cases across 12 categories
- SQL Injection, XSS, CSRF, XXE, SSTI detection
- API security testing (REST, GraphQL)
- Authentication & authorization bypass

### cloud-security
Cloud infrastructure security assessment:
- AWS (IAM, S3, EC2, Lambda, RDS)
- Azure (AD, Blob Storage, RBAC, Key Vault)
- GCP (IAM, GCS, Compute, Cloud Functions)
- CIS Benchmark compliance checks
- Cloud privilege escalation paths

### internal-network
Internal network & Active Directory specialist:
- Network enumeration and service discovery
- AD attacks (Kerberoasting, AS-REP Roasting)
- Credential attacks (Password Spraying, Pass-the-Hash)
- Lateral movement (DCOM, WMI, PSExec)
- Privilege escalation (Windows, Linux, Domain)

### bug-hunter
Bug bounty hunting methodology:
- Asset discovery and subdomain enumeration
- Historical data analysis (Wayback, GAU)
- JavaScript analysis for endpoints and secrets
- Vulnerability chaining for maximum impact
- Platform strategies (HackerOne, Bugcrowd)

## Knowledge Base

Built-in WSTG (Web Security Testing Guide) checklists in `knowledge/web-application/`:

| Category    | Tests | Description            |
|-------------|-------|------------------------|
| WSTG-INFO   | 10    | Information Gathering  |
| WSTG-CONF   | 13    | Configuration Testing  |
| WSTG-IDNT   | 5     | Identity Management    |
| WSTG-ATHN   | 11    | Authentication Testing |
| WSTG-AUTHZ  | 7     | Authorization Testing  |
| WSTG-SESS   | 11    | Session Management     |
| WSTG-INPV   | 29    | Input Validation       |
| WSTG-ERRH   | 2     | Error Handling         |
| WSTG-CRYP   | 4     | Cryptography           |
| WSTG-BUSL   | 10    | Business Logic         |
| WSTG-CLNT   | 14    | Client-side Testing    |
| WSTG-APIT   | 4     | API Testing            |

**Total: 120+ automated test cases**

## Usage

```bash
# Start web application pentest
cyberstrike --agent web-application
> "Test https://target.com for SQL injection following WSTG-INPV-05"

# Run reconnaissance
cyberstrike --agent bug-hunter
> "Enumerate subdomains for target.com"

# Cloud security audit
cyberstrike --agent cloud-security
> "Audit my AWS account for S3 bucket misconfigurations"

# Internal network pentest
cyberstrike --agent internal-network
> "Perform Kerberoasting attack on the domain"
```

## Tool Integrations

CyberStrike agents leverage industry-standard security tools:

| Category   | Tools                                |
|------------|--------------------------------------|
| Network    | nmap, masscan, netcat                |
| Web        | nuclei, sqlmap, ffuf, nikto, burp    |
| Cloud      | prowler, scoutsuite, pacu            |
| AD/Windows | bloodhound, netexec, kerbrute        |
| Recon      | subfinder, amass, httpx, gau         |
| OSINT      | theHarvester, shodan, censys         |

### MCP Kali Integration

CyberStrike includes an MCP server (`packages/mcp-kali`) with access to 100+ Kali Linux tools through dynamic tool loading, saving 150K+ tokens per session.

## Architecture

- **Runtime**: Bun for fast execution
- **Language**: TypeScript for type safety
- **UI**: Solid.js + TUI for terminal interface
- **AI**: Vercel AI SDK with 15+ provider support (Anthropic, OpenAI, Google, Azure, AWS Bedrock, and more)
- **MCP**: Model Context Protocol for extensible tool integration

## Documentation

Full documentation available at [docs.cyberstrike.io](https://docs.cyberstrike.io).

## Contributing

Interested in contributing? Please read our [contributing guide](./CONTRIBUTING.md) before submitting a pull request.

## License

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">Website</a> |
  <a href="https://docs.cyberstrike.io">Docs</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
