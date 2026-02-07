<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike logo" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>AI-drevet autonomt penetrationstestagent-framework.</strong></p>
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

## Hvad er CyberStrike?

CyberStrike er et open-source, AI-drevet penetrationstestframework, der bruger autonome agenter til at udføre sikkerhedsvurderinger. Det integrerer 15+ AI-udbydere med specialiserede sikkerhedstestagenter til automatiseret sårbarheds-opdagelse.

## Installation

```bash
# Hurtig installation
curl -fsSL https://cyberstrike.io/install | bash

# Pakkehåndteringer
npm i -g cyberstrike@latest        # eller bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS & Linux (anbefalet)

# Fra kildekode
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

### Desktop-app

Tilgængelig til macOS, Windows og Linux. Download fra [releases-siden](https://github.com/CyberStrikeus/cyberstrike.io/releases) eller [cyberstrike.io/download](https://cyberstrike.io/download).

| Platform              | Download                                 |
| --------------------- | ---------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg`  |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`      |
| Windows               | `cyberstrike-desktop-windows-x64.exe`     |
| Linux                 | `.deb`, `.rpm`, eller AppImage           |

## Pentest-agenter

CyberStrike inkluderer 4 specialiserede penetrationstestagenter:

### web-application
Webapplikationssikkerhedstest efter OWASP/WSTG-metodik:
- OWASP Top 10 (A01-A10) dækning
- 120+ WSTG-testcases på tværs af 12 kategorier
- SQL Injection, XSS, CSRF, XXE, SSTI-detektion
- API-sikkerhedstest (REST, GraphQL)
- Autentificerings- og autorisationsomgåelse

### cloud-security
Sikkerhedsvurdering af cloud-infrastruktur:
- AWS (IAM, S3, EC2, Lambda, RDS)
- Azure (AD, Blob Storage, RBAC, Key Vault)
- GCP (IAM, GCS, Compute, Cloud Functions)
- CIS Benchmark-compliance-tjek
- Cloud-privilegieeskaleringsforløb

### internal-network
Internt netværk & Active Directory-specialist:
- Netværksenumeration og serviceopdagelse
- AD-angreb (Kerberoasting, AS-REP Roasting)
- Credential-angreb (Password Spraying, Pass-the-Hash)
- Lateral movement (DCOM, WMI, PSExec)
- Privilegieeskalering (Windows, Linux, Domain)

### bug-hunter
Bug bounty hunting-metodik:
- Asset-opdagelse og subdomain-enumeration
- Historisk dataanalyse (Wayback, GAU)
- JavaScript-analyse til endpoints og secrets
- Sårbarheds-chaining for maksimal impact
- Platformstrategier (HackerOne, Bugcrowd)

## Vidensbase

Indbyggede WSTG (Web Security Testing Guide) tjeklister i `knowledge/web-application/`:

| Kategori    | Tests | Beskrivelse               |
|-------------|-------|---------------------------|
| WSTG-INFO   | 10    | Informationsindsamling    |
| WSTG-CONF   | 13    | Konfigurationstest        |
| WSTG-IDNT   | 5     | Identitetshåndtering      |
| WSTG-ATHN   | 11    | Autentificeringstest      |
| WSTG-AUTHZ  | 7     | Autorisationstest         |
| WSTG-SESS   | 11    | Sessionshåndtering        |
| WSTG-INPV   | 29    | Inputvalidering           |
| WSTG-ERRH   | 2     | Fejlhåndtering            |
| WSTG-CRYP   | 4     | Kryptografi               |
| WSTG-BUSL   | 10    | Forretningslogik          |
| WSTG-CLNT   | 14    | Client-side-test          |
| WSTG-APIT   | 4     | API-test                  |

**I alt: 120+ automatiserede testcases**

## Brug

```bash
# Start webapplikations-pentest
cyberstrike --agent web-application
> "Test https://target.com for SQL injection efter WSTG-INPV-05"

# Kør reconnaissance
cyberstrike --agent bug-hunter
> "Enumerer subdomains for target.com"

# Cloud-sikkerhedsaudit
cyberstrike --agent cloud-security
> "Auditer min AWS-konto for S3-bucket fejlkonfigurationer"

# Internt netværks-pentest
cyberstrike --agent internal-network
> "Udfør Kerberoasting-angreb på domænet"
```

## Værktøjsintegrationer

CyberStrike-agenter udnytter industristandard sikkerhedsværktøjer:

| Kategori   | Værktøjer                            |
|------------|--------------------------------------|
| Netværk    | nmap, masscan, netcat                |
| Web        | nuclei, sqlmap, ffuf, nikto, burp    |
| Cloud      | prowler, scoutsuite, pacu            |
| AD/Windows | bloodhound, netexec, kerbrute        |
| Recon      | subfinder, amass, httpx, gau         |
| OSINT      | theHarvester, shodan, censys         |

### MCP Kali-integration

CyberStrike inkluderer en MCP-server (`packages/mcp-kali`) med adgang til 100+ Kali Linux-værktøjer gennem dynamisk værktøjsindlæsning, hvilket sparer 150K+ tokens pr. session.

## Arkitektur

- **Runtime**: Bun til hurtig eksekvering
- **Sprog**: TypeScript til typesikkerhed
- **UI**: Solid.js + TUI til terminalinterface
- **AI**: Vercel AI SDK med 15+ udbydersupport (Anthropic, OpenAI, Google, Azure, AWS Bedrock og flere)
- **MCP**: Model Context Protocol til udvidelig værktøjsintegration

## Dokumentation

Fuld dokumentation tilgængelig på [docs.cyberstrike.io](https://docs.cyberstrike.io).

## Bidrag

Interesseret i at bidrage? Læs venligst vores [bidragsguide](./CONTRIBUTING.md) før du indsender en pull request.

## Licens

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">Website</a> |
  <a href="https://docs.cyberstrike.io">Docs</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
