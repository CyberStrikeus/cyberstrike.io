<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike logo" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>KI-gestütztes autonomes Penetrationstest-Agent-Framework.</strong></p>
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

## Was ist CyberStrike?

CyberStrike ist ein Open-Source, KI-gestütztes Penetrationstest-Framework, das autonome Agenten für Sicherheitsbewertungen einsetzt. Es integriert über 15 KI-Anbieter mit spezialisierten Sicherheitstest-Agenten für automatisierte Schwachstellenerkennung.

## Installation

```bash
# Schnellinstallation
curl -fsSL https://cyberstrike.io/install | bash

# Paketmanager
npm i -g cyberstrike@latest        # oder bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS & Linux (empfohlen)

# Aus Quellcode
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

### Desktop-App

Verfügbar für macOS, Windows und Linux. Download von der [Releases-Seite](https://github.com/CyberStrikeus/cyberstrike.io/releases) oder [cyberstrike.io/download](https://cyberstrike.io/download).

| Plattform             | Download                                 |
| --------------------- | ---------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg`  |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`      |
| Windows               | `cyberstrike-desktop-windows-x64.exe`     |
| Linux                 | `.deb`, `.rpm` oder AppImage              |

## Pentest-Agenten

CyberStrike umfasst 4 spezialisierte Penetrationstest-Agenten:

### web-application
Webanwendungs-Sicherheitstests nach OWASP/WSTG-Methodik:
- OWASP Top 10 (A01-A10) Abdeckung
- 120+ WSTG-Testfälle über 12 Kategorien
- SQL Injection, XSS, CSRF, XXE, SSTI Erkennung
- API-Sicherheitstests (REST, GraphQL)
- Authentifizierungs- und Autorisierungs-Bypass

### cloud-security
Cloud-Infrastruktur-Sicherheitsbewertung:
- AWS (IAM, S3, EC2, Lambda, RDS)
- Azure (AD, Blob Storage, RBAC, Key Vault)
- GCP (IAM, GCS, Compute, Cloud Functions)
- CIS Benchmark Compliance-Prüfungen
- Cloud-Privilegieneskalationspfade

### internal-network
Internes Netzwerk & Active Directory Spezialist:
- Netzwerk-Enumeration und Service-Erkennung
- AD-Angriffe (Kerberoasting, AS-REP Roasting)
- Credential-Angriffe (Password Spraying, Pass-the-Hash)
- Lateral Movement (DCOM, WMI, PSExec)
- Privilegieneskalation (Windows, Linux, Domain)

### bug-hunter
Bug-Bounty-Hunting-Methodik:
- Asset-Discovery und Subdomain-Enumeration
- Historische Datenanalyse (Wayback, GAU)
- JavaScript-Analyse für Endpunkte und Secrets
- Schwachstellen-Verkettung für maximale Wirkung
- Plattform-Strategien (HackerOne, Bugcrowd)

## Wissensdatenbank

Integrierte WSTG (Web Security Testing Guide) Checklisten in `knowledge/web-application/`:

| Kategorie   | Tests | Beschreibung                   |
|-------------|-------|--------------------------------|
| WSTG-INFO   | 10    | Informationsbeschaffung        |
| WSTG-CONF   | 13    | Konfigurationstests            |
| WSTG-IDNT   | 5     | Identitätsverwaltung           |
| WSTG-ATHN   | 11    | Authentifizierungstests        |
| WSTG-AUTHZ  | 7     | Autorisierungstests            |
| WSTG-SESS   | 11    | Sitzungsverwaltung             |
| WSTG-INPV   | 29    | Eingabevalidierung             |
| WSTG-ERRH   | 2     | Fehlerbehandlung               |
| WSTG-CRYP   | 4     | Kryptographie                  |
| WSTG-BUSL   | 10    | Geschäftslogik                 |
| WSTG-CLNT   | 14    | Client-seitige Tests           |
| WSTG-APIT   | 4     | API-Tests                      |

**Gesamt: 120+ automatisierte Testfälle**

## Verwendung

```bash
# Webanwendungs-Pentest starten
cyberstrike --agent web-application
> "Teste https://target.com auf SQL Injection gemäß WSTG-INPV-05"

# Reconnaissance durchführen
cyberstrike --agent bug-hunter
> "Enumeriere Subdomains für target.com"

# Cloud-Sicherheitsaudit
cyberstrike --agent cloud-security
> "Prüfe mein AWS-Konto auf S3-Bucket-Fehlkonfigurationen"

# Interner Netzwerk-Pentest
cyberstrike --agent internal-network
> "Führe Kerberoasting-Angriff auf die Domain durch"
```

## Tool-Integrationen

CyberStrike-Agenten nutzen branchenübliche Sicherheitstools:

| Kategorie  | Tools                                |
|------------|--------------------------------------|
| Netzwerk   | nmap, masscan, netcat                |
| Web        | nuclei, sqlmap, ffuf, nikto, burp    |
| Cloud      | prowler, scoutsuite, pacu            |
| AD/Windows | bloodhound, netexec, kerbrute        |
| Recon      | subfinder, amass, httpx, gau         |
| OSINT      | theHarvester, shodan, censys         |

### MCP Kali Integration

CyberStrike enthält einen MCP-Server (`packages/mcp-kali`) mit Zugriff auf über 100 Kali Linux Tools durch dynamisches Tool-Loading, wodurch über 150.000 Tokens pro Sitzung eingespart werden.

## Architektur

- **Runtime**: Bun für schnelle Ausführung
- **Sprache**: TypeScript für Typsicherheit
- **UI**: Solid.js + TUI für Terminal-Oberfläche
- **KI**: Vercel AI SDK mit Unterstützung für über 15 Anbieter (Anthropic, OpenAI, Google, Azure, AWS Bedrock und mehr)
- **MCP**: Model Context Protocol für erweiterbare Tool-Integration

## Dokumentation

Vollständige Dokumentation verfügbar unter [docs.cyberstrike.io](https://docs.cyberstrike.io).

## Mitwirken

Interessiert an einem Beitrag? Bitte lesen Sie unseren [Leitfaden zur Mitarbeit](./CONTRIBUTING.md), bevor Sie einen Pull Request einreichen.

## Lizenz

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">Website</a> |
  <a href="https://docs.cyberstrike.io">Docs</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
