<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike logo" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>AI-drevet autonomt penetrasjonstestagent-rammeverk.</strong></p>
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

## Hva er CyberStrike?

CyberStrike er et åpen kildekode, AI-drevet penetrasjonstest-rammeverk som bruker autonome agenter for å utføre sikkerhetsvurderinger. Det integrerer 15+ AI-leverandører med spesialiserte sikkerhetstestingsagenter for automatisert sårbarhetsentdekking.

## Installasjon

```bash
# Rask installasjon
curl -fsSL https://cyberstrike.io/install | bash

# Pakkehåndterere
npm i -g cyberstrike@latest        # eller bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS & Linux (anbefalt)

# Fra kildekode
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

### Skrivebordsapp

Tilgjengelig for macOS, Windows og Linux. Last ned fra [releases-siden](https://github.com/CyberStrikeus/cyberstrike.io/releases) eller [cyberstrike.io/download](https://cyberstrike.io/download).

| Plattform             | Nedlasting                                |
| --------------------- | ----------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg`  |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`      |
| Windows               | `cyberstrike-desktop-windows-x64.exe`     |
| Linux                 | `.deb`, `.rpm` eller AppImage             |

## Penetrasjonstest-agenter

CyberStrike inkluderer 4 spesialiserte penetrasjonstest-agenter:

### web-application
Weapplikasjonssikkerhetstesting som følger OWASP/WSTG-metodikk:
- OWASP Top 10 (A01-A10) dekning
- 120+ WSTG-testtilfeller på tvers av 12 kategorier
- SQL-injeksjon, XSS, CSRF, XXE, SSTI-deteksjon
- API-sikkerhetstesting (REST, GraphQL)
- Autentiserings- og autorisasjonsomgåelse

### cloud-security
Vurdering av skyinfrastruktur-sikkerhet:
- AWS (IAM, S3, EC2, Lambda, RDS)
- Azure (AD, Blob Storage, RBAC, Key Vault)
- GCP (IAM, GCS, Compute, Cloud Functions)
- CIS Benchmark-overholdelseskontroller
- Privilegieeskaleringsveier i skyen

### internal-network
Internt nettverk & Active Directory-spesialist:
- Nettverksoppregning og tjenesteoppdagelse
- AD-angrep (Kerberoasting, AS-REP Roasting)
- Legitimasjonsangrep (Password Spraying, Pass-the-Hash)
- Lateral bevegelse (DCOM, WMI, PSExec)
- Privilegieeskalering (Windows, Linux, Domain)

### bug-hunter
Bug bounty-jaktmetodikk:
- Ressursoppdagelse og underdomene-oppregning
- Historisk dataanalyse (Wayback, GAU)
- JavaScript-analyse for endepunkter og hemmeligheter
- Sårbarhetskjeding for maksimal påvirkning
- Plattformstrategier (HackerOne, Bugcrowd)

## Kunnskapsbase

Innebygde WSTG (Web Security Testing Guide)-sjekklister i `knowledge/web-application/`:

| Kategori    | Tester | Beskrivelse                  |
|-------------|--------|------------------------------|
| WSTG-INFO   | 10     | Informasjonsinnsamling       |
| WSTG-CONF   | 13     | Konfigurasjonstesting        |
| WSTG-IDNT   | 5      | Identitetsstyring            |
| WSTG-ATHN   | 11     | Autentiseringstesting        |
| WSTG-AUTHZ  | 7      | Autorisasjonstesting         |
| WSTG-SESS   | 11     | Sesjonshåndtering            |
| WSTG-INPV   | 29     | Inndatavalidering            |
| WSTG-ERRH   | 2      | Feilhåndtering               |
| WSTG-CRYP   | 4      | Kryptografi                  |
| WSTG-BUSL   | 10     | Forretningslogikk            |
| WSTG-CLNT   | 14     | Klientsidstesting            |
| WSTG-APIT   | 4      | API-testing                  |

**Totalt: 120+ automatiserte testtilfeller**

## Bruk

```bash
# Start weapplikasjonspentest
cyberstrike --agent web-application
> "Test https://target.com for SQL-injeksjon etter WSTG-INPV-05"

# Kjør rekognosering
cyberstrike --agent bug-hunter
> "Regn opp underdomener for target.com"

# Skysikkerhetsrevisjon
cyberstrike --agent cloud-security
> "Revidere AWS-kontoen min for S3-bucket-feilkonfigurasjoner"

# Internt nettverkspentest
cyberstrike --agent internal-network
> "Utfør Kerberoasting-angrep på domenet"
```

## Verktøyintegrasjoner

CyberStrike-agenter utnytter bransjestandardsikkerhetsverktøy:

| Kategori   | Verktøy                              |
|------------|--------------------------------------|
| Nettverk   | nmap, masscan, netcat                |
| Web        | nuclei, sqlmap, ffuf, nikto, burp    |
| Sky        | prowler, scoutsuite, pacu            |
| AD/Windows | bloodhound, netexec, kerbrute        |
| Recon      | subfinder, amass, httpx, gau         |
| OSINT      | theHarvester, shodan, censys         |

### MCP Kali-integrasjon

CyberStrike inkluderer en MCP-server (`packages/mcp-kali`) med tilgang til 100+ Kali Linux-verktøy gjennom dynamisk verktøylasting, som sparer 150K+ tokens per økt.

## Arkitektur

- **Runtime**: Bun for rask utførelse
- **Språk**: TypeScript for typesikkerhet
- **UI**: Solid.js + TUI for terminalgrensesnitt
- **AI**: Vercel AI SDK med 15+ leverandørstøtte (Anthropic, OpenAI, Google, Azure, AWS Bedrock og mer)
- **MCP**: Model Context Protocol for utvidbar verktøyintegrasjon

## Dokumentasjon

Fullstendig dokumentasjon tilgjengelig på [docs.cyberstrike.io](https://docs.cyberstrike.io).

## Bidra

Interessert i å bidra? Vennligst les vår [bidragsguide](./CONTRIBUTING.md) før du sender inn en pull request.

## Lisens

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">Nettsted</a> |
  <a href="https://docs.cyberstrike.io">Dokumentasjon</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
