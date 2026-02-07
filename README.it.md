<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike logo" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>Framework autonomo per test di penetrazione basato sull'IA.</strong></p>
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

## Cos'è CyberStrike?

CyberStrike è un framework open-source per test di penetrazione basato sull'IA che utilizza agenti autonomi per eseguire valutazioni di sicurezza. Integra oltre 15 provider AI con agenti specializzati nei test di sicurezza per la scoperta automatizzata di vulnerabilità.

## Installazione

```bash
# Installazione rapida
curl -fsSL https://cyberstrike.io/install | bash

# Gestori di pacchetti
npm i -g cyberstrike@latest        # o bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS e Linux (consigliato)

# Dal sorgente
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

### App Desktop

Disponibile per macOS, Windows e Linux. Scarica dalla [pagina delle release](https://github.com/CyberStrikeus/cyberstrike.io/releases) o da [cyberstrike.io/download](https://cyberstrike.io/download).

| Piattaforma           | Download                                 |
| --------------------- | ---------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg`  |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`      |
| Windows               | `cyberstrike-desktop-windows-x64.exe`     |
| Linux                 | `.deb`, `.rpm`, o AppImage              |

## Agenti di Pentest

CyberStrike include 4 agenti specializzati per test di penetrazione:

### web-application
Test di sicurezza per applicazioni web seguendo la metodologia OWASP/WSTG:
- Copertura OWASP Top 10 (A01-A10)
- Oltre 120 test case WSTG in 12 categorie
- Rilevamento SQL Injection, XSS, CSRF, XXE, SSTI
- Test di sicurezza API (REST, GraphQL)
- Bypass di autenticazione e autorizzazione

### cloud-security
Valutazione della sicurezza dell'infrastruttura cloud:
- AWS (IAM, S3, EC2, Lambda, RDS)
- Azure (AD, Blob Storage, RBAC, Key Vault)
- GCP (IAM, GCS, Compute, Cloud Functions)
- Controlli di conformità CIS Benchmark
- Percorsi di escalation dei privilegi cloud

### internal-network
Specialista di reti interne e Active Directory:
- Enumerazione di rete e scoperta di servizi
- Attacchi AD (Kerberoasting, AS-REP Roasting)
- Attacchi alle credenziali (Password Spraying, Pass-the-Hash)
- Movimento laterale (DCOM, WMI, PSExec)
- Escalation dei privilegi (Windows, Linux, Domain)

### bug-hunter
Metodologia per caccia ai bug bounty:
- Scoperta di asset ed enumerazione di sottodomini
- Analisi di dati storici (Wayback, GAU)
- Analisi JavaScript per endpoint e segreti
- Concatenazione di vulnerabilità per massimo impatto
- Strategie per piattaforme (HackerOne, Bugcrowd)

## Base di Conoscenza

Checklist WSTG (Web Security Testing Guide) integrate in `knowledge/web-application/`:

| Categoria   | Test | Descrizione                    |
|-------------|------|--------------------------------|
| WSTG-INFO   | 10   | Information Gathering          |
| WSTG-CONF   | 13   | Configuration Testing          |
| WSTG-IDNT   | 5    | Identity Management            |
| WSTG-ATHN   | 11   | Authentication Testing         |
| WSTG-AUTHZ  | 7    | Authorization Testing          |
| WSTG-SESS   | 11   | Session Management             |
| WSTG-INPV   | 29   | Input Validation               |
| WSTG-ERRH   | 2    | Error Handling                 |
| WSTG-CRYP   | 4    | Cryptography                   |
| WSTG-BUSL   | 10   | Business Logic                 |
| WSTG-CLNT   | 14   | Client-side Testing            |
| WSTG-APIT   | 4    | API Testing                    |

**Totale: oltre 120 test case automatizzati**

## Utilizzo

```bash
# Avvia pentest per applicazioni web
cyberstrike --agent web-application
> "Testa https://target.com per SQL injection seguendo WSTG-INPV-05"

# Esegui ricognizione
cyberstrike --agent bug-hunter
> "Enumera i sottodomini per target.com"

# Audit di sicurezza cloud
cyberstrike --agent cloud-security
> "Controlla il mio account AWS per configurazioni errate dei bucket S3"

# Pentest di rete interna
cyberstrike --agent internal-network
> "Esegui attacco Kerberoasting sul dominio"
```

## Integrazioni Strumenti

Gli agenti CyberStrike sfruttano strumenti di sicurezza standard del settore:

| Categoria   | Strumenti                                |
|------------|------------------------------------------|
| Network    | nmap, masscan, netcat                    |
| Web        | nuclei, sqlmap, ffuf, nikto, burp        |
| Cloud      | prowler, scoutsuite, pacu                |
| AD/Windows | bloodhound, netexec, kerbrute            |
| Recon      | subfinder, amass, httpx, gau             |
| OSINT      | theHarvester, shodan, censys             |

### Integrazione MCP Kali

CyberStrike include un server MCP (`packages/mcp-kali`) con accesso a oltre 100 strumenti Kali Linux tramite caricamento dinamico degli strumenti, risparmiando oltre 150K token per sessione.

## Architettura

- **Runtime**: Bun per un'esecuzione veloce
- **Linguaggio**: TypeScript per la sicurezza dei tipi
- **UI**: Solid.js + TUI per interfaccia terminale
- **AI**: Vercel AI SDK con supporto per oltre 15 provider (Anthropic, OpenAI, Google, Azure, AWS Bedrock e altri)
- **MCP**: Model Context Protocol per integrazione estensibile degli strumenti

## Documentazione

Documentazione completa disponibile su [docs.cyberstrike.io](https://docs.cyberstrike.io).

## Contribuire

Interessato a contribuire? Leggi la nostra [guida alla contribuzione](./CONTRIBUTING.md) prima di inviare una pull request.

## Licenza

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">Website</a> |
  <a href="https://docs.cyberstrike.io">Docs</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
