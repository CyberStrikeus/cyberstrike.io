<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike logo" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>Autonomiczny framework agentów do testów penetracyjnych oparty na AI.</strong></p>
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

## Czym jest CyberStrike?

CyberStrike to otwartoźródłowy framework do testów penetracyjnych oparty na AI, który wykorzystuje autonomiczne agenty do przeprowadzania ocen bezpieczeństwa. Integruje ponad 15 dostawców AI ze specjalistycznymi agentami testów bezpieczeństwa do automatycznego wykrywania podatności.

## Instalacja

```bash
# Szybka instalacja
curl -fsSL https://cyberstrike.io/install | bash

# Menedżery pakietów
npm i -g cyberstrike@latest        # lub bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS i Linux (zalecane)

# Ze źródeł
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

### Aplikacja desktopowa

Dostępna dla macOS, Windows i Linux. Pobierz ze [strony wydań](https://github.com/CyberStrikeus/cyberstrike.io/releases) lub [cyberstrike.io/download](https://cyberstrike.io/download).

| Platforma             | Pobierz                                  |
| --------------------- | ---------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg`  |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`      |
| Windows               | `cyberstrike-desktop-windows-x64.exe`     |
| Linux                 | `.deb`, `.rpm` lub AppImage              |

## Agenty pentestowe

CyberStrike zawiera 4 wyspecjalizowane agenty testów penetracyjnych:

### web-application
Testowanie bezpieczeństwa aplikacji webowych zgodnie z metodologią OWASP/WSTG:
- Pokrycie OWASP Top 10 (A01-A10)
- Ponad 120 przypadków testowych WSTG w 12 kategoriach
- Wykrywanie SQL Injection, XSS, CSRF, XXE, SSTI
- Testowanie bezpieczeństwa API (REST, GraphQL)
- Obejście uwierzytelniania i autoryzacji

### cloud-security
Ocena bezpieczeństwa infrastruktury chmurowej:
- AWS (IAM, S3, EC2, Lambda, RDS)
- Azure (AD, Blob Storage, RBAC, Key Vault)
- GCP (IAM, GCS, Compute, Cloud Functions)
- Kontrole zgodności z CIS Benchmark
- Ścieżki eskalacji uprawnień w chmurze

### internal-network
Specjalista od sieci wewnętrznych i Active Directory:
- Enumeracja sieci i wykrywanie usług
- Ataki AD (Kerberoasting, AS-REP Roasting)
- Ataki na poświadczenia (Password Spraying, Pass-the-Hash)
- Ruch lateralny (DCOM, WMI, PSExec)
- Eskalacja uprawnień (Windows, Linux, Domena)

### bug-hunter
Metodologia łowienia błędów bug bounty:
- Odkrywanie zasobów i enumeracja subdomen
- Analiza danych historycznych (Wayback, GAU)
- Analiza JavaScript w poszukiwaniu endpointów i sekretów
- Łańcuchy podatności dla maksymalnego wpływu
- Strategie dla platform (HackerOne, Bugcrowd)

## Baza wiedzy

Wbudowane listy kontrolne WSTG (Web Security Testing Guide) w `knowledge/web-application/`:

| Kategoria   | Testy | Opis                           |
|-------------|-------|--------------------------------|
| WSTG-INFO   | 10    | Zbieranie informacji           |
| WSTG-CONF   | 13    | Testowanie konfiguracji        |
| WSTG-IDNT   | 5     | Zarządzanie tożsamością        |
| WSTG-ATHN   | 11    | Testowanie uwierzytelniania    |
| WSTG-AUTHZ  | 7     | Testowanie autoryzacji         |
| WSTG-SESS   | 11    | Zarządzanie sesją              |
| WSTG-INPV   | 29    | Walidacja danych wejściowych   |
| WSTG-ERRH   | 2     | Obsługa błędów                 |
| WSTG-CRYP   | 4     | Kryptografia                   |
| WSTG-BUSL   | 10    | Logika biznesowa               |
| WSTG-CLNT   | 14    | Testowanie po stronie klienta  |
| WSTG-APIT   | 4     | Testowanie API                 |

**Razem: Ponad 120 zautomatyzowanych przypadków testowych**

## Użycie

```bash
# Rozpocznij pentest aplikacji webowej
cyberstrike --agent web-application
> "Przetestuj https://target.com pod kątem SQL injection zgodnie z WSTG-INPV-05"

# Uruchom rozpoznanie
cyberstrike --agent bug-hunter
> "Wylicz subdomeny dla target.com"

# Audyt bezpieczeństwa chmury
cyberstrike --agent cloud-security
> "Przeprowadź audyt mojego konta AWS pod kątem błędnych konfiguracji zasobników S3"

# Pentest sieci wewnętrznej
cyberstrike --agent internal-network
> "Przeprowadź atak Kerberoasting na domenę"
```

## Integracje narzędzi

Agenty CyberStrike wykorzystują standardowe w branży narzędzia bezpieczeństwa:

| Kategoria    | Narzędzia                            |
|--------------|--------------------------------------|
| Sieć         | nmap, masscan, netcat                |
| Web          | nuclei, sqlmap, ffuf, nikto, burp    |
| Chmura       | prowler, scoutsuite, pacu            |
| AD/Windows   | bloodhound, netexec, kerbrute        |
| Rekonesans   | subfinder, amass, httpx, gau         |
| OSINT        | theHarvester, shodan, censys         |

### Integracja MCP Kali

CyberStrike zawiera serwer MCP (`packages/mcp-kali`) z dostępem do ponad 100 narzędzi Kali Linux poprzez dynamiczne ładowanie narzędzi, oszczędzając ponad 150 tys. tokenów na sesję.

## Architektura

- **Runtime**: Bun dla szybkiego wykonywania
- **Język**: TypeScript dla bezpieczeństwa typów
- **UI**: Solid.js + TUI dla interfejsu terminalowego
- **AI**: Vercel AI SDK z obsługą ponad 15 dostawców (Anthropic, OpenAI, Google, Azure, AWS Bedrock i więcej)
- **MCP**: Model Context Protocol dla rozszerzalnej integracji narzędzi

## Dokumentacja

Pełna dokumentacja dostępna na [docs.cyberstrike.io](https://docs.cyberstrike.io).

## Współtworzenie

Zainteresowany współtworzeniem? Przeczytaj nasz [przewodnik współtworzenia](./CONTRIBUTING.md) przed przesłaniem pull requesta.

## Licencja

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">Strona</a> |
  <a href="https://docs.cyberstrike.io">Dokumentacja</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
