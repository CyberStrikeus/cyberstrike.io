<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike Logo" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>Framework autonome de tests de pénétration propulsé par l'IA.</strong></p>
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

## Qu'est-ce que CyberStrike ?

CyberStrike est un framework open-source de tests de pénétration propulsé par l'IA qui utilise des agents autonomes pour effectuer des évaluations de sécurité. Il intègre plus de 15 fournisseurs d'IA avec des agents spécialisés dans les tests de sécurité pour la découverte automatisée de vulnérabilités.

## Installation

```bash
# Installation rapide
curl -fsSL https://cyberstrike.io/install | bash

# Gestionnaires de paquets
npm i -g cyberstrike@latest        # ou bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS & Linux (recommandé)

# Depuis les sources
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

### Application de Bureau

Disponible pour macOS, Windows et Linux. Téléchargez depuis la [page des versions](https://github.com/CyberStrikeus/cyberstrike.io/releases) ou [cyberstrike.io/download](https://cyberstrike.io/download).

| Plateforme            | Téléchargement                           |
| --------------------- | ---------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg`  |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`      |
| Windows               | `cyberstrike-desktop-windows-x64.exe`     |
| Linux                 | `.deb`, `.rpm`, ou AppImage              |

## Agents de Pentest

CyberStrike inclut 4 agents spécialisés dans les tests de pénétration :

### web-application
Tests de sécurité des applications web suivant la méthodologie OWASP/WSTG :
- Couverture OWASP Top 10 (A01-A10)
- Plus de 120 cas de test WSTG répartis dans 12 catégories
- Détection SQL Injection, XSS, CSRF, XXE, SSTI
- Tests de sécurité API (REST, GraphQL)
- Contournement d'authentification et d'autorisation

### cloud-security
Évaluation de sécurité des infrastructures cloud :
- AWS (IAM, S3, EC2, Lambda, RDS)
- Azure (AD, Blob Storage, RBAC, Key Vault)
- GCP (IAM, GCS, Compute, Cloud Functions)
- Vérifications de conformité CIS Benchmark
- Chemins d'escalade de privilèges cloud

### internal-network
Spécialiste des réseaux internes et Active Directory :
- Énumération réseau et découverte de services
- Attaques AD (Kerberoasting, AS-REP Roasting)
- Attaques par identifiants (Password Spraying, Pass-the-Hash)
- Déplacement latéral (DCOM, WMI, PSExec)
- Escalade de privilèges (Windows, Linux, Domaine)

### bug-hunter
Méthodologie de chasse aux bugs (bug bounty) :
- Découverte d'actifs et énumération de sous-domaines
- Analyse de données historiques (Wayback, GAU)
- Analyse JavaScript pour endpoints et secrets
- Chaînage de vulnérabilités pour un impact maximal
- Stratégies de plateformes (HackerOne, Bugcrowd)

## Base de Connaissances

Listes de vérification WSTG (Web Security Testing Guide) intégrées dans `knowledge/web-application/` :

| Catégorie   | Tests | Description            |
|-------------|-------|------------------------|
| WSTG-INFO   | 10    | Collecte d'informations |
| WSTG-CONF   | 13    | Tests de configuration  |
| WSTG-IDNT   | 5     | Gestion d'identité      |
| WSTG-ATHN   | 11    | Tests d'authentification |
| WSTG-AUTHZ  | 7     | Tests d'autorisation    |
| WSTG-SESS   | 11    | Gestion de session      |
| WSTG-INPV   | 29    | Validation d'entrée     |
| WSTG-ERRH   | 2     | Gestion d'erreurs       |
| WSTG-CRYP   | 4     | Cryptographie           |
| WSTG-BUSL   | 10    | Logique métier          |
| WSTG-CLNT   | 14    | Tests côté client       |
| WSTG-APIT   | 4     | Tests API               |

**Total : plus de 120 cas de test automatisés**

## Utilisation

```bash
# Démarrer un pentest d'application web
cyberstrike --agent web-application
> "Tester https://target.com pour les injections SQL selon WSTG-INPV-05"

# Exécuter une reconnaissance
cyberstrike --agent bug-hunter
> "Énumérer les sous-domaines pour target.com"

# Audit de sécurité cloud
cyberstrike --agent cloud-security
> "Auditer mon compte AWS pour les mauvaises configurations de buckets S3"

# Pentest de réseau interne
cyberstrike --agent internal-network
> "Effectuer une attaque Kerberoasting sur le domaine"
```

## Intégrations d'Outils

Les agents CyberStrike exploitent des outils de sécurité standard de l'industrie :

| Catégorie  | Outils                               |
|------------|--------------------------------------|
| Réseau     | nmap, masscan, netcat                |
| Web        | nuclei, sqlmap, ffuf, nikto, burp    |
| Cloud      | prowler, scoutsuite, pacu            |
| AD/Windows | bloodhound, netexec, kerbrute        |
| Recon      | subfinder, amass, httpx, gau         |
| OSINT      | theHarvester, shodan, censys         |

### Intégration MCP Kali

CyberStrike inclut un serveur MCP (`packages/mcp-kali`) avec accès à plus de 100 outils Kali Linux grâce au chargement dynamique d'outils, économisant plus de 150K tokens par session.

## Architecture

- **Runtime** : Bun pour une exécution rapide
- **Langage** : TypeScript pour la sécurité des types
- **UI** : Solid.js + TUI pour l'interface terminal
- **IA** : Vercel AI SDK avec support de plus de 15 fournisseurs (Anthropic, OpenAI, Google, Azure, AWS Bedrock, et plus)
- **MCP** : Model Context Protocol pour une intégration extensible d'outils

## Documentation

Documentation complète disponible sur [docs.cyberstrike.io](https://docs.cyberstrike.io).

## Contribuer

Intéressé par la contribution ? Veuillez lire notre [guide de contribution](./CONTRIBUTING.md) avant de soumettre une pull request.

## Licence

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">Website</a> |
  <a href="https://docs.cyberstrike.io">Docs</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
