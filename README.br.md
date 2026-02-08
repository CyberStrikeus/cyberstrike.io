<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike logo" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>Framework autônomo de testes de penetração impulsionado por IA.</strong></p>
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

## O que é o CyberStrike?

CyberStrike é um framework de código aberto impulsionado por IA para testes de penetração que utiliza agentes autônomos para realizar avaliações de segurança. Ele integra mais de 15 provedores de IA com agentes especializados em testes de segurança para descoberta automatizada de vulnerabilidades.

## Instalação

```bash
# Instalação rápida
curl -fsSL https://cyberstrike.io/install | bash

# Gerenciadores de pacotes
npm i -g cyberstrike@latest        # ou bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS & Linux (recomendado)

# A partir do código-fonte
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

### Aplicativo Desktop

Disponível para macOS, Windows e Linux. Baixe da [página de releases](https://github.com/CyberStrikeus/cyberstrike.io/releases) ou [cyberstrike.io/download](https://cyberstrike.io/download).

| Plataforma            | Download                                 |
| --------------------- | ---------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg`  |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`      |
| Windows               | `cyberstrike-desktop-windows-x64.exe`     |
| Linux                 | `.deb`, `.rpm`, ou AppImage              |

## Agentes de Pentest

O CyberStrike inclui 4 agentes especializados de testes de penetração:

### web-application
Testes de segurança de aplicações web seguindo a metodologia OWASP/WSTG:
- Cobertura do OWASP Top 10 (A01-A10)
- Mais de 120 casos de teste WSTG em 12 categorias
- Detecção de SQL Injection, XSS, CSRF, XXE, SSTI
- Testes de segurança de API (REST, GraphQL)
- Bypass de autenticação e autorização

### cloud-security
Avaliação de segurança de infraestrutura em nuvem:
- AWS (IAM, S3, EC2, Lambda, RDS)
- Azure (AD, Blob Storage, RBAC, Key Vault)
- GCP (IAM, GCS, Compute, Cloud Functions)
- Verificações de conformidade CIS Benchmark
- Caminhos de escalação de privilégios em nuvem

### internal-network
Especialista em redes internas e Active Directory:
- Enumeração de rede e descoberta de serviços
- Ataques AD (Kerberoasting, AS-REP Roasting)
- Ataques de credenciais (Password Spraying, Pass-the-Hash)
- Movimentação lateral (DCOM, WMI, PSExec)
- Escalação de privilégios (Windows, Linux, Domínio)

### bug-hunter
Metodologia de caça a bugs (bug bounty):
- Descoberta de ativos e enumeração de subdomínios
- Análise de dados históricos (Wayback, GAU)
- Análise de JavaScript para endpoints e segredos
- Encadeamento de vulnerabilidades para impacto máximo
- Estratégias de plataformas (HackerOne, Bugcrowd)

## Base de Conhecimento

Checklists integradas do WSTG (Web Security Testing Guide) em `knowledge/web-application/`:

| Categoria   | Testes | Descrição                  |
|-------------|--------|----------------------------|
| WSTG-INFO   | 10     | Coleta de Informações      |
| WSTG-CONF   | 13     | Testes de Configuração     |
| WSTG-IDNT   | 5      | Gerenciamento de Identidade|
| WSTG-ATHN   | 11     | Testes de Autenticação     |
| WSTG-AUTHZ  | 7      | Testes de Autorização      |
| WSTG-SESS   | 11     | Gerenciamento de Sessão    |
| WSTG-INPV   | 29     | Validação de Entrada       |
| WSTG-ERRH   | 2      | Tratamento de Erros        |
| WSTG-CRYP   | 4      | Criptografia               |
| WSTG-BUSL   | 10     | Lógica de Negócio          |
| WSTG-CLNT   | 14     | Testes do Lado do Cliente  |
| WSTG-APIT   | 4      | Testes de API              |

**Total: Mais de 120 casos de teste automatizados**

## Uso

```bash
# Iniciar pentest de aplicação web
cyberstrike --agent web-application
> "Testar https://target.com para SQL injection seguindo WSTG-INPV-05"

# Executar reconhecimento
cyberstrike --agent bug-hunter
> "Enumerar subdomínios para target.com"

# Auditoria de segurança em nuvem
cyberstrike --agent cloud-security
> "Auditar minha conta AWS para configurações incorretas de buckets S3"

# Pentest de rede interna
cyberstrike --agent internal-network
> "Executar ataque de Kerberoasting no domínio"
```

## Integrações de Ferramentas

Os agentes do CyberStrike aproveitam ferramentas de segurança padrão da indústria:

| Categoria   | Ferramentas                          |
|-------------|--------------------------------------|
| Rede        | nmap, masscan, netcat                |
| Web         | nuclei, sqlmap, ffuf, nikto, burp    |
| Nuvem       | prowler, scoutsuite, pacu            |
| AD/Windows  | bloodhound, netexec, kerbrute        |
| Recon       | subfinder, amass, httpx, gau         |
| OSINT       | theHarvester, shodan, censys         |

### Integração MCP Kali

O CyberStrike inclui um servidor MCP (`packages/mcp-kali`) com acesso a mais de 100 ferramentas do Kali Linux através de carregamento dinâmico de ferramentas, economizando mais de 150K tokens por sessão.

## Arquitetura

- **Runtime**: Bun para execução rápida
- **Linguagem**: TypeScript para segurança de tipos
- **UI**: Solid.js + TUI para interface de terminal
- **IA**: Vercel AI SDK com suporte a mais de 15 provedores (Anthropic, OpenAI, Google, Azure, AWS Bedrock e mais)
- **MCP**: Model Context Protocol para integração extensível de ferramentas

## Documentação

Documentação completa disponível em [docs.cyberstrike.io](https://docs.cyberstrike.io).

## Contribuindo

Interessado em contribuir? Por favor, leia nosso [guia de contribuição](./CONTRIBUTING.md) antes de enviar um pull request.

## Licença

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">Website</a> |
  <a href="https://docs.cyberstrike.io">Docs</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
