<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike Logo" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>Framework autónomo de pruebas de penetración impulsado por IA.</strong></p>
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

## ¿Qué es CyberStrike?

CyberStrike es un framework de pruebas de penetración de código abierto e impulsado por IA que utiliza agentes autónomos para realizar evaluaciones de seguridad. Integra más de 15 proveedores de IA con agentes especializados en pruebas de seguridad para el descubrimiento automatizado de vulnerabilidades.

## Instalación

```bash
# Instalación rápida
curl -fsSL https://cyberstrike.io/install | bash

# Gestores de paquetes
npm i -g cyberstrike@latest        # o bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS & Linux (recomendado)

# Desde el código fuente
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

### Aplicación de Escritorio

Disponible para macOS, Windows y Linux. Descárgalo desde la [página de versiones](https://github.com/CyberStrikeus/cyberstrike.io/releases) o [cyberstrike.io/download](https://cyberstrike.io/download).

| Plataforma            | Descarga                                 |
| --------------------- | ---------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg`  |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`      |
| Windows               | `cyberstrike-desktop-windows-x64.exe`     |
| Linux                 | `.deb`, `.rpm`, o AppImage              |

## Agentes de Pentest

CyberStrike incluye 4 agentes especializados en pruebas de penetración:

### web-application
Pruebas de seguridad de aplicaciones web siguiendo la metodología OWASP/WSTG:
- Cobertura de OWASP Top 10 (A01-A10)
- Más de 120 casos de prueba WSTG en 12 categorías
- Detección de SQL Injection, XSS, CSRF, XXE, SSTI
- Pruebas de seguridad de API (REST, GraphQL)
- Bypass de autenticación y autorización

### cloud-security
Evaluación de seguridad de infraestructura en la nube:
- AWS (IAM, S3, EC2, Lambda, RDS)
- Azure (AD, Blob Storage, RBAC, Key Vault)
- GCP (IAM, GCS, Compute, Cloud Functions)
- Verificaciones de cumplimiento de CIS Benchmark
- Rutas de escalamiento de privilegios en la nube

### internal-network
Especialista en redes internas y Active Directory:
- Enumeración de red y descubrimiento de servicios
- Ataques AD (Kerberoasting, AS-REP Roasting)
- Ataques de credenciales (Password Spraying, Pass-the-Hash)
- Movimiento lateral (DCOM, WMI, PSExec)
- Escalamiento de privilegios (Windows, Linux, Dominio)

### bug-hunter
Metodología de caza de recompensas por errores:
- Descubrimiento de activos y enumeración de subdominios
- Análisis de datos históricos (Wayback, GAU)
- Análisis de JavaScript para endpoints y secretos
- Encadenamiento de vulnerabilidades para máximo impacto
- Estrategias de plataformas (HackerOne, Bugcrowd)

## Base de Conocimiento

Listas de verificación WSTG (Web Security Testing Guide) integradas en `knowledge/web-application/`:

| Categoría   | Pruebas | Descripción                        |
|-------------|---------|-------------------------------------|
| WSTG-INFO   | 10      | Recopilación de Información        |
| WSTG-CONF   | 13      | Pruebas de Configuración           |
| WSTG-IDNT   | 5       | Gestión de Identidad               |
| WSTG-ATHN   | 11      | Pruebas de Autenticación           |
| WSTG-AUTHZ  | 7       | Pruebas de Autorización            |
| WSTG-SESS   | 11      | Gestión de Sesiones                |
| WSTG-INPV   | 29      | Validación de Entrada              |
| WSTG-ERRH   | 2       | Manejo de Errores                  |
| WSTG-CRYP   | 4       | Criptografía                       |
| WSTG-BUSL   | 10      | Lógica de Negocio                  |
| WSTG-CLNT   | 14      | Pruebas del Lado del Cliente       |
| WSTG-APIT   | 4       | Pruebas de API                     |

**Total: Más de 120 casos de prueba automatizados**

## Uso

```bash
# Iniciar pentest de aplicación web
cyberstrike --agent web-application
> "Prueba https://target.com para SQL injection siguiendo WSTG-INPV-05"

# Ejecutar reconocimiento
cyberstrike --agent bug-hunter
> "Enumerar subdominios para target.com"

# Auditoría de seguridad en la nube
cyberstrike --agent cloud-security
> "Audita mi cuenta de AWS en busca de configuraciones erróneas de buckets S3"

# Pentest de red interna
cyberstrike --agent internal-network
> "Realiza un ataque de Kerberoasting en el dominio"
```

## Integraciones de Herramientas

Los agentes de CyberStrike aprovechan herramientas de seguridad estándar de la industria:

| Categoría   | Herramientas                         |
|-------------|--------------------------------------|
| Red         | nmap, masscan, netcat                |
| Web         | nuclei, sqlmap, ffuf, nikto, burp    |
| Nube        | prowler, scoutsuite, pacu            |
| AD/Windows  | bloodhound, netexec, kerbrute        |
| Recon       | subfinder, amass, httpx, gau         |
| OSINT       | theHarvester, shodan, censys         |

### Integración MCP Kali

CyberStrike incluye un servidor MCP (`packages/mcp-kali`) con acceso a más de 100 herramientas de Kali Linux mediante carga dinámica de herramientas, ahorrando más de 150K tokens por sesión.

## Arquitectura

- **Runtime**: Bun para ejecución rápida
- **Lenguaje**: TypeScript para seguridad de tipos
- **UI**: Solid.js + TUI para interfaz de terminal
- **IA**: Vercel AI SDK con soporte para más de 15 proveedores (Anthropic, OpenAI, Google, Azure, AWS Bedrock y más)
- **MCP**: Model Context Protocol para integración extensible de herramientas

## Documentación

Documentación completa disponible en [docs.cyberstrike.io](https://docs.cyberstrike.io).

## Contribuir

¿Interesado en contribuir? Por favor, lee nuestra [guía de contribución](./CONTRIBUTING.md) antes de enviar un pull request.

## Licencia

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">Website</a> |
  <a href="https://docs.cyberstrike.io">Docs</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
