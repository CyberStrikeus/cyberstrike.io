<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike logo" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>Автономный фреймворк агентов для тестирования на проникновение на базе ИИ.</strong></p>
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

## Что такое CyberStrike?

CyberStrike — это фреймворк с открытым исходным кодом для тестирования на проникновение на базе искусственного интеллекта, который использует автономных агентов для проведения оценки безопасности. Он интегрирует более 15 провайдеров ИИ со специализированными агентами для автоматического обнаружения уязвимостей.

## Установка

```bash
# Быстрая установка
curl -fsSL https://cyberstrike.io/install | bash

# Менеджеры пакетов
npm i -g cyberstrike@latest        # или bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS и Linux (рекомендуется)

# Из исходников
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

### Десктопное приложение

Доступно для macOS, Windows и Linux. Скачайте со [страницы релизов](https://github.com/CyberStrikeus/cyberstrike.io/releases) или [cyberstrike.io/download](https://cyberstrike.io/download).

| Платформа             | Загрузка                              |
| --------------------- | ------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg` |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`     |
| Windows               | `cyberstrike-desktop-windows-x64.exe`    |
| Linux                 | `.deb`, `.rpm` или AppImage           |

## Агенты пентеста

CyberStrike включает 4 специализированных агента для тестирования на проникновение:

### web-application
Тестирование безопасности веб-приложений по методологии OWASP/WSTG:
- Покрытие OWASP Top 10 (A01-A10)
- Более 120 тестовых случаев WSTG в 12 категориях
- Обнаружение SQL-инъекций, XSS, CSRF, XXE, SSTI
- Тестирование безопасности API (REST, GraphQL)
- Обход аутентификации и авторизации

### cloud-security
Оценка безопасности облачной инфраструктуры:
- AWS (IAM, S3, EC2, Lambda, RDS)
- Azure (AD, Blob Storage, RBAC, Key Vault)
- GCP (IAM, GCS, Compute, Cloud Functions)
- Проверки соответствия CIS Benchmark
- Пути повышения привилегий в облаке

### internal-network
Специалист по внутренним сетям и Active Directory:
- Перечисление сети и обнаружение сервисов
- Атаки на AD (Kerberoasting, AS-REP Roasting)
- Атаки на учетные данные (Password Spraying, Pass-the-Hash)
- Латеральное перемещение (DCOM, WMI, PSExec)
- Повышение привилегий (Windows, Linux, Domain)

### bug-hunter
Методология поиска багов в рамках bug bounty:
- Обнаружение активов и перечисление поддоменов
- Анализ исторических данных (Wayback, GAU)
- Анализ JavaScript для поиска endpoints и секретов
- Построение цепочек уязвимостей для максимального эффекта
- Стратегии для платформ (HackerOne, Bugcrowd)

## База знаний

Встроенные чеклисты WSTG (Web Security Testing Guide) в `knowledge/web-application/`:

| Категория   | Тестов | Описание                      |
|-------------|--------|-------------------------------|
| WSTG-INFO   | 10     | Сбор информации               |
| WSTG-CONF   | 13     | Тестирование конфигурации     |
| WSTG-IDNT   | 5      | Управление идентификацией     |
| WSTG-ATHN   | 11     | Тестирование аутентификации   |
| WSTG-AUTHZ  | 7      | Тестирование авторизации      |
| WSTG-SESS   | 11     | Управление сессиями           |
| WSTG-INPV   | 29     | Валидация входных данных      |
| WSTG-ERRH   | 2      | Обработка ошибок              |
| WSTG-CRYP   | 4      | Криптография                  |
| WSTG-BUSL   | 10     | Бизнес-логика                 |
| WSTG-CLNT   | 14     | Клиентское тестирование       |
| WSTG-APIT   | 4      | Тестирование API              |

**Всего: более 120 автоматизированных тестовых случаев**

## Использование

```bash
# Начать пентест веб-приложения
cyberstrike --agent web-application
> "Протестируй https://target.com на SQL-инъекции согласно WSTG-INPV-05"

# Запустить разведку
cyberstrike --agent bug-hunter
> "Перечисли поддомены для target.com"

# Аудит облачной безопасности
cyberstrike --agent cloud-security
> "Проверь мой аккаунт AWS на неправильные конфигурации S3-корзин"

# Пентест внутренней сети
cyberstrike --agent internal-network
> "Выполни атаку Kerberoasting на домен"
```

## Интеграция инструментов

Агенты CyberStrike используют стандартные инструменты безопасности:

| Категория  | Инструменты                          |
|------------|--------------------------------------|
| Сеть       | nmap, masscan, netcat                |
| Веб        | nuclei, sqlmap, ffuf, nikto, burp    |
| Облако     | prowler, scoutsuite, pacu            |
| AD/Windows | bloodhound, netexec, kerbrute        |
| Разведка   | subfinder, amass, httpx, gau         |
| OSINT      | theHarvester, shodan, censys         |

### Интеграция MCP Kali

CyberStrike включает MCP-сервер (`packages/mcp-kali`) с доступом к более чем 100 инструментам Kali Linux через динамическую загрузку инструментов, что экономит более 150 тысяч токенов за сессию.

## Архитектура

- **Runtime**: Bun для быстрого выполнения
- **Язык**: TypeScript для типобезопасности
- **UI**: Solid.js + TUI для терминального интерфейса
- **AI**: Vercel AI SDK с поддержкой более 15 провайдеров (Anthropic, OpenAI, Google, Azure, AWS Bedrock и другие)
- **MCP**: Model Context Protocol для расширяемой интеграции инструментов

## Документация

Полная документация доступна на [docs.cyberstrike.io](https://docs.cyberstrike.io).

## Вклад

Хотите внести вклад? Пожалуйста, прочитайте наше [руководство по участию](./CONTRIBUTING.md) перед отправкой pull request.

## Лицензия

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">Website</a> |
  <a href="https://docs.cyberstrike.io">Docs</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
