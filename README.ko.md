<p align="center">
  <a href="https://cyberstrike.io">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="CyberStrike 로고" width="300">
    </picture>
  </a>
</p>
<p align="center"><strong>AI 기반 자율 침투 테스트 에이전트 프레임워크.</strong></p>
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
  <img src="https://raw.githubusercontent.com/CyberStrikeus/docs/main/public/docs/images/gifs/g01-first-run.gif" alt="CyberStrike 데모" width="700">
</p>

---

## CyberStrike란?

CyberStrike는 자율 에이전트를 사용하여 보안 평가를 수행하는 오픈소스 AI 기반 침투 테스트 프레임워크입니다. 15개 이상의 AI 프로바이더와 전문화된 보안 테스트 에이전트를 통합하여 취약점을 자동으로 발견합니다.

## 설치

```bash
# 빠른 설치
curl -fsSL https://cyberstrike.io/install | bash

# 패키지 관리자
npm i -g cyberstrike@latest        # 또는 bun/pnpm/yarn
brew install cyberstrike/tap/cyberstrike # macOS 및 Linux (권장)

# 소스에서 설치
git clone https://github.com/CyberStrikeus/cyberstrike.io.git
cd cyberstrike.io && bun install && bun dev
```

### 데스크톱 앱

macOS, Windows 및 Linux에서 사용할 수 있습니다. [릴리스 페이지](https://github.com/CyberStrikeus/cyberstrike.io/releases) 또는 [cyberstrike.io/download](https://cyberstrike.io/download)에서 다운로드하세요.

| 플랫폼                  | 다운로드                                   |
| --------------------- | ---------------------------------------- |
| macOS (Apple Silicon) | `cyberstrike-desktop-darwin-aarch64.dmg`  |
| macOS (Intel)         | `cyberstrike-desktop-darwin-x64.dmg`      |
| Windows               | `cyberstrike-desktop-windows-x64.exe`     |
| Linux                 | `.deb`, `.rpm` 또는 AppImage              |

## 침투 테스트 에이전트

CyberStrike에는 4개의 전문화된 침투 테스트 에이전트가 포함되어 있습니다:

### web-application
OWASP/WSTG 방법론을 따르는 웹 애플리케이션 보안 테스트:
- OWASP Top 10 (A01-A10) 범위
- 12개 카테고리에 걸친 120개 이상의 WSTG 테스트 케이스
- SQL 인젝션, XSS, CSRF, XXE, SSTI 탐지
- API 보안 테스트 (REST, GraphQL)
- 인증 및 권한 부여 우회

### cloud-security
클라우드 인프라 보안 평가:
- AWS (IAM, S3, EC2, Lambda, RDS)
- Azure (AD, Blob Storage, RBAC, Key Vault)
- GCP (IAM, GCS, Compute, Cloud Functions)
- CIS 벤치마크 준수 검사
- 클라우드 권한 상승 경로

### internal-network
내부 네트워크 및 Active Directory 전문가:
- 네트워크 열거 및 서비스 탐지
- AD 공격 (Kerberoasting, AS-REP Roasting)
- 자격 증명 공격 (Password Spraying, Pass-the-Hash)
- 측면 이동 (DCOM, WMI, PSExec)
- 권한 상승 (Windows, Linux, Domain)

### bug-hunter
버그 바운티 헌팅 방법론:
- 자산 발견 및 서브도메인 열거
- 과거 데이터 분석 (Wayback, GAU)
- 엔드포인트 및 시크릿을 위한 JavaScript 분석
- 최대 영향을 위한 취약점 체인
- 플랫폼 전략 (HackerOne, Bugcrowd)

## 지식 베이스

`knowledge/web-application/`에 내장된 WSTG (웹 보안 테스팅 가이드) 체크리스트:

| 카테고리      | 테스트 수 | 설명                  |
|-------------|---------|----------------------|
| WSTG-INFO   | 10      | 정보 수집              |
| WSTG-CONF   | 13      | 구성 테스트            |
| WSTG-IDNT   | 5       | 신원 관리              |
| WSTG-ATHN   | 11      | 인증 테스트            |
| WSTG-AUTHZ  | 7       | 권한 부여 테스트        |
| WSTG-SESS   | 11      | 세션 관리              |
| WSTG-INPV   | 29      | 입력 유효성 검사        |
| WSTG-ERRH   | 2       | 오류 처리              |
| WSTG-CRYP   | 4       | 암호화                |
| WSTG-BUSL   | 10      | 비즈니스 로직          |
| WSTG-CLNT   | 14      | 클라이언트 측 테스트    |
| WSTG-APIT   | 4       | API 테스트            |

**총 120개 이상의 자동화된 테스트 케이스**

## 사용법

```bash
# 웹 애플리케이션 침투 테스트 시작
cyberstrike --agent web-application
> "WSTG-INPV-05에 따라 https://target.com의 SQL 인젝션을 테스트하세요"

# 정찰 실행
cyberstrike --agent bug-hunter
> "target.com의 서브도메인을 열거하세요"

# 클라우드 보안 감사
cyberstrike --agent cloud-security
> "S3 버킷 잘못된 구성에 대해 내 AWS 계정을 감사하세요"

# 내부 네트워크 침투 테스트
cyberstrike --agent internal-network
> "도메인에 대해 Kerberoasting 공격을 수행하세요"
```

## 도구 통합

CyberStrike 에이전트는 업계 표준 보안 도구를 활용합니다:

| 카테고리     | 도구                                    |
|------------|--------------------------------------|
| 네트워크    | nmap, masscan, netcat                |
| 웹         | nuclei, sqlmap, ffuf, nikto, burp    |
| 클라우드    | prowler, scoutsuite, pacu            |
| AD/Windows | bloodhound, netexec, kerbrute        |
| 정찰       | subfinder, amass, httpx, gau         |
| OSINT      | theHarvester, shodan, censys         |

### MCP Kali 통합

CyberStrike에는 동적 도구 로딩을 통해 100개 이상의 Kali Linux 도구에 액세스할 수 있는 MCP 서버 (`packages/mcp-kali`)가 포함되어 있어 세션당 150K 이상의 토큰을 절약합니다.

## 아키텍처

- **런타임**: 빠른 실행을 위한 Bun
- **언어**: 타입 안전성을 위한 TypeScript
- **UI**: 터미널 인터페이스를 위한 Solid.js + TUI
- **AI**: 15개 이상의 프로바이더 지원을 제공하는 Vercel AI SDK (Anthropic, OpenAI, Google, Azure, AWS Bedrock 등)
- **MCP**: 확장 가능한 도구 통합을 위한 Model Context Protocol

## 문서

전체 문서는 [docs.cyberstrike.io](https://docs.cyberstrike.io)에서 확인할 수 있습니다.

## 기여하기

기여에 관심이 있으신가요? 풀 리퀘스트를 제출하기 전에 [기여 가이드](./CONTRIBUTING.md)를 읽어주세요.

## 라이선스

[MIT](./LICENSE)

---

<p align="center">
  <a href="https://cyberstrike.io">웹사이트</a> |
  <a href="https://docs.cyberstrike.io">문서</a> |
  <a href="https://discord.gg/cyberstrike">Discord</a> |
  <a href="https://x.com/cyberstrike">X.com</a>
</p>
