# Cyberstrike Architecture

Bu dokuman Cyberstrike'in teknik mimarisini ve bilesenlerini aciklar.

## Genel Bakis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CYBERSTRIKE ECOSYSTEM                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                   │
│  │ Cyberstrike │     │  Cyberstrike│     │  Cyberstrike│                   │
│  │    CLI      │     │    TUI      │     │   Desktop   │                   │
│  │  (Terminal) │     │  (Terminal) │     │    (App)    │                   │
│  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘                   │
│         │                   │                   │                           │
│         └───────────────────┼───────────────────┘                           │
│                             │                                               │
│                             ▼                                               │
│                    ┌─────────────────┐                                      │
│                    │    Provider     │                                      │
│                    │     System      │                                      │
│                    └────────┬────────┘                                      │
│                             │                                               │
│         ┌───────────────────┼───────────────────┐                           │
│         │                   │                   │                           │
│         ▼                   ▼                   ▼                           │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                   │
│  │   Arsenal   │     │   Direct    │     │   Direct    │                   │
│  │  (Gateway)  │     │  Anthropic  │     │   OpenAI    │                   │
│  └──────┬──────┘     └─────────────┘     └─────────────┘                   │
│         │                                                                   │
│         ▼                                                                   │
│  ┌─────────────────────────────────────┐                                   │
│  │         Arsenal Backend             │                                   │
│  │  ┌─────────┐ ┌─────────┐ ┌───────┐ │                                   │
│  │  │  Hydra  │ │ Claude  │ │  GPT  │ │                                   │
│  │  │ (Free)  │ │ Models  │ │Models │ │                                   │
│  │  └─────────┘ └─────────┘ └───────┘ │                                   │
│  └─────────────────────────────────────┘                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Bilesenler

### 1. Cyberstrike CLI/TUI

Kullanicinin etkilesimde bulundugu arayuz.

- **CLI**: Komut satiri arayuzu (cyberstrike komutu)
- **TUI**: Terminal UI (interaktif arayuz)
- **Desktop**: Electron tabanli masaustu uygulamasi

### 2. Provider System

AI saglayicilarini yoneten katman. Desteklenen saglayicilar:

| Provider | Aciklama | Baglanti |
|----------|----------|----------|
| **Arsenal** | Cyberstrike AI Gateway | cyberstrike.io/arsenal/v1 |
| Anthropic | Claude modelleri (direkt) | api.anthropic.com |
| OpenAI | GPT modelleri (direkt) | api.openai.com |
| Google | Gemini modelleri (direkt) | generativelanguage.googleapis.com |
| Azure | Azure OpenAI (direkt) | *.openai.azure.com |
| AWS Bedrock | Amazon Bedrock (direkt) | bedrock-runtime.*.amazonaws.com |
| + 15 diger | OpenRouter, Groq, Mistral, vb. | - |

### 3. Arsenal (AI Gateway)

Cyberstrike'in merkezi AI gateway servisi.

#### Arsenal Nedir?

```
┌─────────────────────────────────────────────────────────────────┐
│                         ARSENAL                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Gorevleri:                                                     │
│  ├── AI isteklerini uygun provider'a yonlendirir               │
│  ├── Farkli API formatlarini donusturur                        │
│  │   (Anthropic <-> OpenAI <-> Google)                         │
│  ├── Kullanim takibi ve faturalandirma                         │
│  ├── Rate limiting ve guvenlik                                  │
│  ├── Model secimi ve load balancing                            │
│  └── Ucretsiz tier yonetimi (Hydra, GPT-5-Nano)               │
│                                                                 │
│  Avantajlari:                                                   │
│  ├── Tek API key ile tum modellere erisim                      │
│  ├── Open source kullanicilar icin ucretsiz modeller           │
│  ├── Unified billing (tek fatura)                              │
│  └── Test edilmis/optimize edilmis model konfigurasyon        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Arsenal Endpoints

| Endpoint | Format | Modeller |
|----------|--------|----------|
| /arsenal/v1/messages | Anthropic | Claude modelleri |
| /arsenal/v1/responses | OpenAI | GPT modelleri |
| /arsenal/v1/chat/completions | OpenAI Compatible | Hydra, GLM, Kimi, Qwen |
| /arsenal/v1/models | - | Model listesi |

---

## Modeller

### Hydra (Ucretsiz Model)

```
┌─────────────────────────────────────────────────────────────────┐
│                          HYDRA                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Tur:        Ucretsiz AI Modeli                                │
│  Hedef:      Open source kullanicilari                         │
│  Maliyet:    $0 (input/output/cache)                           │
│  Erisim:     API key gerekmez (anonim)                         │
│                                                                 │
│  Kullanim:                                                      │
│  ├── cyberstrike.jsonc: { "model": "cyberstrike/hydra" }       │
│  └── CLI: cyberstrike --model cyberstrike/hydra                │
│                                                                 │
│  Mitoloji:                                                      │
│  Hydra - Yunan mitolojisinde cok basli canavar.                │
│  Kesilen her bas icin iki yeni bas cikar.                      │
│  Resilient, adaptive - pentest temasi icin uygun.              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Diger Modeller

| Model | Provider | Fiyat (1M token) | Ozellik |
|-------|----------|------------------|---------|
| **hydra** | Arsenal | Free | Open source icin |
| **gpt-5-nano** | Arsenal | Free | Kucuk/hizli |
| claude-sonnet-4.5 | Arsenal | $3/$15 | Coding icin iyi |
| claude-opus-4.5 | Arsenal | $5/$25 | En yetenekli |
| gpt-5.2-codex | Arsenal | $1.75/$14 | OpenAI coding |
| gemini-3-pro | Arsenal | $2/$12 | Google modeli |

---

## Kullanici Tipleri

```
┌─────────────────────────────────────────────────────────────────┐
│                    KULLANICI TIPLERI                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. OPEN SOURCE KULLANICI (API key yok)                        │
│     ├── Erisim: Sadece ucretsiz modeller (Hydra, GPT-5-Nano)  │
│     ├── Baglanti: Arsenal Gateway                              │
│     └── apiKey: "public" (anonim)                              │
│                                                                 │
│  2. ARSENAL SUBSCRIBER (Cyberstrike hesabi var)                │
│     ├── Erisim: Tum Arsenal modelleri                          │
│     ├── Baglanti: Arsenal Gateway                              │
│     ├── Billing: Pay-as-you-go veya subscription               │
│     └── Ozellikler: Rate limit yuksek, cache, vb.              │
│                                                                 │
│  3. BYOK KULLANICI (Kendi API key'leri var)                    │
│     ├── Erisim: Direkt provider API'lari                       │
│     ├── Baglanti: Anthropic/OpenAI/Google direkt               │
│     ├── Billing: Provider'a direkt odeme                       │
│     └── Arsenal bypass edilir                                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Teknik Stack

### Backend (Console)

| Teknoloji | Kullanim |
|-----------|----------|
| **SST** | Infrastructure as Code |
| **Cloudflare Workers** | Serverless functions |
| **Cloudflare R2** | Object storage |
| **Cloudflare KV** | Key-value storage |
| **TiDB Serverless** | MySQL-compatible database |
| **Stripe** | Payment processing |
| **Drizzle ORM** | Database ORM |

### Frontend (CLI/TUI)

| Teknoloji | Kullanim |
|-----------|----------|
| **Bun** | JavaScript runtime |
| **TypeScript** | Type-safe JavaScript |
| **SolidJS** | TUI rendering |
| **AI SDK** | Provider integrations |

---

## SST Secrets

Deploy icin gereken secret'lar:

### Zorunlu

| Secret | Aciklama |
|--------|----------|
| TIDB_HOST | TiDB database host |
| TIDB_USER | TiDB username |
| TIDB_PASSWORD | TiDB password |
| TIDB_DATABASE | TiDB database name |
| ARSENAL_SESSION_SECRET | Session encryption key |
| ARSENAL_MODELS1-8 | Model configurations (JSON) |
| ARSENAL_BLACK_LIMITS | Premium plan limits |
| ADMIN_SECRET | Admin panel access |
| STRIPE_SECRET_KEY | Stripe API key |
| STRIPE_PUBLISHABLE_KEY | Stripe public key |
| GITHUB_CLIENT_ID_CONSOLE | GitHub OAuth client ID |
| GITHUB_CLIENT_SECRET_CONSOLE | GitHub OAuth secret |

### Opsiyonel

| Secret | Aciklama |
|--------|----------|
| GOOGLE_CLIENT_ID | Google OAuth |
| AWS_SES_ACCESS_KEY_ID | Email sending |
| AWS_SES_SECRET_ACCESS_KEY | Email sending |
| DISCORD_SUPPORT_BOT_TOKEN | Discord integration |
| EMAILOCTOPUS_API_KEY | Newsletter |
| HONEYCOMB_API_KEY | Logging/monitoring |

---

## Rebrand Ozeti

Opencode'dan Cyberstrike'a geciste yapilan degisiklikler:

| Eski (Opencode) | Yeni (Cyberstrike) | Aciklama |
|-----------------|-------------------|----------|
| opencode | cyberstrike | Proje adi |
| Zen | Arsenal | AI Gateway servisi |
| Big Pickle | Hydra | Ucretsiz AI modeli |
| opencode.ai | cyberstrike.io | Domain |

---

## Dizin Yapisi

```
cyberstrike/
├── packages/
│   ├── cyberstrike/          # Ana CLI/TUI paketi
│   │   ├── src/
│   │   │   ├── cli/          # CLI komutlari
│   │   │   ├── provider/     # AI provider entegrasyonlari
│   │   │   ├── session/      # Chat session yonetimi
│   │   │   └── acp/          # Agent Communication Protocol
│   │   └── test/
│   │
│   ├── console/              # Backend (Cloudflare Workers)
│   │   ├── app/              # SolidStart web app
│   │   │   └── src/routes/
│   │   │       └── arsenal/  # Arsenal API endpoints
│   │   ├── core/             # Database, models, billing
│   │   └── function/         # Worker functions
│   │
│   ├── app/                  # Desktop app (Electron)
│   ├── web/                  # Documentation website
│   └── tui-core/             # TUI rendering engine
│
├── infra/                    # SST infrastructure
│   ├── app.ts
│   ├── console.ts
│   └── enterprise.ts
│
└── sst.config.ts             # SST configuration
```

---

*Bu dokuman Cyberstrike v1.0 icin hazirlanmistir.*
