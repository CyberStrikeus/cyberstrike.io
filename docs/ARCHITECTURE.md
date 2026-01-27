# Cyberstrike Mimari Dokümantasyonu

## Genel Bakış

Cyberstrike, açık kaynaklı bir AI kodlama ajanıdır. Terminal tabanlı arayüzü (TUI), web arayüzü ve masaüstü uygulaması ile kullanılabilir. Birden fazla AI sağlayıcısını (Anthropic, OpenAI, Google, vb.) destekler ve dosya okuma/yazma, bash komutları çalıştırma gibi araçlar sunar.

## Dizin Yapısı

```
packages/cyberstrike/src/
├── index.ts              # Ana giriş noktası (CLI parser)
├── cli/                  # Komut satırı arayüzü
│   ├── cmd/              # CLI komutları
│   │   ├── tui/          # Terminal UI (SolidJS + OpenTUI)
│   │   ├── run.ts        # `cyberstrike run` komutu
│   │   ├── serve.ts      # `cyberstrike serve` komutu
│   │   ├── web.ts        # `cyberstrike web` komutu
│   │   └── ...
│   └── ui.ts             # UI yardımcıları
├── session/              # Oturum yönetimi
│   ├── index.ts          # Session namespace
│   ├── llm.ts            # AI API çağrıları
│   ├── message-v2.ts     # Mesaj formatları
│   ├── prompt/           # System promptları
│   └── system.ts         # System prompt oluşturma
├── provider/             # AI sağlayıcı yönetimi
│   ├── provider.ts       # Provider namespace
│   ├── models.ts         # Model veritabanı (models.dev)
│   └── transform.ts      # Mesaj dönüşümleri
├── tool/                 # AI araçları
│   ├── registry.ts       # Araç kaydı
│   ├── tool.ts           # Tool base tipi
│   ├── bash.ts           # Bash tool
│   ├── read.ts           # Read tool
│   ├── edit.ts           # Edit tool
│   ├── write.ts          # Write tool
│   ├── glob.ts           # Glob tool
│   ├── grep.ts           # Grep tool
│   ├── task.ts           # Task tool (sub-agent)
│   └── ...
├── agent/                # Ajan sistemi
│   ├── agent.ts          # Agent tanımları
│   └── prompt/           # Ajan promptları
├── permission/           # İzin sistemi
│   └── next.ts           # Permission namespace
├── config/               # Yapılandırma
│   └── config.ts         # Config schema ve yönetimi
├── server/               # HTTP/WebSocket sunucusu
│   ├── server.ts         # Hono tabanlı sunucu
│   └── routes/           # API endpoint'leri
├── mcp/                  # Model Context Protocol
│   └── index.ts          # MCP server yönetimi
├── plugin/               # Plugin sistemi
│   └── index.ts          # Plugin yükleyici
├── project/              # Proje yönetimi
│   └── instance.ts       # Instance state
└── global/               # Global state
    └── index.ts          # XDG dizin yolları
```

---

## 1. CLI Sistemi (`cli/`)

### 1.1 Giriş Noktası (`index.ts`)

```typescript
// Yargs ile CLI komutları tanımlanır
const cli = yargs(hideBin(process.argv))
  .scriptName("cyberstrike")
  .command(TuiCommand)      // Varsayılan: TUI başlat
  .command(RunCommand)      // cyberstrike run "mesaj"
  .command(ServeCommand)    // cyberstrike serve
  .command(WebCommand)      // cyberstrike web
  .command(McpCommand)      // cyberstrike mcp
  // ...
```

### 1.2 Komutlar

| Komut | Açıklama |
|-------|----------|
| `cyberstrike` | TUI (Terminal UI) başlatır |
| `cyberstrike run [mesaj]` | Tek seferlik komut çalıştırır |
| `cyberstrike serve` | Headless sunucu başlatır |
| `cyberstrike web` | Web arayüzü açar |
| `cyberstrike models` | Mevcut modelleri listeler |
| `cyberstrike auth` | Kimlik doğrulama yönetimi |
| `cyberstrike mcp` | MCP server yönetimi |
| `cyberstrike agent` | Ajan yönetimi |

### 1.3 TUI Yapısı

TUI, **SolidJS** ve **OpenTUI** kullanılarak oluşturulmuştur:

```
cli/cmd/tui/
├── app.tsx              # Ana TUI uygulaması
├── thread.ts            # Worker thread yönetimi
├── worker.ts            # Background worker
├── context/             # SolidJS context'leri
│   ├── sdk.tsx          # SDK bağlantısı
│   ├── theme.tsx        # Tema yönetimi
│   └── ...
├── routes/              # TUI sayfaları
│   └── session/         # Oturum ekranı
└── component/           # UI bileşenleri
```

---

## 2. Session Sistemi (`session/`)

Session, bir konuşma oturumunu temsil eder ve mesajları, context'i ve state'i yönetir.

### 2.1 Session Info

```typescript
export const Info = z.object({
  id: Identifier.schema("session"),
  slug: z.string(),
  projectID: z.string(),
  directory: z.string(),
  title: z.string(),
  version: z.string(),
  time: z.object({
    created: z.number(),
    updated: z.number(),
  }),
  permission: PermissionNext.Ruleset.optional(),
})
```

### 2.2 Mesaj Tipleri (`message-v2.ts`)

```typescript
// Kullanıcı mesajı
export const User = z.object({
  id: z.string(),
  role: z.literal("user"),
  content: z.string(),
  files: FilePart.array().optional(),
})

// AI yanıtı
export const Assistant = z.object({
  id: z.string(),
  role: z.literal("assistant"),
  parts: Part.array(),  // Text, ToolCall, ToolResult
})
```

### 2.3 LLM Çağrısı (`llm.ts`)

```typescript
export async function stream(input: StreamInput) {
  // 1. Model ve provider al
  const language = await Provider.getLanguage(input.model)

  // 2. System prompt oluştur
  const system = [
    input.agent.prompt || SystemPrompt.provider(input.model),
    ...input.system,
  ]

  // 3. AI SDK ile stream başlat
  return streamText({
    model: language,
    system: system.join("\n"),
    messages: input.messages,
    tools: input.tools,
    maxTokens: OUTPUT_TOKEN_MAX,
    abortSignal: input.abort,
  })
}
```

---

## 3. Tool Sistemi (`tool/`)

AI'ın kullanabileceği araçlar bu sistemde tanımlanır.

### 3.1 Tool Tanımı

```typescript
export namespace Tool {
  export interface Info<Parameters, Metadata> {
    id: string
    init: (ctx?: InitContext) => Promise<{
      description: string
      parameters: Parameters  // Zod schema
      execute(args, ctx): Promise<{
        title: string
        output: string
        metadata: Metadata
      }>
    }>
  }
}
```

### 3.2 Tool Örnekleri

#### Bash Tool
```typescript
// tool/bash.ts
export const BashTool = Tool.define("Bash", async () => ({
  description: "Execute bash commands",
  parameters: z.object({
    command: z.string(),
    timeout: z.number().optional(),
  }),
  async execute(args, ctx) {
    // İzin kontrolü
    await ctx.ask({
      permission: "bash",
      patterns: [args.command],
    })

    // Komutu çalıştır
    const result = await $`${args.command}`
    return { output: result.stdout }
  }
}))
```

#### Read Tool
```typescript
// tool/read.ts
export const ReadTool = Tool.define("Read", async () => ({
  description: "Read file contents",
  parameters: z.object({
    file_path: z.string(),
    offset: z.number().optional(),
    limit: z.number().optional(),
  }),
  async execute(args, ctx) {
    const content = await Bun.file(args.file_path).text()
    return { output: content }
  }
}))
```

### 3.3 Tool Registry

```typescript
// tool/registry.ts
export namespace ToolRegistry {
  export async function all(): Promise<Tool.Info[]> {
    return [
      BashTool,
      ReadTool,
      WriteTool,
      EditTool,
      GlobTool,
      GrepTool,
      TaskTool,
      WebFetchTool,
      // + custom tools from config
      ...custom,
    ]
  }
}
```

---

## 4. Provider Sistemi (`provider/`)

AI sağlayıcılarını ve modellerini yönetir.

### 4.1 Provider Tanımı

```typescript
export interface Info {
  id: string           // "anthropic", "openai", "google"
  name: string         // "Anthropic", "OpenAI"
  env: string[]        // ["ANTHROPIC_API_KEY"]
  models: Record<string, Model>
}

export interface Model {
  id: string           // "claude-sonnet-4-20250514"
  providerID: string   // "anthropic"
  api: {
    id: string         // Model ID for API
    npm: string        // "@ai-sdk/anthropic"
  }
  limit: {
    context: number    // 200000
    output: number     // 64000
  }
  cost: {
    input: number      // $ per million tokens
    output: number
  }
}
```

### 4.2 Desteklenen Sağlayıcılar

| Provider | npm package | Modeller |
|----------|-------------|----------|
| Anthropic | `@ai-sdk/anthropic` | Claude Opus, Sonnet, Haiku |
| OpenAI | `@ai-sdk/openai` | GPT-4o, GPT-4.5, o1 |
| Google | `@ai-sdk/google` | Gemini Pro, Flash |
| Amazon Bedrock | `@ai-sdk/amazon-bedrock` | Claude, Titan |
| Azure | `@ai-sdk/azure` | GPT modelleri |
| Groq | `@ai-sdk/groq` | Llama, Mixtral |
| Mistral | `@ai-sdk/mistral` | Mistral Large |
| xAI | `@ai-sdk/xai` | Grok |

### 4.3 Model Veritabanı

Modeller `https://models.dev/api.json` adresinden çekilir ve cache'lenir:

```typescript
// provider/models.ts
export namespace ModelsDev {
  export async function refresh() {
    const result = await fetch("https://models.dev/api.json")
    await Bun.write(filepath, await result.text())
  }
}
```

---

## 5. Agent Sistemi (`agent/`)

Farklı görevler için özelleştirilmiş ajanlar.

### 5.1 Agent Tanımı

```typescript
export const Info = z.object({
  name: z.string(),
  description: z.string().optional(),
  mode: z.enum(["subagent", "primary", "all"]),
  permission: PermissionNext.Ruleset,
  prompt: z.string().optional(),
  model: z.object({
    modelID: z.string(),
    providerID: z.string(),
  }).optional(),
})
```

### 5.2 Yerleşik Ajanlar

| Ajan | Açıklama |
|------|----------|
| `build` | Varsayılan ajan, tüm araçları kullanabilir |
| `plan` | Planlama modu, düzenleme yapmaz |
| `summary` | Özet çıkarır |
| `title` | Başlık oluşturur |
| `explore` | Kod tabanını keşfeder |
| `web-application` | Web güvenlik testi |
| `cloud-security` | Bulut güvenlik analizi |

### 5.3 Özel Ajan Oluşturma

`cyberstrike.jsonc` veya `.cyberstrike/agent/` dizininde:

```jsonc
{
  "agent": {
    "my-agent": {
      "description": "Custom agent",
      "prompt": "You are a specialized assistant...",
      "permission": {
        "bash": "deny",
        "read": "allow"
      }
    }
  }
}
```

---

## 6. Permission Sistemi (`permission/`)

Araç kullanımı için izin kontrolü.

### 6.1 İzin Eylemleri

```typescript
export const Action = z.enum(["allow", "deny", "ask"])
```

- **allow**: Otomatik izin ver
- **deny**: Otomatik reddet
- **ask**: Kullanıcıya sor

### 6.2 İzin Kuralları

```typescript
// cyberstrike.jsonc
{
  "permission": {
    "bash": "ask",                    // Tüm bash komutları için sor
    "read": {
      "*": "allow",                   // Tüm dosyaları oku
      "*.env": "ask"                  // .env dosyaları için sor
    },
    "external_directory": {
      "~/Desktop/*": "allow",
      "*": "deny"
    }
  }
}
```

### 6.3 İzin Kontrolü

```typescript
// Tool içinde izin isteme
await ctx.ask({
  permission: "bash",
  patterns: ["rm -rf *"],
  metadata: { command: "rm -rf *" }
})
```

---

## 7. Config Sistemi (`config/`)

### 7.1 Yapılandırma Dosyaları

Arama sırası:
1. `./cyberstrike.jsonc` (proje dizini)
2. `./.cyberstrike/cyberstrike.jsonc`
3. `~/.config/cyberstrike/cyberstrike.jsonc` (global)

### 7.2 Config Schema

```typescript
export const Config = z.object({
  $schema: z.string().optional(),

  // Model ayarları
  model: z.string().optional(),           // "anthropic/claude-sonnet-4"

  // Provider ayarları
  provider: z.record(ProviderConfig).optional(),

  // İzinler
  permission: Permission.optional(),

  // Ajanlar
  agent: z.record(Agent).optional(),

  // MCP sunucuları
  mcp: z.record(McpServer).optional(),

  // Araçlar
  disabled_tools: z.array(z.string()).optional(),

  // Sunucu
  server: z.object({
    hostname: z.string().optional(),
    port: z.number().optional(),
  }).optional(),
})
```

### 7.3 Örnek Yapılandırma

```jsonc
// cyberstrike.jsonc
{
  "$schema": "https://cyberstrike.io/config.json",
  "model": "anthropic/claude-sonnet-4-20250514",

  "provider": {
    "anthropic": {
      "options": {
        "apiKey": "${ANTHROPIC_API_KEY}"
      }
    }
  },

  "permission": {
    "bash": {
      "git *": "allow",
      "npm *": "allow",
      "*": "ask"
    }
  },

  "mcp": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

---

## 8. Server Sistemi (`server/`)

HTTP ve WebSocket sunucusu, SDK ile iletişim sağlar.

### 8.1 Sunucu Başlatma

```typescript
// server/server.ts
const app = new Hono()

// REST API
app.route("/session", sessionRoutes)
app.route("/project", projectRoutes)
app.route("/config", configRoutes)

// WebSocket (SSE)
app.get("/events", async (c) => {
  return streamSSE(c, async (stream) => {
    Bus.subscribe("*", (event) => {
      stream.writeSSE({ data: JSON.stringify(event) })
    })
  })
})
```

### 8.2 API Endpoint'leri

| Endpoint | Method | Açıklama |
|----------|--------|----------|
| `/session` | GET | Tüm oturumları listele |
| `/session/:id` | GET | Oturum detayı |
| `/session` | POST | Yeni oturum oluştur |
| `/session/:id/message` | POST | Mesaj gönder |
| `/project` | GET | Proje bilgisi |
| `/config` | GET/POST | Yapılandırma |
| `/events` | GET (SSE) | Canlı olaylar |

---

## 9. MCP Sistemi (`mcp/`)

Model Context Protocol, harici araç entegrasyonu sağlar.

### 9.1 MCP Server Tanımı

```jsonc
{
  "mcp": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

### 9.2 MCP Komutları

```bash
cyberstrike mcp list              # Sunucuları listele
cyberstrike mcp add <name>        # Sunucu ekle
cyberstrike mcp remove <name>     # Sunucu kaldır
cyberstrike mcp auth <name>       # OAuth kimlik doğrulama
```

---

## 10. Event Sistemi (`bus/`)

Bileşenler arası iletişim için event bus.

### 10.1 Event Tanımı

```typescript
export const Event = {
  Created: BusEvent.define("session.created", z.object({
    info: Session.Info,
  })),
  Updated: BusEvent.define("session.updated", z.object({
    info: Session.Info,
  })),
  Message: BusEvent.define("message.created", z.object({
    sessionID: z.string(),
    message: MessageV2.Any,
  })),
}
```

### 10.2 Event Kullanımı

```typescript
// Event yayınlama
Bus.publish(Session.Event.Created, { info: session })

// Event dinleme
Bus.subscribe(Session.Event.Created, (payload) => {
  console.log("Yeni oturum:", payload.info.id)
})
```

---

## 11. Çalışma Akışı

```
┌──────────────────────────────────────────────────────────────────┐
│                        KULLANICI GİRİŞİ                          │
│                    "Bu dosyadaki bug'ı düzelt"                   │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                         SESSION                                   │
│  1. Mesajı kaydet                                                │
│  2. Context oluştur (önceki mesajlar + system prompt)           │
│  3. LLM.stream() çağır                                          │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                          LLM                                      │
│  1. Provider'dan model al                                        │
│  2. System prompt + tools hazırla                                │
│  3. AI SDK streamText() çağır                                    │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                       AI RESPONSE                                 │
│  "Dosyayı okumam gerekiyor"                                      │
│  → tool_call: Read { file_path: "main.ts" }                     │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                      TOOL EXECUTION                               │
│  1. Permission kontrolü                                          │
│  2. ReadTool.execute({ file_path: "main.ts" })                  │
│  3. Sonucu döndür                                                │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                       AI RESPONSE                                 │
│  "Bug'ı buldum, düzeltiyorum"                                    │
│  → tool_call: Edit { file_path: "main.ts", ... }                │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                      TOOL EXECUTION                               │
│  1. Permission kontrolü (ask)                                    │
│  2. Kullanıcı onayı bekle                                        │
│  3. EditTool.execute({ ... })                                    │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                       AI RESPONSE                                 │
│  "Bug düzeltildi. İşte değişiklikler: ..."                      │
│  → end_turn                                                      │
└──────────────────────────────────────────────────────────────────┘
```

---

## 12. Geliştirme

### 12.1 Gereksinimler

- Bun 1.3+
- Node.js 22+ (opsiyonel)

### 12.2 Kurulum

```bash
bun install
```

### 12.3 Çalıştırma

```bash
# Geliştirme modu
bun run dev

# Veya doğrudan
bun run --cwd packages/cyberstrike --conditions=browser ./src/index.ts
```

### 12.4 Test

```bash
cd packages/cyberstrike
bun test
```

### 12.5 Build

```bash
cd packages/cyberstrike
bun run build
```

---

## 13. Katkıda Bulunma

1. `.cyberstrike/` dizininde özel araçlar oluşturabilirsiniz
2. `cyberstrike.jsonc` ile yapılandırma özelleştirebilirsiniz
3. Plugin sistemi ile yeni özellikler ekleyebilirsiniz

Detaylı bilgi için: https://cyberstrike.io/docs
