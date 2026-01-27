# Whykido Mimari Dokümantasyonu (Türkçe)

## Ne İşe Yarar?

**Whykido**, bir AI kodlama asistanıdır. Terminalden çalışır ve:

1. **Kod yazar/düzenler** - Dosyaları okuyup değiştirebilir
2. **Komut çalıştırır** - Bash/shell komutları çalıştırabilir
3. **Kod araması yapar** - Projede arama yapabilir
4. **Çoklu AI destekler** - Claude, GPT, Gemini, vb.

## Temel Kavramlar

### 1. Session (Oturum)
Bir konuşmayı temsil eder. Her session:
- Benzersiz bir ID'ye sahiptir
- Mesaj geçmişini saklar
- Bir proje dizinine bağlıdır

### 2. Tool (Araç)
AI'ın yapabileceği işlemler:

| Tool | Açıklama |
|------|----------|
| `Read` | Dosya okuma |
| `Write` | Dosya yazma |
| `Edit` | Dosya düzenleme (find/replace) |
| `Bash` | Terminal komutu çalıştırma |
| `Glob` | Dosya pattern araması |
| `Grep` | İçerik araması |
| `Task` | Alt-ajan başlatma |

### 3. Agent (Ajan)
Farklı görevler için özelleştirilmiş AI profilleri:

| Agent | Görev |
|-------|-------|
| `build` | Kod yazma/düzenleme (varsayılan) |
| `plan` | Sadece planlama, düzenleme yok |
| `explore` | Kod tabanını keşfetme |

### 4. Provider (Sağlayıcı)
AI API sağlayıcıları:
- **Anthropic** - Claude modelleri
- **OpenAI** - GPT modelleri
- **Google** - Gemini modelleri
- **Bedrock** - AWS üzerinden Claude
- ve daha fazlası...

### 5. Permission (İzin)
Güvenlik için izin sistemi:

```jsonc
{
  "permission": {
    "bash": "ask",           // Her bash için sor
    "read": "allow",         // Okumaya izin ver
    "write": "ask",          // Yazmak için sor
    "external_directory": "deny"  // Dış dizinlere erişme
  }
}
```

## Nasıl Çalışır?

```
[Kullanıcı] → "Bu dosyadaki hatayı düzelt"
     ↓
[Session] → Mesajı kaydet, context oluştur
     ↓
[LLM] → AI API'ye istek gönder
     ↓
[AI] → "Önce dosyayı okumam lazım"
       tool_call: Read { file: "main.ts" }
     ↓
[Tool] → Dosyayı oku, sonucu döndür
     ↓
[AI] → "Hatayı buldum, düzeltiyorum"
       tool_call: Edit { file: "main.ts", ... }
     ↓
[Permission] → Kullanıcıya sor: "Düzenleme yapılsın mı?"
     ↓
[Kullanıcı] → Onay ver
     ↓
[Tool] → Dosyayı düzenle
     ↓
[AI] → "Hata düzeltildi!"
```

## Yapılandırma

`whykido.jsonc` dosyası:

```jsonc
{
  // Varsayılan model
  "model": "anthropic/claude-sonnet-4-20250514",

  // İzinler
  "permission": {
    "bash": {
      "git *": "allow",
      "npm *": "allow",
      "*": "ask"
    }
  },

  // Özel araçlar
  "mcp": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

## Komutlar

```bash
# TUI başlat (varsayılan)
whykido

# Tek komut çalıştır
whykido run "README.md dosyasını güncelle"

# Web arayüzü
whykido web

# Model listele
whykido models

# MCP server yönetimi
whykido mcp list
```

## Dizin Yapısı

```
~/.config/whykido/        # Global yapılandırma
~/.cache/whykido/         # Cache (modeller, vb.)
~/.local/state/whykido/   # Log dosyaları

./whykido.jsonc           # Proje yapılandırması
./.whykido/               # Proje özel ayarlar
  ├── whykido.jsonc
  ├── tool/               # Özel araçlar
  └── agent/              # Özel ajanlar
```

## Özel Araç Oluşturma

`.whykido/tool/my-tool.ts`:

```typescript
import { z } from "zod"

export default {
  description: "Benim özel aracım",
  args: {
    input: z.string().describe("Girdi parametresi"),
  },
  async execute(args, ctx) {
    // İşlem yap
    return `Sonuç: ${args.input}`
  },
}
```

## Önemli Dosyalar

| Dosya | Açıklama |
|-------|----------|
| `src/index.ts` | CLI giriş noktası |
| `src/session/index.ts` | Oturum yönetimi |
| `src/session/llm.ts` | AI API çağrıları |
| `src/tool/*.ts` | Araç implementasyonları |
| `src/provider/provider.ts` | Sağlayıcı yönetimi |
| `src/config/config.ts` | Yapılandırma schema |

## Geliştirme

```bash
# Bağımlılıkları yükle
bun install

# Geliştirme modunda çalıştır
bun run --cwd packages/whykido --conditions=browser ./src/index.ts

# Test çalıştır
cd packages/whykido && bun test

# Build
cd packages/whykido && bun run build
```
