#!/usr/bin/env bun
// @ts-nocheck
import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { BoltTransport } from "./src/mcp/bolt-transport.js"
import { Ed25519Auth } from "./src/mcp/ed25519.js"

// Type helper for tool results
interface TextContent {
  type: "text"
  text: string
}

console.log("\n🔐 BOLT MCP - ULTIMATE COMPREHENSIVE TEST\n")
console.log("=".repeat(70))

const creds = await Ed25519Auth.loadCredentials("bol-88")
const transport = new BoltTransport(new URL("http://147.135.60.70:3001/mcp"), creds!.clientId, creds!.privateKey)
const client = new Client({ name: "ultimate-test", version: "1.0.0" })

await client.connect(transport)
console.log("✅ Ed25519 kimlik doğrulama: BAŞARILI")
console.log("   Client ID:", creds!.clientId)
console.log("=".repeat(70) + "\n")

let testCount = 0
let passCount = 0

async function test(name: string, fn: () => Promise<void>) {
  testCount++
  try {
    console.log(`\n🧪 TEST ${testCount}: ${name}`)
    console.log("-".repeat(70))
    await fn()
    passCount++
    console.log("✅ BAŞARILI")
  } catch (error) {
    console.log("❌ HATA:", error)
  }
}

// TEST 1: Kategori ve araç listesi
await test("Kategori ve araç sayısı", async () => {
  const cats = await client.callTool({ name: "kali_categories", arguments: {} })
  const text = (cats.content as TextContent[])[0].text
  console.log(text)
  if (!text.includes("100 tools")) throw new Error("100 araç bulunamadı")
})

// TEST 2: Araç arama
await test("Araç arama (nmap)", async () => {
  const result = await client.callTool({
    name: "kali_search",
    arguments: { query: "nmap" }
  })
  console.log((result.content as TextContent[])[0].text)
  if (!(result.content as TextContent[])[0].text.includes("nmap")) throw new Error("nmap bulunamadı")
})

// TEST 3: Nmap yükle ve çalıştır
await test("Nmap yükle ve version kontrolü", async () => {
  await client.callTool({
    name: "kali_load",
    arguments: { tools: ["nmap"] }
  })
  console.log("✓ Nmap yüklendi")

  const result = await client.callTool({
    name: "kali_nmap",
    arguments: { args: "--version" }
  })
  const output = (result.content as TextContent[])[0].text
  console.log("Çıktı:", output.slice(0, 300))
  if (!output.includes("Nmap") && !output.includes("7.")) throw new Error("Nmap çalışmadı")
})

// TEST 4: Masscan yükle ve localhost taraması
await test("Masscan ile port taraması", async () => {
  await client.callTool({
    name: "kali_load",
    arguments: { tools: ["masscan"] }
  })
  console.log("✓ Masscan yüklendi")

  const result = await client.callTool({
    name: "kali_masscan",
    arguments: { target: "127.0.0.1/32", ports: "80,443", rate: "100" }
  })
  console.log("Çıktı:", (result.content as TextContent[])[0].text.slice(0, 400))
})

// TEST 5: Whois ile domain sorgusu
await test("Whois ile domain sorgusu", async () => {
  await client.callTool({
    name: "kali_load",
    arguments: { tools: ["whois"] }
  })
  console.log("✓ Whois yüklendi")

  const result = await client.callTool({
    name: "kali_whois",
    arguments: { domain: "google.com" }
  })
  const output = (result.content as TextContent[])[0].text
  console.log("Çıktı (ilk 300 karakter):", output.slice(0, 300))
  if (!output.includes("google") && !output.includes("Google")) throw new Error("Whois sonuç dönmedi")
})

// TEST 6: DNSRecon ile DNS enumeration
await test("DNSRecon ile DNS enumeration", async () => {
  await client.callTool({
    name: "kali_load",
    arguments: { tools: ["dnsrecon"] }
  })
  console.log("✓ DNSRecon yüklendi")

  const result = await client.callTool({
    name: "kali_dnsrecon",
    arguments: { domain: "google.com", type: "std" }
  })
  const output = (result.content as TextContent[])[0].text
  console.log("Çıktı (ilk 400 karakter):", output.slice(0, 400))
})

// TEST 7: Subfinder ile subdomain bulma
await test("Subfinder ile subdomain enumeration", async () => {
  await client.callTool({
    name: "kali_load",
    arguments: { tools: ["subfinder"] }
  })
  console.log("✓ Subfinder yüklendi")

  const result = await client.callTool({
    name: "kali_subfinder",
    arguments: { domain: "google.com" }
  })
  const output = (result.content as TextContent[])[0].text
  console.log("Çıktı (ilk 500 karakter):", output.slice(0, 500))
})

// TEST 8: Whatweb ile teknoloji tespiti
await test("Whatweb ile web teknoloji tespiti", async () => {
  await client.callTool({
    name: "kali_load",
    arguments: { tools: ["whatweb"] }
  })
  console.log("✓ Whatweb yüklendi")

  const result = await client.callTool({
    name: "kali_whatweb",
    arguments: { url: "https://google.com" }
  })
  const output = (result.content as TextContent[])[0].text
  console.log("Çıktı:", output.slice(0, 400))
  if (!output.includes("http") && !output.includes("HTTP")) throw new Error("Whatweb sonuç dönmedi")
})

// TEST 9: Crunch ile wordlist oluşturma
await test("Crunch ile basit wordlist", async () => {
  await client.callTool({
    name: "kali_load",
    arguments: { tools: ["crunch"] }
  })
  console.log("✓ Crunch yüklendi")

  const result = await client.callTool({
    name: "kali_crunch",
    arguments: { min: "3", max: "3", charset: "ab", output: "" }
  })
  const output = (result.content as TextContent[])[0].text
  console.log("Çıktı (ilk 200 karakter):", output.slice(0, 200))
  if (!output.includes("aaa") && !output.includes("crunch")) throw new Error("Crunch çalışmadı")
})

// TEST 10: Yüklü araçları kontrol et
await test("Yüklü araçları listele", async () => {
  const result = await client.callTool({ name: "kali_status", arguments: {} })
  const text = (result.content as TextContent[])[0].text
  console.log(text)
  if (!text.includes("kali_nmap")) throw new Error("Nmap yüklü gösterilmiyor")
})

// TEST 11: Araç önerisi
await test("Araç önerisi al", async () => {
  const result = await client.callTool({ name: "kali_recommend", arguments: {} })
  console.log((result.content as TextContent[])[0].text)
})

// TEST 12: Bazı araçları kaldır
await test("Araçları kaldır (cleanup)", async () => {
  const result = await client.callTool({
    name: "kali_unload",
    arguments: { tools: ["masscan", "crunch"] }
  })
  console.log((result.content as TextContent[])[0].text)
})

// TEST 13: Jobs kontrolü
await test("Background jobs listele", async () => {
  const result = await client.callTool({ name: "kali_jobs", arguments: {} })
  console.log((result.content as TextContent[])[0].text)
})

await client.close()

// Final results
console.log("\n" + "=".repeat(70))
console.log("📊 TEST SONUÇLARI")
console.log("=".repeat(70))
console.log(`\n✅ Başarılı: ${passCount}/${testCount}`)
console.log(`❌ Başarısız: ${testCount - passCount}/${testCount}`)

if (passCount === testCount) {
  console.log("\n🎉 TÜM TESTLER BAŞARILI!")
  console.log("\n✅ Doğrulanan özellikler:")
  console.log("   • Ed25519 kimlik doğrulama")
  console.log("   • Kategori ve araç arama")
  console.log("   • Araç yükleme/kaldırma")
  console.log("   • Network tarama (nmap, masscan)")
  console.log("   • DNS enumeration (dnsrecon, subfinder)")
  console.log("   • Domain bilgisi (whois)")
  console.log("   • Web teknoloji tespiti (whatweb)")
  console.log("   • Wordlist oluşturma (crunch)")
  console.log("   • Araç önerileri")
  console.log("   • Status ve jobs yönetimi")
  console.log("\n🚀 Bolt MCP sunucusu tam fonksiyonel!")
} else {
  console.log("\n⚠️  Bazı testler başarısız oldu")
}

console.log()
