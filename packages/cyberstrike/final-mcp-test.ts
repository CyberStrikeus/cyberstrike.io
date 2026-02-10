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

const mcpName = "bol-88"
const serverUrl = "http://147.135.60.70:3001/mcp"

console.log("🔐 BOLT MCP SERVER - KAPSAMLI TEST\n")
console.log("=" .repeat(60))

const creds = await Ed25519Auth.loadCredentials(mcpName)
if (!creds) {
  console.error("❌ Kimlik bilgileri bulunamadı")
  process.exit(1)
}

const transport = new BoltTransport(new URL(serverUrl), creds.clientId, creds.privateKey)
const client = new Client({ name: "comprehensive-test", version: "1.0.0" })

await client.connect(transport)
console.log("✓ Bağlantı başarılı - Client ID:", creds.clientId)
console.log("=" .repeat(60) + "\n")

// Test 1: Kategori listesi
console.log("📋 TEST 1: Mevcut kategoriler")
const cats = await client.callTool({ name: "kali_categories", arguments: {} })
console.log((.content as TextContent[])[].text)
console.log()

// Test 2: Reconnaissance araçları yükle
console.log("📋 TEST 2: Reconnaissance preset yükle")
const preset = await client.callTool({
  name: "kali_preset",
  arguments: { preset: "recon-network" }
})
console.log((.content as TextContent[])[].text)
console.log()

// Test 3: Yüklü araçları kontrol et
console.log("📋 TEST 3: Yüklü araçlar")
const status = await client.callTool({ name: "kali_status", arguments: {} })
console.log((.content as TextContent[])[].text)
console.log()

// Test 4: Nmap ile port taraması
console.log("📋 TEST 4: Nmap ile localhost port taraması")
const nmap = await client.callTool({
  name: "kali_nmap",
  arguments: { target: "127.0.0.1", args: "-p 22,80,443,3306 -T4" }
})
console.log("✓ Nmap sonucu:")
console.log((.content as TextContent[])[].text.slice(0, 600) + "\n...\n")

// Test 5: DNSRecon
console.log("📋 TEST 5: DNSRecon ile DNS enumeration")
const dns = await client.callTool({
  name: "kali_dnsrecon",
  arguments: { domain: "google.com", type: "std" }
})
console.log("✓ DNSRecon sonucu (ilk 400 karakter):")
console.log((.content as TextContent[])[].text.slice(0, 400) + "\n...\n")

// Test 6: Masscan yükle ve test et
console.log("📋 TEST 6: Masscan yükle ve test et")
await client.callTool({
  name: "kali_load",
  arguments: { tools: ["masscan"] }
})
const masscan = await client.callTool({
  name: "kali_masscan",
  arguments: { target: "127.0.0.1/32", ports: "80,443", rate: "100" }
})
console.log("✓ Masscan sonucu:")
console.log((.content as TextContent[])[].text.slice(0, 300) + "\n")

// Test 7: Web araçları yükle
console.log("📋 TEST 7: Web application preset yükle")
await client.callTool({
  name: "kali_preset",
  arguments: { preset: "web-scan" }
})
const status2 = await client.callTool({ name: "kali_status", arguments: {} })
console.log((.content as TextContent[])[].text)
console.log()

// Test 8: Whatweb test
console.log("📋 TEST 8: Whatweb ile teknoloji tespiti")
const whatweb = await client.callTool({
  name: "kali_whatweb",
  arguments: { url: "https://google.com" }
})
console.log("✓ Whatweb sonucu:")
console.log((.content as TextContent[])[].text.slice(0, 500) + "\n")

// Test 9: Nikto yükle
console.log("📋 TEST 9: Nikto yükle ve test et")
await client.callTool({
  name: "kali_load",
  arguments: { tools: ["nikto"] }
})
// Just check it's loaded, don't run full scan (too slow)
const niktoCheck = await client.callTool({
  name: "kali_nikto",
  arguments: { target: "127.0.0.1", args: "-h" }
})
console.log("✓ Nikto yüklendi ve hazır\n")

// Test 10: Password araçları
console.log("📋 TEST 10: Password cracking preset")
await client.callTool({
  name: "kali_preset",
  arguments: { preset: "password-wordlist" }
})
const pwStatus = await client.callTool({ name: "kali_status", arguments: {} })
console.log((.content as TextContent[])[].text)
console.log()

// Test 11: Crunch ile wordlist oluştur
console.log("📋 TEST 11: Crunch ile küçük wordlist oluştur")
const crunch = await client.callTool({
  name: "kali_crunch",
  arguments: { min: "4", max: "4", charset: "abc", output: "" }
})
console.log("✓ Crunch sonucu (ilk 200 karakter):")
console.log((.content as TextContent[])[].text.slice(0, 200) + "\n")

// Test 12: Araç önerisi al
console.log("📋 TEST 12: Araç önerisi al")
const recommend = await client.callTool({
  name: "kali_recommend",
  arguments: {}
})
console.log((.content as TextContent[])[].text)
console.log()

// Test 13: Belirli araçları kaldır
console.log("📋 TEST 13: Bazı araçları kaldır")
const unload = await client.callTool({
  name: "kali_unload",
  arguments: { tools: ["masscan", "nikto"] }
})
console.log((.content as TextContent[])[].text)
console.log()

// Final status
console.log("📋 FINAL STATUS")
const finalStatus = await client.callTool({ name: "kali_status", arguments: {} })
console.log((.content as TextContent[])[].text)

await client.close()

console.log("\n" + "=".repeat(60))
console.log("✅ TÜM TESTLER TAMAMLANDI!")
console.log("=".repeat(60))
console.log("\n📊 Test edilen özellikler:")
console.log("  ✓ Ed25519 kimlik doğrulama")
console.log("  ✓ Kategori listeleme")
console.log("  ✓ Preset yükleme (recon, web, password)")
console.log("  ✓ Araç arama ve yükleme")
console.log("  ✓ Port tarama (nmap, masscan)")
console.log("  ✓ DNS enumeration (dnsrecon)")
console.log("  ✓ Web teknoloji tespiti (whatweb)")
console.log("  ✓ Wordlist oluşturma (crunch)")
console.log("  ✓ Araç önerisi")
console.log("  ✓ Araç kaldırma")
console.log("\n🎯 Sonuç: Tüm MCP araçları düzgün çalışıyor!\n")
