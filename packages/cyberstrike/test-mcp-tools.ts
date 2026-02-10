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

console.log("🔌 Kali Bolt MCP sunucusuna bağlanıyor...")

// Load credentials
const creds = await Ed25519Auth.loadCredentials(mcpName)
if (!creds) {
  console.error("❌ Kimlik bilgileri bulunamadı:", mcpName)
  process.exit(1)
}

console.log("✓ Kimlik yüklendi - Client ID:", creds.clientId)

// Create transport with Ed25519 auth
const transport = new BoltTransport(new URL(serverUrl), creds.clientId, creds.privateKey)

// Create client
const client = new Client({
  name: "test-client",
  version: "1.0.0"
})

try {
  // Connect
  console.log("\n📡 Bağlanıyor...")
  await client.connect(transport)
  console.log("✓ Başarıyla bağlandı!")

  // List tools
  console.log("\n📋 Mevcut araçlar listeleniyor...")
  const toolsResult = await client.listTools()
  console.log(`✓ ${toolsResult.tools.length} araç bulundu\n`)

  // Show all tools with descriptions
  console.log("🔧 Tüm araçlar:")
  toolsResult.tools.forEach((tool, i) => {
    console.log(`  ${i + 1}. ${tool.name}`)
    console.log(`     ${tool.description}`)
  })

  // Test 1: kali_status - check loaded tools
  console.log("\n\n🧪 TEST 1: kali_status (yüklü araçları kontrol et)")
  const statusResult = await client.callTool({
    name: "kali_status",
    arguments: {}
  })
  console.log("✓ Sonuç:", statusResult(content as TextContent[])[0].text)

  // Test 2: kali_categories - list available categories
  console.log("\n\n🧪 TEST 2: kali_categories (kategorileri listele)")
  const categoriesResult = await client.callTool({
    name: "kali_categories",
    arguments: {}
  })
  console.log("✓ Sonuç:", categoriesResult(content as TextContent[])[0].text)

  // Test 3: kali_search - search for nmap
  console.log("\n\n🧪 TEST 3: kali_search (nmap ara)")
  const searchResult = await client.callTool({
    name: "kali_search",
    arguments: { query: "nmap" }
  })
  console.log("✓ Sonuç:", searchResult(content as TextContent[])[0].text.slice(0, 500))

  // Test 4: kali_load - load nmap
  console.log("\n\n🧪 TEST 4: kali_load (nmap yükle)")
  const loadResult = await client.callTool({
    name: "kali_load",
    arguments: { tools: ["nmap"] }
  })
  console.log("✓ Sonuç:", loadResult(content as TextContent[])[0].text)

  // Test 5: Check status again to see loaded tools
  console.log("\n\n🧪 TEST 5: kali_status (nmap yüklendikten sonra)")
  const status2Result = await client.callTool({
    name: "kali_status",
    arguments: {}
  })
  console.log("✓ Sonuç:", status2Result(content as TextContent[])[0].text)

  // Test 6: Run nmap (with kali_ prefix)
  console.log("\n\n🧪 TEST 6: kali_nmap (version kontrolü)")
  const nmapResult = await client.callTool({
    name: "kali_nmap",
    arguments: { args: "--version" }
  })
  console.log("✓ Nmap çıktısı:")
  console.log(nmapResult(content as TextContent[])[0].text.split('\n').slice(0, 5).join('\n'))

  // Test 7: Load and run whois
  console.log("\n\n🧪 TEST 7: whois yükle ve çalıştır")
  await client.callTool({
    name: "kali_load",
    arguments: { tools: ["whois"] }
  })
  console.log("✓ whois yüklendi")

  const whoisResult = await client.callTool({
    name: "kali_whois",
    arguments: { domain: "google.com" }
  })
  console.log("✓ Whois çıktısı (ilk 10 satır):")
  console.log(whoisResult(content as TextContent[])[0].text.split('\n').slice(0, 10).join('\n'))

  // Test 8: kali_preset - load a preset
  console.log("\n\n🧪 TEST 8: kali_preset (recon preset yükle)")
  const presetResult = await client.callTool({
    name: "kali_preset",
    arguments: { preset: "recon" }
  })
  console.log("✓ Sonuç:", presetResult(content as TextContent[])[0].text)

  // Test 9: kali_jobs - list background jobs
  console.log("\n\n🧪 TEST 9: kali_jobs (arka plan işlerini listele)")
  const jobsResult = await client.callTool({
    name: "kali_jobs",
    arguments: {}
  })
  console.log("✓ Sonuç:", jobsResult(content as TextContent[])[0].text)

  // Test 10: kali_cleanup - cleanup loaded tools
  console.log("\n\n🧪 TEST 10: kali_cleanup (yüklü araçları temizle)")
  const cleanupResult = await client.callTool({
    name: "kali_cleanup",
    arguments: {}
  })
  console.log("✓ Sonuç:", cleanupResult(content as TextContent[])[0].text)

  // Final summary
  console.log("\n\n" + "=".repeat(60))
  console.log("✅ TÜM TESTLER BAŞARILI!")
  console.log("=".repeat(60))
  console.log("\n📊 Özet:")
  console.log(`   ✓ Toplam araç: ${toolsResult.tools.length}`)
  console.log(`   ✓ Meta-araçlar: kali_status, kali_search, kali_load, kali_preset`)
  console.log(`   ✓ Test edilen güvenlik araçları: nmap, whois`)
  console.log(`   ✓ Ed25519 kimlik doğrulama: ÇALIŞIYOR`)
  console.log(`   ✓ Araç yükleme/kaldırma: ÇALIŞIYOR`)
  console.log(`   ✓ Araç çalıştırma: ÇALIŞIYOR`)

} catch (error) {
  console.error("\n❌ Hata:", error)
  process.exit(1)
} finally {
  await client.close()
  console.log("\n🔌 Bağlantı kesildi\n")
}
