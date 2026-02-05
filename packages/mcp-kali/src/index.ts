#!/usr/bin/env node

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import path from "path"
import { fileURLToPath } from "url"
import { loadAllTools } from "./tools/loader.js"
import { DynamicRegistry } from "./tools/registry.js"
import { createMcpServer } from "./server.js"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const DEFINITIONS_DIR = path.join(__dirname, "..", "src", "definitions")

/**
 * MCP Server for Kali Linux Tools - Stdio Transport
 *
 * Features:
 * - 100+ Kali tools available
 * - Dynamic tool loading to minimize context usage
 * - Only loaded tools consume context budget
 * - Meta-tools for search, load, unload operations
 */

async function main() {
  console.error("[bolt] Starting Bolt server (stdio)...")

  // Load all tool definitions
  const tools = await loadAllTools(DEFINITIONS_DIR)

  // Create a fresh registry instance
  const registry = new DynamicRegistry()
  registry.initialize(tools)

  const stats = registry.getStats()
  console.error(`[bolt] ${stats.totalTools} tools indexed, 0 loaded initially`)
  console.error(`[bolt] Context saved: ~${stats.totalTools * 500} tokens`)

  // Create MCP server with the registry
  const server = createMcpServer(registry)

  // Connect via stdio transport
  const transport = new StdioServerTransport()
  await server.connect(transport)

  console.error("[bolt] Bolt ready")
}

main().catch((err) => {
  console.error("[bolt] Fatal error:", err)
  process.exit(1)
})
