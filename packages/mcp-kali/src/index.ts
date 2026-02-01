#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js"
import path from "path"
import { fileURLToPath } from "url"
import { loadAllTools } from "./tools/loader.js"
import { executeTool, validateToolExists } from "./tools/executor.js"
import { toJsonSchema } from "./tools/types.js"
import { registry } from "./tools/registry.js"
import { PRESETS, getPreset, getPresetsByCategory } from "./tools/presets.js"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const DEFINITIONS_DIR = path.join(__dirname, "..", "src", "definitions")

/**
 * MCP Server for Kali Linux Tools - Dynamic Loading Edition
 *
 * Features:
 * - 100+ Kali tools available
 * - Dynamic tool loading to minimize context usage
 * - Only loaded tools consume context budget
 * - Meta-tools for search, load, unload operations
 */

async function main() {
  console.error("[mcp-kali] Starting Kali Linux MCP Server (Dynamic Loading)...")

  // Load all tool definitions into registry
  const tools = await loadAllTools(DEFINITIONS_DIR)
  registry.initialize(tools)

  const stats = registry.getStats()
  console.error(`[mcp-kali] ${stats.totalTools} tools indexed, 0 loaded initially`)
  console.error(`[mcp-kali] Context saved: ~${stats.totalTools * 500} tokens`)

  // Create MCP server
  const server = new Server(
    {
      name: "mcp-kali",
      version: "0.2.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  )

  // Handle list tools request
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const mcpTools: Tool[] = []

    // === META-TOOLS (Always Available) ===

    // 1. Search tool
    mcpTools.push({
      name: "kali_search",
      description:
        "Search for Kali Linux tools by capability. Returns tool names and descriptions. Use this FIRST to find tools, then use kali_load to load them.",
      inputSchema: {
        type: "object",
        properties: {
          query: {
            type: "string",
            description: "Search query (e.g., 'sql injection', 'port scan', 'password crack', 'subdomain')",
          },
          limit: {
            type: "integer",
            description: "Maximum results (default: 10)",
            default: 10,
          },
        },
        required: ["query"],
      },
    })

    // 2. Load tools
    mcpTools.push({
      name: "kali_load",
      description:
        "Load tools into context to make them available for use. You MUST load a tool before you can use it. Recommend loading max 5-10 tools at a time.",
      inputSchema: {
        type: "object",
        properties: {
          tools: {
            type: "array",
            items: { type: "string" },
            description: "Tool names to load (e.g., ['nmap', 'sqlmap'])",
          },
        },
        required: ["tools"],
      },
    })

    // 3. Unload tools
    mcpTools.push({
      name: "kali_unload",
      description:
        "Unload tools from context to free up context budget. Use when done with a tool.",
      inputSchema: {
        type: "object",
        properties: {
          tools: {
            type: "array",
            items: { type: "string" },
            description: "Tool names to unload (e.g., ['nmap']). Use ['*'] to unload all.",
          },
        },
        required: ["tools"],
      },
    })

    // 4. List loaded tools
    mcpTools.push({
      name: "kali_status",
      description:
        "Show currently loaded tools and context usage statistics.",
      inputSchema: {
        type: "object",
        properties: {},
      },
    })

    // 5. List categories
    mcpTools.push({
      name: "kali_categories",
      description:
        "List all tool categories with tool counts. Useful for exploring available tools.",
      inputSchema: {
        type: "object",
        properties: {
          category: {
            type: "string",
            description: "Optional: show tools in a specific category",
          },
        },
      },
    })

    // 6. Presets - load tool sets for common tasks
    mcpTools.push({
      name: "kali_preset",
      description:
        "Load a pre-defined set of tools for common pentest scenarios. Much faster than loading tools individually. Use 'list' to see available presets.",
      inputSchema: {
        type: "object",
        properties: {
          name: {
            type: "string",
            description: "Preset name (e.g., 'web-scan', 'ad-enum', 'recon-network') or 'list' to see all",
          },
        },
        required: ["name"],
      },
    })

    // 7. Recommendations
    mcpTools.push({
      name: "kali_recommend",
      description:
        "Get tool recommendations based on currently loaded tools and usage patterns.",
      inputSchema: {
        type: "object",
        properties: {
          limit: {
            type: "integer",
            description: "Number of recommendations (default: 5)",
            default: 5,
          },
        },
      },
    })

    // 8. Auto-cleanup
    mcpTools.push({
      name: "kali_cleanup",
      description:
        "Auto-unload tools that haven't been used recently to free context budget.",
      inputSchema: {
        type: "object",
        properties: {},
      },
    })

    // === LOADED TOOLS (Dynamic) ===
    for (const tool of registry.getLoadedTools()) {
      mcpTools.push({
        name: `kali_${tool.name.replace(/-/g, "_")}`,
        description: tool.description,
        inputSchema: toJsonSchema(tool) as Tool["inputSchema"],
      })
    }

    const loadedCount = registry.getLoadedToolNames().length
    console.error(`[mcp-kali] Returning ${mcpTools.length} tools (5 meta + ${loadedCount} loaded)`)

    return { tools: mcpTools }
  })

  // Handle tool execution
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params

    console.error(`[mcp-kali] Tool call: ${name}`)

    // === META-TOOL: Search ===
    if (name === "kali_search") {
      const query = (args?.query as string) || ""
      const limit = (args?.limit as number) || 10

      const results = registry.search(query, limit)

      if (results.length === 0) {
        return {
          content: [{
            type: "text",
            text: `No tools found for "${query}". Try different keywords like: port scan, sql injection, password, subdomain, wifi, etc.`,
          }],
        }
      }

      const formatted = results
        .map((t, i) => {
          const loaded = registry.isLoaded(t.name) ? " ✓ LOADED" : ""
          return `${i + 1}. **${t.name}**${loaded} (${t.category})\n   ${t.description}`
        })
        .join("\n\n")

      return {
        content: [{
          type: "text",
          text: `Found ${results.length} tools for "${query}":\n\n${formatted}\n\n**Next step:** Use \`kali_load\` to load the tools you need, then use them with \`kali_<tool_name>\``,
        }],
      }
    }

    // === META-TOOL: Load ===
    if (name === "kali_load") {
      const toolNames = (args?.tools as string[]) || []

      if (toolNames.length === 0) {
        return {
          content: [{ type: "text", text: "No tools specified. Provide tool names to load." }],
          isError: true,
        }
      }

      const result = registry.load(toolNames)

      let response = ""
      if (result.loaded.length > 0) {
        response += `✓ Loaded: ${result.loaded.join(", ")}\n`
      }
      if (result.failed.length > 0) {
        response += `✗ Not found: ${result.failed.join(", ")}\n`
      }
      if (result.warning) {
        response += `\n⚠️ ${result.warning}`
      }

      const stats = registry.getStats()
      response += `\n\n**Status:** ${stats.loadedTools}/${stats.maxTools} tools loaded (~${stats.estimatedTokens} tokens)`
      response += `\n\n**Loaded tools can now be used as:** ${result.loaded.map(t => `kali_${t.replace(/-/g, "_")}`).join(", ")}`

      return {
        content: [{ type: "text", text: response }],
      }
    }

    // === META-TOOL: Unload ===
    if (name === "kali_unload") {
      const toolNames = (args?.tools as string[]) || []

      if (toolNames.length === 0) {
        return {
          content: [{ type: "text", text: "No tools specified." }],
          isError: true,
        }
      }

      // Handle unload all
      if (toolNames.includes("*")) {
        const count = registry.unloadAll()
        return {
          content: [{
            type: "text",
            text: `✓ Unloaded all ${count} tools. Context freed: ~${count * 500} tokens`,
          }],
        }
      }

      const result = registry.unload(toolNames)

      let response = ""
      if (result.unloaded.length > 0) {
        response += `✓ Unloaded: ${result.unloaded.join(", ")}\n`
        response += `Context freed: ~${result.unloaded.length * 500} tokens`
      }
      if (result.notLoaded.length > 0) {
        response += `\nNot loaded: ${result.notLoaded.join(", ")}`
      }

      return {
        content: [{ type: "text", text: response }],
      }
    }

    // === META-TOOL: Status ===
    if (name === "kali_status") {
      const stats = registry.getStats()
      const loadedNames = registry.getLoadedToolNames()

      let response = `## Kali Tools Status\n\n`
      response += `**Available:** ${stats.totalTools} tools\n`
      response += `**Loaded:** ${stats.loadedTools}/${stats.maxTools}\n`
      response += `**Context usage:** ~${stats.estimatedTokens} tokens\n\n`

      if (loadedNames.length > 0) {
        response += `**Loaded tools:**\n`
        response += loadedNames.map(n => `- kali_${n.replace(/-/g, "_")}`).join("\n")
      } else {
        response += `_No tools loaded. Use kali_search to find tools, then kali_load to load them._`
      }

      return {
        content: [{ type: "text", text: response }],
      }
    }

    // === META-TOOL: Categories ===
    if (name === "kali_categories") {
      const categoryName = args?.category as string | undefined
      const categories = registry.getCategories()

      if (categoryName) {
        const category = categories.find(c => c.name.toLowerCase() === categoryName.toLowerCase())
        if (!category) {
          return {
            content: [{
              type: "text",
              text: `Category "${categoryName}" not found. Available: ${categories.map(c => c.name).join(", ")}`,
            }],
            isError: true,
          }
        }

        const toolList = category.tools
          .map(t => {
            const loaded = registry.isLoaded(t) ? " ✓" : ""
            return `- ${t}${loaded}`
          })
          .join("\n")

        return {
          content: [{
            type: "text",
            text: `## ${category.name} (${category.count} tools)\n\n${toolList}\n\n_Use kali_load to load tools_`,
          }],
        }
      }

      const formatted = categories
        .map(c => `- **${c.name}**: ${c.count} tools`)
        .join("\n")

      return {
        content: [{
          type: "text",
          text: `## Available Categories\n\n${formatted}\n\n**Total:** ${stats.totalTools} tools\n\n_Use \`kali_categories\` with a category name to see tools in that category_`,
        }],
      }
    }

    // === META-TOOL: Preset ===
    if (name === "kali_preset") {
      const presetName = (args?.name as string) || ""

      // List all presets
      if (presetName === "list" || presetName === "") {
        const categories = getPresetsByCategory()
        let response = "## Available Presets\n\n"

        for (const [category, presets] of Object.entries(categories)) {
          if (presets.length === 0) continue
          response += `### ${category}\n`
          for (const preset of presets) {
            const key = Object.entries(PRESETS).find(([_, v]) => v === preset)?.[0]
            response += `- **${key}**: ${preset.description} (${preset.tools.length} tools)\n`
          }
          response += "\n"
        }

        response += "\n_Use `kali_preset` with a preset name to load tools_"
        return { content: [{ type: "text", text: response }] }
      }

      // Load specific preset
      const preset = getPreset(presetName)
      if (!preset) {
        const available = Object.keys(PRESETS).join(", ")
        return {
          content: [{
            type: "text",
            text: `Preset "${presetName}" not found.\n\nAvailable: ${available}`,
          }],
          isError: true,
        }
      }

      // Load the preset tools
      const result = registry.load(preset.tools)

      let response = `## ${preset.name}\n\n`
      response += `${preset.description}\n\n`

      if (result.loaded.length > 0) {
        response += `✓ Loaded: ${result.loaded.join(", ")}\n`
      }
      if (result.failed.length > 0) {
        response += `✗ Not found: ${result.failed.join(", ")}\n`
      }

      if (preset.workflow) {
        response += `\n### Recommended Workflow\n\`\`\`\n${preset.workflow}\n\`\`\`\n`
      }

      const stats = registry.getStats()
      response += `\n**Status:** ${stats.loadedTools}/${stats.maxTools} tools loaded`

      return { content: [{ type: "text", text: response }] }
    }

    // === META-TOOL: Recommend ===
    if (name === "kali_recommend") {
      const limit = (args?.limit as number) || 5
      const recommendations = registry.getRecommendations(limit)

      if (recommendations.length === 0) {
        return {
          content: [{
            type: "text",
            text: "No recommendations available. Start by loading some tools with `kali_preset` or `kali_load`.",
          }],
        }
      }

      let response = "## Recommended Tools\n\n"
      response += "Based on your current context and usage patterns:\n\n"

      for (const rec of recommendations) {
        response += `- **${rec.name}** - ${rec.reason}\n`
      }

      response += `\n_Use \`kali_load\` to load recommended tools_`

      return { content: [{ type: "text", text: response }] }
    }

    // === META-TOOL: Cleanup ===
    if (name === "kali_cleanup") {
      const stale = registry.getStaleTools()

      if (stale.length === 0) {
        const stats = registry.getStats()
        return {
          content: [{
            type: "text",
            text: `No stale tools to unload. Currently loaded: ${stats.loadedTools} tools.`,
          }],
        }
      }

      const result = registry.autoUnload()

      if (result.unloaded.length === 0) {
        return {
          content: [{
            type: "text",
            text: `Found ${stale.length} stale tools but kept them (under limit). Stale: ${stale.join(", ")}`,
          }],
        }
      }

      const stats = registry.getStats()
      return {
        content: [{
          type: "text",
          text: `✓ Auto-unloaded ${result.unloaded.length} stale tools: ${result.unloaded.join(", ")}\n\nReason: ${result.reason}\nContext freed: ~${result.unloaded.length * 500} tokens\nNow loaded: ${stats.loadedTools} tools`,
        }],
      }
    }

    // === KALI TOOL EXECUTION ===
    if (name.startsWith("kali_")) {
      const toolName = name.replace("kali_", "").replace(/_/g, "-")

      // Check if tool is loaded
      if (!registry.isLoaded(toolName)) {
        // Try to help the user
        const searchResults = registry.search(toolName, 3)
        const suggestions = searchResults.length > 0
          ? `\n\nDid you mean: ${searchResults.map(t => t.name).join(", ")}?\nUse kali_load to load the tool first.`
          : "\n\nUse kali_search to find tools, then kali_load to load them."

        return {
          content: [{
            type: "text",
            text: `Tool "${toolName}" is not loaded.${suggestions}`,
          }],
          isError: true,
        }
      }

      const tool = registry.getToolForExecution(toolName)
      if (!tool) {
        return {
          content: [{ type: "text", text: `Tool "${toolName}" not found.` }],
          isError: true,
        }
      }

      // Check if tool exists on system
      const exists = await validateToolExists(tool.name)
      if (!exists) {
        return {
          content: [{
            type: "text",
            text: `Tool "${tool.name}" is not installed. Install with: sudo apt install ${tool.name}`,
          }],
          isError: true,
        }
      }

      // Record usage for recommendations
      registry.recordUsage(toolName)

      // Execute the tool
      const result = await executeTool(tool, (args as Record<string, unknown>) || {})

      const status = result.success ? "✓ Success" : "✗ Failed"
      const duration = result.duration ? ` (${(result.duration / 1000).toFixed(1)}s)` : ""

      return {
        content: [{
          type: "text",
          text: `## ${tool.name} ${status}${duration}\n\n\`\`\`\n${result.output}\n\`\`\`${result.error ? `\n\n**Error:** ${result.error}` : ""}`,
        }],
        isError: !result.success,
      }
    }

    return {
      content: [{ type: "text", text: `Unknown tool: ${name}` }],
      isError: true,
    }
  })

  // Start server
  const transport = new StdioServerTransport()
  await server.connect(transport)

  console.error("[mcp-kali] Server ready (Dynamic Loading enabled)")
}

main().catch((err) => {
  console.error("[mcp-kali] Fatal error:", err)
  process.exit(1)
})
