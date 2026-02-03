import z from "zod"
import { Tool } from "./tool"
import { LazyToolRegistry } from "./lazy-registry"
import { Log } from "../util/log"

const log = Log.create({ service: "tool.tool-search" })

/**
 * ToolSearch - Meta-tool for dynamic tool discovery
 *
 * This tool enables AI agents to work with hundreds of MCP tools
 * without overwhelming the context window.
 *
 * Instead of including all tool definitions in every request,
 * only this meta-tool is included. When the agent needs a specific
 * capability, it searches for matching tools and loads them.
 *
 * Pattern:
 * 1. Agent receives task: "scan target for SQL injection"
 * 2. Agent calls: tool_search({ query: "sql injection scanner" })
 * 3. ToolSearch returns: list of matching tools with IDs
 * 4. Agent calls: load_tools({ tool_ids: ["sqlmap_scan", "..."] })
 * 5. Tools become available for use in next turn
 */
export const ToolSearchTool = Tool.define("tool_search", async () => {
  return {
    description: [
      "Search for available tools by capability or description.",
      "Use this to find tools before using them.",
      "Returns tool IDs that can be loaded with load_tools.",
      "",
      "Example queries:",
      '- "sql injection testing"',
      '- "port scanner"',
      '- "subdomain enumeration"',
      '- "aws security"',
    ].join("\n"),
    parameters: z.object({
      query: z.string().describe("Search query describing the capability you need"),
      limit: z.number().optional().default(5).describe("Maximum number of results (default: 5)"),
    }),
    async execute(params, ctx) {
      const { query, limit } = params

      log.info("searching tools", { query, limit })

      // Search lazy registry
      const results = LazyToolRegistry.search(query, limit)

      // Format results
      const output = LazyToolRegistry.formatSearchResults(results)

      // Get stats
      const stats = LazyToolRegistry.stats()

      return {
        title: `Found ${results.length} tools`,
        output: [
          output,
          "",
          "---",
          `Tool Stats: ${stats.loaded}/${stats.available} loaded | ~${stats.estimatedTokens} tokens used | ${stats.budgetRemaining} budget remaining`,
        ].join("\n"),
        metadata: {
          query,
          resultCount: results.length,
          toolIds: results.map((t) => t.id),
        },
      }
    },
  }
})

/**
 * LoadTools - Load tools into context for use
 *
 * After finding tools with tool_search, use this to load them.
 * Loaded tools become available in the next turn.
 */
export const LoadToolsTool = Tool.define("load_tools", async () => {
  return {
    description: [
      "Load tools into context so they can be used.",
      "Use tool_search first to find tool IDs.",
      "Loaded tools will be available in the next turn.",
      "",
      "Note: Loading too many tools may exceed context budget.",
    ].join("\n"),
    parameters: z.object({
      tool_ids: z.array(z.string()).describe("Tool IDs to load (from tool_search results)"),
    }),
    async execute(params, ctx) {
      const { tool_ids } = params

      log.info("loading tools", { tool_ids })

      // Load tools
      const loaded = await LazyToolRegistry.load(tool_ids)

      // Get stats
      const stats = LazyToolRegistry.stats()

      const output = [
        `Loaded ${loaded.length} tool(s):`,
        "",
        ...loaded.map((t) => `- ${t.id}`),
        "",
        "These tools are now available for use.",
        "",
        "---",
        `Tool Stats: ${stats.loaded}/${stats.available} loaded | ~${stats.estimatedTokens} tokens used | ${stats.budgetRemaining} budget remaining`,
      ].join("\n")

      return {
        title: `Loaded ${loaded.length} tools`,
        output,
        metadata: {
          loadedCount: loaded.length,
          loadedIds: loaded.map((t) => t.id),
          stats,
        },
      }
    },
  }
})

/**
 * UnloadTools - Remove tools from context to free budget
 */
export const UnloadToolsTool = Tool.define("unload_tools", async () => {
  return {
    description: [
      "Remove tools from context to free up token budget.",
      "Use this when you no longer need certain tools.",
    ].join("\n"),
    parameters: z.object({
      tool_ids: z.array(z.string()).describe("Tool IDs to unload"),
    }),
    async execute(params, ctx) {
      const { tool_ids } = params

      log.info("unloading tools", { tool_ids })

      LazyToolRegistry.unload(tool_ids)

      const stats = LazyToolRegistry.stats()

      return {
        title: `Unloaded ${tool_ids.length} tools`,
        output: [
          `Unloaded ${tool_ids.length} tool(s).`,
          "",
          `Tool Stats: ${stats.loaded}/${stats.available} loaded | ~${stats.estimatedTokens} tokens used | ${stats.budgetRemaining} budget remaining`,
        ].join("\n"),
        metadata: {
          unloadedCount: tool_ids.length,
          unloadedIds: tool_ids,
          stats,
        },
      }
    },
  }
})

/**
 * ListLoadedTools - Show currently loaded tools
 */
export const ListLoadedToolsTool = Tool.define("list_loaded_tools", async () => {
  return {
    description: "List all currently loaded tools and context usage.",
    parameters: z.object({}),
    async execute(params, ctx) {
      const loaded = LazyToolRegistry.getLoaded()
      const stats = LazyToolRegistry.stats()

      const output =
        loaded.length === 0
          ? "No tools currently loaded. Use tool_search to find tools."
          : [
              `Currently loaded tools (${loaded.length}):`,
              "",
              ...loaded.map((t) => `- ${t.id}`),
              "",
              "---",
              `Available: ${stats.available} | Loaded: ${stats.loaded}`,
              `Token usage: ~${stats.estimatedTokens} / ${stats.estimatedTokens + stats.budgetRemaining}`,
            ].join("\n")

      return {
        title: `${loaded.length} tools loaded`,
        output,
        metadata: {
          loadedCount: loaded.length,
          loadedIds: loaded.map((t) => t.id),
          stats,
        },
      }
    },
  }
})
