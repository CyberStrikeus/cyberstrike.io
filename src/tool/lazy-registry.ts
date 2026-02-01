import { Log } from "../util/log"
import { Instance } from "../project/instance"
import { MCP } from "../mcp"
import { Config } from "../config/config"
import type { Tool as AITool } from "ai"

const log = Log.create({ service: "tool.lazy-registry" })

/**
 * Lazy Tool Registry
 *
 * This module implements dynamic tool loading to prevent context overflow.
 *
 * Problem:
 * - Each tool definition consumes ~500 tokens (description + parameters)
 * - 100 MCP tools = 50,000 tokens just for tool definitions
 * - This leaves little room for actual conversation
 *
 * Solution:
 * - Store only tool metadata (name, summary, keywords) - ~50 tokens each
 * - Full tool definitions loaded on-demand via ToolSearch
 * - Keep only actively-used tools in context
 *
 * How it works:
 * 1. At startup, collect metadata for all available tools
 * 2. User asks for capability (e.g., "scan for vulnerabilities")
 * 3. ToolSearch finds matching tools by keywords/description
 * 4. Matching tools are dynamically loaded for the next turn
 * 5. Unused tools can be unloaded to free context
 */
export namespace LazyToolRegistry {
  /**
   * Minimal tool metadata for search (low context cost)
   */
  export interface LazyTool {
    id: string
    name: string
    summary: string // Short description, max 100 chars
    keywords: string[] // For search matching
    category: string // For grouping
    source: "mcp" | "plugin" | "builtin"
    mcpServer?: string // If source is mcp
  }

  /**
   * Full tool definition (high context cost)
   */
  export interface LoadedTool {
    id: string
    tool: AITool
  }

  // State
  const lazyTools = new Map<string, LazyTool>()
  const loadedTools = new Map<string, LoadedTool>()
  const loadedToolIds = new Set<string>()

  // Token budget for tool definitions
  const TOOL_CONTEXT_BUDGET = 30000 // ~30K tokens for tools
  const AVG_TOKENS_PER_TOOL = 500

  /**
   * Initialize lazy registry by collecting metadata from all MCP servers
   */
  export async function init(): Promise<void> {
    log.info("initializing lazy tool registry")

    // Get all MCP tools metadata
    const mcpStatus = await MCP.status()
    const clients = await MCP.clients()

    for (const [serverName, status] of Object.entries(mcpStatus)) {
      if (status.status !== "connected") continue

      const client = clients[serverName]
      if (!client) continue

      try {
        const toolsResult = await client.listTools()

        for (const mcpTool of toolsResult.tools) {
          const sanitizedServerName = serverName.replace(/[^a-zA-Z0-9_-]/g, "_")
          const sanitizedToolName = mcpTool.name.replace(/[^a-zA-Z0-9_-]/g, "_")
          const id = `${sanitizedServerName}_${sanitizedToolName}`

          // Extract keywords from description and name
          const keywords = extractKeywords(mcpTool.name, mcpTool.description || "")

          // Create summary (truncate description)
          const summary = (mcpTool.description || mcpTool.name).slice(0, 100)

          // Categorize based on keywords
          const category = categorize(keywords)

          lazyTools.set(id, {
            id,
            name: mcpTool.name,
            summary,
            keywords,
            category,
            source: "mcp",
            mcpServer: serverName,
          })
        }

        log.info("collected tool metadata", {
          server: serverName,
          count: toolsResult.tools.length,
        })
      } catch (err) {
        log.error("failed to collect tool metadata", { server: serverName, error: err })
      }
    }

    log.info("lazy tool registry initialized", {
      totalTools: lazyTools.size,
      loadedTools: loadedTools.size,
    })
  }

  /**
   * Search for tools by query
   */
  export function search(query: string, limit = 10): LazyTool[] {
    const queryLower = query.toLowerCase()
    const queryWords = queryLower.split(/\s+/)

    const scored: Array<{ tool: LazyTool; score: number }> = []

    for (const tool of lazyTools.values()) {
      let score = 0

      // Exact name match
      if (tool.name.toLowerCase() === queryLower) {
        score += 100
      }

      // Name contains query
      if (tool.name.toLowerCase().includes(queryLower)) {
        score += 50
      }

      // Summary contains query
      if (tool.summary.toLowerCase().includes(queryLower)) {
        score += 30
      }

      // Keyword matches
      for (const word of queryWords) {
        for (const keyword of tool.keywords) {
          if (keyword.includes(word) || word.includes(keyword)) {
            score += 20
          }
        }
      }

      // Category bonus
      if (tool.category.toLowerCase().includes(queryLower)) {
        score += 25
      }

      if (score > 0) {
        scored.push({ tool, score })
      }
    }

    // Sort by score descending
    scored.sort((a, b) => b.score - a.score)

    return scored.slice(0, limit).map((s) => s.tool)
  }

  /**
   * Load tools by IDs (makes them available for use)
   */
  export async function load(toolIds: string[]): Promise<LoadedTool[]> {
    const newlyLoaded: LoadedTool[] = []

    // Check budget
    const currentCount = loadedTools.size
    const newCount = toolIds.filter((id) => !loadedToolIds.has(id)).length
    const estimatedTokens = (currentCount + newCount) * AVG_TOKENS_PER_TOOL

    if (estimatedTokens > TOOL_CONTEXT_BUDGET) {
      log.warn("tool context budget exceeded, unloading least used tools", {
        current: currentCount,
        new: newCount,
        estimated: estimatedTokens,
        budget: TOOL_CONTEXT_BUDGET,
      })
      // Could implement LRU eviction here
    }

    // Get all MCP tools (full definitions)
    const mcpTools = await MCP.tools()

    for (const id of toolIds) {
      if (loadedToolIds.has(id)) {
        const existing = loadedTools.get(id)
        if (existing) newlyLoaded.push(existing)
        continue
      }

      const lazyTool = lazyTools.get(id)
      if (!lazyTool) {
        log.warn("tool not found in lazy registry", { id })
        continue
      }

      // Get full tool from MCP
      const fullTool = mcpTools[id]
      if (!fullTool) {
        log.warn("tool not found in MCP", { id })
        continue
      }

      const loaded: LoadedTool = {
        id,
        tool: fullTool,
      }

      loadedTools.set(id, loaded)
      loadedToolIds.add(id)
      newlyLoaded.push(loaded)

      log.info("loaded tool", { id, source: lazyTool.source })
    }

    return newlyLoaded
  }

  /**
   * Unload tools to free context budget
   */
  export function unload(toolIds: string[]): void {
    for (const id of toolIds) {
      loadedTools.delete(id)
      loadedToolIds.delete(id)
      log.info("unloaded tool", { id })
    }
  }

  /**
   * Get currently loaded tools
   */
  export function getLoaded(): LoadedTool[] {
    return Array.from(loadedTools.values())
  }

  /**
   * Get all available tool metadata
   */
  export function getAll(): LazyTool[] {
    return Array.from(lazyTools.values())
  }

  /**
   * Check if a tool is loaded
   */
  export function isLoaded(id: string): boolean {
    return loadedToolIds.has(id)
  }

  /**
   * Get tool count statistics
   */
  export function stats(): {
    available: number
    loaded: number
    estimatedTokens: number
    budgetRemaining: number
  } {
    const loaded = loadedTools.size
    const estimatedTokens = loaded * AVG_TOKENS_PER_TOOL
    return {
      available: lazyTools.size,
      loaded,
      estimatedTokens,
      budgetRemaining: TOOL_CONTEXT_BUDGET - estimatedTokens,
    }
  }

  /**
   * Format tools for display in tool search results
   */
  export function formatSearchResults(tools: LazyTool[]): string {
    if (tools.length === 0) {
      return "No matching tools found."
    }

    const lines = [
      `Found ${tools.length} matching tool(s):`,
      "",
      ...tools.map((t, i) => {
        const loaded = isLoaded(t.id) ? " [LOADED]" : ""
        return `${i + 1}. **${t.name}**${loaded}\n   ID: \`${t.id}\`\n   ${t.summary}\n   Category: ${t.category}`
      }),
      "",
      "Use `load_tools` with the tool IDs to make them available for use.",
    ]

    return lines.join("\n")
  }

  // Helper functions

  function extractKeywords(name: string, description: string): string[] {
    const text = `${name} ${description}`.toLowerCase()

    // Remove common words
    const stopWords = new Set([
      "the",
      "a",
      "an",
      "is",
      "are",
      "was",
      "were",
      "be",
      "been",
      "being",
      "have",
      "has",
      "had",
      "do",
      "does",
      "did",
      "will",
      "would",
      "could",
      "should",
      "may",
      "might",
      "must",
      "shall",
      "can",
      "need",
      "dare",
      "ought",
      "used",
      "to",
      "of",
      "in",
      "for",
      "on",
      "with",
      "at",
      "by",
      "from",
      "as",
      "into",
      "through",
      "during",
      "before",
      "after",
      "above",
      "below",
      "between",
      "under",
      "again",
      "further",
      "then",
      "once",
      "and",
      "but",
      "or",
      "nor",
      "so",
      "yet",
      "this",
      "that",
      "these",
      "those",
    ])

    const words = text
      .replace(/[^a-z0-9\s]/g, " ")
      .split(/\s+/)
      .filter((w) => w.length > 2 && !stopWords.has(w))

    return [...new Set(words)]
  }

  function categorize(keywords: string[]): string {
    const categories: Record<string, string[]> = {
      web: ["http", "web", "url", "api", "request", "response", "html", "css", "javascript", "browser"],
      network: ["network", "port", "scan", "nmap", "tcp", "udp", "ip", "dns", "socket"],
      file: ["file", "read", "write", "directory", "path", "folder"],
      security: ["security", "vulnerability", "exploit", "attack", "inject", "xss", "sql", "csrf"],
      cloud: ["aws", "azure", "gcp", "cloud", "s3", "ec2", "lambda", "bucket"],
      database: ["database", "sql", "query", "mysql", "postgres", "mongo", "redis"],
      git: ["git", "commit", "branch", "merge", "repository", "clone"],
      shell: ["shell", "bash", "command", "terminal", "exec", "process"],
    }

    for (const [category, categoryKeywords] of Object.entries(categories)) {
      for (const keyword of keywords) {
        if (categoryKeywords.some((ck) => keyword.includes(ck) || ck.includes(keyword))) {
          return category
        }
      }
    }

    return "general"
  }

  /**
   * Clear all state (for testing)
   */
  export function clear(): void {
    lazyTools.clear()
    loadedTools.clear()
    loadedToolIds.clear()
  }
}
