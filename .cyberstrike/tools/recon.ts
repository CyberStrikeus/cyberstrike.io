import { tool } from "@cyberstrike/plugin"

/**
 * Reconnaissance Tools - Subdomain enumeration and asset discovery
 *
 * IMPORTANT: Only use on domains/targets you have explicit authorization to test.
 */

export const subdomainEnum = tool({
  description: `Enumerate subdomains for a target domain using subfinder.
IMPORTANT: Only use on domains you have explicit authorization to test.
Requires subfinder to be installed.`,
  args: {
    domain: tool.schema.string().describe("Target domain to enumerate (e.g., example.com)"),
    sources: tool.schema
      .array(tool.schema.string())
      .optional()
      .describe("Specific data sources to use"),
    recursive: tool.schema
      .boolean()
      .default(false)
      .describe("Enable recursive subdomain enumeration"),
    output_format: tool.schema
      .enum(["text", "json"])
      .default("text")
      .describe("Output format"),
  },
  async execute(args, ctx) {
    const { $ } = await import("bun")

    try {
      await $`which subfinder`.quiet()
    } catch {
      return "Error: subfinder is not installed. Please install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    }

    const subfinderArgs: string[] = ["-d", args.domain, "-silent"]

    if (args.sources && args.sources.length > 0) {
      subfinderArgs.push("-sources", args.sources.join(","))
    }

    if (args.recursive) {
      subfinderArgs.push("-recursive")
    }

    if (args.output_format === "json") {
      subfinderArgs.push("-oJ")
    }

    ctx.metadata({ title: `subfinder: ${args.domain}` })

    try {
      const result = await $`subfinder ${subfinderArgs}`.text()
      const subdomains = result.trim().split("\n").filter(Boolean)

      if (args.output_format === "json") {
        return JSON.stringify({
          domain: args.domain,
          subdomains,
          total: subdomains.length,
        }, null, 2)
      }

      return `Found ${subdomains.length} subdomains:\n${result}`
    } catch (error) {
      return `Error running subfinder: ${error instanceof Error ? error.message : String(error)}`
    }
  },
})

export const httpProbe = tool({
  description: `Probe a list of hosts/URLs to check which are alive using httpx.
IMPORTANT: Only use on targets you have explicit authorization to test.
Requires httpx to be installed.`,
  args: {
    targets: tool.schema
      .array(tool.schema.string())
      .describe("List of hosts or URLs to probe"),
    ports: tool.schema
      .string()
      .optional()
      .describe("Ports to probe (e.g., '80,443,8080')"),
    follow_redirects: tool.schema
      .boolean()
      .default(true)
      .describe("Follow HTTP redirects"),
    tech_detect: tool.schema
      .boolean()
      .default(false)
      .describe("Enable technology detection"),
    output_format: tool.schema
      .enum(["text", "json"])
      .default("text")
      .describe("Output format"),
  },
  async execute(args, ctx) {
    const { $ } = await import("bun")

    try {
      await $`which httpx`.quiet()
    } catch {
      return "Error: httpx is not installed. Please install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    }

    const httpxArgs: string[] = ["-silent"]

    if (args.ports) {
      httpxArgs.push("-ports", args.ports)
    }

    if (!args.follow_redirects) {
      httpxArgs.push("-no-follow-redirects")
    }

    if (args.tech_detect) {
      httpxArgs.push("-tech-detect")
    }

    if (args.output_format === "json") {
      httpxArgs.push("-json")
    }

    ctx.metadata({ title: `httpx probe: ${args.targets.length} targets` })

    try {
      const input = args.targets.join("\n")
      const result = await $`echo ${input} | httpx ${httpxArgs}`.text()

      if (args.output_format === "json" && result.trim()) {
        const hosts = result
          .trim()
          .split("\n")
          .filter(Boolean)
          .map((line) => {
            try {
              return JSON.parse(line)
            } catch {
              return { url: line }
            }
          })

        return JSON.stringify({
          targets: args.targets.length,
          alive: hosts.length,
          hosts,
        }, null, 2)
      }

      return result || "No live hosts found"
    } catch (error) {
      return `Error running httpx: ${error instanceof Error ? error.message : String(error)}`
    }
  },
})

export const waybackUrls = tool({
  description: `Fetch URLs from Wayback Machine for a domain using waybackurls/gau.
IMPORTANT: Only use on domains you have explicit authorization to test.
Requires gau to be installed.`,
  args: {
    domain: tool.schema.string().describe("Target domain"),
    providers: tool.schema
      .array(tool.schema.enum(["wayback", "commoncrawl", "otx", "urlscan"]))
      .optional()
      .describe("Data providers to use"),
    filter_extensions: tool.schema
      .array(tool.schema.string())
      .optional()
      .describe("Filter by file extensions (e.g., ['js', 'json', 'xml'])"),
  },
  async execute(args, ctx) {
    const { $ } = await import("bun")

    try {
      await $`which gau`.quiet()
    } catch {
      return "Error: gau is not installed. Please install: go install -v github.com/lc/gau/v2/cmd/gau@latest"
    }

    const gauArgs: string[] = ["--subs"]

    if (args.providers && args.providers.length > 0) {
      gauArgs.push("--providers", args.providers.join(","))
    }

    ctx.metadata({ title: `gau: ${args.domain}` })

    try {
      let result = await $`echo ${args.domain} | gau ${gauArgs}`.text()

      if (args.filter_extensions && args.filter_extensions.length > 0) {
        const urls = result.trim().split("\n").filter(Boolean)
        const extPattern = new RegExp(`\\.(${args.filter_extensions.join("|")})($|\\?)`, "i")
        const filtered = urls.filter((url) => extPattern.test(url))
        result = filtered.join("\n")
      }

      const urls = result.trim().split("\n").filter(Boolean)
      return `Found ${urls.length} URLs:\n${result.slice(0, 10000)}${result.length > 10000 ? "\n... (truncated)" : ""}`
    } catch (error) {
      return `Error running gau: ${error instanceof Error ? error.message : String(error)}`
    }
  },
})
