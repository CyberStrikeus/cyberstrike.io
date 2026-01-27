import { tool } from "@whykido/plugin"

/**
 * Nuclei Scanner Tool - Vulnerability scanning with nuclei templates
 *
 * IMPORTANT: This tool should only be used on systems you have
 * explicit authorization to test. Unauthorized scanning is illegal.
 */
export default tool({
  description: `Execute nuclei vulnerability scanner for security assessment.
IMPORTANT: Only use on systems you have explicit authorization to test.
Returns vulnerability findings based on nuclei templates.
Requires nuclei to be installed on the system.`,
  args: {
    target: tool.schema.string().describe("Target URL or file path containing targets"),
    templates: tool.schema
      .array(tool.schema.string())
      .optional()
      .describe("Specific template tags to use (e.g., ['cve', 'misconfig'])"),
    severity: tool.schema
      .array(tool.schema.enum(["info", "low", "medium", "high", "critical"]))
      .optional()
      .describe("Filter by severity levels"),
    rate_limit: tool.schema
      .number()
      .default(150)
      .describe("Maximum requests per second"),
    output_format: tool.schema
      .enum(["text", "json"])
      .default("text")
      .describe("Output format for results"),
    silent: tool.schema
      .boolean()
      .default(false)
      .describe("Only show findings, no progress"),
  },
  async execute(args, ctx) {
    const { $ } = await import("bun")

    // Check if nuclei is installed
    try {
      await $`which nuclei`.quiet()
    } catch {
      return "Error: nuclei is not installed. Please install nuclei first: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    }

    const nucleiArgs: string[] = ["-u", args.target, "-rl", String(args.rate_limit)]

    if (args.templates && args.templates.length > 0) {
      for (const tag of args.templates) {
        nucleiArgs.push("-tags", tag)
      }
    }

    if (args.severity && args.severity.length > 0) {
      nucleiArgs.push("-severity", args.severity.join(","))
    }

    if (args.output_format === "json") {
      nucleiArgs.push("-jsonl")
    }

    if (args.silent) {
      nucleiArgs.push("-silent")
    }

    ctx.metadata({ title: `nuclei scan: ${args.target}` })

    try {
      const result = await $`nuclei ${nucleiArgs}`.text()

      if (args.output_format === "json" && result.trim()) {
        // Parse JSONL output
        const findings = result
          .trim()
          .split("\n")
          .filter((line) => line.trim())
          .map((line) => {
            try {
              return JSON.parse(line)
            } catch {
              return { raw: line }
            }
          })

        return JSON.stringify({ target: args.target, findings, total: findings.length }, null, 2)
      }

      return result || "No vulnerabilities found"
    } catch (error) {
      return `Error running nuclei: ${error instanceof Error ? error.message : String(error)}`
    }
  },
})
