import { tool } from "@cyberstrike-io/plugin"

/**
 * Nmap Scan Tool - Network reconnaissance and service enumeration
 *
 * IMPORTANT: This tool should only be used on networks and systems you have
 * explicit authorization to test. Unauthorized scanning is illegal.
 */
export default tool({
  description: `Execute nmap network scan for security assessment.
IMPORTANT: Only use on systems you have explicit authorization to test.
Returns parsed scan results including open ports, services, and versions.
Requires nmap to be installed on the system.`,
  args: {
    target: tool.schema.string().describe("Target IP, hostname, or CIDR range to scan"),
    scan_type: tool.schema
      .enum(["quick", "default", "version", "comprehensive"])
      .default("default")
      .describe("Scan type: quick (-F), default (-sV), version (-sV --version-intensity 5), comprehensive (-sV -sC -O)"),
    ports: tool.schema.string().optional().describe("Specific ports to scan (e.g., '22,80,443' or '1-1000')"),
    timing: tool.schema
      .enum(["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"])
      .default("normal")
      .describe("Scan timing template (T0-T5)"),
    output_format: tool.schema
      .enum(["text", "xml", "json"])
      .default("text")
      .describe("Output format for results"),
  },
  async execute(args, ctx) {
    const { $ } = await import("bun")

    // Check if nmap is installed
    try {
      await $`which nmap`.quiet()
    } catch {
      return "Error: nmap is not installed. Please install nmap first: brew install nmap (macOS) or apt install nmap (Linux)"
    }

    const timingMap: Record<string, string> = {
      paranoid: "-T0",
      sneaky: "-T1",
      polite: "-T2",
      normal: "-T3",
      aggressive: "-T4",
      insane: "-T5",
    }

    const scanTypeMap: Record<string, string[]> = {
      quick: ["-F"],
      default: ["-sV"],
      version: ["-sV", "--version-intensity", "5"],
      comprehensive: ["-sV", "-sC", "-O"],
    }

    const nmapArgs: string[] = [
      ...scanTypeMap[args.scan_type],
      timingMap[args.timing],
    ]

    if (args.ports) {
      nmapArgs.push("-p", args.ports)
    }

    if (args.output_format === "xml") {
      nmapArgs.push("-oX", "-")
    }

    nmapArgs.push(args.target)

    ctx.metadata({ title: `nmap ${args.scan_type} scan: ${args.target}` })

    try {
      const result = await $`nmap ${nmapArgs}`.text()

      if (args.output_format === "json") {
        // Parse nmap text output to JSON
        const lines = result.split("\n")
        const ports: Array<{ port: number; protocol: string; state: string; service: string; version?: string }> = []

        for (const line of lines) {
          const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?/)
          if (portMatch) {
            ports.push({
              port: parseInt(portMatch[1]),
              protocol: portMatch[2],
              state: portMatch[3],
              service: portMatch[4],
              version: portMatch[5]?.trim(),
            })
          }
        }

        return JSON.stringify({ target: args.target, ports, raw: result }, null, 2)
      }

      return result
    } catch (error) {
      return `Error running nmap: ${error instanceof Error ? error.message : String(error)}`
    }
  },
})
