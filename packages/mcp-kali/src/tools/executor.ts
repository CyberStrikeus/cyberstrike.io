import { spawn } from "child_process"
import { ToolDefinition, ToolResult, buildCommand } from "./types.js"

/**
 * Execute a tool with given arguments
 */
export async function executeTool(
  tool: ToolDefinition,
  args: Record<string, unknown>
): Promise<ToolResult> {
  const command = buildCommand(tool, args)
  const startTime = Date.now()

  console.error(`[bolt] Executing: ${command}`)

  return new Promise((resolve) => {
    const timeout = (tool.timeout || 300) * 1000 // Convert to ms

    // Split command into parts
    const parts = parseCommand(command)
    const [cmd, ...cmdArgs] = parts

    // Determine if we need sudo
    const needsSudo = tool.requires_root && process.getuid?.() !== 0
    const finalCmd = needsSudo ? "sudo" : cmd
    const finalArgs = needsSudo ? [cmd, ...cmdArgs] : cmdArgs

    const proc = spawn(finalCmd, finalArgs, {
      shell: false,
      timeout,
      env: {
        ...process.env,
        // Ensure consistent output
        TERM: "dumb",
        LANG: "en_US.UTF-8",
      },
    })

    let stdout = ""
    let stderr = ""

    proc.stdout.on("data", (data) => {
      stdout += data.toString()
    })

    proc.stderr.on("data", (data) => {
      stderr += data.toString()
    })

    proc.on("error", (err) => {
      resolve({
        success: false,
        output: stdout,
        error: `Failed to execute command: ${err.message}`,
        duration: Date.now() - startTime,
      })
    })

    proc.on("close", (code) => {
      const duration = Date.now() - startTime

      // Combine output
      let output = stdout
      if (stderr && !stdout.includes(stderr)) {
        output += stderr ? `\n\nSTDERR:\n${stderr}` : ""
      }

      resolve({
        success: code === 0,
        output: output || "(no output)",
        exitCode: code ?? undefined,
        duration,
        error: code !== 0 ? `Command exited with code ${code}` : undefined,
      })
    })

    // Handle timeout
    setTimeout(() => {
      if (!proc.killed) {
        proc.kill("SIGTERM")
        setTimeout(() => {
          if (!proc.killed) proc.kill("SIGKILL")
        }, 5000)
      }
    }, timeout)
  })
}

/**
 * Parse command string into parts, respecting quotes
 */
function parseCommand(command: string): string[] {
  const parts: string[] = []
  let current = ""
  let inQuote = false
  let quoteChar = ""

  for (const char of command) {
    if ((char === '"' || char === "'") && !inQuote) {
      inQuote = true
      quoteChar = char
    } else if (char === quoteChar && inQuote) {
      inQuote = false
      quoteChar = ""
    } else if (char === " " && !inQuote) {
      if (current) {
        parts.push(current)
        current = ""
      }
    } else {
      current += char
    }
  }

  if (current) {
    parts.push(current)
  }

  return parts
}

/**
 * Validate that a tool exists on the system
 */
export async function validateToolExists(toolName: string): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn("which", [toolName])
    proc.on("close", (code) => {
      resolve(code === 0)
    })
    proc.on("error", () => {
      resolve(false)
    })
  })
}

/**
 * Get tool version
 */
export async function getToolVersion(toolName: string): Promise<string | null> {
  return new Promise((resolve) => {
    // Try common version flags
    const flags = ["--version", "-V", "-v", "version"]

    const tryNext = (index: number) => {
      if (index >= flags.length) {
        resolve(null)
        return
      }

      const proc = spawn(toolName, [flags[index]], { timeout: 5000 })
      let output = ""

      proc.stdout.on("data", (data) => {
        output += data.toString()
      })

      proc.stderr.on("data", (data) => {
        output += data.toString()
      })

      proc.on("close", (code) => {
        if (code === 0 && output.trim()) {
          // Extract first line as version
          const firstLine = output.trim().split("\n")[0]
          resolve(firstLine)
        } else {
          tryNext(index + 1)
        }
      })

      proc.on("error", () => {
        tryNext(index + 1)
      })
    }

    tryNext(0)
  })
}
