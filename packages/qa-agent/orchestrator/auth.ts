import fs from "fs/promises"
import path from "path"

const HOME = process.env.HOME || "/data"
const CREDENTIALS_PATH = path.join(HOME, ".claude", ".credentials.json")

export interface AuthStatus {
  authenticated: boolean
  expiresAt?: string
}

export async function checkAuthStatus(): Promise<AuthStatus> {
  // First try: check credentials file
  try {
    const raw = await fs.readFile(CREDENTIALS_PATH, "utf-8")
    const creds = JSON.parse(raw)
    const oauth = creds.claudeAiOauth
    if (oauth?.accessToken) {
      return {
        authenticated: true,
        expiresAt: oauth.expiresAt ? new Date(oauth.expiresAt).toISOString() : undefined,
      }
    }
  } catch {}

  // Second try: run claude auth status
  try {
    const proc = Bun.spawn(["claude", "auth", "status"], {
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env, HOME },
    })
    const stdout = await new Response(proc.stdout).text()
    const exitCode = await proc.exited
    if (exitCode === 0 && !stdout.toLowerCase().includes("not logged in")) {
      return { authenticated: true }
    }
  } catch {}

  return { authenticated: false }
}

interface LoginSession {
  process: ReturnType<typeof Bun.spawn>
  callbackPort: number | null
  stream: ReadableStream<Uint8Array>
}

let activeLogin: LoginSession | null = null

export function startLogin(): ReadableStream<Uint8Array> {
  // Kill any existing login process
  if (activeLogin?.process) {
    try {
      activeLogin.process.kill()
    } catch {}
    activeLogin = null
  }

  let callbackPort: number | null = null
  let controller: ReadableStreamDefaultController<Uint8Array>

  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      controller = c
    },
    cancel() {
      if (activeLogin?.process) {
        try {
          activeLogin.process.kill()
        } catch {}
        activeLogin = null
      }
    },
  })

  const encoder = new TextEncoder()
  const sendEvent = (event: string, data: Record<string, unknown>) => {
    try {
      controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`))
    } catch {}
  }

  // Spawn claude auth login
  const proc = Bun.spawn(["claude", "auth", "login"], {
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, HOME, BROWSER: "echo" }, // BROWSER=echo prevents opening browser, prints URL
  })

  activeLogin = { process: proc, callbackPort: null, stream }

  const readStream = async (readable: ReadableStream<Uint8Array> | null, label: string) => {
    if (!readable) return
    const reader = readable.getReader()
    const decoder = new TextDecoder()
    let buffer = ""

    try {
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })

        const lines = buffer.split("\n")
        buffer = lines.pop() || ""

        for (const line of lines) {
          if (!line.trim()) continue
          sendEvent("output", { text: line, source: label })

          // Detect OAuth URL
          const urlMatch = line.match(/https?:\/\/[^\s"']+/)
          if (urlMatch) {
            const url = urlMatch[0]

            // Extract callback port from redirect_uri in the URL
            const redirectMatch = url.match(/redirect_uri=http%3A%2F%2Flocalhost%3A(\d+)/)
              || url.match(/localhost:(\d+)/)
            if (redirectMatch) {
              callbackPort = parseInt(redirectMatch[1])
              if (activeLogin) activeLogin.callbackPort = callbackPort
            }

            sendEvent("url", { url, callbackPort })
          }
        }
      }
      // Flush remaining buffer
      if (buffer.trim()) {
        sendEvent("output", { text: buffer, source: label })
        const urlMatch = buffer.match(/https?:\/\/[^\s"']+/)
        if (urlMatch) {
          const url = urlMatch[0]
          const redirectMatch = url.match(/redirect_uri=http%3A%2F%2Flocalhost%3A(\d+)/)
            || url.match(/localhost:(\d+)/)
          if (redirectMatch) {
            callbackPort = parseInt(redirectMatch[1])
            if (activeLogin) activeLogin.callbackPort = callbackPort
          }
          sendEvent("url", { url, callbackPort })
        }
      }
    } catch {}
  }

  // Read both streams
  Promise.all([
    readStream(proc.stdout as ReadableStream<Uint8Array>, "stdout"),
    readStream(proc.stderr as ReadableStream<Uint8Array>, "stderr"),
  ]).then(async () => {
    const exitCode = await proc.exited
    if (exitCode === 0) {
      sendEvent("done", { success: true })
    } else {
      sendEvent("error", { message: `Login process exited with code ${exitCode}` })
    }
    try {
      controller.close()
    } catch {}
    activeLogin = null
  })

  return stream
}

export async function relayCallback(callbackUrl: string): Promise<{ success: boolean; error?: string }> {
  try {
    // Extract the actual callback URL parts
    let targetUrl: string

    if (callbackUrl.startsWith("http://localhost")) {
      // Already a localhost URL, use as-is
      targetUrl = callbackUrl
    } else {
      // User pasted a URL that failed - extract query params and build localhost URL
      const url = new URL(callbackUrl)
      const port = activeLogin?.callbackPort
      if (!port) {
        return { success: false, error: "No active login session. Start login first." }
      }
      targetUrl = `http://localhost:${port}${url.pathname}${url.search}`
    }

    // Forward the callback to Claude's internal server
    const response = await fetch(targetUrl, {
      redirect: "follow",
    })

    if (response.ok) {
      // Wait a moment for credentials to be written
      await new Promise((r) => setTimeout(r, 2000))
      const status = await checkAuthStatus()
      return { success: status.authenticated }
    }

    return { success: false, error: `Callback returned ${response.status}` }
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : String(err) }
  }
}

export async function logout(): Promise<void> {
  try {
    const proc = Bun.spawn(["claude", "auth", "logout"], {
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env, HOME },
    })
    await proc.exited
  } catch {}

  // Also try to remove credentials file
  try {
    await fs.unlink(CREDENTIALS_PATH)
  } catch {}
}
