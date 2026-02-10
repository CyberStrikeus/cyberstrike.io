import { useEffect, useState, useRef } from "react"
import { useNavigate } from "react-router-dom"
import { api } from "../api"

interface LoginProps {
  onAuth: () => void
}

type Phase = "idle" | "connecting" | "waiting-auth" | "paste-callback" | "relaying" | "success" | "error"

interface LogEntry {
  text: string
  source: string
}

export function Login({ onAuth }: LoginProps) {
  const navigate = useNavigate()
  const [phase, setPhase] = useState<Phase>("idle")
  const [authenticated, setAuthenticated] = useState(false)
  const [oauthUrl, setOauthUrl] = useState("")
  const [callbackPort, setCallbackPort] = useState<number | null>(null)
  const [callbackInput, setCallbackInput] = useState("")
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [error, setError] = useState("")
  const logsEndRef = useRef<HTMLDivElement>(null)
  const eventSourceRef = useRef<EventSource | null>(null)

  useEffect(() => {
    api.getAuthStatus().then((s) => {
      setAuthenticated(s.authenticated)
      if (s.authenticated) setPhase("success")
    })
  }, [])

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [logs])

  const addLog = (entry: LogEntry) => {
    setLogs((prev) => [...prev, entry])
  }

  const startLogin = () => {
    setPhase("connecting")
    setLogs([])
    setOauthUrl("")
    setCallbackPort(null)
    setError("")

    const es = new EventSource("/api/auth/login")
    eventSourceRef.current = es

    es.addEventListener("output", (e) => {
      const data = JSON.parse(e.data)
      addLog({ text: data.text, source: data.source })
    })

    es.addEventListener("url", (e) => {
      const data = JSON.parse(e.data)
      setOauthUrl(data.url)
      if (data.callbackPort) setCallbackPort(data.callbackPort)
      setPhase("waiting-auth")
      addLog({ text: `OAuth URL detected`, source: "system" })
    })

    es.addEventListener("done", (e) => {
      const data = JSON.parse(e.data)
      if (data.success) {
        setPhase("success")
        setAuthenticated(true)
        onAuth()
        addLog({ text: "Authentication successful!", source: "system" })
      }
      es.close()
    })

    es.addEventListener("error", (e) => {
      // SSE error can be from event or connection
      try {
        const data = JSON.parse((e as MessageEvent).data)
        setError(data.message || "Login failed")
      } catch {
        // Connection error - might mean login completed
        api.getAuthStatus().then((s) => {
          if (s.authenticated) {
            setPhase("success")
            setAuthenticated(true)
            onAuth()
          } else {
            setPhase("paste-callback")
          }
        })
      }
      es.close()
    })

    es.onerror = () => {
      // After SSE closes, check if we need to paste callback
      setTimeout(() => {
        if (oauthUrl && phase !== "success") {
          setPhase("paste-callback")
        }
      }, 2000)
    }
  }

  const handleRelay = async () => {
    if (!callbackInput.trim()) return
    setPhase("relaying")
    setError("")

    try {
      const result = await api.relayCallback(callbackInput.trim())
      if (result.success) {
        setPhase("success")
        setAuthenticated(true)
        onAuth()
        addLog({ text: "Authentication successful via callback relay!", source: "system" })
      } else {
        setError(result.error || "Callback relay failed")
        setPhase("paste-callback")
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Relay failed")
      setPhase("paste-callback")
    }
  }

  const handleLogout = async () => {
    await api.logout()
    setAuthenticated(false)
    setPhase("idle")
    setOauthUrl("")
    setLogs([])
  }

  const goToDashboard = () => {
    navigate("/")
  }

  return (
    <div className="min-h-screen bg-gray-950 text-white flex items-center justify-center p-6">
      <div className="w-full max-w-xl">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-emerald-400 mb-2">QA Agent</h1>
          <p className="text-gray-500">Claude CLI Authentication</p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          {/* Already authenticated */}
          {phase === "success" && (
            <div className="text-center">
              <div className="w-12 h-12 bg-emerald-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-emerald-400 text-xl">&#10003;</span>
              </div>
              <h2 className="text-lg font-semibold mb-2">Authenticated</h2>
              <p className="text-gray-500 text-sm mb-6">Claude CLI is connected with your Pro/Max subscription.</p>
              <div className="flex gap-3 justify-center">
                <button
                  onClick={goToDashboard}
                  className="bg-emerald-600 hover:bg-emerald-500 px-6 py-2 rounded text-sm font-medium"
                >
                  Go to Dashboard
                </button>
                <button
                  onClick={handleLogout}
                  className="bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded text-sm text-gray-400"
                >
                  Logout
                </button>
              </div>
            </div>
          )}

          {/* Idle - not started */}
          {phase === "idle" && !authenticated && (
            <div className="text-center">
              <h2 className="text-lg font-semibold mb-2">Connect Claude CLI</h2>
              <p className="text-gray-500 text-sm mb-6">
                Authenticate with your Anthropic account to use Claude Pro/Max subscription.
              </p>
              <button
                onClick={startLogin}
                className="bg-emerald-600 hover:bg-emerald-500 px-6 py-2 rounded text-sm font-medium"
              >
                Login to Claude
              </button>
            </div>
          )}

          {/* Connecting */}
          {phase === "connecting" && (
            <div className="text-center">
              <div className="animate-spin w-8 h-8 border-2 border-emerald-400 border-t-transparent rounded-full mx-auto mb-4" />
              <p className="text-gray-400 text-sm">Starting Claude login process...</p>
            </div>
          )}

          {/* Waiting for auth - show URL */}
          {phase === "waiting-auth" && oauthUrl && (
            <div>
              <h2 className="text-lg font-semibold mb-3">Step 1: Authenticate</h2>
              <p className="text-gray-400 text-sm mb-3">
                Click the link below to login with your Anthropic account:
              </p>
              <a
                href={oauthUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="block bg-gray-800 border border-gray-700 rounded p-3 text-emerald-400 text-sm break-all hover:bg-gray-700 transition-colors"
              >
                {oauthUrl.length > 100 ? oauthUrl.slice(0, 100) + "..." : oauthUrl}
              </a>
              <p className="text-gray-500 text-xs mt-2 mb-4">Opens in a new tab</p>

              <h2 className="text-lg font-semibold mb-3">Step 2: Complete Authentication</h2>
              <p className="text-gray-400 text-sm mb-3">
                After authenticating, the page will try to redirect to a localhost URL that won't load.
                Copy the full URL from your browser's address bar and paste it below:
              </p>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={callbackInput}
                  onChange={(e) => setCallbackInput(e.target.value)}
                  placeholder="http://localhost:xxxxx/oauth/callback?code=..."
                  className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
                />
                <button
                  onClick={handleRelay}
                  disabled={!callbackInput.trim()}
                  className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 px-4 py-2 rounded text-sm font-medium whitespace-nowrap"
                >
                  Complete
                </button>
              </div>
            </div>
          )}

          {/* Paste callback fallback */}
          {phase === "paste-callback" && (
            <div>
              <h2 className="text-lg font-semibold mb-3">Paste Callback URL</h2>
              {oauthUrl && (
                <>
                  <p className="text-gray-400 text-sm mb-2">If you haven't yet, open this link first:</p>
                  <a
                    href={oauthUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block bg-gray-800 border border-gray-700 rounded p-2 text-emerald-400 text-xs break-all hover:bg-gray-700 mb-4"
                  >
                    {oauthUrl.length > 80 ? oauthUrl.slice(0, 80) + "..." : oauthUrl}
                  </a>
                </>
              )}
              <p className="text-gray-400 text-sm mb-3">
                After authenticating, copy the redirect URL from your browser and paste it here:
              </p>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={callbackInput}
                  onChange={(e) => setCallbackInput(e.target.value)}
                  placeholder="http://localhost:xxxxx/oauth/callback?code=..."
                  className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
                />
                <button
                  onClick={handleRelay}
                  disabled={!callbackInput.trim()}
                  className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 px-4 py-2 rounded text-sm font-medium whitespace-nowrap"
                >
                  Complete
                </button>
              </div>
            </div>
          )}

          {/* Relaying */}
          {phase === "relaying" && (
            <div className="text-center">
              <div className="animate-spin w-8 h-8 border-2 border-emerald-400 border-t-transparent rounded-full mx-auto mb-4" />
              <p className="text-gray-400 text-sm">Completing authentication...</p>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="mt-4 bg-red-500/10 border border-red-500/30 rounded p-3">
              <p className="text-red-400 text-sm">{error}</p>
              <button
                onClick={() => { setError(""); setPhase("idle") }}
                className="text-red-400/70 text-xs mt-2 hover:text-red-300"
              >
                Try again
              </button>
            </div>
          )}

          {/* Log output */}
          {logs.length > 0 && (
            <div className="mt-4 bg-gray-950 border border-gray-800 rounded p-3 font-mono text-xs max-h-40 overflow-y-auto">
              {logs.map((log, i) => (
                <div key={i} className="text-gray-500 py-0.5">
                  <span className="text-gray-600">[{log.source}]</span> {log.text}
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
