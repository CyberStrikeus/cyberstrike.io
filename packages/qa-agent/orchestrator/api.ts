import type { ProjectManager } from "./manager.js"
import { checkAuthStatus, startLogin, relayCallback, logout } from "./auth.js"

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  })
}

export function createAPI(manager: ProjectManager) {
  return function handleAPI(req: Request): Response | null {
    const url = new URL(req.url)
    const path = url.pathname
    const method = req.method

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      })
    }

    // ── Auth routes ──────────────────────────────────────

    if (path === "/api/auth/status" && method === "GET") {
      return (async () => {
        const status = await checkAuthStatus()
        return json(status)
      })() as any
    }

    if (path === "/api/auth/login" && method === "GET") {
      // SSE stream
      const stream = startLogin()
      return new Response(stream, {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
          "Access-Control-Allow-Origin": "*",
        },
      })
    }

    if (path === "/api/auth/callback-relay" && method === "POST") {
      return (async () => {
        try {
          const body = await req.json()
          const result = await relayCallback(body.callbackUrl)
          return json(result)
        } catch (err) {
          return json({ success: false, error: "Invalid request" }, 400)
        }
      })() as any
    }

    if (path === "/api/auth/logout" && method === "POST") {
      return (async () => {
        await logout()
        return json({ success: true })
      })() as any
    }

    // ── Health ────────────────────────────────────────────

    if (path === "/api/health" && method === "GET") {
      return (async () => {
        const auth = await checkAuthStatus()
        return json({ status: "ok", authenticated: auth.authenticated })
      })() as any
    }

    // ── Project routes ───────────────────────────────────

    if (path === "/api/projects" && method === "GET") {
      return json(manager.listProjects())
    }

    if (path === "/api/projects" && method === "POST") {
      return (async () => {
        try {
          const body = await req.json()
          const project = await manager.addProject(body)
          return json(project, 201)
        } catch (err) {
          return json({ error: err instanceof Error ? err.message : "Failed to add project" }, 400)
        }
      })() as any
    }

    // Project-specific routes
    const projectMatch = path.match(/^\/api\/projects\/([^/]+)$/)
    if (projectMatch) {
      const id = projectMatch[1]

      if (method === "GET") {
        const project = manager.getProject(id)
        return project ? json(project) : json({ error: "Not found" }, 404)
      }

      if (method === "DELETE") {
        return (async () => {
          await manager.removeProject(id)
          return json({ success: true })
        })() as any
      }
    }

    // Project actions
    const actionMatch = path.match(/^\/api\/projects\/([^/]+)\/(start|stop|reports|fixes|logs)$/)
    if (actionMatch) {
      const [, id, action] = actionMatch

      if (action === "start" && method === "POST") {
        return (async () => {
          try {
            await manager.startAgents(id)
            return json({ success: true })
          } catch (err) {
            return json({ error: err instanceof Error ? err.message : "Failed" }, 400)
          }
        })() as any
      }

      if (action === "stop" && method === "POST") {
        return (async () => {
          await manager.stopAgents(id)
          return json({ success: true })
        })() as any
      }

      if (action === "reports" && method === "GET") {
        return (async () => {
          const reports = await manager.getReports(id)
          return json(reports)
        })() as any
      }

      if (action === "fixes" && method === "GET") {
        return (async () => {
          const fixes = await manager.getFixes(id)
          return json(fixes)
        })() as any
      }

      if (action === "logs" && method === "GET") {
        return json(manager.getLogs(id))
      }
    }

    return null
  }
}
