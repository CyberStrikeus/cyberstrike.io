import path from "path"
import fs from "fs/promises"
import { ProjectManager } from "./manager.js"
import { createAPI } from "./api.js"

const PORT = parseInt(process.env.PORT || "3000")
const PUBLIC_DIR = process.env.PUBLIC_DIR || path.join(import.meta.dir, "../public")
const QA_AGENT_PATH = process.env.QA_AGENT_PATH || path.join(import.meta.dir, "../qa-agent")

console.log(`
  ╔══════════════════════════════════╗
  ║   QA Agent Orchestrator          ║
  ║   Multi-Repo Dashboard           ║
  ╚══════════════════════════════════╝
`)

const manager = new ProjectManager(QA_AGENT_PATH)
await manager.init()
console.log(`[orchestrator] Loaded ${manager.listProjects().length} projects`)

const handleAPI = createAPI(manager)

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html",
  ".js": "application/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
}

async function serveStatic(pathname: string): Promise<Response | null> {
  let filePath = path.join(PUBLIC_DIR, pathname)

  try {
    const stat = await fs.stat(filePath)
    if (stat.isDirectory()) {
      filePath = path.join(filePath, "index.html")
    }
  } catch {
    // SPA fallback: serve index.html for non-file routes
    filePath = path.join(PUBLIC_DIR, "index.html")
  }

  try {
    const file = Bun.file(filePath)
    if (await file.exists()) {
      const ext = path.extname(filePath)
      return new Response(file, {
        headers: { "Content-Type": MIME_TYPES[ext] || "application/octet-stream" },
      })
    }
  } catch {}

  return null
}

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url)

    // API routes
    if (url.pathname.startsWith("/api/")) {
      const apiResponse = handleAPI(req)
      if (apiResponse) return apiResponse
      return new Response("Not found", { status: 404 })
    }

    // Static files / SPA
    const staticResponse = await serveStatic(url.pathname)
    if (staticResponse) return staticResponse

    return new Response("Not found", { status: 404 })
  },
})

console.log(`[orchestrator] Dashboard: http://localhost:${server.port}`)
console.log(`[orchestrator] API: http://localhost:${server.port}/api/health`)
console.log("")

// Graceful shutdown
const shutdown = async () => {
  console.log("\n[orchestrator] Shutting down...")
  await manager.shutdown()
  server.stop()
  process.exit(0)
}
process.on("SIGINT", shutdown)
process.on("SIGTERM", shutdown)
