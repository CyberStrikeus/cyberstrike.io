#!/usr/bin/env node

import http from "node:http"
import crypto from "node:crypto"
import fs from "node:fs/promises"
import path from "path"
import { fileURLToPath } from "url"
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js"
import { loadAllTools } from "./tools/loader.js"
import { DynamicRegistry } from "./tools/registry.js"
import { createMcpServer } from "./server.js"
import { KnockDaemon } from "./knock.js"
import type { Server } from "@modelcontextprotocol/sdk/server/index.js"
import type { ToolDefinition } from "./tools/types.js"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const DEFINITIONS_DIR = path.join(__dirname, "..", "src", "definitions")

// --- Configuration ---

const DEFAULT_PORT = 3001
const DEFAULT_HOST = "0.0.0.0"
const SESSION_TIMEOUT_MS = 30 * 60 * 1000 // 30 minutes
const PAIRING_CODE_TTL_MS = 5 * 60 * 1000 // 5 minutes
const NONCE_TTL_MS = 30 * 1000 // 30 second window for replay protection
const TIMESTAMP_DRIFT_MS = 30 * 1000 // 30 second clock drift tolerance
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "..", "data")
const DEFAULT_KNOCK_TTL_MS = 10 * 60 * 1000 // 10 minutes

// --- Parse CLI arguments ---

const cliArgs = process.argv.slice(2)
for (let i = 0; i < cliArgs.length; i++) {
  if (cliArgs[i] === "--port" && cliArgs[i + 1]) {
    process.env.PORT = cliArgs[++i]
  } else if (cliArgs[i] === "--host" && cliArgs[i + 1]) {
    process.env.HOST = cliArgs[++i]
  } else if (cliArgs[i] === "--admin-token" && cliArgs[i + 1]) {
    process.env.MCP_ADMIN_TOKEN = cliArgs[++i]
  } else if (cliArgs[i] === "--data-dir" && cliArgs[i + 1]) {
    process.env.DATA_DIR = cliArgs[++i]
  } else if (cliArgs[i] === "--knock") {
    process.env.KNOCK_ENABLED = "true"
  }
}

const effectivePort = parseInt(process.env.PORT || String(DEFAULT_PORT), 10)
const effectiveHost = process.env.HOST || DEFAULT_HOST
const adminToken = process.env.MCP_ADMIN_TOKEN || ""

/**
 * Constant-time string comparison to prevent timing attacks
 */
function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  try {
    const bufA = Buffer.from(a)
    const bufB = Buffer.from(b)
    return crypto.timingSafeEqual(bufA, bufB)
  } catch {
    return false
  }
}
const dataDir = process.env.DATA_DIR || DATA_DIR
const knockEnabled = process.env.KNOCK_ENABLED === "true"

// =====================================================================
// Ed25519 Key Management
// =====================================================================

interface ServerKeys {
  publicKey: crypto.KeyObject
  privateKey: crypto.KeyObject
  publicKeyPem: string
}

interface AuthorizedClient {
  clientId: string // fingerprint of public key
  publicKeyPem: string
  name: string
  pairedAt: string
}

let serverKeys: ServerKeys
const authorizedClients = new Map<string, AuthorizedClient>()

const SERVER_KEYS_PATH = () => path.join(dataDir, "server-keys.json")
const CLIENTS_PATH = () => path.join(dataDir, "authorized-clients.json")

/**
 * Compute a short fingerprint for a public key PEM.
 */
function fingerprint(publicKeyPem: string): string {
  return crypto.createHash("sha256").update(publicKeyPem).digest("hex").slice(0, 16)
}

/**
 * Generate or load the server's Ed25519 key pair.
 */
async function initServerKeys(): Promise<void> {
  await fs.mkdir(dataDir, { recursive: true })

  try {
    const raw = await fs.readFile(SERVER_KEYS_PATH(), "utf-8")
    const stored = JSON.parse(raw) as { publicKey: string; privateKey: string }
    serverKeys = {
      publicKey: crypto.createPublicKey(stored.publicKey),
      privateKey: crypto.createPrivateKey(stored.privateKey),
      publicKeyPem: stored.publicKey,
    }
    console.error("[auth] Loaded existing server key pair")
  } catch {
    // Generate new key pair
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519")
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string

    await fs.writeFile(
      SERVER_KEYS_PATH(),
      JSON.stringify({ publicKey: publicKeyPem, privateKey: privateKeyPem }),
      { mode: 0o600 }
    )

    serverKeys = { publicKey, privateKey, publicKeyPem }
    console.error("[auth] Generated new server key pair")
  }

  console.error(`[auth] Server public key fingerprint: ${fingerprint(serverKeys.publicKeyPem)}`)
}

/**
 * Load authorized clients from disk.
 */
async function loadAuthorizedClients(): Promise<void> {
  try {
    const raw = await fs.readFile(CLIENTS_PATH(), "utf-8")
    const clients = JSON.parse(raw) as AuthorizedClient[]
    for (const client of clients) {
      authorizedClients.set(client.clientId, client)
    }
    console.error(`[auth] Loaded ${authorizedClients.size} authorized client(s)`)
  } catch {
    console.error("[auth] No authorized clients found (fresh install)")
  }
}

/**
 * Persist authorized clients to disk.
 */
async function saveAuthorizedClients(): Promise<void> {
  const clients = Array.from(authorizedClients.values())
  await fs.writeFile(CLIENTS_PATH(), JSON.stringify(clients, null, 2), { mode: 0o600 })
}

// =====================================================================
// Pairing Code Management
// =====================================================================

interface PairingCode {
  code: string
  createdAt: number
  used: boolean
}

const activePairingCodes = new Map<string, PairingCode>()

/**
 * Generate a cryptographically random pairing code (format: XXX-XXX).
 */
function generatePairingCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no ambiguous chars (0/O, 1/I)
  const limit = 256 - (256 % chars.length)
  let code = ""
  while (code.replace("-", "").length < 6) {
    const bytes = crypto.randomBytes(6 - code.replace("-", "").length)
    for (const byte of bytes) {
      if (byte < limit) {
        code += chars[byte % chars.length]
        if (code.replace("-", "").length === 3 && !code.includes("-")) code += "-"
        if (code.replace("-", "").length === 6) break
      }
    }
  }
  return code
}

/**
 * Clean up expired pairing codes.
 */
function cleanupPairingCodes(): void {
  const now = Date.now()
  for (const [code, entry] of activePairingCodes.entries()) {
    if (entry.used || now - entry.createdAt > PAIRING_CODE_TTL_MS) {
      activePairingCodes.delete(code)
    }
  }
}

// =====================================================================
// Replay Protection (nonce + timestamp)
// =====================================================================

const usedNonces = new Map<string, number>() // nonce → timestamp

function cleanupNonces(): void {
  const cutoff = Date.now() - NONCE_TTL_MS * 2
  for (const [nonce, ts] of usedNonces.entries()) {
    if (ts < cutoff) usedNonces.delete(nonce)
  }
}

// =====================================================================
// Ed25519 Signature Verification
// =====================================================================

interface AuthResult {
  authenticated: boolean
  clientId?: string
  error?: string
}

/**
 * Verify an Ed25519-signed request.
 *
 * Required headers:
 *   X-Client-Id:  fingerprint of client public key
 *   X-Timestamp:  ISO 8601 timestamp
 *   X-Nonce:      unique random value
 *   X-Signature:  base64-encoded Ed25519 signature of "{timestamp}\n{nonce}\n{method}\n{path}\n{bodyHash}"
 */
function verifySignature(req: http.IncomingMessage, bodyStr: string): AuthResult {
  const clientId = req.headers["x-client-id"] as string | undefined
  const timestamp = req.headers["x-timestamp"] as string | undefined
  const nonce = req.headers["x-nonce"] as string | undefined
  const signature = req.headers["x-signature"] as string | undefined

  if (!clientId || !timestamp || !nonce || !signature) {
    return { authenticated: false, error: "Missing auth headers (X-Client-Id, X-Timestamp, X-Nonce, X-Signature)" }
  }

  // 1. Check client is authorized
  const client = authorizedClients.get(clientId)
  if (!client) {
    return { authenticated: false, error: "Unknown client" }
  }

  // 2. Check timestamp drift
  const ts = new Date(timestamp).getTime()
  if (isNaN(ts) || Math.abs(Date.now() - ts) > TIMESTAMP_DRIFT_MS) {
    return { authenticated: false, error: "Timestamp out of range" }
  }

  // 3. Check nonce hasn't been used
  if (usedNonces.has(nonce)) {
    return { authenticated: false, error: "Nonce already used (replay detected)" }
  }

  // 4. Verify signature
  const method = (req.method || "GET").toUpperCase()
  const urlPath = req.url || "/"
  const bodyHash = crypto.createHash("sha256").update(bodyStr).digest("hex")
  const message = `${timestamp}\n${nonce}\n${method}\n${urlPath}\n${bodyHash}`

  try {
    const publicKey = crypto.createPublicKey(client.publicKeyPem)
    const valid = crypto.verify(null, Buffer.from(message), publicKey, Buffer.from(signature, "base64"))
    if (!valid) {
      return { authenticated: false, error: "Invalid signature" }
    }
  } catch {
    return { authenticated: false, error: "Signature verification failed" }
  }

  // 5. Record nonce
  usedNonces.set(nonce, Date.now())

  return { authenticated: true, clientId }
}

/**
 * Authenticate /mcp requests.
 * Uses Ed25519 signatures if clients are registered, falls back to admin token if no clients exist.
 */
function authenticateMcpRequest(req: http.IncomingMessage, bodyStr: string): AuthResult {
  // If no clients are registered and no admin token, auth is disabled (local dev)
  if (authorizedClients.size === 0 && !adminToken) {
    return { authenticated: true, clientId: "anonymous" }
  }

  // Try Ed25519 signature auth first
  if (req.headers["x-client-id"]) {
    return verifySignature(req, bodyStr)
  }

  // Fallback: admin token can also access /mcp (for backwards compat / debugging)
  if (adminToken) {
    const authHeader = req.headers.authorization
    if (authHeader) {
      const [scheme, token] = authHeader.split(" ")
      if (scheme === "Bearer" && token && secureCompare(token, adminToken)) {
        return { authenticated: true, clientId: "admin" }
      }
    }
  }

  return { authenticated: false, error: "No valid authentication provided" }
}

/**
 * Authenticate admin-only endpoints (/pair).
 * Requires MCP_ADMIN_TOKEN.
 */
function authenticateAdmin(req: http.IncomingMessage): boolean {
  if (!adminToken) return false // Admin endpoints require a token

  const authHeader = req.headers.authorization
  if (!authHeader) return false

  const [scheme, token] = authHeader.split(" ")
  return scheme === "Bearer" && !!token && secureCompare(token, adminToken)
}

// =====================================================================
// MCP Session Management
// =====================================================================

interface Session {
  server: Server
  transport: StreamableHTTPServerTransport
  registry: DynamicRegistry
  lastActivity: number
}

const sessions = new Map<string, Session>()
let sharedToolDefs: Map<string, ToolDefinition>
let knockDaemon: KnockDaemon | null = null

function createSession(): Session {
  const registry = new DynamicRegistry()
  registry.initialize(sharedToolDefs)

  const server = createMcpServer(registry)

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => crypto.randomUUID(),
    onsessioninitialized: (sessionId: string) => {
      console.error(`[bolt] Session initialized: ${sessionId}`)
      sessions.set(sessionId, session)
    },
  })

  const session: Session = {
    server,
    transport,
    registry,
    lastActivity: Date.now(),
  }

  server.connect(transport).catch((err) => {
    console.error("[bolt] Failed to connect server to transport:", err)
  })

  return session
}

function getSession(req: http.IncomingMessage): Session | undefined {
  const sessionId = req.headers["mcp-session-id"] as string | undefined
  if (!sessionId) return undefined
  const session = sessions.get(sessionId)
  if (session) session.lastActivity = Date.now()
  return session
}

function cleanupSessions(): void {
  const now = Date.now()
  for (const [id, session] of sessions.entries()) {
    if (now - session.lastActivity > SESSION_TIMEOUT_MS) {
      console.error(`[bolt] Cleaning up expired session: ${id}`)
      session.transport.close().catch(() => {})
      sessions.delete(id)
    }
  }
}

// =====================================================================
// CORS & Helpers
// =====================================================================

function setCorsHeaders(res: http.ServerResponse): void {
  res.setHeader("Access-Control-Allow-Origin", "*")
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, Mcp-Session-Id, Mcp-Protocol-Version, X-Client-Id, X-Timestamp, X-Nonce, X-Signature"
  )
  res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id")
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = ""
    req.on("data", (chunk: Buffer) => { data += chunk })
    req.on("end", () => resolve(data))
    req.on("error", reject)
  })
}

function jsonResponse(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" })
  res.end(JSON.stringify(body))
}

// =====================================================================
// Request Router
// =====================================================================

async function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`)
  const pathname = url.pathname

  setCorsHeaders(res)

  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204)
    res.end()
    return
  }

  // =================================================================
  // ENDPOINTS NOT PROTECTED BY KNOCK (always accessible)
  // These are needed for initial pairing before client can knock.
  // Protected by their own auth mechanisms (admin token, pairing code).
  // =================================================================

  // --- Health check (no auth, no knock) ---
  // Allows clients to verify this is a Bolt server before pairing
  if (pathname === "/health" && req.method === "GET") {
    jsonResponse(res, 200, {
      status: "ok",
      identity: "bolt",
      version: "0.2.0",
      transport: "streamable-http",
      auth: "ed25519",
      knock: knockDaemon?.getStatus() ?? { active: false },
      activeSessions: sessions.size,
      authorizedClients: authorizedClients.size,
      toolCount: sharedToolDefs?.size ?? 0,
      uptime: process.uptime(),
      serverFingerprint: fingerprint(serverKeys.publicKeyPem),
    })
    return
  }

  // --- Pairing: Generate code (admin token required, no knock) ---
  // Admin generates a one-time code for new client to pair
  if (pathname === "/pair" && req.method === "POST") {
    if (!authenticateAdmin(req)) {
      jsonResponse(res, 401, { error: "Unauthorized", message: "Admin token required (MCP_ADMIN_TOKEN)" })
      return
    }

    cleanupPairingCodes()

    const code = generatePairingCode()
    activePairingCodes.set(code, {
      code,
      createdAt: Date.now(),
      used: false,
    })

    console.error(`[auth] Pairing code generated: ${code}`)

    jsonResponse(res, 200, {
      code,
      expiresIn: PAIRING_CODE_TTL_MS / 1000,
      serverFingerprint: fingerprint(serverKeys.publicKeyPem),
    })
    return
  }

  // --- Pairing: Exchange keys (pairing code required, no knock) ---
  // New client exchanges public keys using the one-time pairing code.
  // After this, client is authorized and can send knock packets.
  if (pathname === "/pair/exchange" && req.method === "POST") {
    const bodyStr = await readBody(req)
    let body: { code?: string; clientPublicKey?: string; clientName?: string }
    try {
      body = JSON.parse(bodyStr)
    } catch {
      jsonResponse(res, 400, { error: "Invalid JSON" })
      return
    }

    const { code, clientPublicKey, clientName } = body

    if (!code || !clientPublicKey) {
      jsonResponse(res, 400, { error: "Missing required fields: code, clientPublicKey" })
      return
    }

    // Validate pairing code
    cleanupPairingCodes()
    const pairingEntry = activePairingCodes.get(code)

    if (!pairingEntry) {
      jsonResponse(res, 403, { error: "Invalid or expired pairing code" })
      return
    }

    if (pairingEntry.used) {
      jsonResponse(res, 403, { error: "Pairing code already used" })
      return
    }

    // Validate the client public key is a valid Ed25519 key
    try {
      const keyObj = crypto.createPublicKey(clientPublicKey)
      if (keyObj.asymmetricKeyType !== "ed25519") {
        jsonResponse(res, 400, { error: "Key must be Ed25519" })
        return
      }
    } catch {
      jsonResponse(res, 400, { error: "Invalid public key format (expected PEM-encoded Ed25519)" })
      return
    }

    // Mark code as used
    pairingEntry.used = true
    activePairingCodes.delete(code)

    // Register client
    const clientId = fingerprint(clientPublicKey)
    const client: AuthorizedClient = {
      clientId,
      publicKeyPem: clientPublicKey,
      name: clientName || `client-${clientId.slice(0, 8)}`,
      pairedAt: new Date().toISOString(),
    }

    authorizedClients.set(clientId, client)
    await saveAuthorizedClients()

    console.error(`[auth] Client paired: ${client.name} (${clientId})`)

    // Enable port knocking if this is the first client
    if (knockDaemon && authorizedClients.size === 1) {
      await knockDaemon.enable()
    }

    // Include bolt key in response for future knock packets
    const responseData: Record<string, unknown> = {
      clientId,
      serverPublicKey: serverKeys.publicKeyPem,
      serverFingerprint: fingerprint(serverKeys.publicKeyPem),
      name: client.name,
    }

    if (knockDaemon) {
      responseData.boltKey = knockDaemon.getBoltKey()
    }

    jsonResponse(res, 200, responseData)
    return
  }

  // --- List paired clients (admin token required, no knock) ---
  if (pathname === "/pair/clients" && req.method === "GET") {
    if (!authenticateAdmin(req)) {
      jsonResponse(res, 401, { error: "Unauthorized", message: "Admin token required" })
      return
    }

    const clients = Array.from(authorizedClients.values()).map((c) => ({
      clientId: c.clientId,
      name: c.name,
      pairedAt: c.pairedAt,
    }))

    jsonResponse(res, 200, { clients })
    return
  }

  // --- Revoke a client (admin token required, no knock) ---
  if (pathname.startsWith("/pair/clients/") && req.method === "DELETE") {
    if (!authenticateAdmin(req)) {
      jsonResponse(res, 401, { error: "Unauthorized", message: "Admin token required" })
      return
    }

    const clientId = pathname.split("/pair/clients/")[1]
    if (authorizedClients.has(clientId)) {
      const client = authorizedClients.get(clientId)!
      authorizedClients.delete(clientId)
      await saveAuthorizedClients()
      console.error(`[auth] Client revoked: ${client.name} (${clientId})`)

      // Disable port knocking if this was the last client
      if (knockDaemon && authorizedClients.size === 0) {
        await knockDaemon.disable()
      }

      jsonResponse(res, 200, { revoked: clientId })
    } else {
      jsonResponse(res, 404, { error: "Client not found" })
    }
    return
  }

  // =================================================================
  // ENDPOINTS PROTECTED BY KNOCK (requires SPA packet first)
  // When knock is enabled, these are blocked by iptables until
  // client sends a valid knock packet from their IP.
  // =================================================================

  // --- MCP endpoint (knock + Ed25519 signature required) ---
  // This is where tool execution happens. Protected by:
  //   1. Knock (iptables blocks unless client knocked)
  //   2. Ed25519 signed requests (every request must be signed)
  if (pathname === "/mcp") {
    // Read body for signature verification (POST only)
    const bodyStr = req.method === "POST" ? await readBody(req) : ""

    // Authenticate (Ed25519 signature verification)
    const auth = authenticateMcpRequest(req, bodyStr)
    if (!auth.authenticated) {
      jsonResponse(res, 401, { error: "Unauthorized", message: auth.error })
      return
    }

    if (req.method === "POST") {
      let parsedBody: unknown
      try {
        parsedBody = JSON.parse(bodyStr)
      } catch {
        jsonResponse(res, 400, { error: "Invalid JSON" })
        return
      }

      const existingSession = getSession(req)
      if (existingSession) {
        await existingSession.transport.handleRequest(req, res, parsedBody)
        return
      }

      const isInit = Array.isArray(parsedBody)
        ? (parsedBody as Array<{ method?: string }>).some((m) => m.method === "initialize")
        : (parsedBody as { method?: string }).method === "initialize"

      if (isInit) {
        const session = createSession()
        await session.transport.handleRequest(req, res, parsedBody)
        return
      }

      jsonResponse(res, 400, {
        error: "Bad Request",
        message: "Missing Mcp-Session-Id header. Send an initialize request first.",
      })
      return
    }

    if (req.method === "GET") {
      const session = getSession(req)
      if (!session) {
        jsonResponse(res, 400, { error: "Bad Request", message: "Missing or invalid session ID" })
        return
      }
      await session.transport.handleRequest(req, res)
      return
    }

    if (req.method === "DELETE") {
      const sessionId = req.headers["mcp-session-id"] as string | undefined
      const session = sessionId ? sessions.get(sessionId) : undefined

      if (session) {
        await session.transport.handleRequest(req, res)
        sessions.delete(sessionId!)
        console.error(`[bolt] Session closed: ${sessionId}`)
      } else {
        jsonResponse(res, 404, { error: "Session not found" })
      }
      return
    }

    jsonResponse(res, 405, { error: "Method not allowed" })
    return
  }

  jsonResponse(res, 404, { error: "Not found" })
}

// =====================================================================
// Main
// =====================================================================

// Periodic cleanup
const cleanupInterval = setInterval(() => {
  cleanupSessions()
  cleanupPairingCodes()
  cleanupNonces()
  knockDaemon?.cleanupNonces()
}, 5 * 60 * 1000)

async function main(): Promise<void> {
  console.error("[bolt] Starting Bolt server...")

  // Initialize crypto keys and authorized clients
  await initServerKeys()
  await loadAuthorizedClients()

  // Load tool definitions
  sharedToolDefs = await loadAllTools(DEFINITIONS_DIR)
  console.error(`[bolt] ${sharedToolDefs.size} tools indexed`)

  // Start knock daemon if enabled
  if (knockEnabled) {
    knockDaemon = new KnockDaemon(
      {
        dataDir,
        targetPort: effectivePort,
        accessTtlMs: DEFAULT_KNOCK_TTL_MS,
        timestampDriftMs: TIMESTAMP_DRIFT_MS,
      },
      {
        getClientPublicKey(clientId: string): string | undefined {
          return authorizedClients.get(clientId)?.publicKeyPem
        },
      }
    )
    await knockDaemon.start()
  }

  const server = http.createServer(async (req, res) => {
    try {
      await handleRequest(req, res)
    } catch (err) {
      console.error("[bolt] Request error:", err)
      if (!res.headersSent) {
        jsonResponse(res, 500, { error: "Internal server error" })
      }
    }
  })

  server.listen(effectivePort, effectiveHost, () => {
    console.error(`[bolt] Server listening on http://${effectiveHost}:${effectivePort}`)
    console.error(`[bolt] Endpoints:`)
    console.error(`[bolt]   MCP:     http://${effectiveHost}:${effectivePort}/mcp`)
    console.error(`[bolt]   Health:  http://${effectiveHost}:${effectivePort}/health`)
    console.error(`[bolt]   Pair:    http://${effectiveHost}:${effectivePort}/pair`)
    console.error(`[bolt] Auth: Ed25519 signatures (${authorizedClients.size} client(s) registered)`)
    if (knockDaemon) {
      const ks = knockDaemon.getStatus()
      console.error(`[bolt] Knock: enabled, rotating ports (iptables: ${ks.iptables ? "active" : "unavailable"})`)
      console.error(`[bolt] Bolt key: ${knockDaemon.getBoltKey()}`)
    } else {
      console.error("[bolt] Knock: disabled (use --knock to enable)")
    }
    if (adminToken) {
      console.error("[bolt] Admin token: set")
    } else {
      console.error("[bolt] Admin token: NOT SET — pairing disabled (set MCP_ADMIN_TOKEN)")
    }
  })

  // Graceful shutdown
  const shutdown = async (): Promise<void> => {
    console.error("[bolt] Shutting down...")
    clearInterval(cleanupInterval)

    if (knockDaemon) {
      await knockDaemon.stop()
    }

    for (const [id, session] of sessions.entries()) {
      session.transport.close().catch(() => {})
      sessions.delete(id)
    }

    server.close(() => {
      console.error("[bolt] Server closed")
      process.exit(0)
    })

    setTimeout(() => process.exit(1), 5000)
  }

  process.on("SIGINT", () => { shutdown().catch(() => process.exit(1)) })
  process.on("SIGTERM", () => { shutdown().catch(() => process.exit(1)) })
}

main().catch((err) => {
  console.error("[bolt] Fatal error:", err)
  process.exit(1)
})
