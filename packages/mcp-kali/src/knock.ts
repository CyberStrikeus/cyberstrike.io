/**
 * SPA (Single Packet Authorization) Knock Daemon with Rotating Ports
 *
 * Makes the Bolt completely invisible on the internet. The knock port
 * changes every minute based on a shared secret, so even if an attacker
 * scans all UDP ports, by the time they finish the port has rotated.
 *
 * SECURITY MODEL:
 *
 *   1. Bolt generates a random 256-bit "bolt key" on first startup
 *   2. Admin shares this key with users out-of-band (like SSH keys)
 *   3. Client and server derive the current knock port from:
 *        port = HMAC-SHA256(boltKey, floor(timestamp / 60))[0:2] % 16384 + 49152
 *   4. Server listens on 3 ports simultaneously: t-1, t, t+1 (clock drift tolerance)
 *   5. Client sends SPA packet to the current port
 *   6. After valid knock, /mcp endpoint opens for that IP
 *
 *   Without the bolt key, attacker cannot:
 *     - Know which port to knock on
 *     - Predict future ports
 *     - Replay old knocks (nonce + timestamp validation)
 *
 * FLOW:
 *
 *   Bolt setup (one-time):
 *     1. Bolt generates bolt key: "xK9mP2vL8qR4..."
 *     2. Admin copies key to user
 *
 *   Client pairing:
 *     1. User enters: URL + bolt key in TUI
 *     2. Client derives knock port from key + current time
 *     3. Client sends knock → port opens
 *     4. Client calls /pair/exchange → keys exchanged
 *     5. Client is now authorized for future knocks
 *
 *   Normal operation:
 *     1. Client derives port from key + time
 *     2. Client sends signed knock packet
 *     3. Server verifies signature + opens port for IP
 *     4. Client makes MCP requests
 *
 * Knock packet format (JSON, max 512 bytes):
 *   {
 *     "c": "<clientId fingerprint or 'pairing' for new clients>",
 *     "t": "<ISO 8601 timestamp>",
 *     "n": "<random nonce>",
 *     "s": "<base64 HMAC-SHA256(boltKey, c|t|n) for pairing, or Ed25519 sig for authorized>"
 *   }
 *
 * The UDP sockets never send responses. To a scanner, all ports appear filtered.
 */

import dgram from "node:dgram"
import crypto from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { execFile } from "node:child_process"
import { promisify } from "node:util"

const execFileAsync = promisify(execFile)

// --- Constants ---

const PORT_RANGE_MIN = 49152
const PORT_RANGE_SIZE = 16384 // 49152 - 65535
const PORT_ROTATION_INTERVAL_MS = 60 * 1000 // 1 minute
const CLOCK_DRIFT_WINDOWS = 1 // ±1 minute tolerance

// --- Types ---

export interface KnockConfig {
  /** Directory to store bolt key */
  dataDir: string
  /** TCP port to open on valid knock (the MCP HTTP port) */
  targetPort: number
  /** How long the port stays open for a given IP (ms) */
  accessTtlMs: number
  /** Max clock drift for knock timestamp (ms) */
  timestampDriftMs: number
}

export interface AuthorizedClientLookup {
  /** Get client public key PEM by clientId, or undefined if not found */
  getClientPublicKey(clientId: string): string | undefined
}

interface ActiveRule {
  ip: string
  expiresAt: number
  timer: ReturnType<typeof setTimeout>
}

interface KnockPacket {
  c: string // clientId (or "pairing" for new clients)
  t: string // timestamp
  n: string // nonce
  s: string // signature (HMAC for pairing, Ed25519 for authorized)
}

// --- Port Derivation ---

/**
 * Derive the knock port for a given time window.
 * Both client and server use this same function.
 */
export function deriveKnockPort(boltKey: Buffer, timeWindow: number): number {
  const hmac = crypto.createHmac("sha256", boltKey)
  hmac.update(String(timeWindow))
  const hash = hmac.digest()
  // Use first 2 bytes as 16-bit unsigned int
  const portOffset = hash.readUInt16BE(0) % PORT_RANGE_SIZE
  return PORT_RANGE_MIN + portOffset
}

/**
 * Get the current time window (minute-based).
 */
function getCurrentTimeWindow(): number {
  return Math.floor(Date.now() / PORT_ROTATION_INTERVAL_MS)
}

/**
 * Get all active time windows (current ± drift tolerance).
 */
function getActiveTimeWindows(): number[] {
  const current = getCurrentTimeWindow()
  const windows: number[] = []
  for (let i = -CLOCK_DRIFT_WINDOWS; i <= CLOCK_DRIFT_WINDOWS; i++) {
    windows.push(current + i)
  }
  return windows
}

// --- Knock Daemon ---

export class KnockDaemon {
  private sockets: Map<number, dgram.Socket> = new Map()
  private activeRules = new Map<string, ActiveRule>()
  private usedNonces = new Set<string>()
  private config: KnockConfig
  private clientLookup: AuthorizedClientLookup
  private iptablesAvailable = false
  private boltKey: Buffer = Buffer.alloc(0)
  private rotationTimer: ReturnType<typeof setInterval> | null = null
  private currentPorts: number[] = []

  constructor(config: KnockConfig, clientLookup: AuthorizedClientLookup) {
    this.config = config
    this.clientLookup = clientLookup
  }

  /**
   * Start the knock daemon: load/generate key, set up firewall, begin listening.
   */
  async start(): Promise<void> {
    // Load or generate bolt key
    await this.initBoltKey()

    // Check if iptables is available
    this.iptablesAvailable = await this.checkIptables()

    if (!this.iptablesAvailable) {
      console.error("[knock] iptables not available — running in log-only mode")
      console.error("[knock] (Port knocking requires Linux with iptables and NET_ADMIN capability)")
    } else {
      // Install DROP rule for the target port
      await this.lockPort()
      console.error(`[knock] Port ${this.config.targetPort} locked (iptables DROP)`)
    }

    // Start listening on current ports
    await this.rotatePorts()

    // Set up port rotation timer
    this.rotationTimer = setInterval(() => {
      this.rotatePorts().catch((err) => {
        console.error("[knock] Port rotation error:", err)
      })
    }, PORT_ROTATION_INTERVAL_MS)

    console.error(`[knock] Access TTL: ${this.config.accessTtlMs / 1000}s`)
    console.error(`[knock] Port rotation: every ${PORT_ROTATION_INTERVAL_MS / 1000}s`)
  }

  /**
   * Initialize or load the bolt key.
   */
  private async initBoltKey(): Promise<void> {
    const keyPath = path.join(this.config.dataDir, "bolt.key")

    try {
      const keyHex = await fs.readFile(keyPath, "utf-8")
      this.boltKey = Buffer.from(keyHex.trim(), "hex")
      console.error("[knock] Loaded existing bolt key")
    } catch {
      // Generate new key
      this.boltKey = crypto.randomBytes(32)
      await fs.mkdir(this.config.dataDir, { recursive: true })
      await fs.writeFile(keyPath, this.boltKey.toString("hex"), { mode: 0o600 })
      console.error("[knock] Generated new bolt key")
    }

    // Display key for admin to share
    const keyDisplay = this.boltKey.toString("hex")
    console.error(`[knock] ========================================`)
    console.error(`[knock] BOLT KEY (share with users):`)
    console.error(`[knock] ${keyDisplay}`)
    console.error(`[knock] ========================================`)
  }

  /**
   * Get the bolt key for display purposes.
   */
  getBoltKey(): string {
    return this.boltKey.toString("hex")
  }

  /**
   * Rotate listening ports based on current time.
   */
  private async rotatePorts(): Promise<void> {
    const timeWindows = getActiveTimeWindows()
    const newPorts = timeWindows.map((tw) => deriveKnockPort(this.boltKey, tw))

    // Find ports to close and ports to open
    const portsToClose = this.currentPorts.filter((p) => !newPorts.includes(p))
    const portsToOpen = newPorts.filter((p) => !this.currentPorts.includes(p))

    // Close old ports
    for (const port of portsToClose) {
      const socket = this.sockets.get(port)
      if (socket) {
        socket.close()
        this.sockets.delete(port)
      }
    }

    // Open new ports
    for (const port of portsToOpen) {
      await this.listenOnPort(port)
    }

    this.currentPorts = newPorts

    if (portsToOpen.length > 0 || portsToClose.length > 0) {
      console.error(`[knock] Ports rotated: now listening on ${newPorts.join(", ")}`)
    }
  }

  /**
   * Start listening on a specific UDP port.
   */
  private listenOnPort(port: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = dgram.createSocket({ type: "udp4" })

      socket.on("message", (msg, rinfo) => {
        this.handleKnock(msg, rinfo, port).catch((err) => {
          console.error("[knock] Error handling knock:", err)
        })
      })

      socket.on("error", (err) => {
        console.error(`[knock] Socket error on port ${port}:`, err)
      })

      socket.bind(port, "0.0.0.0", () => {
        this.sockets.set(port, socket)
        resolve()
      })
    })
  }

  /**
   * Stop the daemon: remove all rules and close sockets.
   */
  async stop(): Promise<void> {
    // Stop rotation timer
    if (this.rotationTimer) {
      clearInterval(this.rotationTimer)
      this.rotationTimer = null
    }

    // Remove all active access rules
    for (const [ip, rule] of this.activeRules.entries()) {
      clearTimeout(rule.timer)
      if (this.iptablesAvailable) {
        await this.removeAccess(ip).catch(() => {})
      }
    }
    this.activeRules.clear()

    // Remove the DROP rule
    if (this.iptablesAvailable) {
      await this.unlockPort().catch(() => {})
    }

    // Close all UDP sockets
    for (const [port, socket] of this.sockets.entries()) {
      socket.close()
    }
    this.sockets.clear()
    this.currentPorts = []

    console.error("[knock] Daemon stopped")
  }

  /**
   * Handle an incoming UDP packet.
   */
  private async handleKnock(msg: Buffer, rinfo: dgram.RemoteInfo, port: number): Promise<void> {
    const sourceIp = rinfo.address

    // Reject oversized packets
    if (msg.length > 512) return

    // Parse
    let packet: KnockPacket
    try {
      packet = JSON.parse(msg.toString("utf-8"))
    } catch {
      return // silently ignore malformed packets
    }

    const { c: clientId, t: timestamp, n: nonce, s: signature } = packet
    if (!clientId || !timestamp || !nonce || !signature) return

    // Validate timestamp
    const ts = new Date(timestamp).getTime()
    if (isNaN(ts) || Math.abs(Date.now() - ts) > this.config.timestampDriftMs) {
      console.error(`[knock] Expired timestamp from ${sourceIp}`)
      return
    }

    // Check nonce uniqueness
    if (this.usedNonces.has(nonce)) {
      console.error(`[knock] Replay detected from ${sourceIp}`)
      return
    }

    // Verify based on client type
    if (clientId === "pairing") {
      // Pairing knock: verify HMAC using bolt key
      const message = `${clientId}|${timestamp}|${nonce}`
      const expectedHmac = crypto
        .createHmac("sha256", this.boltKey)
        .update(message)
        .digest("base64")

      if (signature !== expectedHmac) {
        console.error(`[knock] Invalid pairing HMAC from ${sourceIp}`)
        return
      }

      console.error(`[knock] Valid pairing knock from ${sourceIp}`)
    } else {
      // Authorized client knock: verify Ed25519 signature
      const publicKeyPem = this.clientLookup.getClientPublicKey(clientId)
      if (!publicKeyPem) {
        console.error(`[knock] Unknown client ${clientId} from ${sourceIp}`)
        return
      }

      const message = `${clientId}|${timestamp}|${nonce}`
      try {
        const publicKey = crypto.createPublicKey(publicKeyPem)
        const valid = crypto.verify(
          null,
          Buffer.from(message),
          publicKey,
          Buffer.from(signature, "base64")
        )
        if (!valid) {
          console.error(`[knock] Invalid signature from ${sourceIp}`)
          return
        }
      } catch {
        console.error(`[knock] Signature verification error from ${sourceIp}`)
        return
      }

      console.error(`[knock] Valid knock from ${sourceIp} (client: ${clientId})`)
    }

    // Record nonce
    this.usedNonces.add(nonce)

    // Grant access
    await this.grantAccess(sourceIp)
  }

  /**
   * Grant port access to an IP address.
   */
  private async grantAccess(ip: string): Promise<void> {
    // If already has access, extend it
    const existing = this.activeRules.get(ip)
    if (existing) {
      clearTimeout(existing.timer)
      existing.expiresAt = Date.now() + this.config.accessTtlMs
      existing.timer = setTimeout(() => this.revokeAccess(ip), this.config.accessTtlMs)
      console.error(`[knock] Extended access for ${ip} (${this.config.accessTtlMs / 1000}s)`)
      return
    }

    // Add iptables rule
    if (this.iptablesAvailable) {
      await this.addAccess(ip)
    }

    const timer = setTimeout(() => this.revokeAccess(ip), this.config.accessTtlMs)

    this.activeRules.set(ip, {
      ip,
      expiresAt: Date.now() + this.config.accessTtlMs,
      timer,
    })

    console.error(`[knock] Access granted to ${ip} for ${this.config.accessTtlMs / 1000}s`)
  }

  /**
   * Revoke port access from an IP address.
   */
  private async revokeAccess(ip: string): Promise<void> {
    const rule = this.activeRules.get(ip)
    if (!rule) return

    clearTimeout(rule.timer)
    this.activeRules.delete(ip)

    if (this.iptablesAvailable) {
      await this.removeAccess(ip).catch(() => {})
    }

    console.error(`[knock] Access revoked for ${ip}`)
  }

  // --- iptables operations ---

  private async checkIptables(): Promise<boolean> {
    try {
      await execFileAsync("iptables", ["--version"])
      return true
    } catch {
      return false
    }
  }

  private async lockPort(): Promise<void> {
    await this.unlockPort().catch(() => {})
    await execFileAsync("iptables", [
      "-A", "INPUT",
      "-p", "tcp",
      "--dport", String(this.config.targetPort),
      "-j", "DROP",
    ])
  }

  private async unlockPort(): Promise<void> {
    try {
      await execFileAsync("iptables", [
        "-D", "INPUT",
        "-p", "tcp",
        "--dport", String(this.config.targetPort),
        "-j", "DROP",
      ])
    } catch {
      // Rule didn't exist
    }
  }

  private async addAccess(ip: string): Promise<void> {
    await execFileAsync("iptables", [
      "-I", "INPUT",
      "-s", ip,
      "-p", "tcp",
      "--dport", String(this.config.targetPort),
      "-j", "ACCEPT",
    ])
  }

  private async removeAccess(ip: string): Promise<void> {
    await execFileAsync("iptables", [
      "-D", "INPUT",
      "-s", ip,
      "-p", "tcp",
      "--dport", String(this.config.targetPort),
      "-j", "ACCEPT",
    ])
  }

  // --- Cleanup ---

  cleanupNonces(): void {
    if (this.usedNonces.size > 10000) {
      this.usedNonces.clear()
    }
  }

  // --- Status ---

  getStatus(): {
    active: boolean
    activeRules: number
    iptables: boolean
    currentPorts: number[]
  } {
    return {
      active: this.sockets.size > 0,
      activeRules: this.activeRules.size,
      iptables: this.iptablesAvailable,
      currentPorts: this.currentPorts,
    }
  }

  getActiveIPs(): string[] {
    return Array.from(this.activeRules.keys())
  }
}
