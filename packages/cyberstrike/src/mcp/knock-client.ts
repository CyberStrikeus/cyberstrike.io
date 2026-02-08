import crypto from "crypto"
import dgram from "dgram"

/**
 * Port knocking client for Bolt MCP servers
 * Sends authenticated UDP packets to rotating ports to unlock access
 */

const PORT_RANGE_MIN = 49152
const PORT_RANGE_SIZE = 16384
const PORT_ROTATION_INTERVAL_MS = 60 * 1000

/**
 * Derive the knock port for a given time window
 * (Same algorithm as server-side)
 */
function deriveKnockPort(boltKey: Buffer, timeWindow: number): number {
  const hmac = crypto.createHmac("sha256", boltKey)
  hmac.update(String(timeWindow))
  const hash = hmac.digest()
  const portOffset = hash.readUInt16BE(0) % PORT_RANGE_SIZE
  return PORT_RANGE_MIN + portOffset
}

/**
 * Get current time window (minute-based)
 */
function getCurrentTimeWindow(): number {
  return Math.floor(Date.now() / PORT_ROTATION_INTERVAL_MS)
}

/**
 * Send a knock packet to the server
 */
async function sendKnockPacket(
  host: string,
  port: number,
  packet: { c: string; t: string; n: string; s: string },
): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4")
    const message = Buffer.from(JSON.stringify(packet))

    socket.send(message, port, host, (err) => {
      socket.close()
      if (err) reject(err)
      else resolve()
    })

    // Timeout after 1 second
    setTimeout(() => {
      socket.close()
      reject(new Error("Knock packet send timeout"))
    }, 1000)
  })
}

/**
 * Perform port knock for pairing (HMAC signature)
 */
export async function knockForPairing(url: string, boltKey: string): Promise<void> {
  const boltKeyBuffer = Buffer.from(boltKey, "hex")
  const hostname = new URL(url).hostname
  const timeWindow = getCurrentTimeWindow()
  const port = deriveKnockPort(boltKeyBuffer, timeWindow)

  const timestamp = new Date().toISOString()
  const nonce = crypto.randomBytes(16).toString("hex")
  const message = `pairing|${timestamp}|${nonce}`
  const signature = crypto.createHmac("sha256", boltKeyBuffer).update(message).digest("base64")

  const packet = {
    c: "pairing",
    t: timestamp,
    n: nonce,
    s: signature,
  }

  await sendKnockPacket(hostname, port, packet)
}

/**
 * Perform port knock for authorized client (Ed25519 signature)
 */
export async function knockForClient(
  url: string,
  boltKey: string,
  clientId: string,
  privateKey: crypto.KeyObject,
): Promise<void> {
  const boltKeyBuffer = Buffer.from(boltKey, "hex")
  const hostname = new URL(url).hostname
  const timeWindow = getCurrentTimeWindow()
  const port = deriveKnockPort(boltKeyBuffer, timeWindow)

  const timestamp = new Date().toISOString()
  const nonce = crypto.randomBytes(16).toString("hex")
  const message = `${clientId}|${timestamp}|${nonce}`
  const signature = crypto.sign(null, Buffer.from(message), privateKey).toString("base64")

  const packet = {
    c: clientId,
    t: timestamp,
    n: nonce,
    s: signature,
  }

  await sendKnockPacket(hostname, port, packet)
}

/**
 * Perform port knock and wait for port to open
 */
export async function performKnock(
  url: string,
  boltKey: string,
  clientId?: string,
  privateKey?: crypto.KeyObject,
): Promise<void> {
  if (clientId && privateKey) {
    await knockForClient(url, boltKey, clientId, privateKey)
  } else {
    await knockForPairing(url, boltKey)
  }

  // Wait 1 second for iptables to update
  await new Promise((resolve) => setTimeout(resolve, 1000))
}
