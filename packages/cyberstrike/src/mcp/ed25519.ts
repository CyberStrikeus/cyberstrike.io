import crypto from "crypto"
import { McpAuth } from "./auth"

export namespace Ed25519Auth {
  export interface KeyPair {
    publicKey: crypto.KeyObject
    privateKey: crypto.KeyObject
    publicKeyPem: string
    privateKeyPem: string
  }

  export interface Credentials {
    clientId: string
    privateKey: crypto.KeyObject
    boltKey?: string // For port knocking
  }

  export interface SignatureHeaders {
    timestamp: string
    nonce: string
    signature: string
  }

  /**
   * Generate Ed25519 keypair for client authentication
   */
  export async function generateKeyPair(): Promise<KeyPair> {
    return new Promise((resolve, reject) => {
      crypto.generateKeyPair(
        "ed25519",
        {
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
        },
        (err, publicKeyPem, privateKeyPem) => {
          if (err) return reject(err)

          const publicKey = crypto.createPublicKey(publicKeyPem)
          const privateKey = crypto.createPrivateKey(privateKeyPem)

          resolve({
            publicKey,
            privateKey,
            publicKeyPem,
            privateKeyPem,
          })
        },
      )
    })
  }

  /**
   * Compute SHA256 fingerprint of public key (first 16 chars)
   * Matches server's client ID generation
   */
  export function fingerprint(publicKeyPem: string): string {
    const hash = crypto.createHash("sha256")
    hash.update(publicKeyPem)
    return hash.digest("hex").slice(0, 16)
  }

  /**
   * Sign HTTP request with Ed25519
   * Returns headers to add to request: X-Timestamp, X-Nonce, X-Signature
   */
  export function signRequest(
    privateKey: crypto.KeyObject,
    clientId: string,
    method: string,
    path: string,
    body: string,
  ): SignatureHeaders {
    // Generate timestamp (ISO 8601)
    const timestamp = new Date().toISOString()

    // Generate cryptographically random nonce
    const nonce = crypto.randomBytes(16).toString("hex")

    // Compute body hash (SHA256)
    const bodyHash = crypto.createHash("sha256").update(body).digest("hex")

    // Create signature payload
    // Format: ${timestamp}\n${nonce}\n${method}\n${path}\n${bodyHash}
    const payload = `${timestamp}\n${nonce}\n${method}\n${path}\n${bodyHash}`

    // Sign with Ed25519 private key
    const signature = crypto.sign(null, Buffer.from(payload), privateKey)

    return {
      timestamp,
      nonce,
      signature: signature.toString("base64"),
    }
  }

  /**
   * Store Ed25519 credentials in mcp-auth.json
   * File is created with 0o600 permissions (owner read/write only)
   */
  export async function storeCredentials(
    mcpName: string,
    serverUrl: string,
    clientPublicKey: string,
    clientPrivateKey: string,
    serverPublicKey: string,
    clientId: string,
    serverFingerprint: string,
    boltKey?: string,
  ): Promise<void> {
    const entry = (await McpAuth.get(mcpName)) ?? {}

    entry.ed25519 = {
      clientId,
      clientPublicKey,
      clientPrivateKey,
      serverPublicKey,
      serverFingerprint,
      boltKey,
    }

    await McpAuth.set(mcpName, entry, serverUrl)
  }

  /**
   * Load Ed25519 credentials for signing requests
   * Returns undefined if no credentials exist
   */
  export async function loadCredentials(mcpName: string): Promise<Credentials | undefined> {
    const entry = await McpAuth.get(mcpName)
    if (!entry?.ed25519) return undefined

    try {
      const privateKey = crypto.createPrivateKey(entry.ed25519.clientPrivateKey)
      return {
        clientId: entry.ed25519.clientId,
        privateKey,
        boltKey: entry.ed25519.boltKey,
      }
    } catch (error) {
      console.error(`Failed to load Ed25519 credentials for ${mcpName}:`, error)
      return undefined
    }
  }
}
