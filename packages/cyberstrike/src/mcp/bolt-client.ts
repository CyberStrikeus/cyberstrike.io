import crypto from "crypto"
import { Ed25519Auth } from "./ed25519"

/**
 * HTTP client for Bolt MCP servers with Ed25519 request signing
 * All requests are automatically signed with the client's private key
 */
export class BoltClient {
  constructor(
    private serverUrl: string,
    private clientId: string,
    private privateKey: crypto.KeyObject,
  ) {}

  /**
   * Fetch with automatic Ed25519 signature headers
   * Adds: X-Client-Id, X-Timestamp, X-Nonce, X-Signature
   */
  async fetch(path: string, options?: RequestInit): Promise<Response> {
    const method = options?.method || "GET"
    const body = options?.body ? String(options.body) : ""

    // Generate Ed25519 signature
    const { timestamp, nonce, signature } = Ed25519Auth.signRequest(
      this.privateKey,
      this.clientId,
      method,
      path,
      body,
    )

    // Merge headers
    const headers = new Headers(options?.headers)
    headers.set("X-Client-Id", this.clientId)
    headers.set("X-Timestamp", timestamp)
    headers.set("X-Nonce", nonce)
    headers.set("X-Signature", signature)

    // Make request with signed headers
    const url = this.serverUrl + path
    return fetch(url, {
      ...options,
      headers,
    })
  }

  /**
   * Create BoltClient from stored credentials
   * Returns undefined if no Ed25519 credentials exist
   */
  static async fromConfig(mcpName: string, serverUrl: string): Promise<BoltClient | undefined> {
    const creds = await Ed25519Auth.loadCredentials(mcpName)
    if (!creds) return undefined

    return new BoltClient(serverUrl, creds.clientId, creds.privateKey)
  }
}
