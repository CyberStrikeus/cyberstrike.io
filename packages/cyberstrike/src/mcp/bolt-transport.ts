import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js"
import { Ed25519Auth } from "./ed25519.js"
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js"
import type { KeyObject } from "node:crypto"

/**
 * Custom StreamableHTTP transport with Ed25519 request signing
 * Automatically adds signature headers to all MCP requests
 */
export class BoltTransport extends StreamableHTTPClientTransport {
  private _clientId: string
  private _privateKey: KeyObject

  constructor(
    url: URL,
    clientId: string,
    privateKey: KeyObject,
    options?: ConstructorParameters<typeof StreamableHTTPClientTransport>[1],
  ) {
    super(url, options)
    this._clientId = clientId
    this._privateKey = privateKey
  }

  /**
   * Override send to add Ed25519 signature headers to each request
   */
  override async send(message: any): Promise<void> {
    // Wrap the internal fetch to add Ed25519 headers
    const originalFetch = globalThis.fetch
    const clientId = this._clientId
    const privateKey = this._privateKey

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url

      // Only sign requests to our MCP server
      if (urlStr.includes("/mcp")) {
        const method = init?.method || "POST"
        const body = init?.body ? String(init.body) : ""
        const urlObj = new URL(urlStr)
        const path = urlObj.pathname + urlObj.search

        // Generate Ed25519 signature
        const { timestamp, nonce, signature } = Ed25519Auth.signRequest(
          privateKey,
          clientId,
          method,
          path,
          body,
        )

        // Add signature headers
        const headers = new Headers(init?.headers)
        headers.set("X-Client-Id", clientId)
        headers.set("X-Timestamp", timestamp)
        headers.set("X-Nonce", nonce)
        headers.set("X-Signature", signature)

        return originalFetch(input, { ...init, headers })
      }

      return originalFetch(input, init)
    }) as typeof fetch

    try {
      return await super.send(message)
    } finally {
      globalThis.fetch = originalFetch
    }
  }

  /**
   * Create BoltTransport from stored Ed25519 credentials
   */
  static async fromCredentials(
    mcpName: string,
    serverUrl: string,
  ): Promise<BoltTransport | undefined> {
    const creds = await Ed25519Auth.loadCredentials(mcpName)
    if (!creds) return undefined

    return new BoltTransport(new URL(serverUrl), creds.clientId, creds.privateKey)
  }
}
