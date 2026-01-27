export * from "./client.js"
export * from "./server.js"

import { createWhykidoClient } from "./client.js"
import { createWhykidoServer } from "./server.js"
import type { ServerOptions } from "./server.js"

export async function createWhykido(options?: ServerOptions) {
  const server = await createWhykidoServer({
    ...options,
  })

  const client = createWhykidoClient({
    baseUrl: server.url,
  })

  return {
    client,
    server,
  }
}
