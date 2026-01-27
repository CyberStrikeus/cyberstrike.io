export * from "./gen/types.gen.js"

import { createClient } from "./gen/client/client.gen.js"
import { type Config } from "./gen/client/types.gen.js"
import { WhykidoClient } from "./gen/sdk.gen.js"
export { type Config as WhykidoClientConfig, WhykidoClient }

export function createWhykidoClient(config?: Config & { directory?: string }) {
  if (!config?.fetch) {
    const customFetch: any = (req: any) => {
      // @ts-ignore
      req.timeout = false
      return fetch(req)
    }
    config = {
      ...config,
      fetch: customFetch,
    }
  }

  if (config?.directory) {
    config.headers = {
      ...config.headers,
      "x-whykido-directory": config.directory,
    }
  }

  const client = createClient(config)
  return new WhykidoClient({ client })
}
