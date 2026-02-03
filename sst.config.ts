/// <reference path="./.sst/platform/config.d.ts" />

export default $config({
  app(input) {
    return {
      name: "cyberstrike",
      removal: input?.stage === "production" ? "retain" : "remove",
      protect: ["production"].includes(input?.stage),
      home: "cloudflare",
      providers: {
        // TiDB Serverless - MySQL compatible, no provider needed
      },
    }
  },
  async run() {
    await import("./infra/app.js")
  },
})
