import { domain } from "./stage"
import { EMAILOCTOPUS_API_KEY } from "./app"

////////////////
// DATABASE (TiDB Serverless)
////////////////

const TIDB_HOST = new sst.Secret("TIDB_HOST")
const TIDB_USER = new sst.Secret("TIDB_USER")
const TIDB_PASSWORD = new sst.Secret("TIDB_PASSWORD")
const TIDB_DATABASE = new sst.Secret("TIDB_DATABASE")

export const database = new sst.Linkable("Database", {
  properties: {
    host: TIDB_HOST.value,
    database: TIDB_DATABASE.value,
    username: TIDB_USER.value,
    password: TIDB_PASSWORD.value,
    port: 4000,
  },
})

new sst.x.DevCommand("Studio", {
  link: [database],
  dev: {
    command: "bun db studio",
    directory: "packages/console/core",
    autostart: true,
  },
})

////////////////
// AUTH
////////////////

const GITHUB_CLIENT_ID_CONSOLE = new sst.Secret("GITHUB_CLIENT_ID_CONSOLE")
const GITHUB_CLIENT_SECRET_CONSOLE = new sst.Secret("GITHUB_CLIENT_SECRET_CONSOLE")
const GOOGLE_CLIENT_ID = new sst.Secret("GOOGLE_CLIENT_ID")
const authStorage = new sst.cloudflare.Kv("AuthStorage")
export const auth = new sst.cloudflare.Worker("AuthApi", {
  domain: `auth.${domain}`,
  handler: "packages/console/function/src/auth.ts",
  url: true,
  link: [database, authStorage, GITHUB_CLIENT_ID_CONSOLE, GITHUB_CLIENT_SECRET_CONSOLE, GOOGLE_CLIENT_ID],
})

////////////////
// GATEWAY
////////////////

const ARSENAL_MODELS = [
  new sst.Secret("ARSENAL_MODELS1"),
  new sst.Secret("ARSENAL_MODELS2"),
  new sst.Secret("ARSENAL_MODELS3"),
  new sst.Secret("ARSENAL_MODELS4"),
  new sst.Secret("ARSENAL_MODELS5"),
  new sst.Secret("ARSENAL_MODELS6"),
  new sst.Secret("ARSENAL_MODELS7"),
  new sst.Secret("ARSENAL_MODELS8"),
]
const AUTH_API_URL = new sst.Linkable("AUTH_API_URL", {
  properties: { value: auth.url.apply((url) => url!) },
})
const gatewayKv = new sst.cloudflare.Kv("GatewayKv")

////////////////
// CONSOLE
////////////////

const bucket = new sst.cloudflare.Bucket("ArsenalData")
const bucketNew = new sst.cloudflare.Bucket("ArsenalDataNew")

const AWS_SES_ACCESS_KEY_ID = new sst.Secret("AWS_SES_ACCESS_KEY_ID")
const AWS_SES_SECRET_ACCESS_KEY = new sst.Secret("AWS_SES_SECRET_ACCESS_KEY")

let logProcessor
if ($app.stage === "production" || $app.stage === "frank") {
  const HONEYCOMB_API_KEY = new sst.Secret("HONEYCOMB_API_KEY")
  logProcessor = new sst.cloudflare.Worker("LogProcessor", {
    handler: "packages/console/function/src/log-processor.ts",
    link: [HONEYCOMB_API_KEY],
  })
}

new sst.cloudflare.x.SolidStart("Console", {
  domain,
  path: "packages/console/app",
  link: [
    bucket,
    bucketNew,
    database,
    AUTH_API_URL,
    EMAILOCTOPUS_API_KEY,
    AWS_SES_ACCESS_KEY_ID,
    AWS_SES_SECRET_ACCESS_KEY,
    new sst.Secret("ARSENAL_SESSION_SECRET"),
    ...ARSENAL_MODELS,
    ...($dev
      ? [
          new sst.Secret("CLOUDFLARE_DEFAULT_ACCOUNT_ID", process.env.CLOUDFLARE_DEFAULT_ACCOUNT_ID!),
          new sst.Secret("CLOUDFLARE_API_TOKEN", process.env.CLOUDFLARE_API_TOKEN!),
        ]
      : []),
    gatewayKv,
  ],
  environment: {
    //VITE_DOCS_URL: web.url.apply((url) => url!),
    //VITE_API_URL: gateway.url.apply((url) => url!),
    VITE_AUTH_URL: auth.url.apply((url) => url!),
  },
  transform: {
    server: {
      transform: {
        worker: {
          placement: { mode: "smart" },
          tailConsumers: logProcessor ? [{ service: logProcessor.nodes.worker.scriptName }] : [],
        },
      },
    },
  },
})
