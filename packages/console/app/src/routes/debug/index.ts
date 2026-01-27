import type { APIEvent } from "@solidjs/start/server"
import { json } from "@solidjs/router"
import { Database } from "@whykido/console-core/drizzle/index.js"
import { UserTable } from "@whykido/console-core/schema/user.sql.js"

export async function GET(evt: APIEvent) {
  return json({
    data: await Database.use(async (tx) => {
      const result = await tx.$count(UserTable)
      return result
    }),
  })
}
