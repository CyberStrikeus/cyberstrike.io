import { Database, and, eq, sql } from "../src/drizzle/index.js"
import { AuthTable } from "../src/schema/auth.sql.js"
import { UserTable } from "../src/schema/user.sql.js"
import { UsageTable } from "../src/schema/billing.sql.js"
import { WorkspaceTable } from "../src/schema/workspace.sql.js"

// get input from command line
const identifier = process.argv[2]
if (!identifier) {
  console.error("Usage: bun lookup-user.ts <email|workspaceID>")
  process.exit(1)
}

if (identifier.startsWith("wrk_")) {
  await printWorkspace(identifier)
} else {
  const authData = await Database.use(async (tx) =>
    tx.select().from(AuthTable).where(eq(AuthTable.subject, identifier)),
  )
  if (authData.length === 0) {
    console.error("Email not found")
    process.exit(1)
  }
  if (authData.length > 1) console.warn("Multiple users found for email", identifier)

  // Get all auth records for email
  const accountID = authData[0].accountID
  await printTable("Auth", (tx) => tx.select().from(AuthTable).where(eq(AuthTable.accountID, accountID)))

  // Get all workspaces for this account
  const users = await printTable("Workspaces", (tx) =>
    tx
      .select({
        userID: UserTable.id,
        workspaceID: UserTable.workspaceID,
        workspaceName: WorkspaceTable.name,
        role: UserTable.role,
      })
      .from(UserTable)
      .rightJoin(WorkspaceTable, eq(WorkspaceTable.id, UserTable.workspaceID))
      .where(eq(UserTable.accountID, accountID))
      .then((rows) =>
        rows.map((row) => ({
          userID: row.userID,
          workspaceID: row.workspaceID,
          workspaceName: row.workspaceName,
          role: row.role,
        })),
      ),
  )

  for (const user of users) {
    await printWorkspace(user.workspaceID)
  }
}

async function printWorkspace(workspaceID: string) {
  const workspace = await Database.use((tx) =>
    tx
      .select()
      .from(WorkspaceTable)
      .where(eq(WorkspaceTable.id, workspaceID))
      .then((rows) => rows[0]),
  )

  printHeader(`Workspace "${workspace.name}" (${workspace.id})`)

  await printTable("Users", (tx) =>
    tx
      .select({
        authEmail: AuthTable.subject,
        inviteEmail: UserTable.email,
        role: UserTable.role,
        timeSeen: UserTable.timeSeen,
        timeDeleted: UserTable.timeDeleted,
      })
      .from(UserTable)
      .leftJoin(AuthTable, and(eq(UserTable.accountID, AuthTable.accountID), eq(AuthTable.provider, "email")))
      .where(eq(UserTable.workspaceID, workspace.id))
      .then((rows) =>
        rows.map((row) => ({
          email: (row.timeDeleted ? "❌ " : "") + (row.authEmail ?? row.inviteEmail),
          role: row.role,
          timeSeen: formatDate(row.timeSeen),
        })),
      ),
  )

  await printTable("Usage (last 10)", (tx) =>
    tx
      .select({
        model: UsageTable.model,
        provider: UsageTable.provider,
        inputTokens: UsageTable.inputTokens,
        outputTokens: UsageTable.outputTokens,
        cost: UsageTable.cost,
        timeCreated: UsageTable.timeCreated,
      })
      .from(UsageTable)
      .where(eq(UsageTable.workspaceID, workspace.id))
      .orderBy(sql`${UsageTable.timeCreated} DESC`)
      .limit(10)
      .then((rows) =>
        rows.map((row) => ({
          ...row,
          cost: `$${(row.cost / 100000000).toFixed(2)}`,
        })),
      ),
  )
}

function formatDate(value: Date | null | undefined) {
  if (!value) return null
  return value.toISOString().split("T")[0]
}

function printHeader(title: string) {
  console.log()
  console.log("─".repeat(title.length))
  console.log(`${title}`)
  console.log("─".repeat(title.length))
}

function printTable(title: string, callback: (tx: Database.TxOrDb) => Promise<any>): Promise<any> {
  return Database.use(async (tx) => {
    const data = await callback(tx)
    console.log(`\n== ${title} ==`)
    if (data.length === 0) {
      console.log("(no data)")
    } else {
      console.table(data)
    }
    return data
  })
}
