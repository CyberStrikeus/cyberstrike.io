import { createMemo, createSignal } from "solid-js"
import { useLocal } from "@tui/context/local"
import { DialogSelect } from "@tui/ui/dialog-select"
import { useDialog } from "@tui/ui/dialog"
import { Config } from "@/config/config"

// Common permissions that can be toggled
const PERMISSION_OPTIONS = [
  { id: "browser", label: "Browser", description: "Web browser automation with traffic capture" },
  { id: "bash", label: "Bash", description: "Execute shell commands" },
  { id: "read", label: "Read", description: "Read files from filesystem" },
  { id: "edit", label: "Edit", description: "Edit files" },
  { id: "write", label: "Write", description: "Write new files" },
  { id: "glob", label: "Glob", description: "Search for files by pattern" },
  { id: "grep", label: "Grep", description: "Search file contents" },
  { id: "webfetch", label: "WebFetch", description: "Fetch web pages" },
  { id: "websearch", label: "WebSearch", description: "Search the web" },
  { id: "task", label: "Task", description: "Spawn sub-agents" },
] as const

type PermissionId = (typeof PERMISSION_OPTIONS)[number]["id"]

export function DialogAgentSettings() {
  const local = useLocal()
  const dialog = useDialog()

  const options = createMemo(() =>
    local.agent.list().map((item) => ({
      value: item.name,
      title: item.name,
      description: item.description || (item.native ? "Native agent" : "Custom agent"),
    })),
  )

  return (
    <DialogSelect
      title="Agent Settings"
      current={local.agent.current().name}
      options={options()}
      onSelect={(option) => {
        dialog.replace(() => <DialogAgentPermissions agentName={option.value} />)
      }}
    />
  )
}

function DialogAgentPermissions(props: { agentName: string }) {
  const local = useLocal()
  const dialog = useDialog()
  const [saving, setSaving] = createSignal(false)
  const [permissions, setPermissions] = createSignal<Record<string, "allow" | "deny" | "ask">>({})

  // Get current agent's permissions
  const agent = createMemo(() => local.agent.list().find((a) => a.name === props.agentName))

  // Initialize permissions from agent config
  const currentPermissions = createMemo(() => {
    const a = agent()
    if (!a) return {}

    const result: Record<string, "allow" | "deny" | "ask"> = {}
    for (const opt of PERMISSION_OPTIONS) {
      // Check if permission is explicitly set in the agent's permission rules
      const rule = a.permission?.find((r: any) => r.permission === opt.id)
      if (rule) {
        result[opt.id] = rule.action as "allow" | "deny" | "ask"
      } else {
        // Check wildcard
        const wildcardRule = a.permission?.find((r: any) => r.permission === "*")
        result[opt.id] = wildcardRule?.action as "allow" | "deny" | "ask" || "deny"
      }
    }
    return result
  })

  // Merge with local changes
  const effectivePermissions = createMemo(() => ({
    ...currentPermissions(),
    ...permissions(),
  }))

  const togglePermission = (id: PermissionId) => {
    const current = effectivePermissions()[id] || "deny"
    const next = current === "allow" ? "deny" : "allow"
    setPermissions((p) => ({ ...p, [id]: next }))
  }

  const savePermissions = async () => {
    setSaving(true)
    try {
      const permConfig: Record<string, string> = {}
      for (const [key, value] of Object.entries(permissions())) {
        permConfig[key] = value
      }

      await Config.update({
        agent: {
          [props.agentName]: {
            permission: permConfig,
          },
        },
      } as any)

      dialog.clear()
    } catch (e) {
      console.error("Failed to save permissions:", e)
    } finally {
      setSaving(false)
    }
  }

  const options = createMemo(() => [
    ...PERMISSION_OPTIONS.map((opt) => {
      const status = effectivePermissions()[opt.id] || "deny"
      const icon = status === "allow" ? "✓" : status === "ask" ? "?" : "✗"
      const color = status === "allow" ? "green" : status === "ask" ? "yellow" : "red"

      return {
        value: opt.id,
        title: `${icon} ${opt.label}`,
        description: opt.description,
        footer: status,
        color,
      }
    }),
    {
      value: "__save__",
      title: "💾 Save Changes",
      description: "Save permission changes to config",
      category: "Actions",
    },
    {
      value: "__back__",
      title: "← Back",
      description: "Return to agent list",
      category: "Actions",
    },
  ])

  return (
    <DialogSelect
      title={`${props.agentName} Permissions`}
      options={options()}
      onSelect={(option) => {
        if (option.value === "__save__") {
          savePermissions()
        } else if (option.value === "__back__") {
          dialog.replace(() => <DialogAgentSettings />)
        } else {
          togglePermission(option.value as PermissionId)
        }
      }}
    />
  )
}
