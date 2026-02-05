import { createMemo, createSignal, Show } from "solid-js"
import { useLocal } from "@tui/context/local"
import { useSync } from "@tui/context/sync"
import { map, pipe, entries, sortBy, filter } from "remeda"
import { DialogSelect, type DialogSelectRef, type DialogSelectOption } from "@tui/ui/dialog-select"
import { useTheme } from "../context/theme"
import { Keybind } from "@/util/keybind"
import { TextAttributes } from "@cyberstrike-io/tui-core"
import { useDialog } from "@tui/ui/dialog"
import { useToast } from "@tui/ui/toast"
import { useSDK } from "@tui/context/sdk"
import { Global } from "@/global"
import { modify, applyEdits } from "jsonc-parser"
import path from "path"

// Get MCP type indicator
function getMcpType(config: any): "local" | "remote" | "unknown" {
  if (!config || typeof config !== "object") return "unknown"
  if (config.type === "local" || config.command) return "local"
  if (config.type === "remote" || config.url) return "remote"
  return "unknown"
}

// Check if it's a Bolt server (for special indicator)
function isBoltServer(name: string, config: any): boolean {
  if (!config || typeof config !== "object") return false
  return config.bolt === true || name.startsWith("bolt-") || name === "bolt"
}

function Status(props: { status: string; loading: boolean; type: "local" | "remote" | "unknown"; isBolt: boolean }) {
  const { theme } = useTheme()
  if (props.loading) {
    return <span style={{ fg: theme.textMuted }}>⋯ Connecting</span>
  }

  const typeIndicator = props.isBolt ? "⚡" : props.type === "local" ? "◆" : "◇"

  switch (props.status) {
    case "connected":
      return <span style={{ fg: theme.success, attributes: TextAttributes.BOLD }}>{typeIndicator} Connected</span>
    case "disabled":
      return <span style={{ fg: theme.textMuted }}>{typeIndicator} Disabled</span>
    case "failed":
      return <span style={{ fg: theme.error }}>{typeIndicator} Failed</span>
    case "needs_auth":
      return <span style={{ fg: theme.warning }}>{typeIndicator} Needs Auth</span>
    default:
      return <span style={{ fg: theme.textMuted }}>{typeIndicator} {props.status}</span>
  }
}

export function DialogBolt() {
  const local = useLocal()
  const sync = useSync()
  const sdk = useSDK()
  const dialog = useDialog()
  const toast = useToast()
  const [, setRef] = createSignal<DialogSelectRef<unknown>>()
  const [loading, setLoading] = createSignal<string | null>(null)

  // Get ALL MCP servers (both local and remote)
  const mcpServers = createMemo(() => {
    const mcpData = sync.data.mcp ?? {}
    const configData = sync.data.config?.mcp ?? {}

    return pipe(
      entries(mcpData),
      sortBy(([name, status]) => {
        // Sort: connected first, then by name
        const statusOrder = status.status === "connected" ? 0 : status.status === "disabled" ? 2 : 1
        return `${statusOrder}-${name}`
      }),
    )
  })

  const options = createMemo(() => {
    const loadingName = loading()
    const servers = mcpServers()
    const configData = sync.data.config?.mcp ?? {}

    const serverOptions = servers.map(([name, status]) => {
      const config = (configData as any)?.[name]
      const mcpType = getMcpType(config)
      const isBolt = isBoltServer(name, config)
      const description = mcpType === "local"
        ? (config?.command?.join(" ") || "Local server")
        : (config?.url || "Remote server")

      return {
        value: name,
        title: name,
        description,
        footer: <Status status={status.status} loading={loadingName === name} type={mcpType} isBolt={isBolt} />,
      }
    })

    // Always show "Add MCP Server" option at the end
    return [
      ...serverOptions,
      {
        value: "__add__",
        title: "Add MCP Server",
        description: "Connect local or remote MCP server",
        footer: <span style={{ fg: useTheme().theme.accent }}>+ Add</span>,
      },
    ]
  })

  const keybinds = createMemo(() => [
    {
      keybind: Keybind.parse("space")[0],
      title: "toggle",
      onTrigger: async (option: DialogSelectOption<string>) => {
        if (option.value === "__add__") {
          dialog.replace(() => <DialogBoltAdd />)
          return
        }
        if (loading() !== null) return

        setLoading(option.value)
        try {
          await local.mcp.toggle(option.value)
          // Refresh MCP status from server
          const status = await sdk.client.mcp.status()
          if (status.data) {
            sync.set("mcp", status.data)
          }
        } catch (error) {
          console.error("Failed to toggle MCP:", error)
          toast.show({ message: `Failed to toggle: ${error}`, variant: "error" })
        } finally {
          setLoading(null)
        }
      },
    },
    {
      keybind: Keybind.parse("a")[0],
      title: "add",
      onTrigger: () => {
        dialog.replace(() => <DialogBoltAdd />)
      },
    },
    {
      keybind: Keybind.parse("d")[0],
      title: "delete",
      onTrigger: async (option: DialogSelectOption<string>) => {
        if (option.value === "__add__") return
        dialog.replace(() => <DialogBoltDelete name={option.value} />)
      },
    },
  ])

  return (
    <DialogSelect
      ref={setRef}
      title="⚡ Bolt - MCP Servers"
      options={options()}
      keybind={keybinds()}
      onSelect={(option) => {
        if (option.value === "__add__") {
          dialog.replace(() => <DialogBoltAdd />)
        }
      }}
    />
  )
}

function DialogBoltAdd() {
  const dialog = useDialog()
  const toast = useToast()
  const sdk = useSDK()
  const sync = useSync()
  const { theme } = useTheme()
  const [step, setStep] = createSignal<"type" | "url" | "command" | "token" | "name">("type")
  const [mcpType, setMcpType] = createSignal<"local" | "remote">("remote")
  const [url, setUrl] = createSignal("")
  const [command, setCommand] = createSignal("")
  const [adminToken, setAdminToken] = createSignal("")
  const [name, setName] = createSignal("")
  const [saving, setSaving] = createSignal(false)

  async function handleSubmit() {
    setSaving(true)
    try {
      let serverName: string
      let mcpConfig: any

      if (mcpType() === "remote") {
        serverName = name() || `mcp-${new URL(url()).hostname.replace(/\./g, "-")}`
        const serverUrl = url().replace(/\/$/, "")

        mcpConfig = {
          type: "remote",
          url: `${serverUrl}/mcp`,
          headers: adminToken() ? {
            Authorization: `Bearer ${adminToken()}`
          } : undefined,
        }
      } else {
        // Local MCP
        const cmdParts = command().split(/\s+/).filter(Boolean)
        serverName = name() || `mcp-${cmdParts[0] || "local"}`

        mcpConfig = {
          type: "local",
          command: cmdParts,
        }
      }

      // Add MCP to config file
      const configPath = path.join(Global.Path.config, "cyberstrike.json")
      const file = Bun.file(configPath)

      let text = "{}"
      if (await file.exists()) {
        text = await file.text()
      }

      // Use jsonc-parser to modify while preserving comments
      const edits = modify(text, ["mcp", serverName], mcpConfig, {
        formattingOptions: { tabSize: 2, insertSpaces: true },
      })
      const result = applyEdits(text, edits)

      await Bun.write(configPath, result)

      // Add MCP to running system
      await sdk.client.mcp.add({ name: serverName, config: mcpConfig as any })
      const status = await sdk.client.mcp.status()
      if (status.data) {
        sync.set("mcp", status.data)
      }

      toast.show({ message: `Added ${serverName}`, variant: "success" })
      dialog.replace(() => <DialogBolt />)
    } catch (error) {
      console.error("Failed to add MCP server:", error)
      toast.show({ message: `Failed to add: ${error}`, variant: "error" })
    } finally {
      setSaving(false)
    }
  }

  return (
    <box gap={1} paddingBottom={1}>
      <box paddingLeft={4} paddingRight={4}>
        <box flexDirection="row" justifyContent="space-between">
          <text fg={theme.text} attributes={TextAttributes.BOLD}>
            ⚡ Add MCP Server
          </text>
          <text fg={theme.textMuted}>esc</text>
        </box>

        {/* Step 1: Choose type */}
        <Show when={step() === "type"}>
          <box paddingTop={1}>
            <text fg={theme.textMuted}>Select MCP server type:</text>
            <box paddingTop={1} flexDirection="row" gap={2}>
              <box
                backgroundColor={mcpType() === "remote" ? theme.primary : theme.backgroundPanel}
                padding={1}
                onMouseUp={() => setMcpType("remote")}
              >
                <text fg={mcpType() === "remote" ? theme.background : theme.text}>
                  ◇ Remote (HTTP)
                </text>
              </box>
              <box
                backgroundColor={mcpType() === "local" ? theme.primary : theme.backgroundPanel}
                padding={1}
                onMouseUp={() => setMcpType("local")}
              >
                <text fg={mcpType() === "local" ? theme.background : theme.text}>
                  ◆ Local (Command)
                </text>
              </box>
            </box>
            <text fg={theme.textMuted} paddingTop={1}>
              {mcpType() === "remote"
                ? "Connect to a remote MCP server via HTTP (e.g., Bolt container)"
                : "Run a local MCP server as a child process"}
            </text>
            <box paddingTop={2}>
              <box
                backgroundColor={theme.primary}
                padding={1}
                onMouseUp={() => setStep(mcpType() === "remote" ? "url" : "command")}
              >
                <text fg={theme.background} attributes={TextAttributes.BOLD}>
                  Next
                </text>
              </box>
            </box>
          </box>
        </Show>

        {/* Step 2a: URL for remote */}
        <Show when={step() === "url"}>
          <box paddingTop={1}>
            <text fg={theme.textMuted}>Enter the MCP server URL:</text>
            <box paddingTop={1}>
              <input
                onInput={setUrl}
                focusedBackgroundColor={theme.backgroundPanel}
                cursorColor={theme.primary}
                focusedTextColor={theme.text}
                placeholder="http://localhost:3001"
                ref={(r) => setTimeout(() => r.focus(), 1)}
                onKeyDown={(evt) => {
                  if (evt.name === "return" && url().length > 0) {
                    try {
                      new URL(url())
                      setStep("token")
                    } catch {
                      toast.show({ message: "Invalid URL", variant: "error" })
                    }
                  }
                }}
              />
            </box>
          </box>
        </Show>

        {/* Step 2b: Command for local */}
        <Show when={step() === "command"}>
          <box paddingTop={1}>
            <text fg={theme.textMuted}>Enter the command to run the MCP server:</text>
            <box paddingTop={1}>
              <input
                onInput={setCommand}
                focusedBackgroundColor={theme.backgroundPanel}
                cursorColor={theme.primary}
                focusedTextColor={theme.text}
                placeholder="npx @cyberstrike/mcp-kali"
                ref={(r) => setTimeout(() => r.focus(), 1)}
                onKeyDown={(evt) => {
                  if (evt.name === "return" && command().length > 0) {
                    setStep("name")
                  }
                }}
              />
            </box>
            <text fg={theme.textMuted} paddingTop={1}>
              Examples: npx @modelcontextprotocol/server-filesystem /path
            </text>
          </box>
        </Show>

        {/* Step 3: Token (remote only) */}
        <Show when={step() === "token"}>
          <box paddingTop={1}>
            <text fg={theme.textMuted}>
              Enter authentication token (optional):
            </text>
            <box paddingTop={1}>
              <input
                onInput={setAdminToken}
                focusedBackgroundColor={theme.backgroundPanel}
                cursorColor={theme.primary}
                focusedTextColor={theme.text}
                placeholder="Bearer token or leave empty"
                ref={(r) => setTimeout(() => r.focus(), 1)}
                onKeyDown={(evt) => {
                  if (evt.name === "return") {
                    setStep("name")
                  }
                }}
              />
            </box>
            <text fg={theme.textMuted} paddingTop={1}>
              For Bolt: get token from <span style={{ fg: theme.accent }}>docker logs bolt</span>
            </text>
          </box>
        </Show>

        {/* Step 4: Name */}
        <Show when={step() === "name"}>
          <box paddingTop={1}>
            <text fg={theme.textMuted}>Give this server a name (optional):</text>
            <box paddingTop={1}>
              <input
                onInput={setName}
                focusedBackgroundColor={theme.backgroundPanel}
                cursorColor={theme.primary}
                focusedTextColor={theme.text}
                placeholder={mcpType() === "remote"
                  ? `mcp-${(() => { try { return new URL(url()).hostname.replace(/\./g, "-") } catch { return "server" } })()}`
                  : `mcp-${command().split(/\s+/)[0] || "local"}`
                }
                ref={(r) => setTimeout(() => r.focus(), 1)}
                onKeyDown={(evt) => {
                  if (evt.name === "return" && !saving()) {
                    handleSubmit()
                  }
                }}
              />
            </box>
          </box>
        </Show>

        {/* Navigation buttons */}
        <box paddingTop={2} flexDirection="row" gap={2}>
          <Show when={step() !== "type"}>
            <box
              backgroundColor={theme.backgroundPanel}
              padding={1}
              onMouseUp={() => {
                if (step() === "name") {
                  setStep(mcpType() === "remote" ? "token" : "command")
                } else if (step() === "token") {
                  setStep("url")
                } else if (step() === "url" || step() === "command") {
                  setStep("type")
                }
              }}
            >
              <text fg={theme.text}>Back</text>
            </box>
          </Show>
          <Show when={step() === "name"}>
            <box
              backgroundColor={saving() ? theme.backgroundPanel : theme.primary}
              padding={1}
              onMouseUp={() => !saving() && handleSubmit()}
            >
              <text fg={theme.background} attributes={TextAttributes.BOLD}>
                {saving() ? "Adding..." : "Add Server"}
              </text>
            </box>
          </Show>
        </box>
      </box>
    </box>
  )
}

function DialogBoltDelete(props: { name: string }) {
  const dialog = useDialog()
  const toast = useToast()
  const sdk = useSDK()
  const sync = useSync()
  const { theme } = useTheme()
  const [deleting, setDeleting] = createSignal(false)

  const config = () => (sync.data.config?.mcp as any)?.[props.name]
  const mcpType = () => getMcpType(config())
  const serverInfo = () => {
    const cfg = config()
    if (mcpType() === "local") {
      return cfg?.command?.join(" ") || "Local server"
    }
    return cfg?.url || "Remote server"
  }

  async function handleDelete() {
    setDeleting(true)
    try {
      // Remove from config file
      const configPath = path.join(Global.Path.config, "cyberstrike.json")
      const file = Bun.file(configPath)

      if (await file.exists()) {
        const text = await file.text()

        // Use jsonc-parser to remove the entry
        const edits = modify(text, ["mcp", props.name], undefined, {
          formattingOptions: { tabSize: 2, insertSpaces: true },
        })
        const result = applyEdits(text, edits)

        await Bun.write(configPath, result)
      }

      // Disconnect the MCP (will be removed on restart)
      await sdk.client.mcp.disconnect({ name: props.name }).catch(() => {})
      const status = await sdk.client.mcp.status()
      if (status.data) {
        sync.set("mcp", status.data)
      }

      toast.show({ message: `Removed ${props.name}`, variant: "info" })
      dialog.replace(() => <DialogBolt />)
    } catch (error) {
      console.error("Failed to delete MCP server:", error)
      toast.show({ message: `Failed to delete: ${error}`, variant: "error" })
    } finally {
      setDeleting(false)
    }
  }

  return (
    <box gap={1} paddingBottom={1}>
      <box paddingLeft={4} paddingRight={4}>
        <box flexDirection="row" justifyContent="space-between">
          <text fg={theme.text} attributes={TextAttributes.BOLD}>
            Delete MCP Server
          </text>
          <text fg={theme.textMuted}>esc</text>
        </box>

        <box paddingTop={1}>
          <text fg={theme.text}>
            Are you sure you want to remove <span style={{ fg: theme.accent }}>{props.name}</span>?
          </text>
          <text fg={theme.textMuted} paddingTop={1}>
            {mcpType() === "local" ? "◆ Local: " : "◇ Remote: "}{serverInfo()}
          </text>
        </box>

        <box paddingTop={2} flexDirection="row" gap={2}>
          <box
            backgroundColor={theme.backgroundPanel}
            padding={1}
            onMouseUp={() => dialog.replace(() => <DialogBolt />)}
          >
            <text fg={theme.text}>Cancel</text>
          </box>
          <box
            backgroundColor={deleting() ? theme.backgroundPanel : theme.error}
            padding={1}
            onMouseUp={() => !deleting() && handleDelete()}
          >
            <text fg={theme.background} attributes={TextAttributes.BOLD}>
              {deleting() ? "Deleting..." : "Delete"}
            </text>
          </box>
        </box>
      </box>
    </box>
  )
}
