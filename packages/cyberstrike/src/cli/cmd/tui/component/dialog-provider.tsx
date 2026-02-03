import { createMemo, createSignal, onMount, Show } from "solid-js"
import { useSync } from "@tui/context/sync"
import { DialogSelect } from "@tui/ui/dialog-select"
import { useDialog } from "@tui/ui/dialog"
import { useSDK } from "../context/sdk"
import { DialogPrompt } from "../ui/dialog-prompt"
import { Link } from "../ui/link"
import { useTheme } from "../context/theme"
import { TextAttributes } from "@cyberstrike-io/tui-core"
import type { ProviderAuthAuthorization } from "@cyberstrike-io/sdk/v2"
import { DialogModel } from "./dialog-model"
import { useKeyboard } from "@cyberstrike-io/tui-solid"
import { Clipboard } from "@tui/util/clipboard"
import { useToast } from "../ui/toast"

// Simplified provider list for initial release
const ENABLED_PROVIDERS = ["openai", "claude-api", "claude-cli", "ollama"] as const

interface SimpleProvider {
  id: string
  name: string
  description: string
}

const SIMPLE_PROVIDERS: SimpleProvider[] = [
  {
    id: "claude-api",
    name: "Claude Code CLI (API)",
    description: "Use your Claude Max/Pro subscription - Fast, real streaming",
  },
  {
    id: "claude-cli",
    name: "Claude Code CLI (Subprocess)",
    description: "Use your Claude Max/Pro subscription - Subprocess mode",
  },
  {
    id: "openai",
    name: "OpenAI",
    description: "GPT-4o, GPT-5 and other OpenAI models",
  },
  {
    id: "ollama",
    name: "Local Llama (Ollama)",
    description: "Run AI locally with Ollama or any OpenAI-compatible API",
  },
]

export function createDialogProviderOptions() {
  const sync = useSync()
  const dialog = useDialog()
  const sdk = useSDK()
  const connected = createMemo(() => new Set(sync.data.provider_next.connected))

  const options = createMemo(() => {
    return SIMPLE_PROVIDERS.map((provider) => {
      const isConnected = connected().has(provider.id)
      return {
        title: provider.name,
        value: provider.id,
        description: provider.description,
        footer: isConnected ? "Connected" : undefined,
        async onSelect() {
          // Claude CLI providers don't need authentication - they use local CLI credentials
          if (provider.id === "claude-cli" || provider.id === "claude-api") {
            dialog.replace(() => <DialogModel providerID={provider.id} />)
            return
          }

          // Ollama / Local Llama needs base URL configuration
          if (provider.id === "ollama") {
            dialog.replace(() => <OllamaMethod />)
            return
          }

          // Other providers use API key
          const methods = sync.data.provider_auth[provider.id] ?? [
            {
              type: "api",
              label: "API key",
            },
          ]
          let index: number | null = 0
          if (methods.length > 1) {
            index = await new Promise<number | null>((resolve) => {
              dialog.replace(
                () => (
                  <DialogSelect
                    title="Select auth method"
                    options={methods.map((x, index) => ({
                      title: x.label,
                      value: index,
                    }))}
                    onSelect={(option) => resolve(option.value)}
                  />
                ),
                () => resolve(null),
              )
            })
          }
          if (index == null) return
          const method = methods[index]
          if (method.type === "oauth") {
            const result = await sdk.client.provider.oauth.authorize({
              providerID: provider.id,
              method: index,
            })
            if (result.data?.method === "code") {
              dialog.replace(() => (
                <CodeMethod
                  providerID={provider.id}
                  title={method.label}
                  index={index}
                  authorization={result.data!}
                />
              ))
            }
            if (result.data?.method === "auto") {
              dialog.replace(() => (
                <AutoMethod
                  providerID={provider.id}
                  title={method.label}
                  index={index}
                  authorization={result.data!}
                />
              ))
            }
          }
          if (method.type === "api") {
            return dialog.replace(() => <ApiMethod providerID={provider.id} title={method.label} />)
          }
        },
      }
    })
  })
  return options
}

export function DialogProvider() {
  const options = createDialogProviderOptions()
  return <DialogSelect title="Connect a provider" options={options()} />
}

interface AutoMethodProps {
  index: number
  providerID: string
  title: string
  authorization: ProviderAuthAuthorization
}
function AutoMethod(props: AutoMethodProps) {
  const { theme } = useTheme()
  const sdk = useSDK()
  const dialog = useDialog()
  const sync = useSync()
  const toast = useToast()

  useKeyboard((evt) => {
    if (evt.name === "c" && !evt.ctrl && !evt.meta) {
      const code = props.authorization.instructions.match(/[A-Z0-9]{4}-[A-Z0-9]{4}/)?.[0] ?? props.authorization.url
      Clipboard.copy(code)
        .then(() => toast.show({ message: "Copied to clipboard", variant: "info" }))
        .catch(toast.error)
    }
  })

  onMount(async () => {
    const result = await sdk.client.provider.oauth.callback({
      providerID: props.providerID,
      method: props.index,
    })
    if (result.error) {
      dialog.clear()
      return
    }
    await sdk.client.instance.dispose()
    await sync.bootstrap()
    dialog.replace(() => <DialogModel providerID={props.providerID} />)
  })

  return (
    <box paddingLeft={2} paddingRight={2} gap={1} paddingBottom={1}>
      <box flexDirection="row" justifyContent="space-between">
        <text attributes={TextAttributes.BOLD} fg={theme.text}>
          {props.title}
        </text>
        <text fg={theme.textMuted}>esc</text>
      </box>
      <box gap={1}>
        <Link href={props.authorization.url} fg={theme.primary} />
        <text fg={theme.textMuted}>{props.authorization.instructions}</text>
      </box>
      <text fg={theme.textMuted}>Waiting for authorization...</text>
      <text fg={theme.text}>
        c <span style={{ fg: theme.textMuted }}>copy</span>
      </text>
    </box>
  )
}

interface CodeMethodProps {
  index: number
  title: string
  providerID: string
  authorization: ProviderAuthAuthorization
}
function CodeMethod(props: CodeMethodProps) {
  const { theme } = useTheme()
  const sdk = useSDK()
  const sync = useSync()
  const dialog = useDialog()
  const [error, setError] = createSignal(false)

  return (
    <DialogPrompt
      title={props.title}
      placeholder="Authorization code"
      onConfirm={async (value) => {
        const { error } = await sdk.client.provider.oauth.callback({
          providerID: props.providerID,
          method: props.index,
          code: value,
        })
        if (!error) {
          await sdk.client.instance.dispose()
          await sync.bootstrap()
          dialog.replace(() => <DialogModel providerID={props.providerID} />)
          return
        }
        setError(true)
      }}
      description={() => (
        <box gap={1}>
          <text fg={theme.textMuted}>{props.authorization.instructions}</text>
          <Link href={props.authorization.url} fg={theme.primary} />
          <Show when={error()}>
            <text fg={theme.error}>Invalid code</text>
          </Show>
        </box>
      )}
    />
  )
}

interface ApiMethodProps {
  providerID: string
  title: string
}
function ApiMethod(props: ApiMethodProps) {
  const dialog = useDialog()
  const sdk = useSDK()
  const sync = useSync()
  const { theme } = useTheme()

  return (
    <DialogPrompt
      title={props.title}
      placeholder="API key"
      description={
        props.providerID === "openai" ? (
          <box gap={1}>
            <text fg={theme.textMuted}>Enter your OpenAI API key from platform.openai.com</text>
            <text fg={theme.text}>
              Get your API key at <span style={{ fg: theme.primary }}>https://platform.openai.com/api-keys</span>
            </text>
          </box>
        ) : props.providerID === "anthropic" ? (
          <box gap={1}>
            <text fg={theme.textMuted}>Enter your Anthropic API key from console.anthropic.com</text>
            <text fg={theme.textMuted}>
              Tip: Use "Claude Code CLI" provider to use your Claude Max subscription instead
            </text>
          </box>
        ) : undefined
      }
      onConfirm={async (value) => {
        if (!value) return
        await sdk.client.auth.set({
          providerID: props.providerID,
          auth: {
            type: "api",
            key: value,
          },
        })
        await sdk.client.instance.dispose()
        await sync.bootstrap()
        dialog.replace(() => <DialogModel providerID={props.providerID} />)
      }}
    />
  )
}

function OllamaMethod() {
  const dialog = useDialog()
  const sdk = useSDK()
  const sync = useSync()
  const { theme } = useTheme()
  const [step, setStep] = createSignal<"url" | "key">("url")
  const [baseUrl, setBaseUrl] = createSignal("http://localhost:11434/v1")

  return (
    <Show
      when={step() === "url"}
      fallback={
        <DialogPrompt
          title="API Key (optional)"
          placeholder="Leave empty if not required"
          description={
            <box gap={1}>
              <text fg={theme.textMuted}>
                Most local Ollama setups don't require an API key.
              </text>
              <text fg={theme.textMuted}>
                Press Enter to skip, or enter a key if your setup requires it.
              </text>
            </box>
          }
          onConfirm={async (value) => {
            // Save ollama config
            await sdk.client.auth.set({
              providerID: "ollama",
              auth: {
                type: "api",
                key: value || "ollama", // Use "ollama" as placeholder if no key
              },
            })
            // Also need to set the base URL in config
            await sdk.client.config.update({
              config: {
                provider: {
                  ollama: {
                    options: {
                      baseURL: baseUrl(),
                    },
                  },
                },
              },
            })
            await sdk.client.instance.dispose()
            await sync.bootstrap()
            dialog.replace(() => <DialogModel providerID="ollama" />)
          }}
        />
      }
    >
      <DialogPrompt
        title="Ollama Base URL"
        placeholder="http://localhost:11434/v1"
        description={
          <box gap={1}>
            <text fg={theme.textMuted}>
              Enter the base URL of your Ollama or OpenAI-compatible API server.
            </text>
            <text fg={theme.text}>
              Default: <span style={{ fg: theme.primary }}>http://localhost:11434/v1</span>
            </text>
            <text fg={theme.textMuted}>
              Make sure Ollama is running: <span style={{ fg: theme.accent }}>ollama serve</span>
            </text>
          </box>
        }
        onConfirm={async (value) => {
          setBaseUrl(value || "http://localhost:11434/v1")
          setStep("key")
        }}
      />
    </Show>
  )
}
