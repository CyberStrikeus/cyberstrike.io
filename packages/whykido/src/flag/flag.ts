function truthy(key: string) {
  const value = process.env[key]?.toLowerCase()
  return value === "true" || value === "1"
}

export namespace Flag {
  export const WHYKIDO_AUTO_SHARE = truthy("WHYKIDO_AUTO_SHARE")
  export const WHYKIDO_GIT_BASH_PATH = process.env["WHYKIDO_GIT_BASH_PATH"]
  export const WHYKIDO_CONFIG = process.env["WHYKIDO_CONFIG"]
  export declare const WHYKIDO_CONFIG_DIR: string | undefined
  export const WHYKIDO_CONFIG_CONTENT = process.env["WHYKIDO_CONFIG_CONTENT"]
  export const WHYKIDO_DISABLE_AUTOUPDATE = truthy("WHYKIDO_DISABLE_AUTOUPDATE")
  export const WHYKIDO_DISABLE_PRUNE = truthy("WHYKIDO_DISABLE_PRUNE")
  export const WHYKIDO_DISABLE_TERMINAL_TITLE = truthy("WHYKIDO_DISABLE_TERMINAL_TITLE")
  export const WHYKIDO_PERMISSION = process.env["WHYKIDO_PERMISSION"]
  export const WHYKIDO_DISABLE_DEFAULT_PLUGINS = truthy("WHYKIDO_DISABLE_DEFAULT_PLUGINS")
  export const WHYKIDO_DISABLE_LSP_DOWNLOAD = truthy("WHYKIDO_DISABLE_LSP_DOWNLOAD")
  export const WHYKIDO_ENABLE_EXPERIMENTAL_MODELS = truthy("WHYKIDO_ENABLE_EXPERIMENTAL_MODELS")
  export const WHYKIDO_DISABLE_AUTOCOMPACT = truthy("WHYKIDO_DISABLE_AUTOCOMPACT")
  export const WHYKIDO_DISABLE_MODELS_FETCH = truthy("WHYKIDO_DISABLE_MODELS_FETCH")
  export const WHYKIDO_DISABLE_CLAUDE_CODE = truthy("WHYKIDO_DISABLE_CLAUDE_CODE")
  export const WHYKIDO_DISABLE_CLAUDE_CODE_PROMPT =
    WHYKIDO_DISABLE_CLAUDE_CODE || truthy("WHYKIDO_DISABLE_CLAUDE_CODE_PROMPT")
  export const WHYKIDO_DISABLE_CLAUDE_CODE_SKILLS =
    WHYKIDO_DISABLE_CLAUDE_CODE || truthy("WHYKIDO_DISABLE_CLAUDE_CODE_SKILLS")
  export declare const WHYKIDO_DISABLE_PROJECT_CONFIG: boolean
  export const WHYKIDO_FAKE_VCS = process.env["WHYKIDO_FAKE_VCS"]
  export const WHYKIDO_CLIENT = process.env["WHYKIDO_CLIENT"] ?? "cli"
  export const WHYKIDO_SERVER_PASSWORD = process.env["WHYKIDO_SERVER_PASSWORD"]
  export const WHYKIDO_SERVER_USERNAME = process.env["WHYKIDO_SERVER_USERNAME"]

  // Experimental
  export const WHYKIDO_EXPERIMENTAL = truthy("WHYKIDO_EXPERIMENTAL")
  export const WHYKIDO_EXPERIMENTAL_FILEWATCHER = truthy("WHYKIDO_EXPERIMENTAL_FILEWATCHER")
  export const WHYKIDO_EXPERIMENTAL_DISABLE_FILEWATCHER = truthy("WHYKIDO_EXPERIMENTAL_DISABLE_FILEWATCHER")
  export const WHYKIDO_EXPERIMENTAL_ICON_DISCOVERY =
    WHYKIDO_EXPERIMENTAL || truthy("WHYKIDO_EXPERIMENTAL_ICON_DISCOVERY")
  export const WHYKIDO_EXPERIMENTAL_DISABLE_COPY_ON_SELECT = truthy("WHYKIDO_EXPERIMENTAL_DISABLE_COPY_ON_SELECT")
  export const WHYKIDO_ENABLE_EXA =
    truthy("WHYKIDO_ENABLE_EXA") || WHYKIDO_EXPERIMENTAL || truthy("WHYKIDO_EXPERIMENTAL_EXA")
  export const WHYKIDO_EXPERIMENTAL_BASH_MAX_OUTPUT_LENGTH = number("WHYKIDO_EXPERIMENTAL_BASH_MAX_OUTPUT_LENGTH")
  export const WHYKIDO_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS = number("WHYKIDO_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS")
  export const WHYKIDO_EXPERIMENTAL_OUTPUT_TOKEN_MAX = number("WHYKIDO_EXPERIMENTAL_OUTPUT_TOKEN_MAX")
  export const WHYKIDO_EXPERIMENTAL_OXFMT = WHYKIDO_EXPERIMENTAL || truthy("WHYKIDO_EXPERIMENTAL_OXFMT")
  export const WHYKIDO_EXPERIMENTAL_LSP_TY = truthy("WHYKIDO_EXPERIMENTAL_LSP_TY")
  export const WHYKIDO_EXPERIMENTAL_LSP_TOOL = WHYKIDO_EXPERIMENTAL || truthy("WHYKIDO_EXPERIMENTAL_LSP_TOOL")
  export const WHYKIDO_DISABLE_FILETIME_CHECK = truthy("WHYKIDO_DISABLE_FILETIME_CHECK")
  export const WHYKIDO_EXPERIMENTAL_PLAN_MODE = WHYKIDO_EXPERIMENTAL || truthy("WHYKIDO_EXPERIMENTAL_PLAN_MODE")
  export const WHYKIDO_MODELS_URL = process.env["WHYKIDO_MODELS_URL"]

  function number(key: string) {
    const value = process.env[key]
    if (!value) return undefined
    const parsed = Number(value)
    return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined
  }
}

// Dynamic getter for WHYKIDO_DISABLE_PROJECT_CONFIG
// This must be evaluated at access time, not module load time,
// because external tooling may set this env var at runtime
Object.defineProperty(Flag, "WHYKIDO_DISABLE_PROJECT_CONFIG", {
  get() {
    return truthy("WHYKIDO_DISABLE_PROJECT_CONFIG")
  },
  enumerable: true,
  configurable: false,
})

// Dynamic getter for WHYKIDO_CONFIG_DIR
// This must be evaluated at access time, not module load time,
// because external tooling may set this env var at runtime
Object.defineProperty(Flag, "WHYKIDO_CONFIG_DIR", {
  get() {
    return process.env["WHYKIDO_CONFIG_DIR"]
  },
  enumerable: true,
  configurable: false,
})
