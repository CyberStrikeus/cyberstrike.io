import { TextAttributes, RGBA } from "@cyberstrike/tui-core"
import { For, type JSX, createSignal, onMount, onCleanup } from "solid-js"
import { useTheme, tint } from "@tui/context/theme"

// Shadow markers (rendered chars in parens):
// _ = full shadow cell (space with bg=shadow)
// ^ = letter top, shadow bottom (▀ with fg=letter, bg=shadow)
// ~ = shadow top only (▀ with fg=shadow)
const SHADOW_MARKER = /[_^~]/

// Aggressive cyberpunk style logo
const LOGO_CYBER = [
  `┌─────────────────────────┐`,
  `│ ▄████▄ ▓██   ██▓ ▄▄▄▄  │`,
  `│▒██▀ ▀█  ▒██  ██▒▓█████▄│`,
  `│▒▓█    ▄  ▒██ ██░▒██▒ ▄█│`,
  `│▒▓▓▄ ▄██▒ ░ ▐██▓░▒██░█▀ │`,
  `│▒ ▓███▀ ░ ░ ██▒▓░░▓█  ▀█│`,
  `│░ ░▒ ▒  ░  ██▒▒▒ ░▒▓███▀│`,
  `└─────────────────────────┘`,
]

const LOGO_STRIKE = [
  `┌──────────────────────────────────┐`,
  `│ ▓█████  ██▀███    ██████ ▄▄▄█████│`,
  `│ ▓█   ▀ ▓██ ▒ ██▒▒██    ▒ ▓  ██▒ ▓│`,
  `│ ▒███   ▓██ ░▄█ ▒░ ▓██▄   ▒ ▓██░ ▒│`,
  `│ ▒▓█  ▄ ▒██▀▀█▄    ▒   ██▒░ ▓██▓ ░│`,
  `│ ░▒████▒░██▓ ▒██▒▒██████▒▒  ▒██▒ ░│`,
  `│ ░░ ▒░ ░░ ▒▓ ░▒▓░▒ ▒▓▒ ▒ ░  ▒ ░░  │`,
  `└──────────────────────────────────┘`,
]

// Simple compact logo for smaller terminals
const LOGO_LEFT = [`                        `, `█▀▀ █  █ █▀▀▄ █▀▀ █▀▀▄`, `█   ▀▀▀█ █▀▀▄ █▀▀ █▄▄▀`, `▀▀▀   ▀  ▀▀▀  ▀▀▀ ▀ ▀▀`]

const LOGO_RIGHT = [`                       `, `█▀▀ ▀▀█▀▀ █▀▀▄ ▀█▀ █ █ █▀▀`, `▀▀█   █   █▄▄▀  █  █▀  █▀▀`, `▀▀▀   ▀   ▀ ▀▀ ▀▀▀ █ ▀ ▀▀▀`]

// Glitch characters for animation
const GLITCH_CHARS = ['█', '▓', '▒', '░', '╳', '╱', '╲', '▄', '▀']

export function Logo(props: { style?: "compact" | "full" | "animated" }) {
  const { theme } = useTheme()
  const style = props.style ?? "compact"
  const [glitchIndex, setGlitchIndex] = createSignal(-1)

  // Glitch animation effect
  onMount(() => {
    if (style === "animated") {
      const interval = setInterval(() => {
        if (Math.random() > 0.7) {
          setGlitchIndex(Math.floor(Math.random() * 8))
          setTimeout(() => setGlitchIndex(-1), 50)
        }
      }, 200)
      onCleanup(() => clearInterval(interval))
    }
  })

  const renderLine = (line: string, fg: RGBA, bold: boolean): JSX.Element[] => {
    const shadow = tint(theme.background, fg, 0.25)
    const attrs = bold ? TextAttributes.BOLD : undefined
    const elements: JSX.Element[] = []
    let i = 0

    while (i < line.length) {
      const rest = line.slice(i)
      const markerIndex = rest.search(SHADOW_MARKER)

      if (markerIndex === -1) {
        elements.push(
          <text fg={fg} attributes={attrs} selectable={false}>
            {rest}
          </text>,
        )
        break
      }

      if (markerIndex > 0) {
        elements.push(
          <text fg={fg} attributes={attrs} selectable={false}>
            {rest.slice(0, markerIndex)}
          </text>,
        )
      }

      const marker = rest[markerIndex]
      switch (marker) {
        case "_":
          elements.push(
            <text fg={fg} bg={shadow} attributes={attrs} selectable={false}>
              {" "}
            </text>,
          )
          break
        case "^":
          elements.push(
            <text fg={fg} bg={shadow} attributes={attrs} selectable={false}>
              ▀
            </text>,
          )
          break
        case "~":
          elements.push(
            <text fg={shadow} attributes={attrs} selectable={false}>
              ▀
            </text>,
          )
          break
      }

      i += markerIndex + 1
    }

    return elements
  }

  // Full cyberpunk style logo
  if (style === "full" || style === "animated") {
    return (
      <box>
        <For each={LOGO_CYBER}>
          {(line, index) => (
            <box flexDirection="row">
              <text
                fg={glitchIndex() === index() ? theme.warning : theme.primary}
                attributes={TextAttributes.BOLD}
                selectable={false}
              >
                {glitchIndex() === index()
                  ? line.split('').map(c => Math.random() > 0.8 ? GLITCH_CHARS[Math.floor(Math.random() * GLITCH_CHARS.length)] : c).join('')
                  : line}
              </text>
              <text fg={theme.secondary} attributes={TextAttributes.BOLD} selectable={false}>
                {LOGO_STRIKE[index()]}
              </text>
            </box>
          )}
        </For>
        <box flexDirection="row" marginTop={1}>
          <text fg={theme.textMuted} selectable={false}>{"  "}</text>
          <text fg={theme.accent} attributes={TextAttributes.BOLD} selectable={false}>
            ⚡ PENETRATION TESTING FRAMEWORK
          </text>
          <text fg={theme.textMuted} selectable={false}>{" │ "}</text>
          <text fg={theme.success} selectable={false}>v0.1.0</text>
        </box>
      </box>
    )
  }

  // Compact style (default)
  return (
    <box>
      <For each={LOGO_LEFT}>
        {(line, index) => (
          <box flexDirection="row" gap={1}>
            <box flexDirection="row">{renderLine(line, theme.primary, true)}</box>
            <box flexDirection="row">{renderLine(LOGO_RIGHT[index()], theme.secondary, true)}</box>
          </box>
        )}
      </For>
    </box>
  )
}
