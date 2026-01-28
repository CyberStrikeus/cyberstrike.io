import z from "zod"
import { EOL } from "os"
import { NamedError } from "@cyberstrike/util/error"

export namespace UI {
  // CYBER (left) + STRIKE (right) parts for gradient coloring
  const LOGO_CYBER = [
    `                        `,
    `█▀▀ █░░█ █▀▀▄ █▀▀ █▀▀▄ `,
    `█░░ █▄▄█ █▀▀▄ █▀▀ █▄▄▀ `,
    `▀▀▀ ░░░█ ▀▀▀░ ▀▀▀ ▀░▀▀ `,
  ]
  const LOGO_STRIKE = [
    `                      `,
    `█▀▀ ▀▀█▀▀ █▀▀▄ ▀█▀ █░█ █▀▀`,
    `▀▀█ ░░█░░ █▄▄▀ ░█░ █▀▄ █▀▀`,
    `▀▀▀ ░░▀░░ ▀░▀▀ ▀▀▀ ▀░▀ ▀▀▀`,
  ]

  export const CancelledError = NamedError.create("UICancelledError", z.void())

  export const Style = {
    TEXT_HIGHLIGHT: "\x1b[96m",
    TEXT_HIGHLIGHT_BOLD: "\x1b[96m\x1b[1m",
    TEXT_DIM: "\x1b[90m",
    TEXT_DIM_BOLD: "\x1b[90m\x1b[1m",
    TEXT_NORMAL: "\x1b[0m",
    TEXT_NORMAL_BOLD: "\x1b[1m",
    TEXT_WARNING: "\x1b[93m",
    TEXT_WARNING_BOLD: "\x1b[93m\x1b[1m",
    TEXT_DANGER: "\x1b[91m",
    TEXT_DANGER_BOLD: "\x1b[91m\x1b[1m",
    TEXT_SUCCESS: "\x1b[92m",
    TEXT_SUCCESS_BOLD: "\x1b[92m\x1b[1m",
    TEXT_INFO: "\x1b[94m",
    TEXT_INFO_BOLD: "\x1b[94m\x1b[1m",
  }

  export function println(...message: string[]) {
    print(...message)
    Bun.stderr.write(EOL)
  }

  export function print(...message: string[]) {
    blank = false
    Bun.stderr.write(message.join(" "))
  }

  let blank = false
  export function empty() {
    if (blank) return
    println("" + Style.TEXT_NORMAL)
    blank = true
  }

  // True color ANSI escape codes for neon cyberpunk effect
  const NEON_CYAN = "\x1b[38;2;0;255;255m"        // #00ffff
  const TERMINAL_GREEN = "\x1b[38;2;0;255;136m"   // #00ff88
  const ELECTRIC_BLUE = "\x1b[38;2;0;170;255m"    // #00aaff
  const ACCENT_PURPLE = "\x1b[38;2;170;102;255m"  // #aa66ff
  const DIM = "\x1b[2m"
  const RESET = "\x1b[0m"

  export function logo(pad?: string) {
    const result = []
    for (let i = 0; i < LOGO_CYBER.length; i++) {
      if (pad) result.push(pad)
      result.push(NEON_CYAN)
      result.push(LOGO_CYBER[i])
      result.push(TERMINAL_GREEN)
      result.push(LOGO_STRIKE[i])
      result.push(RESET)
      result.push(EOL)
    }
    return result.join("").trimEnd()
  }

  // Color demo function to show all theme colors
  export function colorDemo() {
    const colors = [
      { name: "NEON CYAN (Primary)", code: NEON_CYAN },
      { name: "TERMINAL GREEN (Secondary)", code: TERMINAL_GREEN },
      { name: "ELECTRIC BLUE (Info)", code: ELECTRIC_BLUE },
      { name: "ACCENT PURPLE", code: ACCENT_PURPLE },
      { name: "WARNING YELLOW", code: "\x1b[38;2;255;221;0m" },
      { name: "DANGER RED", code: "\x1b[38;2;255;51;68m" },
      { name: "ALERT ORANGE", code: "\x1b[38;2;255;153;0m" },
      { name: "MATRIX GREEN", code: "\x1b[38;2;0;255;102m" },
    ]

    const result = []
    result.push(EOL)
    result.push(NEON_CYAN + "╔══════════════════════════════════════════════╗" + RESET + EOL)
    result.push(NEON_CYAN + "║" + RESET + "       CYBERSTRIKE COLOR PALETTE DEMO         " + NEON_CYAN + "║" + RESET + EOL)
    result.push(NEON_CYAN + "╠══════════════════════════════════════════════╣" + RESET + EOL)

    for (const color of colors) {
      result.push(NEON_CYAN + "║ " + RESET)
      result.push(color.code + "████ " + color.name.padEnd(38) + RESET)
      result.push(NEON_CYAN + "║" + RESET + EOL)
    }

    result.push(NEON_CYAN + "╚══════════════════════════════════════════════╝" + RESET + EOL)
    return result.join("")
  }

  export async function input(prompt: string): Promise<string> {
    const readline = require("readline")
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    })

    return new Promise((resolve) => {
      rl.question(prompt, (answer: string) => {
        rl.close()
        resolve(answer.trim())
      })
    })
  }

  export function error(message: string) {
    println(Style.TEXT_DANGER_BOLD + "Error: " + Style.TEXT_NORMAL + message)
  }

  export function markdown(text: string): string {
    return text
  }
}
