import { UI } from "../ui"
import { EOL } from "os"

// ANSI color codes
const RESET = "\x1b[0m"
const BOLD = "\x1b[1m"
const DIM = "\x1b[2m"

const NEON_CYAN = "\x1b[38;2;0;255;255m"
const TERMINAL_GREEN = "\x1b[38;2;0;255;136m"
const ELECTRIC_BLUE = "\x1b[38;2;0;170;255m"
const ACCENT_PURPLE = "\x1b[38;2;170;102;255m"
const WARNING_YELLOW = "\x1b[38;2;255;221;0m"
const DANGER_RED = "\x1b[38;2;255;51;68m"
const ALERT_ORANGE = "\x1b[38;2;255;153;0m"
const MATRIX_GREEN = "\x1b[38;2;0;255;102m"
const MOON_GLOW = "\x1b[38;2;120;120;160m"
const STAR_LIGHT = "\x1b[38;2;184;184;216m"

export async function demo() {
  const write = (text: string) => process.stdout.write(text)

  // Clear screen
  write("\x1b[2J\x1b[H")

  // Logo
  write(UI.logo() + EOL + EOL)

  // Color palette
  write(UI.colorDemo())

  // Status bar demo
  write(EOL)
  write(NEON_CYAN + "┌─────────────────────────────────────────────────────────────────────────┐" + RESET + EOL)
  write(NEON_CYAN + "│" + RESET)
  write(WARNING_YELLOW + " ⎯ TARGET: " + RESET + "192.168.1.100")
  write(MOON_GLOW + " │ " + RESET)
  write(ELECTRIC_BLUE + "◉ SESSIONS: " + RESET + "3")
  write(MOON_GLOW + " │ " + RESET)
  write(MATRIX_GREEN + "⚙ TOOLS: " + RESET + "2")
  write(MOON_GLOW + " │ " + RESET)
  write(NEON_CYAN + "⏱ 14:32:45" + RESET)
  write("        " + NEON_CYAN + "│" + RESET + EOL)
  write(NEON_CYAN + "└─────────────────────────────────────────────────────────────────────────┘" + RESET + EOL)

  // Sample session output
  write(EOL)
  write(NEON_CYAN + "═══════════════════════════════════════════════════════════════════════════" + RESET + EOL)
  write(BOLD + STAR_LIGHT + " SESSION OUTPUT DEMO" + RESET + EOL)
  write(NEON_CYAN + "═══════════════════════════════════════════════════════════════════════════" + RESET + EOL)
  write(EOL)

  // Simulated scan output
  write(MOON_GLOW + "[" + RESET + NEON_CYAN + "14:32:01" + RESET + MOON_GLOW + "] " + RESET)
  write(TERMINAL_GREEN + "Starting reconnaissance scan..." + RESET + EOL)

  write(MOON_GLOW + "[" + RESET + NEON_CYAN + "14:32:02" + RESET + MOON_GLOW + "] " + RESET)
  write(ELECTRIC_BLUE + "→ " + RESET + "Scanning target: " + WARNING_YELLOW + "192.168.1.100" + RESET + EOL)

  write(MOON_GLOW + "[" + RESET + NEON_CYAN + "14:32:05" + RESET + MOON_GLOW + "] " + RESET)
  write(MATRIX_GREEN + "✓ " + RESET + "Port " + BOLD + "22/tcp" + RESET + " open - " + TERMINAL_GREEN + "SSH" + RESET + EOL)

  write(MOON_GLOW + "[" + RESET + NEON_CYAN + "14:32:05" + RESET + MOON_GLOW + "] " + RESET)
  write(MATRIX_GREEN + "✓ " + RESET + "Port " + BOLD + "80/tcp" + RESET + " open - " + TERMINAL_GREEN + "HTTP" + RESET + EOL)

  write(MOON_GLOW + "[" + RESET + NEON_CYAN + "14:32:06" + RESET + MOON_GLOW + "] " + RESET)
  write(MATRIX_GREEN + "✓ " + RESET + "Port " + BOLD + "443/tcp" + RESET + " open - " + TERMINAL_GREEN + "HTTPS" + RESET + EOL)

  write(MOON_GLOW + "[" + RESET + NEON_CYAN + "14:32:08" + RESET + MOON_GLOW + "] " + RESET)
  write(WARNING_YELLOW + "⚠ " + RESET + "Potential vulnerability detected: " + DANGER_RED + "CVE-2024-1234" + RESET + EOL)

  write(MOON_GLOW + "[" + RESET + NEON_CYAN + "14:32:10" + RESET + MOON_GLOW + "] " + RESET)
  write(ACCENT_PURPLE + "◆ " + RESET + "Running exploit module: " + ACCENT_PURPLE + "apache_struts_rce" + RESET + EOL)

  write(MOON_GLOW + "[" + RESET + NEON_CYAN + "14:32:15" + RESET + MOON_GLOW + "] " + RESET)
  write(MATRIX_GREEN + "★ " + BOLD + "SUCCESS" + RESET + " - Shell obtained!" + EOL)

  // Code block demo
  write(EOL)
  write(NEON_CYAN + "───────────────────────────────────────────────────────────────────────────" + RESET + EOL)
  write(BOLD + STAR_LIGHT + " CODE SYNTAX HIGHLIGHTING" + RESET + EOL)
  write(NEON_CYAN + "───────────────────────────────────────────────────────────────────────────" + RESET + EOL)
  write(EOL)

  // Python code example
  write(MOON_GLOW + "  1 │ " + RESET + NEON_CYAN + "import" + RESET + " socket" + EOL)
  write(MOON_GLOW + "  2 │ " + RESET + NEON_CYAN + "import" + RESET + " subprocess" + EOL)
  write(MOON_GLOW + "  3 │ " + RESET + EOL)
  write(MOON_GLOW + "  4 │ " + RESET + NEON_CYAN + "def" + RESET + " " + ELECTRIC_BLUE + "connect" + RESET + "(" + STAR_LIGHT + "host" + RESET + ", " + STAR_LIGHT + "port" + RESET + "):" + EOL)
  write(MOON_GLOW + "  5 │ " + RESET + "    s = socket." + ELECTRIC_BLUE + "socket" + RESET + "()" + EOL)
  write(MOON_GLOW + "  6 │ " + RESET + "    s." + ELECTRIC_BLUE + "connect" + RESET + "((" + TERMINAL_GREEN + `"192.168.1.100"` + RESET + ", " + ALERT_ORANGE + "4444" + RESET + "))" + EOL)
  write(MOON_GLOW + "  7 │ " + RESET + "    " + NEON_CYAN + "return" + RESET + " s" + EOL)

  write(EOL)
  write(NEON_CYAN + "═══════════════════════════════════════════════════════════════════════════" + RESET + EOL)

  // Only wait for keypress if stdin is a TTY
  if (process.stdin.isTTY) {
    write(MOON_GLOW + "  Press any key to exit demo..." + RESET + EOL)
    process.stdin.setRawMode(true)
    process.stdin.resume()
    await new Promise<void>((resolve) => {
      process.stdin.once("data", () => {
        process.stdin.setRawMode(false)
        resolve()
      })
    })
  } else {
    write(MOON_GLOW + "  Demo complete." + RESET + EOL)
  }
}
