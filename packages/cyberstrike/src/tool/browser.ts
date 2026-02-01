import z from "zod"
import { Tool } from "./tool"
import DESCRIPTION from "./browser.txt"
import path from "path"
import { Instance } from "../project/instance"
import { Log } from "../util/log"
import { CYBERSTRIKE_CONTROL_PAGE } from "./browser-ui"

const log = Log.create({ service: "tool.browser" })

// Cyberstrike browser injection script - adds banner and border like Claude
const CYBERSTRIKE_INJECTION = `
(function() {
  // Skip injection on the Cyberstrike control page
  if (document.title === 'Cyberstrike Browser' || window.__cyberstrike_injected) return;
  window.__cyberstrike_injected = true;

  // Add styles
  const style = document.createElement('style');
  style.textContent = \`
    /* Navy blue border around page */
    html {
      border: 3px solid #1e3a5f !important;
      box-sizing: border-box !important;
    }

    /* Top banner */
    #cyberstrike-banner {
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      right: 0 !important;
      z-index: 2147483647 !important;
      background: linear-gradient(to bottom, #1e3a5f, #152a45) !important;
      border-bottom: 1px solid #0f2337 !important;
      padding: 8px 16px !important;
      display: flex !important;
      align-items: center !important;
      gap: 12px !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
      font-size: 13px !important;
      color: #e2e8f0 !important;
      box-shadow: 0 2px 4px rgba(0,0,0,0.3) !important;
    }

    #cyberstrike-banner button {
      background: rgba(255,255,255,0.15) !important;
      border: 1px solid rgba(255,255,255,0.2) !important;
      border-radius: 4px !important;
      padding: 4px 12px !important;
      font-size: 12px !important;
      color: #e2e8f0 !important;
      cursor: pointer !important;
    }

    #cyberstrike-banner button:hover {
      background: rgba(255,255,255,0.25) !important;
    }

    /* Push body content down */
    body {
      margin-top: 40px !important;
    }
  \`;

  // Create banner
  const banner = document.createElement('div');
  banner.id = 'cyberstrike-banner';
  banner.innerHTML = '<span>"Cyberstrike" started debugging this browser</span><button onclick="window.close()">Cancel</button>';

  // Insert when ready
  function insert() {
    if (!document.getElementById('cyberstrike-banner')) {
      document.head?.appendChild(style);
      document.body?.insertBefore(banner, document.body.firstChild);
    }
  }

  if (document.body) {
    insert();
  } else {
    document.addEventListener('DOMContentLoaded', insert);
  }
})();
`

// Browser state management
interface BrowserState {
  browser: any // Playwright Browser
  context: any // Playwright BrowserContext
  page: any // Playwright Page
  networkLogs: NetworkEntry[]
  consoleLogs: ConsoleEntry[]
  harPath: string
}

interface NetworkEntry {
  timestamp: number
  method: string
  url: string
  status?: number
  statusText?: string
  requestHeaders: Record<string, string>
  responseHeaders?: Record<string, string>
  requestBody?: string
  responseBody?: string
  resourceType: string
  duration?: number
}

interface ConsoleEntry {
  timestamp: number
  type: string
  text: string
  location?: string
}

// Global browser state (per session)
const browserStates = new Map<string, BrowserState>()

async function getPlaywright() {
  try {
    const pw = await import("playwright")
    return pw
  } catch (e) {
    throw new Error(
      "Playwright is not installed. Run: bun add playwright && bunx playwright install chromium",
    )
  }
}

async function launchBrowser(sessionID: string): Promise<BrowserState> {
  if (browserStates.has(sessionID)) {
    return browserStates.get(sessionID)!
  }

  const playwright = await getPlaywright()
  const harPath = path.join(Instance.directory, `cyberstrike-session-${sessionID}.har`)

  log.info("Launching Cyberstrike browser", { harPath })

  // Launch browser
  const browser = await playwright.chromium.launch({
    headless: false,
    args: [
      "--disable-web-security",
      "--disable-features=IsolateOrigins,site-per-process",
    ],
  })

  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    ignoreHTTPSErrors: true,
    recordHar: { path: harPath },
  })

  // Inject Cyberstrike banner and border on every page (except control page)
  await context.addInitScript(CYBERSTRIKE_INJECTION)

  // Create the Cyberstrike control page (first tab)
  const controlPage = await context.newPage()
  await controlPage.setContent(CYBERSTRIKE_CONTROL_PAGE, { waitUntil: "domcontentloaded" })

  // Create the main working page for testing (second tab)
  const page = await context.newPage()

  const state: BrowserState = {
    browser,
    context,
    page,
    networkLogs: [],
    consoleLogs: [],
    harPath,
  }

  // Capture network traffic
  page.on("request", (request: any) => {
    const entry: NetworkEntry = {
      timestamp: Date.now(),
      method: request.method(),
      url: request.url(),
      requestHeaders: request.headers(),
      requestBody: request.postData() || undefined,
      resourceType: request.resourceType(),
    }
    state.networkLogs.push(entry)
  })

  page.on("response", async (response: any) => {
    const url = response.url()
    const entry = state.networkLogs.find((e) => e.url === url && !e.status)
    if (entry) {
      entry.status = response.status()
      entry.statusText = response.statusText()
      entry.responseHeaders = response.headers()
      entry.duration = Date.now() - entry.timestamp

      try {
        const contentType = response.headers()["content-type"] || ""
        if (
          contentType.includes("text") ||
          contentType.includes("json") ||
          contentType.includes("javascript") ||
          contentType.includes("xml")
        ) {
          entry.responseBody = await response.text().catch(() => undefined)
        }
      } catch {
        // Ignore body capture errors
      }
    }
  })

  // Capture console logs
  page.on("console", (msg: any) => {
    state.consoleLogs.push({
      timestamp: Date.now(),
      type: msg.type(),
      text: msg.text(),
      location: msg.location()?.url,
    })
  })

  // Capture page errors
  page.on("pageerror", (error: any) => {
    state.consoleLogs.push({
      timestamp: Date.now(),
      type: "error",
      text: error.message,
    })
  })

  // Handle browser disconnect (user closes browser)
  browser.on("disconnected", () => {
    log.info("Browser closed by user, HAR saved", { harPath })
    browserStates.delete(sessionID)
  })

  browserStates.set(sessionID, state)
  return state
}

async function closeBrowser(sessionID: string): Promise<string | undefined> {
  const state = browserStates.get(sessionID)
  if (state) {
    const harPath = state.harPath
    await state.context.close()
    await state.browser.close()
    browserStates.delete(sessionID)
    return harPath
  }
  return undefined
}

function getState(sessionID: string): BrowserState | undefined {
  return browserStates.get(sessionID)
}

const FilterSchema = z.object({
  urlPattern: z.string().optional(),
  method: z.string().optional(),
  statusCode: z.number().optional(),
  resourceType: z.string().optional(),
})

const BrowserParams = z.object({
  action: z
    .enum(["launch", "navigate", "screenshot", "execute", "network", "har", "console", "close", "click", "fill", "wait", "status", "content"])
    .describe("The browser action to perform"),
  url: z.string().optional().describe("URL for navigate action"),
  script: z.string().optional().describe("JavaScript code for execute action"),
  selector: z.string().optional().describe("CSS selector for screenshot (element), click, or fill actions"),
  value: z.string().optional().describe("Value for fill action"),
  fullPage: z.boolean().optional().default(true).describe("Capture full page screenshot"),
  timeout: z.number().optional().default(30000).describe("Timeout in milliseconds"),
  filter: FilterSchema.optional().describe("Filter for network logs"),
})

type BrowserParamsType = z.infer<typeof BrowserParams>

export const BrowserTool = Tool.define("browser", {
  description: DESCRIPTION,
  parameters: BrowserParams,
  async execute(params: BrowserParamsType, ctx) {
    const sessionID = ctx.sessionID

    // Permission check for browser automation
    await ctx.ask({
      permission: "browser",
      patterns: params.url ? [params.url] : ["*"],
      always: ["*"],
      metadata: {
        action: params.action,
        url: params.url,
      },
    })

    switch (params.action) {
      case "launch": {
        const state = await launchBrowser(sessionID)
        return {
          title: "Browser launched",
          output: `Browser launched with Cyberstrike extension.\nNetwork capture active.\nHAR will be saved to: ${state.harPath}\n\nUse navigate action to go to a URL.`,
          metadata: { action: "launch" },
        }
      }

      case "navigate": {
        if (!params.url) {
          throw new Error("URL is required for navigate action")
        }
        const state = getState(sessionID)
        if (!state) {
          throw new Error("Browser not launched. Use launch action first.")
        }

        await state.page.goto(params.url, {
          waitUntil: "networkidle",
          timeout: params.timeout,
        })

        const title = await state.page.title()
        const url = state.page.url()

        return {
          title: `Navigated to ${url}`,
          output: `Page loaded: ${title}\nURL: ${url}\nNetwork requests captured: ${state.networkLogs.length}`,
          metadata: { action: "navigate" },
        }
      }

      case "screenshot": {
        const state = getState(sessionID)
        if (!state) {
          throw new Error("Browser not launched. Use launch action first.")
        }

        const filename = `screenshot-${Date.now()}.png`
        const filepath = path.join(Instance.directory, filename)

        if (params.selector) {
          const element = await state.page.$(params.selector)
          if (!element) {
            throw new Error(`Element not found: ${params.selector}`)
          }
          await element.screenshot({ path: filepath })
        } else {
          await state.page.screenshot({
            path: filepath,
            fullPage: params.fullPage,
          })
        }

        return {
          title: "Screenshot captured",
          output: `Screenshot saved: ${filepath}`,
          metadata: { action: "screenshot" },
        }
      }

      case "execute": {
        if (!params.script) {
          throw new Error("Script is required for execute action")
        }
        const state = getState(sessionID)
        if (!state) {
          throw new Error("Browser not launched. Use launch action first.")
        }

        const result = await state.page.evaluate(params.script)
        const output = typeof result === "object" ? JSON.stringify(result, null, 2) : String(result)

        return {
          title: "JavaScript executed",
          output: output || "(no return value)",
          metadata: { action: "execute" },
        }
      }

      case "network": {
        const state = getState(sessionID)
        if (!state) {
          throw new Error("Browser not launched. Use launch action first.")
        }

        let logs = state.networkLogs

        if (params.filter) {
          const { urlPattern, method, statusCode, resourceType } = params.filter
          logs = logs.filter((entry) => {
            if (urlPattern && !entry.url.includes(urlPattern)) return false
            if (method && entry.method !== method.toUpperCase()) return false
            if (statusCode && entry.status !== statusCode) return false
            if (resourceType && entry.resourceType !== resourceType) return false
            return true
          })
        }

        const summary = logs.map((entry) => ({
          method: entry.method,
          url: entry.url,
          status: entry.status,
          type: entry.resourceType,
          duration: entry.duration ? `${entry.duration}ms` : "pending",
          hasBody: !!entry.responseBody,
        }))

        return {
          title: `Network traffic (${logs.length} requests)`,
          output: JSON.stringify(summary, null, 2),
          metadata: { action: "network" },
        }
      }

      case "har": {
        const state = getState(sessionID)
        if (!state) {
          throw new Error("Browser not launched. Use launch action first.")
        }

        const har = {
          log: {
            version: "1.2",
            creator: { name: "cyberstrike-browser", version: "1.0" },
            entries: state.networkLogs
              .filter((entry) => entry.status)
              .map((entry) => ({
                startedDateTime: new Date(entry.timestamp).toISOString(),
                time: entry.duration || 0,
                request: {
                  method: entry.method,
                  url: entry.url,
                  headers: Object.entries(entry.requestHeaders).map(([name, value]) => ({ name, value })),
                  postData: entry.requestBody
                    ? { text: entry.requestBody, mimeType: "application/x-www-form-urlencoded" }
                    : undefined,
                },
                response: {
                  status: entry.status,
                  statusText: entry.statusText,
                  headers: entry.responseHeaders
                    ? Object.entries(entry.responseHeaders).map(([name, value]) => ({ name, value }))
                    : [],
                  content: {
                    size: entry.responseBody?.length || 0,
                    mimeType: entry.responseHeaders?.["content-type"] || "text/plain",
                    text: entry.responseBody,
                  },
                },
              })),
          },
        }

        const filename = `traffic-${Date.now()}.har`
        const filepath = path.join(Instance.directory, filename)
        await Bun.write(filepath, JSON.stringify(har, null, 2))

        return {
          title: "HAR file exported",
          output: `HAR file saved: ${filepath}\nTotal entries: ${har.log.entries.length}\n\nPlaywright HAR also at: ${state.harPath}`,
          metadata: { action: "har" },
        }
      }

      case "console": {
        const state = getState(sessionID)
        if (!state) {
          throw new Error("Browser not launched. Use launch action first.")
        }

        const logs = state.consoleLogs.map((entry) => ({
          time: new Date(entry.timestamp).toISOString(),
          type: entry.type,
          text: entry.text,
          location: entry.location,
        }))

        return {
          title: `Console logs (${logs.length} entries)`,
          output: JSON.stringify(logs, null, 2),
          metadata: { action: "console" },
        }
      }

      case "click": {
        if (!params.selector) {
          throw new Error("Selector is required for click action")
        }
        const state = getState(sessionID)
        if (!state) {
          throw new Error("Browser not launched. Use launch action first.")
        }

        await state.page.click(params.selector, { timeout: params.timeout })

        return {
          title: `Clicked ${params.selector}`,
          output: `Successfully clicked element: ${params.selector}`,
          metadata: { action: "click" },
        }
      }

      case "fill": {
        if (!params.selector || params.value === undefined) {
          throw new Error("Selector and value are required for fill action")
        }
        const state = getState(sessionID)
        if (!state) {
          throw new Error("Browser not launched. Use launch action first.")
        }

        await state.page.fill(params.selector, params.value, { timeout: params.timeout })

        return {
          title: `Filled ${params.selector}`,
          output: `Successfully filled element: ${params.selector}`,
          metadata: { action: "fill" },
        }
      }

      case "wait": {
        const state = getState(sessionID)
        if (!state) {
          throw new Error("Browser not launched. Use launch action first.")
        }

        if (params.selector) {
          await state.page.waitForSelector(params.selector, { timeout: params.timeout })
          return {
            title: `Waited for ${params.selector}`,
            output: `Element appeared: ${params.selector}`,
            metadata: { action: "wait" },
          }
        } else {
          await state.page.waitForLoadState("networkidle", { timeout: params.timeout })
          return {
            title: "Waited for network idle",
            output: "Page reached network idle state",
            metadata: { action: "wait" },
          }
        }
      }

      case "close": {
        const harPath = await closeBrowser(sessionID)
        return {
          title: "Browser closed",
          output: `Browser closed.\nHAR file saved: ${harPath}`,
          metadata: { action: "close" },
        }
      }

      case "status": {
        const state = getState(sessionID)
        if (!state) {
          throw new Error("Browser not launched. Use launch action first.")
        }

        const url = state.page.url()
        const title = await state.page.title()

        // Get recent network requests (last 10)
        const recentRequests = state.networkLogs.slice(-10).map((entry) => ({
          method: entry.method,
          url: entry.url.length > 80 ? entry.url.slice(0, 80) + "..." : entry.url,
          status: entry.status || "pending",
        }))

        // Get recent console logs (last 5)
        const recentConsole = state.consoleLogs.slice(-5).map((entry) => ({
          type: entry.type,
          text: entry.text.length > 100 ? entry.text.slice(0, 100) + "..." : entry.text,
        }))

        const status = {
          url,
          title,
          totalRequests: state.networkLogs.length,
          recentRequests,
          totalConsoleLogs: state.consoleLogs.length,
          recentConsole,
        }

        return {
          title: `Page: ${title}`,
          output: JSON.stringify(status, null, 2),
          metadata: { action: "status" },
        }
      }

      case "content": {
        const state = getState(sessionID)
        if (!state) {
          throw new Error("Browser not launched. Use launch action first.")
        }

        const url = state.page.url()
        const title = await state.page.title()

        // Get page text content (not HTML to keep it readable)
        const textContent = await state.page.evaluate(() => {
          // Remove script and style elements
          const clone = document.body.cloneNode(true) as HTMLElement
          clone.querySelectorAll("script, style, noscript").forEach((el) => el.remove())
          return clone.innerText.trim().slice(0, 5000) // Limit to 5000 chars
        })

        // Get all visible links
        const links = await state.page.evaluate(() => {
          return Array.from(document.querySelectorAll("a[href]"))
            .slice(0, 20)
            .map((a) => ({
              text: (a as HTMLAnchorElement).innerText.trim().slice(0, 50),
              href: (a as HTMLAnchorElement).href,
            }))
            .filter((l) => l.text && l.href)
        })

        // Get all form elements
        const forms = await state.page.evaluate(() => {
          return Array.from(document.querySelectorAll("form")).map((form) => ({
            action: form.action,
            method: form.method || "GET",
            inputs: Array.from(form.querySelectorAll("input, textarea, select")).map((input) => ({
              type: (input as HTMLInputElement).type || "text",
              name: (input as HTMLInputElement).name,
              id: input.id,
            })),
          }))
        })

        const content = {
          url,
          title,
          textContent: textContent.length >= 5000 ? textContent + "\n...(truncated)" : textContent,
          links,
          forms,
        }

        return {
          title: `Content: ${title}`,
          output: JSON.stringify(content, null, 2),
          metadata: { action: "content" },
        }
      }

      default:
        throw new Error(`Unknown action: ${params.action}`)
    }
  },
})
