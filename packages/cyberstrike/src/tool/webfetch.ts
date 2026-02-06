import z from "zod"
import { Tool } from "./tool"
import TurndownService from "turndown"
import DESCRIPTION from "./webfetch.txt"
import { Config } from "../config/config"

const MAX_RESPONSE_SIZE = 5 * 1024 * 1024 // 5MB
const DEFAULT_TIMEOUT = 30 * 1000 // 30 seconds
const MAX_TIMEOUT = 120 * 1000 // 2 minutes

async function getDefaultTimeout(): Promise<number> {
  const cfg = await Config.get()
  return cfg.timeout?.webfetch ?? DEFAULT_TIMEOUT
}

export const WebFetchTool = Tool.define("webfetch", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("The URL to fetch content from"),
    method: z
      .enum(["GET", "POST", "PUT", "DELETE", "PATCH"])
      .default("GET")
      .describe("HTTP method to use. Defaults to GET."),
    body: z
      .union([z.string(), z.record(z.unknown())])
      .optional()
      .describe("Request body. Objects are automatically serialized to JSON."),
    headers: z
      .record(z.string())
      .optional()
      .describe("Custom HTTP headers to include in the request."),
    format: z
      .enum(["text", "markdown", "html", "json"])
      .default("markdown")
      .describe("The format to return the content in (text, markdown, html, or json). Defaults to markdown."),
    timeout: z.number().describe("Optional timeout in seconds (max 120)").optional(),
  }),
  async execute(params, ctx) {
    // Validate URL
    if (!params.url.startsWith("http://") && !params.url.startsWith("https://")) {
      throw new Error("URL must start with http:// or https://")
    }

    await ctx.ask({
      permission: "webfetch",
      patterns: [params.url],
      always: ["*"],
      metadata: {
        url: params.url,
        method: params.method,
        format: params.format,
        timeout: params.timeout,
        hasBody: !!params.body,
      },
    })

    const configTimeout = await getDefaultTimeout()
    const timeout = Math.min((params.timeout ?? configTimeout / 1000) * 1000, MAX_TIMEOUT)

    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), timeout)

    // Build Accept header based on requested format with q parameters for fallbacks
    let acceptHeader = "*/*"
    switch (params.format) {
      case "markdown":
        acceptHeader = "text/markdown;q=1.0, text/x-markdown;q=0.9, text/plain;q=0.8, text/html;q=0.7, */*;q=0.1"
        break
      case "text":
        acceptHeader = "text/plain;q=1.0, text/markdown;q=0.9, text/html;q=0.8, */*;q=0.1"
        break
      case "html":
        acceptHeader = "text/html;q=1.0, application/xhtml+xml;q=0.9, text/plain;q=0.8, text/markdown;q=0.7, */*;q=0.1"
        break
      case "json":
        acceptHeader = "application/json;q=1.0, text/json;q=0.9, */*;q=0.1"
        break
      default:
        acceptHeader =
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
    }

    const signal = AbortSignal.any([controller.signal, ctx.abort])

    // Prepare request body
    let requestBody: string | undefined
    let contentTypeHeader: string | undefined
    if (params.body !== undefined) {
      if (typeof params.body === "object") {
        requestBody = JSON.stringify(params.body)
        contentTypeHeader = "application/json"
      } else {
        requestBody = params.body
        // Try to detect if it's JSON
        try {
          JSON.parse(params.body)
          contentTypeHeader = "application/json"
        } catch {
          contentTypeHeader = "text/plain"
        }
      }
    }

    // Build headers with defaults that can be overridden by custom headers
    const defaultHeaders: Record<string, string> = {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
      Accept: acceptHeader,
      "Accept-Language": "en-US,en;q=0.9",
    }

    if (contentTypeHeader) {
      defaultHeaders["Content-Type"] = contentTypeHeader
    }

    // Merge custom headers (they take precedence)
    const headers = { ...defaultHeaders, ...params.headers }

    const fetchOptions: RequestInit = {
      method: params.method,
      signal,
      headers,
    }

    if (requestBody !== undefined && params.method !== "GET") {
      fetchOptions.body = requestBody
    }

    const initial = await fetch(params.url, fetchOptions)

    // Retry with honest UA if blocked by Cloudflare bot detection (TLS fingerprint mismatch)
    const response =
      initial.status === 403 && initial.headers.get("cf-mitigated") === "challenge"
        ? await fetch(params.url, { ...fetchOptions, headers: { ...headers, "User-Agent": "cyberstrike" } })
        : initial

    clearTimeout(timeoutId)

    if (!response.ok) {
      throw new Error(`Request failed with status code: ${response.status}`)
    }

    // Check content length
    const contentLength = response.headers.get("content-length")
    if (contentLength && parseInt(contentLength) > MAX_RESPONSE_SIZE) {
      throw new Error("Response too large (exceeds 5MB limit)")
    }

    const arrayBuffer = await response.arrayBuffer()
    if (arrayBuffer.byteLength > MAX_RESPONSE_SIZE) {
      throw new Error("Response too large (exceeds 5MB limit)")
    }

    const content = new TextDecoder().decode(arrayBuffer)
    const contentType = response.headers.get("content-type") || ""

    const title = `${params.url} (${contentType})`

    // Handle content based on requested format and actual content type
    switch (params.format) {
      case "markdown":
        if (contentType.includes("text/html")) {
          const markdown = convertHTMLToMarkdown(content)
          return {
            output: markdown,
            title,
            metadata: {},
          }
        }
        return {
          output: content,
          title,
          metadata: {},
        }

      case "text":
        if (contentType.includes("text/html")) {
          const text = await extractTextFromHTML(content)
          return {
            output: text,
            title,
            metadata: {},
          }
        }
        return {
          output: content,
          title,
          metadata: {},
        }

      case "html":
        return {
          output: content,
          title,
          metadata: {},
        }

      case "json":
        try {
          const json = JSON.parse(content)
          return {
            output: JSON.stringify(json, null, 2),
            title,
            metadata: {},
          }
        } catch {
          return {
            output: content,
            title,
            metadata: { error: "Response is not valid JSON" },
          }
        }

      default:
        return {
          output: content,
          title,
          metadata: {},
        }
    }
  },
})

async function extractTextFromHTML(html: string) {
  let text = ""
  let skipContent = false

  const rewriter = new HTMLRewriter()
    .on("script, style, noscript, iframe, object, embed", {
      element() {
        skipContent = true
      },
      text() {
        // Skip text content inside these elements
      },
    })
    .on("*", {
      element(element) {
        // Reset skip flag when entering other elements
        if (!["script", "style", "noscript", "iframe", "object", "embed"].includes(element.tagName)) {
          skipContent = false
        }
      },
      text(input) {
        if (!skipContent) {
          text += input.text
        }
      },
    })
    .transform(new Response(html))

  await rewriter.text()
  return text.trim()
}

function convertHTMLToMarkdown(html: string): string {
  const turndownService = new TurndownService({
    headingStyle: "atx",
    hr: "---",
    bulletListMarker: "-",
    codeBlockStyle: "fenced",
    emDelimiter: "*",
  })
  turndownService.remove(["script", "style", "meta", "link"])
  return turndownService.turndown(html)
}
