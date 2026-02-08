import { describe, test, expect } from "bun:test"
import { securityValidator } from "../../src/middleware/security.js"
import type { MiddlewareContext, MiddlewareError } from "../../src/middleware/types.js"
import http from "http"
import { Readable } from "stream"

function createMockRequest(headers: Record<string, string>, body?: string): http.IncomingMessage {
  let stream: Readable

  if (body) {
    // Create stream that emits body and ends properly
    stream = new Readable({
      read() {
        this.push(body)
        this.push(null) // Signal end of stream
      }
    })
  } else {
    // Empty stream that ends immediately
    stream = new Readable({
      read() {
        this.push(null) // Signal end of stream
      }
    })
  }

  const req = stream as http.IncomingMessage
  req.headers = headers
  req.method = "POST"
  return req
}

function createMockContext(overrides?: Partial<MiddlewareContext>): MiddlewareContext {
  return {
    req: createMockRequest({}),
    res: {} as http.ServerResponse,
    pathname: "/test",
    method: "POST",
    requestId: "test-req-id",
    clientIp: "127.0.0.1",
    startTime: Date.now(),
    ...overrides,
  }
}

describe("Security Validator Middleware", () => {
  describe("Request size limits", () => {
    test("allows requests under size limit", async () => {
      const middleware = securityValidator({ maxBodySize: 1024, maxHeaderSize: 8192 })

      const body = "x".repeat(500) // 500 bytes
      const req = createMockRequest({ "content-length": "500" }, body)
      const ctx = createMockContext({ req, method: "POST" })

      let nextCalled = false
      await middleware(ctx, async () => { nextCalled = true })

      expect(nextCalled).toBe(true)
      expect(ctx.bodyStr).toBe(body)
    })

    test("rejects requests over size limit", async () => {
      const middleware = securityValidator({ maxBodySize: 100, maxHeaderSize: 8192 })

      const body = "x".repeat(200) // 200 bytes > 100 limit
      const req = createMockRequest({ "content-length": "200" }, body)
      const ctx = createMockContext({ req, method: "POST" })

      try {
        await middleware(ctx, async () => {})
        throw new Error("Should have been rejected")
      } catch (err: any) {
        expect(err.statusCode).toBe(413)
        expect(err.message).toContain("too large")
      }
    })

    test("rejects oversized body during streaming (not pre-checked)", async () => {
      const middleware = securityValidator({ maxBodySize: 100, maxHeaderSize: 8192 })

      // Middleware doesn't pre-check Content-Length, it validates during streaming
      // This is still secure - rejects as soon as size exceeds limit
      const body = "x".repeat(200) // 200 bytes > 100 limit
      const req = createMockRequest({ "content-length": "200" }, body)
      const ctx = createMockContext({ req, method: "POST" })

      try {
        await middleware(ctx, async () => {})
        throw new Error("Should have been rejected")
      } catch (err) {
        const error = err as MiddlewareError
        expect(error.statusCode).toBe(413)
        expect(error.message).toContain("too large")
      }
    })
  })

  describe("Header size limits", () => {
    test("allows requests with normal headers", async () => {
      const middleware = securityValidator({ maxBodySize: 1024, maxHeaderSize: 8192 })

      const headers = {
        "content-type": "application/json",
        "user-agent": "test-client",
        "authorization": "Bearer token123"
      }
      const req = createMockRequest(headers)
      const ctx = createMockContext({ req, method: "GET" })

      let nextCalled = false
      await middleware(ctx, async () => { nextCalled = true })

      expect(nextCalled).toBe(true)
    })

    test("rejects requests with oversized headers", async () => {
      const middleware = securityValidator({ maxBodySize: 1024, maxHeaderSize: 100 })

      // Create headers that exceed 100 bytes
      const largeValue = "x".repeat(200)
      const headers = {
        "x-large-header": largeValue
      }
      const req = createMockRequest(headers)
      const ctx = createMockContext({ req, method: "GET" })

      try {
        await middleware(ctx, async () => {})
        throw new Error("Should have been rejected")
      } catch (err: any) {
        expect(err.statusCode).toBe(413)
        expect(err.message).toContain("headers too large")
      }
    })

    test("correctly estimates header size", async () => {
      const middleware = securityValidator({ maxBodySize: 1024, maxHeaderSize: 200 })

      // Each header: name + ": " + value + "\r\n"
      // "test: value\r\n" = 13 bytes
      const headers = {
        "header1": "value1", // ~17 bytes
        "header2": "value2", // ~17 bytes
        "header3": "value3", // ~17 bytes
        "header4": "value4", // ~17 bytes
        "header5": "value5", // ~17 bytes
        "header6": "value6", // ~17 bytes
      }
      // Total: ~102 bytes, should be under 200 limit

      const req = createMockRequest(headers)
      const ctx = createMockContext({ req, method: "GET" })

      let error = null
      try {
        await middleware(ctx, async () => {})
      } catch (err) {
        error = err
      }
      expect(error).toBeNull()
    })
  })

  describe("Request timeout", () => {
    test("allows fast requests", async () => {
      const middleware = securityValidator({
        maxBodySize: 1024,
        maxHeaderSize: 8192,
        timeout: 1000
      })

      const body = "test data"
      const req = createMockRequest({ "content-length": String(body.length) }, body)
      const ctx = createMockContext({ req, method: "POST" })

      let nextCalled = false
      await middleware(ctx, async () => { nextCalled = true })

      expect(nextCalled).toBe(true)
    })

    test("times out slow requests", async () => {
      const middleware = securityValidator({
        maxBodySize: 1024,
        maxHeaderSize: 8192,
        timeout: 50 // 50ms timeout
      })

      // Create a slow stream
      const slowStream = new Readable({
        read() {
          // Delay each chunk
          setTimeout(() => {
            this.push("x")
          }, 100) // 100ms delay > 50ms timeout
        }
      })

      const req = slowStream as http.IncomingMessage
      req.headers = { "content-length": "10" }
      req.method = "POST"

      const ctx = createMockContext({ req, method: "POST" })

      try {
        await middleware(ctx, async () => {})
        throw new Error("Should have timed out")
      } catch (err) {
        const error = err as MiddlewareError
        // Timeout errors are wrapped in 413 errors by the middleware
        expect(error.statusCode).toBe(413)
        expect(error.message).toContain("timeout")
      }
    }, 1000) // Test timeout 1s
  })

  describe("HTTP methods", () => {
    test("skips body reading for GET requests", async () => {
      const middleware = securityValidator({ maxBodySize: 100, maxHeaderSize: 8192 })

      const req = createMockRequest({})
      const ctx = createMockContext({ req, method: "GET" })

      await middleware(ctx, async () => {})

      expect(ctx.bodyStr).toBeUndefined()
    })

    test("skips body reading for HEAD requests", async () => {
      const middleware = securityValidator({ maxBodySize: 100, maxHeaderSize: 8192 })

      const req = createMockRequest({})
      const ctx = createMockContext({ req, method: "HEAD" })

      await middleware(ctx, async () => {})

      expect(ctx.bodyStr).toBeUndefined()
    })

    test("reads body for POST requests", async () => {
      const middleware = securityValidator({ maxBodySize: 1024, maxHeaderSize: 8192 })

      const body = '{"test": "data"}'
      const req = createMockRequest({ "content-length": String(body.length) }, body)
      const ctx = createMockContext({ req, method: "POST" })

      await middleware(ctx, async () => {})

      expect(ctx.bodyStr).toBe(body)
    })

    test("reads body for PUT requests", async () => {
      const middleware = securityValidator({ maxBodySize: 1024, maxHeaderSize: 8192 })

      const body = '{"update": "data"}'
      const req = createMockRequest({ "content-length": String(body.length) }, body)
      const ctx = createMockContext({ req, method: "PUT" })

      await middleware(ctx, async () => {})

      expect(ctx.bodyStr).toBe(body)
    })
  })

  describe("Stream-based rejection", () => {
    test("rejects before buffering entire oversized body", async () => {
      const middleware = securityValidator({ maxBodySize: 100, maxHeaderSize: 8192 })

      // Create large body
      const largeBody = "x".repeat(10000) // 10KB
      const req = createMockRequest({ "content-length": "10000" }, largeBody)
      const ctx = createMockContext({ req, method: "POST" })

      const startTime = Date.now()

      try {
        await middleware(ctx, async () => {})
        throw new Error("Should have been rejected")
      } catch (err: any) {
        const duration = Date.now() - startTime

        expect(err.statusCode).toBe(413)
        // Should reject quickly (< 50ms) without reading full body
        expect(duration).toBeLessThan(50)
      }
    })

    test("stops reading after size limit exceeded", async () => {
      const middleware = securityValidator({ maxBodySize: 50, maxHeaderSize: 8192 })

      let chunksRead = 0
      const stream = new Readable({
        read() {
          chunksRead++
          this.push("x".repeat(20)) // 20 bytes per chunk

          if (chunksRead >= 10) {
            this.push(null) // End stream
          }
        }
      })

      const req = stream as http.IncomingMessage
      req.headers = {}
      req.method = "POST"

      const ctx = createMockContext({ req, method: "POST" })

      try {
        await middleware(ctx, async () => {})
      } catch (err: any) {
        // Should have stopped reading after exceeding 50 bytes
        // Might read 2-3 chunks (40-60 bytes) before stopping
        expect(chunksRead).toBeLessThan(5)
      }
    })
  })

  describe("Configuration", () => {
    test("respects custom maxBodySize", async () => {
      const middleware = securityValidator({ maxBodySize: 200, maxHeaderSize: 8192 })

      const body = "x".repeat(150) // Under limit
      const req = createMockRequest({ "content-length": "150" }, body)
      const ctx = createMockContext({ req, method: "POST" })

      await middleware(ctx, async () => {})
      expect(ctx.bodyStr).toBe(body)
    })

    test("respects custom maxHeaderSize", async () => {
      const middleware = securityValidator({ maxBodySize: 1024, maxHeaderSize: 100 })

      // Create headers that exceed 100 bytes
      // Each header: key (7 bytes) + value (100 bytes) = 107 bytes per header
      const headers = {
        "header1": "x".repeat(100), // 107 bytes total
      }

      const req = createMockRequest(headers)
      const ctx = createMockContext({ req, method: "GET" })

      try {
        await middleware(ctx, async () => {})
        throw new Error("Should have been rejected")
      } catch (err) {
        const error = err as MiddlewareError
        expect(error.statusCode).toBe(413)
        expect(error.message).toContain("headers too large")
      }
    })
  })

  describe("Edge cases", () => {
    test("handles empty body", async () => {
      const middleware = securityValidator({ maxBodySize: 1024, maxHeaderSize: 8192 })

      const req = createMockRequest({ "content-length": "0" }, "")
      const ctx = createMockContext({ req, method: "POST" })

      await middleware(ctx, async () => {})
      expect(ctx.bodyStr).toBe("")
    })

    test("handles missing Content-Length header", async () => {
      const middleware = securityValidator({ maxBodySize: 1024, maxHeaderSize: 8192 })

      const body = "test"
      const req = createMockRequest({}, body) // No Content-Length
      const ctx = createMockContext({ req, method: "POST" })

      await middleware(ctx, async () => {})
      expect(ctx.bodyStr).toBe(body)
    })

    test("handles invalid Content-Length header", async () => {
      const middleware = securityValidator({ maxBodySize: 1024, maxHeaderSize: 8192 })

      const body = "test"
      const req = createMockRequest({ "content-length": "invalid" }, body)
      const ctx = createMockContext({ req, method: "POST" })

      await middleware(ctx, async () => {})
      expect(ctx.bodyStr).toBe(body)
    })
  })
})
