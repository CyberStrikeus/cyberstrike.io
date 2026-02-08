import { describe, test, expect, beforeEach } from "bun:test"
import { rateLimiter } from "../../src/middleware/rate-limit.js"
import type { MiddlewareContext, MiddlewareError } from "../../src/middleware/types.js"
import http from "http"

function createMockContext(overrides?: Partial<MiddlewareContext>): MiddlewareContext {
  return {
    req: {} as http.IncomingMessage,
    res: {
      setHeader: () => {},
      headersSent: false,
    } as http.ServerResponse,
    pathname: "/test",
    method: "GET",
    requestId: "test-req-id",
    clientIp: "127.0.0.1",
    startTime: Date.now(),
    ...overrides,
  }
}

describe("Rate Limiter Middleware", () => {
  describe("IP-based rate limiting", () => {
    test("allows requests under the limit", async () => {
      const middleware = rateLimiter({ globalIpLimit: 10, cleanupInterval: 60000 })
      const ctx = createMockContext({ clientIp: "192.168.1.100" })

      let nextCalled = false
      const next = async () => { nextCalled = true }

      // First request should pass
      await middleware(ctx, next)
      expect(nextCalled).toBe(true)
    })

    test("blocks requests over the limit", async () => {
      const middleware = rateLimiter({ globalIpLimit: 3, cleanupInterval: 60000 })
      const ctx = createMockContext({ clientIp: "192.168.1.101" })

      let error: any = null

      // Make 3 requests (should all pass)
      for (let i = 0; i < 3; i++) {
        try {
          await middleware(ctx, async () => {})
        } catch (err) {
          error = err
        }
      }
      expect(error).toBeNull()

      // 4th request should fail
      try {
        await middleware(ctx, async () => {})
        throw new Error("Should have been rate limited")
      } catch (err: any) {
        expect(err.statusCode).toBe(429)
        expect(err.message).toContain("Rate limit exceeded")
      }
    })

    test("separate limits for different IPs", async () => {
      const middleware = rateLimiter({ globalIpLimit: 2, cleanupInterval: 60000 })

      const ctx1 = createMockContext({ clientIp: "192.168.1.1" })
      const ctx2 = createMockContext({ clientIp: "192.168.1.2" })

      // Both IPs should be able to make 2 requests
      await middleware(ctx1, async () => {})
      await middleware(ctx1, async () => {})

      await middleware(ctx2, async () => {})
      await middleware(ctx2, async () => {})

      // 3rd request from each IP should fail
      let error1 = null
      try {
        await middleware(ctx1, async () => {})
      } catch (err) {
        error1 = err
      }
      expect(error1).not.toBeNull()

      let error2 = null
      try {
        await middleware(ctx2, async () => {})
      } catch (err) {
        error2 = err
      }
      expect(error2).not.toBeNull()
    })
  })

  describe("Client-based rate limiting (token bucket)", () => {
    test("allows authenticated client requests with burst", async () => {
      const middleware = rateLimiter({ clientLimit: 10, clientBurst: 5, cleanupInterval: 60000 })
      const ctx = createMockContext({
        authenticated: true,
        clientId: "client-123",
      })

      // Should allow burst of 5 requests immediately
      for (let i = 0; i < 5; i++) {
        let error = null
        try {
          await middleware(ctx, async () => {})
        } catch (err) {
          error = err
        }
        expect(error).toBeNull()
      }
    })

    test("blocks authenticated client over burst capacity", async () => {
      const middleware = rateLimiter({ clientLimit: 10, clientBurst: 3, cleanupInterval: 60000 })
      const ctx = createMockContext({
        authenticated: true,
        clientId: "client-456",
      })

      // Use up burst capacity
      for (let i = 0; i < 3; i++) {
        await middleware(ctx, async () => {})
      }

      // 4th request should fail (no time for refill)
      try {
        await middleware(ctx, async () => {})
        throw new Error("Should have been rate limited")
      } catch (err: any) {
        expect(err.statusCode).toBe(429)
      }
    })

    test("different clients have separate buckets", async () => {
      const middleware = rateLimiter({ clientLimit: 10, clientBurst: 2, cleanupInterval: 60000 })

      const ctx1 = createMockContext({ authenticated: true, clientId: "client-a" })
      const ctx2 = createMockContext({ authenticated: true, clientId: "client-b" })

      // Each client should have their own bucket
      await middleware(ctx1, async () => {})
      await middleware(ctx1, async () => {})

      await middleware(ctx2, async () => {})
      await middleware(ctx2, async () => {})

      // Both should fail on 3rd request
      let error1 = null
      try {
        await middleware(ctx1, async () => {})
      } catch (err) {
        error1 = err
      }
      expect(error1).not.toBeNull()

      let error2 = null
      try {
        await middleware(ctx2, async () => {})
      } catch (err) {
        error2 = err
      }
      expect(error2).not.toBeNull()
    })
  })

  describe("Endpoint-specific rate limits", () => {
    test("enforces stricter limit on /pair endpoint", async () => {
      const middleware = rateLimiter({
        globalIpLimit: 100,
        pairLimit: 2, // 2 pairing attempts per 5 min
        cleanupInterval: 60000
      })

      const ctx = createMockContext({ pathname: "/pair", clientIp: "10.0.0.1" })

      // First 2 should pass
      await middleware(ctx, async () => {})
      await middleware(ctx, async () => {})

      // 3rd should fail (exceeded pair limit)
      try {
        await middleware(ctx, async () => {})
        throw new Error("Should have been rate limited")
      } catch (err) {
        const error = err as MiddlewareError
        expect(error.statusCode).toBe(429)
      }
    })

    test("normal endpoints not affected by /pair limits", async () => {
      const middleware = rateLimiter({
        globalIpLimit: 100,
        pairLimit: 1,
        cleanupInterval: 60000
      })

      const pairCtx = createMockContext({ pathname: "/pair", clientIp: "10.0.0.2" })
      const mcpCtx = createMockContext({ pathname: "/mcp", clientIp: "10.0.0.2" })

      // Use up /pair limit
      await middleware(pairCtx, async () => {})

      // /mcp should still work (different limit)
      await middleware(mcpCtx, async () => {})
      await middleware(mcpCtx, async () => {})
      await middleware(mcpCtx, async () => {})
    })
  })

  describe("Headers and metadata", () => {
    test("sets Retry-After header on rate limit", async () => {
      const middleware = rateLimiter({ globalIpLimit: 1, cleanupInterval: 60000 })
      const ctx = createMockContext({ clientIp: "10.0.0.3" })

      let retryAfter: string | undefined

      ctx.res.setHeader = (name: string, value: string) => {
        if (name === "Retry-After") {
          retryAfter = value
        }
        return ctx.res
      }

      // Use up limit
      await middleware(ctx, async () => {})

      // Next request should set Retry-After
      try {
        await middleware(ctx, async () => {})
      } catch (err) {
        expect(retryAfter).toBeDefined()
        expect(parseInt(retryAfter!)).toBeGreaterThan(0)
      }
    })

    test("sets rateLimitRemaining in context for authenticated clients", async () => {
      const middleware = rateLimiter({ clientLimit: 10, clientBurst: 5, cleanupInterval: 60000 })
      const ctx = createMockContext({
        authenticated: true,
        clientId: "client-test-123",
      })

      await middleware(ctx, async () => {})

      // rateLimitRemaining is only set for authenticated clients
      expect(ctx.rateLimitRemaining).toBeDefined()
      expect(ctx.rateLimitRemaining).toBeLessThanOrEqual(5)
    })
  })

  describe("Token bucket refill", () => {
    test("refills tokens over time", async () => {
      const middleware = rateLimiter({
        clientLimit: 60, // 60 per minute = 1 per second
        clientBurst: 2,
        cleanupInterval: 60000
      })

      const ctx = createMockContext({
        authenticated: true,
        clientId: "client-refill-test",
      })

      // Use up burst
      await middleware(ctx, async () => {})
      await middleware(ctx, async () => {})

      // Wait for 1 token to refill (1 second at 60/min rate)
      await new Promise(resolve => setTimeout(resolve, 1100))

      // Should allow one more request
      let error = null
      try {
        await middleware(ctx, async () => {})
      } catch (err) {
        error = err
      }
      expect(error).toBeNull()
    })
  })

  describe("Edge cases", () => {
    test("handles missing clientIp gracefully", async () => {
      const middleware = rateLimiter({ globalIpLimit: 10, cleanupInterval: 60000 })
      const ctx = createMockContext({ clientIp: "" })

      let error = null
      try {
        await middleware(ctx, async () => {})
      } catch (err) {
        error = err
      }
      expect(error).toBeNull()
    })

    test("handles undefined authenticated status", async () => {
      const middleware = rateLimiter({ clientLimit: 10, cleanupInterval: 60000 })
      const ctx = createMockContext({ authenticated: undefined, clientId: undefined })

      let error = null
      try {
        await middleware(ctx, async () => {})
      } catch (err) {
        error = err
      }
      // Should fall back to IP-based limiting
      expect(error).toBeNull()
    })
  })
})
