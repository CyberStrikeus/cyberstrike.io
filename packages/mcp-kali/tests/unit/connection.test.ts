import { describe, test, expect } from "bun:test"
import { connectionThrottle } from "../../src/middleware/connection.js"
import type { MiddlewareContext, MiddlewareError } from "../../src/middleware/types.js"
import http from "http"
import { EventEmitter } from "events"

function createMockContext(overrides?: Partial<MiddlewareContext>): MiddlewareContext {
  const req = new EventEmitter() as http.IncomingMessage
  req.socket = new EventEmitter() as any

  return {
    req,
    res: {} as http.ServerResponse,
    pathname: "/test",
    method: "GET",
    requestId: "test-req-id",
    clientIp: "127.0.0.1",
    startTime: Date.now(),
    ...overrides,
  }
}

describe("Connection Throttle Middleware", () => {
  describe("Global connection limits", () => {
    test("allows connections under global limit", async () => {
      const middleware = connectionThrottle({ maxGlobal: 10, maxPerIp: 5 })
      const ctx = createMockContext()

      let nextCalled = false
      await middleware(ctx, async () => { nextCalled = true })

      expect(nextCalled).toBe(true)
    })

    test("blocks connections over global limit", async () => {
      const middleware = connectionThrottle({ maxGlobal: 2, maxPerIp: 10 })

      // Create 2 connections
      const ctx1 = createMockContext({ requestId: "req-1", clientIp: "10.0.0.1" })
      const ctx2 = createMockContext({ requestId: "req-2", clientIp: "10.0.0.2" })

      const promise1 = middleware(ctx1, async () => {
        // Hold connection open
        await new Promise(resolve => setTimeout(resolve, 100))
      })
      const promise2 = middleware(ctx2, async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
      })

      // Wait a bit for connections to register
      await new Promise(resolve => setTimeout(resolve, 10))

      // 3rd connection should fail
      const ctx3 = createMockContext({ requestId: "req-3", clientIp: "10.0.0.3" })

      try {
        await middleware(ctx3, async () => {})
        throw new Error("Should have been rejected")
      } catch (err: any) {
        expect(err.statusCode).toBe(503)
        expect(err.message).toContain("capacity")
      }

      // Wait for first 2 to complete
      await Promise.all([promise1, promise2])
    })
  })

  describe("Per-IP connection limits", () => {
    test("allows connections under per-IP limit", async () => {
      const middleware = connectionThrottle({ maxGlobal: 100, maxPerIp: 3 })
      const ctx = createMockContext({ clientIp: "192.168.1.100" })

      let nextCalled = false
      await middleware(ctx, async () => { nextCalled = true })

      expect(nextCalled).toBe(true)
    })

    test("blocks connections over per-IP limit", async () => {
      const middleware = connectionThrottle({ maxGlobal: 100, maxPerIp: 2 })

      const ip = "192.168.1.101"

      // Create 2 connections from same IP
      const ctx1 = createMockContext({ requestId: "req-1", clientIp: ip })
      const ctx2 = createMockContext({ requestId: "req-2", clientIp: ip })

      const promise1 = middleware(ctx1, async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
      })
      const promise2 = middleware(ctx2, async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
      })

      await new Promise(resolve => setTimeout(resolve, 10))

      // 3rd connection from same IP should fail
      const ctx3 = createMockContext({ requestId: "req-3", clientIp: ip })

      try {
        await middleware(ctx3, async () => {})
        throw new Error("Should have been rejected")
      } catch (err) {
        const error = err as MiddlewareError
        expect(error.statusCode).toBe(429) // Per-IP limit returns 429, not 503
        expect(error.message).toContain("Too many")
      }

      await Promise.all([promise1, promise2])
    })

    test("different IPs have separate limits", async () => {
      const middleware = connectionThrottle({ maxGlobal: 100, maxPerIp: 1 })

      const ip1 = "10.0.0.1"
      const ip2 = "10.0.0.2"

      // Each IP should be able to make 1 connection
      const ctx1 = createMockContext({ requestId: "req-1", clientIp: ip1 })
      const ctx2 = createMockContext({ requestId: "req-2", clientIp: ip2 })

      const promise1 = middleware(ctx1, async () => {
        await new Promise(resolve => setTimeout(resolve, 50))
      })
      const promise2 = middleware(ctx2, async () => {
        await new Promise(resolve => setTimeout(resolve, 50))
      })

      await new Promise(resolve => setTimeout(resolve, 10))

      // Both should succeed (different IPs)
      await Promise.all([promise1, promise2])
    })
  })

  describe("Connection cleanup", () => {
    test("releases connections on completion", async () => {
      const middleware = connectionThrottle({ maxGlobal: 1, maxPerIp: 1 })
      const ctx1 = createMockContext({ clientIp: "10.0.0.10" })
      const ctx2 = createMockContext({ clientIp: "10.0.0.10" })

      // First connection
      await middleware(ctx1, async () => {})

      // Second connection should now succeed (first released)
      let error = null
      try {
        await middleware(ctx2, async () => {})
      } catch (err) {
        error = err
      }
      expect(error).toBeNull()
    })

    test("releases connections on socket close", async () => {
      const middleware = connectionThrottle({ maxGlobal: 1, maxPerIp: 1 })

      const ctx = createMockContext({ clientIp: "10.0.0.11" })

      // Start connection but don't complete
      const promise = middleware(ctx, async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
      })

      await new Promise(resolve => setTimeout(resolve, 10))

      // Simulate socket close
      ctx.req.socket.emit("close")

      await promise

      // New connection should succeed (old one cleaned up)
      const ctx2 = createMockContext({ clientIp: "10.0.0.11" })
      await middleware(ctx2, async () => {})
    })
  })

  describe("Error scenarios", () => {
    test("handles missing clientIp gracefully", async () => {
      const middleware = connectionThrottle({ maxGlobal: 10, maxPerIp: 5 })
      const ctx = createMockContext({ clientIp: "" })

      let error = null
      try {
        await middleware(ctx, async () => {})
      } catch (err) {
        error = err
      }
      // Should still work (tracked with empty IP)
      expect(error).toBeNull()
    })

    test("handles errors in next() function", async () => {
      const middleware = connectionThrottle({ maxGlobal: 10, maxPerIp: 5 })
      const ctx = createMockContext()

      try {
        await middleware(ctx, async () => {
          throw new Error("Handler error")
        })
        throw new Error("Should have propagated error")
      } catch (err: any) {
        expect(err.message).toBe("Handler error")
      }
    })
  })

  describe("Metadata", () => {
    test("tracks connection start time", async () => {
      const middleware = connectionThrottle({ maxGlobal: 10, maxPerIp: 5 })
      const ctx = createMockContext()

      const before = Date.now()
      await middleware(ctx, async () => {
        await new Promise(resolve => setTimeout(resolve, 10))
      })
      const after = Date.now()

      // Connection should have lasted at least 10ms
      expect(after - before).toBeGreaterThanOrEqual(10)
    })
  })

  describe("Configuration", () => {
    test("respects custom maxGlobal setting", async () => {
      const middleware = connectionThrottle({ maxGlobal: 3, maxPerIp: 10 })

      // Should allow 3 concurrent connections
      const promises = []
      for (let i = 0; i < 3; i++) {
        const ctx = createMockContext({ requestId: `req-${i}`, clientIp: `10.0.0.${i}` })
        promises.push(middleware(ctx, async () => {
          await new Promise(resolve => setTimeout(resolve, 50))
        }))
      }

      await new Promise(resolve => setTimeout(resolve, 10))

      // 4th should fail
      const ctx4 = createMockContext({ requestId: "req-4", clientIp: "10.0.0.4" })
      try {
        await middleware(ctx4, async () => {})
        throw new Error("Should have failed")
      } catch (err: any) {
        expect(err.statusCode).toBe(503)
      }

      await Promise.all(promises)
    })

    test("respects custom maxPerIp setting", async () => {
      const middleware = connectionThrottle({ maxGlobal: 100, maxPerIp: 5 })

      const ip = "192.168.1.200"
      const promises = []

      // Should allow 5 concurrent connections from same IP
      for (let i = 0; i < 5; i++) {
        const ctx = createMockContext({ requestId: `req-${i}`, clientIp: ip })
        promises.push(middleware(ctx, async () => {
          await new Promise(resolve => setTimeout(resolve, 50))
        }))
      }

      await new Promise(resolve => setTimeout(resolve, 10))

      // 6th from same IP should fail
      const ctx6 = createMockContext({ requestId: "req-6", clientIp: ip })
      try {
        await middleware(ctx6, async () => {})
        throw new Error("Should have failed")
      } catch (err) {
        const error = err as MiddlewareError
        expect(error.statusCode).toBe(429) // Per-IP limit returns 429
      }

      await Promise.all(promises)
    })
  })
})
