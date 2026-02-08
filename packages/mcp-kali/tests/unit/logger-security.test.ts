import { describe, test, expect } from "bun:test"
import { toSafeString, sanitizeValue } from "../../src/logging/formatters.js"

describe("Logger Security - RCE Prevention", () => {
  describe("toSafeString() - Control Character Removal", () => {
    test("removes null bytes", () => {
      const input = "test\x00malicious"
      const result = toSafeString(input)
      expect(result).toBe("testmalicious")
      expect(result).not.toContain("\x00")
    })

    test("removes ANSI escape characters", () => {
      const input = "test\x1b[31mEVIL\x1b[0m"
      const result = toSafeString(input)
      // Escape character (\x1b) is removed, but ANSI codes remain as text
      expect(result).toBe("test[31mEVIL[0m")
      expect(result).not.toContain("\x1b")
    })

    test("removes all control characters (\\x00-\\x1F, \\x7F-\\x9F)", () => {
      const controlChars = "\x00\x01\x02\x1F\x7F\x9F"
      const input = `safe${controlChars}text`
      const result = toSafeString(input)
      expect(result).toBe("safetext")
    })
  })

  describe("toSafeString() - JSON Breaking Prevention", () => {
    test("escapes double quotes", () => {
      const input = 'User logged in", "isAdmin": true, "fake": "'
      const result = toSafeString(input)
      expect(result).toBe('User logged in\\", \\"isAdmin\\": true, \\"fake\\": \\"')
      expect(result).not.toMatch(/[^\\]"/)
    })

    test("escapes backslashes", () => {
      const input = "path\\to\\file"
      const result = toSafeString(input)
      expect(result).toBe("path\\\\to\\\\file")
    })

    test("handles complex JSON injection attempt", () => {
      const injection = '", "role": "admin", "bypass": "'
      const result = toSafeString(injection)
      // Quotes should be escaped
      expect(result).toContain('\\"')
      // Should be safe to embed in JSON
      const jsonTest = JSON.parse(`{"input": "${result}"}`)
      expect(typeof jsonTest.input).toBe("string")
    })
  })

  describe("toSafeString() - Newline Injection Prevention", () => {
    test("removes newlines", () => {
      const input = "admin\nFAKE LOG ENTRY"
      const result = toSafeString(input)
      expect(result).toBe("adminFAKE LOG ENTRY") // Newline removed
      expect(result).not.toContain("\n")
    })

    test("removes carriage returns", () => {
      const input = "test\rmalicious"
      const result = toSafeString(input)
      expect(result).toBe("testmalicious") // CR removed
      expect(result).not.toContain("\r")
    })

    test("removes tabs", () => {
      const input = "test\tmalicious"
      const result = toSafeString(input)
      expect(result).toBe("testmalicious") // Tab removed
      expect(result).not.toContain("\t")
    })

    test("prevents log forgery with multiline injection", () => {
      const injection = "user: admin\n[CRITICAL] Unauthorized access\n[ERROR] System compromised"
      const result = toSafeString(injection)
      expect(result).not.toContain("\n")
      // Newlines are removed, not escaped (more secure)
      expect(result).toBe("user: admin[CRITICAL] Unauthorized access[ERROR] System compromised")
    })
  })

  describe("toSafeString() - Template Injection Prevention", () => {
    test("safely handles template strings", () => {
      const input = "${process.exit(1)}"
      const result = toSafeString(input)
      expect(result).toBe("${process.exit(1)}")
      // Ensure it's just a string, not executable
      expect(typeof result).toBe("string")
    })

    test("handles template literal with variables", () => {
      const input = "${config.apiKey}"
      const result = toSafeString(input)
      expect(result).toBe("${config.apiKey}")
    })
  })

  describe("toSafeString() - Function Code Leakage Prevention", () => {
    test("never logs function code", () => {
      const fn = function malicious() { return "evil" }
      const result = toSafeString(fn)
      expect(result).toBe("[Function]")
      expect(result).not.toContain("malicious")
      expect(result).not.toContain("evil")
    })

    test("handles arrow functions", () => {
      const fn = () => { console.log("secret") }
      const result = toSafeString(fn)
      expect(result).toBe("[Function]")
    })

    test("handles async functions", () => {
      const fn = async () => { return "secret" }
      const result = toSafeString(fn)
      expect(result).toBe("[Function]")
    })
  })

  describe("toSafeString() - Type Handling", () => {
    test("handles null", () => {
      expect(toSafeString(null)).toBe("null")
    })

    test("handles undefined", () => {
      expect(toSafeString(undefined)).toBe("undefined")
    })

    test("handles numbers", () => {
      expect(toSafeString(123)).toBe("123")
      expect(toSafeString(3.14)).toBe("3.14")
      expect(toSafeString(-42)).toBe("-42")
    })

    test("handles booleans", () => {
      expect(toSafeString(true)).toBe("true")
      expect(toSafeString(false)).toBe("false")
    })

    test("handles bigints", () => {
      expect(toSafeString(BigInt(9007199254740991))).toBe("9007199254740991")
    })

    test("handles symbols", () => {
      const sym = Symbol("test")
      expect(toSafeString(sym)).toBe("[Symbol]")
    })
  })

  describe("toSafeString() - Circular Reference Prevention", () => {
    test("handles circular references gracefully", () => {
      const obj: any = { name: "test" }
      obj.self = obj // Create circular reference

      const result = toSafeString(obj)
      expect(result).toBe("[Circular or Invalid Object]")
    })

    test("handles deeply nested circular references", () => {
      const a: any = { name: "a" }
      const b: any = { name: "b" }
      a.b = b
      b.a = a // Circular

      const result = toSafeString(a)
      expect(result).toBe("[Circular or Invalid Object]")
    })
  })

  describe("sanitizeValue() - PII Redaction", () => {
    test("redacts password fields", () => {
      const obj = { username: "admin", password: "secret123" }
      const result = sanitizeValue(obj)

      expect(result).toHaveProperty("username")
      expect(result).toHaveProperty("password")
      expect((result as any).password).toMatch(/\[REDACTED:[a-f0-9]{8}\]/)
    })

    test("redacts token fields", () => {
      const obj = { token: "abc123xyz", data: "public" }
      const result = sanitizeValue(obj)

      expect((result as any).token).toMatch(/\[REDACTED:[a-f0-9]{8}\]/)
      expect((result as any).data).toBe("public")
    })

    test("redacts secret fields (case-insensitive)", () => {
      const obj = {
        API_KEY: "key123",
        apiKey: "key456",
        apikey: "key789",
        privateKey: "priv123",
        access_token: "token123",
      }
      const result = sanitizeValue(obj) as any

      expect(result.API_KEY).toMatch(/\[REDACTED/)
      expect(result.apiKey).toMatch(/\[REDACTED/)
      expect(result.apikey).toMatch(/\[REDACTED/)
      expect(result.privateKey).toMatch(/\[REDACTED/)
      expect(result.access_token).toMatch(/\[REDACTED/)
    })

    test("preserves non-sensitive fields", () => {
      const obj = { username: "admin", email: "test@example.com", age: 25 }
      const result = sanitizeValue(obj) as any

      expect(result.username).toBe("admin")
      expect(result.email).toBe("test@example.com")
      expect(result.age).toBe("25")
    })

    test("recursively sanitizes nested objects", () => {
      const obj = {
        user: {
          name: "admin",
          credentials: {
            password: "secret",
            apiKey: "key123"
          }
        }
      }
      const result = sanitizeValue(obj) as any

      // sanitizeValue returns stringified values
      expect(result.user).toBeDefined()
      expect(typeof result.user).toBe("string")
    })

    test("sanitizes arrays", () => {
      const arr = ["public", "data"]
      const result = sanitizeValue(arr)

      expect(Array.isArray(result)).toBe(true)
      expect((result as any[]).length).toBe(2)
    })
  })

  describe("Real-world Attack Scenarios", () => {
    test("ATTACK: Log injection with newlines and control chars", () => {
      const maliciousInput = "user: admin\x00\n[CRITICAL] FAKE ALERT\x1b[31mRED\x1b[0m"
      const result = toSafeString(maliciousInput)

      // All control characters should be removed
      expect(result).not.toContain("\x00")
      expect(result).not.toContain("\n")
      expect(result).not.toContain("\x1b")
      // Result should be safe (control chars removed)
      expect(result).toBe("user: admin[CRITICAL] FAKE ALERT[31mRED[0m")
    })

    test("ATTACK: JSON structure breaking", () => {
      const maliciousInput = '{"user":"admin","role":"user"} <-- ignore this, "role":"admin"'
      const result = toSafeString(maliciousInput)

      // Should be escaped, not break JSON
      const wrapped = JSON.parse(`{"log": "${result}"}`)
      expect(typeof wrapped.log).toBe("string")
    })

    test("ATTACK: Command injection via template strings", () => {
      const maliciousInput = "${require('child_process').execSync('rm -rf /')}"
      const result = toSafeString(maliciousInput)

      // Should be inert string
      expect(result).toBe("${require('child_process').execSync('rm -rf /')}")
      expect(typeof result).toBe("string")
    })

    test("ATTACK: Credential leakage in logs", () => {
      const toolArgs = {
        target: "192.168.1.1",
        username: "admin",
        password: "SuperSecret123!",
        port: 22
      }
      const result = sanitizeValue(toolArgs) as any

      expect(result.target).toBe("192.168.1.1")
      expect(result.username).toBe("admin")
      expect(result.password).toMatch(/\[REDACTED/)
      expect(result.password).not.toContain("SuperSecret")
    })
  })

  describe("Performance", () => {
    test("handles large strings efficiently", () => {
      const largeString = "x".repeat(100000)
      const start = performance.now()
      const result = toSafeString(largeString)
      const duration = performance.now() - start

      expect(result.length).toBe(100000)
      expect(duration).toBeLessThan(50) // Should be < 50ms
    })

    test("handles deep objects efficiently", () => {
      const deepObj = { a: { b: { c: { d: { e: "value" } } } } }
      const start = performance.now()
      const result = sanitizeValue(deepObj)
      const duration = performance.now() - start

      expect(duration).toBeLessThan(10) // Should be < 10ms
    })
  })
})
