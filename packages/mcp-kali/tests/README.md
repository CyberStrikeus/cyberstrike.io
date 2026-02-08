# MCP Kali - Test Suite

Comprehensive test coverage for middleware, logging, and HTTP server.

## Test Structure

```
tests/
├── unit/                    # Unit tests (fast, isolated)
│   ├── logger-security.test.ts   # RCE prevention, sanitization
│   ├── rate-limit.test.ts        # Rate limiting logic
│   ├── connection.test.ts        # Connection throttling
│   └── security.test.ts          # Request size validation
├── integration/             # Integration tests (server required)
│   └── http-server.test.ts       # Full HTTP flow tests
└── load/                    # Load/stress tests
    └── rate-limit-stress.sh      # Load testing script
```

## Running Tests

### Unit Tests (Fast)

```bash
# Run all unit tests
bun test tests/unit/

# Run specific test file
bun test tests/unit/logger-security.test.ts

# Run with coverage
bun test --coverage tests/unit/

# Watch mode
bun test --watch tests/unit/
```

### Integration Tests (Requires Server)

**Important:** Start the server before running integration tests.

```bash
# Terminal 1: Start server
bun src/http.ts

# Terminal 2: Run integration tests
bun test tests/integration/
```

### Load Tests (Requires autocannon)

```bash
# Install autocannon
npm install -g autocannon

# Run load tests (server must be running)
./tests/load/rate-limit-stress.sh

# Custom configuration
DURATION=60 CONNECTIONS=200 ./tests/load/rate-limit-stress.sh
```

## Test Coverage

### Logger Security (CRITICAL)

**File:** `tests/unit/logger-security.test.ts`

Tests RCE prevention and log injection attacks:

- ✅ Control character removal
- ✅ JSON breaking prevention
- ✅ Newline injection prevention
- ✅ Template injection prevention
- ✅ Function code leakage prevention
- ✅ Circular reference handling
- ✅ PII redaction (passwords, tokens, keys)

**Attack scenarios tested:**
- Log injection with newlines and control chars
- JSON structure breaking
- Command injection via template strings
- Credential leakage in logs

### Rate Limiting

**File:** `tests/unit/rate-limit.test.ts`

Tests rate limiting enforcement:

- ✅ IP-based rate limiting (300 req/min global)
- ✅ Client-based token bucket (100 req/min, burst: 20)
- ✅ Endpoint-specific limits (/pair: 10 req/5min)
- ✅ Retry-After header
- ✅ Token bucket refill
- ✅ Separate limits per IP/client

### Connection Throttling

**File:** `tests/unit/connection.test.ts`

Tests connection limits:

- ✅ Global connection limit (100 concurrent)
- ✅ Per-IP connection limit (10 concurrent)
- ✅ Connection cleanup on close
- ✅ Separate limits for different IPs
- ✅ Graceful error handling

### Request Security

**File:** `tests/unit/security.test.ts`

Tests request size validation:

- ✅ Body size limits (1MB)
- ✅ Header size limits (8KB)
- ✅ Stream-based rejection (before buffering)
- ✅ Request timeout (30s)
- ✅ HTTP method handling (GET/POST/PUT/HEAD)
- ✅ Early rejection on Content-Length

### Integration Tests

**File:** `tests/integration/http-server.test.ts`

Tests full HTTP server flows:

- ✅ Health endpoint
- ✅ Rate limiting enforcement
- ✅ Request size validation
- ✅ Error handling (404, 400)
- ✅ CORS headers
- ✅ Middleware pipeline

## Success Criteria

### Unit Tests

- ✅ All tests pass
- ✅ No memory leaks
- ✅ RCE prevention verified
- ✅ PII redaction works

### Integration Tests

- ✅ Server responds to requests
- ✅ Middleware pipeline functional
- ✅ Error responses correct (429, 503, 413)
- ✅ Rate limiting enforced

### Load Tests

- ✅ Rate limiting triggers at expected thresholds
- ✅ Connection limits enforced (100 global, 10 per IP)
- ✅ No 500 errors (only 429, 503, 413)
- ✅ Server remains responsive under load
- ✅ Memory usage stable (no leaks)
- ✅ p99 latency < 50ms

## Performance Benchmarks

**Expected performance:**

| Metric | Target | Acceptable |
|--------|--------|------------|
| Middleware overhead | <5ms | <10ms |
| Logging overhead | <3ms | <5ms |
| Request throughput | >1000 req/s | >500 req/s |
| p99 latency | <20ms | <50ms |
| Memory (1h load) | <200MB | <500MB |

## Debugging Failed Tests

### Logger tests failing

```bash
# Check sanitization
bun test tests/unit/logger-security.test.ts --grep "toSafeString"

# Check PII redaction
bun test tests/unit/logger-security.test.ts --grep "PII"
```

### Middleware tests failing

```bash
# Check rate limiter
bun test tests/unit/rate-limit.test.ts -t 20000

# Check connection throttle
bun test tests/unit/connection.test.ts
```

### Integration tests failing

```bash
# Ensure server is running
curl http://localhost:3001/health

# Check logs
tail -f data/logs/errors-$(date +%Y-%m-%d).log
```

## CI/CD Integration

```bash
# Run in CI (GitHub Actions, etc.)
bun test tests/unit/ --coverage
```

**Example GitHub Actions:**

```yaml
- name: Run unit tests
  run: bun test tests/unit/ --coverage

- name: Start server
  run: bun src/http.ts &

- name: Wait for server
  run: sleep 5

- name: Run integration tests
  run: bun test tests/integration/
```

## Adding New Tests

### Unit Test Template

```typescript
import { describe, test, expect } from "bun:test"
import { myFunction } from "../../src/my-module.js"

describe("My Module", () => {
  test("does something", () => {
    const result = myFunction("input")
    expect(result).toBe("expected")
  })
})
```

### Integration Test Template

```typescript
import { describe, test, expect } from "bun:test"

describe("My Integration", () => {
  test("makes HTTP request", async () => {
    const res = await fetch("http://localhost:3001/endpoint")
    expect(res.status).toBe(200)
  })
})
```

## Troubleshooting

**Issue:** Tests timeout

- Increase timeout: `test("name", async () => { ... }, 10000)`
- Check server is running for integration tests

**Issue:** Port already in use

- Change port: `PORT=3002 bun src/http.ts`
- Kill existing process: `lsof -ti:3001 | xargs kill`

**Issue:** Memory leak detected

- Run tests with `--inspect` flag
- Use Chrome DevTools for heap snapshots
- Check connection cleanup in middleware

**Issue:** Flaky tests

- Add retries for network tests
- Increase timeouts for async operations
- Check for race conditions in concurrent tests

## Resources

- [Bun Test Runner Docs](https://bun.sh/docs/cli/test)
- [autocannon Load Testing](https://github.com/mcollina/autocannon)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
