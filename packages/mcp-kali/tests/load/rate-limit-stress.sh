#!/usr/bin/env bash
#
# Load test for rate limiting
# Requires: autocannon (npm install -g autocannon)
#

set -e

BASE_URL="${BASE_URL:-http://localhost:3001}"
DURATION="${DURATION:-30}"
CONNECTIONS="${CONNECTIONS:-100}"

echo "======================================"
echo "Rate Limit Load Test"
echo "======================================"
echo "URL: $BASE_URL"
echo "Duration: ${DURATION}s"
echo "Connections: $CONNECTIONS"
echo "======================================"
echo ""

# Test 1: Health endpoint (should handle high load)
echo "Test 1: Health Endpoint Stress Test"
echo "Expected: Should handle $CONNECTIONS concurrent connections"
echo ""

autocannon \
  -c $CONNECTIONS \
  -d $DURATION \
  --renderStatusCodes \
  "$BASE_URL/health"

echo ""
echo "======================================"
echo ""

# Test 2: Rate limit threshold test
echo "Test 2: Rate Limit Threshold Test"
echo "Expected: Should start returning 429 after ~300 requests/min per IP"
echo ""

autocannon \
  -c 50 \
  -d 10 \
  --renderStatusCodes \
  "$BASE_URL/health"

echo ""
echo "======================================"
echo ""

# Test 3: Connection limit test
echo "Test 3: Connection Limit Test"
echo "Expected: Should start returning 503 after 100 concurrent connections"
echo ""

autocannon \
  -c 200 \
  -d 10 \
  --renderStatusCodes \
  "$BASE_URL/health"

echo ""
echo "======================================"
echo "Load Test Complete"
echo "======================================"
echo ""
echo "Check for:"
echo "  - 200 OK responses (successful)"
echo "  - 429 responses (rate limited)"
echo "  - 503 responses (connection limited)"
echo "  - p99 latency < 50ms"
echo ""
