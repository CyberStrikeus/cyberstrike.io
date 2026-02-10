# Docker Startup Behavior - Zero-Config Experience

## 🎯 Goal
User runs: `docker run -p 3001:3001 ghcr.io/cyberstrikeus/bolt`
And it **just works** - ready to pair with cyberstrike CLI immediately.

## 📋 Startup Sequence

### Step 1: Environment Detection (1-2 seconds)
```bash
[BOLT] 🔍 Initializing Bolt MCP Server...
[BOLT] ✓ Data directory: /data
[BOLT] ✓ Port: 3001
[BOLT] ✓ TLS: Enabled (auto-configure)
```

### Step 2: Auto-Generate TLS Certificate (if not exists)
```bash
[BOLT] 🔒 Setting up TLS/SSL...
[BOLT] ⚠  No certificate found, generating self-signed certificate...
[BOLT] ✓ Certificate generated: /data/certs/server.crt
[BOLT] ✓ Private key: /data/certs/server.key
[BOLT] ✓ Valid for: 365 days
```

**Implementation:**
- Check if `/data/certs/server.crt` exists
- If not, run the existing `generateSelfSignedCert()` from `http.ts`
- Use Docker container ID as CN (fallback to "localhost")

### Step 3: Generate Pairing Code (automatically)
```bash
[BOLT] 🔐 Generating pairing code...
[BOLT] ✓ Pairing code: XKCD-RAIN-FISH-MOON
[BOLT] ⏱  Expires in: 5 minutes
```

**Implementation:**
- Auto-call `/pair` endpoint on startup
- Generate pairing code without requiring admin token
- Store pairing code for display

### Step 4: Start Server
```bash
[BOLT] 🚀 Starting server...
[BOLT] ✓ HTTPS server listening on https://0.0.0.0:3001
[BOLT] ✓ Health check: https://localhost:3001/health
```

### Step 5: Display Connection Instructions
```bash
╔═══════════════════════════════════════════════════════════╗
║              ✅ Bolt MCP Server Running!                  ║
╚═══════════════════════════════════════════════════════════╝

📡 Connection URL:
   https://localhost:3001/mcp

🔐 Pairing Code (expires in 5 minutes):
   ┌────────────────────────┐
   │   XKCD-RAIN-FISH-MOON  │
   └────────────────────────┘

💻 Connect from CyberStrike CLI:

   cyberstrike mcp pair https://localhost:3001/mcp XKCD-RAIN-FISH-MOON

   Or just:

   cyberstrike mcp pair

   Then enter the pairing code when prompted.

📚 Documentation: https://docs.cyberstrike.io/mcp-kali

⚡ Server ready! Waiting for connections...
```

## 🔧 Implementation Requirements

### 1. Docker Image Entrypoint Script

Create `/docker-entrypoint.sh`:

```bash
#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           🔐 Bolt MCP Server - Starting Up 🔐            ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Step 1: Environment
echo -e "${GREEN}[BOLT]${NC} 🔍 Initializing..."
DATA_DIR=${DATA_DIR:-/data}
PORT=${PORT:-3001}
TLS_ENABLED=${TLS_ENABLED:-true}
CERTS_DIR="$DATA_DIR/certs"

mkdir -p "$CERTS_DIR"

echo -e "${GREEN}[BOLT]${NC} ✓ Data directory: $DATA_DIR"
echo -e "${GREEN}[BOLT]${NC} ✓ Port: $PORT"
echo -e "${GREEN}[BOLT]${NC} ✓ TLS: Enabled (auto-configure)"
echo ""

# Step 2: TLS Setup
echo -e "${GREEN}[BOLT]${NC} 🔒 Setting up TLS/SSL..."

TLS_CERT="$CERTS_DIR/server.crt"
TLS_KEY="$CERTS_DIR/server.key"

if [ ! -f "$TLS_CERT" ] || [ ! -f "$TLS_KEY" ]; then
    echo -e "${YELLOW}[BOLT]${NC} ⚠  No certificate found, generating self-signed certificate..."

    # Use container hostname or ID
    CERT_CN=${CERT_CN:-$(hostname)}

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$TLS_KEY" \
        -out "$TLS_CERT" \
        -subj "/CN=$CERT_CN/O=Bolt MCP/C=US" \
        > /dev/null 2>&1

    echo -e "${GREEN}[BOLT]${NC} ✓ Certificate generated: $TLS_CERT"
    echo -e "${GREEN}[BOLT]${NC} ✓ Private key: $TLS_KEY"
    echo -e "${GREEN}[BOLT]${NC} ✓ Valid for: 365 days"
else
    echo -e "${GREEN}[BOLT]${NC} ✓ Using existing certificate"
fi

export TLS_KEY_PATH="$TLS_KEY"
export TLS_CERT_PATH="$TLS_CERT"

echo ""

# Step 3: Start server in background
echo -e "${GREEN}[BOLT]${NC} 🚀 Starting server..."
node /app/dist/index.js &
SERVER_PID=$!

# Wait for server to be ready
sleep 3

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}[BOLT]${NC} ❌ Server failed to start"
    exit 1
fi

echo -e "${GREEN}[BOLT]${NC} ✓ HTTPS server listening on https://0.0.0.0:$PORT"
echo -e "${GREEN}[BOLT]${NC} ✓ Health check: https://localhost:$PORT/health"
echo ""

# Step 4: Generate pairing code
echo -e "${GREEN}[BOLT]${NC} 🔐 Generating pairing code..."

# Call /pair endpoint to generate code
PAIR_RESPONSE=$(curl -s -k -X POST https://localhost:$PORT/pair 2>/dev/null || echo '{"error":"failed"}')

# Extract pairing code
PAIRING_CODE=$(echo "$PAIR_RESPONSE" | grep -o '"code":"[^"]*"' | cut -d'"' -f4)

if [ -n "$PAIRING_CODE" ]; then
    echo -e "${GREEN}[BOLT]${NC} ✓ Pairing code: ${CYAN}$PAIRING_CODE${NC}"
    echo -e "${GREEN}[BOLT]${NC} ⏱  Expires in: 5 minutes"
else
    echo -e "${YELLOW}[BOLT]${NC} ⚠  Could not generate pairing code automatically"
    echo -e "${YELLOW}[BOLT]${NC}    Use: cyberstrike mcp pair https://localhost:$PORT/mcp"
fi

echo ""

# Step 5: Display connection instructions
cat << EOF

${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}
${BLUE}║              ✅ Bolt MCP Server Running!                  ║${NC}
${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}

${CYAN}📡 Connection URL:${NC}
   https://localhost:$PORT/mcp

EOF

if [ -n "$PAIRING_CODE" ]; then
cat << EOF
${CYAN}🔐 Pairing Code (expires in 5 minutes):${NC}
   ┌────────────────────────┐
   │   ${GREEN}$PAIRING_CODE${NC}  │
   └────────────────────────┘

${CYAN}💻 Connect from CyberStrike CLI:${NC}

   ${GREEN}cyberstrike mcp pair https://localhost:$PORT/mcp $PAIRING_CODE${NC}

   Or just:

   ${GREEN}cyberstrike mcp pair${NC}

   Then enter the pairing code when prompted.

EOF
fi

cat << EOF
${CYAN}📚 Documentation:${NC} https://docs.cyberstrike.io/mcp-kali

${GREEN}⚡ Server ready! Waiting for connections...${NC}

EOF

# Keep container running and show logs
wait $SERVER_PID
```

### 2. Dockerfile Updates

```dockerfile
# Add entrypoint script
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/docker-entrypoint.sh"]
```

### 3. http.ts Updates

**Auto-generate pairing code on startup if in Docker:**

```typescript
// In http.ts, after server starts:
if (process.env.DOCKER_CONTAINER === 'true') {
  // Auto-generate pairing code for better UX
  const { code, expiresIn } = await generatePairingCode()
  console.log(`[BOLT] Auto-generated pairing code: ${code}`)
  console.log(`[BOLT] Expires in: ${expiresIn}ms`)
}
```

## 📝 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_DIR` | `/data` | Data directory for certs, logs, etc. |
| `PORT` | `3001` | HTTP server port |
| `TLS_ENABLED` | `true` | Enable TLS/SSL |
| `TLS_KEY_PATH` | `$DATA_DIR/certs/server.key` | Path to private key |
| `TLS_CERT_PATH` | `$DATA_DIR/certs/server.crt` | Path to certificate |
| `AUTO_PAIR` | `true` | Auto-generate pairing code on startup |
| `DOCKER_CONTAINER` | `true` | Indicates running in Docker |

## 🎯 User Experience Flow

```bash
# User runs:
docker run -p 3001:3001 ghcr.io/cyberstrikeus/bolt

# They see:
╔═══════════════════════════════════════════════════════════╗
║              ✅ Bolt MCP Server Running!                  ║
╚═══════════════════════════════════════════════════════════╝

📡 Connection URL:
   https://localhost:3001/mcp

🔐 Pairing Code (expires in 5 minutes):
   ┌────────────────────────┐
   │   XKCD-RAIN-FISH-MOON  │
   └────────────────────────┘

💻 Connect from CyberStrike CLI:
   cyberstrike mcp pair https://localhost:3001/mcp XKCD-RAIN-FISH-MOON

# User copies and runs:
cyberstrike mcp pair https://localhost:3001/mcp XKCD-RAIN-FISH-MOON

# Done! Connected immediately.
```

## ✅ Success Criteria

- ✅ **Zero configuration** - No manual cert generation
- ✅ **Immediate pairing** - Pairing code displayed on startup
- ✅ **Copy/paste ready** - Exact command shown
- ✅ **5-second setup** - From docker run to paired
- ✅ **User-friendly** - Clear, colorful output
- ✅ **Production-ready** - TLS enabled by default

## 🚀 Comparison

**Before (Complex):**
```bash
# 1. Generate certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ~/certs/server.key -out ~/certs/server.crt

# 2. Run with all flags
docker run -d --name mcp-kali \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p 3001:3001 \
  -v mcp-kali-data:/data \
  -v ~/certs:/data/certs:ro \
  -e TLS_ENABLED=true \
  -e TLS_KEY_PATH=/data/certs/server.key \
  -e TLS_CERT_PATH=/data/certs/server.crt \
  cyberstrike/mcp-kali:latest

# 3. Get pairing code manually
docker exec mcp-kali curl -k https://localhost:3001/pair

# 4. Pair
cyberstrike mcp pair https://localhost:3001/mcp CODE
```

**After (Simple):**
```bash
# 1. Run
docker run -p 3001:3001 ghcr.io/cyberstrikeus/bolt

# 2. Copy the pairing command shown in output
cyberstrike mcp pair https://localhost:3001/mcp XKCD-RAIN-FISH-MOON

# Done!
```

**Time to pair:** 60 seconds → 5 seconds 🚀
