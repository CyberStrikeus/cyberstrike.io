#!/bin/bash
set -e

# Set TERM if not set (for Docker compatibility)
export TERM=${TERM:-xterm}

# Colors for pretty output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

# Banner
echo -e "\033c"  # Clear screen (ANSI escape)
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           🔐 Bolt MCP Server - Starting Up 🔐            ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Environment setup
DATA_DIR=${DATA_DIR:-/data}
PORT=${PORT:-3001}
TLS_ENABLED=${TLS_ENABLED:-true}
CERTS_DIR="$DATA_DIR/certs"

mkdir -p "$CERTS_DIR"

echo -e "${GREEN}[BOLT]${NC} 🔍 Initializing..."
echo -e "${GREEN}[BOLT]${NC} ✓ Data directory: $DATA_DIR"
echo -e "${GREEN}[BOLT]${NC} ✓ Port: $PORT"
echo -e "${GREEN}[BOLT]${NC} ✓ TLS: Enabled"
echo ""

# TLS Certificate Setup
echo -e "${GREEN}[BOLT]${NC} 🔒 Setting up TLS/SSL..."

TLS_CERT="$CERTS_DIR/server.crt"
TLS_KEY="$CERTS_DIR/server.key"

if [ ! -f "$TLS_CERT" ] || [ ! -f "$TLS_KEY" ]; then
    echo -e "${YELLOW}[BOLT]${NC} ⚠  Generating self-signed certificate..."

    # Use container hostname
    CERT_CN=${CERT_CN:-$(hostname)}

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$TLS_KEY" \
        -out "$TLS_CERT" \
        -subj "/CN=$CERT_CN/O=Bolt MCP/C=US" \
        > /dev/null 2>&1

    echo -e "${GREEN}[BOLT]${NC} ✓ Certificate generated"
    echo -e "${GREEN}[BOLT]${NC} ✓ Valid for 365 days"
else
    echo -e "${GREEN}[BOLT]${NC} ✓ Using existing certificate"
fi

export TLS_KEY_PATH="$TLS_KEY"
export TLS_CERT_PATH="$TLS_CERT"
export DOCKER_CONTAINER="true"

echo ""

# Start MCP server in background
echo -e "${GREEN}[BOLT]${NC} 🚀 Starting MCP server..."

# Start the server (use CMD arguments or default)
"$@" &
SERVER_PID=$!

# Wait for server to initialize
sleep 3

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}[BOLT]${NC} ❌ Server failed to start"
    exit 1
fi

echo -e "${GREEN}[BOLT]${NC} ✓ Server started (PID: $SERVER_PID)"
echo ""

# Note: Pairing is handled via CLI
echo -e "${GREEN}[BOLT]${NC} 🔐 Server ready for pairing"
echo ""

# Display connection instructions
cat << EOF
${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}
${BLUE}║              ✅ Bolt MCP Server Running!                  ║${NC}
${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}

${CYAN}📡 Server URL:${NC}
   https://localhost:$PORT/mcp

${CYAN}🔐 To connect from CyberStrike CLI:${NC}

   ${GREEN}cyberstrike mcp pair${NC}

   ${YELLOW}Then follow the pairing prompts.${NC}

${CYAN}📚 Documentation:${NC}
   https://docs.cyberstrike.io/mcp-kali

${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
${GREEN}⚡ Ready! Server is listening for connections...${NC}
${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}

EOF

# Keep container running
wait $SERVER_PID
