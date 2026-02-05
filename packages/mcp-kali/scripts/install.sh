#!/bin/bash
#
# Bolt Installer
# Usage: curl -sSL https://bolt.cyberstrike.io/install.sh | bash
#
# This script:
#   1. Checks Docker is installed
#   2. Pulls the Bolt image from ghcr.io
#   3. Generates a random admin token
#   4. Starts the container
#   5. Displays the bolt key for sharing with users
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Config
IMAGE="ghcr.io/cyberstrike/bolt:latest"
CONTAINER_NAME="bolt"
DATA_VOLUME="bolt-data"
HTTP_PORT="${BOLT_PORT:-3001}"

echo -e "${CYAN}"
echo "  ⚡ Bolt Installer"
echo "  ─────────────────"
echo -e "${NC}"

# Check Docker
echo -e "${BLUE}[1/5]${NC} Checking Docker..."
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed.${NC}"
    echo ""
    echo "Install Docker first:"
    echo "  curl -fsSL https://get.docker.com | sh"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "${RED}Error: Docker daemon is not running.${NC}"
    echo ""
    echo "Start Docker and try again."
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Docker is ready"

# Check if container already exists
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${YELLOW}Warning: Container '${CONTAINER_NAME}' already exists.${NC}"
    read -p "Remove and reinstall? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}[*]${NC} Stopping and removing existing container..."
        docker stop "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true
    else
        echo "Aborted."
        exit 0
    fi
fi

# Pull image
echo -e "${BLUE}[2/5]${NC} Pulling Bolt image..."
docker pull "$IMAGE"
echo -e "  ${GREEN}✓${NC} Image pulled"

# Generate admin token
echo -e "${BLUE}[3/5]${NC} Generating admin token..."
ADMIN_TOKEN=$(openssl rand -hex 32)
echo -e "  ${GREEN}✓${NC} Token generated"

# Start container
echo -e "${BLUE}[4/5]${NC} Starting Bolt container..."
docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -p "${HTTP_PORT}:3001" \
    -p 49152-65535:49152-65535/udp \
    --cap-add NET_RAW \
    --cap-add NET_ADMIN \
    -v "${DATA_VOLUME}:/data" \
    -e "MCP_ADMIN_TOKEN=${ADMIN_TOKEN}" \
    "$IMAGE" > /dev/null

echo -e "  ${GREEN}✓${NC} Container started"

# Wait for startup and get bolt key
echo -e "${BLUE}[5/5]${NC} Waiting for Bolt to initialize..."
sleep 3

# Get bolt key from logs
BOLT_KEY=$(docker logs "$CONTAINER_NAME" 2>&1 | grep "BOLT KEY" -A1 | tail -1 | sed 's/.*\] //')

if [ -z "$BOLT_KEY" ]; then
    echo -e "${YELLOW}Warning: Could not extract bolt key from logs.${NC}"
    echo "Run 'docker logs bolt' to find it manually."
    BOLT_KEY="<check docker logs bolt>"
fi

# Done!
echo ""
echo -e "${GREEN}${BOLD}⚡ Bolt is running!${NC}"
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Bolt Key (share with users):${NC}"
echo -e "${YELLOW}${BOLT_KEY}${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BOLD}Admin Token (keep secret):${NC}"
echo -e "${YELLOW}${ADMIN_TOKEN}${NC}"
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Health check:"
echo "  curl http://localhost:${HTTP_PORT}/health"
echo ""
echo "View logs:"
echo "  docker logs -f bolt"
echo ""
echo "Stop:"
echo "  docker stop bolt"
echo ""
echo -e "${GREEN}Users can now connect with the bolt key above.${NC}"
