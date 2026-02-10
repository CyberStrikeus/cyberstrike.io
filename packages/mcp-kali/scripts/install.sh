#!/bin/sh
# Bolt MCP Kali - Universal Installation Script
# Compatible with: sh, bash, zsh, dash (POSIX-compliant)
# Platform: Linux, macOS, BSD, WSL
# Usage: curl -fsSL https://bolt.cyberstrike.io/install.sh | sudo sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ASCII Art Banner
printf "${BLUE}"
cat << 'BANNER'
 ________  ________  ___   _________
|\   __  \|\   __  \|\  \ |\___   ___\
\ \  \|\ /\ \  \|\  \ \  \\|___ \  \_|
 \ \   __  \ \  \\\  \ \  \    \ \  \
  \ \  \|\  \ \  \\\  \ \  \____\ \  \
   \ \_______\ \_______\ \_______\ \__\
    \|_______|\|_______|\|_______|\|__|
BANNER
printf "${NC}\n"
printf "${CYAN}Bolt MCP Kali - Smart Installation${NC}\n"
printf "${CYAN}One command, zero configuration, just works™${NC}\n\n"

# Root check
CURRENT_UID=$(id -u)
if [ "$CURRENT_UID" -ne 0 ]; then
   printf "${RED}❌ Please run as root:${NC}\n"
   printf "   ${CYAN}curl -fsSL https://bolt.cyberstrike.io/install.sh | sudo sh${NC}\n"
   exit 1
fi

# ============================================================================
# STEP 1: Auto-detect environment
# ============================================================================

printf "${YELLOW}[1/6]${NC} 🔍 Detecting environment...\n"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME=$NAME
    OS_VERSION=$VERSION_ID
else
    OS_NAME="Unknown"
    OS_VERSION="Unknown"
fi

# Detect package manager
if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt-get"
    PKG_UPDATE="apt-get update -qq"
    PKG_INSTALL="apt-get install -y -qq"
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
    PKG_UPDATE="yum check-update"
    PKG_INSTALL="yum install -y"
elif command -v apk >/dev/null 2>&1; then
    PKG_MANAGER="apk"
    PKG_UPDATE="apk update"
    PKG_INSTALL="apk add"
elif command -v brew >/dev/null 2>&1; then
    PKG_MANAGER="brew"
    PKG_UPDATE="brew update"
    PKG_INSTALL="brew install"
else
    printf "${RED}❌ Unsupported package manager${NC}\n"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        ARCH_NAME="x64"
        ;;
    aarch64|arm64)
        ARCH_NAME="arm64"
        ;;
    armv7l|armhf)
        ARCH_NAME="armv7"
        ;;
    *)
        printf "${RED}❌ Unsupported architecture: $ARCH${NC}\n"
        exit 1
        ;;
esac

# Detect primary IP
if command -v hostname >/dev/null 2>&1; then
    PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
PRIMARY_IP=${PRIMARY_IP:-127.0.0.1}

# Detect public domain
PUBLIC_DOMAIN=""
if command -v dig >/dev/null 2>&1; then
    HOSTNAME_FULL=$(hostname -f 2>/dev/null || hostname 2>/dev/null)
    if [ -n "$HOSTNAME_FULL" ]; then
        if dig +short "$HOSTNAME_FULL" >/dev/null 2>&1; then
            PUBLIC_DOMAIN="$HOSTNAME_FULL"
        fi
    fi
fi

printf "   ${GREEN}✓${NC} OS: $OS_NAME $OS_VERSION\n"
printf "   ${GREEN}✓${NC} Package Manager: $PKG_MANAGER\n"
printf "   ${GREEN}✓${NC} Architecture: $ARCH ($ARCH_NAME)\n"
printf "   ${GREEN}✓${NC} Primary IP: $PRIMARY_IP\n"
[ -n "$PUBLIC_DOMAIN" ] && printf "   ${GREEN}✓${NC} Public Domain: $PUBLIC_DOMAIN\n"
printf "\n"

# ============================================================================
# STEP 2: Install dependencies
# ============================================================================

printf "${YELLOW}[2/6]${NC} 📦 Installing dependencies...\n"

# Update package list
$PKG_UPDATE >/dev/null 2>&1 || true

# Install required packages
DEPS="curl openssl ca-certificates"
for dep in $DEPS; do
    if ! command -v $dep >/dev/null 2>&1; then
        printf "   Installing $dep...\n"
        $PKG_INSTALL $dep >/dev/null 2>&1 || true
    fi
done

printf "   ${GREEN}✓${NC} Dependencies installed\n\n"

# ============================================================================
# STEP 3: Install Bolt MCP Server
# ============================================================================

printf "${YELLOW}[3/6]${NC} 🚀 Installing Bolt MCP Server...\n"

# Check for Node.js/npm or Docker
INSTALL_METHOD=""

if command -v npm >/dev/null 2>&1; then
    INSTALL_METHOD="npm"
    printf "   ${GREEN}✓${NC} Detected npm, using npm installation\n"
elif command -v docker >/dev/null 2>&1; then
    INSTALL_METHOD="docker"
    printf "   ${GREEN}✓${NC} Detected Docker, using containerized installation\n"
else
    printf "   ${CYAN}ℹ${NC}  Installing Node.js and npm...\n"

    # Install Node.js
    if [ "$PKG_MANAGER" = "apt-get" ]; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | sh - >/dev/null 2>&1
        $PKG_INSTALL nodejs >/dev/null 2>&1
    else
        $PKG_INSTALL nodejs npm >/dev/null 2>&1
    fi

    INSTALL_METHOD="npm"
    printf "   ${GREEN}✓${NC} Node.js installed\n"
fi

# Create service user
if ! id "mcp-kali" >/dev/null 2>&1; then
    useradd -r -s /bin/bash -m -d /var/lib/mcp-kali mcp-kali 2>/dev/null || \
    useradd -r -s /bin/sh -m -d /var/lib/mcp-kali mcp-kali 2>/dev/null || true
    printf "   ${GREEN}✓${NC} Created service user: mcp-kali\n"
fi

# Install based on method
if [ "$INSTALL_METHOD" = "npm" ]; then
    npm install -g @cyberstrike-io/mcp-kali >/dev/null 2>&1
    MCP_BIN=$(command -v mcp-kali-http)
    printf "   ${GREEN}✓${NC} Installed via npm globally\n"
else
    # Docker installation
    docker pull cyberstrike/mcp-kali:latest >/dev/null 2>&1

    # Create wrapper script
    cat > /usr/local/bin/mcp-kali-http << 'DOCKER_WRAPPER'
#!/bin/sh
docker run -d --name mcp-kali \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p ${PORT:-3001}:${PORT:-3001} \
  -v /var/lib/mcp-kali:/data \
  -e PORT=${PORT:-3001} \
  -e TLS_ENABLED=${TLS_ENABLED:-true} \
  -e TLS_KEY_PATH=/data/certs/server.key \
  -e TLS_CERT_PATH=/data/certs/server.crt \
  cyberstrike/mcp-kali:latest
DOCKER_WRAPPER
    chmod +x /usr/local/bin/mcp-kali-http
    MCP_BIN="/usr/local/bin/mcp-kali-http"
    printf "   ${GREEN}✓${NC} Installed via Docker\n"
fi

printf "\n"

# ============================================================================
# STEP 4: Setup TLS/SSL (Smart Defaults)
# ============================================================================

printf "${YELLOW}[4/6]${NC} 🔒 Configuring TLS/SSL...\n"

DATA_DIR="/var/lib/mcp-kali"
CERTS_DIR="$DATA_DIR/certs"
mkdir -p "$CERTS_DIR"
chown -R mcp-kali:mcp-kali "$DATA_DIR" 2>/dev/null || true

TLS_KEY="$CERTS_DIR/server.key"
TLS_CERT="$CERTS_DIR/server.crt"
TLS_METHOD="self-signed"

# Smart TLS decision
if [ -n "$PUBLIC_DOMAIN" ]; then
    # Has public domain → Try Let's Encrypt
    if command -v certbot >/dev/null 2>&1 || $PKG_INSTALL certbot >/dev/null 2>&1; then
        printf "   ${CYAN}ℹ${NC}  Public domain detected, attempting Let's Encrypt...\n"

        # Try to get certificate (non-interactive)
        if certbot certonly --standalone --non-interactive --agree-tos \
            --register-unsafely-without-email \
            -d "$PUBLIC_DOMAIN" >/dev/null 2>&1; then

            TLS_KEY="/etc/letsencrypt/live/$PUBLIC_DOMAIN/privkey.pem"
            TLS_CERT="/etc/letsencrypt/live/$PUBLIC_DOMAIN/fullchain.pem"
            TLS_METHOD="letsencrypt"

            printf "   ${GREEN}✓${NC} Let's Encrypt certificate obtained for $PUBLIC_DOMAIN\n"
        else
            printf "   ${YELLOW}⚠${NC}  Let's Encrypt failed, falling back to self-signed\n"
        fi
    fi
fi

# Fallback to self-signed
if [ "$TLS_METHOD" = "self-signed" ]; then
    DOMAIN="${PUBLIC_DOMAIN:-$PRIMARY_IP}"

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$TLS_KEY" -out "$TLS_CERT" \
        -subj "/CN=$DOMAIN/O=Bolt MCP/C=US" >/dev/null 2>&1

    chmod 600 "$TLS_KEY" 2>/dev/null
    chmod 644 "$TLS_CERT" 2>/dev/null
    chown mcp-kali:mcp-kali "$TLS_KEY" "$TLS_CERT" 2>/dev/null || true

    printf "   ${GREEN}✓${NC} Self-signed certificate generated for $DOMAIN\n"
fi

printf "\n"

# ============================================================================
# STEP 5: Setup Permissions (Smart Selection)
# ============================================================================

printf "${YELLOW}[5/6]${NC} 🔑 Configuring tool permissions...\n"

# Only essential tools - others handled by sudoers
ESSENTIAL_TOOLS="nmap tcpdump"

# Check if setcap is available (for capabilities approach)
if command -v setcap >/dev/null 2>&1 && command -v getcap >/dev/null 2>&1; then
    # Prefer capabilities (more secure)
    PERM_METHOD="capabilities"

    printf "   ${CYAN}ℹ${NC}  Using Linux capabilities\n"

    # Apply capabilities to essential tools only
    for tool in $ESSENTIAL_TOOLS; do
        TOOL_PATH=$(command -v "$tool" 2>/dev/null || true)
        if [ -n "$TOOL_PATH" ] && [ -f "$TOOL_PATH" ]; then
            setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$TOOL_PATH" 2>/dev/null || true
        fi
    done

    printf "   ${GREEN}✓${NC} Capabilities configured\n"
else
    # Fallback to sudoers
    PERM_METHOD="sudoers"
fi

# Always create sudoers for broader tool access
printf "   ${CYAN}ℹ${NC}  Configuring sudoers for security tools\n"

SUDOERS_FILE="/etc/sudoers.d/mcp-kali"

cat > "$SUDOERS_FILE" << 'SUDOERS_CONTENT'
# Bolt MCP Kali - Passwordless sudo for security tools
# Generated by install.sh
# Allow mcp-kali user to run ALL Kali security tools
mcp-kali ALL=(ALL) NOPASSWD: ALL
Defaults:mcp-kali !requiretty
SUDOERS_CONTENT

chmod 0440 "$SUDOERS_FILE" 2>/dev/null || true

# Validate sudoers syntax
if visudo -c -f "$SUDOERS_FILE" >/dev/null 2>&1; then
    printf "   ${GREEN}✓${NC} Sudoers configured for tool access\n"
else
    printf "   ${YELLOW}⚠${NC}  Sudoers validation failed\n"
    rm -f "$SUDOERS_FILE" 2>/dev/null || true
fi

printf "\n"

# ============================================================================
# STEP 6: Create and start systemd service
# ============================================================================

printf "${YELLOW}[6/6]${NC} 🎯 Setting up background service...\n"

# Create systemd service
cat > /etc/systemd/system/mcp-kali.service << SERVICE_CONTENT
[Unit]
Description=Bolt MCP Kali Server
Documentation=https://docs.cyberstrike.io/mcp-kali
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mcp-kali
Group=mcp-kali
WorkingDirectory=/var/lib/mcp-kali

# Environment
Environment=DATA_DIR=/var/lib/mcp-kali
Environment=PORT=3001
Environment=TLS_ENABLED=true
Environment=TLS_KEY_PATH=$TLS_KEY
Environment=TLS_CERT_PATH=$TLS_CERT

# Start command
ExecStart=$MCP_BIN

# Restart policy
Restart=always
RestartSec=10
StartLimitInterval=5min
StartLimitBurst=3

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/mcp-kali
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mcp-kali

[Install]
WantedBy=multi-user.target
SERVICE_CONTENT

# Reload systemd
systemctl daemon-reload 2>/dev/null || true

# Enable service
systemctl enable mcp-kali.service >/dev/null 2>&1 || true

# Start service
systemctl start mcp-kali.service 2>/dev/null || true

printf "   ${GREEN}✓${NC} Systemd service created and started\n\n"

# ============================================================================
# STEP 7: Wait for service to be ready
# ============================================================================

printf "${CYAN}⏳ Waiting for service to start...${NC}\n"
sleep 3

# Check service status
if systemctl is-active --quiet mcp-kali.service 2>/dev/null; then
    printf "${GREEN}✅ Service is running!${NC}\n"
else
    printf "${YELLOW}⚠️  Service may still be starting...${NC}\n"
    printf "   Check logs: ${CYAN}journalctl -u mcp-kali -n 50${NC}\n"
fi

# ============================================================================
# SUCCESS - Display connection info
# ============================================================================

PORT=3001
PROTOCOL="https"
CONNECT_URL="$PROTOCOL://$PRIMARY_IP:$PORT/mcp"

printf "\n"
printf "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}\n"
printf "${GREEN}║              ✅ Installation Complete! ✅                  ║${NC}\n"
printf "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}\n"
printf "\n"
printf "${BLUE}📡 Connection Information:${NC}\n"
printf "   URL:      ${CYAN}$CONNECT_URL${NC}\n"
printf "   Port:     ${CYAN}$PORT${NC}\n"
printf "   Protocol: ${CYAN}HTTPS (TLS enabled)${NC}\n"
printf "   Method:   ${CYAN}$TLS_METHOD${NC}\n"
[ -n "$PUBLIC_DOMAIN" ] && printf "   Domain:   ${CYAN}$PUBLIC_DOMAIN${NC}\n"
printf "\n"

printf "${BLUE}🔐 Next Steps:${NC}\n"
printf "   1. Pair with CyberStrike CLI:\n"
printf "      ${CYAN}cyberstrike mcp pair $CONNECT_URL${NC}\n"
printf "\n"
printf "   2. Verify connection:\n"
printf "      ${CYAN}cyberstrike mcp list${NC}\n"
printf "\n"
printf "   3. Test a tool:\n"
printf "      ${CYAN}cyberstrike mcp call kali-bolt tool_search --query nmap${NC}\n"
printf "\n"

printf "${BLUE}📊 Service Management:${NC}\n"
printf "   Status:  ${CYAN}systemctl status mcp-kali${NC}\n"
printf "   Logs:    ${CYAN}journalctl -u mcp-kali -f${NC}\n"
printf "   Restart: ${CYAN}systemctl restart mcp-kali${NC}\n"
printf "   Stop:    ${CYAN}systemctl stop mcp-kali${NC}\n"
printf "\n"

printf "${BLUE}🔧 Configuration:${NC}\n"
printf "   Data:     ${CYAN}/var/lib/mcp-kali/${NC}\n"
printf "   Logs:     ${CYAN}/var/lib/mcp-kali/logs/${NC}\n"
printf "   Certs:    ${CYAN}$CERTS_DIR${NC}\n"
printf "   Method:   ${CYAN}$INSTALL_METHOD${NC}\n"
printf "   Perms:    ${CYAN}$PERM_METHOD${NC}\n"
printf "\n"

if [ "$TLS_METHOD" = "self-signed" ]; then
    printf "${YELLOW}⚠️  Self-signed certificate warning:${NC}\n"
    printf "   The client may show TLS verification errors.\n"
    printf "   This is normal for self-signed certificates.\n"
    printf "   For production, consider using Let's Encrypt.\n"
    printf "\n"
fi

printf "${GREEN}🎉 Bolt MCP Kali is ready to use!${NC}\n"
printf "${GREEN}📚 Documentation: ${CYAN}https://docs.cyberstrike.io/mcp-kali${NC}\n"
printf "\n"
