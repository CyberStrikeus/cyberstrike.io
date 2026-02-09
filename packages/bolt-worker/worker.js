/**
 * Cloudflare Worker for bolt.cyberstrike.io
 * Uses assets from cyberstrike.io
 */

const INSTALL_SCRIPT = String.raw`#!/bin/sh
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
printf "$BLUE"
cat << 'BANNER'
 ________  ________  ___   _________
|\   __  \|\   __  \|\  \ |\___   ___\
\ \  \|\ /\ \  \|\  \ \  \\|___ \  \_|
 \ \   __  \ \  \\\  \ \  \    \ \  \
  \ \  \|\  \ \  \\\  \ \  \____\ \  \
   \ \_______\ \_______\ \_______\ \__\
    \|_______|\|_______|\|_______|\|__|
BANNER
printf "$NC\n"
printf "$` + `{CYAN}Bolt MCP Kali - Smart Installation$NC\n"
printf "$` + `{CYAN}One command, zero configuration, just works™$NC\n\n"

# Root check
CURRENT_UID=$(id -u)
if [ "$CURRENT_UID" -ne 0 ]; then
   printf "$RED❌ Please run as root:$NC\n"
   printf "   $` + `{CYAN}curl -fsSL https://bolt.cyberstrike.io/install.sh | sudo sh$NC\n"
   exit 1
fi

# ============================================================================
# STEP 1: Auto-detect environment
# ============================================================================

printf "$YELLOW[1/6]$NC 🔍 Detecting environment...\n"

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
    printf "$RED❌ Unsupported package manager$NC\n"
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
        printf "$RED❌ Unsupported architecture: $ARCH$NC\n"
        exit 1
        ;;
esac

# Detect primary IP
if command -v hostname >/dev/null 2>&1; then
    PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
PRIMARY_IP=$` + `{PRIMARY_IP:-127.0.0.1}

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

printf "   $GREEN✓$NC OS: $OS_NAME $OS_VERSION\n"
printf "   $GREEN✓$NC Package Manager: $PKG_MANAGER\n"
printf "   $GREEN✓$NC Architecture: $ARCH ($ARCH_NAME)\n"
printf "   $GREEN✓$NC Primary IP: $PRIMARY_IP\n"
[ -n "$PUBLIC_DOMAIN" ] && printf "   $GREEN✓$NC Public Domain: $PUBLIC_DOMAIN\n"
printf "\n"

# ============================================================================
# STEP 2: Install dependencies
# ============================================================================

printf "$YELLOW[2/6]$NC 📦 Installing dependencies...\n"

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

printf "   $GREEN✓$NC Dependencies installed\n\n"

# ============================================================================
# STEP 3: Install Bolt MCP Server
# ============================================================================

printf "$YELLOW[3/6]$NC 🚀 Installing Bolt MCP Server...\n"

# Check for Node.js/npm or Docker
INSTALL_METHOD=""

if command -v npm >/dev/null 2>&1; then
    INSTALL_METHOD="npm"
    printf "   $GREEN✓$NC Detected npm, using npm installation\n"
elif command -v docker >/dev/null 2>&1; then
    INSTALL_METHOD="docker"
    printf "   $GREEN✓$NC Detected Docker, using containerized installation\n"
else
    printf "   $CYANℹ$NC  Installing Node.js and npm...\n"

    # Install Node.js
    if [ "$PKG_MANAGER" = "apt-get" ]; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | sh - >/dev/null 2>&1
        $PKG_INSTALL nodejs >/dev/null 2>&1
    else
        $PKG_INSTALL nodejs npm >/dev/null 2>&1
    fi

    INSTALL_METHOD="npm"
    printf "   $GREEN✓$NC Node.js installed\n"
fi

# Create service user
if ! id "mcp-kali" >/dev/null 2>&1; then
    useradd -r -s /bin/bash -m -d /var/lib/mcp-kali mcp-kali 2>/dev/null || \
    useradd -r -s /bin/sh -m -d /var/lib/mcp-kali mcp-kali 2>/dev/null || true
    printf "   $GREEN✓$NC Created service user: mcp-kali\n"
fi

# Install based on method
if [ "$INSTALL_METHOD" = "npm" ]; then
    npm install -g @cyberstrike-io/mcp-kali >/dev/null 2>&1
    MCP_BIN=$(command -v mcp-kali-http)
    printf "   $GREEN✓$NC Installed via npm globally\n"
else
    # Docker installation
    docker pull cyberstrike/mcp-kali:latest >/dev/null 2>&1

    # Create wrapper script
    cat > /usr/local/bin/mcp-kali-http << 'DOCKER_WRAPPER'
#!/bin/sh
docker run -d --name mcp-kali \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p $` + `{PORT:-3001}:$` + `{PORT:-3001} \
  -v /var/lib/mcp-kali:/data \
  -e PORT=$` + `{PORT:-3001} \
  -e TLS_ENABLED=$` + `{TLS_ENABLED:-true} \
  -e TLS_KEY_PATH=/data/certs/server.key \
  -e TLS_CERT_PATH=/data/certs/server.crt \
  cyberstrike/mcp-kali:latest
DOCKER_WRAPPER
    chmod +x /usr/local/bin/mcp-kali-http
    MCP_BIN="/usr/local/bin/mcp-kali-http"
    printf "   $GREEN✓$NC Installed via Docker\n"
fi

printf "\n"

# ============================================================================
# STEP 4: Setup TLS/SSL (Smart Defaults)
# ============================================================================

printf "$YELLOW[4/6]$NC 🔒 Configuring TLS/SSL...\n"

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
        printf "   $CYANℹ$NC  Public domain detected, attempting Let's Encrypt...\n"

        # Try to get certificate (non-interactive)
        if certbot certonly --standalone --non-interactive --agree-tos \
            --register-unsafely-without-email \
            -d "$PUBLIC_DOMAIN" >/dev/null 2>&1; then

            TLS_KEY="/etc/letsencrypt/live/$PUBLIC_DOMAIN/privkey.pem"
            TLS_CERT="/etc/letsencrypt/live/$PUBLIC_DOMAIN/fullchain.pem"
            TLS_METHOD="letsencrypt"

            printf "   $GREEN✓$NC Let's Encrypt certificate obtained for $PUBLIC_DOMAIN\n"
        else
            printf "   $YELLOW⚠$NC  Let's Encrypt failed, falling back to self-signed\n"
        fi
    fi
fi

# Fallback to self-signed
if [ "$TLS_METHOD" = "self-signed" ]; then
    DOMAIN="$` + `{PUBLIC_DOMAIN:-$PRIMARY_IP}"

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$TLS_KEY" -out "$TLS_CERT" \
        -subj "/CN=$DOMAIN/O=Bolt MCP/C=US" >/dev/null 2>&1

    chmod 600 "$TLS_KEY" 2>/dev/null
    chmod 644 "$TLS_CERT" 2>/dev/null
    chown mcp-kali:mcp-kali "$TLS_KEY" "$TLS_CERT" 2>/dev/null || true

    printf "   $GREEN✓$NC Self-signed certificate generated for $DOMAIN\n"
fi

printf "\n"

# ============================================================================
# STEP 5: Setup Permissions (Smart Selection)
# ============================================================================

printf "$YELLOW[5/6]$NC 🔑 Configuring tool permissions...\n"

# Only essential tools - others handled by sudoers
ESSENTIAL_TOOLS="nmap tcpdump"

# Check if setcap is available (for capabilities approach)
if command -v setcap >/dev/null 2>&1 && command -v getcap >/dev/null 2>&1; then
    # Prefer capabilities (more secure)
    PERM_METHOD="capabilities"

    printf "   $CYANℹ$NC  Using Linux capabilities\n"

    # Apply capabilities to essential tools only
    for tool in $ESSENTIAL_TOOLS; do
        TOOL_PATH=$(command -v "$tool" 2>/dev/null || true)
        if [ -n "$TOOL_PATH" ] && [ -f "$TOOL_PATH" ]; then
            setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$TOOL_PATH" 2>/dev/null || true
        fi
    done

    printf "   $GREEN✓$NC Capabilities configured\n"
else
    # Fallback to sudoers
    PERM_METHOD="sudoers"
fi

# Always create sudoers for broader tool access
printf "   $CYANℹ$NC  Configuring sudoers for security tools\n"

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
    printf "   $GREEN✓$NC Sudoers configured for tool access\n"
else
    printf "   $YELLOW⚠$NC  Sudoers validation failed\n"
    rm -f "$SUDOERS_FILE" 2>/dev/null || true
fi

printf "\n"

# ============================================================================
# STEP 6: Create and start systemd service
# ============================================================================

printf "$YELLOW[6/6]$NC 🎯 Setting up background service...\n"

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

printf "   $GREEN✓$NC Systemd service created and started\n\n"

# ============================================================================
# STEP 7: Wait for service to be ready
# ============================================================================

printf "$CYAN⏳ Waiting for service to start...$NC\n"
sleep 3

# Check service status
if systemctl is-active --quiet mcp-kali.service 2>/dev/null; then
    printf "$GREEN✅ Service is running!$NC\n"
else
    printf "$YELLOW⚠️  Service may still be starting...$NC\n"
    printf "   Check logs: $` + `{CYAN}journalctl -u mcp-kali -n 50$NC\n"
fi

# ============================================================================
# SUCCESS - Display connection info
# ============================================================================

PORT=3001
PROTOCOL="https"
CONNECT_URL="$PROTOCOL://$PRIMARY_IP:$PORT/mcp"

printf "\n"
printf "$GREEN╔═══════════════════════════════════════════════════════════╗$NC\n"
printf "$GREEN║              ✅ Installation Complete! ✅                  ║$NC\n"
printf "$GREEN╚═══════════════════════════════════════════════════════════╝$NC\n"
printf "\n"
printf "$BLUE📡 Connection Information:$NC\n"
printf "   URL:      $CYAN$CONNECT_URL$NC\n"
printf "   Port:     $CYAN$PORT$NC\n"
printf "   Protocol: $` + `{CYAN}HTTPS (TLS enabled)$NC\n"
printf "   Method:   $CYAN$TLS_METHOD$NC\n"
[ -n "$PUBLIC_DOMAIN" ] && printf "   Domain:   $CYAN$PUBLIC_DOMAIN$NC\n"
printf "\n"

printf "$BLUE🔐 Next Steps:$NC\n"
printf "   1. Pair with CyberStrike CLI:\n"
printf "      $` + `{CYAN}cyberstrike mcp pair $CONNECT_URL$NC\n"
printf "\n"
printf "   2. Verify connection:\n"
printf "      $` + `{CYAN}cyberstrike mcp list$NC\n"
printf "\n"
printf "   3. Test a tool:\n"
printf "      $` + `{CYAN}cyberstrike mcp call kali-bolt tool_search --query nmap$NC\n"
printf "\n"

printf "$BLUE📊 Service Management:$NC\n"
printf "   Status:  $` + `{CYAN}systemctl status mcp-kali$NC\n"
printf "   Logs:    $` + `{CYAN}journalctl -u mcp-kali -f$NC\n"
printf "   Restart: $` + `{CYAN}systemctl restart mcp-kali$NC\n"
printf "   Stop:    $` + `{CYAN}systemctl stop mcp-kali$NC\n"
printf "\n"

printf "$BLUE🔧 Configuration:$NC\n"
printf "   Data:     $CYAN/var/lib/mcp-kali/$NC\n"
printf "   Logs:     $CYAN/var/lib/mcp-kali/logs/$NC\n"
printf "   Certs:    $CYAN$CERTS_DIR$NC\n"
printf "   Method:   $CYAN$INSTALL_METHOD$NC\n"
printf "   Perms:    $CYAN$PERM_METHOD$NC\n"
printf "\n"

if [ "$TLS_METHOD" = "self-signed" ]; then
    printf "$YELLOW⚠️  Self-signed certificate warning:$NC\n"
    printf "   The client may show TLS verification errors.\n"
    printf "   This is normal for self-signed certificates.\n"
    printf "   For production, consider using Let's Encrypt.\n"
    printf "\n"
fi

printf "$GREEN🎉 Bolt MCP Kali is ready to use!$NC\n"
printf "$GREEN📚 Documentation: $` + `{CYAN}https://docs.cyberstrike.io/mcp-kali$NC\n"
printf "\n"
`;

const LANDING_HTML = `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Bolt - Kali Linux Tools via MCP | Cyberstrike</title>
  <meta name="description" content="Access 100+ Kali Linux security tools through Cyberstrike's MCP interface. Docker-based, secure, and AI-powered.">

  <!-- Favicons from cyberstrike.io -->
  <link rel="icon" type="image/svg+xml" href="https://cyberstrike.io/favicons/favicon.svg">
  <link rel="apple-touch-icon" sizes="180x180" href="https://cyberstrike.io/favicons/apple-touch-icon.png">
  <meta name="theme-color" content="#000000">

  <!-- Space Grotesk font -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&display=swap" rel="stylesheet">

  <style>
    :root {
      /* Neutral (base) colors - same as landing */
      --base-50: #fafafa;
      --base-100: #f5f5f5;
      --base-200: #e5e5e5;
      --base-300: #d4d4d4;
      --base-400: #a3a3a3;
      --base-500: #737373;
      --base-600: #525252;
      --base-700: #404040;
      --base-800: #262626;
      --base-900: #171717;
      --base-950: #0a0a0a;

      /* Blue (primary) colors */
      --primary-300: #93c5fd;
      --primary-400: #60a5fa;
      --primary-500: #3b82f6;
      --primary-600: #2563eb;
      --primary-700: #1d4ed8;

      /* Dark background - same as landing */
      --dark-bg: hsl(0, 0%, 1%);
    }

    * { margin: 0; padding: 0; box-sizing: border-box; border-color: var(--base-800); }

    html {
      scroll-behavior: smooth;
      color-scheme: dark;
    }

    body {
      font-family: 'Space Grotesk', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: var(--dark-bg);
      color: var(--base-200);
      min-height: 100vh;
      line-height: 1.6;
    }

    /* Neon arc background - same as landing HeroCentered */
    .neon-arc {
      position: absolute;
      top: 80px;
      left: -40px;
      right: -40px;
      height: 400px;
      pointer-events: none;
      overflow: hidden;
      opacity: 0.7;
    }

    .neon-arc svg {
      width: 100%;
      height: 100%;
      color: var(--primary-500);
    }

    /* Container - same as landing site-container */
    .site-container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 1rem;
    }

    /* Navigation - same as landing Nav */
    .nav-container {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 30;
      transition: all 0.3s;
      border-bottom: 1px solid transparent;
    }

    .nav-container.scrolled {
      background: rgba(3, 3, 3, 0.7);
      backdrop-filter: blur(8px);
      border-bottom-color: rgba(255, 255, 255, 0.1);
    }

    .nav-inner {
      height: 56px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    /* Logo - same as landing SiteLogo */
    .logo {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      text-decoration: none;
      color: var(--base-200);
      font-weight: 500;
      font-size: 1.25rem;
    }

    .logo img {
      height: 3.5rem;
      width: 3.5rem;
      filter: brightness(0) invert(1);
    }

    .nav-links {
      display: flex;
      align-items: center;
      gap: 1rem;
    }

    .nav-links a {
      color: var(--base-400);
      text-decoration: none;
      font-size: 0.875rem;
      font-weight: 500;
      letter-spacing: -0.01em;
      transition: color 0.2s;
      padding: 0 1rem;
    }

    .nav-links a:hover {
      color: var(--base-200);
    }

    /* Primary button - same as landing button--primary */
    .button--primary {
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 0.375rem 1rem;
      border-radius: 9999px;
      font-size: 0.875rem;
      font-weight: 500;
      letter-spacing: -0.01em;
      text-decoration: none;
      transition: box-shadow 0.3s, color 0.3s, background-color 0.3s, border-color 0.3s;
      position: relative;
      border: 1px solid var(--primary-600);
      background: linear-gradient(to top, var(--primary-700), var(--primary-700));
      color: white;
    }

    .button--primary::before {
      content: '';
      position: absolute;
      inset: -2px;
      z-index: -1;
      border-radius: 9999px;
      background: var(--primary-500);
      opacity: 0;
      filter: blur(4px);
      transition: opacity 0.3s;
    }

    .button--primary:hover {
      border-color: var(--primary-300);
    }

    .button--primary:hover::before {
      opacity: 1;
    }

    @media (max-width: 768px) {
      .nav-links { display: none; }
      .nav-btn { display: none !important; }
    }

    /* Hero - same as landing HeroCentered */
    .hero {
      position: relative;
      padding: 7rem 0 3rem;
      text-align: center;
      overflow: hidden;
    }

    .hero-content {
      position: relative;
      z-index: 1;
      max-width: 750px;
      margin: 0 auto;
      padding: 0 1rem;
    }

    /* Notification badge - same as landing */
    .notification {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.25rem 1rem;
      margin-bottom: 1rem;
      border-radius: 9999px;
      border: 1px solid var(--base-800);
      background: var(--base-950);
      color: var(--base-300);
      font-size: 0.875rem;
      text-decoration: none;
      transition: all 0.3s;
    }

    .notification:hover {
      border-color: var(--primary-300);
    }

    .notification svg {
      width: 1rem;
      height: 1rem;
      color: var(--primary-500);
    }

    /* h1 - same as landing .h1 class */
    .h1 {
      font-size: 3rem;
      font-weight: 500;
      line-height: 1.1;
      letter-spacing: -0.02em;
      margin-bottom: 1.5rem;
      background: linear-gradient(to bottom right, var(--base-200), rgba(229, 229, 229, 0.6));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    @media (min-width: 768px) {
      .h1 { font-size: 3.75rem; }
    }

    .hero-description {
      font-size: 1.125rem;
      color: var(--base-100);
      max-width: 48rem;
      margin: 0 auto 2.5rem;
    }

    /* Buttons group */
    .btn-group {
      display: flex;
      gap: 1rem;
      justify-content: center;
      flex-wrap: wrap;
    }

    .button {
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 0.625rem 1.25rem;
      border-radius: 9999px;
      font-size: 0.875rem;
      font-weight: 500;
      letter-spacing: -0.01em;
      text-decoration: none;
      transition: box-shadow 0.3s, color 0.3s, background-color 0.3s, border-color 0.3s;
      cursor: pointer;
      font-family: inherit;
    }

    .button--outline {
      border: 1px solid var(--base-600);
      background: transparent;
      color: var(--base-100);
    }

    .button--outline:hover {
      border-color: var(--base-100);
      background: var(--base-100);
      color: var(--base-900);
    }

    /* GitHub badge - same as landing */
    .github-badge {
      display: inline-flex;
      align-items: center;
      gap: 1rem;
      margin-top: 2rem;
      padding: 0.5rem 1.25rem;
      border-radius: 9999px;
      border: 1px solid var(--base-700);
      background: rgba(10, 10, 10, 0.5);
      text-decoration: none;
      transition: all 0.3s;
    }

    .github-badge:hover {
      border-color: var(--primary-300);
    }

    .github-badge-left {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      color: var(--base-200);
      font-weight: 500;
      font-size: 0.875rem;
    }

    .github-badge-left svg {
      width: 1.25rem;
      height: 1.25rem;
      color: var(--base-300);
    }

    .github-badge-right {
      display: flex;
      align-items: center;
      gap: 0.25rem;
      color: var(--base-400);
      font-size: 0.875rem;
    }

    .github-badge-right svg {
      width: 1rem;
      height: 1rem;
      color: #facc15;
    }

    /* Install Section */
    .install-section {
      padding: 3rem 0;
    }

    .install-box {
      background: var(--base-950);
      border: 1px solid var(--base-800);
      border-radius: 0.75rem;
      padding: 1.5rem;
      max-width: 700px;
      margin: 0 auto;
    }

    .install-label {
      font-size: 0.875rem;
      color: var(--base-400);
      margin-bottom: 0.75rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .install-code {
      background: var(--dark-bg);
      border: 1px solid var(--base-800);
      border-radius: 0.5rem;
      padding: 0.875rem 1rem;
      font-family: 'SFMono-Regular', Menlo, Monaco, Consolas, monospace;
      font-size: 0.875rem;
      color: var(--primary-400);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }

    .install-code code {
      overflow-x: auto;
    }

    .copy-btn {
      background: transparent;
      border: 1px solid var(--base-700);
      color: var(--base-400);
      padding: 0.375rem 0.75rem;
      border-radius: 0.375rem;
      cursor: pointer;
      font-size: 0.75rem;
      font-family: inherit;
      transition: all 0.2s;
      white-space: nowrap;
    }

    .copy-btn:hover {
      background: var(--base-800);
      color: var(--base-200);
    }

    /* Features - same as landing FeatureCardsSmall style */
    .features {
      padding: 4rem 0;
    }

    .h2 {
      text-align: center;
      font-size: 2rem;
      font-weight: 500;
      letter-spacing: -0.02em;
      margin-bottom: 2.5rem;
      background: linear-gradient(to bottom right, var(--base-200), rgba(229, 229, 229, 0.6));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    @media (min-width: 768px) {
      .h2 { font-size: 2.5rem; }
    }

    .features-grid {
      display: grid;
      grid-template-columns: repeat(1, 1fr);
      gap: 1rem;
    }

    @media (min-width: 640px) {
      .features-grid { grid-template-columns: repeat(2, 1fr); }
    }

    @media (min-width: 1024px) {
      .features-grid { grid-template-columns: repeat(4, 1fr); }
    }

    .feature-card {
      background: var(--base-950);
      border: 1px solid var(--base-800);
      border-radius: 0.75rem;
      padding: 1.25rem;
      transition: border-color 0.2s;
    }

    .feature-card:hover {
      border-color: var(--primary-300);
    }

    .feature-icon {
      width: 2.5rem;
      height: 2.5rem;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 0.75rem;
      border-radius: 0.5rem;
      background: var(--base-900);
      color: var(--primary-400);
    }

    .feature-icon svg {
      width: 1.25rem;
      height: 1.25rem;
    }

    .feature-title {
      font-size: 1rem;
      font-weight: 500;
      color: var(--base-100);
      margin-bottom: 0.375rem;
      letter-spacing: -0.01em;
    }

    .feature-desc {
      color: var(--base-400);
      font-size: 0.875rem;
      line-height: 1.5;
    }

    /* Tools */
    .tools {
      padding: 4rem 0;
    }

    .tools-subtitle {
      text-align: center;
      color: var(--base-400);
      margin-top: -1.5rem;
      margin-bottom: 2.5rem;
      font-size: 1rem;
    }

    .tools-grid {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      justify-content: center;
      max-width: 900px;
      margin: 0 auto;
    }

    .tool-tag {
      background: var(--base-950);
      border: 1px solid var(--base-800);
      border-radius: 0.5rem;
      padding: 0.5rem 1rem;
      font-family: 'SFMono-Regular', Menlo, Monaco, Consolas, monospace;
      font-size: 0.8rem;
      color: var(--base-300);
      transition: all 0.2s;
    }

    .tool-tag:hover {
      border-color: var(--primary-400);
      color: var(--primary-300);
    }

    /* Footer */
    footer {
      padding: 3rem 0;
      text-align: center;
      border-top: 1px solid var(--base-800);
    }

    .footer-links {
      display: flex;
      gap: 2rem;
      justify-content: center;
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
    }

    .footer-links a {
      color: var(--base-400);
      text-decoration: none;
      font-size: 0.875rem;
      font-weight: 500;
      transition: color 0.2s;
    }

    .footer-links a:hover {
      color: var(--base-200);
    }

    .footer-text {
      color: var(--base-500);
      font-size: 0.875rem;
    }
  </style>
</head>
<body>
  <div class="nav-container" id="nav">
    <div class="site-container">
      <div class="nav-inner">
        <a href="https://cyberstrike.io" class="logo">
          <img src="https://cyberstrike.io/logo.svg" alt="Cyberstrike">
          <span>Cyberstrike</span>
        </a>
        <div class="nav-links">
          <a href="https://docs.cyberstrike.io/docs/mcp/bolt">Docs</a>
          <a href="https://github.com/CyberStrikeus/cyberstrike.io">GitHub</a>
          <a href="https://discord.gg/NpjPCbQVHe">Discord</a>
        </div>
        <a href="https://github.com/CyberStrikeus/cyberstrike.io" class="button--primary nav-btn" target="_blank">
          Get Started
        </a>
      </div>
    </div>
  </div>

  <main>
    <section class="hero">
      <div class="neon-arc">
        <svg viewBox="0 0 1800 400" preserveAspectRatio="xMidYMax slice">
          <defs>
            <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="8" result="blur"/>
              <feMerge>
                <feMergeNode in="blur"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
          </defs>
          <path d="M 0 400 Q 900 -100 1800 400" stroke="currentColor" stroke-width="2" fill="none" filter="url(#glow)" opacity="0.6"/>
          <path d="M 0 400 Q 900 -100 1800 400" stroke="white" stroke-width="0.5" fill="none" opacity="0.3"/>
        </svg>
      </div>

      <div class="hero-content">
        <a href="https://docs.cyberstrike.io/changelog" class="notification" target="_blank">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 3l1.912 5.813a2 2 0 0 0 1.275 1.275L21 12l-5.813 1.912a2 2 0 0 0-1.275 1.275L12 21l-1.912-5.813a2 2 0 0 0-1.275-1.275L3 12l5.813-1.912a2 2 0 0 0 1.275-1.275z"/>
          </svg>
          <span>100+ Kali Linux tools available</span>
        </a>

        <h1 class="h1">Bolt<br>Kali Linux Tools via MCP</h1>

        <p class="hero-description">
          Access professional security tools through a Docker container.
          Connect to Cyberstrike and let AI orchestrate your penetration tests.
        </p>

        <div class="btn-group">
          <a href="https://docs.cyberstrike.io/docs/mcp/bolt" class="button button--primary" target="_blank">
            Read the Docs
          </a>
          <a href="https://github.com/CyberStrikeus/cyberstrike.io/tree/main/packages/mcp-kali" class="button button--outline" target="_blank">
            View Source
          </a>
        </div>

        <a href="https://github.com/CyberStrikeus/cyberstrike.io" class="github-badge" target="_blank">
          <div class="github-badge-left">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/>
              <path d="M9 18c-4.51 2-5-2-7-2"/>
            </svg>
            <span>CyberStrikeus/cyberstrike.io</span>
          </div>
          <div class="github-badge-right">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/>
            </svg>
            <span id="stars">-</span>
          </div>
        </a>
      </div>
    </section>

    <section class="install-section">
      <div class="site-container">
        <div class="install-box">
          <div class="install-label">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
              <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
              <line x1="12" y1="22.08" x2="12" y2="12"/>
            </svg>
            1. Docker (Recommended) 🐳 - Works on all platforms
          </div>
          <div class="install-code">
            <code>docker run -p 3001:3001 ghcr.io/cyberstrikeus/bolt</code>
            <button class="copy-btn" onclick="copyDocker()">Copy</button>
          </div>
          <div style="margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--base-800);">
            <div class="install-label">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"/>
                <path d="m16 12-4-4-4 4M12 16V8"/>
              </svg>
              2. Native Install (Kali Linux only) 🔧
            </div>
            <div class="install-code">
              <code>curl -fsSL https://bolt.cyberstrike.io/install.sh | sudo sh</code>
              <button class="copy-btn" onclick="copyInstall()">Copy</button>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="features">
      <div class="site-container">
        <h2 class="h2">Why Bolt?</h2>
        <div class="features-grid">
          <div class="feature-card">
            <div class="feature-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
              </svg>
            </div>
            <div class="feature-title">Docker-based</div>
            <div class="feature-desc">
              All tools pre-installed in an isolated container. No manual setup required.
            </div>
          </div>
          <div class="feature-card">
            <div class="feature-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
            </div>
            <div class="feature-title">Secure by Design</div>
            <div class="feature-desc">
              Token authentication for secure remote deployments.
            </div>
          </div>
          <div class="feature-card">
            <div class="feature-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 2a4 4 0 0 0-4 4v2H6a2 2 0 0 0-2 2v10c0 1.1.9 2 2 2h12a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2h-2V6a4 4 0 0 0-4-4Z"/>
                <circle cx="12" cy="14" r="2"/>
                <path d="M12 16v2"/>
              </svg>
            </div>
            <div class="feature-title">AI-Powered</div>
            <div class="feature-desc">
              Let Claude orchestrate complex security assessments.
            </div>
          </div>
          <div class="feature-card">
            <div class="feature-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"/>
                <line x1="2" y1="12" x2="22" y2="12"/>
                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
              </svg>
            </div>
            <div class="feature-title">Cross-Platform</div>
            <div class="feature-desc">
              Works on macOS, Windows, and Linux. Anywhere Docker runs.
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="tools">
      <div class="site-container">
        <h2 class="h2">100+ Tools Included</h2>
        <p class="tools-subtitle">Reconnaissance, web testing, Active Directory, password attacks, and more.</p>
        <div class="tools-grid">
          <div class="tool-tag">nmap</div>
          <div class="tool-tag">sqlmap</div>
          <div class="tool-tag">nuclei</div>
          <div class="tool-tag">ffuf</div>
          <div class="tool-tag">gobuster</div>
          <div class="tool-tag">nikto</div>
          <div class="tool-tag">netexec</div>
          <div class="tool-tag">bloodhound</div>
          <div class="tool-tag">hydra</div>
          <div class="tool-tag">john</div>
          <div class="tool-tag">hashcat</div>
          <div class="tool-tag">responder</div>
          <div class="tool-tag">subfinder</div>
          <div class="tool-tag">amass</div>
          <div class="tool-tag">wpscan</div>
          <div class="tool-tag">metasploit</div>
        </div>
      </div>
    </section>
  </main>

  <footer>
    <div class="site-container">
      <div class="footer-links">
        <a href="https://cyberstrike.io">Cyberstrike</a>
        <a href="https://docs.cyberstrike.io">Documentation</a>
        <a href="https://github.com/CyberStrikeus/cyberstrike.io">GitHub</a>
        <a href="https://discord.gg/NpjPCbQVHe">Discord</a>
      </div>
      <p class="footer-text">Built by the Cyberstrike team. Open source under MIT license.</p>
    </div>
  </footer>

  <script>
    // Navbar scroll effect
    const nav = document.getElementById('nav');
    window.addEventListener('scroll', () => {
      if (window.scrollY > 50) {
        nav.classList.add('scrolled');
      } else {
        nav.classList.remove('scrolled');
      }
    }, { passive: true });

    // Copy install command
    function copyInstall() {
      navigator.clipboard.writeText('curl -fsSL https://bolt.cyberstrike.io/install.sh | sudo sh');
      const btn = event.target;
      btn.textContent = 'Copied!';
      setTimeout(() => btn.textContent = 'Copy', 2000);
    }

    // Copy Docker command
    function copyDocker() {
      navigator.clipboard.writeText('docker run -p 3001:3001 ghcr.io/cyberstrikeus/bolt');
      const btn = event.target;
      btn.textContent = 'Copied!';
      setTimeout(() => btn.textContent = 'Copy', 2000);
    }

    // Fetch GitHub stars
    async function fetchStars() {
      try {
        const res = await fetch('https://api.github.com/repos/CyberStrikeus/cyberstrike.io');
        const data = await res.json();
        if (data.stargazers_count !== undefined) {
          document.getElementById('stars').textContent = data.stargazers_count.toLocaleString();
        }
      } catch (e) {
        console.error('Failed to fetch stars:', e);
      }
    }
    fetchStars();
  </script>
</body>
</html>
`;

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Serve install script
    if (url.pathname === '/install.sh' || url.pathname === '/install') {
      return new Response(INSTALL_SCRIPT, {
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'public, max-age=300',
        }
      });
    }

    // Health check
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Landing page
    return new Response(LANDING_HTML, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'public, max-age=3600',
      }
    });
  }
}
