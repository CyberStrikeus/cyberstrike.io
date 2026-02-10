# Bolt MCP Kali - Quick Installation

## 🚀 Installation Options

### Option 1: Smart Installer (Recommended)

```bash
curl -fsSL https://bolt.cyberstrike.io/install.sh | sudo bash
```

Automatically sets up TLS, permissions, systemd service, and more.

### Option 2: Docker (No Installation Required)

```bash
docker run -p 3001:3001 ghcr.io/cyberstrikeus/bolt
```

**Zero configuration** - TLS, pairing code, and connection instructions are generated automatically! Just copy the pairing command from the output and run it.

**What you'll see:**
```
╔═══════════════════════════════════════════════════════════╗
║              ✅ Bolt MCP Server Running!                  ║
╚═══════════════════════════════════════════════════════════╝

📡 Connection URL: https://localhost:3001/mcp
🔐 Pairing Code: XKCD-RAIN-FISH-MOON

💻 Connect from CyberStrike CLI:
   cyberstrike mcp pair https://localhost:3001/mcp XKCD-RAIN-FISH-MOON
```

Then just paste and run the command! ⚡

**That's it!** The script automatically:
- ✅ Detects your environment (OS, package manager, architecture)
- ✅ Installs dependencies (Node.js/npm or Docker)
- ✅ Configures TLS/SSL (Let's Encrypt if public domain, self-signed otherwise)
- ✅ Sets up tool permissions (capabilities or sudoers)
- ✅ Creates systemd service (starts on boot)
- ✅ Starts the server immediately

## 📋 What Gets Installed

| Component | Details |
|-----------|---------|
| **MCP Server** | `@cyberstrike-io/mcp-kali` (npm) or Docker image |
| **Service** | systemd service at `/etc/systemd/system/mcp-kali.service` |
| **User** | `mcp-kali` (non-root service user) |
| **Data Directory** | `/var/lib/mcp-kali/` |
| **Port** | `3001` (HTTPS) |
| **TLS** | Auto-configured (Let's Encrypt or self-signed) |
| **Permissions** | Linux capabilities (preferred) or sudoers |

## 🔐 Post-Install: Pair with CyberStrike CLI

After installation completes, pair your CLI:

```bash
# The install script shows your server URL, e.g.:
# https://192.168.1.100:3001/mcp

cyberstrike mcp pair https://YOUR_SERVER_IP:3001/mcp
```

Follow the pairing prompts to enter the code displayed by the server.

## 🐳 Docker-Only Installation (Manual)

If you prefer to use Docker directly without the installer:

### Basic (HTTP only)

```bash
docker run -d \
  --name mcp-kali \
  --restart unless-stopped \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p 3001:3001 \
  -v mcp-kali-data:/data \
  cyberstrike/mcp-kali:latest
```

Then connect to: `http://localhost:3001/mcp`

### With Self-Signed TLS

```bash
# Generate certificate first
mkdir -p ~/mcp-certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ~/mcp-certs/server.key \
  -out ~/mcp-certs/server.crt \
  -subj "/CN=localhost/O=MCP/C=US"

# Run with TLS
docker run -d \
  --name mcp-kali \
  --restart unless-stopped \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p 3001:3001 \
  -v mcp-kali-data:/data \
  -v ~/mcp-certs:/data/certs:ro \
  -e TLS_ENABLED=true \
  -e TLS_KEY_PATH=/data/certs/server.key \
  -e TLS_CERT_PATH=/data/certs/server.crt \
  cyberstrike/mcp-kali:latest
```

Then connect to: `https://localhost:3001/mcp`

### With Let's Encrypt

```bash
# Requires:
# - Public domain pointing to your server
# - Port 80 open for ACME challenge

docker run -d \
  --name mcp-kali \
  --restart unless-stopped \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p 80:80 \
  -p 3001:3001 \
  -v mcp-kali-data:/data \
  -e TLS_AUTO_CERT=true \
  -e TLS_DOMAIN=bolt.yourdomain.com \
  -e TLS_EMAIL=admin@yourdomain.com \
  cyberstrike/mcp-kali:latest
```

Then connect to: `https://bolt.yourdomain.com:3001/mcp`

### Docker Compose (Production)

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  mcp-kali:
    image: cyberstrike/mcp-kali:latest
    container_name: mcp-kali
    restart: unless-stopped

    cap_add:
      - NET_RAW
      - NET_ADMIN

    ports:
      - "3001:3001"

    volumes:
      - mcp-kali-data:/data
      - ./certs:/data/certs:ro  # Optional: mount certificates

    environment:
      - PORT=3001
      - TLS_ENABLED=true
      - TLS_KEY_PATH=/data/certs/server.key
      - TLS_CERT_PATH=/data/certs/server.crt
      # Or for Let's Encrypt:
      # - TLS_AUTO_CERT=true
      # - TLS_DOMAIN=bolt.yourdomain.com
      # - TLS_EMAIL=admin@yourdomain.com

volumes:
  mcp-kali-data:
    driver: local
```

Then:
```bash
docker-compose up -d
docker-compose logs -f  # View logs
```

## ✅ Verify Connection

```bash
# List connected servers
cyberstrike mcp list

# Search for a tool
cyberstrike mcp call kali-bolt tool_search --query nmap

# Load and use nmap
cyberstrike mcp call kali-bolt load_tools --tools '["nmap"]'
cyberstrike mcp call kali-bolt kali_nmap --args '--version'
```

## 🛠️ Service Management

```bash
# Check status
systemctl status mcp-kali

# View logs (live tail)
journalctl -u mcp-kali -f

# Restart service
systemctl restart mcp-kali

# Stop service
systemctl stop mcp-kali

# Disable auto-start
systemctl disable mcp-kali
```

## 📊 Installation Details

### Smart TLS Detection

The installer automatically chooses the best TLS method:

1. **Public Domain Detected** → Attempts Let's Encrypt
   - Uses `certbot` to obtain free SSL certificate
   - Auto-renews before expiration
   - Production-grade encryption

2. **Private IP or No Domain** → Self-Signed Certificate
   - Generates 2048-bit RSA certificate
   - Valid for 365 days
   - Suitable for internal/development use

3. **Let's Encrypt Failed** → Falls back to self-signed

### Smart Permission Setup

The installer chooses the most secure permission method:

1. **Linux Capabilities Available** (preferred)
   - Uses `setcap` to grant minimal privileges
   - Most secure (principle of least privilege)
   - Only grants `CAP_NET_RAW`, `CAP_NET_ADMIN`
   - ⚠️ Must re-run after package updates

2. **Fallback to Sudoers**
   - Creates `/etc/sudoers.d/mcp-kali`
   - Passwordless sudo for specific tools only
   - Survives package updates
   - Slightly less secure than capabilities

### Installation Methods

The installer auto-detects and uses:

1. **npm** (if Node.js available)
   - Global package: `npm install -g @cyberstrike-io/mcp-kali`
   - Binary: `/usr/local/bin/mcp-kali-http`

2. **Docker** (if npm unavailable but Docker exists)
   - Pulls `cyberstrike/mcp-kali:latest`
   - Runs with `--cap-add=NET_RAW --cap-add=NET_ADMIN`

3. **Auto-install Node.js** (if neither available)
   - Installs Node.js 20.x from NodeSource
   - Then installs via npm

## 🔧 Advanced Configuration

### Custom Port

Edit the systemd service:

```bash
sudo systemctl edit mcp-kali

# Add:
[Service]
Environment=PORT=8443
```

Then restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart mcp-kali
```

### Custom Certificate

Replace the auto-generated certificate:

```bash
# Copy your certificate
sudo cp /path/to/your/cert.pem /var/lib/mcp-kali/certs/server.crt
sudo cp /path/to/your/key.pem /var/lib/mcp-kali/certs/server.key

# Set permissions
sudo chown mcp-kali:mcp-kali /var/lib/mcp-kali/certs/*
sudo chmod 600 /var/lib/mcp-kali/certs/server.key

# Restart service
sudo systemctl restart mcp-kali
```

### Add More Tools to Sudoers

```bash
# Edit sudoers file
sudo visudo -f /etc/sudoers.d/mcp-kali

# Add to MCP_NETWORK alias:
Cmnd_Alias MCP_NETWORK = \
    /usr/bin/nmap, \
    /usr/bin/masscan, \
    /usr/bin/YOUR_NEW_TOOL
```

### Re-apply Capabilities After Update

If you updated security tools (apt upgrade):

```bash
# Re-run capability setup
sudo bash /path/to/setup-capabilities.sh

# Or manually for specific tool:
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap
```

## 📂 File Locations

```
/var/lib/mcp-kali/                    # Data directory
├── certs/                            # TLS certificates
│   ├── server.crt                    # Certificate
│   └── server.key                    # Private key
├── logs/                             # Application logs
│   ├── current/                      # Latest logs
│   │   ├── audit.log                 # Client activities
│   │   ├── tools.log                 # Tool executions
│   │   ├── connections.log           # Sessions
│   │   └── errors.log                # Errors
│   └── archive/                      # Rotated logs
└── data/                             # Runtime data

/etc/systemd/system/mcp-kali.service  # Systemd service
/etc/sudoers.d/mcp-kali               # Sudoers config (if used)
```

## 🧪 Testing the Installation

```bash
# 1. Check service is running
systemctl is-active mcp-kali
# Should output: active

# 2. Check port is listening
sudo ss -tlnp | grep 3001
# Should show: LISTEN on *:3001

# 3. Test HTTPS endpoint (from server)
curl -k https://localhost:3001/health
# Should return: {"status":"healthy"}

# 4. Pair from client machine
cyberstrike mcp pair https://SERVER_IP:3001/mcp

# 5. Run a simple tool test
cyberstrike mcp call kali-bolt tool_search --query nmap
```

## 🐛 Troubleshooting

### Installation Failed

```bash
# Check the error message in the output
# Common issues:

# 1. Port 3001 already in use
sudo ss -tlnp | grep 3001
# Kill the process or change port in service config

# 2. Node.js version too old
node --version
# Should be >= 18.x

# 3. Missing dependencies
sudo apt-get update
sudo apt-get install -y curl openssl ca-certificates
```

### Service Won't Start

```bash
# Check service logs
journalctl -u mcp-kali -n 50 --no-pager

# Common issues:

# 1. Certificate permission error
sudo chown mcp-kali:mcp-kali /var/lib/mcp-kali/certs/*

# 2. Port permission denied
# Port < 1024 requires CAP_NET_BIND_SERVICE
# Use port 3001 (default) or higher

# 3. npm package not found
which mcp-kali-http
npm list -g @cyberstrike-io/mcp-kali
```

### Pairing Fails

```bash
# 1. Check firewall allows port 3001
sudo ufw status
sudo ufw allow 3001/tcp

# 2. Verify server is reachable
curl -k https://SERVER_IP:3001/health

# 3. Check TLS certificate
openssl s_client -connect SERVER_IP:3001 -showcerts

# 4. For self-signed certs, CLI may need to skip verification
# (See CyberStrike CLI docs for --insecure flag)
```

### Tools Require Password

```bash
# Check if sudoers or capabilities are configured

# For sudoers approach:
sudo -l -U mcp-kali
# Should list tools without NOPASSWD

# For capabilities approach:
getcap /usr/bin/nmap
# Should show: cap_net_raw,cap_net_admin+eip

# Fix: Re-run permission setup
sudo bash /path/to/install.sh  # Will detect and fix
```

## 🔄 Updating

```bash
# For npm installation
sudo npm update -g @cyberstrike-io/mcp-kali
sudo systemctl restart mcp-kali

# For Docker installation
docker pull cyberstrike/mcp-kali:latest
sudo systemctl restart mcp-kali

# Re-apply capabilities if needed (after apt upgrade)
sudo bash /path/to/setup-capabilities.sh
```

## 🗑️ Uninstallation

```bash
# Stop and disable service
sudo systemctl stop mcp-kali
sudo systemctl disable mcp-kali
sudo rm /etc/systemd/system/mcp-kali.service
sudo systemctl daemon-reload

# Remove npm package
sudo npm uninstall -g @cyberstrike-io/mcp-kali

# Or remove Docker image
docker stop mcp-kali
docker rm mcp-kali
docker rmi cyberstrike/mcp-kali

# Remove data and configs
sudo rm -rf /var/lib/mcp-kali
sudo rm -f /etc/sudoers.d/mcp-kali

# Remove service user
sudo userdel -r mcp-kali
```

## 📚 Next Steps

- **DEPLOYMENT.md** - Production deployment guide, security hardening
- **README.md** - Full documentation and API reference
- **docs.cyberstrike.io** - Complete CyberStrike documentation

## 🆘 Support

- **Issues**: https://github.com/CyberStrikeus/cyberstrike.io/issues
- **Discord**: https://discord.gg/cyberstrike
- **Docs**: https://docs.cyberstrike.io/mcp-kali
