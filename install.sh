#!/bin/bash
set -e

# Cyberstrike CLI Installer
# Usage: curl -fsSL https://cyberstrike.io/install.sh | bash
#
# For Windows PowerShell, use:
#   irm https://cyberstrike.io/install.ps1 | iex

REPO="CyberStrikeus/cyberstrike.io"
INSTALL_DIR="${CYBERSTRIKE_INSTALL_DIR:-$HOME/.local/bin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*)
            echo ""
            warn "You're running this in a Windows terminal emulator (Git Bash/MSYS/Cygwin)."
            echo ""
            echo -e "${CYAN}For native Windows, use PowerShell instead:${NC}"
            echo ""
            echo "  irm https://cyberstrike.io/install.ps1 | iex"
            echo ""
            echo -e "${CYAN}Or continue with this installer for the Unix-like environment.${NC}"
            echo ""
            read -p "Continue with Unix-style installation? [y/N]: " -r
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo "Aborted. Use the PowerShell command above for native Windows."
                exit 0
            fi
            echo "windows"
            ;;
        *) error "Unsupported operating system: $(uname -s)" ;;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x64" ;;
        arm64|aarch64) echo "arm64" ;;
        *) error "Unsupported architecture: $(uname -m)" ;;
    esac
}

# Get latest version from GitHub
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

main() {
    info "Installing Cyberstrike CLI..."

    OS=$(detect_os)
    ARCH=$(detect_arch)
    VERSION=$(get_latest_version)

    if [ -z "$VERSION" ]; then
        VERSION="v1.0.1"
        warn "Could not fetch latest version, using $VERSION"
    fi

    info "Detected: $OS-$ARCH"
    info "Version: $VERSION"

    # Construct download URL
    ASSET_NAME="cyberstrike-${OS}-${ARCH}.tar.gz"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}"

    # Create install directory
    mkdir -p "$INSTALL_DIR"

    # Download and extract
    info "Downloading from $DOWNLOAD_URL..."
    TEMP_DIR=$(mktemp -d)
    TEMP_FILE="$TEMP_DIR/$ASSET_NAME"

    if ! curl -fsSL "$DOWNLOAD_URL" -o "$TEMP_FILE"; then
        error "Failed to download $DOWNLOAD_URL"
    fi

    info "Extracting..."
    tar -xzf "$TEMP_FILE" -C "$TEMP_DIR"

    # Find and move binary
    if [ -f "$TEMP_DIR/cyberstrike" ]; then
        mv "$TEMP_DIR/cyberstrike" "$INSTALL_DIR/cyberstrike"
    elif [ -f "$TEMP_DIR/bin/cyberstrike" ]; then
        mv "$TEMP_DIR/bin/cyberstrike" "$INSTALL_DIR/cyberstrike"
    else
        error "Could not find cyberstrike binary in archive"
    fi

    chmod +x "$INSTALL_DIR/cyberstrike"

    # Cleanup
    rm -rf "$TEMP_DIR"

    info "Installed to $INSTALL_DIR/cyberstrike"

    # Check if install dir is in PATH
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        warn "$INSTALL_DIR is not in your PATH"
        echo ""

        # Detect current shell
        CURRENT_SHELL=$(basename "$SHELL")

        # Check if running in WSL
        if grep -qi microsoft /proc/version 2>/dev/null; then
            echo "You're running in WSL (Windows Subsystem for Linux)."
            echo ""
        fi

        echo "Add this line to your shell profile:"
        echo ""

        case "$CURRENT_SHELL" in
            zsh)
                echo "  # Add to ~/.zshrc:"
                echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
                ;;
            fish)
                echo "  # Add to ~/.config/fish/config.fish:"
                echo "  set -gx PATH $INSTALL_DIR \$PATH"
                ;;
            *)
                echo "  # Add to ~/.bashrc or ~/.profile:"
                echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
                ;;
        esac
        echo ""
        echo "Then reload your shell or run:"
        echo "  source ~/.$CURRENT_SHELL""rc"
        echo ""
    fi

    echo ""
    info "Cyberstrike CLI installed successfully!"
    echo ""
    echo "  Run 'cyberstrike --help' to get started"
    echo ""
}

main "$@"
