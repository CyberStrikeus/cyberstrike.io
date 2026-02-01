#!/bin/bash
#
# Cyberstrike Installation Script
# https://cyberstrike.io
#
# Usage:
#   curl -fsSL https://cyberstrike.io/install.sh | bash
#   wget -qO- https://cyberstrike.io/install.sh | bash
#
# Environment variables:
#   CYBERSTRIKE_INSTALL_DIR - Installation directory (default: ~/.cyberstrike)
#   CYBERSTRIKE_VERSION     - Specific version to install (default: latest)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
INSTALL_DIR="${CYBERSTRIKE_INSTALL_DIR:-$HOME/.cyberstrike}"
BIN_DIR="$INSTALL_DIR/bin"
VERSION="${CYBERSTRIKE_VERSION:-latest}"
GITHUB_REPO="CyberStrikeus/cyberstrike.io"

# Print banner
print_banner() {
    echo -e "${CYAN}"
    echo "   ______      __              _____ __       _ __       "
    echo "  / ____/_  __/ /_  ___  _____/ ___// /______(_) /_____  "
    echo " / /   / / / / __ \/ _ \/ ___/\__ \/ __/ ___/ / //_/ _ \ "
    echo "/ /___/ /_/ / /_/ /  __/ /   ___/ / /_/ /  / / ,< /  __/ "
    echo "\____/\__, /_.___/\___/_/   /____/\__/_/  /_/_/|_|\___/  "
    echo "     /____/                                              "
    echo -e "${NC}"
    echo -e "${BLUE}AI-powered penetration testing agent${NC}"
    echo ""
}

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux*)     PLATFORM="linux" ;;
        Darwin*)    PLATFORM="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
        *)          error "Unsupported operating system: $OS" ;;
    esac

    case "$ARCH" in
        x86_64|amd64)   ARCH="x64" ;;
        arm64|aarch64)  ARCH="arm64" ;;
        *)              error "Unsupported architecture: $ARCH" ;;
    esac

    echo -e "${GREEN}Detected platform:${NC} $PLATFORM-$ARCH"
}

# Print error and exit
error() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

# Print warning
warn() {
    echo -e "${YELLOW}Warning: $1${NC}"
}

# Print info
info() {
    echo -e "${GREEN}$1${NC}"
}

# Check dependencies
check_deps() {
    local missing=()

    for cmd in curl tar; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        error "Missing required dependencies: ${missing[*]}"
    fi
}

# Get latest version from GitHub
get_latest_version() {
    local latest
    latest=$(curl -fsSL "https://api.github.com/repos/$GITHUB_REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')

    if [ -z "$latest" ]; then
        error "Failed to fetch latest version"
    fi

    echo "$latest"
}

# Download and install
install() {
    # Get version
    if [ "$VERSION" = "latest" ]; then
        info "Fetching latest version..."
        VERSION=$(get_latest_version)
    fi

    info "Installing Cyberstrike v$VERSION..."

    # Create directories
    mkdir -p "$BIN_DIR"

    # Construct download URL
    local filename="cyberstrike-${PLATFORM}-${ARCH}.tar.gz"
    local url="https://github.com/$GITHUB_REPO/releases/download/v$VERSION/$filename"

    # Download
    info "Downloading from $url..."
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT

    if ! curl -fsSL "$url" -o "$tmp_dir/$filename"; then
        error "Failed to download Cyberstrike. Please check the version and try again."
    fi

    # Extract
    info "Extracting..."
    tar -xzf "$tmp_dir/$filename" -C "$tmp_dir"

    # Install binary
    if [ -f "$tmp_dir/cyberstrike" ]; then
        mv "$tmp_dir/cyberstrike" "$BIN_DIR/cyberstrike"
        chmod +x "$BIN_DIR/cyberstrike"
    elif [ -f "$tmp_dir/cyberstrike.exe" ]; then
        mv "$tmp_dir/cyberstrike.exe" "$BIN_DIR/cyberstrike.exe"
    else
        error "Binary not found in archive"
    fi

    info "Installed to $BIN_DIR/cyberstrike"
}

# Add to PATH
setup_path() {
    local shell_config=""
    local shell_name=""

    # Detect shell
    case "$SHELL" in
        */bash)
            shell_name="bash"
            if [ -f "$HOME/.bashrc" ]; then
                shell_config="$HOME/.bashrc"
            elif [ -f "$HOME/.bash_profile" ]; then
                shell_config="$HOME/.bash_profile"
            fi
            ;;
        */zsh)
            shell_name="zsh"
            shell_config="$HOME/.zshrc"
            ;;
        */fish)
            shell_name="fish"
            shell_config="$HOME/.config/fish/config.fish"
            ;;
    esac

    # Check if already in PATH
    if echo "$PATH" | grep -q "$BIN_DIR"; then
        return
    fi

    if [ -n "$shell_config" ] && [ -f "$shell_config" ]; then
        # Check if already added
        if ! grep -q "CYBERSTRIKE" "$shell_config" 2>/dev/null; then
            echo "" >> "$shell_config"
            echo "# Cyberstrike" >> "$shell_config"
            if [ "$shell_name" = "fish" ]; then
                echo "set -gx PATH \$PATH $BIN_DIR" >> "$shell_config"
            else
                echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$shell_config"
            fi
            info "Added Cyberstrike to PATH in $shell_config"
            warn "Run 'source $shell_config' or restart your terminal to use cyberstrike"
        fi
    else
        warn "Could not detect shell config file."
        echo ""
        echo "Add the following to your shell config:"
        echo -e "  ${CYAN}export PATH=\"\$PATH:$BIN_DIR\"${NC}"
    fi
}

# Print success message
print_success() {
    echo ""
    echo -e "${GREEN}Cyberstrike installed successfully!${NC}"
    echo ""
    echo "Get started:"
    echo -e "  ${CYAN}export ANTHROPIC_API_KEY=your_key_here${NC}"
    echo -e "  ${CYAN}cyberstrike${NC}"
    echo ""
    echo "Documentation: https://docs.cyberstrike.io"
    echo "GitHub: https://github.com/$GITHUB_REPO"
    echo ""
}

# Main
main() {
    print_banner
    check_deps
    detect_platform
    install
    setup_path
    print_success
}

main "$@"
