#!/usr/bin/env bash

# Playwright Cleanup Script
# Use this to test the interactive Playwright installation feature
# Removes Playwright packages and browser binaries from all locations

set -e

echo "========================================"
echo "  Playwright Cleanup Script"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

cleanup_npm_global() {
    echo -e "${YELLOW}Checking npm global installation...${NC}"
    if npm list -g playwright &>/dev/null 2>&1; then
        echo "  Removing npm global playwright..."
        npm uninstall -g playwright playwright-core 2>/dev/null || true
        echo -e "  ${GREEN}npm global playwright removed${NC}"
    else
        echo "  No npm global playwright found"
    fi
}

cleanup_bun_global() {
    echo -e "${YELLOW}Checking bun global installation...${NC}"
    if command -v bun &>/dev/null; then
        if bun pm ls -g 2>/dev/null | grep -q playwright; then
            echo "  Removing bun global playwright..."
            bun remove -g playwright playwright-core 2>/dev/null || true
            echo -e "  ${GREEN}bun global playwright removed${NC}"
        else
            echo "  No bun global playwright found"
        fi
    else
        echo "  Bun not installed"
    fi
}

cleanup_local_node_modules() {
    echo -e "${YELLOW}Checking local node_modules...${NC}"

    # Current directory
    if [ -d "./node_modules/playwright" ] || [ -d "./node_modules/playwright-core" ]; then
        echo "  Removing from ./node_modules..."
        rm -rf ./node_modules/playwright ./node_modules/playwright-core 2>/dev/null || true
        echo -e "  ${GREEN}Local node_modules playwright removed${NC}"
    fi

    # Home directory common locations
    local locations=(
        "$HOME/node_modules"
        "$HOME/.npm/node_modules"
    )

    for loc in "${locations[@]}"; do
        if [ -d "$loc/playwright" ] || [ -d "$loc/playwright-core" ]; then
            echo "  Removing from $loc..."
            rm -rf "$loc/playwright" "$loc/playwright-core" 2>/dev/null || true
            echo -e "  ${GREEN}Removed from $loc${NC}"
        fi
    done

    echo "  Local node_modules checked"
}

cleanup_browser_binaries() {
    echo -e "${YELLOW}Checking browser binaries...${NC}"

    # Playwright stores browsers in different locations based on OS
    local browser_locations=(
        "$HOME/.cache/ms-playwright"           # Linux
        "$HOME/Library/Caches/ms-playwright"   # macOS
        "$HOME/.cache/playwright"              # Alternative Linux
        "$LOCALAPPDATA/ms-playwright"          # Windows (if running in WSL)
    )

    local found=false
    for loc in "${browser_locations[@]}"; do
        if [ -d "$loc" ]; then
            found=true
            local size=$(du -sh "$loc" 2>/dev/null | cut -f1)
            echo -e "  Found browser cache at $loc (${BLUE}$size${NC})"
            read -p "  Remove browser binaries? [Y/n] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                rm -rf "$loc"
                echo -e "  ${GREEN}Browser binaries removed${NC}"
            else
                echo "  Browser binaries kept"
            fi
        fi
    done

    if [ "$found" = false ]; then
        echo "  No browser binaries found"
    fi
}

cleanup_npm_cache() {
    echo -e "${YELLOW}Checking npm cache...${NC}"

    # Clean playwright from npm cache
    if [ -d "$HOME/.npm" ]; then
        local count=$(find "$HOME/.npm" -name "*playwright*" -type d 2>/dev/null | wc -l | tr -d ' ')
        if [ "$count" -gt 0 ]; then
            echo "  Found $count playwright entries in npm cache"
            find "$HOME/.npm" -name "*playwright*" -type d -exec rm -rf {} + 2>/dev/null || true
            echo -e "  ${GREEN}npm cache cleaned${NC}"
        else
            echo "  No playwright in npm cache"
        fi
    fi
}

cleanup_bun_cache() {
    echo -e "${YELLOW}Checking bun cache...${NC}"

    if [ -d "$HOME/.bun" ]; then
        # Bun install cache
        if [ -d "$HOME/.bun/install/cache" ]; then
            local count=$(find "$HOME/.bun/install/cache" -name "*playwright*" -type d 2>/dev/null | wc -l | tr -d ' ')
            if [ "$count" -gt 0 ]; then
                echo "  Found $count playwright entries in bun cache"
                find "$HOME/.bun/install/cache" -name "*playwright*" -type d -exec rm -rf {} + 2>/dev/null || true
                echo -e "  ${GREEN}bun cache cleaned${NC}"
            else
                echo "  No playwright in bun cache"
            fi
        fi

        # Bun global modules
        if [ -d "$HOME/.bun/install/global/node_modules" ]; then
            if [ -d "$HOME/.bun/install/global/node_modules/playwright" ]; then
                rm -rf "$HOME/.bun/install/global/node_modules/playwright" "$HOME/.bun/install/global/node_modules/playwright-core" 2>/dev/null || true
                echo -e "  ${GREEN}bun global modules cleaned${NC}"
            fi
        fi
    else
        echo "  Bun directory not found"
    fi
}

cleanup_pnpm() {
    echo -e "${YELLOW}Checking pnpm...${NC}"

    if command -v pnpm &>/dev/null; then
        if pnpm list -g playwright &>/dev/null 2>&1; then
            echo "  Removing pnpm global playwright..."
            pnpm remove -g playwright playwright-core 2>/dev/null || true
            echo -e "  ${GREEN}pnpm global playwright removed${NC}"
        else
            echo "  No pnpm global playwright found"
        fi

        # pnpm store
        local store=$(pnpm store path 2>/dev/null || echo "")
        if [ -n "$store" ] && [ -d "$store" ]; then
            local count=$(find "$store" -name "*playwright*" -type d 2>/dev/null | wc -l | tr -d ' ')
            if [ "$count" -gt 0 ]; then
                echo "  Found playwright in pnpm store, running prune..."
                pnpm store prune 2>/dev/null || true
                echo -e "  ${GREEN}pnpm store pruned${NC}"
            fi
        fi
    else
        echo "  pnpm not installed"
    fi
}

verify_removal() {
    echo ""
    echo -e "${YELLOW}Verifying removal...${NC}"

    local found=false

    # Check if playwright can be imported
    if node -e "require('playwright')" 2>/dev/null; then
        echo -e "  ${RED}WARNING: playwright still importable via Node.js${NC}"
        found=true
    fi

    if command -v bun &>/dev/null && bun -e "import('playwright')" 2>/dev/null; then
        echo -e "  ${RED}WARNING: playwright still importable via Bun${NC}"
        found=true
    fi

    # Check browser binaries
    for loc in "$HOME/.cache/ms-playwright" "$HOME/Library/Caches/ms-playwright"; do
        if [ -d "$loc" ]; then
            echo -e "  ${RED}WARNING: Browser binaries still exist at $loc${NC}"
            found=true
        fi
    done

    if [ "$found" = false ]; then
        echo -e "  ${GREEN}Playwright completely removed!${NC}"
    fi
}

show_test_instructions() {
    echo ""
    echo "========================================"
    echo "  Testing Instructions"
    echo "========================================"
    echo ""
    echo "Now you can test the interactive Playwright installation:"
    echo ""
    echo "  1. Start cyberstrike:"
    echo -e "     ${BLUE}cyberstrike${NC}"
    echo ""
    echo "  2. Use the browser tool:"
    echo -e "     ${BLUE}> Use the browser to navigate to https://example.com${NC}"
    echo ""
    echo "  3. You should see the prompt:"
    echo -e "     ${YELLOW}Would you like to install Playwright now? [Y/n]:${NC}"
    echo ""
    echo "  4. Press Y or Enter to test automatic installation"
    echo ""
}

# Main
echo "This script will remove Playwright from all locations."
echo "Use this to test the interactive installation feature."
echo ""

cleanup_npm_global
cleanup_bun_global
cleanup_local_node_modules
cleanup_npm_cache
cleanup_bun_cache
cleanup_pnpm
cleanup_browser_binaries
verify_removal
show_test_instructions

echo ""
echo "========================================"
echo "  Cleanup complete!"
echo "========================================"
