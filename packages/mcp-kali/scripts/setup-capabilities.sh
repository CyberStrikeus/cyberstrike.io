#!/bin/bash
# Bolt MCP Kali - Linux Capabilities Setup
# This grants specific capabilities to tools instead of using sudo

set -e

if [ "$EUID" -ne 0 ]; then
   echo "❌ Please run as root or with sudo"
   exit 1
fi

echo "🔐 Setting up Linux capabilities for MCP Kali tools..."
echo "   This is MORE SECURE than sudoers (minimum privilege principle)"
echo ""

# Function to set capabilities
set_caps() {
    local tool=$1
    local caps=$2

    if [ -f "$tool" ]; then
        echo "   ✓ $tool"
        setcap "$caps" "$tool"
    else
        echo "   ⚠ $tool not found (skipping)"
    fi
}

# Network raw socket capabilities (for packet crafting)
echo "📡 Network scanning tools..."
set_caps /usr/bin/nmap "cap_net_raw,cap_net_admin,cap_net_bind_service+eip"
set_caps /usr/bin/masscan "cap_net_raw,cap_net_admin+eip"
set_caps /usr/bin/zmap "cap_net_raw,cap_net_admin+eip"
set_caps /usr/bin/unicornscan "cap_net_raw,cap_net_admin+eip"
set_caps /usr/bin/hping3 "cap_net_raw+eip"

# Packet capture capabilities
echo ""
echo "📦 Packet sniffing tools..."
set_caps /usr/bin/tcpdump "cap_net_raw,cap_net_admin+eip"
set_caps /usr/bin/dumpcap "cap_net_raw,cap_net_admin+eip"
set_caps /usr/bin/tshark "cap_net_raw,cap_net_admin+eip"

# Wireless tools (need raw sockets + admin)
echo ""
echo "📶 Wireless tools..."
set_caps /usr/sbin/airmon-ng "cap_net_raw,cap_net_admin+eip"
set_caps /usr/sbin/airodump-ng "cap_net_raw,cap_net_admin+eip"
set_caps /usr/bin/bettercap "cap_net_raw,cap_net_admin,cap_net_bind_service+eip"

# Network utilities
echo ""
echo "🌐 Network utilities..."
set_caps /usr/sbin/arp-scan "cap_net_raw+eip"

echo ""
echo "✅ Capabilities setup complete!"
echo ""
echo "🔍 Verify with: getcap /usr/bin/nmap"
echo ""
echo "⚠️  NOTE: File updates (apt upgrade) will reset capabilities."
echo "   Run this script again after package updates."
