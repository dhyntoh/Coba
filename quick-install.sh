#!/bin/bash

# Quick Installer - One command setup
# Usage: curl -sSL https://raw.githubusercontent.com/your-repo/vpn/main/quick-install.sh | bash

set -e

echo "🔧 Ultimate VPN Quick Installer"
echo "📥 Downloading and installing..."

# Download main installer
if curl -sSL -o /tmp/vpn-installer.sh "https://raw.githubusercontent.com/dhyntoh/Coba/refs/heads/main/install.sh"; then
    chmod +x /tmp/vpn-installer.sh
    /tmp/vpn-installer.sh
else
    echo "❌ Failed to download installer"
    exit 1
fi
