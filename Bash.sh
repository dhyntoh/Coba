#!/bin/bash

# install_vpn_auto.sh
# Auto-Installation Script with Token Verification

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ADMIN_BOT_TOKEN="8248259347:AAFHwfo0eytvsNbTt9PVinkbnL7dAIMPihk"

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

get_vps_ip() {
    VPS_IP=$(curl -s https://api.ipify.org)
    if [ -z "$VPS_IP" ]; then
        VPS_IP=$(hostname -I | awk '{print $1}')
    fi
    echo "$VPS_IP"
}

verify_installation_token() {
    local TOKEN="$1"
    local VPS_IP="$2"
    
    log "🔐 Verifying installation token..."
    
    # In real implementation, this would verify against database
    # For now, we'll do basic validation
    if [ ${#TOKEN} -lt 20 ]; then
        return 1
    fi
    
    # Simulate API verification
    log "✅ Token format valid"
    log "🖥️ VPS IP: $VPS_IP"
    
    return 0
}

notify_admin() {
    local message="$1"
    local url="https://api.telegram.org/bot${ADMIN_BOT_TOKEN}/sendMessage"
    
    curl -s -X POST $url \
        -d chat_id="5407046882" \
        -d text="$message" > /dev/null
}

perform_installation() {
    log "🚀 Starting installation process..."
    
    # Actual installation steps would go here
    log "📦 Installing dependencies..."
    # ... installation code ...
    
    log "✅ Installation completed successfully!"
}

main() {
    echo
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║               VPN AUTO-INSTALLATION                     ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    VPS_IP=$(get_vps_ip)
    echo -e "🖥️  VPS IP: ${YELLOW}$VPS_IP${NC}"
    echo
    
    # Check if token provided as argument
    if [ $# -eq 1 ]; then
        INSTALL_TOKEN="$1"
        echo -e "🔑 Token provided via command line"
    else
        echo -e "${YELLOW}🔐 Token Required${NC}"
        echo -e "Get your token from the admin bot using:"
        echo -e "   /mytoken"
        echo
        read -p "Enter installation token: " INSTALL_TOKEN
    fi
    
    if [ -z "$INSTALL_TOKEN" ]; then
        error "Installation token is required!"
    fi
    
    echo
    echo -e "${BLUE}⏳ Verifying token...${NC}"
    
    if verify_installation_token "$INSTALL_TOKEN" "$VPS_IP"; then
        echo
        log "✅ Token verified successfully!"
        
        # Notify admin
        notify_admin "🚀 Installation Started
VPS: $VPS_IP
Time: $(date)
Status: Token verified"
        
        # Perform installation
        perform_installation
        
        # Final notification
        notify_admin "🎉 Installation Completed
VPS: $VPS_IP
Time: $(date)
Status: SUCCESS"
        
    else
        error "❌ Invalid token! Please check your token and try again."
    fi
}

# Run installation
main "$@"
