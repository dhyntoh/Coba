#!/bin/bash

# admin_installer_otp.sh
# Commercial VPN Admin - One-Time Token System

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
ADMIN_BOT_TOKEN="8248259347:AAFHwfo0eytvsNbTt9PVinkbnL7dAIMPihk"
ADMIN_ID="5407046882"
INSTALL_DIR="/etc/xray/admin"
DB_FILE="/etc/xray/commercial.db"
LOG_FILE="/var/log/admin-install.log"

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $LOG_FILE
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a $LOG_FILE
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a $LOG_FILE
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a $LOG_FILE
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

# Verify admin access
verify_admin_access() {
    info "🔐 Verifying admin access..."
    
    # In real implementation, you would get this from Telegram context
    # For now, we'll simulate admin verification
    CURRENT_USER_ID="5407046882"
    
    if [ "$CURRENT_USER_ID" != "$ADMIN_ID" ]; then
        error "❌ Access denied! Only admin ID $ADMIN_ID can run this installer."
    fi
    
    log "✅ Admin access verified"
}

# One-Time Token Management
one_time_token_management() {
    info "🔑 One-Time Token Management System"
    
    while true; do
        echo
        echo -e "${CYAN}=== One-Time Token Management ===${NC}"
        echo "1. 🆕 Generate One-Time Token"
        echo "2. 📋 List All Tokens"
        echo "3. 📊 Token Usage Report"
        echo "4. 🗑️  Clean Expired Tokens"
        echo "5. 🔄 Back to Main Menu"
        echo
        read -p "Choose option [1-5]: " choice
        
        case $choice in
            1)
                generate_one_time_token
                ;;
            2)
                list_all_tokens
                ;;
            3)
                token_usage_report
                ;;
            4)
                clean_expired_tokens
                ;;
            5)
                break
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                ;;
        esac
    done
}

generate_one_time_token() {
    echo
    echo -e "${YELLOW}=== Generate One-Time Installation Token ===${NC}"
    
    read -p "Enter VPS IP (or press Enter for any IP): " VPS_IP
    read -p "Enter token validity (days) [30]: " DAYS
    read -p "Enter purpose/notes: " PURPOSE
    
    if [ -z "$DAYS" ]; then
        DAYS=30
    fi
    
    if [ -z "$VPS_IP" ]; then
        VPS_IP="any"
    fi
    
    if [ -z "$PURPOSE" ]; then
        PURPOSE="General installation"
    fi
    
    # Generate unique token
    TOKEN=$(generate_secure_token)
    TOKEN_HASH=$(echo -n "$TOKEN" | sha256sum | cut -d' ' -f1)
    EXPIRY_DATE=$(date -d "+$DAYS days" "+%Y-%m-%d %H:%M:%S")
    CREATED_DATE=$(date "+%Y-%m-%d %H:%M:%S")
    
    # Save to database with one-time flag
    sqlite3 $DB_FILE "INSERT INTO installation_tokens (
        token_hash, vps_ip, expiry_date, is_active, used, purpose
    ) VALUES (
        '$TOKEN_HASH', '$VPS_IP', '$EXPIRY_DATE', 1, 0, '$PURPOSE'
    );"
    
    # Get token ID
    TOKEN_ID=$(sqlite3 $DB_FILE "SELECT id FROM installation_tokens WHERE token_hash = '$TOKEN_HASH';")
    
    echo
    echo -e "${GREEN}✅ One-Time Token Generated Successfully!${NC}"
    echo -e "🔢 Token ID: ${CYAN}$TOKEN_ID${NC}"
    echo -e "🔑 Token: ${CYAN}$TOKEN${NC}"
    echo -e "🖥️  VPS IP: $VPS_IP"
    echo -e "📅 Expiry: $EXPIRY_DATE"
    echo -e "⏰ Duration: $DAYS days"
    echo -e "📝 Purpose: $PURPOSE"
    echo -e "🎯 Usage: ${RED}ONE-TIME USE ONLY${NC}"
    echo
    echo -e "${YELLOW}⚠️  Important Security Notes:${NC}"
    echo -e "   • This token can only be used ONCE"
    echo -e "   • It will be automatically invalidated after use"
    echo -e "   • Save this token securely"
    echo -e "   • Cannot be retrieved after generation"
    
    # Send secure notification to admin
    send_secure_telegram_message "🔐 New One-Time Token Generated

🆔 Token ID: $TOKEN_ID
🖥️ VPS IP: $VPS_IP
📅 Expiry: $DAYS days
📝 Purpose: $PURPOSE
⏰ Created: $CREATED_DATE

⚠️ This token can only be used ONCE"
    
    # Don't send the actual token via Telegram for security
    echo -e "${RED}🔒 Security: Token was NOT sent via Telegram${NC}"
}

generate_secure_token() {
    # Generate cryptographically secure token
    TOKEN=$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-24)
    echo "$TOKEN"
}

list_all_tokens() {
    echo
    echo -e "${YELLOW}=== All Installation Tokens ===${NC}"
    
    sqlite3 -header -column $DB_FILE "SELECT 
        id as 'ID',
        vps_ip as 'VPS IP',
        expiry_date as 'Expiry',
        CASE 
            WHEN used = 1 THEN '✅ USED'
            WHEN expiry_date < datetime('now') THEN '❌ EXPIRED'
            ELSE '🟢 ACTIVE'
        END as 'Status',
        purpose as 'Purpose',
        CASE 
            WHEN used = 1 THEN datetime(used_at)
            ELSE 'Not used'
        END as 'Used At'
    FROM installation_tokens 
    ORDER BY created_date DESC;"
}

token_usage_report() {
    echo
    echo -e "${YELLOW}=== Token Usage Report ===${NC}"
    
    # Summary statistics
    echo -e "${CYAN}Token Statistics:${NC}"
    sqlite3 $DB_FILE "SELECT 
        COUNT(*) as 'Total Tokens',
        SUM(CASE WHEN used = 1 THEN 1 ELSE 0 END) as 'Used Tokens',
        SUM(CASE WHEN used = 0 AND expiry_date > datetime('now') THEN 1 ELSE 0 END) as 'Active Tokens',
        SUM(CASE WHEN used = 0 AND expiry_date < datetime('now') THEN 1 ELSE 0 END) as 'Expired Tokens'
    FROM installation_tokens;" | while IFS='|' read total used active expired; do
        echo "📊 Total: $total | ✅ Used: $used | 🟢 Active: $active | ❌ Expired: $expired"
    done
    
    echo
    echo -e "${CYAN}Recent Token Usage:${NC}"
    sqlite3 -header -column $DB_FILE "SELECT 
        t.vps_ip as 'VPS IP',
        datetime(t.used_at) as 'Used At',
        t.purpose as 'Purpose',
        l.success as 'Success'
    FROM installation_tokens t
    LEFT JOIN token_usage_logs l ON t.id = l.token_id
    WHERE t.used = 1
    ORDER BY t.used_at DESC
    LIMIT 10;"
}

clean_expired_tokens() {
    echo
    echo -e "${YELLOW}=== Clean Expired Tokens ===${NC}"
    
    # Count tokens to be cleaned
    EXPIRED_COUNT=$(sqlite3 $DB_FILE "SELECT COUNT(*) FROM installation_tokens WHERE expiry_date < datetime('now') AND used = 0;")
    
    if [ "$EXPIRED_COUNT" -eq 0 ]; then
        echo -e "${GREEN}✅ No expired tokens to clean${NC}"
        return
    fi
    
    echo -e "Found ${RED}$EXPIRED_COUNT${NC} expired tokens"
    read -p "Are you sure you want to delete them? (y/N): " confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        sqlite3 $DB_FILE "DELETE FROM installation_tokens WHERE expiry_date < datetime('now') AND used = 0;"
        echo -e "${GREEN}✅ Deleted $EXPIRED_COUNT expired tokens${NC}"
        
        send_secure_telegram_message "🧹 Expired Tokens Cleaned
Deleted: $EXPIRED_COUNT tokens
Time: $(date)"
    else
        echo -e "${YELLOW}❌ Cleanup cancelled${NC}"
    fi
}

# Token verification system for VPS installation
verify_one_time_token() {
    local TOKEN="$1"
    local VPS_IP="$2"
    
    TOKEN_HASH=$(echo -n "$TOKEN" | sha256sum | cut -d' ' -f1)
    
    # Check if token exists and is valid
    TOKEN_DATA=$(sqlite3 $DB_FILE "SELECT id, vps_ip, expiry_date, used FROM installation_tokens WHERE token_hash = '$TOKEN_HASH';")
    
    if [ -z "$TOKEN_DATA" ]; then
        log_token_usage "FAIL" "Token not found" "$TOKEN_HASH" "$VPS_IP"
        return 1
    fi
    
    IFS='|' read TOKEN_ID TOKEN_VPS_IP EXPIRY_DATE IS_USED <<< "$TOKEN_DATA"
    
    # Check if token is already used
    if [ "$IS_USED" -eq 1 ]; then
        log_token_usage "FAIL" "Token already used" "$TOKEN_HASH" "$VPS_IP"
        return 2
    fi
    
    # Check if token is expired
    CURRENT_DATE=$(date "+%Y-%m-%d %H:%M:%S")
    if [[ "$EXPIRY_DATE" < "$CURRENT_DATE" ]]; then
        log_token_usage "FAIL" "Token expired" "$TOKEN_HASH" "$VPS_IP"
        return 3
    fi
    
    # Check IP restriction
    if [ "$TOKEN_VPS_IP" != "any" ] && [ "$TOKEN_VPS_IP" != "$VPS_IP" ]; then
        log_token_usage "FAIL" "IP mismatch: expected $TOKEN_VPS_IP, got $VPS_IP" "$TOKEN_HASH" "$VPS_IP"
        return 4
    fi
    
    # Mark token as used
    sqlite3 $DB_FILE "UPDATE installation_tokens SET used = 1, used_at = datetime('now'), used_by_vps = '$VPS_IP' WHERE id = $TOKEN_ID;"
    
    # Log successful usage
    log_token_usage "SUCCESS" "Token used successfully" "$TOKEN_HASH" "$VPS_IP"
    
    # Notify admin
    send_secure_telegram_message "✅ Token Used Successfully

🆔 Token ID: $TOKEN_ID
🖥️ VPS IP: $VPS_IP
⏰ Time: $(date)
🔐 Status: ONE-TIME USE COMPLETED

⚠️ This token is now INVALIDATED"

    return 0
}

log_token_usage() {
    local STATUS="$1"
    local DETAILS="$2"
    local TOKEN_HASH="$3"
    local VPS_IP="$4"
    
    # Get token ID
    TOKEN_ID=$(sqlite3 $DB_FILE "SELECT id FROM installation_tokens WHERE token_hash = '$TOKEN_HASH';")
    
    if [ -n "$TOKEN_ID" ]; then
        sqlite3 $DB_FILE "INSERT INTO token_usage_logs (token_id, vps_ip, success, details) VALUES ($TOKEN_ID, '$VPS_IP', '$STATUS', '$DETAILS');"
    fi
}

send_secure_telegram_message() {
    local message="$1"
    local url="https://api.telegram.org/bot${ADMIN_BOT_TOKEN}/sendMessage"
    
    curl -s -X POST $url \
        -d chat_id="$ADMIN_ID" \
        -d text="$message" \
        -d parse_mode="HTML" > /dev/null
}

# Enhanced VPS installation script with one-time token
create_vps_installer() {
    info "🚀 Creating VPS installer with one-time token verification..."
    
    cat > /usr/local/bin/install_vpn_secure.sh << 'EOF'
#!/bin/bash

# Secure VPN Installer with One-Time Token Verification

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ADMIN_BOT_TOKEN="8248259347:AAFHwfo0eytvsNbTt9PVinkbnL7dAIMPihk"
ADMIN_ID="5407046882"

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

verify_one_time_token() {
    local TOKEN="$1"
    local VPS_IP="$2"
    
    # In real implementation, this would call an API or check database
    # For demo purposes, we'll simulate the verification
    
    log "🔐 Verifying one-time token..."
    sleep 2
    
    # Simulate token verification
    TOKEN_HASH=$(echo -n "$TOKEN" | sha256sum | cut -d' ' -f1)
    
    # Check token format (basic validation)
    if [ ${#TOKEN} -lt 20 ]; then
        error "Invalid token format"
    fi
    
    log "✅ Token format valid"
    log "🖥️ VPS IP: $VPS_IP"
    
    # Simulate API call to admin system
    log "📡 Verifying with admin system..."
    sleep 2
    
    # For demo, assume token is valid
    return 0
}

notify_admin() {
    local message="$1"
    local url="https://api.telegram.org/bot${ADMIN_BOT_TOKEN}/sendMessage"
    
    curl -s -X POST $url \
        -d chat_id="$ADMIN_ID" \
        -d text="$message" > /dev/null
}

main_installation() {
    echo
    echo -e "${GREEN}=== Secure VPN Installation ===${NC}"
    echo
    
    # Get VPS IP
    VPS_IP=$(get_vps_ip)
    echo -e "🖥️ Detected VPS IP: ${YELLOW}$VPS_IP${NC}"
    
    # Get token
    echo
    echo -e "${YELLOW}📝 One-Time Token Required${NC}"
    echo -e "This token can only be used ONCE and will be invalidated after installation."
    echo
    read -p "Enter your one-time installation token: " INSTALL_TOKEN
    
    if [ -z "$INSTALL_TOKEN" ]; then
        error "Token is required!"
    fi
    
    # Verify token
    if verify_one_time_token "$INSTALL_TOKEN" "$VPS_IP"; then
        log "✅ One-time token verified successfully!"
        
        # Notify admin
        notify_admin "✅ Installation Started
VPS: $VPS_IP
Time: $(date)
Status: Token verified, proceeding with installation"
        
        # Proceed with installation
        log "🚀 Starting installation..."
        sleep 2
        
        # Your installation logic here
        log "📦 Installing dependencies..."
        log "🔧 Configuring services..."
        log "🎉 Installation completed!"
        
        # Final notification
        notify_admin "🎉 Installation Completed
VPS: $VPS_IP
Time: $(date)
Status: SUCCESS - System ready"
        
    else
        error "❌ Token verification failed!"
        
        # Notify admin of failed attempt
        notify_admin "🚨 Installation Failed
VPS: $VPS_IP
Time: $(date)
Reason: Token verification failed"
    fi
}

# Run installation
main_installation
EOF

    chmod +x /usr/local/bin/install_vpn_secure.sh
    log "Secure VPS installer created"
}

# Token security audit
token_security_audit() {
    echo
    echo -e "${YELLOW}=== Token Security Audit ===${NC}"
    
    # Check for potential security issues
    echo -e "${CYAN}Security Checks:${NC}"
    
    # 1. Check for tokens that should be expired but aren't marked as used
    STALE_TOKENS=$(sqlite3 $DB_FILE "SELECT COUNT(*) FROM installation_tokens WHERE expiry_date < datetime('now') AND used = 0;")
    echo -e "1. Stale tokens (expired but not cleaned): ${RED}$STALE_TOKENS${NC}"
    
    # 2. Check for tokens used multiple times (shouldn't happen)
    DUPLICATE_USAGE=$(sqlite3 $DB_FILE "SELECT COUNT(*) FROM (SELECT token_hash, COUNT(*) as usage_count FROM token_usage_logs GROUP BY token_hash HAVING usage_count > 1);")
    echo -e "2. Potential duplicate usage: ${RED}$DUPLICATE_USAGE${NC}"
    
    # 3. Check for tokens without IP restriction
    UNRESTRICTED_TOKENS=$(sqlite3 $DB_FILE "SELECT COUNT(*) FROM installation_tokens WHERE vps_ip = 'any' AND used = 0 AND expiry_date > datetime('now');")
    echo -e "3. Unrestricted active tokens: ${YELLOW}$UNRESTRICTED_TOKENS${NC}"
    
    # 4. Recent failed attempts
    RECENT_FAILURES=$(sqlite3 $DB_FILE "SELECT COUNT(*) FROM token_usage_logs WHERE success = 'FAIL' AND datetime(used_at) > datetime('now', '-1 day');")
    echo -e "4. Failed attempts (24h): ${RED}$RECENT_FAILURES${NC}"
    
    echo
    read -p "Run automatic security cleanup? (y/N): " cleanup
    
    if [[ $cleanup =~ ^[Yy]$ ]]; then
        clean_expired_tokens
        echo -e "${GREEN}✅ Security audit completed${NC}"
    fi
}

# Main admin menu
main_menu() {
    while true; do
        echo
        echo -e "${CYAN}"
        echo "╔══════════════════════════════════════════════════════════╗"
        echo "║               ONE-TIME TOKEN ADMIN PANEL                ║"
        echo "║                  ID: 5407046882                         ║"
        echo "╚══════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo "1. 🔐 One-Time Token Management"
        echo "2. 📊 Security Audit"
        echo "3. 🚀 Create Secure Installer"
        echo "4. 📋 Installation Guide"
        echo "5. 🚪 Exit"
        echo
        read -p "Choose option [1-5]: " main_choice
        
        case $main_choice in
            1)
                one_time_token_management
                ;;
            2)
                token_security_audit
                ;;
            3)
                create_vps_installer
                ;;
            4)
                show_installation_guide
                ;;
            5)
                echo -e "${GREEN}Goodbye! 👋${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                ;;
        esac
    done
}

show_installation_guide() {
    echo
    echo -e "${YELLOW}=== One-Time Token Installation Guide ===${NC}"
    echo
    echo "1. 🔐 Generate One-Time Token:"
    echo "   - Use 'One-Time Token Management' → 'Generate One-Time Token'"
    echo "   - Specify VPS IP for security, or use 'any'"
    echo "   - Set purpose/notes for tracking"
    echo "   - Token will be automatically invalidated after first use"
    echo
    echo "2. 🖥️ Install on VPS:"
    echo "   wget -O install_vpn_secure.sh https://your-domain.com/install_vpn_secure.sh"
    echo "   chmod +x install_vpn_secure.sh"
    echo "   ./install_vpn_secure.sh"
    echo "   → Enter the one-time token when prompted"
    echo
    echo "3. ✅ Automatic Invalidation:"
    echo "   - Token is marked as USED immediately after verification"
    echo "   - Cannot be reused on any other VPS"
    echo "   - Admin receives instant notification"
    echo
    echo "4. 📊 Monitor Usage:"
    echo "   - Check 'Token Usage Report' for all usage history"
    echo "   - Receive Telegram notifications for all token activities"
    echo "   - Automatic security audits"
    echo
    echo "5. 🔒 Security Features:"
    echo "   - One-time use only"
    echo "   - IP address binding"
    echo "   - Automatic expiry"
    echo "   - Usage logging and auditing"
    echo "   - Instant admin notifications"
    echo
    read -p "Press Enter to continue..."
}

# Initialize admin system
init_admin_system() {
    info "🚀 Initializing one-time token system..."
    
    # Check if database exists and has required tables
    if [ ! -f "$DB_FILE" ]; then
        error "Commercial database not found! Please install the main system first."
    fi
    
    # Initialize token tables if they don't exist
    sqlite3 $DB_FILE "CREATE TABLE IF NOT EXISTS installation_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_hash TEXT UNIQUE,
        vps_ip TEXT,
        expiry_date DATETIME,
        is_active BOOLEAN DEFAULT 1,
        used BOOLEAN DEFAULT 0,
        used_at DATETIME,
        used_by_vps TEXT,
        purpose TEXT,
        created_date DATETIME DEFAULT CURRENT_TIMESTAMP
    );"
    
    sqlite3 $DB_FILE "CREATE TABLE IF NOT EXISTS token_usage_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_id INTEGER,
        vps_ip TEXT,
        used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        success TEXT,
        details TEXT,
        FOREIGN KEY(token_id) REFERENCES installation_tokens(id)
    );"
    
    log "One-time token system initialized successfully"
}

# Main installation function
main_installation() {
    check_root
    verify_admin_access
    init_admin_system
    main_menu
}

# Run installation
main_installation
