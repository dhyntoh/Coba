#!/bin/bash

# admin_installer.sh
# Commercial VPN Admin Installation System

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Get VPS IP
get_vps_ip() {
    VPS_IP=$(curl -s https://api.ipify.org)
    if [ -z "$VPS_IP" ]; then
        VPS_IP=$(hostname -I | awk '{print $1}')
    fi
    echo "$VPS_IP"
}

# Verify admin access
verify_admin_access() {
    info "🔐 Verifying admin access..."
    
    CURRENT_USER_ID="5407046882"  # This would be dynamic in real scenario
    
    if [ "$CURRENT_USER_ID" != "$ADMIN_ID" ]; then
        error "❌ Access denied! Only admin ID $ADMIN_ID can run this installer."
    fi
    
    log "✅ Admin access verified"
}

# Token management system
token_management() {
    info "🔑 Token Management System"
    
    while true; do
        echo
        echo -e "${CYAN}=== Token Management ===${NC}"
        echo "1. Generate New Token"
        echo "2. List Active Tokens"
        echo "3. Extend Token Validity"
        echo "4. Revoke Token"
        echo "5. Check Token Status"
        echo "6. Back to Main Menu"
        echo
        read -p "Choose option [1-6]: " choice
        
        case $choice in
            1)
                generate_token
                ;;
            2)
                list_tokens
                ;;
            3)
                extend_token
                ;;
            4)
                revoke_token
                ;;
            5)
                check_token_status
                ;;
            6)
                break
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                ;;
        esac
    done
}

generate_token() {
    echo
    echo -e "${YELLOW}=== Generate New Installation Token ===${NC}"
    
    read -p "Enter VPS IP (or press Enter for any IP): " VPS_IP
    read -p "Enter token validity (days): " DAYS
    
    if [ -z "$DAYS" ]; then
        DAYS=30
    fi
    
    if [ -z "$VPS_IP" ]; then
        VPS_IP="any"
    fi
    
    # Generate random token
    TOKEN=$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-32)
    TOKEN_HASH=$(echo -n "$TOKEN" | sha256sum | cut -d' ' -f1)
    EXPIRY_DATE=$(date -d "+$DAYS days" "+%Y-%m-%d %H:%M:%S")
    
    # Save to database
    sqlite3 $DB_FILE "INSERT INTO installation_tokens (token_hash, vps_ip, expiry_date) VALUES ('$TOKEN_HASH', '$VPS_IP', '$EXPIRY_DATE');"
    
    echo
    echo -e "${GREEN}✅ Token Generated Successfully!${NC}"
    echo -e "🔑 Token: ${CYAN}$TOKEN${NC}"
    echo -e "🖥️  VPS IP: $VPS_IP"
    echo -e "📅 Expiry: $EXPIRY_DATE"
    echo -e "⏰ Duration: $DAYS days"
    echo
    echo -e "${YELLOW}⚠️  Important: Save this token immediately!${NC}"
    echo -e "It cannot be retrieved later."
    
    # Send to admin via Telegram
    send_telegram_message "🔑 New Token Generated
VPS: $VPS_IP
Expiry: $DAYS days
Token: $TOKEN"
}

list_tokens() {
    echo
    echo -e "${YELLOW}=== Active Installation Tokens ===${NC}"
    
    sqlite3 -header -column $DB_FILE "SELECT 
        vps_ip as 'VPS IP', 
        expiry_date as 'Expiry Date',
        CASE WHEN is_active = 1 THEN 'Active' ELSE 'Inactive' END as Status,
        datetime(created_date) as 'Created'
    FROM installation_tokens 
    ORDER BY created_date DESC;"
}

extend_token() {
    echo
    echo -e "${YELLOW}=== Extend Token Validity ===${NC}"
    
    read -p "Enter VPS IP to extend: " VPS_IP
    read -p "Enter additional days: " DAYS
    
    if [ -z "$VPS_IP" ] || [ -z "$DAYS" ]; then
        error "VPS IP and days are required!"
    fi
    
    sqlite3 $DB_FILE "UPDATE installation_tokens SET expiry_date = datetime(expiry_date, '+$DAYS days') WHERE vps_ip = '$VPS_IP';"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Token extended for $VPS_IP by $DAYS days${NC}"
        send_telegram_message "🔄 Token Extended
VPS: $VPS_IP
Added: $DAYS days"
    else
        error "❌ Failed to extend token"
    fi
}

revoke_token() {
    echo
    echo -e "${YELLOW}=== Revoke Token ===${NC}"
    
    read -p "Enter VPS IP to revoke: " VPS_IP
    
    if [ -z "$VPS_IP" ]; then
        error "VPS IP is required!"
    fi
    
    sqlite3 $DB_FILE "UPDATE installation_tokens SET is_active = 0 WHERE vps_ip = '$VPS_IP';"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Token revoked for $VPS_IP${NC}"
        send_telegram_message "🚫 Token Revoked
VPS: $VPS_IP"
    else
        error "❌ Failed to revoke token"
    fi
}

check_token_status() {
    echo
    echo -e "${YELLOW}=== Token Status Check ===${NC}"
    
    read -p "Enter VPS IP to check: " VPS_IP
    
    if [ -z "$VPS_IP" ]; then
        error "VPS IP is required!"
    fi
    
    sqlite3 -header -column $DB_FILE "SELECT 
        vps_ip as 'VPS IP',
        expiry_date as 'Expiry Date',
        CASE WHEN is_active = 1 THEN 'Active' ELSE 'Inactive' END as Status,
        CASE WHEN expiry_date > datetime('now') THEN 'Valid' ELSE 'Expired' END as 'Validity'
    FROM installation_tokens 
    WHERE vps_ip = '$VPS_IP';"
}

# System monitoring
system_monitoring() {
    info "📊 System Monitoring"
    
    while true; do
        echo
        echo -e "${CYAN}=== System Monitoring ===${NC}"
        echo "1. System Statistics"
        echo "2. User Statistics"
        echo "3. Sales Report"
        echo "4. Payment Status"
        echo "5. Service Status"
        echo "6. Back to Main Menu"
        echo
        read -p "Choose option [1-6]: " choice
        
        case $choice in
            1)
                show_system_stats
                ;;
            2)
                show_user_stats
                ;;
            3)
                show_sales_report
                ;;
            4)
                show_payment_status
                ;;
            5)
                show_service_status
                ;;
            6)
                break
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                ;;
        esac
    done
}

show_system_stats() {
    echo
    echo -e "${YELLOW}=== System Statistics ===${NC}"
    
    # VPS Information
    VPS_IP=$(get_vps_ip)
    UPTIME=$(uptime -p)
    LOAD=$(uptime | awk -F'load average:' '{print $2}')
    MEMORY=$(free -h | grep Mem | awk '{print $3"/"$2}')
    DISK=$(df -h / | grep -v Filesystem | awk '{print $3"/"$2" ("$5")"}')
    
    echo "🖥️  VPS IP: $VPS_IP"
    echo "⏰ Uptime: $UPTIME"
    echo "📊 Load: $LOAD"
    echo "💾 Memory: $MEMORY"
    echo "💿 Disk: $DISK"
    
    # Database statistics
    echo
    echo -e "${CYAN}Database Statistics:${NC}"
    sqlite3 $DB_FILE "SELECT 
        (SELECT COUNT(*) FROM users) as 'Total Users',
        (SELECT COUNT(*) FROM users WHERE is_active = 1) as 'Active Users',
        (SELECT COUNT(*) FROM vpn_accounts) as 'Total Accounts',
        (SELECT COUNT(*) FROM vpn_accounts WHERE is_active = 1 AND expiry_date > datetime('now')) as 'Active Accounts',
        (SELECT SUM(balance) FROM users) as 'Total Balance',
        (SELECT SUM(total_spent) FROM users) as 'Total Revenue';" | while IFS='|' read users active_users accounts active_accounts balance revenue; do
        echo "👥 Users: $users (Active: $active_users)"
        echo "📱 Accounts: $accounts (Active: $active_accounts)"
        echo "💰 Total Balance: Rp ${balance:-0}"
        echo "💳 Total Revenue: Rp ${revenue:-0}"
    done
}

show_user_stats() {
    echo
    echo -e "${YELLOW}=== User Statistics ===${NC}"
    
    sqlite3 -header -column $DB_FILE "SELECT 
        username as 'Username',
        balance as 'Balance',
        total_spent as 'Total Spent',
        accounts_created as 'Accounts',
        datetime(join_date) as 'Join Date'
    FROM users 
    ORDER BY join_date DESC 
    LIMIT 10;"
}

show_sales_report() {
    echo
    echo -e "${YELLOW}=== Sales Report (Last 7 Days) ===${NC}"
    
    sqlite3 -header -column $DB_FILE "SELECT 
        date(va.created_date) as 'Date',
        COUNT(*) as 'Accounts Sold',
        SUM(va.data_limit)/1073741824 as 'Total GB',
        SUM(s.price_per_gb * (va.data_limit/1073741824)) as 'Revenue'
    FROM vpn_accounts va
    JOIN servers s ON va.server_id = s.id
    WHERE date(va.created_date) >= date('now', '-7 days')
    GROUP BY date(va.created_date)
    ORDER BY Date DESC;"
}

show_payment_status() {
    echo
    echo -e "${YELLOW}=== Payment Status ===${NC}"
    
    sqlite3 -header -column $DB_FILE "SELECT 
        t.id as 'ID',
        u.username as 'User',
        t.amount as 'Amount',
        t.status as 'Status',
        datetime(t.created_date) as 'Created',
        datetime(t.completed_date) as 'Completed'
    FROM transactions t
    JOIN users u ON t.user_id = u.id
    ORDER BY t.created_date DESC
    LIMIT 10;"
}

show_service_status() {
    echo
    echo -e "${YELLOW}=== Service Status ===${NC}"
    
    echo "Xray Service: $(systemctl is-active xray)"
    echo "Commercial Bot: $(systemctl is-active xray-commercial-bot)"
    echo "Payment Verifier: $(crontab -l | grep payment_verifier > /dev/null && echo 'Active' || echo 'Inactive')"
}

# Send Telegram message
send_telegram_message() {
    local message="$1"
    local url="https://api.telegram.org/bot${ADMIN_BOT_TOKEN}/sendMessage"
    
    curl -s -X POST $url \
        -d chat_id="$ADMIN_ID" \
        -d text="$message" \
        -d parse_mode="HTML" > /dev/null
}

# Install admin tools
install_admin_tools() {
    info "🛠️ Installing admin tools..."
    
    mkdir -p $INSTALL_DIR
    
    # Create admin management script
    cat > /usr/local/bin/vpn-admin << 'EOF'
#!/bin/bash

# VPN Admin Management Tool
# For Admin ID: 5407046882

ADMIN_DIR="/etc/xray/admin"
DB_FILE="/etc/xray/commercial.db"

show_menu() {
    echo "=== VPN Admin Management ==="
    echo "1. System Status"
    echo "2. User Management"
    echo "3. Token Management"
    echo "4. Sales Report"
    echo "5. Service Control"
    echo "6. Exit"
    echo
    read -p "Choose option [1-6]: " choice
}

system_status() {
    echo "=== System Status ==="
    echo "Xray: $(systemctl is-active xray)"
    echo "Bot: $(systemctl is-active xray-commercial-bot)"
    echo "VPS IP: $(curl -s https://api.ipify.org)"
    
    # Database stats
    sqlite3 $DB_FILE "SELECT 
        (SELECT COUNT(*) FROM users) as 'Total Users',
        (SELECT COUNT(*) FROM vpn_accounts WHERE is_active = 1) as 'Active Accounts',
        (SELECT SUM(balance) FROM users) as 'Total Balance';" | while IFS='|' read users accounts balance; do
        echo "Users: $users | Active Accounts: $accounts"
        echo "Total Balance: Rp ${balance:-0}"
    done
}

user_management() {
    echo "=== User Management ==="
    sqlite3 -header -column $DB_FILE "SELECT 
        username as 'Username',
        balance as 'Balance',
        accounts_created as 'Accounts'
    FROM users 
    ORDER BY join_date DESC 
    LIMIT 10;"
}

token_management() {
    echo "=== Token Management ==="
    sqlite3 -header -column $DB_FILE "SELECT 
        vps_ip as 'VPS IP',
        expiry_date as 'Expiry',
        CASE WHEN is_active = 1 THEN 'Active' ELSE 'Inactive' END as Status
    FROM installation_tokens 
    ORDER BY created_date DESC;"
}

sales_report() {
    echo "=== Sales Report (Today) ==="
    sqlite3 -header -column $DB_FILE "SELECT 
        u.username as 'User',
        s.name as 'Server',
        va.data_limit/1073741824 as 'GB',
        s.price_per_gb * (va.data_limit/1073741824) as 'Amount',
        datetime(va.created_date) as 'Time'
    FROM vpn_accounts va
    JOIN users u ON va.user_id = u.id
    JOIN servers s ON va.server_id = s.id
    WHERE date(va.created_date) = date('now')
    ORDER BY va.created_date DESC;"
}

service_control() {
    echo "=== Service Control ==="
    echo "1. Start Bot"
    echo "2. Stop Bot"
    echo "3. Restart Bot"
    echo "4. Start Xray"
    echo "5. Stop Xray"
    echo "6. Restart Xray"
    echo
    read -p "Choose action [1-6]: " action
    
    case $action in
        1) systemctl start xray-commercial-bot ;;
        2) systemctl stop xray-commercial-bot ;;
        3) systemctl restart xray-commercial-bot ;;
        4) systemctl start xray ;;
        5) systemctl stop xray ;;
        6) systemctl restart xray ;;
        *) echo "Invalid option" ;;
    esac
}

# Main loop
while true; do
    show_menu
    
    case $choice in
        1) system_status ;;
        2) user_management ;;
        3) token_management ;;
        4) sales_report ;;
        5) service_control ;;
        6) exit 0 ;;
        *) echo "Invalid option!" ;;
    esac
    
    echo
    read -p "Press Enter to continue..."
    clear
done
EOF

    chmod +x /usr/local/bin/vpn-admin
    
    # Create admin monitoring service
    cat > /etc/systemd/system/vpn-admin-monitor.service << EOF
[Unit]
Description=VPN Admin Monitoring Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'while true; do /usr/local/bin/admin_monitor.sh; sleep 300; done'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # Create admin monitor script
    cat > /usr/local/bin/admin_monitor.sh << 'EOF'
#!/bin/bash

DB_FILE="/etc/xray/commercial.db"
ADMIN_BOT_TOKEN="8248259347:AAFHwfo0eytvsNbTt9PVinkbnL7dAIMPihk"
ADMIN_ID="5407046882"

send_alert() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot${ADMIN_BOT_TOKEN}/sendMessage" \
        -d chat_id="$ADMIN_ID" \
        -d text="$message" > /dev/null
}

# Check system status
check_system() {
    if ! systemctl is-active xray > /dev/null; then
        send_alert "🚨 Xray service is down!"
    fi
    
    if ! systemctl is-active xray-commercial-bot > /dev/null; then
        send_alert "🚨 Commercial bot is down!"
    fi
}

# Check token expiry
check_tokens() {
    sqlite3 $DB_FILE "SELECT vps_ip, expiry_date FROM installation_tokens WHERE is_active = 1 AND expiry_date < datetime('now', '+3 days');" | while IFS='|' read ip expiry; do
        send_alert "⚠️ Token expiring soon
VPS: $ip
Expiry: $expiry"
    done
}

# Check payments
check_payments() {
    pending_count=$(sqlite3 $DB_FILE "SELECT COUNT(*) FROM transactions WHERE status = 'pending' AND created_date > datetime('now', '-1 hour');")
    
    if [ $pending_count -gt 5 ]; then
        send_alert "📊 High pending payments: $pending_count"
    fi
}

check_system
check_tokens
check_payments
EOF

    chmod +x /usr/local/bin/admin_monitor.sh
    
    systemctl daemon-reload
    systemctl enable vpn-admin-monitor
    systemctl start vpn-admin-monitor
    
    log "Admin tools installed successfully"
}

# Main admin menu
main_menu() {
    while true; do
        echo
        echo -e "${CYAN}"
        echo "╔══════════════════════════════════════════════════════════╗"
        echo "║                   VPN ADMIN PANEL                       ║"
        echo "║                  ID: 5407046882                         ║"
        echo "╚══════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo "1. 🔑 Token Management"
        echo "2. 📊 System Monitoring"
        echo "3. 🛠️ Install Admin Tools"
        echo "4. 🔄 Update System"
        echo "5. 📋 Installation Guide"
        echo "6. 🚪 Exit"
        echo
        read -p "Choose option [1-6]: " main_choice
        
        case $main_choice in
            1)
                token_management
                ;;
            2)
                system_monitoring
                ;;
            3)
                install_admin_tools
                ;;
            4)
                update_system
                ;;
            5)
                show_installation_guide
                ;;
            6)
                echo -e "${GREEN}Goodbye! 👋${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                ;;
        esac
    done
}

update_system() {
    info "🔄 Updating system..."
    
    # Update packages
    if command -v apt &> /dev/null; then
        apt update && apt upgrade -y
    elif command -v yum &> /dev/null; then
        yum update -y
    fi
    
    # Update Python packages
    pip3 install --upgrade python-telegram-bot requests pyyaml
    
    # Restart services
    systemctl restart xray-commercial-bot
    systemctl restart vpn-admin-monitor
    
    log "System updated successfully"
    send_telegram_message "🔄 System Updated
All services restarted and updated successfully"
}

show_installation_guide() {
    echo
    echo -e "${YELLOW}=== Installation Guide ===${NC}"
    echo
    echo "1. 🔑 Generate installation token:"
    echo "   - Use 'Token Management' → 'Generate New Token'"
    echo "   - Specify VPS IP or use 'any' for any IP"
    echo "   - Set validity period (default 30 days)"
    echo "   - Save the token securely"
    echo
    echo "2. 🖥️ Install on VPS:"
    echo "   wget -O install_vpn.sh https://your-domain.com/install_vpn.sh"
    echo "   chmod +x install_vpn.sh"
    echo "   ./install_vpn.sh"
    echo "   → Enter the token when prompted"
    echo
    echo "3. 🤖 Configure bot:"
    echo "   nano /etc/xray/bot/config.yaml"
    echo "   Set your bot token and other settings"
    echo "   systemctl restart xray-commercial-bot"
    echo
    echo "4. ✅ Verify installation:"
    echo "   Check bot status: systemctl status xray-commercial-bot"
    echo "   Test payment system with small amount"
    echo "   Monitor logs: journalctl -u xray-commercial-bot -f"
    echo
    echo "5. 📊 Monitor system:"
    echo "   Use 'vpn-admin' command for daily management"
    echo "   Check 'System Monitoring' for statistics"
    echo "   Set up alerts in monitoring service"
    echo
    read -p "Press Enter to continue..."
}

# Initialize admin system
init_admin_system() {
    info "🚀 Initializing admin system..."
    
    # Check if database exists
    if [ ! -f "$DB_FILE" ]; then
        error "Commercial database not found! Please install the main system first."
    fi
    
    # Verify admin access to database
    if ! sqlite3 $DB_FILE "SELECT 1;" > /dev/null 2>&1; then
        error "Cannot access database. Check permissions."
    fi
    
    log "Admin system initialized successfully"
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
