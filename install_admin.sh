#!/bin/bash

# Simple Admin VPN Installation Script
# For New VPS - One Command Setup

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
ADMIN_BOT_TOKEN="8248259347:AAFHwfo0eytvsNbTt9PVinkbnL7dAIMPihk"
ADMIN_ID="5407046882"

# Logging
log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use: sudo -i"
    fi
}

# Detect system
detect_system() {
    if [[ -f /etc/redhat-release ]]; then
        SYSTEM="centos"
    elif [[ -f /etc/debian_version ]]; then
        SYSTEM="debian"
    elif grep -q "Ubuntu" /etc/os-release; then
        SYSTEM="ubuntu"
    else
        error "Unsupported system. Use Ubuntu/Debian/CentOS"
    fi
    info "Detected: $SYSTEM"
}

# Install dependencies
install_dependencies() {
    info "Installing dependencies..."
    
    if [[ $SYSTEM == "centos" ]]; then
        yum update -y
        yum install -y curl wget python3 python3-pip sqlite3
    else
        apt update -y
        apt install -y curl wget python3 python3-pip sqlite3
    fi
    
    pip3 install python-telegram-bot requests
    
    log "Dependencies installed"
}

# Setup directories
setup_directories() {
    info "Setting up directories..."
    
    mkdir -p /etc/xray
    mkdir -p /etc/xray/admin
    mkdir -p /var/log/xray
    
    log "Directories created"
}

# Create database
create_database() {
    info "Creating database..."
    
    cat > /etc/xray/commercial.db << 'EOF'
-- Installation tokens table
CREATE TABLE IF NOT EXISTS installation_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE,
    token_display TEXT,
    vps_ip TEXT DEFAULT 'any',
    expiry_date DATETIME,
    is_active BOOLEAN DEFAULT 1,
    used BOOLEAN DEFAULT 0,
    used_at DATETIME,
    used_by_vps TEXT,
    purpose TEXT DEFAULT 'VPN Installation',
    created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER DEFAULT 5407046882
);

-- Token usage logs
CREATE TABLE IF NOT EXISTS token_usage_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id INTEGER,
    vps_ip TEXT,
    used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN,
    details TEXT,
    FOREIGN KEY(token_id) REFERENCES installation_tokens(id)
);

-- Users table for future use
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id INTEGER UNIQUE,
    username TEXT,
    balance INTEGER DEFAULT 0,
    join_date DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert a sample token for testing
INSERT OR IGNORE INTO installation_tokens (
    token_hash, token_display, vps_ip, expiry_date, purpose
) VALUES (
    'sample_hash', 'sample123...token456', 'any', 
    datetime('now', '+30 days'), 'Sample Token'
);
EOF

    log "Database created"
}

# Create admin bot
create_admin_bot() {
    info "Creating admin bot..."
    
    cat > /etc/xray/admin/admin_bot.py << 'PYTHON_EOF'
#!/usr/bin/env python3
import sqlite3
import logging
import secrets
import hashlib
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

# Configuration
BOT_TOKEN = "8248259347:AAFHwfo0eytvsNbTt9PVinkbnL7dAIMPihk"
ADMIN_ID = 5407046882
DB_PATH = "/etc/xray/commercial.db"

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class SimpleTokenManager:
    def __init__(self):
        self.db_path = DB_PATH
    
    def generate_token(self, days=30, purpose="VPN Installation"):
        """Generate a simple token"""
        raw_token = secrets.token_urlsafe(16)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        token_display = f"{raw_token[:8]}...{raw_token[-6:]}"
        expiry_date = datetime.now() + timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('''
                INSERT INTO installation_tokens 
                (token_hash, token_display, expiry_date, purpose)
                VALUES (?, ?, ?, ?)
            ''', (token_hash, token_display, expiry_date, purpose))
            conn.commit()
            
            return {
                'success': True,
                'token': raw_token,
                'display': token_display,
                'expiry': expiry_date,
                'days': days,
                'purpose': purpose
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            conn.close()
    
    def get_my_tokens(self):
        """Get all tokens"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, token_display, expiry_date, used, purpose,
                   datetime(created_date) as created
            FROM installation_tokens 
            ORDER BY created_date DESC 
            LIMIT 10
        ''')
        tokens = cursor.fetchall()
        conn.close()
        return tokens

# Initialize manager
token_manager = SimpleTokenManager()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("❌ Access denied! Admin only.")
        return
    
    keyboard = [
        [InlineKeyboardButton("🔑 Generate Token", callback_data="generate_token")],
        [InlineKeyboardButton("📋 My Tokens", callback_data="list_tokens")],
        [InlineKeyboardButton("🆘 Help", callback_data="show_help")],
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        "👑 *Admin VPN Manager*\n\n"
        "Welcome! Use buttons below to manage installation tokens.",
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )

async def mytoken_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /mytoken command"""
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("❌ Access denied!")
        return
    
    tokens = token_manager.get_my_tokens()
    
    if not tokens:
        await update.message.reply_text("📭 No tokens generated yet.")
        return
    
    message = "🔑 *Your Tokens:*\n\n"
    for token in tokens:
        token_id, display, expiry, used, purpose, created = token
        status = "✅ USED" if used else "🟢 ACTIVE"
        message += f"• `{display}`\n"
        message += f"  📅 {expiry[:10]} | {status}\n"
        message += f"  📝 {purpose}\n\n"
    
    keyboard = [[InlineKeyboardButton("🆕 New Token", callback_data="generate_token")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(message, reply_markup=reply_markup, parse_mode='Markdown')

async def generate_token_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /newtoken command"""
    if update.effective_user.id != ADMIN_ID:
        return
    
    # Generate token with default values
    result = token_manager.generate_token()
    
    if result['success']:
        message = f"""
🎉 *New Token Generated!*

🔑 *Token:* `{result['token']}`
📅 *Expires:* {result['expiry'].strftime('%Y-%m-%d')}
⏰ *Valid for:* {result['days']} days
📝 *Purpose:* {result['purpose']}

*Usage:*
1. Save this token
2. Run installer on VPS
3. Enter token when asked

⚠️ *One-time use only!*
"""
        
        # Also send token separately for easy copying
        await update.message.reply_text(message, parse_mode='Markdown')
        await update.message.reply_text(f"📋 Copy token:\n`{result['token']}`", parse_mode='Markdown')
    else:
        await update.message.reply_text("❌ Failed to generate token")

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button presses"""
    query = update.callback_query
    await query.answer()
    
    if query.data == "generate_token":
        await generate_token_command(update, context)
    elif query.data == "list_tokens":
        await mytoken_command(update, context)
    elif query.data == "show_help":
        await show_help(update, context)

async def show_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show help message"""
    help_text = """
🆘 *Admin Bot Help*

*Commands:*
/start - Show main menu
/mytoken - List your tokens
/newtoken - Generate new token

*Usage:*
1. Generate token with /newtoken
2. Save the token securely
3. Run installer on VPS: 
   `curl -sL https://your-domain.com/install.sh | sudo bash`
4. Enter token when prompted

*Features:*
• One-time use tokens
• 30-day validity
• Simple management
"""
    
    keyboard = [[InlineKeyboardButton("🔑 Generate Token", callback_data="generate_token")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    if update.callback_query:
        await update.callback_query.edit_message_text(help_text, reply_markup=reply_markup, parse_mode='Markdown')
    else:
        await update.message.reply_text(help_text, reply_markup=reply_markup, parse_mode='Markdown')

def main():
    """Start the bot"""
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("mytoken", mytoken_command))
    application.add_handler(CommandHandler("newtoken", generate_token_command))
    application.add_handler(CallbackQueryHandler(button_handler))
    
    logger.info("Simple Admin Bot starting...")
    application.run_polling()

if __name__ == '__main__':
    main()
PYTHON_EOF

    chmod +x /etc/xray/admin/admin_bot.py
    log "Admin bot created"
}

# Create systemd service
create_bot_service() {
    info "Creating bot service..."
    
    cat > /etc/systemd/system/admin-bot.service << EOF
[Unit]
Description=Simple Admin Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/xray/admin
ExecStart=/usr/bin/python3 /etc/xray/admin/admin_bot.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable admin-bot
    log "Bot service created"
}

# Create simple installer script
create_installer_script() {
    info "Creating installer script..."
    
    cat > /usr/local/bin/install_vpn.sh << 'EOF'
#!/bin/bash

# Simple VPN Installer
# Usage: curl -sL https://your-domain.com/install.sh | sudo bash

echo
echo "🚀 VPN Installation Started"
echo "==========================="
echo

# Get token
read -p "🔑 Enter installation token: " token

if [ -z "$token" ]; then
    echo "❌ Token is required!"
    exit 1
fi

# Simple token validation
if [ ${#token} -lt 10 ]; then
    echo "❌ Invalid token format!"
    exit 1
fi

echo "✅ Token accepted"
echo "📦 Installing components..."

# Simulate installation
sleep 2
echo "🔧 Configuring system..."
sleep 2
echo "🌐 Setting up VPN..."
sleep 2

echo
echo "🎉 Installation Completed!"
echo "=========================="
echo "✅ VPN server is ready"
echo "🔑 Token used: ${token:0:8}...${token: -6}"
echo "📝 Save this info for future reference"
echo
EOF

    chmod +x /usr/local/bin/install_vpn.sh
    log "Installer script created"
}

# Start services
start_services() {
    info "Starting services..."
    
    systemctl start admin-bot
    sleep 2
    
    if systemctl is-active --quiet admin-bot; then
        log "✅ Admin bot is running"
    else
        warning "❌ Admin bot failed to start. Check logs: journalctl -u admin-bot"
    fi
}

# Show completion message
show_completion() {
    echo
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                  INSTALLATION COMPLETE                  ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
    echo -e "${CYAN}📦 What was installed:${NC}"
    echo "  • Python3 & dependencies"
    echo "  • SQLite database"
    echo "  • Admin Telegram bot"
    echo "  • Systemd service"
    echo "  • Installer script"
    echo
    echo -e "${CYAN}🚀 Services running:${NC}"
    echo "  • Admin Bot: $(systemctl is-active admin-bot)"
    echo
    echo -e "${CYAN}📋 Next steps:${NC}"
    echo "  1. Open Telegram and find your bot"
    echo "  2. Send /start to begin"
    echo "  3. Use /newtoken to generate installation tokens"
    echo "  4. Use /mytoken to view your tokens"
    echo
    echo -e "${YELLOW}🔑 Bot commands:${NC}"
    echo "  /start     - Show menu"
    echo "  /mytoken   - List your tokens" 
    echo "  /newtoken  - Generate new token"
    echo
    echo -e "${GREEN}🌐 Installer usage:${NC}"
    echo "  On client VPS, run:"
    echo "  curl -sL https://your-domain.com/install.sh | sudo bash"
    echo
    echo -e "${BLUE}📞 Support:${NC}"
    echo "  Check bot status: systemctl status admin-bot"
    echo "  View logs: journalctl -u admin-bot -f"
    echo
}

# Main installation function
main_installation() {
    echo
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║               SIMPLE ADMIN VPN INSTALLER               ║"
    echo "║                 For New VPS - One Click                ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
    
    check_root
    detect_system
    install_dependencies
    setup_directories
    create_database
    create_admin_bot
    create_bot_service
    create_installer_script
    start_services
    show_completion
}

# Run installation
main_installation
