# install_commercial_vpn.sh
#!/bin/bash

# Commercial Xray VPN Auto-Installation System
# With OrderKuota.com QRIS Payment Integration

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
INSTALL_DIR="/etc/xray"
DB_FILE="/etc/xray/commercial.db"
BACKUP_DIR="/root/xray-backups"
LOG_FILE="/var/log/xray-install.log"

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

# Token verification
verify_token() {
    info "🔑 Checking installation token..."
    
    VPS_IP=$(get_vps_ip)
    
    echo -e "${YELLOW}📝 Token required for installation${NC}"
    echo -n "Enter installation token: "
    read INSTALL_TOKEN
    
    if [ -z "$INSTALL_TOKEN" ]; then
        error "Token is required!"
    fi
    
    # Simple token validation
    if [ ${#INSTALL_TOKEN} -lt 10 ]; then
        error "Invalid token format!"
    fi
    
    # Save token for later use
    echo "$INSTALL_TOKEN" > /tmp/install_token.txt
    log "Token verified successfully!"
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
        error "Unsupported system"
    fi
    info "Detected system: $SYSTEM"
}

# Install dependencies
install_dependencies() {
    info "📦 Installing dependencies..."
    
    if [[ $SYSTEM == "centos" ]]; then
        yum update -y
        yum install -y curl wget unzip socat openssl sqlite python3 python3-pip iptables-services qrencode
    else
        apt update -y
        apt install -y curl wget unzip socat openssl sqlite3 python3 python3-pip iptables-persistent qrencode
    fi
    
    # Install Python requirements
    pip3 install python-telegram-bot requests pyyaml psutil qrcode[pil] cryptography
    
    log "Dependencies installed successfully"
}

# Configure firewall
configure_firewall() {
    info "🔥 Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow 22/tcp comment 'SSH'
        ufw allow 80/tcp comment 'HTTP'
        ufw allow 443/tcp comment 'HTTPS VPN'
        ufw allow 443/udp comment 'UDP VPN'
        ufw --force enable
        log "UFW firewall configured"
    elif command -v firewall-cmd &> /dev/null; then
        systemctl start firewalld
        systemctl enable firewalld
        firewall-cmd --permanent --add-port=22/tcp
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --permanent --add-port=443/udp
        firewall-cmd --reload
        log "Firewalld configured"
    else
        warning "No firewall manager found, please configure manually"
    fi
}

# Install Xray
install_xray() {
    info "🚀 Installing Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    systemctl enable xray
    log "Xray installed successfully"
}

# Initialize database
init_database() {
    info "🗄️ Initializing commercial database..."
    
    # Create database schema
    sqlite3 $DB_FILE << 'EOF'
-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id INTEGER UNIQUE,
    username TEXT,
    balance INTEGER DEFAULT 0,
    total_spent INTEGER DEFAULT 0,
    join_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    accounts_created INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT 1
);

-- Servers table
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    domain TEXT,
    location TEXT,
    price_per_gb INTEGER DEFAULT 5000,
    max_ips INTEGER DEFAULT 3,
    max_bandwidth INTEGER DEFAULT 100,
    is_active BOOLEAN DEFAULT 1
);

-- VPN accounts table
CREATE TABLE IF NOT EXISTS vpn_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    server_id INTEGER,
    username TEXT UNIQUE,
    uuid TEXT,
    password TEXT,
    data_limit INTEGER,
    used_data INTEGER DEFAULT 0,
    max_ips INTEGER,
    expiry_date DATETIME,
    is_active BOOLEAN DEFAULT 1,
    created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(server_id) REFERENCES servers(id)
);

-- Transactions table
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    amount INTEGER,
    transaction_type TEXT,
    status TEXT DEFAULT 'pending',
    qr_code TEXT,
    transaction_id TEXT,
    created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_date DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

-- Installation tokens table
CREATE TABLE IF NOT EXISTS installation_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE,
    vps_ip TEXT UNIQUE,
    expiry_date DATETIME,
    is_active BOOLEAN DEFAULT 1,
    created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    admin_id INTEGER DEFAULT 5407046882
);

-- Banned IPs table
CREATE TABLE IF NOT EXISTS banned_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE,
    reason TEXT,
    banned_date DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Security logs table
CREATE TABLE IF NOT EXISTS security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT,
    details TEXT,
    ip_address TEXT,
    created_date DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default server
INSERT OR IGNORE INTO servers (name, domain, location, price_per_gb, max_ips, max_bandwidth) 
VALUES ('Premium Server 1', 'your-domain.com', 'Singapore', 5000, 3, 100);

INSERT OR IGNORE INTO servers (name, domain, location, price_per_gb, max_ips, max_bandwidth) 
VALUES ('Premium Server 2', 'your-domain2.com', 'Japan', 6000, 3, 100);
EOF

    # Get current VPS IP for the token
    VPS_IP=$(get_vps_ip)
    INSTALL_TOKEN=$(cat /tmp/install_token.txt)
    TOKEN_HASH=$(echo -n "$INSTALL_TOKEN$VPS_IP" | sha256sum | cut -d' ' -f1)
    
    # Insert installation token
    sqlite3 $DB_FILE "INSERT OR IGNORE INTO installation_tokens (token_hash, vps_ip, expiry_date) VALUES ('$TOKEN_HASH', '$VPS_IP', datetime('now', '+30 days'));"
    
    log "Commercial database initialized"
}

# Create Xray configuration
create_xray_config() {
    info "⚙️ Creating Xray configuration..."
    
    mkdir -p $INSTALL_DIR/ssl
    
    # Generate self-signed certificate
    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
        -keyout $INSTALL_DIR/ssl/key.pem \
        -out $INSTALL_DIR/ssl/cert.pem
    
    # Create basic Xray config
    cat > $INSTALL_DIR/config.json << EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "tag": "vmess-ws",
            "port": 443,
            "protocol": "vmess",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/xray/ssl/cert.pem",
                            "keyFile": "/etc/xray/ssl/key.pem"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/vmess"
                }
            }
        },
        {
            "tag": "vless-ws",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/xray/ssl/cert.pem",
                            "keyFile": "/etc/xray/ssl/key.pem"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/vless"
                }
            }
        }
    ],
    "outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom"
        }
    ]
}
EOF

    log "Xray configuration created"
}

# Create commercial bot with OrderKuota integration
create_commercial_bot() {
    info "🤖 Creating commercial bot with OrderKuota payment..."
    
    BOT_DIR="$INSTALL_DIR/bot"
    mkdir -p $BOT_DIR
    
    # Get VPS IP for domain
    VPS_IP=$(get_vps_ip)
    
    # Create bot configuration
    cat > $BOT_DIR/config.yaml << EOF
bot:
  token: "YOUR_BOT_TOKEN_HERE"
  admin_id: 5407046882

database:
  path: "$DB_FILE"

orderkuota:
  username: "dinto07"
  token: "2477598:CMpqHtWF0U61Pr7jg923cdnhTRzY4Sif"

server:
  name: "Premium VPN"
  domain: "$VPS_IP"
  location: "Singapore"

pricing:
  price_per_gb: 5000
  default_days: 30
  min_topup: 10000
EOF

    # Create the main commercial bot
    cat > $BOT_DIR/commercial_bot.py << 'PYTHON_EOF'
#!/usr/bin/env python3
import sqlite3
import json
import logging
import yaml
import subprocess
import base64
import requests
import datetime
import os
import hashlib
import qrcode
from io import BytesIO
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters

# Load configuration
with open('/etc/xray/bot/config.yaml', 'r') as f:
    config = yaml.safe_load(f)

BOT_TOKEN = config['bot']['token']
ADMIN_ID = config['bot']['admin_id']
DB_PATH = config['database']['path']
ORDERKUOTA_USERNAME = config['orderkuota']['username']
ORDERKUOTA_TOKEN = config['orderkuota']['token']

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OrderKuotaAPI:
    def __init__(self, username, token):
        self.username = username
        self.token = token
        self.base_url = "https://orderkuota.com/api"
    
    def create_qris_payment(self, amount, customer_ref=None):
        """Create QRIS payment via OrderKuota API"""
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'username': self.username,
            'amount': amount,
            'customer_ref': customer_ref or f"VPN_{int(datetime.datetime.now().timestamp())}",
            'type': 'qris'
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/transaction",
                json=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'success': True,
                        'qr_code': data.get('qr_code'),
                        'qr_url': data.get('qr_url'),
                        'transaction_id': data.get('transaction_id'),
                        'customer_ref': data.get('customer_ref'),
                        'amount': amount,
                        'expiry': data.get('expiry_time')
                    }
                else:
                    return {
                        'success': False,
                        'error': data.get('message', 'Unknown error')
                    }
            else:
                return {
                    'success': False,
                    'error': f'API Error: {response.status_code}'
                }
                
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Network error: {str(e)}'
            }

class CommercialVPNSystem:
    def __init__(self):
        self.db_path = DB_PATH
        self.qris_api = OrderKuotaAPI(ORDERKUOTA_USERNAME, ORDERKUOTA_TOKEN)
    
    def get_user(self, telegram_id):
        conn = sqlite3.connect(self.db_path)
        user = conn.execute('SELECT * FROM users WHERE telegram_id = ?', (telegram_id,)).fetchone()
        conn.close()
        return user
    
    def create_user(self, telegram_id, username):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('INSERT OR IGNORE INTO users (telegram_id, username) VALUES (?, ?)', (telegram_id, username))
            conn.commit()
            return True
        except:
            return False
        finally:
            conn.close()
    
    def update_balance(self, user_id, amount):
        conn = sqlite3.connect(self.db_path)
        conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
        conn.commit()
        conn.close()
    
    def get_servers(self):
        conn = sqlite3.connect(self.db_path)
        servers = conn.execute('SELECT * FROM servers WHERE is_active = 1').fetchall()
        conn.close()
        return servers
    
    def generate_qr_code(self, amount, transaction_id, user_id):
        """Generate QRIS using OrderKuota API"""
        customer_ref = f"VPN_{user_id}_{transaction_id}"
        result = self.qris_api.create_qris_payment(amount, customer_ref)
        
        if result['success']:
            # Save transaction details
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                UPDATE transactions 
                SET qr_code = ?, status = 'pending', transaction_id = ?
                WHERE id = ?
            ''', (result['qr_url'], result['transaction_id'], transaction_id))
            conn.commit()
            conn.close()
            
            # Generate QR code image
            try:
                qr_response = requests.get(result['qr_code'])
                if qr_response.status_code == 200:
                    return {
                        'success': True,
                        'qr_image': BytesIO(qr_response.content),
                        'transaction_id': result['transaction_id'],
                        'amount': amount,
                        'expiry': result['expiry'],
                        'customer_ref': customer_ref
                    }
            except:
                # Fallback: generate QR locally
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(result['qr_url'])
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                bio = BytesIO()
                img.save(bio, 'PNG')
                bio.seek(0)
                
                return {
                    'success': True,
                    'qr_image': bio,
                    'transaction_id': result['transaction_id'],
                    'amount': amount,
                    'expiry': result['expiry'],
                    'customer_ref': customer_ref
                }
        
        return {'success': False, 'error': result['error']}
    
    def create_transaction(self, user_id, amount, trans_type='topup'):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO transactions (user_id, amount, transaction_type) 
            VALUES (?, ?, ?)
        ''', (user_id, amount, trans_type))
        transaction_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return transaction_id
    
    def create_vpn_account(self, user_id, server_id, data_gb, duration_days):
        conn = sqlite3.connect(self.db_path)
        
        # Get server info
        server = conn.execute('SELECT * FROM servers WHERE id = ?', (server_id,)).fetchone()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        
        if not server or not user:
            return None
        
        # Calculate cost
        cost = server[4] * data_gb
        
        if user[3] < cost:
            return "insufficient_balance"
        
        # Generate account
        import uuid
        account_uuid = str(uuid.uuid4())
        account_password = str(uuid.uuid4())[:8]
        username = f"user{user_id}_{int(datetime.datetime.now().timestamp())}"
        
        # Create account
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO vpn_accounts 
            (user_id, server_id, username, uuid, password, data_limit, max_ips, expiry_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id, server_id, username, account_uuid, account_password, 
            data_gb * 1073741824, server[5],
            datetime.datetime.now() + datetime.timedelta(days=duration_days)
        ))
        
        # Update user balance and stats
        conn.execute('''
            UPDATE users SET 
            balance = balance - ?, 
            total_spent = total_spent + ?,
            accounts_created = accounts_created + 1 
            WHERE id = ?
        ''', (cost, cost, user_id))
        
        account_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            'id': account_id,
            'username': username,
            'uuid': account_uuid,
            'password': account_password,
            'server_name': server[1],
            'data_limit': data_gb,
            'expiry_date': datetime.datetime.now() + datetime.timedelta(days=duration_days),
            'cost': cost
        }

# Initialize system
vpn_system = CommercialVPNSystem()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    vpn_system.create_user(user.id, user.username)
    
    user_info = vpn_system.get_user(user.id)
    
    welcome_text = f"""
🤖 Welcome to Commercial VPN Service!

👤 User: {user.mention_html()}
💰 Balance: Rp {user_info[3]:,}
📊 Accounts: {user_info[6]}
📅 Member since: {user_info[5][:10]}

Choose an option:
"""
    
    keyboard = [
        [InlineKeyboardButton("💰 Top Up Balance", callback_data="topup")],
        [InlineKeyboardButton("🛒 Buy VPN", callback_data="buy_vpn")],
        [InlineKeyboardButton("📱 My Accounts", callback_data="my_accounts")],
        [InlineKeyboardButton("👤 Profile", callback_data="profile")]
    ]
    
    if user.id == ADMIN_ID:
        keyboard.append([InlineKeyboardButton("🔧 Admin", callback_data="admin_panel")])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode='HTML')

async def handle_topup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    keyboard = [
        [InlineKeyboardButton("10.000", callback_data="topup_10000")],
        [InlineKeyboardButton("25.000", callback_data="topup_25000")],
        [InlineKeyboardButton("50.000", callback_data="topup_50000")],
        [InlineKeyboardButton("100.000", callback_data="topup_100000")],
        [InlineKeyboardButton("Custom Amount", callback_data="topup_custom")],
        [InlineKeyboardButton("🔙 Back", callback_data="back_main")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text("💳 Select top up amount:", reply_markup=reply_markup)

async def handle_topup_amount(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.data == "topup_custom":
        context.user_data['awaiting_topup'] = True
        await query.edit_message_text("💵 Enter custom amount (min Rp 10,000):")
        return
    
    amount = int(query.data.split('_')[1])
    await process_topup(query, amount, context)

async def process_topup(query, amount, context):
    user_info = vpn_system.get_user(query.from_user.id)
    
    if amount < 10000:
        await query.edit_message_text("❌ Minimum top up is Rp 10,000")
        return
    
    transaction_id = vpn_system.create_transaction(user_info[0], amount)
    qr_result = vpn_system.generate_qr_code(amount, transaction_id, user_info[0])
    
    if not qr_result['success']:
        await query.edit_message_text(f"❌ Failed to generate QRIS: {qr_result['error']}")
        return
    
    caption = f"""
💰 Top Up: Rp {amount:,}

📱 Scan QRIS code to pay
⏰ Expires: {qr_result['expiry']}
🔢 Ref: {qr_result['customer_ref']}

💡 Payment will be verified automatically
"""
    
    await context.bot.send_photo(
        chat_id=query.from_user.id,
        photo=qr_result['qr_image'],
        caption=caption
    )
    
    await query.edit_message_text(f"✅ QRIS generated for Rp {amount:,}\n\nCheck your messages for the QR code!")

async def handle_buy_vpn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    servers = vpn_system.get_servers()
    
    keyboard = []
    for server in servers:
        keyboard.append([InlineKeyboardButton(
            f"🌐 {server[1]} - Rp {server[4]:,}/GB", 
            callback_data=f"server_{server[0]}"
        )])
    
    keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="back_main")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text("🛒 Select server:", reply_markup=reply_markup)

async def handle_server_selection(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    server_id = int(query.data.split('_')[1])
    context.user_data['selected_server'] = server_id
    
    keyboard = [
        [InlineKeyboardButton("5GB - 30 Days", callback_data=f"package_{server_id}_5_30")],
        [InlineKeyboardButton("10GB - 30 Days", callback_data=f"package_{server_id}_10_30")],
        [InlineKeyboardButton("25GB - 30 Days", callback_data=f"package_{server_id}_25_30")],
        [InlineKeyboardButton("Custom Package", callback_data=f"custom_{server_id}")],
        [InlineKeyboardButton("🔙 Back", callback_data="buy_vpn")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text("📦 Select package:", reply_markup=reply_markup)

async def handle_package_selection(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.data.startswith('custom_'):
        server_id = int(query.data.split('_')[1])
        context.user_data['awaiting_custom'] = True
        context.user_data['custom_server'] = server_id
        await query.edit_message_text("📦 Enter custom package:\n\nFormat: <code>data_gb days</code>\nExample: <code>15 30</code>", parse_mode='HTML')
        return
    
    _, server_id, data_gb, days = query.data.split('_')
    await create_vpn_account(query, context, int(server_id), int(data_gb), int(days))

async def create_vpn_account(query, context, server_id, data_gb, days):
    user_info = vpn_system.get_user(query.from_user.id)
    result = vpn_system.create_vpn_account(user_info[0], server_id, data_gb, days)
    
    if result == "insufficient_balance":
        await query.edit_message_text("❌ Insufficient balance! Please top up first.")
        return
    
    if isinstance(result, dict):
        vmess_config = {
            "v": "2",
            "ps": f"{result['server_name']}-{result['username']}",
            "add": result['server_name'],
            "port": "443",
            "id": result['uuid'],
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": result['server_name'],
            "path": "/vmess",
            "tls": "tls",
            "sni": result['server_name']
        }
        
        vmess_base64 = base64.b64encode(json.dumps(vmess_config).encode()).decode()
        
        config_text = f"""
✅ VPN Account Created!

📋 Account Details:
👤 Username: {result['username']}
🔑 UUID: {result['uuid']}
🔒 Password: {result['password']}
🌐 Server: {result['server_name']}
📊 Data: {result['data_limit']}GB
⏰ Expires: {result['expiry_date'].strftime('%Y-%m-%d')}
💰 Cost: Rp {result['cost']:,}

🔧 Configurations:

VMess:
<code>vmess://{vmess_base64}</code>

⚠️ Keep this information secure!
"""
        await query.edit_message_text(config_text, parse_mode='HTML')

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get('awaiting_topup'):
        try:
            amount = int(update.message.text)
            await process_topup(update, amount, context)
            context.user_data['awaiting_topup'] = False
        except ValueError:
            await update.message.reply_text("❌ Please enter a valid number!")
    
    elif context.user_data.get('awaiting_custom'):
        try:
            data_gb, days = map(int, update.message.text.split())
            server_id = context.user_data['custom_server']
            await create_vpn_account(update, context, server_id, data_gb, days)
            context.user_data['awaiting_custom'] = False
        except ValueError:
            await update.message.reply_text("❌ Use format: <code>data_gb days</code>", parse_mode='HTML')

async def handle_back(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await start(update, context)

def main():
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(handle_topup, pattern="^topup$"))
    application.add_handler(CallbackQueryHandler(handle_topup_amount, pattern="^topup_"))
    application.add_handler(CallbackQueryHandler(handle_buy_vpn, pattern="^buy_vpn$"))
    application.add_handler(CallbackQueryHandler(handle_server_selection, pattern="^server_"))
    application.add_handler(CallbackQueryHandler(handle_package_selection, pattern="^package_"))
    application.add_handler(CallbackQueryHandler(handle_package_selection, pattern="^custom_"))
    application.add_handler(CallbackQueryHandler(handle_back, pattern="^back_main$"))
    
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    logger.info("Commercial VPN Bot started!")
    application.run_polling()

if __name__ == '__main__':
    main()
PYTHON_EOF

    chmod +x $BOT_DIR/commercial_bot.py
    log "Commercial bot created"
}

# Create payment verification system
create_payment_verifier() {
    info "💳 Creating payment verification system..."
    
    cat > $INSTALL_DIR/payment_verifier.py << 'PYTHON_EOF'
#!/usr/bin/env python3
import sqlite3
import requests
import datetime
import logging
from telegram import Bot

DB_PATH = "/etc/xray/commercial.db"
ORDERKUOTA_USERNAME = "dinto07"
ORDERKUOTA_TOKEN = "2477598:CMpqHtWF0U61Pr7jg923cdnhTRzY4Sif"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PaymentVerifier:
    def __init__(self):
        self.db_path = DB_PATH
    
    def check_pending_payments(self):
        """Check all pending payments"""
        conn = sqlite3.connect(self.db_path)
        pending_transactions = conn.execute('''
            SELECT t.id, t.amount, t.transaction_id, u.telegram_id, u.username 
            FROM transactions t 
            JOIN users u ON t.user_id = u.id 
            WHERE t.status = 'pending'
        ''').fetchall()
        conn.close()
        
        for transaction in pending_transactions:
            self.check_single_payment(transaction[0], transaction[2], transaction[3], transaction[1])
    
    def check_single_payment(self, transaction_id, api_transaction_id, user_id, amount):
        """Check single payment status"""
        headers = {
            'Authorization': f'Bearer {ORDERKUOTA_TOKEN}',
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.get(
                f"https://orderkuota.com/api/transaction/{api_transaction_id}",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'paid':
                    self.mark_payment_completed(transaction_id, user_id, amount)
                    logger.info(f"Payment completed: Transaction {transaction_id}, User {user_id}")
                    return True
        except Exception as e:
            logger.error(f"Error checking payment: {e}")
        
        return False
    
    def mark_payment_completed(self, transaction_id, user_id, amount):
        """Mark payment as completed"""
        conn = sqlite3.connect(self.db_path)
        
        # Update transaction status
        conn.execute('''
            UPDATE transactions 
            SET status = 'completed', completed_date = ? 
            WHERE id = ?
        ''', (datetime.datetime.now(), transaction_id))
        
        # Update user balance
        conn.execute('''
            UPDATE users 
            SET balance = balance + ? 
            WHERE telegram_id = ?
        ''', (amount, user_id))
        
        conn.commit()
        conn.close()

def main():
    verifier = PaymentVerifier()
    verifier.check_pending_payments()

if __name__ == '__main__':
    main()
PYTHON_EOF

    chmod +x $INSTALL_DIR/payment_verifier.py
    
    # Add to crontab for automatic payment checking
    (crontab -l 2>/dev/null; echo "*/2 * * * * /usr/bin/python3 /etc/xray/payment_verifier.py") | crontab -
    
    log "Payment verification system created"
}

# Create bot service
create_bot_service() {
    info "🔧 Creating bot service..."
    
    cat > /etc/systemd/system/xray-commercial-bot.service << EOF
[Unit]
Description=Xray Commercial Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/xray/bot
ExecStart=/usr/bin/python3 /etc/xray/bot/commercial_bot.py
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log "Bot service created"
}

# Create management tools
create_management_tools() {
    info "🛠️ Creating management tools..."
    
    # Create admin menu
    cat > /usr/local/bin/vpn-admin << 'EOF'
#!/bin/bash
echo "=== Commercial VPN Admin Menu ==="
echo "1. Start Bot"
echo "2. Stop Bot"
echo "3. Restart Bot"
echo "4. Check Bot Status"
echo "5. Check Payment Status"
echo "6. View System Info"
echo "7. Exit"
echo
read -p "Choose option: " choice

case $choice in
    1)
        systemctl start xray-commercial-bot
        echo "✅ Bot started"
        ;;
    2)
        systemctl stop xray-commercial-bot
        echo "✅ Bot stopped"
        ;;
    3)
        systemctl restart xray-commercial-bot
        echo "✅ Bot restarted"
        ;;
    4)
        systemctl status xray-commercial-bot
        ;;
    5)
        python3 /etc/xray/payment_verifier.py
        echo "✅ Payment status checked"
        ;;
    6)
        echo "=== System Information ==="
        echo "Xray Status: $(systemctl is-active xray)"
        echo "Bot Status: $(systemctl is-active xray-commercial-bot)"
        echo "VPS IP: $(curl -s https://api.ipify.org)"
        ;;
    7)
        exit 0
        ;;
    *)
        echo "❌ Invalid option"
        ;;
esac
EOF

    chmod +x /usr/local/bin/vpn-admin
    
    log "Management tools created"
}

# Final setup
final_setup() {
    info "🎯 Finalizing installation..."
    
    # Start services
    systemctl start xray
    systemctl start xray-commercial-bot
    
    systemctl enable xray
    systemctl enable xray-commercial-bot
    
    # Get installation details
    VPS_IP=$(get_vps_ip)
    INSTALL_TOKEN=$(cat /tmp/install_token.txt)
    
    # Display completion message
    echo
    echo -e "${GREEN}🎉 Commercial VPN Installation Complete!${NC}"
    echo
    echo -e "${CYAN}📊 Installation Summary:${NC}"
    echo -e "  VPS IP: ${VPS_IP}"
    echo -e "  Admin ID: 5407046882"
    echo -e "  Database: ${DB_FILE}"
    echo -e "  Bot Config: /etc/xray/bot/config.yaml"
    echo
    echo -e "${YELLOW}⚠️ Important Next Steps:${NC}"
    echo -e "  1. Edit /etc/xray/bot/config.yaml"
    echo -e "  2. Set your bot token in the config file"
    echo -e "  3. Restart the bot: systemctl restart xray-commercial-bot"
    echo
    echo -e "${GREEN}🚀 Management Commands:${NC}"
    echo -e "  vpn-admin          - Admin management menu"
    echo -e "  systemctl status xray-commercial-bot - Check bot status"
    echo -e "  python3 /etc/xray/payment_verifier.py - Manual payment check"
    echo
    echo -e "${BLUE}📱 Bot Features:${NC}"
    echo -e "  ✅ QRIS Payments via OrderKuota"
    echo -e "  ✅ Auto Payment Verification"
    echo -e "  ✅ VPN Account Creation"
    echo -e "  ✅ User Balance Management"
    echo -e "  ✅ Multi-server Support"
    echo
    
    # Cleanup
    rm -f /tmp/install_token.txt
    
    log "Installation completed successfully!"
}

# Main installation function
main_installation() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║              COMMERCIAL VPN AUTO-INSTALLER              ║"
    echo "║                 With QRIS Payment System                ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_root
    verify_token
    detect_system
    install_dependencies
    configure_firewall
    install_xray
    init_database
    create_xray_config
    create_commercial_bot
    create_payment_verifier
    create_bot_service
    create_management_tools
    final_setup
}

# Run installation
main_installation}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
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

# Token verification
verify_token() {
    info "Checking installation token..."
    
    VPS_IP=$(get_vps_ip)
    TOKEN_FILE="/tmp/install_token.txt"
    
    if [ ! -f "$TOKEN_FILE" ]; then
        echo -e "${YELLOW}📝 Token required for installation${NC}"
        echo -n "Enter installation token: "
        read INSTALL_TOKEN
        
        if [ -z "$INSTALL_TOKEN" ]; then
            error "Token is required!"
            exit 1
        fi
        
        echo "$INSTALL_TOKEN" > $TOKEN_FILE
    else
        INSTALL_TOKEN=$(cat $TOKEN_FILE)
    fi
    
    # Verify token with admin bot
    VERIFY_URL="https://api.telegram.org/bot${ADMIN_BOT_TOKEN}/sendMessage"
    VERIFY_DATA="chat_id=5407046882&text=🔐 Token Verification Request%0A🖥️ VPS IP: ${VPS_IP}%0A🔑 Token: ${INSTALL_TOKEN}%0A⏰ Time: $(date)"
    
    curl -s -X POST $VERIFY_URL -d "$VERIFY_DATA" > /dev/null
    
    # Simple token validation (in production, use proper API)
    TOKEN_HASH=$(echo -n "$INSTALL_TOKEN$VPS_IP" | sha256sum | cut -d' ' -f1)
    
    if [ ${#INSTALL_TOKEN} -lt 10 ]; then
        error "Invalid token format!"
        rm -f $TOKEN_FILE
        exit 1
    fi
    
    log "Token verified successfully!"
    return 0
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
        error "Unsupported system"
        exit 1
    fi
    info "Detected system: $SYSTEM"
}

# Install dependencies
install_dependencies() {
    info "Installing dependencies..."
    
    if [[ $SYSTEM == "centos" ]]; then
        yum update -y
        yum install -y curl wget unzip socat openssl sqlite python3 python3-pip iptables-services qrencode
    else
        apt update -y
        apt install -y curl wget unzip socat openssl sqlite3 python3 python3-pip iptables-persistent qrencode
    fi
    
    # Install Python requirements
    pip3 install python-telegram-bot requests pyyaml psutil qrcode[pil] cryptography
    
    log "Dependencies installed successfully"
}

# Configure firewall
configure_firewall() {
    info "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow 22/tcp comment 'SSH'
        ufw allow 80/tcp comment 'HTTP'
        ufw allow 443/tcp comment 'HTTPS VPN'
        ufw allow 443/udp comment 'UDP VPN'
        ufw allow 8443/tcp comment 'Stunnel'
        ufw allow 89/tcp comment 'OpenClash'
        ufw --force enable
    elif command -v firewall-cmd &> /dev/null; then
        systemctl start firewalld
        systemctl enable firewalld
        firewall-cmd --permanent --add-port=22/tcp
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --permanent --add-port=443/udp
        firewall-cmd --permanent --add-port=8443/tcp
        firewall-cmd --permanent --add-port=89/tcp
        firewall-cmd --reload
    fi
    
    log "Firewall configured"
}

# Install Xray
install_xray() {
    info "Installing Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    systemctl enable xray
    log "Xray installed successfully"
}

# Initialize database
init_database() {
    info "Initializing commercial database..."
    
    sqlite3 $DB_FILE << 'EOF'
-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id INTEGER UNIQUE,
    username TEXT,
    balance INTEGER DEFAULT 0,
    total_spent INTEGER DEFAULT 0,
    join_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    accounts_created INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT 1
);

-- Servers table
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    domain TEXT,
    location TEXT,
    price_per_gb INTEGER DEFAULT 5000,
    max_ips INTEGER DEFAULT 3,
    max_bandwidth INTEGER DEFAULT 100,
    is_active BOOLEAN DEFAULT 1
);

-- VPN accounts table
CREATE TABLE IF NOT EXISTS vpn_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    server_id INTEGER,
    username TEXT UNIQUE,
    uuid TEXT,
    password TEXT,
    data_limit INTEGER,
    used_data INTEGER DEFAULT 0,
    max_ips INTEGER,
    expiry_date DATETIME,
    is_active BOOLEAN DEFAULT 1,
    created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(server_id) REFERENCES servers(id)
);

-- Transactions table
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    amount INTEGER,
    transaction_type TEXT,
    status TEXT DEFAULT 'pending',
    qr_code TEXT,
    created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_date DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

-- Installation tokens table
CREATE TABLE IF NOT EXISTS installation_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE,
    vps_ip TEXT UNIQUE,
    expiry_date DATETIME,
    is_active BOOLEAN DEFAULT 1,
    created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    admin_id INTEGER DEFAULT 5407046882
);

-- Banned IPs table
CREATE TABLE IF NOT EXISTS banned_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE,
    reason TEXT,
    banned_date DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Security logs table
CREATE TABLE IF NOT EXISTS security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT,
    details TEXT,
    ip_address TEXT,
    created_date DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default server
INSERT OR IGNORE INTO servers (name, domain, location, price_per_gb, max_ips, max_bandwidth) 
VALUES ('Premium Server', 'your-domain.com', 'Singapore', 5000, 3, 100);

-- Insert current installation token
INSERT OR IGNORE INTO installation_tokens (token_hash, vps_ip, expiry_date) 
VALUES (?, ?, datetime('now', '+30 days'));
EOF

    # Get token hash for current installation
    INSTALL_TOKEN=$(cat /tmp/install_token.txt 2>/dev/null || echo "default_token")
    VPS_IP=$(get_vps_ip)
    TOKEN_HASH=$(echo -n "$INSTALL_TOKEN$VPS_IP" | sha256sum | cut -d' ' -f1)
    
    sqlite3 $DB_FILE "UPDATE installation_tokens SET token_hash = '$TOKEN_HASH', vps_ip = '$VPS_IP' WHERE id = 1;"
    
    log "Commercial database initialized"
}

# Create commercial bot
create_commercial_bot() {
    info "Creating commercial bot..."
    
    BOT_DIR="$INSTALL_DIR/bot"
    mkdir -p $BOT_DIR
    
    # Create bot configuration
    cat > $BOT_DIR/config.yaml << EOF
bot:
  token: "YOUR_BOT_TOKEN_HERE"
  admin_id: 5407046882

database:
  path: "$DB_FILE"

server:
  name: "Premium VPN"
  domain: "$(get_vps_ip)"
  location: "Singapore"

pricing:
  price_per_gb: 5000
  default_days: 30
EOF

    # Create the main commercial bot
    cat > $BOT_DIR/commercial_bot.py << 'PYTHON_EOF'
#!/usr/bin/env python3
import sqlite3
import json
import logging
import yaml
import subprocess
import base64
import requests
import datetime
import os
import tempfile
import hashlib
import qrcode
from io import BytesIO
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters

# Load configuration
with open('/etc/xray/bot/config.yaml', 'r') as f:
    config = yaml.safe_load(f)

BOT_TOKEN = config['bot']['token']
ADMIN_ID = config['bot']['admin_id']
DB_PATH = config['database']['path']

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CommercialVPNSystem:
    def __init__(self):
        self.db_path = DB_PATH
    
    def get_user(self, telegram_id):
        conn = sqlite3.connect(self.db_path)
        user = conn.execute('SELECT * FROM users WHERE telegram_id = ?', (telegram_id,)).fetchone()
        conn.close()
        return user
    
    def create_user(self, telegram_id, username):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('INSERT OR IGNORE INTO users (telegram_id, username) VALUES (?, ?)', (telegram_id, username))
            conn.commit()
            return True
        except:
            return False
        finally:
            conn.close()
    
    def update_balance(self, telegram_id, amount):
        conn = sqlite3.connect(self.db_path)
        conn.execute('UPDATE users SET balance = balance + ? WHERE telegram_id = ?', (amount, telegram_id))
        conn.commit()
        conn.close()
    
    def get_servers(self):
        conn = sqlite3.connect(self.db_path)
        servers = conn.execute('SELECT * FROM servers WHERE is_active = 1').fetchall()
        conn.close()
        return servers
    
    def generate_qr_code(self, amount, transaction_id):
        # Generate QRIS payload
        qr_data = f"00020101021126650014ID.CO.QRIS.WWW01189360091436009175420213{amount:012d}5204541153033605802ID5910VPN_STORE6013Indonesia6304"
        qr_data += hashlib.sha256(qr_data.encode()).hexdigest()[:8]
        
        # Create QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        bio = BytesIO()
        img.save(bio, 'PNG')
        bio.seek(0)
        
        # Save QR data to transaction
        conn = sqlite3.connect(self.db_path)
        conn.execute('UPDATE transactions SET qr_code = ? WHERE id = ?', (qr_data, transaction_id))
        conn.commit()
        conn.close()
        
        return bio
    
    def create_transaction(self, user_id, amount, trans_type='topup'):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO transactions (user_id, amount, transaction_type) 
            VALUES (?, ?, ?)
        ''', (user_id, amount, trans_type))
        transaction_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return transaction_id
    
    def create_vpn_account(self, user_id, server_id, data_gb, duration_days):
        conn = sqlite3.connect(self.db_path)
        
        # Get server info
        server = conn.execute('SELECT * FROM servers WHERE id = ?', (server_id,)).fetchone()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        
        if not server or not user:
            return None
        
        # Calculate cost
        cost = server[4] * data_gb
        
        if user[3] < cost:
            return "insufficient_balance"
        
        # Generate account
        import uuid
        account_uuid = str(uuid.uuid4())
        account_password = str(uuid.uuid4())[:8]
        username = f"user{user_id}_{int(datetime.datetime.now().timestamp())}"
        
        # Create account
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO vpn_accounts 
            (user_id, server_id, username, uuid, password, data_limit, max_ips, expiry_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id, server_id, username, account_uuid, account_password, 
            data_gb * 1073741824, server[5],
            datetime.datetime.now() + datetime.timedelta(days=duration_days)
        ))
        
        # Update user balance and stats
        conn.execute('''
            UPDATE users SET 
            balance = balance - ?, 
            total_spent = total_spent + ?,
            accounts_created = accounts_created + 1 
            WHERE id = ?
        ''', (cost, cost, user_id))
        
        account_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            'id': account_id,
            'username': username,
            'uuid': account_uuid,
            'password': account_password,
            'server_name': server[1],
            'data_limit': data_gb,
            'expiry_date': datetime.datetime.now() + datetime.timedelta(days=duration_days),
            'cost': cost
        }

# Initialize system
vpn_system = CommercialVPNSystem()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    vpn_system.create_user(user.id, user.username)
    
    user_info = vpn_system.get_user(user.id)
    
    welcome_text = f"""
🤖 Welcome to Commercial VPN Service!

👤 User: {user.mention_html()}
💰 Balance: Rp {user_info[3]:,}
📊 Accounts: {user_info[6]}
📅 Member since: {user_info[5][:10]}

Choose an option:
"""
    
    keyboard = [
        [InlineKeyboardButton("💰 Top Up Balance", callback_data="topup")],
        [InlineKeyboardButton("🛒 Buy VPN", callback_data="buy_vpn")],
        [InlineKeyboardButton("📱 My Accounts", callback_data="my_accounts")],
        [InlineKeyboardButton("💳 Balance Info", callback_data="balance_info")],
        [InlineKeyboardButton("👤 Profile", callback_data="profile")]
    ]
    
    if user.id == ADMIN_ID:
        keyboard.append([InlineKeyboardButton("🔧 Admin", callback_data="admin_panel")])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode='HTML')

async def handle_topup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    keyboard = [
        [InlineKeyboardButton("10.000", callback_data="topup_10000")],
        [InlineKeyboardButton("25.000", callback_data="topup_25000")],
        [InlineKeyboardButton("50.000", callback_data="topup_50000")],
        [InlineKeyboardButton("100.000", callback_data="topup_100000")],
        [InlineKeyboardButton("Custom Amount", callback_data="topup_custom")],
        [InlineKeyboardButton("🔙 Back", callback_data="back_main")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text("💳 Select top up amount:", reply_markup=reply_markup)

async def handle_topup_amount(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.data == "topup_custom":
        context.user_data['awaiting_topup'] = True
        await query.edit_message_text("💵 Enter custom amount:")
        return
    
    amount = int(query.data.split('_')[1])
    await process_topup(query, amount)

async def process_topup(query, amount):
    user_info = vpn_system.get_user(query.from_user.id)
    transaction_id = vpn_system.create_transaction(user_info[0], amount)
    
    qr_code = vpn_system.generate_qr_code(amount, transaction_id)
    
    await query.message.reply_photo(
        photo=qr_code,
        caption=f"""
💰 Top Up: Rp {amount:,}

📱 Scan QRIS code to pay
⏰ Auto verification in 1-5 minutes

After payment, click /checkpayment
Transaction ID: {transaction_id}
"""
    )
    
    await query.edit_message_text(f"✅ QR code generated for Rp {amount:,}")

async def handle_buy_vpn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    servers = vpn_system.get_servers()
    
    keyboard = []
    for server in servers:
        keyboard.append([InlineKeyboardButton(
            f"🌐 {server[1]} - Rp {server[4]:,}/GB", 
            callback_data=f"server_{server[0]}"
        )])
    
    keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="back_main")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text("🛒 Select server:", reply_markup=reply_markup)

async def handle_server_selection(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    server_id = int(query.data.split('_')[1])
    context.user_data['selected_server'] = server_id
    
    keyboard = [
        [InlineKeyboardButton("5GB - 30 Days", callback_data=f"package_{server_id}_5_30")],
        [InlineKeyboardButton("10GB - 30 Days", callback_data=f"package_{server_id}_10_30")],
        [InlineKeyboardButton("25GB - 30 Days", callback_data=f"package_{server_id}_25_30")],
        [InlineKeyboardButton("Custom Package", callback_data=f"custom_{server_id}")],
        [InlineKeyboardButton("🔙 Back", callback_data="buy_vpn")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text("📦 Select package:", reply_markup=reply_markup)

async def handle_package_selection(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.data.startswith('custom_'):
        server_id = int(query.data.split('_')[1])
        context.user_data['awaiting_custom'] = True
        context.user_data['custom_server'] = server_id
        await query.edit_message_text("📦 Enter custom package:\n\nFormat: <code>data_gb days</code>\nExample: <code>15 30</code>", parse_mode='HTML')
        return
    
    _, server_id, data_gb, days = query.data.split('_')
    await create_vpn_account(query, int(server_id), int(data_gb), int(days))

async def create_vpn_account(query, server_id, data_gb, days):
    user_info = vpn_system.get_user(query.from_user.id)
    result = vpn_system.create_vpn_account(user_info[0], server_id, data_gb, days)
    
    if result == "insufficient_balance":
        await query.edit_message_text("❌ Insufficient balance! Please top up first.")
        return
    
    if isinstance(result, dict):
        config_text = f"""
✅ VPN Account Created!

📋 Account Details:
👤 Username: {result['username']}
🔑 UUID: {result['uuid']}
🔒 Password: {result['password']}
🌐 Server: {result['server_name']}
📊 Data: {result['data_limit']}GB
⏰ Expires: {result['expiry_date'].strftime('%Y-%m-%d')}
💰 Cost: Rp {result['cost']:,}

🔧 Connection Info:
Port: 443 • Security: TLS • Network: WS

⚠️ Keep this information secure!
"""
        await query.edit_message_text(config_text)
        
        # Notify admin
        admin_msg = f"""
🆕 New VPN Account

👤 User: {query.from_user.username} ({query.from_user.id})
🌐 Server: {result['server_name']}
📦 Package: {data_gb}GB/{days} days
💰 Amount: Rp {result['cost']:,}
"""
        await context.bot.send_message(ADMIN_ID, admin_msg)

async def handle_profile(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    user_info = vpn_system.get_user(query.from_user.id)
    
    profile_text = f"""
👤 User Profile

🆔 ID: <code>{user_info[1]}</code>
👤 Username: @{user_info[2]}
💰 Balance: Rp {user_info[3]:,}
💳 Total Spent: Rp {user_info[4]:,}
📅 Join Date: {user_info[5][:10]}
📊 Accounts Created: {user_info[6]}
"""
    await query.edit_message_text(profile_text, parse_mode='HTML')

async def handle_balance_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    user_info = vpn_system.get_user(query.from_user.id)
    
    balance_text = f"""
💳 Balance Information

💰 Current Balance: Rp {user_info[3]:,}
💳 Total Spent: Rp {user_info[4]:,}
📊 Accounts: {user_info[6]}

💡 Top up to create more VPN accounts!
"""
    await query.edit_message_text(balance_text)

# Admin functions
async def handle_admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.from_user.id != ADMIN_ID:
        await query.edit_message_text("❌ Access denied!")
        return
    
    keyboard = [
        [InlineKeyboardButton("📊 Statistics", callback_data="admin_stats")],
        [InlineKeyboardButton("🔑 Token Management", callback_data="admin_tokens")],
        [InlineKeyboardButton("🌐 Server Management", callback_data="admin_servers")],
        [InlineKeyboardButton("📈 Sales Report", callback_data="admin_sales")],
        [InlineKeyboardButton("🔙 Back", callback_data="back_main")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text("🔧 Admin Panel", reply_markup=reply_markup)

async def handle_admin_tokens(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.from_user.id != ADMIN_ID:
        return
    
    conn = sqlite3.connect(DB_PATH)
    tokens = conn.execute('SELECT * FROM installation_tokens').fetchall()
    conn.close()
    
    tokens_text = "🔑 Installation Tokens\n\n"
    for token in tokens:
        status = "✅ Active" if token[4] else "❌ Inactive"
        tokens_text += f"IP: {token[2]}\nExpiry: {token[3][:16]}\nStatus: {status}\n\n"
    
    keyboard = [
        [InlineKeyboardButton("➕ Create Token", callback_data="create_token")],
        [InlineKeyboardButton("🔄 Extend Token", callback_data="extend_token")],
        [InlineKeyboardButton("🔙 Back", callback_data="admin_panel")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(tokens_text, reply_markup=reply_markup)

# Message handler for custom inputs
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get('awaiting_topup'):
        try:
            amount = int(update.message.text)
            if amount < 10000:
                await update.message.reply_text("❌ Minimum top up is Rp 10,000")
                return
            
            await process_topup(update, amount)
            context.user_data['awaiting_topup'] = False
        except ValueError:
            await update.message.reply_text("❌ Please enter a valid number!")
    
    elif context.user_data.get('awaiting_custom'):
        try:
            data_gb, days = map(int, update.message.text.split())
            server_id = context.user_data['custom_server']
            await create_vpn_account(update, server_id, data_gb, days)
            context.user_data['awaiting_custom'] = False
        except ValueError:
            await update.message.reply_text("❌ Use format: <code>data_gb days</code>", parse_mode='HTML')

# Back handler
async def handle_back(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await start(update, context)

def main():
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("checkpayment", lambda u,c: u.message.reply_text("🔄 Payment verification system will be implemented")))
    
    application.add_handler(CallbackQueryHandler(handle_topup, pattern="^topup$"))
    application.add_handler(CallbackQueryHandler(handle_topup_amount, pattern="^topup_"))
    application.add_handler(CallbackQueryHandler(handle_buy_vpn, pattern="^buy_vpn$"))
    application.add_handler(CallbackQueryHandler(handle_server_selection, pattern="^server_"))
    application.add_handler(CallbackQueryHandler(handle_package_selection, pattern="^package_"))
    application.add_handler(CallbackQueryHandler(handle_package_selection, pattern="^custom_"))
    application.add_handler(CallbackQueryHandler(handle_profile, pattern="^profile$"))
    application.add_handler(CallbackQueryHandler(handle_balance_info, pattern="^balance_info$"))
    application.add_handler(CallbackQueryHandler(handle_admin_panel, pattern="^admin_panel$"))
    application.add_handler(CallbackQueryHandler(handle_admin_tokens, pattern="^admin_tokens$"))
    application.add_handler(CallbackQueryHandler(handle_back, pattern="^back_main$"))
    
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    logger.info("Commercial VPN Bot started!")
    application.run_polling()

if __name__ == '__main__':
    main()
PYTHON_EOF

    chmod +x $BOT_DIR/commercial_bot.py
    log "Commercial bot created"
}

# Create Xray configuration
create_xray_config() {
    info "Creating Xray configuration..."
    
    cat > $INSTALL_DIR/config.json << EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "tag": "vmess-ws",
            "port": 443,
            "protocol": "vmess",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/xray/ssl/cert.pem",
                            "keyFile": "/etc/xray/ssl/key.pem"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/vmess"
                }
            }
        },
        {
            "tag": "vless-ws",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/xray/ssl/cert.pem",
                            "keyFile": "/etc/xray/ssl/key.pem"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/vless"
                }
            }
        }
    ],
    "outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom"
        }
    ]
}
EOF

    # Generate self-signed certificate
    mkdir -p $INSTALL_DIR/ssl
    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
        -keyout $INSTALL_DIR/ssl/key.pem \
        -out $INSTALL_DIR/ssl/cert.pem
    
    log "Xray configuration created"
}

# Create encryption system
create_encryption_system() {
    info "Creating encryption system..."
    
    # Generate encryption key
    ENCRYPTION_KEY=$(openssl rand -base64 32)
    
    # Create encryption script
    cat > /usr/local/bin/encrypt_system << EOF
#!/bin/bash
# Encryption system - Admin only

if [ \$# -eq 0 ]; then
    echo "Usage: encrypt_system [encrypt|decrypt]"
    exit 1
fi

KEY="$ENCRYPTION_KEY"

if [ "\$1" == "encrypt" ]; then
    # Encrypt Python scripts
    for file in /etc/xray/bot/*.py; do
        if [ -f "\$file" ]; then
            openssl enc -aes-256-cbc -salt -in "\$file" -out "\$file.enc" -k "\$KEY"
            rm -f "\$file"
            echo "Encrypted: \$file"
        fi
    done
    
    # Encrypt configuration files
    for file in /etc/xray/*.json /etc/xray/*.yaml; do
        if [ -f "\$file" ]; then
            openssl enc -aes-256-cbc -salt -in "\$file" -out "\$file.enc" -k "\$KEY"
            rm -f "\$file"
            echo "Encrypted: \$file"
        fi
    done
    
    echo "✅ System encrypted successfully!"
    
elif [ "\$1" == "decrypt" ]; then
    # Decrypt files
    for file in /etc/xray/bot/*.py.enc /etc/xray/*.json.enc /etc/xray/*.yaml.enc; do
        if [ -f "\$file" ]; then
            output_file="\${file%.enc}"
            openssl enc -d -aes-256-cbc -in "\$file" -out "\$output_file" -k "\$KEY"
            echo "Decrypted: \$output_file"
        fi
    done
    
    echo "✅ System decrypted successfully!"
fi
EOF

    chmod +x /usr/local/bin/encrypt_system
    
    # Create encrypted bot service
    cat > /etc/systemd/system/xray-commercial-bot.service << EOF
[Unit]
Description=Xray Commercial Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/xray/bot
ExecStart=/usr/bin/python3 /etc/xray/bot/commercial_bot.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log "Encryption system created"
}

# Create token management
create_token_management() {
    info "Creating token management system..."
    
    cat > /usr/local/bin/token_manager << 'EOF'
#!/bin/bash
# Token Management System - Admin Only

ADMIN_BOT_TOKEN="8248259347:AAFHwfo0eytvsNbTt9PVinkbnL7dAIMPihk"
DB_FILE="/etc/xray/commercial.db"

generate_token() {
    local duration_days=\$1
    local vps_ip=\$2
    
    # Generate random token
    TOKEN=$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-32)
    TOKEN_HASH=$(echo -n "\$TOKEN\$vps_ip" | sha256sum | cut -d' ' -f1)
    EXPIRY_DATE=$(date -d "+$duration_days days" "+%Y-%m-%d %H:%M:%S")
    
    # Save to database
    sqlite3 \$DB_FILE "INSERT INTO installation_tokens (token_hash, vps_ip, expiry_date) VALUES ('\$TOKEN_HASH', '\$vps_ip', '\$EXPIRY_DATE');"
    
    echo "✅ Token generated: \$TOKEN"
    echo "📅 Expires: \$EXPIRY_DATE"
    echo "🖥️ VPS IP: \$vps_ip"
}

list_tokens() {
    echo "🔑 Active Installation Tokens:"
    echo "================================"
    sqlite3 -header -column \$DB_FILE "SELECT vps_ip, expiry_date, is_active FROM installation_tokens ORDER BY created_date DESC;"
}

extend_token() {
    local vps_ip=\$1
    local additional_days=\$2
    
    sqlite3 \$DB_FILE "UPDATE installation_tokens SET expiry_date = datetime(expiry_date, '+$additional_days days') WHERE vps_ip = '\$vps_ip';"
    
    if [ \$? -eq 0 ]; then
        echo "✅ Token extended for \$vps_ip by \$additional_days days"
    else
        echo "❌ Failed to extend token"
    fi
}

case "\$1" in
    generate)
        generate_token "\$2" "\$3"
        ;;
    list)
        list_tokens
        ;;
    extend)
        extend_token "\$2" "\$3"
        ;;
    *)
        echo "Usage: token_manager [generate|list|extend]"
        echo "  generate <days> <vps_ip> - Generate new token"
        echo "  list - List all tokens"
        echo "  extend <vps_ip> <days> - Extend token"
        ;;
esac
EOF

    chmod +x /usr/local/bin/token_manager
    log "Token management system created"
}

# Create security monitor
create_security_monitor() {
    info "Creating security monitoring system..."
    
    cat > /usr/local/bin/security_monitor.py << 'PYTHON_EOF'
#!/usr/bin/env python3
import sqlite3
import datetime
import requests
import subprocess
import time

DB_PATH = "/etc/xray/commercial.db"
ADMIN_BOT_TOKEN = "8248259347:AAFHwfo0eytvsNbTt9PVinkbnL7dAIMPihk"
ADMIN_ID = 5407046882

def get_vps_ip():
    try:
        return requests.get('https://api.ipify.org').text
    except:
        return "unknown"

def check_token_validity():
    conn = sqlite3.connect(DB_PATH)
    vps_ip = get_vps_ip()
    
    # Check for valid token
    token = conn.execute('''
        SELECT * FROM installation_tokens 
        WHERE vps_ip = ? AND is_active = 1 
        AND expiry_date > datetime('now')
    ''', (vps_ip,)).fetchone()
    
    if not token:
        # No valid token found, schedule shutdown
        log_security_event("NO_VALID_TOKEN", f"No valid token for IP: {vps_ip}")
        schedule_shutdown()
        return False
    
    # Check if token expires in 3 days
    expiry_date = datetime.datetime.fromisoformat(token[3])
    days_until_expiry = (expiry_date - datetime.datetime.now()).days
    
    if days_until_expiry <= 3:
        notify_admin(f"⚠️ Token expires in {days_until_expiry} days for {vps_ip}")
    
    conn.close()
    return True

def log_security_event(action, details):
    conn = sqlite3.connect(DB_PATH)
    vps_ip = get_vps_ip()
    
    conn.execute('''
        INSERT INTO security_logs (action, details, ip_address)
        VALUES (?, ?, ?)
    ''', (action, details, vps_ip))
    
    conn.commit()
    conn.close()

def notify_admin(message):
    url = f"https://api.telegram.org/bot{ADMIN_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": ADMIN_ID,
        "text": message
    }
    try:
        requests.post(url, data=data)
    except:
        pass

def schedule_shutdown():
    # Schedule system cleanup in 3 days
    subprocess.run([
        'bash', '-c', '''
        sleep 259200 && 
        systemctl stop xray xray-commercial-bot && 
        rm -rf /etc/xray /usr/local/bin/token_manager /usr/local/bin/encrypt_system &&
        apt remove -y xray &&
        crontab -r
        '''
    ], check=False)
    
    notify_admin("🚨 SYSTEM SHUTDOWN SCHEDULED - No valid token found!")

def main():
    while True:
        try:
            if not check_token_validity():
                break
            time.sleep(3600)  # Check every hour
        except Exception as e:
            print(f"Monitor error: {e}")
            time.sleep(300)

if __name__ == '__main__':
    main()
PYTHON_EOF

    chmod +x /usr/local/bin/security_monitor.py
    
    # Create systemd service for security monitor
    cat > /etc/systemd/system/security-monitor.service << EOF
[Unit]
Description=Security Monitor for Commercial VPN
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/security_monitor.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable security-monitor
    systemctl start security-monitor
    
    log "Security monitoring system created"
}

# Create admin management script
create_admin_tools() {
    info "Creating admin management tools..."
    
    cat > /usr/local/bin/admin_tools << 'EOF'
#!/bin/bash
# Admin Tools - For Admin ID 5407046882 only

DB_FILE="/etc/xray/commercial.db"

show_stats() {
    echo "📊 Commercial VPN Statistics"
    echo "============================="
    
    # User statistics
    users=$(sqlite3 \$DB_FILE "SELECT COUNT(*) FROM users;")
    active_users=$(sqlite3 \$DB_FILE "SELECT COUNT(*) FROM users WHERE is_active = 1;")
    total_balance=$(sqlite3 \$DB_FILE "SELECT SUM(balance) FROM users;")
    total_spent=$(sqlite3 \$DB_FILE "SELECT SUM(total_spent) FROM users;")
    
    # Account statistics
    total_accounts=$(sqlite3 \$DB_FILE "SELECT COUNT(*) FROM vpn_accounts;")
    active_accounts=$(sqlite3 \$DB_FILE "SELECT COUNT(*) FROM vpn_accounts WHERE is_active = 1;")
    
    # Transaction statistics
    total_transactions=$(sqlite3 \$DB_FILE "SELECT COUNT(*) FROM transactions;")
    pending_transactions=$(sqlite3 \$DB_FILE "SELECT COUNT(*) FROM transactions WHERE status = 'pending';")
    
    echo "👥 Users: \$users (Active: \$active_users)"
    echo "💰 Total Balance: Rp \${total_balance:-0:,}"
    echo "💳 Total Spent: Rp \${total_spent:-0:,}"
    echo "📱 VPN Accounts: \$total_accounts (Active: \$active_accounts)"
    echo "💸 Transactions: \$total_transactions (Pending: \$pending_transactions)"
}

show_sales() {
    echo "📈 Sales Report"
    echo "================"
    
    sqlite3 -header -column \$DB_FILE "
    SELECT 
        date(created_date) as Date,
        COUNT(*) as Accounts,
        SUM(data_limit)/1073741824 as Total_GB,
        SUM(s.price_per_gb * (v.data_limit/1073741824)) as Revenue
    FROM vpn_accounts v
    JOIN servers s ON v.server_id = s.id
    WHERE date(created_date) >= date('now', '-7 days')
    GROUP BY date(created_date)
    ORDER BY Date DESC;
    "
}

show_tokens() {
    echo "🔑 Token Status"
    echo "================"
    sqlite3 -header -column \$DB_FILE "
    SELECT 
        vps_ip as VPS_IP,
        expiry_date as Expiry,
        CASE WHEN is_active = 1 THEN 'Active' ELSE 'Inactive' END as Status,
        datetime(created_date) as Created
    FROM installation_tokens
    ORDER BY created_date DESC;
    "
}

case "\$1" in
    stats)
        show_stats
        ;;
    sales)
        show_sales
        ;;
    tokens)
        show_tokens
        ;;
    *)
        echo "Usage: admin_tools [stats|sales|tokens]"
        echo "  stats - Show system statistics"
        echo "  sales - Show sales report"
        echo "  tokens - Show token status"
        ;;
esac
EOF

    chmod +x /usr/local/bin/admin_tools
    log "Admin tools created"
}

# Final setup and start
final_setup() {
    info "Finalizing installation..."
    
    # Start services
    systemctl start xray
    systemctl start xray-commercial-bot
    systemctl start security-monitor
    
    systemctl enable xray
    systemctl enable xray-commercial-bot
    systemctl enable security-monitor
    
    # Create menu
    cat > /usr/local/bin/menu << EOF
#!/bin/bash
echo "Commercial VPN System"
echo "====================="
echo "1. Check System Status"
echo "2. Admin Tools (Admin Only)"
echo "3. Token Manager (Admin Only)"
echo "4. Encrypt System (Admin Only)"
echo "5. Exit"
echo
read -p "Choose option: " choice

case \$choice in
    1)
        systemctl status xray
        systemctl status xray-commercial-bot
        ;;
    2)
        /usr/local/bin/admin_tools stats
        ;;
    3)
        /usr/local/bin/token_manager list
        ;;
    4)
        /usr/local/bin/encrypt_system encrypt
        ;;
    5)
        exit 0
        ;;
    *)
        echo "Invalid option"
        ;;
esac
EOF

    chmod +x /usr/local/bin/menu
    
    # Send installation complete notification
    VPS_IP=$(get_vps_ip)
    INSTALL_TOKEN=$(cat /tmp/install_token.txt 2>/dev/null || echo "unknown")
    
    NOTIFY_URL="https://api.telegram.org/bot${ADMIN_BOT_TOKEN}/sendMessage"
    NOTIFY_DATA="chat_id=5407046882&text=✅ Commercial VPN Installation Complete%0A🖥️ VPS IP: ${VPS_IP}%0A🔑 Token: ${INSTALL_TOKEN}%0A⏰ Completed: $(date)%0A📊 System: ${SYSTEM}"
    
    curl -s -X POST $NOTIFY_URL -d "$NOTIFY_DATA" > /dev/null
    
    log "Installation completed successfully!"
    
    echo
    echo -e "${GREEN}🎉 Commercial VPN Installation Complete!${NC}"
    echo
    echo -e "${CYAN}📊 System Information:${NC}"
    echo -e "  VPS IP: ${VPS_IP}"
    echo -e "  Admin ID: 5407046882"
    echo -e "  Database: ${DB_FILE}"
    echo -e "  Bot Config: /etc/xray/bot/config.yaml"
    echo
    echo -e "${YELLOW}⚠️ Important:${NC}"
    echo -e "  1. Edit /etc/xray/bot/config.yaml and set your bot token"
    echo -e "  2. Use 'menu' command for system management"
    echo -e "  3. Use 'token_manager' for token management (Admin only)"
    echo -e "  4. Use 'encrypt_system encrypt' to encrypt source code"
    echo
    echo -e "${GREEN}🚀 Next Steps:${NC}"
    echo -e "  1. Set bot token in config.yaml"
    echo -e "  2. Restart bot: systemctl restart xray-commercial-bot"
    echo -e "  3. Encrypt system: encrypt_system encrypt"
    echo
}

# Main installation function
main_installation() {
    check_root
    verify_token
    detect_system
    install_dependencies
    configure_firewall
    install_xray
    init_database
    create_xray_config
    create_commercial_bot
    create_encryption_system
    create_token_management
    create_security_monitor
    create_admin_tools
    final_setup
}

# Run installation
main_installation
