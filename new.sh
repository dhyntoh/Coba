#!/bin/bash

# Password Protection
PASSWORD="dintoganteng"
echo -n "Enter installation password: "
read -s input_password
echo

if [ "$input_password" != "$PASSWORD" ]; then
    echo "❌ Access Denied! Wrong password."
    exit 1
fi

echo "✅ Password verified! Starting installation..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
CONFIG_DIR="/etc/xray"
BACKUP_DIR="/root/xray-backups"
DB_FILE="/etc/xray/xray.db"
BOT_DIR="/etc/xray/bot"
LOG_FILE="/var/log/xray-install.log"

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $LOG_FILE
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a $LOG_FILE
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a $LOG_FILE
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a $LOG_FILE
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Detect system information
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

# Configure firewall
configure_firewall() {
    info "Configuring firewall..."
    
    # Check if UFW is available
    if command -v ufw &> /dev/null; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow 22/tcp comment 'SSH'
        ufw allow 80/tcp comment 'HTTP for Certbot'
        ufw allow 443/tcp comment 'HTTPS VPN'
        ufw allow 443/udp comment 'UDP VPN'
        ufw allow 8388/tcp comment 'Shadowsocks'
        ufw allow 8388/udp comment 'Shadowsocks UDP'
        ufw --force enable
        info "UFW firewall configured"
    
    # Check if firewalld is available
    elif command -v firewall-cmd &> /dev/null; then
        systemctl start firewalld
        systemctl enable firewalld
        firewall-cmd --permanent --add-port=22/tcp
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --permanent --add-port=443/udp
        firewall-cmd --permanent --add-port=8388/tcp
        firewall-cmd --permanent --add-port=8388/udp
        firewall-cmd --reload
        info "Firewalld configured"
    
    # Check if iptables is available
    elif command -v iptables &> /dev/null; then
        iptables -F
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        iptables -A INPUT -p tcp --dport 80 -j ACCEPT
        iptables -A INPUT -p tcp --dport 443 -j ACCEPT
        iptables -A INPUT -p udp --dport 443 -j ACCEPT
        iptables -A INPUT -p tcp --dport 8388 -j ACCEPT
        iptables -A INPUT -p udp --dport 8388 -j ACCEPT
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -i lo -j ACCEPT
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT
        info "iptables configured"
        
        # Save iptables rules
        if [[ $SYSTEM == "centos" ]]; then
            service iptables save
        else
            apt-get install -y iptables-persistent
            netfilter-persistent save
        fi
    else
        warning "No firewall manager found, please configure manually"
    fi
}

# Install dependencies
install_dependencies() {
    info "Installing dependencies..."
    
    if [[ $SYSTEM == "centos" ]]; then
        yum update -y
        yum install -y curl wget unzip socat openssl sqlite python3 python3-pip iptables-services
    else
        apt update -y
        apt install -y curl wget unzip socat openssl sqlite3 python3 python3-pip iptables-persistent
    fi
    
    # Install Python requirements for bot
    pip3 install python-telegram-bot requests pyyaml psutil
    
    log "Dependencies installed successfully"
}

# Install Xray
install_xray() {
    info "Installing Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    systemctl enable xray
    log "Xray installed successfully"
}

# Generate TLS certificate
generate_certificate() {
    info "Setting up TLS certificate..."
    
    read -p "Enter your domain (or press enter to use IP): " DOMAIN
    
    if [[ -n $DOMAIN ]]; then
        # Install certbot for Let's Encrypt
        if [[ $SYSTEM == "centos" ]]; then
            yum install -y epel-release
            yum install -y certbot
        else
            apt install -y certbot
        fi
        
        # Stop any service using port 80
        systemctl stop nginx 2>/dev/null || true
        systemctl stop apache2 2>/dev/null || true
        
        # Generate certificate
        certbot certonly --standalone --agree-tos --register-unsafely-without-email -d $DOMAIN -n
        CERT_FILE="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        KEY_FILE="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        
        if [[ ! -f $CERT_FILE ]]; then
            warning "Certificate generation failed, using self-signed"
            generate_selfsigned_cert
        else
            log "SSL certificate generated for $DOMAIN"
        fi
    else
        generate_selfsigned_cert
    fi
}

# Generate self-signed certificate
generate_selfsigned_cert() {
    info "Generating self-signed certificate..."
    mkdir -p $CONFIG_DIR/ssl
    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
        -keyout $CONFIG_DIR/ssl/selfsigned.key \
        -out $CONFIG_DIR/ssl/selfsigned.crt
    CERT_FILE="$CONFIG_DIR/ssl/selfsigned.crt"
    KEY_FILE="$CONFIG_DIR/ssl/selfsigned.key"
    log "Self-signed certificate generated"
}

# Initialize database
init_database() {
    info "Initializing database..."
    
    sqlite3 $DB_FILE "CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        uuid TEXT UNIQUE,
        password TEXT,
        data_limit INTEGER DEFAULT 0,
        used_data INTEGER DEFAULT 0,
        expiry_date TEXT,
        enabled INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );"
    
    sqlite3 $DB_FILE "CREATE TABLE IF NOT EXISTS admin (
        chat_id INTEGER PRIMARY KEY,
        username TEXT
    );"
    
    # Insert default admin
    sqlite3 $DB_FILE "INSERT OR IGNORE INTO admin (chat_id, username) VALUES (0, 'admin');"
    log "Database initialized"
}

# Create Xray configuration with Shadowsocks
create_xray_config() {
    info "Creating Xray configuration with Shadowsocks..."
    
    # Get domain or IP
    if [[ -n $DOMAIN ]]; then
        SERVER_ADDRESS="$DOMAIN"
    else
        SERVER_ADDRESS=$(curl -s ifconfig.me)
    fi
    
    # Generate Shadowsocks password
    SHADOWSOCKS_PASSWORD=$(openssl rand -base64 16)
    
    cat > $CONFIG_DIR/config.json << EOF
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "blocked"
            }
        ]
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
                            "certificateFile": "$CERT_FILE",
                            "keyFile": "$KEY_FILE"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/vmess"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
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
                            "certificateFile": "$CERT_FILE",
                            "keyFile": "$KEY_FILE"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/vless"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        },
        {
            "tag": "trojan-ws",
            "port": 443,
            "protocol": "trojan",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "$CERT_FILE",
                            "keyFile": "$KEY_FILE"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/trojan"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        },
        {
            "tag": "shadowsocks-tcp",
            "port": 8388,
            "protocol": "shadowsocks",
            "settings": {
                "clients": [
                    {
                        "method": "chacha20-ietf-poly1305",
                        "password": "$SHADOWSOCKS_PASSWORD"
                    }
                ],
                "network": "tcp,udp"
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        }
    ],
    "outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom"
        },
        {
            "tag": "blocked",
            "protocol": "blackhole"
        }
    ]
}
EOF
    log "Xray configuration created with Shadowsocks"
    
    # Save Shadowsocks password
    echo "SHADOWSOCKS_PASSWORD=$SHADOWSOCKS_PASSWORD" > $CONFIG_DIR/shadowsocks.info
    echo "SHADOWSOCKS_PORT=8388" >> $CONFIG_DIR/shadowsocks.info
    echo "SHADOWSOCKS_METHOD=chacha20-ietf-poly1305" >> $CONFIG_DIR/shadowsocks.info
}

# Create Telegram Bot
create_telegram_bot() {
    info "Setting up Telegram Bot..."
    
    mkdir -p $BOT_DIR
    
    read -p "Enter your Telegram Bot Token: " BOT_TOKEN
    read -p "Enter your Telegram Chat ID: " ADMIN_CHAT_ID
    
    # Get server address
    if [[ -n $DOMAIN ]]; then
        SERVER_DOMAIN="$DOMAIN"
    else
        SERVER_DOMAIN=$(curl -s ifconfig.me)
    fi
    
    # Save bot configuration
    cat > $BOT_DIR/config.yaml << EOF
bot:
  token: "$BOT_TOKEN"
  admin_id: $ADMIN_CHAT_ID

xray:
  config_path: "$CONFIG_DIR/config.json"
  database_path: "$DB_FILE"

server:
  domain: "$SERVER_DOMAIN"
EOF

    # Create the bot Python script
    cat > $BOT_DIR/xray_bot.py << 'PYTHON_EOF'
#!/usr/bin/env python3
import sqlite3
import json
import logging
import yaml
import subprocess
import base64
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters

# Load configuration
with open('/etc/xray/bot/config.yaml', 'r') as f:
    config = yaml.safe_load(f)

BOT_TOKEN = config['bot']['token']
ADMIN_ID = config['bot']['admin_id']
DB_PATH = config['xray']['database_path']
DOMAIN = config['server']['domain']

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db_connection():
    return sqlite3.connect(DB_PATH)

def is_admin(chat_id):
    conn = get_db_connection()
    admin = conn.execute("SELECT chat_id FROM admin WHERE chat_id = ?", (chat_id,)).fetchone()
    conn.close()
    return admin is not None

def generate_vmess_config(uuid, username):
    config = {
        "v": "2",
        "ps": f"Xray-VMess-{username}",
        "add": DOMAIN,
        "port": "443",
        "id": uuid,
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": DOMAIN,
        "path": "/vmess",
        "tls": "tls",
        "sni": DOMAIN
    }
    return base64.b64encode(json.dumps(config).encode()).decode()

def generate_vless_config(uuid, username):
    return f"vless://{uuid}@{DOMAIN}:443?encryption=none&security=tls&sni={DOMAIN}&type=ws&host={DOMAIN}&path=%2Fvless#Xray-VLess-{username}"

def generate_trojan_config(password, username):
    return f"trojan://{password}@{DOMAIN}:443?security=tls&sni={DOMAIN}&type=ws&host={DOMAIN}&path=%2Ftrojan#Xray-Trojan-{username}"

def generate_shadowsocks_config():
    try:
        with open('/etc/xray/shadowsocks.info', 'r') as f:
            lines = f.readlines()
            password = lines[0].split('=')[1].strip()
            port = lines[1].split('=')[1].strip()
            method = lines[2].split('=')[1].strip()
        
        config = f"{method}:{password}@{DOMAIN}:{port}"
        encoded = base64.b64encode(config.encode()).decode()
        return f"ss://{encoded}#Xray-Shadowsocks"
    except:
        return "Shadowsocks configuration not available"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_chat.id):
        await update.message.reply_text("❌ You are not authorized to use this bot.")
        return
    
    keyboard = [
        [InlineKeyboardButton("👥 Create User", callback_data="create_user")],
        [InlineKeyboardButton("📊 User List", callback_data="user_list")],
        [InlineKeyboardButton("❌ Delete User", callback_data="delete_user")],
        [InlineKeyboardButton("🔄 Restart Xray", callback_data="restart_xray")],
        [InlineKeyboardButton("💾 Backup Config", callback_data="backup_config")],
        [InlineKeyboardButton("📈 Server Status", callback_data="server_status")],
        [InlineKeyboardButton("🔑 Shadowsocks Info", callback_data="shadowsocks_info")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("🤖 Xray VPN Management Bot\nChoose an option:", reply_markup=reply_markup)

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if not is_admin(query.from_user.id):
        await query.edit_message_text("❌ You are not authorized.")
        return
    
    data = query.data
    
    if data == "create_user":
        context.user_data['awaiting_username'] = True
        await query.edit_message_text("Please send me the username for the new user:")
    
    elif data == "user_list":
        users = get_user_list()
        if users:
            message = "👥 User List:\n\n"
            for user in users:
                status = "✅" if user[4] else "❌"
                message += f"{status} {user[1]}\nUUID: {user[2]}\nPassword: {user[3]}\n\n"
        else:
            message = "No users found."
        await query.edit_message_text(message)
    
    elif data == "delete_user":
        users = get_user_list()
        if users:
            keyboard = []
            for user in users:
                keyboard.append([InlineKeyboardButton(f"❌ {user[1]}", callback_data=f"delete_{user[0]}")])
            keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="back_main")])
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text("Select user to delete:", reply_markup=reply_markup)
        else:
            await query.edit_message_text("No users found.")
    
    elif data.startswith("delete_"):
        user_id = data.split("_")[1]
        if delete_user(user_id):
            await query.edit_message_text("✅ User deleted successfully.")
        else:
            await query.edit_message_text("❌ Failed to delete user.")
    
    elif data == "restart_xray":
        if restart_xray():
            await query.edit_message_text("✅ Xray restarted successfully.")
        else:
            await query.edit_message_text("❌ Failed to restart Xray.")
    
    elif data == "backup_config":
        backup_file = backup_config()
        if backup_file:
            await query.edit_message_text(f"✅ Backup created: {backup_file}")
        else:
            await query.edit_message_text("❌ Backup failed.")
    
    elif data == "server_status":
        status = get_server_status()
        await query.edit_message_text(status)
    
    elif data == "shadowsocks_info":
        ss_config = generate_shadowsocks_config()
        await query.edit_message_text(f"🔑 Shadowsocks Configuration:\n\n{ss_config}")
    
    elif data == "back_main":
        await start(update, context)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_chat.id):
        return
    
    if context.user_data.get('awaiting_username'):
        username = update.message.text
        result = create_user(username)
        
        if result:
            uuid, password = result
            context.user_data['awaiting_username'] = False
            
            # Generate configurations
            vmess_config = generate_vmess_config(uuid, username)
            vless_config = generate_vless_config(uuid, username)
            trojan_config = generate_trojan_config(password, username)
            
            message = f"""
✅ User Created Successfully!

👤 Username: {username}
🔑 UUID: {uuid}
🔒 Password: {password}

📋 Configurations:

VMess (Base64):
vmess://{vmess_config}

VLESS:
{vless_config}

Trojan:
{trojan_config}

⚠️ Send these configurations securely to the user.
"""
            await update.message.reply_text(message)
        else:
            await update.message.reply_text("❌ Failed to create user. Username might already exist.")

def get_user_list():
    conn = get_db_connection()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return users

def create_user(username):
    import uuid as uuid_lib
    user_uuid = str(uuid_lib.uuid4())
    password = str(uuid_lib.uuid4())[:8]
    
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, uuid, password) VALUES (?, ?, ?)",
            (username, user_uuid, password)
        )
        conn.commit()
        return user_uuid, password
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def delete_user(user_id):
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()

def restart_xray():
    try:
        subprocess.run(["systemctl", "restart", "xray"], check=True)
        return True
    except:
        return False

def backup_config():
    try:
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"/root/xray-backups/backup_{timestamp}.tar.gz"
        subprocess.run(["tar", "-czf", backup_file, "/etc/xray"], check=True)
        return backup_file
    except:
        return None

def get_server_status():
    try:
        # Xray status
        xray_status = subprocess.run(["systemctl", "is-active", "xray"], capture_output=True, text=True).stdout.strip()
        
        # System info
        disk = subprocess.run(["df", "-h", "/"], capture_output=True, text=True).stdout.split('\n')[1].split()
        memory = subprocess.run(["free", "-m"], capture_output=True, text=True).stdout.split('\n')[1].split()
        
        # Connection info
        connections = subprocess.run(["ss", "-tunlp"], capture_output=True, text=True).stdout
        
        status_msg = f"""
🖥️ Server Status:

✅ Xray Service: {xray_status}
💾 Disk Usage: {disk[2]} / {disk[1]} ({disk[4]})
🧠 Memory: {memory[2]}MB / {memory[1]}MB
🔗 Domain: {DOMAIN}

📊 Active Users: {len(get_user_list())}

🌐 Open Ports:
  443/tcp (VMess/VLESS/Trojan WS)
  443/udp (UDP Support)
  8388/tcp (Shadowsocks)
  8388/udp (Shadowsocks UDP)
"""
        return status_msg
    except Exception as e:
        return f"Error getting status: {e}"

def main():
    # Set admin in database
    conn = get_db_connection()
    conn.execute("UPDATE admin SET chat_id = ? WHERE username = 'admin'", (ADMIN_ID,))
    conn.commit()
    conn.close()
    
    application = Application.builder().token(BOT_TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    logger.info("Bot started successfully!")
    application.run_polling()

if __name__ == '__main__':
    main()
PYTHON_EOF

    chmod +x $BOT_DIR/xray_bot.py
    
    # Create systemd service for bot
    cat > /etc/systemd/system/xray-bot.service << EOF
[Unit]
Description=Xray Telegram Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$BOT_DIR
ExecStart=/usr/bin/python3 $BOT_DIR/xray_bot.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log "Telegram Bot setup completed"
}

# Create management menu
create_management_menu() {
    info "Creating management menu system..."
    
    cat > /usr/local/bin/xray-menu.sh << 'MENU_EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Password check
PASSWORD="dintoganteng"
if [ "$1" != "nopass" ]; then
    echo -n "Enter menu password: "
    read -s input_pass
    echo
    if [ "$input_pass" != "$PASSWORD" ]; then
        echo -e "${RED}❌ Access Denied!${NC}"
        exit 1
    fi
fi

show_header() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                   XRAY VPN MANAGEMENT MENU               ║"
    echo "║                 Created by DintoGanteng                  ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

show_menu() {
    echo -e "${YELLOW}┌──────────────────────────────────────────────────────────┐"
    echo -e "│                     ${CYAN}MAIN MENU${YELLOW}                         │"
    echo -e "├──────────────────────────────────────────────────────────┤"
    echo -e "│  ${GREEN}1${YELLOW}) 📊 System Status & Information                 │"
    echo -e "│  ${GREEN}2${YELLOW}) 👥 User Management (Create/Delete)             │"
    echo -e "│  ${GREEN}3${YELLOW}) 🛠️  Service Control (Start/Stop/Restart)       │"
    echo -e "│  ${GREEN}4${YELLOW}) 📁 Backup & Restore Configuration              │"
    echo -e "│  ${GREEN}5${YELLOW}) 🔧 Firewall & Port Management                  │"
    echo -e "│  ${GREEN}6${YELLOW}) 📈 Real-time Monitoring & Logs                 │"
    echo -e "│  ${GREEN}7${YELLOW}) 🔑 Show Shadowsocks Configuration              │"
    echo -e "│  ${GREEN}8${YELLOW}) 🤖 Telegram Bot Control                        │"
    echo -e "│  ${GREEN}9${YELLOW}) 🚀 Speed Test & Connection Check               │"
    echo -e "│  ${GREEN}0${YELLOW}) ❌ Exit Menu                                   │"
    echo -e "└──────────────────────────────────────────────────────────┘${NC}"
    echo
    echo -n "Select option [0-9]: "
}

system_status() {
    echo -e "\n${CYAN}📊 SYSTEM STATUS & INFORMATION${NC}"
    echo -e "${YELLOW}─────────────────────────────────────${NC}"
    
    # Service status
    echo -e "\n${GREEN}🛠️ Service Status:${NC}"
    systemctl is-active xray >/dev/null 2>&1 && echo -e "Xray: ${GREEN}✅ RUNNING${NC}" || echo -e "Xray: ${RED}❌ STOPPED${NC}"
    systemctl is-active xray-bot >/dev/null 2>&1 && echo -e "Bot: ${GREEN}✅ RUNNING${NC}" || echo -e "Bot: ${RED}❌ STOPPED${NC}"
    
    # System info
    echo -e "\n${GREEN}💻 System Information:${NC}"
    echo "Hostname: $(hostname)"
    echo "Uptime: $(uptime -p)"
    echo "OS: $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"')"
    
    # Resource usage
    echo -e "\n${GREEN}📈 Resource Usage:${NC}"
    echo "CPU Load: $(uptime | awk -F'load average:' '{print $2}')"
    echo "Memory: $(free -h | grep Mem | awk '{print $3"/"$2}')"
    echo "Disk: $(df -h / | grep -v Filesystem | awk '{print $3"/"$2" ("$5")"}')"
    
    # Network info
    echo -e "\n${GREEN}🌐 Network Information:${NC}"
    echo "Public IP: $(curl -s ifconfig.me)"
    echo "Open VPN Ports: 443/tcp, 443/udp, 8388/tcp, 8388/udp"
    
    # User count
    if [ -f "/etc/xray/xray.db" ]; then
        user_count=$(sqlite3 /etc/xray/xray.db "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "0")
        echo "Total Users: $user_count"
    fi
    
    read -p "Press [Enter] to continue..."
}

user_management() {
    while true; do
        clear
        echo -e "\n${CYAN}👥 USER MANAGEMENT${NC}"
        echo -e "${YELLOW}─────────────────────────────────────${NC}"
        echo -e "${GREEN}1${NC}) Create New User"
        echo -e "${GREEN}2${NC}) List All Users" 
        echo -e "${GREEN}3${NC}) Delete User"
        echo -e "${GREEN}4${NC}) Back to Main Menu"
        echo
        echo -n "Select option [1-4]: "
        read user_choice
        
        case $user_choice in
            1)
                echo -n "Enter username: "
                read username
                if [ -n "$username" ]; then
                    # Create user using Python script method
                    python3 -c "
import sqlite3, uuid
conn = sqlite3.connect('/etc/xray/xray.db')
user_uuid = str(uuid.uuid4())
password = str(uuid.uuid4())[:8]
try:
    conn.execute('INSERT INTO users (username, uuid, password) VALUES (?, ?, ?)', ('''$username''', user_uuid, password))
    conn.commit()
    print('User created successfully!')
    print(f'Username: {'''$username''}')
    print(f'UUID: {user_uuid}')
    print(f'Password: {password}')
except:
    print('Error: Username might already exist')
conn.close()
"
                    systemctl restart xray
                fi
                ;;
            2)
                echo -e "\n${GREEN}User List:${NC}"
                sqlite3 /etc/xray/xray.db "SELECT id, username, uuid, password FROM users;" 2>/dev/null | while IFS='|' read id username uuid password; do
                    echo "User: $username | UUID: $uuid | Password: $password"
                done
                ;;
            3)
                echo -n "Enter username to delete: "
                read del_user
                if [ -n "$del_user" ]; then
                    sqlite3 /etc/xray/xray.db "DELETE FROM users WHERE username='$del_user';" 2>/dev/null
                    systemctl restart xray
                    echo "User $del_user deleted!"
                fi
                ;;
            4)
                break
                ;;
        esac
        echo && read -p "Press [Enter] to continue..."
    done
}

service_control() {
    while true; do
        clear
        echo -e "\n${CYAN}🛠️ SERVICE CONTROL${NC}"
        echo -e "${YELLOW}─────────────────────────────────────${NC}"
        echo -e "${GREEN}1${NC}) Start Xray Service"
        echo -e "${GREEN}2${NC}) Stop Xray Service"
        echo -e "${GREEN}3${NC}) Restart Xray Service"
        echo -e "${GREEN}4${NC}) Start Telegram Bot"
        echo -e "${GREEN}5${NC}) Stop Telegram Bot"
        echo -e "${GREEN}6${NC}) Restart Telegram Bot"
        echo -e "${GREEN}7${NC}) Enable Auto-start"
        echo -e "${GREEN}8${NC}) Back to Main Menu"
        echo
        echo -n "Select option [1-8]: "
        read service_choice
        
        case $service_choice in
            1) systemctl start xray; echo "Xray started!" ;;
            2) systemctl stop xray; echo "Xray stopped!" ;;
            3) systemctl restart xray; echo "Xray restarted!" ;;
            4) systemctl start xray-bot; echo "Bot started!" ;;
            5) systemctl stop xray-bot; echo "Bot stopped!" ;;
            6) systemctl restart xray-bot; echo "Bot restarted!" ;;
            7) systemctl enable xray xray-bot; echo "Auto-start enabled!" ;;
            8) break ;;
        esac
        read -p "Press [Enter] to continue..."
    done
}

backup_restore() {
    while true; do
        clear
        echo -e "\n${CYAN}📁 BACKUP & RESTORE${NC}"
        echo -e "${YELLOW}─────────────────────────────────────${NC}"
        echo -e "${GREEN}1${NC}) Create Backup"
        echo -e "${GREEN}2${NC}) Restore Backup"
        echo -e "${GREEN}3${NC}) List Backups"
        echo -e "${GREEN}4${NC}) Back to Main Menu"
        echo
        echo -n "Select option [1-4]: "
        read backup_choice
        
        case $backup_choice in
            1) /usr/local/bin/xray-backup.sh ;;
            2) /usr/local/bin/xray-restore.sh ;;
            3) 
                echo -e "\n${GREEN}Available Backups:${NC}"
                ls -la /root/xray-backups/*.tar.gz 2>/dev/null || echo "No backups found"
                ;;
            4) break ;;
        esac
        read -p "Press [Enter] to continue..."
    done
}

firewall_management() {
    echo -e "\n${CYAN}🔧 FIREWALL & PORT MANAGEMENT${NC}"
    echo -e "${YELLOW}─────────────────────────────────────${NC}"
    
    echo -e "\n${GREEN}Current Firewall Status:${NC}"
    if command -v ufw &> /dev/null; then
        ufw status numbered
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --list-all
    else
        iptables -L -n
    fi
    
    echo -e "\n${GREEN}Open Ports:${NC}"
    echo "443/tcp  - VMess/VLESS/Trojan (WebSocket)"
    echo "443/udp  - UDP Support"
    echo "8388/tcp - Shadowsocks"
    echo "8388/udp - Shadowsocks UDP"
    
    read -p "Press [Enter] to continue..."
}

monitoring_logs() {
    while true; do
        clear
        echo -e "\n${CYAN}📈 MONITORING & LOGS${NC}"
        echo -e "${YELLOW}─────────────────────────────────────${NC}"
        echo -e "${GREEN}1${NC}) View Xray Real-time Log"
        echo -e "${GREEN}2${NC}) View Bot Real-time Log"
        echo -e "${GREEN}3${NC}) View System Log"
        echo -e "${GREEN}4${NC}) Connection Statistics"
        echo -e "${GREEN}5${NC}) Back to Main Menu"
        echo
        echo -n "Select option [1-5]: "
        read monitor_choice
        
        case $monitor_choice in
            1) journalctl -u xray -f ;;
            2) journalctl -u xray-bot -f ;;
            3) tail -f /var/log/xray/access.log ;;
            4) 
                echo -e "\n${GREEN}Active Connections:${NC}"
                ss -tunlp | grep -E '(443|8388)'
                echo -e "\n${GREEN}Xray Connections:${NC}"
                netstat -tunlp | grep xray
                read -p "Press [Enter] to continue..."
                ;;
            5) break ;;
        esac
    done
}

show_shadowsocks() {
    echo -e "\n${CYAN}🔑 SHADOWSOCKS CONFIGURATION${NC}"
    echo -e "${YELLOW}─────────────────────────────────────${NC}"
    
    if [ -f "/etc/xray/shadowsocks.info" ]; then
        source /etc/xray/shadowsocks.info
        echo -e "${GREEN}Server:${NC} $(curl -s ifconfig.me)"
        echo -e "${GREEN}Port:${NC} $SHADOWSOCKS_PORT"
        echo -e "${GREEN}Password:${NC} $SHADOWSOCKS_PASSWORD"
        echo -e "${GREEN}Method:${NC} $SHADOWSOCKS_METHOD"
        echo -e "${GREEN}Configuration URL:${NC}"
        
        config="$SHADOWSOCKS_METHOD:$SHADOWSOCKS_PASSWORD@$(curl -s ifconfig.me):$SHADOWSOCKS_PORT"
        encoded=$(echo -n "$config" | base64 -w 0)
        echo "ss://$encoded"
    else
        echo -e "${RED}Shadowsocks configuration not found!${NC}"
    fi
    
    read -p "Press [Enter] to continue..."
}

bot_control() {
    while true; do
        clear
        echo -e "\n${CYAN}🤖 TELEGRAM BOT CONTROL${NC}"
        echo -e "${YELLOW}─────────────────────────────────────${NC}"
        echo -e "${GREEN}1${NC}) Start Bot"
        echo -e "${GREEN}2${NC}) Stop Bot"
        echo -e "${GREEN}3${NC}) Restart Bot"
        echo -e "${GREEN}4${NC}) View Bot Status"
        echo -e "${GREEN}5${NC}) View Bot Configuration"
        echo -e "${GREEN}6${NC}) Back to Main Menu"
        echo
        echo -n "Select option [1-6]: "
        read bot_choice
        
        case $bot_choice in
            1) systemctl start xray-bot; echo "Bot started!" ;;
            2) systemctl stop xray-bot; echo "Bot stopped!" ;;
            3) systemctl restart xray-bot; echo "Bot restarted!" ;;
            4) systemctl status xray-bot ;;
            5) 
                echo -e "\n${GREEN}Bot Configuration:${NC}"
                cat /etc/xray/bot/config.yaml 2>/dev/null || echo "Configuration not found"
                ;;
            6) break ;;
        esac
        [ $bot_choice -ne 4 ] && read -p "Press [Enter] to continue..."
    done
}

speed_test() {
    echo -e "\n${CYAN}🚀 SPEED TEST & CONNECTION CHECK${NC}"
    echo -e "${YELLOW}─────────────────────────────────────${NC}"
    
    echo -e "${GREEN}Testing download speed...${NC}"
    speedtest-cli --simple
    
    echo -e "\n${GREEN}Testing connectivity to VPN ports...${NC}"
    for port in 443 8388; do
        if nc -z localhost $port; then
            echo -e "Port $port: ${GREEN}✅ OPEN${NC}"
        else
            echo -e "Port $port: ${RED}❌ CLOSED${NC}"
        fi
    done
    
    read -p "Press [Enter] to continue..."
}

# Main menu loop
while true; do
    show_header
    show_menu
    read choice
    
    case $choice in
        1) system_status ;;
        2) user_management ;;
        3) service_control ;;
        4) backup_restore ;;
        5) firewall_management ;;
        6) monitoring_logs ;;
        7) show_shadowsocks ;;
        8) bot_control ;;
        9) speed_test ;;
        0) 
            echo -e "${GREEN}Thank you for using Xray VPN Manager!${NC}"
            exit 0
            ;;
        *) 
            echo -e "${RED}Invalid option! Please try again.${NC}"
            sleep 2
            ;;
    esac
done
MENU_EOF

    chmod +x /usr/local/bin/xray-menu.sh
    log "Management menu created"
}

# Create backup script
create_backup_script() {
    info "Creating backup and restore scripts..."
    
    mkdir -p $BACKUP_DIR
    
    cat > /usr/local/bin/xray-backup.sh << 'BACKUP_EOF'
#!/bin/bash

BACKUP_DIR="/root/xray-backups"
CONFIG_DIR="/etc/xray"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="xray-backup-$DATE.tar.gz"

echo "Creating Xray backup..."
tar -czf $BACKUP_DIR/$BACKUP_FILE $CONFIG_DIR /usr/local/bin/xray 2>/dev/null

if [[ $? -eq 0 ]]; then
    echo "Backup created: $BACKUP_DIR/$BACKUP_FILE"
    ls -t $BACKUP_DIR/xray-backup-*.tar.gz | tail -n +6 | xargs rm -f
else
    echo "Backup failed!"
    exit 1
fi
BACKUP_EOF

    cat > /usr/local/bin/xray-restore.sh << 'RESTORE_EOF'
#!/bin/bash

BACKUP_DIR="/root/xray-backups"
CONFIG_DIR="/etc/xray"

echo "Available backups:"
ls -l $BACKUP_DIR/xray-backup-*.tar.gz 2>/dev/null || echo "No backups found"

read -p "Enter backup filename to restore: " BACKUP_FILE

if [[ ! -f $BACKUP_DIR/$BACKUP_FILE ]]; then
    echo "Backup file not found!"
    exit 1
fi

echo "Stopping services..."
systemctl stop xray
systemctl stop xray-bot

echo "Restoring from backup..."
tar -xzf $BACKUP_DIR/$BACKUP_FILE -C /

echo "Starting services..."
systemctl start xray
systemctl start xray-bot

echo "Restore completed!"
RESTORE_EOF

    chmod +x /usr/local/bin/xray-backup.sh
    chmod +x /usr/local/bin/xray-restore.sh
    log "Backup scripts created"
}

# Show installation info
show_installation_info() {
    log "=== Installation Completed Successfully! ==="
    echo ""
    echo "🔐 Password: dintoganteng"
    echo ""
    echo "📁 Configuration Files:"
    echo "   Xray Config: /etc/xray/config.json"
    echo "   Database: /etc/xray/xray.db"
    echo "   Bot Config: /etc/xray/bot/config.yaml"
    echo "   Backups: /root/xray-backups/"
    echo ""
    echo "🎮 Management Menu:"
    echo "   xray-menu.sh                    # With password"
    echo "   xray-menu.sh nopass             # Without password"
    echo ""
    echo "🛠️ Service Control:"
    echo "   systemctl start|stop|restart xray xray-bot"
    echo "   systemctl enable xray xray-bot"
    echo ""
    echo "🔧 Features Included:"
    echo "   ✅ VMess, VLESS, Trojan, Shadowsocks"
    echo "   ✅ TCP & UDP Support"
    echo "   ✅ Auto Firewall Configuration"
    echo "   ✅ Telegram Bot Control"
    echo "   ✅ Backup & Restore System"
    echo "   ✅ Interactive Management Menu"
    echo "   ✅ Real-time Monitoring"
    echo ""
    echo "📱 Access Menu:"
    echo "   Just type: xray-menu.sh"
    echo "   Password: dintoganteng"
    echo ""
    echo "⚠️ Next Steps:"
    echo "   1. Access menu: xray-menu.sh"
    echo "   2. Start Telegram Bot from menu"
    echo "   3. Create users via menu or bot"
    echo "   4. Test VPN connections"
}

# Main installation function
main_installation() {
    info "Starting Complete Xray VPN Installation..."
    check_root
    detect_system
    configure_firewall
    install_dependencies
    install_xray
    generate_certificate
    init_database
    create_xray_config
    create_telegram_bot
    create_backup_script
    create_management_menu
    
    # Start services
    systemctl start xray
    systemctl enable xray
    
    show_installation_info
    
    # Save installation info
    cat > /root/xray-install-info.txt << EOF
XRAY VPN INSTALLATION COMPLETE
==============================
Installation Date: $(date)
Password: dintoganteng

Management Commands:
- Menu: xray-menu.sh
- Service Control: systemctl [start|stop|restart] xray xray-bot
- Backup: xray-backup.sh
- Restore: xray-restore.sh

Features:
- VMess, VLESS, Trojan, Shadowsocks
- TCP & UDP Support
- Telegram Bot Control
- Firewall Auto-config
- Backup System
- Web Interface Menu

Access the menu with: xray-menu.sh
Password: dintoganteng
EOF
}

# Run main installation
main_installation