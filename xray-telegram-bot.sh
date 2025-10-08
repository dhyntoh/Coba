
#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
CONFIG_DIR="/etc/xray"
BACKUP_DIR="/root/xray-backups"
DB_FILE="/etc/xray/xray.db"
BOT_DIR="/etc/xray/bot"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
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
        log_error "Unsupported system"
        exit 1
    fi
    log_info "Detected system: $SYSTEM"
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies..."
    
    if [[ $SYSTEM == "centos" ]]; then
        yum update -y
        yum install -y curl wget unzip socat openssl sqlite python3 python3-pip
    else
        apt update -y
        apt install -y curl wget unzip socat openssl sqlite3 python3 python3-pip
    fi
    
    # Install Python requirements for bot
    pip3 install python-telegram-bot requests pyyaml psutil
}

# Install Xray
install_xray() {
    log_info "Installing Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    systemctl enable xray
}

# Generate TLS certificate
generate_certificate() {
    log_info "Setting up TLS certificate..."
    
    read -p "Enter your domain (or press enter to use IP): " DOMAIN
    
    if [[ -n $DOMAIN ]]; then
        # Install certbot for Let's Encrypt
        if [[ $SYSTEM == "centos" ]]; then
            yum install -y epel-release
            yum install -y certbot
        else
            apt install -y certbot
        fi
        
        # Generate certificate
        certbot certonly --standalone --agree-tos --register-unsafely-without-email -d $DOMAIN -n
        CERT_FILE="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        KEY_FILE="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        
        if [[ ! -f $CERT_FILE ]]; then
            log_warning "Certificate generation failed, using self-signed"
            generate_selfsigned_cert
        else
            log_success "SSL certificate generated for $DOMAIN"
        fi
    else
        generate_selfsigned_cert
    fi
}

# Generate self-signed certificate
generate_selfsigned_cert() {
    log_info "Generating self-signed certificate..."
    mkdir -p $CONFIG_DIR/ssl
    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
        -keyout $CONFIG_DIR/ssl/selfsigned.key \
        -out $CONFIG_DIR/ssl/selfsigned.crt
    CERT_FILE="$CONFIG_DIR/ssl/selfsigned.crt"
    KEY_FILE="$CONFIG_DIR/ssl/selfsigned.key"
    log_success "Self-signed certificate generated"
}

# Initialize database
init_database() {
    log_info "Initializing database..."
    
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
    log_success "Database initialized"
}

# Create Xray configuration
create_xray_config() {
    log_info "Creating Xray configuration..."
    
    # Get domain or IP
    if [[ -n $DOMAIN ]]; then
        SERVER_ADDRESS="$DOMAIN"
    else
        SERVER_ADDRESS=$(curl -s ifconfig.me)
    fi
    
    cat > $CONFIG_DIR/config.json << EOF
{
    "log": {
        "loglevel": "warning"
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
    log_success "Xray configuration created"
}

# Create Telegram Bot
create_telegram_bot() {
    log_info "Setting up Telegram Bot..."
    
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
    return json.dumps(config)

def generate_vless_config(uuid, username):
    return f"vless://{uuid}@{DOMAIN}:443?encryption=none&security=tls&sni={DOMAIN}&type=ws&host={DOMAIN}&path=%2Fvless#Xray-VLess-{username}"

def generate_trojan_config(password, username):
    return f"trojan://{password}@{DOMAIN}:443?security=tls&sni={DOMAIN}&type=ws&host={DOMAIN}&path=%2Ftrojan#Xray-Trojan-{username}"

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
        [InlineKeyboardButton("📈 Server Status", callback_data="server_status")]
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
{vmess_config}

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
        
        status_msg = f"""
🖥️ Server Status:

✅ Xray Service: {xray_status}
💾 Disk Usage: {disk[2]} / {disk[1]} ({disk[4]})
🧠 Memory: {memory[2]}MB / {memory[1]}MB
🔗 Domain: {DOMAIN}

📊 Active Users: {len(get_user_list())}
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
    log_success "Telegram Bot setup completed"
}

# Create backup script
create_backup_script() {
    log_info "Creating backup and restore scripts..."
    
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
    log_success "Backup scripts created"
}

# Create management script
create_management_script() {
    cat > /usr/local/bin/xray-manager.sh << 'MANAGER_EOF'
#!/bin/bash

case "$1" in
    start)
        systemctl start xray
        systemctl start xray-bot
        echo "Services started"
        ;;
    stop)
        systemctl stop xray
        systemctl stop xray-bot
        echo "Services stopped"
        ;;
    restart)
        systemctl restart xray
        systemctl restart xray-bot
        echo "Services restarted"
        ;;
    status)
        echo "=== Xray Status ==="
        systemctl status xray
        echo "=== Bot Status ==="
        systemctl status xray-bot
        ;;
    backup)
        /usr/local/bin/xray-backup.sh
        ;;
    restore)
        /usr/local/bin/xray-restore.sh
        ;;
    bot-log)
        journalctl -u xray-bot -f
        ;;
    xray-log)
        journalctl -u xray -f
        ;;
    *)
        echo "Usage: xray-manager.sh {start|stop|restart|status|backup|restore|bot-log|xray-log}"
        ;;
esac
MANAGER_EOF

    chmod +x /usr/local/bin/xray-manager.sh
    log_success "Management script created"
}

# Show installation info
show_info() {
    log_success "=== Installation Completed Successfully! ==="
    echo ""
    echo "📁 Configuration Files:"
    echo "   Xray Config: /etc/xray/config.json"
    echo "   Database: /etc/xray/xray.db"
    echo "   Bot Config: /etc/xray/bot/config.yaml"
    echo "   Backups: /root/xray-backups/"
    echo ""
    echo "🛠 Management Commands:"
    echo "   xray-manager.sh start|stop|restart|status"
    echo "   xray-manager.sh backup|restore"
    echo "   xray-manager.sh bot-log|xray-log"
    echo ""
    echo "🤖 Telegram Bot Setup:"
    echo "   1. Start the bot: systemctl start xray-bot"
    echo "   2. Send /start to your bot in Telegram"
    echo "   3. Create users via the bot menu"
    echo ""
    echo "🔧 Service Control:"
    echo "   systemctl start xray xray-bot"
    echo "   systemctl enable xray xray-bot"
    echo ""
    echo "⚠️ Next Steps:"
    echo "   - Configure firewall to allow ports 443, 80"
    echo "   - Test VPN connections with generated configs"
    echo "   - Regular backups with xray-manager.sh backup"
}

# Main installation function
main() {
    log_info "Starting Xray VPN with Telegram Bot installation..."
    check_root
    detect_system
    install_dependencies
    install_xray
    generate_certificate
    init_database
    create_xray_config
    create_telegram_bot
    create_backup_script
    create_management_script
    
    # Start services
    systemctl start xray
    systemctl enable xray
    systemctl enable xray-bot
    
    show_info
}

# Run main function
main
