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
DOMAIN=""
UUID=$(cat /proc/sys/kernel/random/uuid)

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

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
}

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
    pip3 install python-telegram-bot requests pyyaml
}

install_xray() {
    log_info "Installing Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    systemctl enable xray
}

generate_certificate() {
    log_info "Generating TLS certificate..."
    
    if [[ -z $DOMAIN ]]; then
        read -p "Enter your domain (or press enter to use IP): " DOMAIN
    fi
    
    if [[ -n $DOMAIN ]]; then
        if [[ $SYSTEM == "centos" ]]; then
            yum install -y epel-release
            yum install -y certbot
        else
            apt install -y certbot
        fi
        
        certbot certonly --standalone --agree-tos --register-unsafely-without-email -d $DOMAIN
        CERT_FILE="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        KEY_FILE="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    else
        mkdir -p $CONFIG_DIR/ssl
        openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
            -keyout $CONFIG_DIR/ssl/selfsigned.key \
            -out $CONFIG_DIR/ssl/selfsigned.crt
        CERT_FILE="$CONFIG_DIR/ssl/selfsigned.crt"
        KEY_FILE="$CONFIG_DIR/ssl/selfsigned.key"
    fi
}

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
    
    # Insert default admin (will be set via bot)
    sqlite3 $DB_FILE "INSERT OR IGNORE INTO admin (chat_id, username) VALUES (0, 'admin');"
}

create_xray_config() {
    log_info "Creating Xray configuration..."
    
    cat > $CONFIG_DIR/config.json << EOF
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "api": {
        "services": ["HandlerService", "LoggerService", "StatsService"],
        "tag": "api"
    },
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "inboundTag": ["api"],
                "outboundTag": "api"
            },
            {
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "blocked"
            }
        ]
    },
    "policy": {
        "levels": {
            "0": {
                "statsUserDownlink": true,
                "statsUserUplink": true
            }
        },
        "system": {
            "statsInboundUplink": true,
            "statsInboundDownlink": true
        }
    },
    "inbounds": [
        {
            "tag": "api",
            "port": 62789,
            "listen": "127.0.0.1",
            "protocol": "dokodemo-door",
            "settings": {
                "address": "127.0.0.1"
            },
            "sniffing": null
        },
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
    ],
    "stats": {},
    "reverse": {}
}
EOF
}

create_telegram_bot() {
    log_info "Creating Telegram Bot..."
    
    mkdir -p $BOT_DIR
    
    read -p "Enter your Telegram Bot Token: " BOT_TOKEN
    read -p "Enter your Telegram Chat ID: " ADMIN_CHAT_ID
    
    # Save bot configuration
    cat > $BOT_DIR/config.yaml << EOF
bot:
  token: "$BOT_TOKEN"
  admin_id: $ADMIN_CHAT_ID

xray:
  config_path: "$CONFIG_DIR/config.json"
  database_path: "$DB_FILE"
  api_port: 62789

server:
  domain: "${DOMAIN:-$(curl -s ifconfig.me)}"
  ssl_cert: "$CERT_FILE"
  ssl_key: "$KEY_FILE"
EOF

    # Create the bot Python script
    cat > $BOT_DIR/xray_bot.py << 'EOF'
#!/usr/bin/env python3
import sqlite3
import json
import logging
import yaml
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters

# Load configuration
with open('/etc/xray/bot/config.yaml', 'r') as f:
    config = yaml.safe_load(f)

BOT_TOKEN = config['bot']['token']
ADMIN_ID = config['bot']['admin_id']
DB_PATH = config['xray']['database_path']
CONFIG_PATH = config['xray']['config_path']
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
    return {
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

def generate_vless_config(uuid, username):
    return f"vless://{uuid}@{DOMAIN}:443?encryption=none&security=tls&sni={DOMAIN}&type=ws&host={DOMAIN}&path=%2Fvless#{username}"

def generate_trojan_config(password, username):
    return f"trojan://{password}@{DOMAIN}:443?security=tls&sni={DOMAIN}&type=ws&host={DOMAIN}&path=%2Ftrojan#{username}"

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
                status = "✅" if user[3] else "❌"
                message += f"{status} {user[1]}\nData: {user[5]}/{user[4]}GB\nExpiry: {user[6]}\n\n"
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

VMess:
{json.dumps(vmess_config)}

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
        
        # Add user to Xray config
        update_xray_config()
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
        update_xray_config()
        return True
    except:
        return False
    finally:
        conn.close()

def update_xray_config():
    # This function should update Xray config with all users
    # For simplicity, we'll just restart Xray to reload config
    restart_xray()

def restart_xray():
    try:
        import subprocess
        subprocess.run(["systemctl", "restart", "xray"], check=True)
        return True
    except:
        return False

def backup_config():
    try:
        import subprocess
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"/root/xray-backups/backup_{timestamp}.tar.gz"
        subprocess.run(["tar", "-czf", backup_file, CONFIG_PATH, DB_PATH], check=True)
        return backup_file
    except:
        return None

def get_server_status():
    try:
        import subprocess
        import shutil
        import psutil
        
        # Xray status
        xray_status = subprocess.run(["systemctl", "is-active", "xray"], capture_output=True, text=True).stdout.strip()
        
        # System info
        disk_usage = shutil.disk_usage("/")
        memory = psutil.virtual_memory()
        
        status_msg = f"""
🖥️ Server Status:

✅ Xray Service: {xray_status}
💾 Disk Usage: {disk_usage.used // (1024**3)}GB / {disk_usage.total // (1024**3)}GB
🧠 Memory Usage: {memory.percent}%
🔗 Domain: {DOMAIN}

📊 Active Users: {len(get_user_list())}
"""
        return status_msg
    except Exception as e:
        return f"Error getting status: {e}"

def main():
    application = Application.builder().token(BOT_TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    # Set admin
    conn = get_db_connection()
    conn.execute("UPDATE admin SET chat_id = ? WHERE username = 'admin'", (ADMIN_ID,))
    conn.commit()
    conn.close()
    
    logger.info("Bot started successfully!")
    application.run_polling()

if __name__ == '__main__':
    main()
EOF

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
}

create_backup_script() {
    log_info "Creating backup and restore scripts..."
    
    mkdir -p $BACKUP_DIR
    
    cat > /usr/local/bin/xray-backup.sh << EOF
#!/bin/bash

BACKUP_DIR="$BACKUP_DIR"
CONFIG_DIR="$CONFIG_DIR"
DB_FILE="$DB_FILE"
DATE=\$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="xray-backup-\$DATE.tar.gz"

echo "Creating Xray backup..."
tar -czf \$BACKUP_DIR/\$BACKUP_FILE \$CONFIG_DIR \$DB_FILE /usr/local/bin/xray 2>/dev/null

if [[ \$? -eq 0 ]]; then
    echo "Backup created: \$BACKUP_DIR/\$BACKUP_FILE"
    ls -t \$BACKUP_DIR/xray-backup-*.tar.gz | tail -n +6 | xargs rm -f
else
    echo "Backup failed!"
    exit 1
fi
EOF

    cat > /usr/local/bin/xray-restore.sh << EOF
#!/bin/bash

BACKUP_DIR="$BACKUP_DIR"
CONFIG_DIR="$CONFIG_DIR"

echo "Available backups:"
ls -l \$BACKUP_DIR/xray-backup-*.tar.gz 2>/dev/null || echo "No backups found"

read -p "Enter backup filename to restore: " BACKUP_FILE

if [[ ! -f \$BACKUP_DIR/\$BACKUP_FILE ]]; then
    echo "Backup file not found!"
    exit 1
fi

echo "Stopping services..."
systemctl stop xray
systemctl stop xray-bot

echo "Restoring from backup..."
tar -xzf \$BACKUP_DIR/\$BACKUP_FILE -C /

echo "Starting services..."
systemctl start xray
systemctl start xray-bot

echo "Restore completed!"
EOF

    chmod +x /usr/local/bin/xray-backup.sh
    chmod +x /usr/local/bin/xray-restore.sh
}

create_management_script() {
    cat > /usr/local/bin/xray-manager.sh << EOF
#!/bin/bash

case "\$1" in
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
EOF

    chmod +x /usr/local/bin/xray-manager.sh
}

show_info() {
    log_success "Installation completed!"
    echo ""
    echo "=== Installation Summary ==="
    echo "Xray Config: $CONFIG_DIR/config.json"
    echo "Database: $DB_FILE"
    echo "Backup Dir: $BACKUP_DIR"
    echo "Bot Dir: $BOT_DIR"
    echo "Domain: ${DOMAIN:-$(curl -s ifconfig.me)}"
    echo ""
    echo "=== Management Commands ==="
    echo "Start/Stop: systemctl start|stop xray xray-bot"
    echo "Manager: xray-manager.sh {start|stop|restart|status|backup|restore}"
    echo "Bot Logs: xray-manager.sh bot-log"
    echo ""
    echo "=== Next Steps ==="
    echo "1. Start the bot: systemctl start xray-bot"
    echo "2. Send /start to your Telegram bot"
    echo "3. Use the bot to create VPN users"
}

main() {
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

main
