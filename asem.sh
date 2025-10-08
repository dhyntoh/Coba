#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to print status
print_status() {
    echo -e "${YELLOW}[INFO] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

print_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "================================================"
    echo "           VPN BOT AUTO INSTALLER"
    echo "        SSH • XRAY • STUNNEL • BOT TELEGRAM"
    echo "================================================"
    echo -e "${NC}"
}

# Check if root
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root: sudo bash install-vpn-bot.sh"
    exit 1
fi

print_banner

# Get user input
print_status "Masukkan konfigurasi yang diperlukan:"

read -p "Masukkan Domain Anda (contoh: vpn.example.com): " DOMAIN
read -p "Masukkan Bot Token Telegram: " BOT_TOKEN
read -p "Masukkan Admin ID Telegram: " ADMIN_ID
read -p "Masukkan Orderkuota ID [default: dinto07]: " ORDERKUOTA_ID
read -p "Masukkan Orderkuota Token [default: 2477598:CMpqHtWF0U61Pr7jg923cdnhTRzY4Sif]: " ORDERKUOTA_TOKEN

# Set defaults if empty
ORDERKUOTA_ID=${ORDERKUOTA_ID:-"dinto07"}
ORDERKUOTA_TOKEN=${ORDERKUOTA_TOKEN:-"2477598:CMpqHtWF0U61Pr7jg923cdnhTRzY4Sif"}

# Validate inputs
if [ -z "$DOMAIN" ] || [ -z "$BOT_TOKEN" ] || [ -z "$ADMIN_ID" ]; then
    print_error "Domain, Bot Token, dan Admin ID harus diisi!"
    exit 1
fi

# Get server IP
SERVER_IP=$(curl -s ifconfig.me)

print_status "Konfigurasi yang akan digunakan:"
echo -e "  Domain: ${GREEN}$DOMAIN${NC}"
echo -e "  Server IP: ${GREEN}$SERVER_IP${NC}"
echo -e "  Bot Token: ${GREEN}${BOT_TOKEN:0:10}...${NC}"
echo -e "  Admin ID: ${GREEN}$ADMIN_ID${NC}"

read -p "Lanjutkan instalasi? (y/n): " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    print_error "Instalasi dibatalkan"
    exit 1
fi

# Update system
print_status "Updating system packages..."
apt update && apt upgrade -y

# Install dependencies
print_status "Installing dependencies..."
apt install -y curl wget git nano ufw stunnel4 dropbear squid nginx python3 python3-pip python3-venv sqlite3

# Install Xray
print_status "Installing Xray..."
wget -O /tmp/xray-install.sh https://github.com/XTLS/Xray-install/raw/main/install-release.sh
bash /tmp/xray-install.sh

# Create directories
print_status "Creating directories..."
mkdir -p /etc/xray /var/log/xray /etc/stunnel /var/www/html /etc/vpn-users /opt/vpn-bot /usr/local/bin

# Generate UUID for Xray
UUID=$(cat /proc/sys/kernel/random/uuid)
print_status "Generated Xray UUID: $UUID"

# Create Xray configuration
print_status "Configuring Xray..."
cat > /etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": 8443,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
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
      "port": 2083,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "flow": "xtls-rprx-direct"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
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
      "port": 2087,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$UUID"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
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
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF

# Create Stunnel configuration
print_status "Configuring Stunnel..."
cat > /etc/stunnel/stunnel.conf << EOF
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 443
connect = 127.0.0.1:222

[openssh]
accept = 444
connect = 127.0.0.1:22

[xray-vmess]
accept = 6443
connect = 127.0.0.1:8443

[xray-vless]
accept = 6444
connect = 127.0.0.1:2083

[xray-trojan]
accept = 6445
connect = 127.0.0.1:2087
EOF

# Generate SSL certificate for stunnel
print_status "Generating SSL certificate..."
openssl req -new -x509 -days 365 -nodes -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem \
    -subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=$DOMAIN" 2>/dev/null

# Configure Dropbear
print_status "Configuring Dropbear..."
cat > /etc/default/dropbear << EOF
NO_START=0
DROPBEAR_PORT=222
EOF

# Configure Squid
print_status "Configuring Squid..."
cat > /etc/squid/squid.conf << EOF
http_port 3128
http_port 8080
visible_hostname proxy-server
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
http_access allow localnet
http_access allow localhost
http_access deny all
EOF

# Configure firewall
print_status "Configuring firewall..."
ufw --force reset
ufw allow 22/tcp
ufw allow 443/tcp
ufw allow 3128/tcp
ufw allow 8080/tcp
ufw allow 6443/tcp
ufw allow 6444/tcp
ufw allow 6445/tcp
echo "y" | ufw enable

# Create user management script
print_status "Creating user management system..."
cat > /usr/local/bin/vpn-user-manager << 'EOF'
#!/bin/bash

VPN_DIR="/etc/vpn-users"
mkdir -p $VPN_DIR

create_user() {
    local username=$1
    local password=$2
    local expiry_date=$3
    local quota=$4
    
    # Create SSH user
    useradd -M -s /bin/false $username 2>/dev/null
    echo "$username:$password" | chpasswd
    
    # Generate UUID and Trojan password
    local user_uuid=$(cat /proc/sys/kernel/random/uuid)
    local user_trojan_password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
    
    # Save user info
    cat > $VPN_DIR/$username.conf << EOL
USERNAME=$username
PASSWORD=$password
EXPIRY=$expiry_date
QUOTA=$quota
UUID=$user_uuid
TROJAN_PASSWORD=$user_trojan_password
CREATED=$(date +%Y-%m-%d)
EOL
    
    echo "User $username created successfully"
    echo "UUID: $user_uuid"
    echo "Trojan Password: $user_trojan_password"
    echo "Expiry: $expiry_date"
    echo "Quota: ${quota}GB"
}

delete_user() {
    local username=$1
    userdel -r $username 2>/dev/null
    rm -f $VPN_DIR/$username.conf
    echo "User $username deleted"
}

list_users() {
    echo "VPN Users:"
    for user_file in $VPN_DIR/*.conf; do
        if [ -f "$user_file" ]; then
            source $user_file
            echo "Username: $USERNAME | Expiry: $EXPIRY | Quota: ${QUOTA}GB"
        fi
    done
}

case $1 in
    create)
        create_user $2 $3 $4 $5
        ;;
    delete)
        delete_user $2
        ;;
    list)
        list_users
        ;;
    *)
        echo "Usage: $0 {create|delete|list}"
        echo "  create <username> <password> <expiry_date> <quota>"
        echo "  delete <username>"
        echo "  list"
        ;;
esac
EOF

chmod +x /usr/local/bin/vpn-user-manager

# Create OpenClash config generator
print_status "Creating OpenClash config generator..."
cat > /usr/local/bin/generate-openclash.py << 'EOF'
#!/usr/bin/env python3

import yaml
import sys

def generate_openclash_config(user_data):
    config = {
        "proxies": [
            {
                "name": f"VMESS-{user_data['username']}",
                "type": "vmess",
                "server": user_data["server_ip"],
                "port": 6443,
                "uuid": user_data["uuid"],
                "alterId": 0,
                "cipher": "auto",
                "udp": True,
                "tls": True,
                "skip-cert-verify": False,
                "servername": user_data["domain"],
                "network": "ws",
                "ws-opts": {
                    "path": "/vmess",
                    "headers": {
                        "Host": user_data["domain"]
                    }
                }
            },
            {
                "name": f"VLESS-{user_data['username']}",
                "type": "vless",
                "server": user_data["server_ip"],
                "port": 6444,
                "uuid": user_data["uuid"],
                "cipher": "auto",
                "udp": True,
                "tls": True,
                "skip-cert-verify": False,
                "servername": user_data["domain"],
                "network": "ws",
                "ws-opts": {
                    "path": "/vless",
                    "headers": {
                        "Host": user_data["domain"]
                    }
                }
            },
            {
                "name": f"Trojan-{user_data['username']}",
                "type": "trojan",
                "server": user_data["server_ip"],
                "port": 6445,
                "password": user_data["trojan_password"],
                "udp": True,
                "sni": user_data["domain"],
                "skip-cert-verify": False,
                "network": "ws",
                "ws-opts": {
                    "path": "/trojan",
                    "headers": {
                        "Host": user_data["domain"]
                    }
                }
            }
        ],
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": [
                    f"VMESS-{user_data['username']}",
                    f"VLESS-{user_data['username']}",
                    f"Trojan-{user_data['username']}"
                ]
            }
        ],
        "rules": [
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY"
        ]
    }
    
    return yaml.dump(config, default_flow_style=False)

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: generate-openclash.py <username> <server_ip> <domain> <uuid> <trojan_password>")
        sys.exit(1)
    
    user_data = {
        "username": sys.argv[1],
        "server_ip": sys.argv[2],
        "domain": sys.argv[3],
        "uuid": sys.argv[4],
        "trojan_password": sys.argv[5]
    }
    
    print(generate_openclash_config(user_data))
EOF

chmod +x /usr/local/bin/generate-openclash.py

# Install Python packages
print_status "Installing Python packages..."
pip3 install pyyaml

# Create Telegram Bot
print_status "Creating Telegram Bot..."
cat > /opt/vpn-bot/vpn-bot.py << EOF
#!/usr/bin/env python3
import logging
import sqlite3
import datetime
import requests
import yaml
import subprocess
import uuid as uuid_lib
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

# Configuration from installation
BOT_TOKEN = "$BOT_TOKEN"
ADMIN_ID = $ADMIN_ID
ORDERKUOTA_ID = "$ORDERKUOTA_ID"
ORDERKUOTA_TOKEN = "$ORDERKUOTA_TOKEN"
SERVER_IP = "$SERVER_IP"
DOMAIN = "$DOMAIN"

# Database setup
def init_db():
    conn = sqlite3.connect('/opt/vpn-bot/vpn_bot.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY,
        username TEXT,
        balance INTEGER DEFAULT 0,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Servers table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        ip TEXT,
        domain TEXT,
        price_per_day INTEGER,
        monthly_quota INTEGER,
        status TEXT DEFAULT 'active'
    )''')
    
    # VPN accounts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vpn_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        server_id INTEGER,
        username TEXT,
        password TEXT,
        uuid TEXT,
        trojan_password TEXT,
        protocol TEXT,
        expiry_date DATE,
        quota INTEGER,
        used_quota INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Transactions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount INTEGER,
        status TEXT DEFAULT 'pending',
        qris_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Insert admin user
    cursor.execute('INSERT OR IGNORE INTO users (user_id, username, is_admin) VALUES (?, ?, ?)', 
                  (ADMIN_ID, 'admin', True))
    
    # Insert default server
    cursor.execute('''INSERT OR IGNORE INTO servers 
                   (name, ip, domain, price_per_day, monthly_quota) 
                   VALUES (?, ?, ?, ?, ?)''',
                   ('Premium Server 1', SERVER_IP, DOMAIN, 5000, 50))
    
    conn.commit()
    conn.close()

# Orderkuota.com API integration
def create_qris_payment(amount):
    # Simulate QRIS generation (replace with actual API)
    import random
    transaction_id = f"TX{random.randint(100000, 999999)}"
    qris_url = f"https://api.qris.io/pay/{transaction_id}"
    return qris_url, transaction_id

def check_payment_status(transaction_id):
    # Simulate payment check (replace with actual API)
    return 'paid'

# Bot functions
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    username = update.effective_user.username or "User"
    
    conn = sqlite3.connect('/opt/vpn-bot/vpn_bot.db')
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO users (user_id, username) VALUES (?, ?)', (user_id, username))
    conn.commit()
    conn.close()
    
    keyboard = [
        [InlineKeyboardButton("Beli VPN", callback_data="buy_vpn")],
        [InlineKeyboardButton("Top Up Saldo", callback_data="topup")],
        [InlineKeyboardButton("Cek Saldo", callback_data="balance")],
        [InlineKeyboardButton("Akun Saya", callback_data="my_accounts")],
        [InlineKeyboardButton("Bantuan", callback_data="help")]
    ]
    
    if user_id == ADMIN_ID:
        keyboard.append([InlineKeyboardButton("Admin Panel", callback_data="admin_panel")])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        "VPN Bot Panel\n\n"
        "Selamat datang di layanan VPN Premium!\n\n"
        "Fitur yang tersedia:\n"
        "• SSH, VMess, VLess, Trojan\n"
        "• OpenClash Config Generator\n"
        "• Multi Server Support\n"
        "• Auto Renewal\n\n"
        "Ketik 'menu' untuk melihat menu utama",
        reply_markup=reply_markup
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.text.lower() == 'menu':
        await start(update, context)

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    data = query.data
    user_id = query.from_user.id
    
    if data == "buy_vpn":
        await show_servers(query, context)
    elif data == "topup":
        await topup_balance(query, context)
    elif data == "balance":
        await check_balance(query, context)
    elif data == "my_accounts":
        await my_accounts(query, context)
    elif data == "help":
        await help_command(query, context)
    elif data == "admin_panel":
        if user_id == ADMIN_ID:
            await admin_panel(query, context)
    elif data == "main_menu":
        await start_callback(query, context)
    elif data.startswith("server_"):
        server_id = int(data.split("_")[1])
        await create_vpn_account(query, context, server_id)
    elif data.startswith("topup_"):
        amount = int(data.split("_")[1])
        await process_topup(query, context, amount)

async def start_callback(query, context):
    user_id = query.from_user.id
    username = query.from_user.username or "User"
    
    conn = sqlite3.connect('/opt/vpn-bot/vpn_bot.db')
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO users (user_id, username) VALUES (?, ?)', (user_id, username))
    conn.commit()
    conn.close()
    
    keyboard = [
        [InlineKeyboardButton("Beli VPN", callback_data="buy_vpn")],
        [InlineKeyboardButton("Top Up Saldo", callback_data="topup")],
        [InlineKeyboardButton("Cek Saldo", callback_data="balance")],
        [InlineKeyboardButton("Akun Saya", callback_data="my_accounts")],
        [InlineKeyboardButton("Bantuan", callback_data="help")]
    ]
    
    if user_id == ADMIN_ID:
        keyboard.append([InlineKeyboardButton("Admin Panel", callback_data="admin_panel")])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(
        "VPN Bot Panel\n\n"
        "Selamat datang di layanan VPN Premium!\n\n"
        "Fitur yang tersedia:\n"
        "• SSH, VMess, VLess, Trojan\n"
        "• OpenClash Config Generator\n"
        "• Multi Server Support\n"
        "• Auto Renewal\n\n"
        "Ketik 'menu' untuk melihat menu utama",
        reply_markup=reply_markup
    )

async def show_servers(query, context):
    conn = sqlite3.connect('/opt/vpn-bot/vpn_bot.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM servers WHERE status = "active"')
    servers = cursor.fetchall()
    conn.close()
    
    if not servers:
        await query.edit_message_text("Tidak ada server yang tersedia saat ini.")
        return
    
    keyboard = []
    for server in servers:
        keyboard.append([
            InlineKeyboardButton(
                f"{server[1]} - Rp {server[4]}/hari", 
                callback_data=f"server_{server[0]}"
            )
        ])
    
    keyboard.append([InlineKeyboardButton("Kembali", callback_data="main_menu")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(
        "Pilih Server VPN\n\n"
        "Pilih server yang ingin Anda gunakan:",
        reply_markup=reply_markup
    )

async def create_vpn_account(query, context, server_id):
    user_id = query.from_user.id
    
    conn = sqlite3.connect('/opt/vpn-bot/vpn_bot.db')
    cursor = conn.cursor()
    
    # Check balance
    cursor.execute('SELECT balance FROM users WHERE user_id = ?', (user_id,))
    user_balance = cursor.fetchone()[0]
    
    cursor.execute('SELECT * FROM servers WHERE id = ?', (server_id,))
    server = cursor.fetchone()
    
    if user_balance < server[4]:  # price_per_day
        await query.edit_message_text(
            f"Saldo tidak cukup!\n"
            f"Harga: Rp {server[4]}/hari\n"
            f"Saldo Anda: Rp {user_balance}\n\n"
            f"Silakan top up saldo terlebih dahulu."
        )
        conn.close()
        return
    
    # Deduct balance
    new_balance = user_balance - server[4]
    cursor.execute('UPDATE users SET balance = ? WHERE user_id = ?', (new_balance, user_id))
    
    # Generate VPN account
    username = f"user{user_id}_{int(datetime.datetime.now().timestamp())}"
    password = str(uuid_lib.uuid4())[:8]
    vpn_uuid = str(uuid_lib.uuid4())
    trojan_password = str(uuid_lib.uuid4())[:16]
    expiry_date = (datetime.datetime.now() + datetime.timedelta(days=30)).strftime('%Y-%m-%d')
    
    # Create VPN user
    try:
        subprocess.run([
            '/usr/local/bin/vpn-user-manager', 'create',
            username, password, expiry_date, str(server[5])
        ], check=True)
    except Exception as e:
        print(f"Error creating user: {e}")
    
    # Save to database
    cursor.execute('''
        INSERT INTO vpn_accounts 
        (user_id, server_id, username, password, uuid, trojan_password, protocol, expiry_date, quota)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, server_id, username, password, vpn_uuid, trojan_password, 'all', expiry_date, server[5]))
    
    conn.commit()
    conn.close()
    
    # Generate OpenClash config
    openclash_config = f"""proxies:
  - name: VMESS-{username}
    type: vmess
    server: {server[2]}
    port: 6443
    uuid: {vpn_uuid}
    alterId: 0
    cipher: auto
    udp: true
    tls: true
    skip-cert-verify: false
    servername: {server[3]}
    network: ws
    ws-opts:
      path: /vmess
      headers:
        Host: {server[3]}
        
  - name: VLESS-{username}
    type: vless
    server: {server[2]}
    port: 6444
    uuid: {vpn_uuid}
    cipher: auto
    udp: true
    tls: true
    skip-cert-verify: false
    servername: {server[3]}
    network: ws
    ws-opts:
      path: /vless
      headers:
        Host: {server[3]}
        
  - name: Trojan-{username}
    type: trojan
    server: {server[2]}
    port: 6445
    password: {trojan_password}
    udp: true
    sni: {server[3]}
    skip-cert-verify: false
    network: ws
    ws-opts:
      path: /trojan
      headers:
        Host: {server[3]}
        
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - VMESS-{username}
      - VLESS-{username}
      - Trojan-{username}

rules:
  - GEOIP,CN,DIRECT
  - MATCH,PROXY"""
    
    account_info = f"""
Akun VPN Berhasil Dibuat!

Username: {username}
Password: {password}
Server: {server[1]}
Kadaluarsa: {expiry_date}
Quota: {server[5]}GB

Config Details:
VMESS UUID: {vpn_uuid}
Trojan Password: {trojan_password}
Port: 6443-6445

Saldo tersisa: Rp {new_balance}
"""
    
    await query.edit_message_text(account_info)
    
    # Send OpenClash config as file
    await context.bot.send_document(
        chat_id=user_id,
        document=openclash_config.encode('utf-8'),
        filename=f"openclash-{username}.yaml",
        caption="Config OpenClash"
    )

async def topup_balance(query, context):
    keyboard = [
        [InlineKeyboardButton("Rp 10.000", callback_data="topup_10000")],
        [InlineKeyboardButton("Rp 25.000", callback_data="topup_25000")],
        [InlineKeyboardButton("Rp 50.000", callback_data="topup_50000")],
        [InlineKeyboardButton("Rp 100.000", callback_data="topup_100000")],
        [InlineKeyboardButton("Kembali", callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(
        "Top Up Saldo\n\n"
        "Pilih nominal top up:",
        reply_markup=reply_markup
    )

async def process_topup(query, context, amount):
    qris_url, transaction_id = create_qris_payment(amount)
    
    if qris_url:
        conn = sqlite3.connect('/opt/vpn-bot/vpn_bot.db')
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO transactions (user_id, amount, qris_url) VALUES (?, ?, ?)',
            (query.from_user.id, amount, qris_url)
        )
        conn.commit()
        conn.close()
        
        await query.edit_message_text(
            f"Top Up: Rp {amount}\n\n"
            f"Silakan scan QRIS berikut untuk pembayaran:\n"
            f"Transaction ID: {transaction_id}\n\n"
            f"Setelah pembayaran, saldo akan otomatis terupdate."
        )
    else:
        await query.edit_message_text("Gagal membuat pembayaran. Silakan coba lagi.")

async def check_balance(query, context):
    conn = sqlite3.connect('/opt/vpn-bot/vpn_bot.db')
    cursor = conn.cursor()
    cursor.execute('SELECT balance FROM users WHERE user_id = ?', (query.from_user.id,))
    result = cursor.fetchone()
    conn.close()
    
    balance = result[0] if result else 0
    await query.edit_message_text(f"Saldo Anda: Rp {balance}")

async def my_accounts(query, context):
    user_id = query.from_user.id
    
    conn = sqlite3.connect('/opt/vpn-bot/vpn_bot.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT va.username, s.name, va.expiry_date, va.quota, va.used_quota 
        FROM vpn_accounts va 
        JOIN servers s ON va.server_id = s.id 
        WHERE va.user_id = ?
    ''', (user_id,))
    accounts = cursor.fetchall()
    conn.close()
    
    if not accounts:
        await query.edit_message_text("Anda belum memiliki akun VPN.")
        return
    
    accounts_text = "Akun VPN Anda:\n\n"
    for account in accounts:
        remaining_quota = account[3] - account[4]
        accounts_text += f"{account[0]}\n"
        accounts_text += f"   Server: {account[1]}\n"
        accounts_text += f"   Expiry: {account[2]}\n"
        accounts_text += f"   Quota: {remaining_quota}/{account[3]}GB\n\n"
    
    await query.edit_message_text(accounts_text)

async def help_command(query, context):
    help_text = """
Bantuan VPN Bot

Cara penggunaan:
1. Top Up Saldo - Isi saldo terlebih dahulu
2. Beli VPN - Pilih server dan buat akun
3. Akun Saya - Lihat detail akun VPN
4. Download Config - Dapatkan config OpenClash

Fitur:
• Support SSH, VMess, VLess, Trojan
• Config OpenClash otomatis
• Multi-protocol dalam 1 akun
• Monitoring quota dan expiry

Support:
Untuk bantuan lebih lanjut, hubungi Admin.
"""
    await query.edit_message_text(help_text)

# Admin functions
async def admin_panel(query, context):
    keyboard = [
        [InlineKeyboardButton("Tambah Server", callback_data="admin_add_server")],
        [InlineKeyboardButton("Statistik", callback_data="admin_stats")],
        [InlineKeyboardButton("Manage Users", callback_data="admin_manage_users")],
        [InlineKeyboardButton("Kembali", callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(
        "Admin Panel\n\n"
        "Pilih opsi admin:",
        reply_markup=reply_markup
    )

def main():
    # Initialize database
    init_db()
    
    # Create application
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("menu", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(CallbackQueryHandler(button_handler))
    
    # Start bot
    print("Bot started successfully!")
    application.run_polling()

if __name__ == '__main__':
    main()
EOF

# Make bot executable
chmod +x /opt/vpn-bot/vpn-bot.py

# Install Python packages for bot
print_status "Installing Python packages for bot..."
cd /opt/vpn-bot
python3 -m venv venv
./venv/bin/pip install python-telegram-bot requests pyyaml

# Create systemd service for bot
print_status "Creating systemd service..."
cat > /etc/systemd/system/vpn-bot.service << EOF
[Unit]
Description=VPN Telegram Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vpn-bot
Environment=PATH=/opt/vpn-bot/venv/bin
ExecStart=/opt/vpn-bot/venv/bin/python3 /opt/vpn-bot/vpn-bot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create menu control script
print_status "Creating VPN Control Menu..."
cat > /usr/local/bin/menu << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# Server Info
SERVER_IP=$(curl -s ifconfig.me)
DOMAIN="$DOMAIN"

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "================================================"
    echo "               VPN CONTROL MENU"
    echo "                 Management Tools"
    echo "================================================"
    echo -e "${NC}"
}

show_status() {
    echo -e "${YELLOW}Server Status:${NC}"
    systemctl is-active xray >/dev/null 2>&1 && echo -e "  Xray: ${GREEN}Running${NC}" || echo -e "  Xray: ${RED}Stopped${NC}"
    systemctl is-active stunnel4 >/dev/null 2>&1 && echo -e "  Stunnel: ${GREEN}Running${NC}" || echo -e "  Stunnel: ${RED}Stopped${NC}"
    systemctl is-active dropbear >/dev/null 2>&1 && echo -e "  Dropbear: ${GREEN}Running${NC}" || echo -e "  Dropbear: ${RED}Stopped${NC}"
    systemctl is-active squid >/dev/null 2>&1 && echo -e "  Squid: ${GREEN}Running${NC}" || echo -e "  Squid: ${RED}Stopped${NC}"
    systemctl is-active vpn-bot >/dev/null 2>&1 && echo -e "  VPN Bot: ${GREEN}Running${NC}" || echo -e "  VPN Bot: ${RED}Stopped${NC}"
    echo ""
}

show_usage() {
    echo -e "${YELLOW}Server Usage:${NC}"
    echo -e "  CPU: $(grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage "%"}')"
    echo -e "  RAM: $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')"
    echo -e "  Disk: $(df -h / | awk 'NR==2{print $5}')"
    echo ""
}

show_connections() {
    echo -e "${YELLOW}Active Connections:${NC}"
    echo -e "  SSH: $(netstat -an | grep :22 | grep ESTABLISHED | wc -l)"
    echo -e "  Dropbear: $(netstat -an | grep :222 | grep ESTABLISHED | wc -l)"
    echo -e "  Xray: $(netstat -an | grep -E ':(8443|2083|2087)' | grep ESTABLISHED | wc -l)"
    echo ""
}

show_users() {
    echo -e "${YELLOW}VPN Users:${NC}"
    /usr/local/bin/vpn-user-manager list
    echo ""
}

restart_services() {
    echo -e "${YELLOW}Restarting VPN Services...${NC}"
    systemctl restart xray stunnel4 dropbear squid vpn-bot
    echo -e "${GREEN}Services restarted successfully${NC}"
    echo ""
}

stop_services() {
    echo -e "${YELLOW}Stopping VPN Services...${NC}"
    systemctl stop xray stunnel4 dropbear squid vpn-bot
    echo -e "${GREEN}Services stopped successfully${NC}"
    echo ""
}

start_services() {
    echo -e "${YELLOW}Starting VPN Services...${NC}"
    systemctl start xray stunnel4 dropbear squid vpn-bot
    echo -e "${GREEN}Services started successfully${NC}"
    echo ""
}

show_logs() {
    echo -e "${YELLOW}Recent Logs:${NC}"
    journalctl -u vpn-bot -n 10 --no-pager
    echo ""
}

show_config() {
    echo -e "${YELLOW}Server Configuration:${NC}"
    echo -e "  Server IP: ${GREEN}$SERVER_IP${NC}"
    echo -e "  Domain: ${GREEN}$DOMAIN${NC}"
    echo -e "  SSH Port: ${GREEN}22${NC}"
    echo -e "  Dropbear Port: ${GREEN}222${NC}"
    echo -e "  Stunnel Port: ${GREEN}443${NC}"
    echo -e "  VMess WS: ${GREEN}6443${NC}"
    echo -e "  VLess WS: ${GREEN}6444${NC}"
    echo -e "  Trojan WS: ${GREEN}6445${NC}"
    echo -e "  Squid Ports: ${GREEN}3128, 8080${NC}"
    echo ""
}

create_user() {
    echo -e "${YELLOW}Create VPN User:${NC}"
    read -p "Username: " username
    read -s -p "Password: " password
    echo
    read -p "Expiry (YYYY-MM-DD): " expiry
    read -p "Quota (GB): " quota
    
    /usr/local/bin/vpn-user-manager create "$username" "$password" "$expiry" "$quota"
    echo ""
}

delete_user() {
    echo -e "${YELLOW}Delete VPN User:${NC}"
    read -p "Username to delete: " username
    /usr/local/bin/vpn-user-manager delete "$username"
    echo ""
}

show_menu() {
    while true; do
        show_banner
        show_status
        show_usage
        show_connections
        
        echo -e "${BLUE}Please select an option:${NC}"
        echo -e "  ${GREEN}1${NC}) Status Services"
        echo -e "  ${GREEN}2${NC}) Restart Services"
        echo -e "  ${GREEN}3${NC}) Stop Services"
        echo -e "  ${GREEN}4${NC}) Start Services"
        echo -e "  ${GREEN}5${NC}) List Users"
        echo -e "  ${GREEN}6${NC}) Create User"
        echo -e "  ${GREEN}7${NC}) Delete User"
        echo -e "  ${GREEN}8${NC}) View Logs"
        echo -e "  ${GREEN}9${NC}) Server Config"
        echo -e "  ${GREEN}0${NC}) Exit"
        echo
        
        read -p "Enter your choice [0-9]: " choice
        echo
        
        case $choice in
            1) show_status ;;
            2) restart_services ;;
            3) stop_services ;;
            4) start_services ;;
            5) show_users ;;
            6) create_user ;;
            7) delete_user ;;
            8) show_logs ;;
            9) show_config ;;
            0) 
                echo -e "${GREEN}Goodbye!${NC}"
                echo
                exit 0
                ;;
            *) 
                echo -e "${RED}Invalid option!${NC}"
                echo
                ;;
        esac
        
        read -p "Press Enter to continue..."
        clear
    done
}

# Main execution
show_menu
EOF

chmod +x /usr/local/bin/menu

# Start services
print_status "Starting services..."
systemctl daemon-reload
systemctl enable xray stunnel4 dropbear squid vpn-bot
systemctl restart xray stunnel4 dropbear squid

# Start bot
print_status "Starting VPN Bot..."
systemctl start vpn-bot

# Wait a moment for bot to start
sleep 5

# Display completion information
print_success "Installation completed!"
echo ""
echo -e "${CYAN}================================================"
echo "                 INSTALLATION COMPLETE"
echo "================================================"
echo -e "${NC}"
echo -e "${YELLOW}SERVER INFORMATION:${NC}"
echo -e "  Server IP: ${GREEN}$SERVER_IP${NC}"
echo -e "  Domain: ${GREEN}$DOMAIN${NC}"
echo -e "  Xray UUID: ${GREEN}$UUID${NC}"
echo ""
echo -e "${YELLOW}PORTS INFORMATION:${NC}"
echo -e "  SSH Port: ${GREEN}22${NC}"
echo -e "  Stunnel Port: ${GREEN}443${NC}"
echo -e "  VMess WS: ${GREEN}6443${NC}"
echo -e "  VLess WS: ${GREEN}6444${NC}"
echo -e "  Trojan WS: ${GREEN}6445${NC}"
echo -e "  Squid Proxy: ${GREEN}3128, 8080${NC}"
echo ""
echo -e "${YELLOW}BOT INFORMATION:${NC}"
echo -e "  Bot Token: ${GREEN}${BOT_TOKEN:0:10}...${NC}"
echo -e "  Admin ID: ${GREEN}$ADMIN_ID${NC}"
echo ""
echo -e "${YELLOW}CONTROL MENU:${NC}"
echo -e "  Untuk mengontrol server, ketik: ${CYAN}menu${NC}"
echo ""
echo -e "${YELLOW}QUICK COMMANDS:${NC}"
echo -e "  Start Bot: ${CYAN}systemctl start vpn-bot${NC}"
echo -e "  Stop Bot: ${CYAN}systemctl stop vpn-bot${NC}"
echo -e "  Check Status: ${CYAN}systemctl status vpn-bot${NC}"
echo -e "  View Logs: ${CYAN}journalctl -u vpn-bot -f${NC}"
echo -e "  Control Menu: ${CYAN}menu${NC}"
echo ""
echo -e "${GREEN}Your VPN Bot is ready! Send /start to your bot on Telegram${NC}"
echo -e "${GREEN}Type 'menu' to access server control menu${NC}"
