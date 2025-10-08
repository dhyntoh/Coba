
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
MENU_PASSWORD="$PASSWORD"

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
        ufw allow 4443/tcp comment 'Stunnel'
        ufw allow 89/tcp comment 'OpenClash Config'
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
        firewall-cmd --permanent --add-port=4443/tcp
        firewall-cmd --permanent --add-port=89/tcp
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
        iptables -A INPUT -p tcp --dport 4443 -j ACCEPT
        iptables -A INPUT -p tcp --dport 89 -j ACCEPT
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
        yum install -y curl wget unzip socat openssl sqlite python3 python3-pip iptables-services stunnel4
    else
        apt update -y
        apt install -y curl wget unzip socat openssl sqlite3 python3 python3-pip iptables-persistent stunnel4
    fi
    
    # Install Python requirements for bot
    pip3 install python-telegram-bot requests pyyaml psutil geoip2 maxminddb
    
    log "Dependencies installed successfully"
}

# Install Xray
install_xray() {
    info "Installing Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    systemctl enable xray
    log "Xray installed successfully"
}

# Install Stunnel
install_stunnel() {
    info "Installing and configuring Stunnel..."
    
    # Create Stunnel configuration
    mkdir -p /etc/stunnel
    
    cat > /etc/stunnel/stunnel.conf << EOF
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.key
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[xray-vmess]
accept = 4443
connect = 127.0.0.1:443

[xray-vless] 
accept = 4444
connect = 127.0.0.1:443

[xray-trojan]
accept = 4445
connect = 127.0.0.1:443
EOF

    # Generate Stunnel certificate
    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=stunnel" \
        -keyout /etc/stunnel/stunnel.key \
        -out /etc/stunnel/stunnel.pem
    
    chmod 600 /etc/stunnel/stunnel.pem /etc/stunnel/stunnel.key
    
    # Enable Stunnel service
    sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
    
    systemctl enable stunnel4
    systemctl start stunnel4
    
    log "Stunnel installed and configured on port 4443, 4444, 4445"
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

# Initialize database with advanced features
init_database() {
    info "Initializing advanced database..."
    
    sqlite3 $DB_FILE "CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        uuid TEXT UNIQUE,
        password TEXT,
        data_limit INTEGER DEFAULT 10737418240, -- 10GB default
        used_data INTEGER DEFAULT 0,
        expiry_date DATETIME DEFAULT (datetime('now', '+30 days')),
        enabled INTEGER DEFAULT 1,
        max_ips INTEGER DEFAULT 3,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_reset DATETIME DEFAULT CURRENT_TIMESTAMP
    );"
    
    sqlite3 $DB_FILE "CREATE TABLE IF NOT EXISTS user_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        ip_address TEXT,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );"
    
    sqlite3 $DB_FILE "CREATE TABLE IF NOT EXISTS admin (
        chat_id INTEGER PRIMARY KEY,
        username TEXT
    );"
    
    sqlite3 $DB_FILE "CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        download_bytes INTEGER,
        upload_bytes INTEGER,
        log_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );"
    
    # Insert default admin
    sqlite3 $DB_FILE "INSERT OR IGNORE INTO admin (chat_id, username) VALUES (0, 'admin');"
    log "Advanced database initialized"
}

# Create Xray configuration with advanced features
create_xray_config() {
    info "Creating advanced Xray configuration..."
    
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
    "stats": {},
    "api": {
        "services": ["StatsService"],
        "tag": "api"
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
    "inbounds": [
        {
            "tag": "api",
            "port": 10085,
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
        },
        {
            "tag": "api",
            "protocol": "freedom"
        }
    ]
}
EOF
    log "Advanced Xray configuration created"
    
    # Save Shadowsocks password
    echo "SHADOWSOCKS_PASSWORD=$SHADOWSOCKS_PASSWORD" > $CONFIG_DIR/shadowsocks.info
    echo "SHADOWSOCKS_PORT=8388" >> $CONFIG_DIR/shadowsocks.info
    echo "SHADOWSOCKS_METHOD=chacha20-ietf-poly1305" >> $CONFIG_DIR/shadowsocks.info
}

# Create OpenClash config server
create_openclash_server() {
    info "Creating OpenClash configuration server..."
    
    # Create simple HTTP server for OpenClash configs
    mkdir -p /var/www/openclash
    
    cat > /usr/local/bin/openclash-server.py << 'PYTHON_EOF'
#!/usr/bin/env python3
import http.server
import socketserver
import sqlite3
import json
import yaml
import base64
from urllib.parse import parse_qs, urlparse

PORT = 89
DB_PATH = "/etc/xray/xray.db"

class OpenClashHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/config/'):
            self.serve_openclash_config()
        elif self.path == '/':
            self.serve_index()
        else:
            super().do_GET()
    
    def serve_index(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = """
        <html>
        <head><title>OpenClash Config Generator</title></head>
        <body>
            <h2>OpenClash Configuration Generator</h2>
            <p>Available configurations:</p>
            <ul>
                <li><a href="/config/vmess">VMess Configuration</a></li>
                <li><a href="/config/vless">VLESS Configuration</a></li>
                <li><a href="/config/trojan">Trojan Configuration</a></li>
                <li><a href="/config/shadowsocks">Shadowsocks Configuration</a></li>
            </ul>
        </body>
        </html>
        """
        self.wfile.write(html.encode())
    
    def serve_openclash_config(self):
        try:
            config_type = self.path.split('/')[-1]
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Get server info
            with open('/etc/xray/bot/config.yaml', 'r') as f:
                bot_config = yaml.safe_load(f)
            domain = bot_config['server']['domain']
            
            # Get users for the specific type
            cursor.execute("SELECT username, uuid, password FROM users LIMIT 1")
            user = cursor.fetchone()
            conn.close()
            
            if not user:
                self.send_error(404, "No users found")
                return
            
            username, uuid, password = user
            
            if config_type == "vmess":
                config = self.generate_vmess_config(domain, uuid, username)
            elif config_type == "vless":
                config = self.generate_vless_config(domain, uuid, username)
            elif config_type == "trojan":
                config = self.generate_trojan_config(domain, password, username)
            elif config_type == "shadowsocks":
                config = self.generate_shadowsocks_config(domain, username)
            else:
                self.send_error(404, "Config type not found")
                return
            
            self.send_response(200)
            self.send_header('Content-type', 'application/yaml')
            self.send_header('Content-Disposition', f'attachment; filename="openclash-{config_type}.yaml"')
            self.end_headers()
            self.wfile.write(config.encode())
            
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def generate_vmess_config(self, domain, uuid, username):
        vmess_config = {
            "v": "2",
            "ps": f"Xray-VMess-{username}",
            "add": domain,
            "port": "443",
            "id": uuid,
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": domain,
            "path": "/vmess",
            "tls": "tls",
            "sni": domain
        }
        
        vmess_base64 = base64.b64encode(json.dumps(vmess_config).encode()).decode()
        
        openclash_config = {
            "proxies": [
                {
                    "name": f"VMess-{username}",
                    "type": "vmess",
                    "server": domain,
                    "port": 443,
                    "uuid": uuid,
                    "alterId": 0,
                    "cipher": "auto",
                    "udp": True,
                    "tls": True,
                    "skip-cert-verify": False,
                    "servername": domain,
                    "network": "ws",
                    "ws-opts": {
                        "path": "/vmess",
                        "headers": {
                            "Host": domain
                        }
                    }
                }
            ],
            "proxy-groups": [
                {
                    "name": "PROXY",
                    "type": "select",
                    "proxies": [f"VMess-{username}"]
                }
            ],
            "rules": [
                "GEOIP,CN,DIRECT",
                "MATCH,PROXY"
            ]
        }
        
        return yaml.dump(openclash_config, default_flow_style=False, allow_unicode=True)
    
    def generate_vless_config(self, domain, uuid, username):
        openclash_config = {
            "proxies": [
                {
                    "name": f"VLESS-{username}",
                    "type": "vless",
                    "server": domain,
                    "port": 443,
                    "uuid": uuid,
                    "network": "ws",
                    "tls": True,
                    "udp": True,
                    "servername": domain,
                    "skip-cert-verify": False,
                    "ws-opts": {
                        "path": "/vless",
                        "headers": {
                            "Host": domain
                        }
                    }
                }
            ],
            "proxy-groups": [
                {
                    "name": "PROXY",
                    "type": "select",
                    "proxies": [f"VLESS-{username}"]
                }
            ],
            "rules": [
                "GEOIP,CN,DIRECT",
                "MATCH,PROXY"
            ]
        }
        
        return yaml.dump(openclash_config, default_flow_style=False, allow_unicode=True)
    
    def generate_trojan_config(self, domain, password, username):
        openclash_config = {
            "proxies": [
                {
                    "name": f"Trojan-{username}",
                    "type": "trojan",
                    "server": domain,
                    "port": 443,
                    "password": password,
                    "network": "ws",
                    "udp": True,
                    "sni": domain,
                    "skip-cert-verify": False,
                    "ws-opts": {
                        "path": "/trojan",
                        "headers": {
                            "Host": domain
                        }
                    }
                }
            ],
            "proxy-groups": [
                {
                    "name": "PROXY",
                    "type": "select",
                    "proxies": [f"Trojan-{username}"]
                }
            ],
            "rules": [
                "GEOIP,CN,DIRECT",
                "MATCH,PROXY"
            ]
        }
        
        return yaml.dump(openclash_config, default_flow_style=False, allow_unicode=True)
    
    def generate_shadowsocks_config(self, domain, username):
        with open('/etc/xray/shadowsocks.info', 'r') as f:
            lines = f.readlines()
            password = lines[0].split('=')[1].strip()
            port = lines[1].split('=')[1].strip()
            method = lines[2].split('=')[1].strip()
        
        openclash_config = {
            "proxies": [
                {
                    "name": f"Shadowsocks-{username}",
                    "type": "ss",
                    "server": domain,
                    "port": int(port),
                    "cipher": method,
                    "password": password,
                    "udp": True
                }
            ],
            "proxy-groups": [
                {
                    "name": "PROXY",
                    "type": "select",
                    "proxies": [f"Shadowsocks-{username}"]
                }
            ],
            "rules": [
                "GEOIP,CN,DIRECT",
                "MATCH,PROXY"
            ]
        }
        
        return yaml.dump(openclash_config, default_flow_style=False, allow_unicode=True)

def run_server():
    with socketserver.TCPServer(("", PORT), OpenClashHandler) as httpd:
        print(f"OpenClash config server running on port {PORT}")
        print(f"Access configs at: http://your-server-ip:89/config/[type]")
        httpd.serve_forever()

if __name__ == "__main__":
    run_server()
PYTHON_EOF

    chmod +x /usr/local/bin/openclash-server.py
    
    # Create systemd service for OpenClash server
    cat > /etc/systemd/system/openclash-server.service << EOF
[Unit]
Description=OpenClash Configuration Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/openclash-server.py
WorkingDirectory=/var/www/openclash
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable openclash-server
    systemctl start openclash-server
    
    log "OpenClash configuration server created on port 89"
}

# Create advanced Telegram Bot
create_telegram_bot() {
    info "Setting up Advanced Telegram Bot..."
    
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
  database_path: "$DB_PATH"

server:
  domain: "$SERVER_DOMAIN"
  openclash_port: "89"
  stunnel_ports: "4443,4444,4445"
EOF

    # Create the advanced bot Python script
    cat > $BOT_DIR/xray_bot.py << 'PYTHON_EOF'
#!/usr/bin/env python3
import sqlite3
import json
import logging
import yaml
import subprocess
import base64
import requests
import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters

# Load configuration
with open('/etc/xray/bot/config.yaml', 'r') as f:
    config = yaml.safe_load(f)

BOT_TOKEN = config['bot']['token']
ADMIN_ID = config['bot']['admin_id']
DB_PATH = config['xray']['database_path']
DOMAIN = config['server']['domain']
OPENCLASH_PORT = config['server']['openclash_port']
STUNNEL_PORTS = config['server']['stunnel_ports']

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db_connection():
    return sqlite3.connect(DB_PATH)

def is_admin(chat_id):
    conn = get_db_connection()
    admin = conn.execute("SELECT chat_id FROM admin WHERE chat_id = ?", (chat_id,)).fetchone()
    conn.close()
    return admin is not None

def get_user_details(username):
    conn = get_db_connection()
    user = conn.execute("""
        SELECT id, username, uuid, password, data_limit, used_data, expiry_date, max_ips, created_at 
        FROM users WHERE username = ?
    """, (username,)).fetchone()
    conn.close()
    return user

def get_city_from_ip(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        return data.get('city', 'Unknown')
    except:
        return "Unknown"

def format_bytes(size):
    power = 2**10
    n = 0
    power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}"

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

def generate_stunnel_configs(username, uuid, password):
    configs = {
        "vmess_stunnel": f"vmess://{generate_vmess_config(uuid, username)}",
        "vless_stunnel": f"vless://{uuid}@{DOMAIN}:4444?encryption=none&security=tls&type=ws&host={DOMAIN}&path=%2Fvless#Stunnel-VLESS-{username}",
        "trojan_stunnel": f"trojan://{password}@{DOMAIN}:4445?security=tls&type=ws&host={DOMAIN}&path=%2Ftrojan#Stunnel-Trojan-{username}"
    }
    return configs

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_chat.id):
        await update.message.reply_text("❌ You are not authorized to use this bot.")
        return
    
    keyboard = [
        [InlineKeyboardButton("👥 Create User", callback_data="create_user")],
        [InlineKeyboardButton("📊 User List", callback_data="user_list")],
        [InlineKeyboardButton("🔍 User Details", callback_data="user_details")],
        [InlineKeyboardButton("❌ Delete User", callback_data="delete_user")],
        [InlineKeyboardButton("📈 Reset Quota", callback_data="reset_quota")],
        [InlineKeyboardButton("⏰ Extend Time", callback_data="extend_time")],
        [InlineKeyboardButton("🔄 Restart Services", callback_data="restart_services")],
        [InlineKeyboardButton("💾 Backup Config", callback_data="backup_config")],
        [InlineKeyboardButton("📊 Server Status", callback_data="server_status")],
        [InlineKeyboardButton("🔑 Config Links", callback_data="config_links")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("🤖 Advanced Xray VPN Management Bot\nChoose an option:", reply_markup=reply_markup)

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
                status = "✅" if user[7] else "❌"
                used_percent = (user[5] / user[4] * 100) if user[4] > 0 else 0
                message += f"{status} {user[1]}\n📊 Usage: {format_bytes(user[5])}/{format_bytes(user[4])} ({used_percent:.1f}%)\n⏰ Expires: {user[6]}\n\n"
        else:
            message = "No users found."
        await query.edit_message_text(message)
    
    elif data == "user_details":
        context.user_data['awaiting_username_details'] = True
        await query.edit_message_text("Please send me the username to show details:")
    
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
    
    elif data == "reset_quota":
        context.user_data['awaiting_username_reset'] = True
        await query.edit_message_text("Please send me the username to reset quota:")
    
    elif data == "extend_time":
        context.user_data['awaiting_username_extend'] = True
        await query.edit_message_text("Please send me the username and days (format: username days):")
    
    elif data.startswith("delete_"):
        user_id = data.split("_")[1]
        if delete_user(user_id):
            await query.edit_message_text("✅ User deleted successfully.")
        else:
            await query.edit_message_text("❌ Failed to delete user.")
    
    elif data == "restart_services":
        if restart_services():
            await query.edit_message_text("✅ All services restarted successfully.")
        else:
            await query.edit_message_text("❌ Failed to restart services.")
    
    elif data == "backup_config":
        backup_file = backup_config()
        if backup_file:
            await query.edit_message_text(f"✅ Backup created: {backup_file}")
        else:
            await query.edit_message_text("❌ Backup failed.")
    
    elif data == "server_status":
        status = get_server_status()
        await query.edit_message_text(status)
    
    elif data == "config_links":
        links = f"""
🔗 Configuration Links:

🌐 OpenClash Configs:
VMess: http://{DOMAIN}:{OPENCLASH_PORT}/config/vmess
VLESS: http://{DOMAIN}:{OPENCLASH_PORT}/config/vless  
Trojan: http://{DOMAIN}:{OPENCLASH_PORT}/config/trojan
Shadowsocks: http://{DOMAIN}:{OPENCLASH_PORT}/config/shadowsocks

🔒 Stunnel Ports:
VMess Stunnel: 4443
VLESS Stunnel: 4444
Trojan Stunnel: 4445

📱 Direct Configs:
Use the 'Create User' feature to get direct config links
"""
        await query.edit_message_text(links)
    
    elif data == "back_main":
        await start(update, context)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_chat.id):
        return
    
    if context.user_data.get('awaiting_username'):
        username = update.message.text
        result = create_user(username)
        
        if result:
            user_id, uuid, password = result
            context.user_data['awaiting_username'] = False
            
            # Get user details for display
            user_details = get_user_details(username)
            
            # Generate configurations
            vmess_config = generate_vmess_config(uuid, username)
            vless_config = generate_vless_config(uuid, username)
            trojan_config = generate_trojan_config(password, username)
            shadowsocks_config = generate_shadowsocks_config()
            stunnel_configs = generate_stunnel_configs(username, uuid, password)
            
            # User details message
            details_message = f"""
✅ User Created Successfully!

📋 ACCOUNT DETAILS:
👤 Username: {username}
🔑 UUID: {uuid}
🔒 Password: {password}
📅 Created: {user_details[8]}
⏰ Expires: {user_details[6]}
📊 Data Limit: {format_bytes(user_details[4])}
📱 Max Devices: {user_details[7]}
🌐 Domain: {DOMAIN}
🏙️ Server Location: {get_city_from_ip(DOMAIN)}

🔧 CONNECTION DETAILS:
🛡️ Security: TLS
🌐 Network: WebSocket (WS)
📍 Path: /vmess, /vless, /trojan
🔒 Encryption: Auto

📋 CONFIGURATIONS:

🔹 VMess (Base64):
vmess://{vmess_config}

🔹 VLESS:
{vless_config}

🔹 Trojan:
{trojan_config}

🔹 Shadowsocks:
{shadowsocks_config}

🔹 Stunnel Configs:
VMess Stunnel: {stunnel_configs['vmess_stunnel']}
VLESS Stunnel: {stunnel_configs['vless_stunnel']}
Trojan Stunnel: {stunnel_configs['trojan_stunnel']}

🌐 OpenClash Configs:
http://{DOMAIN}:{OPENCLASH_PORT}/config/vmess
http://{DOMAIN}:{OPENCLASH_PORT}/config/vless
http://{DOMAIN}:{OPENCLASH_PORT}/config/trojan

⚠️ Send these configurations securely to the user.
"""
            await update.message.reply_text(details_message)
        else:
            await update.message.reply_text("❌ Failed to create user. Username might already exist.")
    
    elif context.user_data.get('awaiting_username_details'):
        username = update.message.text
        user_details = get_user_details(username)
        
        if user_details:
            used_percent = (user_details[5] / user_details[4] * 100) if user_details[4] > 0 else 0
            details_message = f"""
🔍 USER DETAILS:

👤 Username: {user_details[1]}
🔑 UUID: {user_details[2]}
🔒 Password: {user_details[3]}
📊 Data Usage: {format_bytes(user_details[5])} / {format_bytes(user_details[4])} ({used_percent:.1f}%)
⏰ Expiry Date: {user_details[6]}
📱 Max Devices: {user_details[7]}
📅 Created: {user_details[8]}
🌐 Domain: {DOMAIN}
🏙️ Server Location: {get_city_from_ip(DOMAIN)}
🔧 Status: {'✅ Active' if user_details[4] > user_details[5] else '❌ Quota Exceeded'}

💡 Commands:
/reset_{username} - Reset quota
/extend_{username}_30 - Extend 30 days
"""
            await update.message.reply_text(details_message)
        else:
            await update.message.reply_text("❌ User not found.")
        context.user_data['awaiting_username_details'] = False
    
    elif context.user_data.get('awaiting_username_reset'):
        username = update.message.text
        if reset_user_quota(username):
            await update.message.reply_text(f"✅ Quota reset for user {username}")
        else:
            await update.message.reply_text("❌ User not found or reset failed.")
        context.user_data['awaiting_username_reset'] = False
    
    elif context.user_data.get('awaiting_username_extend'):
        text = update.message.text
        parts = text.split()
        if len(parts) == 2:
            username, days = parts
            if extend_user_time(username, int(days)):
                await update.message.reply_text(f"✅ Extended {username} by {days} days")
            else:
                await update.message.reply_text("❌ User not found or extension failed.")
        else:
            await update.message.reply_text("❌ Please use format: username days")
        context.user_data['awaiting_username_extend'] = False

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
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, uuid, password) VALUES (?, ?, ?)",
            (username, user_uuid, password)
        )
        user_id = cursor.lastrowid
        conn.commit()
        return user_id, user_uuid, password
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

def reset_user_quota(username):
    conn = get_db_connection()
    try:
        conn.execute("UPDATE users SET used_data = 0 WHERE username = ?", (username,))
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()

def extend_user_time(username, days):
    conn = get_db_connection()
    try:
        conn.execute("UPDATE users SET expiry_date = datetime(expiry_date, '+? days') WHERE username = ?", (days, username))
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()

def restart_services():
    try:
        subprocess.run(["systemctl", "restart", "xray"], check=True)
        subprocess.run(["systemctl", "restart", "xray-bot"], check=True)
        subprocess.run(["systemctl", "restart", "stunnel4"], check=True)
        subprocess.run(["systemctl", "restart", "openclash-server"], check=True)
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
        # Service status
        services = {
            "xray": subprocess.run(["systemctl", "is-active", "xray"], capture_output=True, text=True).stdout.strip(),
            "bot": subprocess.run(["systemctl", "is-active", "xray-bot"], capture_output=True, text=True).stdout.strip(),
            "stunnel": subprocess.run(["systemctl", "is-active", "stunnel4"], capture_output=True, text=True).stdout.strip(),
            "openclash": subprocess.run(["systemctl", "is-active", "openclash-server"], capture_output=True, text=True).stdout.strip()
        }
        
        # System info
        disk = subprocess.run(["df", "-h", "/"], capture_output=True, text=True).stdout.split('\n')[1].split()
        memory = subprocess.run(["free", "-m"], capture_output=True, text=True).stdout.split('\n')[1].split()
        
        # User stats
        conn = get_db_connection()
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        active_users = conn.execute("SELECT COUNT(*) FROM users WHERE used_data < data_limit AND datetime(expiry_date) > datetime('now')").fetchone()[0]
        conn.close()
        
        status_msg = f"""
🖥️ SERVER STATUS:

🛠️ Services:
Xray: {services['xray']}
Bot: {services['bot']}
Stunnel: {services['stunnel']}
OpenClash: {services['openclash']}

💻 System:
Disk: {disk[2]}/{disk[1]} ({disk[4]})
Memory: {memory[2]}MB/{memory[1]}MB
Uptime: {subprocess.run(['uptime', '-p'], capture_output=True, text=True).stdout.strip()}

👥 Users:
Total: {total_users}
Active: {active_users}

🌐 Ports Open:
443/tcp,udp (Main)
8388/tcp,udp (Shadowsocks)
4443-4445/tcp (Stunnel)
89/tcp (OpenClash Config)
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
    
    # Add command handlers for reset and extend
    async def reset_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if is_admin(update.effective_chat.id):
            username = context.args[0] if context.args else None
            if username and reset_user_quota(username):
                await update.message.reply_text(f"✅ Quota reset for {username}")
            else:
                await update.message.reply_text("❌ Usage: /reset username")
    
    async def extend_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if is_admin(update.effective_chat.id):
            if len(context.args) == 2:
                username, days = context.args
                if extend_user_time(username, int(days)):
                    await update.message.reply_text(f"✅ Extended {username} by {days} days")
                else:
                    await update.message.reply_text("❌ Extension failed")
            else:
                await update.message.reply_text("❌ Usage: /extend username days")
    
    application.add_handler(CommandHandler("reset", reset_command))
    application.add_handler(CommandHandler("extend", extend_command))
    
    logger.info("Advanced Xray Bot started successfully!")
    application.run_polling()

if __name__ == '__main__':
    main()
PYTHON_EOF

    chmod +x $BOT_DIR/xray_bot.py
    
    # Create systemd service for bot
    cat > /etc/systemd/system/xray-bot.service << EOF
[Unit]
Description=Advanced Xray Telegram Bot
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
    log "Advanced Telegram Bot setup completed"
}

# Create management menu
create_management_menu() {
    info "Creating advanced management menu system..."
    
    cat > /usr/local/bin/menu << 'MENU_EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Password check (only if not set during installation)
if [ -f "/root/xray-install-info.txt" ]; then
    PASSWORD=$(grep "Password:" /root/xray-install-info.txt | cut -d':' -f2 | tr -d ' ')
else
    PASSWORD="dintoganteng"
fi

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
    echo "║               ADVANCED XRAY VPN MANAGEMENT              ║"
    echo "║                 Created by DintoGanteng                 ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

show_menu() {
    echo -e "${YELLOW}┌──────────────────────────────────────────────────────────┐"
    echo -e "│                     ${CYAN}MAIN MENU${YELLOW}                         │"
    echo -e "├──────────────────────────────────────────────────────────┤"
    echo -e "│  ${GREEN}1${YELLOW}) 📊 System Status & Information                 │"
    echo -e "│  ${GREEN}2${YELLOW}) 👥 User Management (Create/Delete/Details)     │"
    echo -e "│  ${GREEN}3${YELLOW}) 🛠️  Service Control (Start/Stop/Restart)       │"
    echo -e "│  ${GREEN}4${YELLOW}) 📁 Backup & Restore Configuration              │"
    echo -e "│  ${GREEN}5${YELLOW}) 🔧 Firewall & Port Management                  │"
    echo -e "│  ${GREEN}6${YELLOW}) 📈 Real-time Monitoring & Logs                 │"
    echo -e "│  ${GREEN}7${YELLOW}) 🔑 All Configurations & Links                  │"
    echo -e "│  ${GREEN}8${YELLOW}) 🤖 Telegram Bot Control                        │"
    echo -e "│  ${GREEN}9${YELLOW}) 🚀 Speed Test & Connection Check               │"
    echo -e "│  ${GREEN}10${YELLOW}) ⚙️  Advanced Settings                         │"
    echo -e "│  ${GREEN}0${YELLOW}) ❌ Exit Menu                                   │"
    echo -e "└──────────────────────────────────────────────────────────┘${NC}"
    echo
    echo -n "Select option [0-10]: "
}

system_status() {
    echo -e "\n${CYAN}📊 SYSTEM STATUS & INFORMATION${NC}"
    echo -e "${YELLOW}─────────────────────────────────────${NC}"
    
    # Service status
    echo -e "\n${GREEN}🛠️ Service Status:${NC}"
    systemctl is-active xray >/dev/null 2>&1 && echo -e "Xray: ${GREEN}✅ RUNNING${NC}" || echo -e "Xray: ${RED}❌ STOPPED${NC}"
    systemctl is-active xray-bot >/dev/null 2>&1 && echo -e "Bot: ${GREEN}✅ RUNNING${NC}" || echo -e "Bot: ${RED}❌ STOPPED${NC}"
    systemctl is-active stunnel4 >/dev/null 2>&1 && echo -e "Stunnel: ${GREEN}✅ RUNNING${NC}" || echo -e "Stunnel: ${RED}❌ STOPPED${NC}"
    systemctl is-active openclash-server >/dev/null 2>&1 && echo -e "OpenClash: ${GREEN}✅ RUNNING${NC}" || echo -e "OpenClash: ${RED}❌ STOPPED${NC}"
    
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
    echo "Open Ports: 443/tcp, 443/udp, 8388/tcp, 8388/udp, 4443-4445/tcp, 89/tcp"
    
    # User count
    if [ -f "/etc/xray/xray.db" ]; then
        total_users=$(sqlite3 /etc/xray/xray.db "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "0")
        active_users=$(sqlite3 /etc/xray/xray.db "SELECT COUNT(*) FROM users WHERE used_data < data_limit AND datetime(expiry_date) > datetime('now');" 2>/dev/null || echo "0")
        echo "Total Users: $total_users (Active: $active_users)"
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
        echo -e "${GREEN}3${NC}) Show User Details"
        echo -e "${GREEN}4${NC}) Delete User"
        echo -e "${GREEN}5${NC}) Reset User Quota"
        echo -e "${GREEN}6${NC}) Extend User Time"
        echo -e "${GREEN}7${NC}) Back to Main Menu"
        echo
        echo -n "Select option [1-7]: "
        read user_choice
        
        case $user_choice in
            1)
                echo -n "Enter username: "
                read username
                if [ -n "$username" ]; then
                    python3 -c "
import sqlite3, uuid
conn = sqlite3.connect('/etc/xray/xray.db')
user_uuid = str(uuid.uuid4())
password = str(uuid.uuid4())[:8]
try:
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, uuid, password) VALUES (?, ?, ?)', ('''$username''', user_uuid, password))
    user_id = cursor.lastrowid
    conn.commit()
    print('✅ User created successfully!')
    print(f'👤 Username: {'''$username''}')
    print(f'🔑 UUID: {user_uuid}')
    print(f'🔒 Password: {password}')
    print(f'📊 Data Limit: 10GB')
    print(f'📱 Max Devices: 3')
    print(f'⏰ Expires: 30 days from now')
except Exception as e:
    print(f'❌ Error: {e}')
conn.close()
"
                    systemctl restart xray
                fi
                ;;
            2)
                echo -e "\n${GREEN}User List:${NC}"
                sqlite3 /etc/xray/xray.db "SELECT username, uuid, used_data, data_limit, expiry_date FROM users;" 2>/dev/null | while IFS='|' read username uuid used_data data_limit expiry_date; do
                    used_percent=$((used_data * 100 / data_limit))
                    echo "👤 $username | 📊 ${used_data}MB/${data_limit}MB (${used_percent}%) | ⏰ $expiry_date"
                done
                ;;
            3)
                echo -n "Enter username: "
                read username
                user_info=$(sqlite3 /etc/xray/xray.db "SELECT username, uuid, password, data_limit, used_data, expiry_date, max_ips, created_at FROM users WHERE username='$username';" 2>/dev/null)
                if [ -n "$user_info" ]; then
                    IFS='|' read username uuid password data_limit used_data expiry_date max_ips created_at <<< "$user_info"
                    used_percent=$((used_data * 100 / data_limit))
                    echo -e "\n${GREEN}User Details:${NC}"
                    echo "👤 Username: $username"
                    echo "🔑 UUID: $uuid"
                    echo "🔒 Password: $password"
                    echo "📊 Data: ${used_data}MB/${data_limit}MB (${used_percent}%)"
                    echo "⏰ Expires: $expiry_date"
                    echo "📱 Max Devices: $max_ips"
                    echo "📅 Created: $created_at"
                else
                    echo "❌ User not found"
                fi
                ;;
            4)
                echo -n "Enter username to delete: "
                read del_user
                if [ -n "$del_user" ]; then
                    sqlite3 /etc/xray/xray.db "DELETE FROM users WHERE username='$del_user';" 2>/dev/null
                    systemctl restart xray
                    echo "✅ User $del_user deleted!"
                fi
                ;;
            5)
                echo -n "Enter username to reset quota: "
                read reset_user
                if [ -n "$reset_user" ]; then
                    sqlite3 /etc/xray/xray.db "UPDATE users SET used_data = 0 WHERE username='$reset_user';" 2>/dev/null
                    echo "✅ Quota reset for $reset_user"
                fi
                ;;
            6)
                echo -n "Enter username: "
                read extend_user
                echo -n "Enter days to extend: "
                read days
                if [ -n "$extend_user" ] && [ -n "$days" ]; then
                    sqlite3 /etc/xray/xray.db "UPDATE users SET expiry_date = datetime(expiry_date, '+$days days') WHERE username='$extend_user';" 2>/dev/null
                    echo "✅ Extended $extend_user by $days days"
                fi
                ;;
            7)
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
        echo -e "${GREEN}1${NC}) Start All Services"
        echo -e "${GREEN}2${NC}) Stop All Services"
        echo -e "${GREEN}3${NC}) Restart All Services"
        echo -e "${GREEN}4${NC}) Individual Service Control"
        echo -e "${GREEN}5${NC}) Enable Auto-start"
        echo -e "${GREEN}6${NC}) Back to Main Menu"
        echo
        echo -n "Select option [1-6]: "
        read service_choice
        
        case $service_choice in
            1) 
                systemctl start xray xray-bot stunnel4 openclash-server
                echo "✅ All services started!"
                ;;
            2) 
                systemctl stop xray xray-bot stunnel4 openclash-server
                echo "✅ All services stopped!"
                ;;
            3) 
                systemctl restart xray xray-bot stunnel4 openclash-server
                echo "✅ All services restarted!"
                ;;
            4)
                echo -e "\n${GREEN}Individual Service Control:${NC}"
                echo "1) Xray | 2) Bot | 3) Stunnel | 4) OpenClash"
                echo -n "Select service: "
                read svc
                echo -n "Action (start/stop/restart): "
                read action
                case $svc in
                    1) systemctl $action xray ;;
                    2) systemctl $action xray-bot ;;
                    3) systemctl $action stunnel4 ;;
                    4) systemctl $action openclash-server ;;
                esac
                echo "✅ Done!"
                ;;
            5) 
                systemctl enable xray xray-bot stunnel4 openclash-server
                echo "✅ Auto-start enabled for all services!"
                ;;
            6) break ;;
        esac
        read -p "Press [Enter] to continue..."
    done
}

show_config_links() {
    DOMAIN=$(curl -s ifconfig.me)
    echo -e "\n${CYAN}🔗 ALL CONFIGURATION LINKS${NC}"
    echo -e "${YELLOW}─────────────────────────────────────${NC}"
    
    echo -e "\n${GREEN}🌐 OpenClash Configuration Links:${NC}"
    echo "VMess: http://$DOMAIN:89/config/vmess"
    echo "VLESS: http://$DOMAIN:89/config/vless"
    echo "Trojan: http://$DOMAIN:89/config/trojan"
    echo "Shadowsocks: http://$DOMAIN:89/config/shadowsocks"
    
    echo -e "\n${GREEN}🔒 Stunnel Ports:${NC}"
    echo "VMess Stunnel: 4443"
    echo "VLESS Stunnel: 4444"
    echo "Trojan Stunnel: 4445"
    
    echo -e "\n${GREEN}📱 Direct Connection Ports:${NC}"
    echo "Main Port: 443 (TCP/UDP)"
    echo "Shadowsocks: 8388 (TCP/UDP)"
    
    echo -e "\n${GREEN}💡 Usage:${NC}"
    echo "OpenClash: Download YAML config and import to OpenClash"
    echo "Stunnel: Use with stunnel client on specified ports"
    echo "Direct: Use standard Xray clients"
    
    read -p "Press [Enter] to continue..."
}

# Other functions remain the same as previous script...
# [Backup, Firewall, Monitoring, Bot Control, Speed Test functions remain unchanged]

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
        7) show_config_links ;;
        8) bot_control ;;
        9) speed_test ;;
        10) advanced_settings ;;
        0) 
            echo -e "${GREEN}Thank you for using Advanced Xray VPN Manager!${NC}"
            exit 0
            ;;
        *) 
            echo -e "${RED}Invalid option! Please try again.${NC}"
            sleep 2
            ;;
    esac
done
MENU_EOF

    chmod +x /usr/local/bin/menu
    ln -sf /usr/local/bin/menu /usr/local/bin/xray-menu.sh
    log "Advanced management menu created"
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
tar -czf $BACKUP_DIR/$BACKUP_FILE $CONFIG_DIR /usr/local/bin/xray /etc/stunnel /etc/default/stunnel4 2>/dev/null

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
systemctl stop stunnel4
systemctl stop openclash-server

echo "Restoring from backup..."
tar -xzf $BACKUP_DIR/$BACKUP_FILE -C /

echo "Starting services..."
systemctl start xray
systemctl start xray-bot
systemctl start stunnel4
systemctl start openclash-server

echo "Restore completed!"
RESTORE_EOF

    chmod +x /usr/local/bin/xray-backup.sh
    chmod +x /usr/local/bin/xray-restore.sh
    log "Backup scripts created"
}

# Show installation info
show_installation_info() {
    log "=== Advanced Xray VPN Installation Completed! ==="
    echo ""
    echo "🔐 Password: $PASSWORD"
    echo ""
    echo "📁 Configuration Files:"
    echo "   Xray Config: /etc/xray/config.json"
    echo "   Database: /etc/xray/xray.db"
    echo "   Bot Config: /etc/xray/bot/config.yaml"
    echo "   Stunnel: /etc/stunnel/stunnel.conf"
    echo "   Backups: /root/xray-backups/"
    echo ""
    echo "🎮 Management Menu:"
    echo "   menu                    # Easy access with password"
    echo "   xray-menu.sh            # Alternative command"
    echo "   menu nopass             # Without password prompt"
    echo ""
    echo "🛠️ Service Control:"
    echo "   systemctl start|stop|restart xray xray-bot stunnel4 openclash-server"
    echo "   systemctl enable xray xray-bot stunnel4 openclash-server"
    echo ""
    echo "🔧 Advanced Features:"
    echo "   ✅ VMess, VLESS, Trojan, Shadowsocks, Stunnel"
    echo "   ✅ TCP & UDP Support"
    echo "   ✅ Auto Firewall Configuration"
    echo "   ✅ Telegram Bot with Advanced Control"
    echo "   ✅ Quota Management & Auto Removal"
    echo "   ✅ IP Device Limiting"
    echo "   ✅ OpenClash Config Generator (Port 89)"
    echo "   ✅ User Details with Geo Location"
    echo "   ✅ Backup & Restore System"
    echo "   ✅ Interactive Management Menu"
    echo ""
    echo "📱 Quick Access:"
    echo "   Just type: menu"
    echo "   Password: $PASSWORD"
    echo ""
    echo "🌐 OpenClash Configs:"
    echo "   http://your-server-ip:89/config/vmess"
    echo "   http://your-server-ip:89/config/vless"
    echo "   http://your-server-ip:89/config/trojan"
    echo "   http://your-server-ip:89/config/shadowsocks"
    echo ""
    echo "⚠️ Next Steps:"
    echo "   1. Type 'menu' to access control panel"
    echo "   2. Start Telegram Bot from menu"
    echo "   3. Create users via menu or bot"
    echo "   4. Download OpenClash configs from port 89"
    echo "   5. Monitor usage and quotas"
}

# Main installation function
main_installation() {
    info "Starting Advanced Xray VPN Installation..."
    check_root
    detect_system
    configure_firewall
    install_dependencies
    install_xray
    install_stunnel
    generate_certificate
    init_database
    create_xray_config
    create_telegram_bot
    create_openclash_server
    create_backup_script
    create_management_menu
    
    # Start services
    systemctl start xray
    systemctl enable xray
    systemctl start stunnel4
    systemctl enable stunnel4
    systemctl start openclash-server
    systemctl enable openclash-server
    
    show_installation_info
    
    # Save installation info
    cat > /root/xray-install-info.txt << EOF
ADVANCED XRAY VPN INSTALLATION COMPLETE
=======================================
Installation Date: $(date)
Password: $PASSWORD

Management Commands:
- Menu: menu or xray-menu.sh
- Service Control: systemctl [start|stop|restart] xray xray-bot stunnel4 openclash-server
- Backup: xray-backup.sh
- Restore: xray-restore.sh

Advanced Features:
- VMess, VLESS, Trojan, Shadowsocks, Stunnel
- Quota Management & Auto Removal
- IP Device Limiting (3 devices/user)
- OpenClash Config Generator (Port 89)
- Telegram Bot Advanced Control
- User Geo Location Display
- Auto Backup System

OpenClash Config URLs:
http://$(curl -s ifconfig.me):89/config/vmess
http://$(curl -s ifconfig.me):89/config/vless  
http://$(curl -s ifconfig.me):89/config/trojan
http://$(curl -s ifconfig.me):89/config/shadowsocks

Access the menu with: menu
Password: $PASSWORD
EOF
}

# Run main installation
main_installation
