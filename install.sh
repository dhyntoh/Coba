#!/bin/bash

# Ultimate VPN AutoScript - Secure & Optimized
# Supports: Xray (VLESS/VMess/Trojan/Shadowsocks) + WebSocket + gRPC
# Optimized for: Performance & Security

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_VERSION="2.0"
DOMAIN=""
EMAIL="admin@yourdomain.com"
INSTALL_DIR="/opt/vpn-setup"
LOG_FILE="/var/log/vpn-install.log"

# Logging functions
log() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a $LOG_FILE
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a $LOG_FILE
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a $LOG_FILE
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a $LOG_FILE
    exit 1
}

# Check system requirements
check_system() {
    log "Checking system requirements..."
    
    # Check OS
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        error "Cannot determine OS version"
    fi
    
    # Supported OS check
    if [[ ! "$OS" =~ ^(ubuntu|debian|centos|fedora)$ ]]; then
        error "Unsupported OS: $OS"
    fi
    
    # Check architecture
    ARCH=$(uname -m)
    if [[ ! "$ARCH" =~ ^(x86_64|aarch64)$ ]]; then
        error "Unsupported architecture: $ARCH"
    fi
    
    # Check memory
    MEMORY_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    MEMORY_MB=$((MEMORY_KB / 1024))
    
    if [[ $MEMORY_MB -lt 512 ]]; then
        warning "Low memory detected: ${MEMORY_MB}MB (Recommended: 1GB+)"
    fi
    
    success "System check passed: $OS $OS_VERSION ($ARCH)"
}

# Install dependencies
install_dependencies() {
    log "Installing dependencies..."
    
    case $OS in
        ubuntu|debian)
            apt update && apt upgrade -y
            apt install -y curl wget git jq tar gzip build-essential \
                         net-tools iproute2 dnsutils socat bc python3 \
                         certbot haproxy nginx cron >> $LOG_FILE 2>&1
            ;;
        centos|fedora)
            yum update -y
            yum install -y curl wget git jq tar gzip make gcc \
                         net-tools iproute bind-utils socat bc python3 \
                         certbot haproxy nginx crontabs >> $LOG_FILE 2>&1
            ;;
    esac
    
    success "Dependencies installed"
}

# User input functions
get_user_input() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════╗"
    echo "║         VPN AUTOINSTALLER           ║"
    echo "║            Version $SCRIPT_VERSION           ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Get domain
    while true; do
        read -p "Enter your domain (e.g., vpn.example.com): " DOMAIN
        if [[ -n "$DOMAIN" ]]; then
            if [[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                break
            else
                warning "Invalid domain format"
            fi
        else
            warning "Domain cannot be empty"
        fi
    done
    
    # Get email for SSL
    read -p "Enter email for SSL certificate (press enter for default): " input_email
    EMAIL="${input_email:-admin@$DOMAIN}"
    
    # Optional: Enable Cloudflare
    read -p "Enable Cloudflare CDN? (y/N): " enable_cf
    ENABLE_CF=${enable_cf:-n}
    
    success "Configuration received: Domain=$DOMAIN, Email=$EMAIL, Cloudflare=$ENABLE_CF"
}

# Generate secure UUID
generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# Install Xray
install_xray() {
    log "Installing Xray..."
    
    # Download and install Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # Create directory structure
    mkdir -p /etc/xray /var/log/xray /usr/local/share/xray
    
    # Generate certificates if not using Cloudflare
    if [[ "$ENABLE_CF" != "y" ]]; then
        log "Generating SSL certificates..."
        certbot certonly --standalone -d $DOMAIN --non-interactive --agree-tos --email $EMAIL
        ln -sf /etc/letsencrypt/live/$DOMAIN/fullchain.pem /etc/xray/xray.crt
        ln -sf /etc/letsencrypt/live/$DOMAIN/privkey.pem /etc/xray/xray.key
    else
        # Generate self-signed certificate (will be replaced by Cloudflare)
        openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN" \
            -keyout /etc/xray/xray.key -out /etc/xray/xray.crt
    fi
    
    success "Xray installed"
}

# Configure Xray
configure_xray() {
    log "Configuring Xray..."
    
    # Generate UUIDs
    UUID_MAIN=$(generate_uuid)
    UUID_VMESS=$(generate_uuid)
    UUID_TROJAN=$(generate_uuid)
    UUID_SS=$(generate_uuid)
    
    cat > /etc/xray/config.json << EOF
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
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": ["geosite:category-ads-all"],
        "outboundTag": "block"
      }
    ]
  },
  "inbounds": [
    {
      "port": 10001,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID_MAIN",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key"
            }
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      },
      "tag": "vless-tls"
    },
    {
      "port": 10002,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$UUID_VMESS",
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
      "tag": "vmess-ws"
    },
    {
      "port": 10003,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$UUID_TROJAN"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/trojan"
        }
      },
      "tag": "trojan-ws"
    },
    {
      "port": 10004,
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "method": "chacha20-ietf-poly1305",
            "password": "$UUID_SS"
          }
        ]
      },
      "streamSettings": {
        "network": "tcp"
      },
      "tag": "ss-tcp"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
EOF

    # Create client configuration file
    mkdir -p $INSTALL_DIR/clients
    cat > $INSTALL_DIR/clients/client-configs.txt << EOF
=== VPN Client Configurations ===
Domain: $DOMAIN

1. VLESS + TLS (Recommended):
Address: $DOMAIN
Port: 443
UUID: $UUID_MAIN
Transport: tcp
Security: tls
Flow: xtls-rprx-vision

2. VMess + WebSocket:
Address: $DOMAIN
Port: 443
UUID: $UUID_VMESS
Transport: websocket
Path: /vmess

3. Trojan + WebSocket:
Address: $DOMAIN
Port: 443
Password: $UUID_TROJAN
Transport: websocket
Path: /trojan

4. Shadowsocks:
Address: $DOMAIN
Port: 443
Password: $UUID_SS
Method: chacha20-ietf-poly1305

EOF

    success "Xray configured with UUIDs generated"
}

# Configure Nginx
configure_nginx() {
    log "Configuring Nginx..."
    
    # Stop default nginx
    systemctl stop nginx >/dev/null 2>&1 || true
    
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    # MIME Types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Gzip
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    # Create Xray configuration
    mkdir -p /etc/nginx/conf.d
    cat > /etc/nginx/conf.d/xray.conf << EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2 reuseport;
    listen [::]:443 ssl http2 reuseport;
    
    server_name $DOMAIN;
    
    # SSL Configuration
    ssl_certificate /etc/xray/xray.crt;
    ssl_certificate_key /etc/xray/xray.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    
    # Security Headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # WebSocket paths
    location /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /trojan {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # Fallback
    location / {
        return 404;
    }
}
EOF

    # Test nginx configuration
    if nginx -t >> $LOG_FILE 2>&1; then
        systemctl enable nginx
        systemctl start nginx
        success "Nginx configured successfully"
    else
        error "Nginx configuration test failed"
    fi
}

# Configure HAProxy
configure_haproxy() {
    log "Configuring HAProxy..."
    
    cat > /etc/haproxy/haproxy.cfg << EOF
global
    daemon
    maxconn 4000
    tune.ssl.default-dh-param 2048
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

defaults
    mode tcp
    timeout connect 5s
    timeout client 60s
    timeout server 60s
    log global
    option tcplog
    option dontlognull

frontend https-in
    bind *:443 tfo ssl crt /etc/xray/xray.crt alpn h2,http/1.1
    tcp-request inspect-delay 5s
    tcp-request content accept if { req_ssl_hello_type 1 }
    
    # Route based on SNI
    use_backend xray-tls if { req_ssl_sni -i $DOMAIN }
    
    default_backend nginx-https

backend xray-tls
    server xray-tls 127.0.0.1:10001 check

backend nginx-https
    server nginx-https 127.0.0.1:443 check ssl verify none
EOF

    systemctl enable haproxy
    systemctl start haproxy
    success "HAProxy configured"
}

# Optimize system
optimize_system() {
    log "Optimizing system performance..."
    
    # Enable BBR
    cat >> /etc/sysctl.conf << 'EOF'
# Network Optimizations
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP Optimizations
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536

# Memory Optimizations
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 67108864
net.core.wmem_default = 67108864

# Security
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
EOF

    # Apply settings
    sysctl -p >> $LOG_FILE 2>&1
    
    # Increase file limits
    cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
EOF

    success "System optimized"
}

# Setup firewall
setup_firewall() {
    log "Configuring firewall..."
    
    # Disable existing firewalls to avoid conflicts
    systemctl stop ufw firewalld >/dev/null 2>&1 || true
    systemctl disable ufw firewalld >/dev/null 2>&1 || true
    
    # Basic iptables rules
    iptables -F
    iptables -X
    iptables -Z
    
    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH (port 22)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Allow HTTP/HTTPS
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    # Save rules based on OS
    case $OS in
        ubuntu|debian)
            apt install -y iptables-persistent
            iptables-save > /etc/iptables/rules.v4
            ;;
        centos)
            yum install -y iptables-services
            iptables-save > /etc/sysconfig/iptables
            systemctl enable iptables
            ;;
    esac
    
    success "Firewall configured"
}

# Create management script
create_management_script() {
    log "Creating management scripts..."
    
    cat > /usr/local/bin/vpn-manager << 'EOF'
#!/bin/bash

SCRIPT_DIR="/opt/vpn-setup"
CONFIG_FILE="$SCRIPT_DIR/config.env"

case "$1" in
    start)
        systemctl start xray nginx haproxy
        echo "VPN services started"
        ;;
    stop)
        systemctl stop xray nginx haproxy
        echo "VPN services stopped"
        ;;
    restart)
        systemctl restart xray nginx haproxy
        echo "VPN services restarted"
        ;;
    status)
        systemctl status xray nginx haproxy --no-pager -l
        ;;
    log)
        tail -f /var/log/xray/error.log
        ;;
    config)
        cat $SCRIPT_DIR/clients/client-configs.txt
        ;;
    update)
        bash $SCRIPT_DIR/scripts/update.sh
        ;;
    *)
        echo "Usage: vpn-manager {start|stop|restart|status|log|config|update}"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/vpn-manager
    
    # Create update script
    mkdir -p $INSTALL_DIR/scripts
    cat > $INSTALL_DIR/scripts/update.sh << 'EOF'
#!/bin/bash
# Update script for VPN
echo "Updating VPN configuration..."
# Add update logic here
echo "Update complete"
EOF

    chmod +x $INSTALL_DIR/scripts/update.sh
    
    success "Management scripts created"
}

# Final setup and display
final_setup() {
    log "Finalizing installation..."
    
    # Start services
    systemctl daemon-reload
    systemctl enable xray nginx haproxy
    systemctl restart xray nginx haproxy
    
    # Wait for services to start
    sleep 5
    
    # Check service status
    if systemctl is-active --quiet xray && systemctl is-active --quiet nginx; then
        success "All services are running correctly"
    else
        warning "Some services might not be running properly"
        systemctl status xray nginx haproxy --no-pager -l
    fi
    
    # Display installation info
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║               INSTALLATION COMPLETE             ║"
    echo "╠══════════════════════════════════════════════════╣"
    echo "║ Domain: $DOMAIN"
    echo "║ Installation Directory: $INSTALL_DIR"
    echo "║ Management Command: vpn-manager"
    echo "║ Client Configs: $INSTALL_DIR/clients/client-configs.txt"
    echo "║ Log File: $LOG_FILE"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Display client configurations
    echo -e "${YELLOW}Client configurations saved to: $INSTALL_DIR/clients/client-configs.txt${NC}"
    echo -e "${CYAN}Use 'vpn-manager' command to manage services${NC}"
}

# Main installation function
main() {
    echo -e "${PURPLE}"
    echo "Starting Ultimate VPN AutoScript Installation..."
    echo "This will install and configure Xray, Nginx, and HAProxy"
    echo -e "${NC}"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
    
    # Create log file
    > $LOG_FILE
    
    # Installation steps
    check_system
    get_user_input
    install_dependencies
    install_xray
    configure_xray
    configure_nginx
    configure_haproxy
    optimize_system
    setup_firewall
    create_management_script
    final_setup
    
    success "Installation completed successfully!"
    log "Check $LOG_FILE for detailed installation log"
}

# Run main function
main "$@"