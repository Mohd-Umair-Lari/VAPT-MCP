#!/bin/bash
# VAPT MCP Quick Deploy Script
# Run on your VPS: curl -sSL https://raw.githubusercontent.com/yourusername/vapt-mcp/main/deploy.sh | bash
# Or: wget -qO- https://raw.githubusercontent.com/yourusername/vapt-mcp/main/deploy.sh | bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_DIR="/opt/vapt-mcp"
APP_USER="vapt"
REPO_URL="https://github.com/yourusername/vapt-mcp.git"
DOMAIN=""  # Set your domain: vapt.yourdomain.com

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect OS"
        exit 1
    fi
    print_success "Detected OS: $OS $VERSION"
}

install_dependencies() {
    print_step "Installing system dependencies..."
    
    apt-get update
    apt-get install -y \
        docker.io \
        docker-compose-plugin \
        nginx \
        certbot \
        python3-certbot-nginx \
        curl \
        git \
        ufw \
        fail2ban \
        unattended-upgrades
    
    # Enable Docker
    systemctl enable docker
    systemctl start docker
    
    print_success "Dependencies installed"
}

setup_user() {
    print_step "Creating application user..."
    
    if ! id "$APP_USER" &>/dev/null; then
        useradd -r -s /bin/bash -d "$APP_DIR" "$APP_USER"
        usermod -aG docker "$APP_USER"
        print_success "Created user: $APP_USER"
    else
        print_warning "User $APP_USER already exists"
    fi
}

setup_directory() {
    print_step "Setting up application directory..."
    
    mkdir -p "$APP_DIR"
    cd "$APP_DIR"
    
    if [[ -d .git ]]; then
        print_warning "Repository already exists, pulling latest..."
        git pull
    else
        git clone "$REPO_URL" .
    fi
    
    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
    print_success "Application directory ready"
}

build_docker() {
    print_step "Building Docker image..."
    
    cd "$APP_DIR"
    docker build -t vapt-mcp:latest .
    
    # Test the image
    if docker run --rm vapt-mcp:latest python -c "import sys; sys.path.insert(0, 'scripts'); import mcp_server; print('OK')"; then
        print_success "Docker image built and tested"
    else
        print_error "Docker image test failed"
        exit 1
    fi
}

setup_systemd() {
    print_step "Setting up systemd service..."
    
    cat > /etc/systemd/system/vapt-mcp.service <<EOF
[Unit]
Description=VAPT MCP Server
Documentation=https://github.com/yourusername/vapt-mcp
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=10
TimeoutStartSec=60
TimeoutStopSec=30

WorkingDirectory=$APP_DIR
User=$APP_USER
Group=$APP_USER

Environment=VAPT_ALLOW_PRIVATE_IPS=true
Environment=VAPT_RATE_PER_SECOND=100
Environment=VAPT_MAX_CONCURRENT=50
Environment=VAPT_MAX_REDIRECTS=10
Environment=VAPT_MAX_RESPONSE_BYTES=5242880
Environment=VAPT_REQUEST_BUDGET=100000
Environment=PYTHONUNBUFFERED=1

ExecStart=/usr/bin/docker run --rm \
    --name vapt-mcp \
    --network host \
    -v $APP_DIR/reports:/app/reports \
    -v $APP_DIR/config.json:/app/config.json:ro \
    -e VAPT_ALLOW_PRIVATE_IPS=true \
    -e VAPT_RATE_PER_SECOND=100 \
    -e VAPT_MAX_CONCURRENT=50 \
    -e VAPT_MAX_REDIRECTS=10 \
    -e VAPT_MAX_RESPONSE_BYTES=5242880 \
    -e VAPT_REQUEST_BUDGET=100000 \
    vapt-mcp:latest \
    python -m mcp_server

ExecStop=/usr/bin/docker stop -t 30 vapt-mcp

MemoryLimit=2G
CPUQuota=200%

StandardOutput=journal
StandardError=journal
SyslogIdentifier=vapt-mcp

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable vapt-mcp
    systemctl start vapt-mcp
    
    print_success "Systemd service installed and started"
}

setup_nginx() {
    if [[ -z "$DOMAIN" ]]; then
        print_warning "No domain provided, skipping Nginx setup"
        return
    fi
    
    print_step "Setting up Nginx reverse proxy for $DOMAIN..."
    
    cat > /etc/nginx/sites-available/$DOMAIN <<EOF
# HTTP -> HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    # SSL will be configured by certbot
    # ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    # include /etc/letsencrypt/options-ssl-nginx.conf;
    # ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;

    # MCP HTTP endpoint
    location /mcp/ {
        proxy_pass http://127.0.0.1:8000/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    location /health {
        proxy_pass http://127.0.0.1:8000/health;
        access_log off;
    }

    location / {
        return 302 /health;
    }
}
EOF

    ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    nginx -t
    systemctl reload nginx
    
    print_success "Nginx configured for $DOMAIN"
}

setup_ssl() {
    if [[ -z "$DOMAIN" ]]; then
        print_warning "No domain provided, skipping SSL setup"
        return
    fi
    
    print_step "Obtaining SSL certificate for $DOMAIN..."
    
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email admin@$DOMAIN
    
    # Test auto-renewal
    certbot renew --dry-run
    
    print_success "SSL certificate obtained for $DOMAIN"
}

setup_cloudflare_waf() {
    if [[ -z "$DOMAIN" ]]; then
        print_warning "No domain provided, skipping Cloudflare WAF hints"
        return
    fi
    
    print_step "Cloudflare WAF Configuration (manual step required)..."
    cat <<EOF

=== Cloudflare Dashboard Configuration ===

1. DNS Records (DNS → Records):
   Type: A    Name: $(echo $DOMAIN | cut -d. -f1)  Content: YOUR_SERVER_IP  Proxy: Proxied (Orange)

2. SSL/TLS → Overview: Full (Strict)

3. Security → Settings:
   - Automatic HTTPS Rewrites: ON
   - Always Use HTTPS: ON
   - Minimum TLS Version: TLS 1.2
   - Opportunistic Encryption: ON
   - TLS 1.3: ON

4. Security → WAF → Custom Rules:
   Rule 1: Block scanners
     Expression: (http.user_agent contains "sqlmap" or http.user_agent contains "nikto" or http.user_agent contains "nmap" or http.user_agent contains "masscan" or http.user_agent contains "zmap")
     Action: Block

   Rule 2: Rate limit MCP
     Expression: (http.request.uri.path contains "/mcp/")
     Action: Rate Limit (100 requests/minute)

   Rule 3: Geo-block (optional)
     Expression: (ip.geoip.country in {"CN" "RU" "KP" "IR" "SY"})
     Action: Managed Challenge

4. Speed → Optimization:
   - Auto Minify: CSS, JS, HTML ON
   - Brotli: ON
   - Early Hints: ON

EOF
}

setup_monitoring() {
    print_step "Setting up basic monitoring..."
    
    # Logrotate
    cat > /etc/logrotate.d/vapt-mcp <<EOF
/var/log/vapt-mcp/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 640 vapt vapt
}
EOF

    # Create log directory
    mkdir -p /var/log/vapt-mcp
    chown vapt:vapt /var/log/vapt-mcp
    
    print_success "Log rotation configured"
}

run_tests() {
    print_step "Running deployment tests..."
    
    # Test Docker image
    if docker run --rm vapt-mcp:latest python -c "import sys; sys.path.insert(0, 'scripts'); import mcp_server; print('MCP Server: OK')"; then
        print_success "Docker image test passed"
    else
        print_error "Docker image test failed"
        exit 1
    fi
    
    # Test systemd service
    if systemctl is-active --quiet vapt-mcp; then
        print_success "Systemd service is running"
    else
        print_error "Systemd service not running"
        exit 1
    fi
    
    # Test MCP tools
    if docker run --rm -i vapt-mcp:latest python -m mcp_server <<< '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' 2>/dev/null | grep -q "vapt_detect"; then
        print_success "MCP tools responding"
    else
        print_warning "MCP tools test inconclusive"
    fi
}

main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           VAPT MCP Quick Deploy Script                     ║"
    echo "║   Deploys VAPT MCP to your VPS with Docker + systemd       ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_root
    detect_os
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain)
                DOMAIN="$2"
                shift 2
                ;;
            --repo)
                REPO_URL="$2"
                shift 2
                ;;
            --no-nginx)
                SKIP_NGINX=1
                shift
                ;;
            --no-ssl)
                SKIP_SSL=1
                shift
                ;;
            --help)
                echo "Usage: $0 [--domain vapt.yourdomain.com] [--repo GIT_URL] [--no-nginx] [--no-ssl]"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    print_step "Starting deployment..."
    
    install_dependencies
    setup_user
    setup_directory
    build_docker
    setup_systemd
    
    if [[ -z "$SKIP_NGINX" ]] && [[ -n "$DOMAIN" ]]; then
        setup_nginx
        if [[ -z "$SKIP_SSL" ]]; then
            setup_ssl
        fi
        setup_cloudflare_waf
    fi
    
    setup_monitoring
    run_tests
    
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           DEPLOYMENT COMPLETE!                             ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    if [[ -n "$DOMAIN" ]]; then
        echo "🌐 Your VAPT MCP is available at: https://$DOMAIN"
        echo "   MCP HTTP endpoint: https://$DOMAIN/mcp/"
        echo "   Health check: https://$DOMAIN/health"
    else
        echo "🖥️  Running in stdio mode (for Hermes integration)"
        echo "   Service: systemctl status vapt-mcp"
    fi
    
    echo ""
    echo "📋 Useful commands:"
    echo "   systemctl status vapt-mcp    # Check service status"
    echo "   journalctl -u vapt-mcp -f    # Follow logs"
    echo "   systemctl restart vapt-mcp   # Restart service"
    echo "   docker logs vapt-mcp         # Docker logs"
    echo ""
    echo "📚 Next steps:"
    echo "   1. Configure Hermes: Add MCP server config"
    echo "   2. Test: docker run --rm -i vapt-mcp:latest python -m mcp_server <<< '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}'"
    echo "   3. Configure Cloudflare WAF (see output above)"
}

main "$@"