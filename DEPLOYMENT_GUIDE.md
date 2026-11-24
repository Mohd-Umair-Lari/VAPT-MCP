# VAPT MCP Deployment Guide for Subdomain via Cloudflare

## Overview
This guide deploys the VAPT MCP project to your subdomain (e.g., `vapt.yourdomain.com`) using Cloudflare for DNS, SSL, and DDoS protection. **No codebase logic changes** - only deployment configuration.

---

## Prerequisites

- **Domain**: `yourdomain.com` managed in Cloudflare
- **Subdomain**: `vapt.yourdomain.com` (or your choice)
- **Server**: Linux VPS (Ubuntu 22.04+ recommended) with 2GB+ RAM, 2+ vCPUs
- **Docker**: Installed on the server
- **Cloudflare Account**: With DNS management for your domain

---

## Step 1: Server Setup

### 1.1 Provision VPS
```bash
# Minimum specs: 2GB RAM, 2 vCPU, 20GB disk
# Recommended: 4GB RAM, 4 vCPU, 50GB disk
# Provider examples: DigitalOcean, Linode, Vultr, Hetzner, AWS Lightsail
```

### 1.2 Initial Server Configuration
```bash
# SSH into your server
ssh root@your-server-ip

# Update system
apt-get update && apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh

# Install Docker Compose
apt-get install -y docker-compose-plugin

# Install Nginx (for reverse proxy)
apt-get install -y nginx certbot python3-certbot-nginx

# Create vapt user
useradd -r -s /bin/bash -d /opt/vapt-mcp vapt
usermod -aG docker vapt
```

### 1.3 Configure Firewall
```bash
# UFW (Ubuntu)
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP (for ACME challenge)
ufw allow 443/tcp   # HTTPS
ufw enable

# Or iptables
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

---

## Step 2: Deploy Application

### 2.1 Clone Repository
```bash
# Create application directory
mkdir -p /opt/vapt-mcp
cd /opt/vapt-mcp

# Clone your repository (or copy files)
git clone https://github.com/yourusername/vapt-mcp.git .
# OR copy files via scp/rsync from local

# Set ownership
chown -R vapt:vapt /opt/vapt-mcp
```

### 2.2 Configure Environment
```bash
# Copy and edit config
cp config.json config.json.production

# Edit config.json.production for production settings
# Key settings:
# - rate_limit_per_second: 100 (adjust based on server capacity)
# - max_concurrent_per_host: 50
# - global_request_budget: 100000
# - allow_private_ips: true (for internal network scanning)
```

### 2.3 Build Docker Image
```bash
cd /opt/vapt-mcp

# Build production image
docker build -t vapt-mcp:latest .

# Verify image works
docker run --rm vapt-mcp:latest python -c "import sys; sys.path.insert(0, 'scripts'); import mcp_server; print('OK')"
```

---

## Step 3: Choose Deployment Mode

### Option A: Stdio Mode (for Hermes Integration)
**Use this if integrating with Hermes desktop app via MCP stdio**

```bash
# Run as systemd service (see Step 4)
# No ports exposed - communicates via stdio
```

### Option B: HTTP Mode (for Direct API Access)
**Use this for direct REST API or webhook integration**

```yaml
# docker-compose.yml - uncomment ports section
ports:
  - "8000:8000"
command: ["python", "scripts/mcp_server.py", "--http", "--port", "8000"]
```

---

## Step 4: Systemd Service (Production)

### 4.1 Install Service File
```bash
# Copy service file
cp vapt-mcp.service /etc/systemd/system/vapt-mcp.service

# Reload systemd
systemctl daemon-reload

# Enable and start
systemctl enable vapt-mcp
systemctl start vapt-mcp

# Check status
systemctl status vapt-mcp
journalctl -u vapt-mcp -f
```

### 4.2 Alternative: Docker Compose
```bash
# Start with docker-compose
cd /opt/vapt-mcp
docker-compose up -d

# Check logs
docker-compose logs -f vapt-mcp
```

---

## Step 5: Nginx Reverse Proxy (for HTTP Mode)

### 5.1 Configure Nginx
```bash
# Copy nginx config
cp nginx.conf /etc/nginx/sites-available/vapt.yourdomain.com

# Enable site
ln -s /etc/nginx/sites-available/vapt.yourdomain.com /etc/nginx/sites-enabled/

# Remove default site
rm /etc/nginx/sites-enabled/default

# Test config
nginx -t

# Reload nginx
systemctl reload nginx
```

### 5.2 SSL Certificate (Let's Encrypt via Certbot)
```bash
# Obtain certificate
certbot --nginx -d vapt.yourdomain.com

# Auto-renewal (already configured by certbot)
systemctl status certbot.timer
```

---

## Step 6: Cloudflare Configuration

### 6.1 DNS Records
In Cloudflare Dashboard → DNS → Records:

| Type | Name | Content | Proxy Status |
|------|------|---------|--------------|
| A    | vapt | YOUR_SERVER_IP | **Proxied** (Orange cloud) |
| AAAA | vapt | YOUR_SERVER_IPv6 | **Proxied** (if IPv6) |

### 6.2 SSL/TLS Settings
**SSL/TLS → Overview**: Set to **Full (Strict)**
- Requires valid cert on origin (Let's Encrypt via certbot handles this)

### 6.3 Security Settings
**Security → Settings**:
- **Automatic HTTPS Rewrites**: ON
- **Always Use HTTPS**: ON
- **Minimum TLS Version**: TLS 1.2
- **Opportunistic Encryption**: ON
- **TLS 1.3**: ON

### 6.4 WAF Rules (Recommended)
**Security → WAF → Custom Rules**:

| Rule Name | Expression | Action |
|-----------|------------|--------|
| Block non-HTTPS | `(http.request.uri.path contains "/mcp/") and (ssl eq false)` | Block |
| Rate Limit MCP | `(http.request.uri.path contains "/mcp/")` | Rate Limit: 100 req/min |
| Block Scanners | `(http.user_agent contains "sqlmap" or http.user_agent contains "nikto" or http.user_agent contains "nmap")` | Block |
| Geo Block (optional) | `(ip.geoip.country in {"CN" "RU" "KP" "IR"})` | Challenge |

### 6.5 DNS Settings
**Network → DNS**:
- **DNSSEC**: Enable
- **CNAME Flattening**: Automatic
- **Always Online**: ON (if using Cloudflare Pages/Workers as fallback)

---

## Step 7: Hermes Integration

### 7.1 Local Stdio Mode (Recommended for Hermes Desktop)
No Cloudflare tunnel needed - Hermes runs MCP locally via stdio.

**Hermes Config** (`~/.config/hermes/hermes-config.yaml`):
```yaml
mcp_servers:
  vapt:
    command: "docker"
    args: ["run", "--rm", "-i", "-v", "/opt/vapt-mcp/reports:/app/reports", "vapt-mcp:latest", "python", "-m", "mcp_server"]
    env:
      VAPT_ALLOW_PRIVATE_IPS: "true"
      VAPT_RATE_PER_SECOND: "100"
      VAPT_MAX_CONCURRENT: "50"
```

### 7.2 Remote HTTP Mode (if using Hermes with remote MCP)
```yaml
mcp_servers:
  vapt:
    url: "https://vapt.yourdomain.com/mcp"
    # For SSE transport
    # transport: sse
```

---

## Step 8: Monitoring & Maintenance

### 8.1 Health Checks
```bash
# Manual health check
docker run --rm vapt-mcp:latest python -c "import sys; sys.path.insert(0, 'scripts'); import mcp_server; print('OK')"

# Check service
systemctl status vapt-mcp
docker logs vapt-mcp --tail 100
```

### 8.2 Log Rotation
```bash
# /etc/logrotate.d/vapt-mcp
/var/log/vapt-mcp/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 640 vapt vapt
}
```

### 8.3 Backup Reports
```bash
# Add to crontab (run daily at 2 AM)
0 2 * * * tar -czf /backups/vapt-reports-$(date +\%Y\%m\%d).tar.gz /opt/vapt-mcp/reports
```

### 8.4 Update Procedure
```bash
cd /opt/vapt-mcp
git pull
docker build -t vapt-mcp:latest .
systemctl restart vapt-mcp
# OR: docker-compose up -d --build
```

---

## Step 9: Testing Deployment

### 9.1 Local Testing
```bash
# Test stdio mode
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | docker run --rm -i vapt-mcp:latest python -m mcp_server

# Test HTTP mode (if enabled)
curl -X POST https://vapt.yourdomain.com/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

### 9.2 Test via Hermes
1. Open Hermes Desktop
2. Add MCP server config
3. Test `vapt_detect` with a target
4. Test `vapt_exploit` with auto_approve

---

## Step 10: Security Hardening (Post-Deploy)

### 10.1 Server Hardening
```bash
# Disable root SSH
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# Fail2ban
apt-get install -y fail2ban
# Configure jail for SSH, Nginx

# Unattended upgrades
apt-get install -y unattended-upgrades
dpkg-reconfigure unattended-upgrades
```

### 10.2 Application Security
- Private IPs allowed only for authorized internal scans
- Rate limiting enforced at application + Cloudflare level
- Approval gates for exploitation (auto-approve configurable)
- Reports directory permissions: `chmod 750 /opt/vapt-mcp/reports`

---

## Quick Reference Commands

| Task | Command |
|------|---------|
| Start service | `systemctl start vapt-mcp` |
| Stop service | `systemctl stop vapt-mcp` |
| Restart | `systemctl restart vapt-mcp` |
| View logs | `journalctl -u vapt-mcp -f` |
| Update app | `cd /opt/vapt-mcp && git pull && docker build -t vapt-mcp:latest . && systemctl restart vapt-mcp` |
| Backup reports | `tar -czf backup-$(date +%F).tar.gz /opt/vapt-mcp/reports` |
| Check SSL | `curl -I https://vapt.yourdomain.com/health` |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| MCP tools not found | Check `docker logs vapt-mcp` for import errors |
| SSL cert errors | Run `certbot renew --dry-run` then `certbot renew` |
| High memory | Reduce `VAPT_MAX_CONCURRENT` and `VAPT_REQUEST_BUDGET` |
| Slow scans | Increase `VAPT_RATE_PER_SECOND` if CPU allows |
| Hermes can't connect | Verify Docker stdio mode, check Hermes config paths |

---

## Architecture Summary

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Hermes    │────▶│  Docker      │────▶│  VAPT MCP   │
│  (Desktop)  │ stdio│  Container   │     │  (Python)   │
└─────────────┘     └──────────────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    ▼             ▼
              ┌──────────┐  ┌──────────┐
              │ Reports  │  │ Scanning │
              │  (vol)   │  │  Tools   │
              └──────────┘  └──────────┘
```

---

## Support

- **Logs**: `journalctl -u vapt-mcp -f` or `docker logs vapt-mcp -f`
- **Health**: `curl https://vapt.yourdomain.com/health`
- **Metrics**: `curl https://vapt.yourdomain.com/metrics` (if enabled)

**No codebase logic was modified** - this deployment preserves all scanning logic, approval gates, CIDR scanning, and exploitation workflows exactly as developed.