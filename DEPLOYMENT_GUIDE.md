# 🚀 MXUI VPN Panel - Deployment Guide

**Version:** 2.0.0 Production-Ready
**Date:** 2024-12-25
**Status:** ✅ Ready for Production Deployment

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Database Setup](#database-setup)
5. [Payment Gateway Setup](#payment-gateway-setup)
6. [Running the Panel](#running-the-panel)
7. [Systemd Service](#systemd-service)
8. [Nginx Reverse Proxy](#nginx-reverse-proxy)
9. [SSL/TLS Setup](#ssltls-setup)
10. [Monitoring](#monitoring)
11. [Backup & Restore](#backup--restore)
12. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

**Minimum:**
- OS: Ubuntu 20.04+ / Debian 11+ / CentOS 8+
- CPU: 2 cores
- RAM: 2GB
- Disk: 20GB SSD
- Network: 1Gbps

**Recommended (Production):**
- OS: Ubuntu 22.04 LTS
- CPU: 4+ cores
- RAM: 4GB+
- Disk: 50GB+ NVMe SSD
- Network: 1Gbps+ with DDoS protection

### Software Dependencies

```bash
# Required
- Go 1.22+ (for building from source)
- PostgreSQL 14+ OR MySQL 8.0+ (recommended for production)
- Nginx (for reverse proxy)
- Certbot (for SSL certificates)

# Optional
- Redis 6.0+ (for caching - highly recommended)
- Docker & Docker Compose (alternative deployment)
- Prometheus + Grafana (for monitoring)
```

---

## Installation

### Method 1: Using install.sh (Recommended)

```bash
# Download and run installer
bash <(curl -Ls https://raw.githubusercontent.com/YOUR-REPO/MXUI/main/install.sh)

# Or clone and install
git clone https://github.com/YOUR-REPO/MXUI.git
cd MXUI
chmod +x install.sh
./install.sh
```

The installer will:
1. Check system requirements
2. Install dependencies
3. Build the binary
4. Set up systemd service
5. Configure firewall
6. Create initial database

### Method 2: Manual Installation

```bash
# 1. Clone repository
git clone https://github.com/YOUR-REPO/MXUI.git
cd MXUI

# 2. Install Go dependencies
go mod download
go mod tidy

# 3. Build binary
go build -o mxui ./cmd/mxui

# 4. Move to system directory
sudo mv mxui /usr/local/bin/
sudo chmod +x /usr/local/bin/mxui

# 5. Create data directory
sudo mkdir -p /opt/mxui/Data
sudo mkdir -p /opt/mxui/Data/logs
sudo mkdir -p /opt/mxui/Data/certs
sudo mkdir -p /opt/mxui/Data/backups
```

### Method 3: Docker Deployment

```bash
# Using Docker Compose
docker-compose up -d

# Or build manually
docker build -t mxui:latest .
docker run -d -p 2096:2096 -v /opt/mxui:/app/Data mxui:latest
```

---

## Configuration

### 1. Create Configuration File

```bash
sudo nano /opt/mxui/config.yaml
```

### 2. Minimal Configuration (SQLite)

```yaml
# Server settings
server:
  host: "0.0.0.0"
  port: 2096
  base_url: "https://panel.yourdomain.com"

# Database (SQLite - for testing)
database:
  type: sqlite
  path: "/opt/mxui/Data/database.db"

# Admin credentials
admin:
  username: "admin"
  password: "CHANGE_THIS_PASSWORD"
  email: "admin@yourdomain.com"
```

### 3. Production Configuration (PostgreSQL)

```yaml
# Server settings
server:
  host: "127.0.0.1"  # Bind to localhost, use Nginx reverse proxy
  port: 2096
  base_url: "https://panel.yourdomain.com"
  tls_enabled: false  # Nginx handles TLS

# Database (PostgreSQL - RECOMMENDED)
database:
  type: postgres
  host: "localhost"
  port: 5432
  database: "mxui"
  username: "mxui_user"
  password: "STRONG_DB_PASSWORD"
  ssl_mode: "disable"  # Use "require" for remote DB

  # Connection pool
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: 5m
  conn_max_idle_time: 10m

# Redis (for caching and sessions)
redis:
  enabled: true
  host: "localhost"
  port: 6379
  password: ""
  db: 0

# Security
security:
  jwt_secret: "GENERATE_RANDOM_32_CHAR_SECRET"
  session_timeout: 24h
  csrf_enabled: true
  rate_limiting:
    enabled: true
    login_attempts: 5
    login_window: 15m
    api_limit: 100
    api_window: 1m

# Payment Gateway (Stripe)
payments:
  stripe:
    enabled: true
    api_key: "sk_live_xxxxx"  # Use sk_test_ for testing
    webhook_secret: "whsec_xxxxx"
    currency: "USD"
    success_url: "https://panel.yourdomain.com/payment/success"
    cancel_url: "https://panel.yourdomain.com/payment/cancel"

# Email Notifications
notifications:
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    smtp_username: "your-email@gmail.com"
    smtp_password: "your-app-password"
    from_email: "noreply@yourdomain.com"
    from_name: "MXUI VPN Panel"
    tls: true

# Backup
backup:
  enabled: true
  schedule: "0 2 * * *"  # Daily at 2 AM
  retention_days: 30
  s3:
    enabled: false
    bucket: "mxui-backups"
    region: "us-east-1"
    access_key: "YOUR_ACCESS_KEY"
    secret_key: "YOUR_SECRET_KEY"

# Monitoring
monitoring:
  prometheus:
    enabled: true
    port: 9090

# Logging
logging:
  level: "info"  # debug, info, warn, error
  file: "/opt/mxui/Data/logs/app.log"
  max_size: 100  # MB
  max_backups: 10
  max_age: 30  # days
```

---

## Database Setup

### PostgreSQL (Recommended)

```bash
# 1. Install PostgreSQL
sudo apt update
sudo apt install postgresql postgresql-contrib

# 2. Create database and user
sudo -u postgres psql

postgres=# CREATE DATABASE mxui;
postgres=# CREATE USER mxui_user WITH ENCRYPTED PASSWORD 'STRONG_PASSWORD';
postgres=# GRANT ALL PRIVILEGES ON DATABASE mxui TO mxui_user;
postgres=# \q

# 3. Run migrations
mxui migrate up
```

### MySQL

```bash
# 1. Install MySQL
sudo apt install mysql-server

# 2. Secure installation
sudo mysql_secure_installation

# 3. Create database
sudo mysql

mysql> CREATE DATABASE mxui CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
mysql> CREATE USER 'mxui_user'@'localhost' IDENTIFIED BY 'STRONG_PASSWORD';
mysql> GRANT ALL PRIVILEGES ON mxui.* TO 'mxui_user'@'localhost';
mysql> FLUSH PRIVILEGES;
mysql> exit;

# 4. Update config.yaml with MySQL settings
database:
  type: mysql
  host: localhost
  port: 3306
  database: mxui
  username: mxui_user
  password: STRONG_PASSWORD

# 5. Run migrations
mxui migrate up
```

### Database Migration Commands

```bash
# Run all pending migrations
mxui migrate up

# Check migration status
mxui migrate status

# Rollback last migration
mxui migrate down

# Rollback to specific version
mxui migrate down --to 001

# Force migration version (advanced)
mxui migrate force 002
```

---

## Payment Gateway Setup

### Stripe Integration

1. **Create Stripe Account:**
   - Go to https://dashboard.stripe.com/register
   - Complete verification

2. **Get API Keys:**
   - Navigate to: Developers → API keys
   - Copy "Secret key" (starts with `sk_test_` or `sk_live_`)
   - Save in `config.yaml`

3. **Create Products & Prices:**
   ```bash
   # Using Stripe CLI (optional)
   stripe products create --name="Basic VPN Plan" --description="30 days, 100GB traffic"
   stripe prices create --product=PRODUCT_ID --unit-amount=999 --currency=usd --recurring-interval=month
   ```

4. **Setup Webhook:**
   - Go to: Developers → Webhooks → Add endpoint
   - URL: `https://panel.yourdomain.com/api/v1/webhooks/stripe`
   - Events to listen:
     - `checkout.session.completed`
     - `invoice.paid`
     - `invoice.payment_failed`
     - `customer.subscription.created`
     - `customer.subscription.updated`
     - `customer.subscription.deleted`
   - Copy "Signing secret" (starts with `whsec_`)
   - Save in `config.yaml`

5. **Test Webhook:**
   ```bash
   # Using Stripe CLI
   stripe listen --forward-to localhost:2096/api/v1/webhooks/stripe
   ```

---

## Running the Panel

### Foreground (Testing)

```bash
# Run with default config
mxui

# Run with custom config
mxui --config /path/to/config.yaml

# Run with verbose logging
mxui --debug
```

### Background (Production)

```bash
# Using nohup
nohup mxui --config /opt/mxui/config.yaml > /opt/mxui/Data/logs/mxui.log 2>&1 &

# Check logs
tail -f /opt/mxui/Data/logs/mxui.log
```

---

## Systemd Service

### Create Service File

```bash
sudo nano /etc/systemd/system/mxui.service
```

```ini
[Unit]
Description=MXUI VPN Panel
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mxui
ExecStart=/usr/local/bin/mxui --config /opt/mxui/config.yaml
Restart=always
RestartSec=10
StandardOutput=append:/opt/mxui/Data/logs/mxui.log
StandardError=append:/opt/mxui/Data/logs/error.log

# Security
NoNewPrivileges=true
PrivateTmp=true

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable on boot
sudo systemctl enable mxui

# Start service
sudo systemctl start mxui

# Check status
sudo systemctl status mxui

# View logs
sudo journalctl -u mxui -f
```

---

## Nginx Reverse Proxy

### Install Nginx

```bash
sudo apt install nginx
```

### Create Site Configuration

```bash
sudo nano /etc/nginx/sites-available/mxui
```

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name panel.yourdomain.com;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS configuration
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name panel.yourdomain.com;

    # SSL certificates (Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/panel.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/panel.yourdomain.com/privkey.pem;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Logging
    access_log /var/log/nginx/mxui-access.log;
    error_log /var/log/nginx/mxui-error.log;

    # Client body size
    client_max_body_size 50M;

    # Proxy to backend
    location / {
        proxy_pass http://127.0.0.1:2096;
        proxy_http_version 1.1;

        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Static files (if any)
    location /static/ {
        alias /opt/mxui/Web/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

### Enable Site

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/mxui /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
```

---

## SSL/TLS Setup

### Using Let's Encrypt (Free)

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d panel.yourdomain.com

# Auto-renewal is set up automatically
# Test renewal
sudo certbot renew --dry-run
```

### Using Custom Certificate

```bash
# Copy your certificate files
sudo cp your-certificate.crt /etc/nginx/ssl/
sudo cp your-private-key.key /etc/nginx/ssl/

# Update Nginx config
ssl_certificate /etc/nginx/ssl/your-certificate.crt;
ssl_certificate_key /etc/nginx/ssl/your-private-key.key;
```

---

## Monitoring

### Prometheus Setup

```bash
# Install Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-amd64.tar.gz
tar -xvf prometheus-2.45.0.linux-amd64.tar.gz
cd prometheus-2.45.0.linux-amd64

# Create config
cat > prometheus.yml <<EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'mxui'
    static_configs:
      - targets: ['localhost:9090']
EOF

# Run Prometheus
./prometheus --config.file=prometheus.yml
```

### Health Checks

```bash
# Check application health
curl http://localhost:2096/api/v1/health

# Check database health
curl http://localhost:2096/api/v1/health/db

# Check nodes health
curl http://localhost:2096/api/v1/health/nodes

# Prometheus metrics
curl http://localhost:2096/api/v1/metrics
```

---

## Backup & Restore

### Manual Backup

```bash
# Create backup
mxui backup create

# Backup with custom path
mxui backup create --output /path/to/backup.tar.gz

# List backups
mxui backup list

# View backup info
mxui backup info backup_20241225.tar.gz
```

### Restore

```bash
# Restore from backup
mxui backup restore backup_20241225.tar.gz

# Restore with confirmation
mxui backup restore backup_20241225.tar.gz --force
```

### Automated Backups (Cron)

```bash
# Edit crontab
crontab -e

# Add daily backup at 2 AM
0 2 * * * /usr/local/bin/mxui backup create --output /opt/mxui/Data/backups/backup_$(date +\%Y\%m\%d).tar.gz

# Add weekly S3 upload
0 3 * * 0 /usr/local/bin/mxui backup upload-s3 /opt/mxui/Data/backups/latest.tar.gz
```

---

## Troubleshooting

### Common Issues

#### 1. Port Already in Use

```bash
# Check what's using port 2096
sudo lsof -i :2096

# Kill process
sudo kill -9 PID

# Or change port in config.yaml
```

#### 2. Database Connection Failed

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Check credentials
psql -U mxui_user -d mxui -h localhost

# Check logs
tail -f /var/log/postgresql/postgresql-14-main.log
```

#### 3. Permission Denied

```bash
# Fix ownership
sudo chown -R root:root /opt/mxui

# Fix permissions
sudo chmod -R 755 /opt/mxui
sudo chmod 600 /opt/mxui/config.yaml
```

#### 4. Nginx 502 Bad Gateway

```bash
# Check if MXUI is running
sudo systemctl status mxui

# Check Nginx error logs
sudo tail -f /var/log/nginx/error.log

# Check backend is listening
sudo netstat -tlnp | grep 2096
```

#### 5. Stripe Webhook Failures

```bash
# Check webhook secret
grep webhook_secret /opt/mxui/config.yaml

# Test webhook manually
stripe trigger checkout.session.completed

# Check logs
tail -f /opt/mxui/Data/logs/app.log | grep webhook
```

### Getting Logs

```bash
# Application logs
tail -f /opt/mxui/Data/logs/app.log

# Error logs
tail -f /opt/mxui/Data/logs/error.log

# Systemd logs
sudo journalctl -u mxui -f

# Nginx logs
sudo tail -f /var/log/nginx/mxui-error.log
```

---

## Performance Tuning

### Database Optimization

```sql
-- PostgreSQL
-- Analyze tables
ANALYZE users;
ANALYZE payments;
ANALYZE subscriptions;

-- Vacuum
VACUUM ANALYZE;

-- Check slow queries
SELECT * FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;
```

### System Limits

```bash
# Increase file descriptors
sudo nano /etc/security/limits.conf

# Add:
* soft nofile 65536
* hard nofile 65536

# Apply
sudo sysctl -p
```

### Nginx Tuning

```nginx
# In /etc/nginx/nginx.conf
worker_processes auto;
worker_connections 4096;
keepalive_timeout 65;
client_body_buffer_size 128k;
client_max_body_size 50m;
```

---

## Security Checklist

- [ ] Change default admin password
- [ ] Use strong database passwords
- [ ] Enable HTTPS/TLS
- [ ] Configure firewall (UFW/iptables)
- [ ] Enable CSRF protection
- [ ] Enable rate limiting
- [ ] Regular security updates
- [ ] Enable automated backups
- [ ] Use PostgreSQL/MySQL (not SQLite)
- [ ] Secure webhook endpoints
- [ ] Implement 2FA for admins
- [ ] Regular log monitoring
- [ ] Use Redis for sessions

---

## Next Steps

After successful deployment:

1. **Create Admin Account**: Access panel and create your admin user
2. **Configure VPN Cores**: Add Xray/Sing-box nodes
3. **Create Plans**: Set up subscription plans with pricing
4. **Test Payment Flow**: Make a test purchase with Stripe test mode
5. **Configure Templates**: Customize email templates
6. **Monitor**: Set up Prometheus + Grafana dashboards
7. **Scale**: Add more nodes as needed

---

## Support & Resources

- **Documentation**: [PRODUCTION_ROADMAP.md](PRODUCTION_ROADMAP.md)
- **Completion Report**: [COMPLETION_REPORT.md](COMPLETION_REPORT.md)
- **Final Summary**: [FINAL_SUMMARY.md](FINAL_SUMMARY.md)
- **GitHub Issues**: Report bugs and feature requests
- **Community**: Join our Discord/Telegram

---

**🎉 Congratulations! Your MXUI VPN Panel is now production-ready!**

*Generated with ❤️ by Claude*
*Version: 2.0.0 Production-Ready*
*Date: 2024-12-25*
