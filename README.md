<p align="center">
  <img src="./Web/assets/logo.png" alt="MR-X Logo" width="200"/>
</p>

<h1 align="center">MR-X VPN Panel</h1>

<p align="center">
  <b>Professional Multi-Protocol VPN Management Panel</b>
</p>

<p align="center">
  <a href="https://github.com/MR-X-Panel/MR-X/releases/latest">
    <img src="https://img.shields.io/github/v/release/MR-X-Panel/MR-X?style=flat-square&color=blue" alt="Latest Release"/>
  </a>
  <a href="https://github.com/MR-X-Panel/MR-X/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/MR-X-Panel/MR-X?style=flat-square" alt="License"/>
  </a>
  <a href="https://github.com/MR-X-Panel/MR-X/stargazers">
    <img src="https://img.shields.io/github/stars/MR-X-Panel/MR-X?style=flat-square" alt="Stars"/>
  </a>
  <a href="https://github.com/MR-X-Panel/MR-X/issues">
    <img src="https://img.shields.io/github/issues/MR-X-Panel/MR-X?style=flat-square" alt="Issues"/>
  </a>
  <a href="https://t.me/MXUI_Support">
    <img src="https://img.shields.io/badge/Telegram-Support-blue?style=flat-square&logo=telegram" alt="Telegram"/>
  </a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#usage">Usage</a> •
  <a href="#api">API</a> •
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <a href="./README_FA.md">🇮🇷 فارسی</a> |
  <a href="./README.md">🇬🇧 English</a> |
  <a href="./README_ZH.md">🇨🇳 中文</a> |
  <a href="./README_RU.md">🇷🇺 Русский</a>
</p>

---

## 📖 Overview

MR-X is a powerful, feature-rich VPN management panel built with Go and modern web technologies. It provides an intuitive interface for managing multiple VPN protocols, users, nodes, and subscriptions with enterprise-grade features.

### Why MR-X?

- **Multi-Protocol Support**: VMess, VLESS, Trojan, Shadowsocks 2022, Hysteria2, TUIC, WireGuard
- **Multiple Cores**: Xray-core, Sing-box, Clash Meta
- **Modern UI**: Beautiful, responsive web panel with PWA support
- **High Performance**: Built with Go for speed and efficiency
- **Easy Management**: One-click installation, updates, and backups

---

## ✨ Features

### 🔐 Security
- Two-Factor Authentication (2FA/TOTP)
- JWT-based session management
- IP whitelist/blacklist
- Brute-force protection
- Rate limiting
- SSL/TLS with Let's Encrypt auto-renewal

### 👥 User Management
- Unlimited users with traffic & time limits
- Multi-device and IP restrictions
- Usage monitoring and analytics
- Bulk user operations (import/export)
- Trial accounts with auto-expiration
- QR code generation for easy setup

### 👨‍💼 Admin System
- **Owner**: Full administrative access
- **Reseller**: Limited to user creation and management
- Permission-based access control
- Activity logging and audit trail

### 🌐 Multi-Node Support
- Centralized management of multiple servers
- Health monitoring and auto-failover
- Load balancing (Round-robin, Least-conn)
- Real-time sync across nodes
- Geographic distribution

### 📡 Protocols & Transports
| Protocol | Transport | Security |
|----------|-----------|----------|
| VMess | WebSocket, gRPC, HTTP/2, TCP, mKCP, QUIC | TLS, Reality |
| VLESS | WebSocket, gRPC, HTTP/2, TCP, QUIC | TLS, Reality, XTLS |
| Trojan | WebSocket, gRPC, TCP | TLS |
| Shadowsocks | TCP, WebSocket | 2022 Encryption |
| Hysteria2 | QUIC | Native |
| TUIC | QUIC | Native |
| WireGuard | UDP | Native |

### 🔧 Advanced Features
- **WARP Integration**: Cloudflare WARP for specific routes
- **Smart Routing**: Block ads, malware, and adult content
- **Auto-Fix**: Automatic issue detection and resolution
- **AI Assistant**: Intelligent suggestions and optimization
- **Telegram Bot**: Full management via Telegram
- **API**: RESTful API for integration

### 💾 Backup & Recovery
- Scheduled automatic backups
- Multiple destinations: Local, Telegram, Google Drive, S3
- One-click restore
- Database encryption

### 📱 Client Support
- Web-based subscription page
- Support for all major clients:
  - v2rayN, v2rayNG, v2rayA
  - Clash, Clash Meta, ClashX
  - Sing-box, SFI, SFA
  - Shadowrocket, Quantumult X
  - Nekoray, Nekobox
  - Hiddify

---

## 📋 Requirements

### Minimum Requirements
- **OS**: Ubuntu 20.04+, Debian 11+, CentOS 8+, AlmaLinux 8+
- **CPU**: 1 core
- **RAM**: 512MB
- **Disk**: 10GB
- **Network**: Public IPv4

### Recommended
- **CPU**: 2+ cores
- **RAM**: 2GB+
- **Disk**: 20GB+ SSD
- **Network**: Public IPv4 + IPv6

---

## 🚀 Installation

Unified installer (select Master/Node, Bash/Docker, Quick/Custom):

```bash
bash <(curl -sL https://raw.githubusercontent.com/matin-x/mxui/main/install.sh)
```

Notes
- Choose Install → Role (Master or Node) → Method (Bash or Docker) → Mode (Quick or Custom).
- Master installs the full web panel and configures the server as node master.
- Node installs only the runtime core without any web UI and prints join info (node name, IP, token) to register in Master.
- Custom mode can request domain and attempt SSL issuance (Let’s Encrypt). If SSL fails or is skipped, HTTP is used until configured in panel.
- All installation logs are written to /tmp/install_MXUI_YYYYmmdd_HHMMSS.log.

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file or set these environment variables:

```bash
# Server
MXUI_PORT=8443
MXUI_API_PORT=8080

# Admin
MXUI_ADMIN_USER=admin
MXUI_ADMIN_PASS=your_secure_password

# Security
MXUI_JWT_SECRET=your_jwt_secret
MXUI_API_KEY=your_api_key

# SSL
MXUI_SSL_ENABLED=true
MXUI_DOMAIN=panel.example.com
MXUI_AUTO_TLS=true
```

### Configuration File

Edit `/opt/Mxui/config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8443

database:
  type: "sqlite"
  path: "/opt/Mxui/data/Mxui.db"

ssl:
  enabled: true
  auto_tls: true
  domain: "panel.example.com"
```

See [config.yaml](./config.yaml) for all options.

---

## 📖 Usage

### Access Panel

After installation, access the panel at:
```
http://YOUR_SERVER_IP:8443
```

Default credentials are shown after installation. **Change them immediately!**

### Commands

```bash
# Service management
systemctl start Mxui      # Start
systemctl stop Mxui       # Stop
systemctl restart Mxui    # Restart
systemctl status Mxui     # Status

# View logs
journalctl -u Mxui -f

# Update
bash <(curl -sL https://raw.githubusercontent.com/MR-X-Panel/MR-X/main/update.sh)

# Uninstall
bash <(curl -sL https://raw.githubusercontent.com/MR-X-Panel/MR-X/main/uninstall.sh)
```

### CLI Commands

```bash
# Show version
Mxui version

# Generate config
Mxui config generate

# Database operations
Mxui db migrate
Mxui db backup
Mxui db restore backup.sql

# User management
Mxui user list
Mxui user create --username test --traffic 10GB --days 30
Mxui user delete --username test

# Core management
Mxui core status
Mxui core restart
```

---

## 🔌 API

MR-X provides a comprehensive REST API for integration.

### Authentication

```bash
# Get token
curl -X POST https://panel.example.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'

# Use token
curl https://panel.example.com/api/v1/users \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | Login |
| GET | `/api/v1/users` | List users |
| POST | `/api/v1/users` | Create user |
| GET | `/api/v1/users/:id` | Get user |
| PUT | `/api/v1/users/:id` | Update user |
| DELETE | `/api/v1/users/:id` | Delete user |
| GET | `/api/v1/nodes` | List nodes |
| GET | `/api/v1/system/stats` | System stats |

See [API Documentation](./docs/API.md) for complete reference.

---

## 🤖 Telegram Bot

Enable Telegram bot for remote management:

1. Create bot with [@BotFather](https://t.me/BotFather)
2. Get your bot token
3. Configure in panel settings or config file:

```yaml
telegram_bot:
  enabled: true
  token: "YOUR_BOT_TOKEN"
  admins:
    - 123456789  # Your Telegram ID
```

### Bot Commands

```
/start - Start bot
/help - Show help
/me - Account info
/usage - Traffic usage
/configs - Get configurations
/buy - Purchase subscription
/support - Contact support
```

---

## 🔄 Backup & Restore

### Automatic Backup

Configure in panel or config file:

```yaml
backup:
  auto_backup: true
  schedule: "0 3 * * *"  # Daily at 3 AM
  retention_days: 7
  destinations:
    telegram:
      enabled: true
      bot_token: "YOUR_BOT_TOKEN"
      chat_id: "YOUR_CHAT_ID"
```

### Manual Backup

```bash
# Create backup
Mxui backup create

# List backups
Mxui backup list

# Restore backup
Mxui backup restore backup_20240101.tar.gz
```

---

## 🌍 Multi-Language

MR-X supports multiple languages:

- 🇬🇧 English
- 🇮🇷 Persian (فارسی)
- 🇨🇳 Chinese (中文)
- 🇷🇺 Russian (Русский)

Change language in panel settings or config:

```yaml
panel:
  language: "en"  # en, fa, zh, ru
```

---

## 🛠️ Troubleshooting

### Common Issues

**Panel not accessible:**
```bash
# Check service status
systemctl status Mxui

# Check port
ss -tlnp | grep 8443

# Check firewall
ufw status
```

**Database errors:**
```bash
# Check database
sqlite3 /opt/Mxui/data/Mxui.db ".tables"

# Repair database
Mxui db repair
```

**Core not starting:**
```bash
# Check Xray logs
tail -f /opt/Mxui/logs/xray_error.log

# Validate config
/opt/Mxui/bin/xray -test -config /opt/Mxui/data/xray_config.json
```

### Logs

```bash
# Panel logs
tail -f /opt/Mxui/logs/Mxui.log

# Access logs
tail -f /opt/Mxui/logs/access.log

# Xray logs
tail -f /opt/Mxui/logs/xray_access.log
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/MR-X-Panel/MR-X.git
cd MR-X

# Install dependencies
make deps

# Run in development mode
make dev

# Run tests
make test

# Build
make build
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Xray-core](https://github.com/XTLS/Xray-core)
- [Sing-box](https://github.com/SagerNet/sing-box)
- [Clash Meta](https://github.com/MetaCubeX/Clash.Meta)
- [Loyalsoldier](https://github.com/Loyalsoldier/v2ray-rules-dat) for GeoIP data
- All contributors and supporters

---

## 📞 Support

- **GitHub Issues**: [Report bugs](https://github.com/MR-X-Panel/MR-X/issues)
- **Telegram**: [@MXUI_Support](https://t.me/MXUI_Support)
- **Documentation**: [Wiki](https://github.com/MR-X-Panel/MR-X/wiki)

---

<p align="center">
  Made with ❤️ by MR-X Team
</p>

<p align="center">
  <a href="#mr-x-vpn-panel">⬆️ Back to Top</a>
</p>
