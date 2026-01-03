#!/bin/bash

#========================================================
# MXUI VPN Panel - Professional Installation Script
# Version: 2.0.0
# GitHub: https://github.com/matin-x/mxui
#========================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

# Configuration
VERSION="2.0.0"
INSTALL_DIR="/opt/mxui"
CONFIG_DIR="$INSTALL_DIR/config"
DATA_DIR="$INSTALL_DIR/data"
LOG_DIR="$INSTALL_DIR/logs"
WEB_DIR="$INSTALL_DIR/web"
BIN_DIR="$INSTALL_DIR/bin"
XRAY_DIR="$INSTALL_DIR/xray"
BACKUP_DIR="$INSTALL_DIR/backups"
TMP_DIR="/tmp/mxui_install"
REPORT_FILE="/tmp/mxui_report_$(date +%Y%m%d_%H%M%S).log"

GITHUB_REPO="matin-x/mxui"
SERVICE_NAME="mxui"
XRAY_SERVICE="mxui-xray"

DEFAULT_ADMIN="admin"
DEFAULT_PORT=8443
DEFAULT_SUB_PORT=8080

#========================================================
# Logging
#========================================================

log() { echo "[$(date '+%H:%M:%S')] $1" >> "$REPORT_FILE"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; log "[INFO] $1"; }
ok() { echo -e "${GREEN}[OK]${NC} $1"; log "[OK] $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; log "[WARN] $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; log "[ERROR] $1"; }

banner() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
  ╔═══════════════════════════════════════════════════════════╗
  ║   ███╗   ███╗██╗  ██╗██╗   ██╗██╗    Professional VPN     ║
  ║   ████╗ ████║╚██╗██╔╝██║   ██║██║    Management Panel     ║
  ║   ██╔████╔██║ ╚███╔╝ ██║   ██║██║    v2.0.0               ║
  ║   ██║╚██╔╝██║ ██╔██╗ ██║   ██║██║                         ║
  ║   ██║ ╚═╝ ██║██╔╝ ██╗╚██████╔╝██║    github.com/matin-x   ║
  ║   ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝                         ║
  ╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

#========================================================
# System Checks
#========================================================

check_root() {
    [[ $EUID -ne 0 ]] && { error "Run as root (sudo)"; exit 1; }
    ok "Root access"
}

check_os() {
    [[ ! -f /etc/os-release ]] && { error "Unknown OS"; exit 1; }
    . /etc/os-release
    OS=$ID; OS_VER=$VERSION_ID

    case $OS in
        ubuntu|debian) PKG="apt-get" ;;
        centos|rhel|rocky|almalinux|fedora) PKG="dnf" ;;
        *) error "Unsupported OS: $OS"; exit 1 ;;
    esac
    ok "OS: $OS $OS_VER"
}

check_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) GO_ARCH="amd64"; XRAY_ARCH="64" ;;
        aarch64) GO_ARCH="arm64"; XRAY_ARCH="arm64-v8a" ;;
        *) error "Unsupported arch: $ARCH"; exit 1 ;;
    esac
    ok "Arch: $ARCH"
}

check_network() {
    ping -c1 google.com &>/dev/null || ping -c1 github.com &>/dev/null || { error "No internet"; exit 1; }
    PUBLIC_IP=$(curl -s --max-time 5 ip.sb 2>/dev/null || curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    ok "IP: $PUBLIC_IP"
}

check_ports() {
    for p in $DEFAULT_PORT $DEFAULT_SUB_PORT; do
        if ss -tuln | grep -q ":$p "; then
            warn "Port $p in use"
        fi
    done
}

run_diagnostics() {
    banner
    echo -e "\n${BOLD}System Diagnostics${NC}\n"

    echo -e "${CYAN}System:${NC}"
    echo "  OS: $OS $OS_VER"
    echo "  Kernel: $(uname -r)"
    echo "  Arch: $ARCH"
    echo "  RAM: $(free -h | awk '/Mem/{print $2}')"
    echo "  Disk: $(df -h / | awk 'NR==2{print $4}') free"
    echo "  CPU: $(nproc) cores"

    echo -e "\n${CYAN}Network:${NC}"
    echo "  Public IP: $PUBLIC_IP"
    echo "  Local IP: $(hostname -I | awk '{print $1}')"

    echo -e "\n${CYAN}Services:${NC}"
    systemctl is-active --quiet mxui && echo "  MXUI: ${GREEN}Running${NC}" || echo "  MXUI: ${RED}Stopped${NC}"
    systemctl is-active --quiet mxui-xray && echo "  Xray: ${GREEN}Running${NC}" || echo "  Xray: ${RED}Stopped${NC}"

    echo -e "\n${CYAN}Ports:${NC}"
    for p in 80 443 8443 8080; do
        ss -tuln | grep -q ":$p " && echo "  $p: ${RED}In Use${NC}" || echo "  $p: ${GREEN}Free${NC}"
    done

    echo -e "\nReport: $REPORT_FILE\n"
}

#========================================================
# Installation
#========================================================

install_deps() {
    info "Installing dependencies..."

    case $PKG in
        apt-get)
            apt-get update -y 2>/dev/null || warn "Some repos failed"
            DEBIAN_FRONTEND=noninteractive apt-get install -y curl wget git unzip tar gcc make sqlite3 jq ca-certificates cron >/dev/null 2>&1
            ;;
        dnf)
            dnf install -y curl wget git unzip tar gcc make sqlite jq ca-certificates cronie >/dev/null 2>&1
            ;;
    esac
    ok "Dependencies installed"
}

install_go() {
    info "Installing Go..."

    if command -v go &>/dev/null; then
        GO_VER=$(go version | grep -oP '\d+\.\d+' | head -1)
        if [[ $(echo "$GO_VER >= 1.22" | bc -l 2>/dev/null) == 1 ]] 2>/dev/null || [[ "$GO_VER" > "1.21" ]]; then
            ok "Go $GO_VER exists"
            return
        fi
    fi

    wget -q "https://go.dev/dl/go1.22.5.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz

    grep -q '/usr/local/go/bin' /etc/profile || echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin

    ok "Go installed"
}

create_dirs() {
    info "Creating directories..."
    mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$WEB_DIR" "$BIN_DIR" "$XRAY_DIR" "$BACKUP_DIR" "$TMP_DIR"
    chmod 700 "$CONFIG_DIR"
    ok "Directories created"
}

download_source() {
    info "Downloading source..."
    cd "$TMP_DIR"
    rm -rf mxui

    if command -v git &>/dev/null; then
        git clone --depth 1 "https://github.com/$GITHUB_REPO.git" mxui 2>/dev/null || {
            wget -q "https://github.com/$GITHUB_REPO/archive/main.zip" -O mxui.zip
            unzip -q mxui.zip && mv mxui-main mxui && rm mxui.zip
        }
    else
        wget -q "https://github.com/$GITHUB_REPO/archive/main.zip" -O mxui.zip
        unzip -q mxui.zip && mv mxui-main mxui && rm mxui.zip
    fi
    ok "Source downloaded"
}

build_mxui() {
    info "Building MXUI..."
    cd "$TMP_DIR/mxui"

    export PATH=$PATH:/usr/local/go/bin
    export CGO_ENABLED=1

    go mod tidy 2>/dev/null || true

    if go build -ldflags "-s -w" -o mxui ./cmd/mxui 2>&1 | tee -a "$REPORT_FILE"; then
        ok "Build complete ($(ls -lh mxui | awk '{print $5}'))"
    else
        error "Build failed - check $REPORT_FILE"
        exit 1
    fi
}

install_mxui() {
    info "Installing MXUI..."
    cp "$TMP_DIR/mxui/mxui" "$BIN_DIR/mxui"
    chmod +x "$BIN_DIR/mxui"

    [[ -d "$TMP_DIR/mxui/Web" ]] && cp -r "$TMP_DIR/mxui/Web/"* "$WEB_DIR/"
    ok "MXUI installed"
}

install_xray() {
    info "Installing Xray..."

    XRAY_VER=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
    [[ -z "$XRAY_VER" ]] && XRAY_VER="v24.12.31"

    wget -q "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-${XRAY_ARCH}.zip" -O /tmp/xray.zip
    unzip -o -q /tmp/xray.zip -d "$XRAY_DIR"
    chmod +x "$XRAY_DIR/xray"
    rm /tmp/xray.zip

    # GeoIP
    wget -q "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" -O "$XRAY_DIR/geoip.dat" 2>/dev/null || true
    wget -q "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" -O "$XRAY_DIR/geosite.dat" 2>/dev/null || true

    ok "Xray $XRAY_VER installed"
}

create_config() {
    info "Creating config..."

    ADMIN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12)
    JWT_SECRET=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)

    cat > "$CONFIG_DIR/config.yaml" << EOF
server:
  host: "0.0.0.0"
  port: $DEFAULT_PORT
  tls_port: 443
  ssl_enabled: false
  read_timeout: 30
  write_timeout: 30

database:
  type: sqlite
  path: "$DATA_DIR/mxui.db"

security:
  jwt_secret: "$JWT_SECRET"
  jwt_expiry: 1440
  rate_limit_enabled: true
  brute_force_enabled: true

admin:
  username: "$DEFAULT_ADMIN"
  password: "$ADMIN_PASS"

panel:
  title: "MXUI Panel"
  login_path: "/dashboard"
  language: "fa"
  theme: "dark"
  decoy_enabled: true
  decoy_type: "nginx"

protocols:
  xray_enabled: true
  xray_path: "$XRAY_DIR/xray"
  xray_config_path: "$DATA_DIR/xray_config.json"
  xray_api_port: 62789

logging:
  level: info
  path: "$LOG_DIR/mxui.log"
EOF
    chmod 600 "$CONFIG_DIR/config.yaml"

    # Xray config
    cat > "$DATA_DIR/xray_config.json" << 'EOF'
{
  "log": {"loglevel": "warning"},
  "api": {"tag": "api", "services": ["HandlerService", "LoggerService", "StatsService"]},
  "inbounds": [{"tag": "api", "listen": "127.0.0.1", "port": 62789, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}}],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "blocked"}],
  "policy": {"levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true}}, "system": {"statsInboundUplink": true, "statsInboundDownlink": true}},
  "routing": {"rules": [{"inboundTag": ["api"], "outboundTag": "api", "type": "field"}]},
  "stats": {}
}
EOF
    ok "Config created"
}

create_services() {
    info "Creating services..."

    cat > /etc/systemd/system/mxui.service << EOF
[Unit]
Description=MXUI VPN Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$BIN_DIR/mxui --config $CONFIG_DIR/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
Environment=MXUI_CONFIG=$CONFIG_DIR/config.yaml

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/mxui-xray.service << EOF
[Unit]
Description=MXUI Xray
After=network.target mxui.service

[Service]
Type=simple
User=root
ExecStart=$XRAY_DIR/xray run -config $DATA_DIR/xray_config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
Environment=XRAY_LOCATION_ASSET=$XRAY_DIR

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    ok "Services created"
}

create_cli() {
    info "Creating CLI..."

    cat > /usr/local/bin/mxui << 'EOFCLI'
#!/bin/bash
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
INSTALL_DIR="/opt/mxui"
CONFIG="$INSTALL_DIR/config/config.yaml"

case "$1" in
    start)
        systemctl start mxui mxui-xray
        echo -e "${GREEN}Started${NC}"
        ;;
    stop)
        systemctl stop mxui mxui-xray
        echo -e "${YELLOW}Stopped${NC}"
        ;;
    restart)
        systemctl restart mxui mxui-xray
        echo -e "${GREEN}Restarted${NC}"
        ;;
    status)
        echo -e "\n${CYAN}MXUI Status${NC}"
        systemctl is-active --quiet mxui && echo -e "Panel: ${GREEN}Running${NC}" || echo -e "Panel: ${RED}Stopped${NC}"
        systemctl is-active --quiet mxui-xray && echo -e "Xray:  ${GREEN}Running${NC}" || echo -e "Xray:  ${RED}Stopped${NC}"
        echo ""
        ;;
    log|logs)
        journalctl -u mxui -u mxui-xray -f -n ${2:-50}
        ;;
    info)
        echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        PORT=$(grep -E "^\s*port:" "$CONFIG" | head -1 | awk '{print $2}')
        USER=$(grep -E "^\s*username:" "$CONFIG" | head -1 | awk '{print $2}' | tr -d '"')
        PASS=$(grep -E "^\s*password:" "$CONFIG" | head -1 | awk '{print $2}' | tr -d '"')
        IP=$(curl -s ip.sb 2>/dev/null || hostname -I | awk '{print $1}')
        echo -e "  Panel:    ${GREEN}http://${IP}:${PORT}/dashboard${NC}"
        echo -e "  Username: ${GREEN}${USER}${NC}"
        echo -e "  Password: ${GREEN}${PASS}${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
        ;;
    update)
        bash <(curl -sL https://raw.githubusercontent.com/matin-x/mxui/main/install.sh)
        ;;
    uninstall)
        read -p "Remove MXUI? (y/N): " c
        [[ "$c" =~ ^[Yy]$ ]] && {
            systemctl stop mxui mxui-xray 2>/dev/null
            systemctl disable mxui mxui-xray 2>/dev/null
            rm -rf /opt/mxui /etc/systemd/system/mxui*.service /usr/local/bin/mxui
            systemctl daemon-reload
            echo -e "${GREEN}Uninstalled${NC}"
        }
        ;;
    backup)
        F="$INSTALL_DIR/backups/backup_$(date +%Y%m%d_%H%M%S).tar.gz"
        tar -czf "$F" -C "$INSTALL_DIR" config data 2>/dev/null
        echo -e "${GREEN}Backup: $F${NC}"
        ;;
    *)
        echo -e "\n${CYAN}MXUI Panel v2.0${NC}\n"
        echo "Usage: mxui <command>"
        echo ""
        echo "Commands:"
        echo "  start      Start services"
        echo "  stop       Stop services"
        echo "  restart    Restart services"
        echo "  status     Show status"
        echo "  info       Show panel info"
        echo "  log [n]    View logs"
        echo "  backup     Create backup"
        echo "  update     Update MXUI"
        echo "  uninstall  Remove MXUI"
        echo ""
        ;;
esac
EOFCLI
    chmod +x /usr/local/bin/mxui
    ok "CLI created"
}

start_services() {
    info "Starting services..."

    systemctl enable mxui mxui-xray 2>/dev/null
    systemctl start mxui-xray 2>/dev/null || true
    sleep 1
    systemctl start mxui
    sleep 2

    if systemctl is-active --quiet mxui; then
        ok "MXUI started"
    else
        error "Failed to start MXUI"
        journalctl -u mxui -n 20 --no-pager
        exit 1
    fi
}

cleanup() {
    rm -rf "$TMP_DIR"
}

show_result() {
    ADMIN_PASS=$(grep -E "^\s*password:" "$CONFIG_DIR/config.yaml" | head -1 | awk '{print $2}' | tr -d '"')

    echo -e "\n${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}       MXUI Installation Complete!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${BOLD}Panel URL:${NC}  ${CYAN}http://${PUBLIC_IP}:${DEFAULT_PORT}/dashboard${NC}"
    echo -e "  ${BOLD}Username:${NC}   ${GREEN}${DEFAULT_ADMIN}${NC}"
    echo -e "  ${BOLD}Password:${NC}   ${GREEN}${ADMIN_PASS}${NC}"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  Commands: ${CYAN}mxui status${NC} | ${CYAN}mxui info${NC} | ${CYAN}mxui log${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  Report: ${CYAN}$REPORT_FILE${NC}"
    echo ""
}

#========================================================
# Main Installation
#========================================================

install_master() {
    banner
    echo "[$(date)]" > "$REPORT_FILE"

    check_root
    check_os
    check_arch
    check_network
    check_ports

    # Check existing
    if [[ -d "$INSTALL_DIR" ]]; then
        warn "Existing installation found"
        read -p "Reinstall? (y/N): " c
        [[ ! "$c" =~ ^[Yy]$ ]] && exit 0
        systemctl stop mxui mxui-xray 2>/dev/null || true
    fi

    install_deps
    install_go
    create_dirs
    download_source
    build_mxui
    install_mxui
    install_xray
    create_config
    create_services
    create_cli
    start_services
    cleanup
    show_result
}

install_node() {
    banner
    echo -e "${YELLOW}Node Installation${NC}\n"

    read -p "Master Address (http://ip:port): " MASTER_ADDR
    read -p "Master Token: " MASTER_TOKEN

    [[ -z "$MASTER_ADDR" || -z "$MASTER_TOKEN" ]] && { error "Required"; exit 1; }

    check_root
    check_os
    check_arch
    check_network

    install_deps
    create_dirs
    install_xray

    cat > "$CONFIG_DIR/node.yaml" << EOF
mode: node
master_address: "$MASTER_ADDR"
master_token: "$MASTER_TOKEN"
EOF

    cat > /etc/systemd/system/mxui-node.service << EOF
[Unit]
Description=MXUI Node
After=network.target

[Service]
Type=simple
ExecStart=$XRAY_DIR/xray run -config $DATA_DIR/xray_config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable mxui-node

    echo -e "\n${GREEN}Node installed. Will sync from master.${NC}\n"
}

show_menu() {
    banner
    echo -e "${BOLD}Installation Options:${NC}\n"
    echo -e "  ${GREEN}1)${NC} Install Master Panel"
    echo -e "  ${GREEN}2)${NC} Install Node Only"
    echo -e "  ${GREEN}3)${NC} Run Diagnostics"
    echo -e "  ${GREEN}4)${NC} Update"
    echo -e "  ${GREEN}5)${NC} Uninstall"
    echo -e "  ${GREEN}0)${NC} Exit"
    echo ""
    read -p "Choice [1]: " choice

    case ${choice:-1} in
        1) install_master ;;
        2) install_node ;;
        3) check_os; check_arch; check_network; run_diagnostics ;;
        4) install_master ;;
        5) mxui uninstall 2>/dev/null || { systemctl stop mxui mxui-xray 2>/dev/null; rm -rf /opt/mxui /usr/local/bin/mxui /etc/systemd/system/mxui*.service; systemctl daemon-reload; echo "Removed"; } ;;
        0) exit 0 ;;
        *) error "Invalid"; exit 1 ;;
    esac
}

# Main
case "${1:-}" in
    --master|-m) install_master ;;
    --node|-n) install_node ;;
    --diag|-d) check_os; check_arch; check_network; run_diagnostics ;;
    --update|-u) install_master ;;
    --help|-h)
        echo "MXUI Installer"
        echo ""
        echo "Options:"
        echo "  --master, -m   Install master"
        echo "  --node, -n     Install node"
        echo "  --diag, -d     Diagnostics"
        echo "  --update, -u   Update"
        echo ""
        ;;
    "") show_menu ;;
    *) error "Unknown: $1"; exit 1 ;;
esac
