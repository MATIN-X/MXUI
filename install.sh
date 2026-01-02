#!/bin/bash

#========================================================
# MXUI VPN Panel - Installation Script
# Version: 2.0.0
# Author: MXUI Team
# GitHub: https://github.com/matin-x/mxui
#========================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/mxui"
CONFIG_DIR="$INSTALL_DIR/config"
DATA_DIR="$INSTALL_DIR/data"
LOG_DIR="$INSTALL_DIR/logs"
WEB_DIR="$INSTALL_DIR/web"
BIN_DIR="$INSTALL_DIR/bin"
XRAY_DIR="$INSTALL_DIR/xray"
BACKUP_DIR="$INSTALL_DIR/backups"

GITHUB_REPO="matin-x/mxui"
SERVICE_NAME="mxui"
XRAY_SERVICE_NAME="mxui-xray"

# Default admin credentials
DEFAULT_ADMIN_USER="admin"
DEFAULT_ADMIN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12)
DEFAULT_PORT=8443

#========================================================
# Helper Functions
#========================================================

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║          ███╗   ███╗██╗  ██╗██╗   ██╗██╗                      ║"
    echo "║          ████╗ ████║╚██╗██╔╝██║   ██║██║                      ║"
    echo "║          ██╔████╔██║ ╚███╔╝ ██║   ██║██║                      ║"
    echo "║          ██║╚██╔╝██║ ██╔██╗ ██║   ██║██║                      ║"
    echo "║          ██║ ╚═╝ ██║██╔╝ ██╗╚██████╔╝██║                      ║"
    echo "║          ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝                      ║"
    echo "║                                                               ║"
    echo "║          Professional VPN Management Panel                    ║"
    echo "║          Version: 2.0.0                                       ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi

    case $OS in
        ubuntu|debian)
            log_info "Detected: $OS $VERSION"
            ;;
        centos|rhel|fedora|almalinux|rocky)
            log_info "Detected: $OS $VERSION"
            ;;
        *)
            log_warning "Untested OS: $OS. Proceeding anyway..."
            ;;
    esac
}

check_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)
            ARCH="64"
            GO_ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64-v8a"
            GO_ARCH="arm64"
            ;;
        armv7l)
            ARCH="arm32-v7a"
            GO_ARCH="arm"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    log_info "Architecture: $ARCH"
}

#========================================================
# Installation Functions
#========================================================

install_dependencies() {
    log_info "Installing dependencies..."

    if command -v apt-get &> /dev/null; then
        apt-get update -y
        apt-get install -y curl wget git unzip tar gcc make sqlite3 jq
    elif command -v yum &> /dev/null; then
        yum update -y
        yum install -y curl wget git unzip tar gcc make sqlite jq
    elif command -v dnf &> /dev/null; then
        dnf update -y
        dnf install -y curl wget git unzip tar gcc make sqlite jq
    fi

    log_success "Dependencies installed"
}

install_go() {
    log_info "Checking Go installation..."

    GO_VERSION="1.22.5"

    if command -v go &> /dev/null; then
        CURRENT_GO=$(go version | grep -oP '\d+\.\d+' | head -1)
        if [[ $(echo "$CURRENT_GO >= 1.22" | bc -l 2>/dev/null || echo "0") == "1" ]] || [[ "$CURRENT_GO" == "1.22" ]] || [[ "$CURRENT_GO" > "1.22" ]]; then
            log_success "Go $CURRENT_GO already installed"
            return
        fi
    fi

    log_info "Installing Go $GO_VERSION..."

    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz

    # Add Go to PATH
    if ! grep -q '/usr/local/go/bin' /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    export PATH=$PATH:/usr/local/go/bin

    log_success "Go $GO_VERSION installed"
}

create_directories() {
    log_info "Creating directories..."

    mkdir -p "$BIN_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$WEB_DIR"
    mkdir -p "$XRAY_DIR"
    mkdir -p "$BACKUP_DIR"

    chmod 755 "$INSTALL_DIR"
    chmod 700 "$DATA_DIR" "$LOG_DIR" "$BACKUP_DIR"

    log_success "Directories created"
}

download_source() {
    log_info "Downloading MXUI source..."

    cd /tmp
    rm -rf mxui

    if git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" mxui 2>/dev/null; then
        log_success "Source downloaded via git"
    else
        log_info "Git failed, trying wget..."
        wget -q "https://github.com/${GITHUB_REPO}/archive/refs/heads/main.zip" -O mxui.zip
        unzip -q mxui.zip
        mv mxui-main mxui
        rm mxui.zip
        log_success "Source downloaded via wget"
    fi
}

build_mxui() {
    log_info "Building MXUI..."

    cd /tmp/mxui
    export PATH=$PATH:/usr/local/go/bin
    export CGO_ENABLED=1

    go mod download 2>/dev/null || true
    go mod tidy 2>/dev/null || true

    if go build -ldflags "-s -w" -o mxui ./cmd/mxui; then
        log_success "Build completed"
    else
        log_error "Build failed!"
        exit 1
    fi
}

install_mxui() {
    log_info "Installing MXUI..."

    # Copy binary
    cp /tmp/mxui/mxui "$BIN_DIR/mxui"
    chmod +x "$BIN_DIR/mxui"

    # Copy web files
    cp -r /tmp/mxui/Web/* "$WEB_DIR/"

    # Create symlink
    ln -sf "$BIN_DIR/mxui" /usr/local/bin/mxui

    log_success "MXUI installed"
}

install_xray() {
    log_info "Installing Xray core..."

    XRAY_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep '"tag_name"' | cut -d'"' -f4)

    if [[ -z "$XRAY_VERSION" ]]; then
        XRAY_VERSION="v1.8.24"
    fi

    log_info "Downloading Xray $XRAY_VERSION..."

    wget -q "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${ARCH}.zip" -O /tmp/xray.zip

    unzip -o -q /tmp/xray.zip -d "$XRAY_DIR"
    chmod +x "$XRAY_DIR/xray"
    rm /tmp/xray.zip

    # Download GeoIP files
    log_info "Downloading GeoIP data..."
    wget -q "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" -O "$XRAY_DIR/geoip.dat" || true
    wget -q "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" -O "$XRAY_DIR/geosite.dat" || true

    log_success "Xray installed"
}

create_config() {
    log_info "Creating configuration..."

    cat > "$CONFIG_DIR/config.yaml" << EOF
# MXUI Configuration
# Generated: $(date)

server:
  host: "0.0.0.0"
  port: $DEFAULT_PORT
  ssl_enabled: false

database:
  type: "sqlite"
  path: "$DATA_DIR/mxui.db"

admin:
  username: "$DEFAULT_ADMIN_USER"
  password: "$DEFAULT_ADMIN_PASS"

panel:
  title: "MXUI Panel"
  login_path: "/dashboard"
  language: "fa"

logging:
  level: "info"
  path: "$LOG_DIR/mxui.log"

xray:
  path: "$XRAY_DIR/xray"
  config_path: "$DATA_DIR/xray_config.json"
  asset_path: "$XRAY_DIR"
EOF

    chmod 600 "$CONFIG_DIR/config.yaml"
    log_success "Configuration created"
}

create_services() {
    log_info "Creating systemd services..."

    # MXUI service
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=MXUI VPN Panel
Documentation=https://github.com/${GITHUB_REPO}
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

    # Xray service
    cat > /etc/systemd/system/${XRAY_SERVICE_NAME}.service << EOF
[Unit]
Description=MXUI Xray Service
After=network.target ${SERVICE_NAME}.service

[Service]
Type=simple
User=root
ExecStart=$XRAY_DIR/xray run -config $DATA_DIR/xray_config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Services created"
}

create_cli_command() {
    log_info "Creating CLI command..."

    cat > /usr/local/bin/mxui << 'MXUICLI'
#!/bin/bash

SERVICE_NAME="mxui"
XRAY_SERVICE="mxui-xray"
INSTALL_DIR="/opt/mxui"
CONFIG_FILE="$INSTALL_DIR/config/config.yaml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

case "$1" in
    start)
        systemctl start $SERVICE_NAME
        systemctl start $XRAY_SERVICE 2>/dev/null || true
        echo -e "${GREEN}MXUI started${NC}"
        ;;
    stop)
        systemctl stop $SERVICE_NAME
        systemctl stop $XRAY_SERVICE 2>/dev/null || true
        echo -e "${YELLOW}MXUI stopped${NC}"
        ;;
    restart)
        systemctl restart $SERVICE_NAME
        systemctl restart $XRAY_SERVICE 2>/dev/null || true
        echo -e "${GREEN}MXUI restarted${NC}"
        ;;
    status)
        systemctl status $SERVICE_NAME --no-pager
        ;;
    log)
        journalctl -u $SERVICE_NAME -f --no-pager
        ;;
    info)
        echo ""
        echo "=========================================="
        echo "           MXUI Panel Info"
        echo "=========================================="
        PORT=$(grep -E "^\s*port:" $CONFIG_FILE 2>/dev/null | awk '{print $2}' | head -1)
        USER=$(grep -E "^\s*username:" $CONFIG_FILE 2>/dev/null | awk '{print $2}' | head -1 | tr -d '"')
        PASS=$(grep -E "^\s*password:" $CONFIG_FILE 2>/dev/null | awk '{print $2}' | head -1 | tr -d '"')
        IP=$(curl -s ip.sb 2>/dev/null || hostname -I | awk '{print $1}')
        echo ""
        echo -e "  Panel URL: ${GREEN}http://${IP}:${PORT:-8443}/dashboard${NC}"
        echo ""
        echo -e "  Username:  ${GREEN}${USER:-admin}${NC}"
        echo -e "  Password:  ${GREEN}${PASS:-admin}${NC}"
        echo ""
        echo "=========================================="
        echo ""
        ;;
    update)
        echo -e "${YELLOW}Updating MXUI...${NC}"
        bash <(curl -sL https://raw.githubusercontent.com/matin-x/mxui/main/install.sh)
        ;;
    uninstall)
        echo -e "${RED}Uninstalling MXUI...${NC}"
        systemctl stop $SERVICE_NAME 2>/dev/null || true
        systemctl stop $XRAY_SERVICE 2>/dev/null || true
        systemctl disable $SERVICE_NAME 2>/dev/null || true
        systemctl disable $XRAY_SERVICE 2>/dev/null || true
        rm -f /etc/systemd/system/${SERVICE_NAME}.service
        rm -f /etc/systemd/system/${XRAY_SERVICE}.service
        systemctl daemon-reload
        rm -rf $INSTALL_DIR
        rm -f /usr/local/bin/mxui
        echo -e "${GREEN}MXUI uninstalled successfully${NC}"
        ;;
    *)
        echo ""
        echo "MXUI Panel Management"
        echo ""
        echo "Usage: mxui {command}"
        echo ""
        echo "Commands:"
        echo "  start      Start MXUI"
        echo "  stop       Stop MXUI"
        echo "  restart    Restart MXUI"
        echo "  status     Show status"
        echo "  log        View logs"
        echo "  info       Show panel info"
        echo "  update     Update MXUI"
        echo "  uninstall  Uninstall MXUI"
        echo ""
        ;;
esac
MXUICLI

    chmod +x /usr/local/bin/mxui
    log_success "CLI command created"
}

start_services() {
    log_info "Starting services..."

    systemctl enable $SERVICE_NAME
    systemctl start $SERVICE_NAME

    sleep 2

    if systemctl is-active --quiet $SERVICE_NAME; then
        log_success "MXUI started successfully"
    else
        log_error "Failed to start MXUI"
        journalctl -u $SERVICE_NAME -n 20 --no-pager
        exit 1
    fi
}

cleanup() {
    log_info "Cleaning up..."
    rm -rf /tmp/mxui
    log_success "Cleanup completed"
}

show_result() {
    IP=$(curl -s ip.sb 2>/dev/null || hostname -I | awk '{print $1}')

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║            MXUI Installation Completed!                       ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Panel URL:  ${CYAN}http://${IP}:${DEFAULT_PORT}/dashboard${NC}"
    echo ""
    echo -e "  Username:   ${YELLOW}${DEFAULT_ADMIN_USER}${NC}"
    echo -e "  Password:   ${YELLOW}${DEFAULT_ADMIN_PASS}${NC}"
    echo ""
    echo -e "  ${RED}Please change password after first login!${NC}"
    echo ""
    echo "  Commands:"
    echo "    mxui start      - Start panel"
    echo "    mxui stop       - Stop panel"
    echo "    mxui restart    - Restart panel"
    echo "    mxui status     - Show status"
    echo "    mxui log        - View logs"
    echo "    mxui info       - Show panel info"
    echo ""
}

#========================================================
# Main Installation
#========================================================

install() {
    print_banner

    check_root
    check_os
    check_arch

    install_dependencies
    install_go
    create_directories
    download_source
    build_mxui
    install_mxui
    install_xray
    create_config
    create_services
    create_cli_command
    start_services
    cleanup

    show_result
}

#========================================================
# Entry Point
#========================================================

case "${1:-install}" in
    install|update)
        install
        ;;
    uninstall)
        check_root
        systemctl stop $SERVICE_NAME 2>/dev/null || true
        systemctl stop $XRAY_SERVICE_NAME 2>/dev/null || true
        systemctl disable $SERVICE_NAME 2>/dev/null || true
        systemctl disable $XRAY_SERVICE_NAME 2>/dev/null || true
        rm -f /etc/systemd/system/${SERVICE_NAME}.service
        rm -f /etc/systemd/system/${XRAY_SERVICE_NAME}.service
        systemctl daemon-reload
        rm -rf $INSTALL_DIR
        rm -f /usr/local/bin/mxui
        echo -e "${GREEN}MXUI uninstalled successfully${NC}"
        ;;
    *)
        echo "Usage: $0 {install|update|uninstall}"
        exit 1
        ;;
esac
