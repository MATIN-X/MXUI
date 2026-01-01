#!/bin/bash

#═══════════════════════════════════════════════════════════════════════════════
#  MXUI Panel Installer v2.0.0
#  Simple Installation Script - Similar to 3x-ui
#  GitHub: https://github.com/matin-x/mxui
#═══════════════════════════════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Variables
PROJ_NAME="MXUI"
VERSION="2.0.0"
REPO_URL="https://github.com/matin-x/mxui"
INSTALL_DIR="/opt/mxui"
CONFIG_DIR="/opt/mxui/config"
DATA_DIR="/opt/mxui/data"
LOG_DIR="/opt/mxui/logs"
BIN_DIR="/opt/mxui/bin"
WEB_DIR="/opt/mxui/web"
XRAY_DIR="/opt/mxui/xray"
SERVICE_FILE="/etc/systemd/system/mxui.service"
XRAY_SERVICE="/etc/systemd/system/mxui-xray.service"
CLI_PATH="/usr/local/bin/mxui"

# Detect system
ARCH=$(uname -m)
case $ARCH in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) ARCH="amd64" ;;
esac

OS_TYPE=""
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    OS_TYPE=$ID
fi

#═══════════════════════════════════════════════════════════════════════════════
# FUNCTIONS
#═══════════════════════════════════════════════════════════════════════════════

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║   ███╗   ███╗██╗  ██╗██╗   ██╗██╗                             ║"
    echo "║   ████╗ ████║╚██╗██╔╝██║   ██║██║                             ║"
    echo "║   ██╔████╔██║ ╚███╔╝ ██║   ██║██║                             ║"
    echo "║   ██║╚██╔╝██║ ██╔██╗ ██║   ██║██║                             ║"
    echo "║   ██║ ╚═╝ ██║██╔╝ ██╗╚██████╔╝██║                             ║"
    echo "║   ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝                             ║"
    echo "║              Professional VPN Panel v${VERSION}                  ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_system() {
    log_info "Checking system requirements..."

    # Check OS
    if [[ "$OS_TYPE" != "ubuntu" && "$OS_TYPE" != "debian" && "$OS_TYPE" != "centos" && "$OS_TYPE" != "fedora" && "$OS_TYPE" != "almalinux" && "$OS_TYPE" != "rocky" ]]; then
        log_warn "Unsupported OS: $OS_TYPE. Installation may fail."
    fi

    # Check architecture
    log_info "Architecture: $ARCH"
    log_info "OS: $OS_TYPE"

    log_success "System check passed"
}

install_dependencies() {
    log_info "Installing dependencies..."

    case $OS_TYPE in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq curl wget git unzip jq sqlite3 ca-certificates gnupg
            ;;
        centos|rhel|almalinux|rocky|fedora)
            if command -v dnf &>/dev/null; then
                dnf install -y -q curl wget git unzip jq sqlite ca-certificates
            else
                yum install -y -q curl wget git unzip jq sqlite ca-certificates
            fi
            ;;
    esac

    log_success "Dependencies installed"
}

install_go() {
    if command -v go &>/dev/null; then
        log_info "Go already installed: $(go version)"
        return 0
    fi

    log_info "Installing Go..."

    GO_VERSION="1.22.0"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz

    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh

    log_success "Go installed"
}

download_and_build() {
    log_info "Downloading MXUI source..."

    cd /tmp
    rm -rf mxui mxui.zip

    # Try git clone first
    if git clone --depth 1 "$REPO_URL" mxui 2>/dev/null; then
        log_success "Source downloaded via git"
    else
        # Fallback to zip
        wget -q "${REPO_URL}/archive/refs/heads/main.zip" -O mxui.zip
        unzip -q mxui.zip
        mv mxui-main mxui
        log_success "Source downloaded via zip"
    fi

    cd mxui

    log_info "Building MXUI binary..."
    export PATH=$PATH:/usr/local/go/bin
    export CGO_ENABLED=1

    go mod download
    go mod tidy

    # Build with simple flags to avoid linker issues
    go build -ldflags "-s -w" -o mxui ./cmd/mxui

    if [[ ! -f mxui ]]; then
        log_error "Build failed!"
        exit 1
    fi

    log_success "Build completed"
}

create_directories() {
    log_info "Creating directories..."

    mkdir -p "$BIN_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$WEB_DIR"
    mkdir -p "$XRAY_DIR"
    mkdir -p "$INSTALL_DIR/backups"

    log_success "Directories created"
}

install_files() {
    log_info "Installing files..."

    cd /tmp/mxui

    # Copy binary
    cp mxui "$BIN_DIR/"
    chmod +x "$BIN_DIR/mxui"

    # Copy web files
    if [[ -d Web ]]; then
        cp -r Web/* "$WEB_DIR/"
    fi

    log_success "Files installed"
}

install_xray() {
    log_info "Installing Xray core..."

    cd /tmp

    # Convert arch for Xray
    local xray_arch="64"
    [[ "$ARCH" == "arm64" ]] && xray_arch="arm64-v8a"

    wget -q "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${xray_arch}.zip" -O xray.zip

    if [[ -f xray.zip ]]; then
        unzip -qo xray.zip -d "$XRAY_DIR/"
        chmod +x "$XRAY_DIR/xray"
        rm xray.zip
        log_success "Xray installed"
    else
        log_warn "Xray download failed, skipping..."
    fi

    # Download geo files
    log_info "Downloading geo files..."
    mkdir -p "$DATA_DIR/geo"
    wget -q "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" -O "$DATA_DIR/geo/geoip.dat" || true
    wget -q "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" -O "$DATA_DIR/geo/geosite.dat" || true

    # Create xray config
    cat > "$XRAY_DIR/config.json" << 'EOF'
{
  "log": {"loglevel": "warning"},
  "api": {"tag": "api", "services": ["HandlerService", "StatsService"]},
  "stats": {},
  "inbounds": [
    {"tag": "api", "listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}}
  ],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "blocked", "protocol": "blackhole"}
  ],
  "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]}
}
EOF
}

generate_config() {
    log_info "Generating configuration..."

    # Generate random values
    JWT_SECRET=$(openssl rand -hex 32)
    ADMIN_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c12)
    LOGIN_PATH=$(openssl rand -hex 4)

    # Find free port
    PANEL_PORT=8080
    while ss -tln | grep -q ":${PANEL_PORT} "; do
        ((PANEL_PORT++))
    done

    # Save admin info
    cat > "$INSTALL_DIR/admin_info" << EOF
ADMIN_USER=admin
ADMIN_PASS=${ADMIN_PASS}
LOGIN_PATH=/${LOGIN_PATH}
PANEL_PORT=${PANEL_PORT}
EOF
    chmod 600 "$INSTALL_DIR/admin_info"

    # Create config
    cat > "$CONFIG_DIR/config.yaml" << EOF
# MXUI Configuration
server:
  host: "0.0.0.0"
  port: ${PANEL_PORT}

database:
  type: "sqlite"
  path: "${DATA_DIR}/mxui.db"

security:
  jwt_secret: "${JWT_SECRET}"

admin:
  username: "admin"
  password: "${ADMIN_PASS}"

panel:
  login_path: "/${LOGIN_PATH}"
  language: "fa"
  theme: "dark"

protocols:
  xray_enabled: true
  xray_path: "${XRAY_DIR}/xray"
  xray_config_path: "${XRAY_DIR}/config.json"

logging:
  level: "info"
  path: "${LOG_DIR}"
EOF

    log_success "Configuration generated"
}

create_services() {
    log_info "Creating systemd services..."

    # MXUI service
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=MXUI VPN Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_DIR}/mxui --config ${CONFIG_DIR}/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=65535
Environment="MXUI_CONFIG=${CONFIG_DIR}/config.yaml"

[Install]
WantedBy=multi-user.target
EOF

    # Xray service
    cat > "$XRAY_SERVICE" << EOF
[Unit]
Description=MXUI Xray Core
After=network.target

[Service]
Type=simple
User=root
ExecStart=${XRAY_DIR}/xray run -config ${XRAY_DIR}/config.json
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Services created"
}

install_cli() {
    log_info "Installing CLI command..."

    cat > "$CLI_PATH" << 'CLIEOF'
#!/bin/bash
# MXUI CLI

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/mxui"

case "$1" in
    start)
        systemctl start mxui mxui-xray
        echo -e "${GREEN}MXUI started${NC}"
        ;;
    stop)
        systemctl stop mxui mxui-xray
        echo -e "${YELLOW}MXUI stopped${NC}"
        ;;
    restart)
        systemctl restart mxui mxui-xray
        echo -e "${GREEN}MXUI restarted${NC}"
        ;;
    status)
        echo -e "${CYAN}=== MXUI Status ===${NC}"
        if systemctl is-active --quiet mxui; then
            echo -e "Panel: ${GREEN}Running${NC}"
        else
            echo -e "Panel: ${RED}Stopped${NC}"
        fi
        if systemctl is-active --quiet mxui-xray; then
            echo -e "Xray:  ${GREEN}Running${NC}"
        else
            echo -e "Xray:  ${RED}Stopped${NC}"
        fi
        ;;
    log|logs)
        journalctl -u mxui -u mxui-xray -f --no-pager
        ;;
    info)
        if [[ -f "$INSTALL_DIR/admin_info" ]]; then
            source "$INSTALL_DIR/admin_info"
            IP=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
            echo -e "${CYAN}=== Admin Info ===${NC}"
            echo -e "Username: ${GREEN}${ADMIN_USER}${NC}"
            echo -e "Password: ${GREEN}${ADMIN_PASS}${NC}"
            echo -e "URL: ${GREEN}http://${IP}:${PANEL_PORT}${LOGIN_PATH}${NC}"
        else
            echo -e "${RED}Admin info not found${NC}"
        fi
        ;;
    update)
        curl -sL https://raw.githubusercontent.com/matin-x/mxui/main/install.sh | bash -s -- install
        ;;
    uninstall)
        echo -e "${RED}Uninstalling MXUI...${NC}"
        systemctl stop mxui mxui-xray 2>/dev/null
        systemctl disable mxui mxui-xray 2>/dev/null
        rm -f /etc/systemd/system/mxui*.service
        rm -rf /opt/mxui
        rm -f /usr/local/bin/mxui
        systemctl daemon-reload
        echo -e "${GREEN}MXUI uninstalled${NC}"
        ;;
    enable)
        systemctl enable mxui mxui-xray
        echo -e "${GREEN}Auto-start enabled${NC}"
        ;;
    disable)
        systemctl disable mxui mxui-xray
        echo -e "${YELLOW}Auto-start disabled${NC}"
        ;;
    *)
        echo -e "${CYAN}MXUI Panel Management${NC}"
        echo ""
        echo "Usage: mxui {command}"
        echo ""
        echo "Commands:"
        echo "  start      Start MXUI"
        echo "  stop       Stop MXUI"
        echo "  restart    Restart MXUI"
        echo "  status     Show status"
        echo "  log        View logs"
        echo "  info       Show admin credentials"
        echo "  update     Update MXUI"
        echo "  uninstall  Uninstall MXUI"
        echo "  enable     Enable auto-start"
        echo "  disable    Disable auto-start"
        ;;
esac
CLIEOF

    chmod +x "$CLI_PATH"
    log_success "CLI installed"
}

start_services() {
    log_info "Starting services..."

    systemctl enable mxui mxui-xray
    systemctl start mxui-xray
    sleep 1
    systemctl start mxui
    sleep 2

    if systemctl is-active --quiet mxui; then
        log_success "Services started"
        return 0
    else
        log_error "Failed to start services"
        return 1
    fi
}

show_result() {
    source "$INSTALL_DIR/admin_info"
    IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           MXUI Installation Completed!                        ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${CYAN}Admin Credentials${NC}"
    echo -e "  ─────────────────────────────────────────"
    echo -e "  Username:  ${GREEN}${ADMIN_USER}${NC}"
    echo -e "  Password:  ${GREEN}${ADMIN_PASS}${NC}"
    echo ""
    echo -e "  ${CYAN}Panel Access${NC}"
    echo -e "  ─────────────────────────────────────────"
    echo -e "  URL:       ${GREEN}http://${IP}:${PANEL_PORT}${LOGIN_PATH}${NC}"
    echo -e "  Port:      ${GREEN}${PANEL_PORT}${NC}"
    echo ""
    echo -e "  ${CYAN}Commands${NC}"
    echo -e "  ─────────────────────────────────────────"
    echo -e "  mxui status   - Check status"
    echo -e "  mxui log      - View logs"
    echo -e "  mxui info     - Show credentials"
    echo -e "  mxui restart  - Restart panel"
    echo ""
}

#═══════════════════════════════════════════════════════════════════════════════
# MAIN INSTALLATION
#═══════════════════════════════════════════════════════════════════════════════

install() {
    print_banner
    check_root
    check_system

    log_info "Starting MXUI installation..."
    echo ""

    install_dependencies
    install_go
    create_directories
    download_and_build
    install_files
    install_xray
    generate_config
    create_services
    install_cli

    if start_services; then
        show_result
    else
        log_error "Installation completed but service failed to start"
        log_info "Check logs with: mxui log"
    fi

    # Cleanup
    rm -rf /tmp/mxui /tmp/mxui.zip
}

#═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
#═══════════════════════════════════════════════════════════════════════════════

case "${1:-install}" in
    install|update)
        install
        ;;
    uninstall)
        check_root
        log_info "Uninstalling MXUI..."
        systemctl stop mxui mxui-xray 2>/dev/null || true
        systemctl disable mxui mxui-xray 2>/dev/null || true
        rm -f /etc/systemd/system/mxui*.service
        rm -rf /opt/mxui
        rm -f /usr/local/bin/mxui
        systemctl daemon-reload
        log_success "MXUI uninstalled"
        ;;
    *)
        echo "Usage: $0 {install|update|uninstall}"
        exit 1
        ;;
esac
