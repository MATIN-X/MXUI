#!/bin/bash

#═══════════════════════════════════════════════════════════════════════════════
#  MX-UI Unified Installer v2.0.0
#  Professional VPN Panel Installer - Similar to 3x-ui
#  Supports: Master/Node, Bash/Docker, Install/Update/Uninstall
#═══════════════════════════════════════════════════════════════════════════════

# Exit on error for critical sections only
set -o pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# COLORS & FORMATTING
# ═══════════════════════════════════════════════════════════════════════════════
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════
PROJ_NAME="MX-UI"
VERSION="2.0.0"
REPO_URL="https://github.com/MATIN-X/MX-UI"
RELEASE_URL="https://github.com/MATIN-X/MX-UI/releases"

# Paths
INSTALL_DIR="/opt/mxui"
NODE_DIR="/opt/mxui-node"
CONFIG_FILE="/opt/mxui/config/config.yaml"
SERVICE_FILE="/etc/systemd/system/mxui.service"
CLI_PATH="/usr/local/bin/mxui"
DATA_DIR="/opt/mxui/data"
LOG_DIR="/opt/mxui/logs"
BACKUP_DIR="/opt/mxui/backups"

# Log file - always in /tmp
TS=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/tmp/mxui_install_${TS}.log"
LAST_LOG="/tmp/mxui_last_install.log"

# Default ports
DEFAULT_PANEL_PORT=8080
DEFAULT_API_PORT=8081
DEFAULT_SINGLE_PORT=443
DEFAULT_XRAY_API_PORT=10085

# System info
ARCH=""
OS_FAMILY=""
OS_VERSION=""

# Install state
INSTALL_STATE_FILE="/tmp/mxui_install_state"

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════
init_log() {
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/mxui_install.log"
    ln -sf "$LOG_FILE" "$LAST_LOG" 2>/dev/null
    echo "═══════════════════════════════════════════════════════════════" >> "$LOG_FILE"
    echo "MX-UI Installation Log - $(date)" >> "$LOG_FILE"
    echo "═══════════════════════════════════════════════════════════════" >> "$LOG_FILE"
}

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${GREEN}[✓]${NC} $1"
    echo "$msg" >> "$LOG_FILE"
}

log_info() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1"
    echo -e "${BLUE}[ℹ]${NC} $1"
    echo "$msg" >> "$LOG_FILE"
}

log_warn() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $1"
    echo -e "${YELLOW}[!]${NC} $1"
    echo "$msg" >> "$LOG_FILE"
}

log_error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1"
    echo -e "${RED}[✗]${NC} $1"
    echo "$msg" >> "$LOG_FILE"
}

log_step() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [STEP] $1"
    echo -e "${CYAN}[→]${NC} $1"
    echo "$msg" >> "$LOG_FILE"
}

# ═══════════════════════════════════════════════════════════════════════════════
# BANNER & UI
# ═══════════════════════════════════════════════════════════════════════════════
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                   ║"
    echo "║   ███╗   ███╗██╗  ██╗      ██╗   ██╗██╗                           ║"
    echo "║   ████╗ ████║╚██╗██╔╝      ██║   ██║██║                           ║"
    echo "║   ██╔████╔██║ ╚███╔╝ █████╗██║   ██║██║                           ║"
    echo "║   ██║╚██╔╝██║ ██╔██╗ ╚════╝██║   ██║██║                           ║"
    echo "║   ██║ ╚═╝ ██║██╔╝ ██╗      ╚██████╔╝██║                           ║"
    echo "║   ╚═╝     ╚═╝╚═╝  ╚═╝       ╚═════╝ ╚═╝                           ║"
    echo "║                                                                   ║"
    echo "║              Professional VPN Panel Manager                       ║"
    echo "║                    Version: ${VERSION}                               ║"
    echo "║                                                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

show_menu() {
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}                     Main Menu${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} Install MX-UI (Master Panel)"
    echo -e "  ${GREEN}2)${NC} Install MX-UI Node Only"
    echo -e "  ${GREEN}3)${NC} Update MX-UI"
    echo -e "  ${GREEN}4)${NC} Uninstall MX-UI"
    echo ""
    echo -e "  ${BLUE}5)${NC} Start MX-UI"
    echo -e "  ${BLUE}6)${NC} Stop MX-UI"
    echo -e "  ${BLUE}7)${NC} Restart MX-UI"
    echo -e "  ${BLUE}8)${NC} Check Status"
    echo ""
    echo -e "  ${PURPLE}9)${NC} View Logs"
    echo -e "  ${PURPLE}10)${NC} Show Admin Info"
    echo -e "  ${PURPLE}11)${NC} Change Port"
    echo -e "  ${PURPLE}12)${NC} Reset Admin Password"
    echo ""
    echo -e "  ${CYAN}13)${NC} System Check"
    echo -e "  ${CYAN}14)${NC} Port Check"
    echo -e "  ${CYAN}15)${NC} Resume Failed Installation"
    echo -e "  ${CYAN}16)${NC} View Last Install Log"
    echo ""
    echo -e "  ${YELLOW}0)${NC} Exit"
    echo ""
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════${NC}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
detect_system() {
    log_step "Detecting system..."

    # Detect OS
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_FAMILY=$ID
        OS_VERSION=$VERSION_ID
    elif [[ -f /etc/redhat-release ]]; then
        OS_FAMILY="centos"
        OS_VERSION=$(cat /etc/redhat-release | grep -oE '[0-9]+' | head -1)
    else
        log_error "Cannot detect operating system"
        return 1
    fi

    # Detect architecture
    case $(uname -m) in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l|armhf)
            ARCH="armv7"
            ;;
        *)
            log_warn "Unknown architecture $(uname -m), defaulting to amd64"
            ARCH="amd64"
            ;;
    esac

    log "System: ${OS_FAMILY} ${OS_VERSION} (${ARCH})"
    echo "OS_FAMILY=${OS_FAMILY}" >> "$LOG_FILE"
    echo "OS_VERSION=${OS_VERSION}" >> "$LOG_FILE"
    echo "ARCH=${ARCH}" >> "$LOG_FILE"

    return 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        echo -e "${YELLOW}Please run: sudo bash $0${NC}"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM CHECK
# ═══════════════════════════════════════════════════════════════════════════════
system_check() {
    show_banner
    echo -e "${BOLD}System Information${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    # OS Info
    detect_system
    echo -e "  ${CYAN}OS:${NC}          ${OS_FAMILY} ${OS_VERSION}"
    echo -e "  ${CYAN}Arch:${NC}        ${ARCH}"
    echo -e "  ${CYAN}Kernel:${NC}      $(uname -r)"
    echo ""

    # Hardware
    echo -e "  ${CYAN}CPU:${NC}         $(grep -c processor /proc/cpuinfo) cores"
    echo -e "  ${CYAN}RAM:${NC}         $(free -h | awk '/^Mem:/{print $2}')"
    echo -e "  ${CYAN}Disk:${NC}        $(df -h / | awk 'NR==2{print $4}') available"
    echo ""

    # Network
    local public_ip=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "N/A")
    local local_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "N/A")
    echo -e "  ${CYAN}Public IP:${NC}   ${public_ip}"
    echo -e "  ${CYAN}Local IP:${NC}    ${local_ip}"
    echo ""

    # Installation Status
    echo -e "${BOLD}Installation Status${NC}"
    echo -e "${WHITE}───────────────────────────────────────────────────────────────────${NC}"

    if [[ -f "$CLI_PATH" ]]; then
        echo -e "  ${CYAN}MX-UI CLI:${NC}   ${GREEN}Installed${NC}"
    else
        echo -e "  ${CYAN}MX-UI CLI:${NC}   ${RED}Not Installed${NC}"
    fi

    if [[ -d "$INSTALL_DIR" ]]; then
        echo -e "  ${CYAN}Panel:${NC}       ${GREEN}Installed${NC} at ${INSTALL_DIR}"
    else
        echo -e "  ${CYAN}Panel:${NC}       ${RED}Not Installed${NC}"
    fi

    if systemctl is-active --quiet mxui 2>/dev/null; then
        echo -e "  ${CYAN}Service:${NC}     ${GREEN}Running${NC}"
    elif systemctl is-enabled --quiet mxui 2>/dev/null; then
        echo -e "  ${CYAN}Service:${NC}     ${YELLOW}Stopped${NC}"
    else
        echo -e "  ${CYAN}Service:${NC}     ${RED}Not Configured${NC}"
    fi

    echo ""
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    read -rp "Press Enter to continue..."
}

# ═══════════════════════════════════════════════════════════════════════════════
# PORT CHECK
# ═══════════════════════════════════════════════════════════════════════════════
port_check() {
    show_banner
    echo -e "${BOLD}Port Status${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    local ports=("80" "443" "8080" "8081" "10085" "62789" "62788" "62787")

    for port in "${ports[@]}"; do
        if ss -tln 2>/dev/null | grep -q ":${port} "; then
            local proc=$(ss -tlnp 2>/dev/null | grep ":${port} " | awk '{print $NF}' | head -1)
            echo -e "  Port ${CYAN}${port}${NC}: ${RED}In Use${NC} - ${proc}"
        else
            echo -e "  Port ${CYAN}${port}${NC}: ${GREEN}Available${NC}"
        fi
    done

    echo ""
    echo -e "${BOLD}Recommended Ports${NC}"
    echo -e "${WHITE}───────────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${CYAN}Panel:${NC}       $(find_free_port 8080)"
    echo -e "  ${CYAN}API:${NC}         $(find_free_port 8081)"
    echo -e "  ${CYAN}Single Port:${NC} $(find_free_port 443)"
    echo ""

    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    read -rp "Press Enter to continue..."
}

find_free_port() {
    local port=${1:-8080}
    while ss -tln 2>/dev/null | grep -q ":${port} "; do
        ((port++))
    done
    echo $port
}

# ═══════════════════════════════════════════════════════════════════════════════
# INSTALLATION STATE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════
save_state() {
    local step=$1
    echo "INSTALL_STEP=${step}" > "$INSTALL_STATE_FILE"
    echo "INSTALL_TIME=$(date +%s)" >> "$INSTALL_STATE_FILE"
    echo "INSTALL_LOG=${LOG_FILE}" >> "$INSTALL_STATE_FILE"
}

load_state() {
    if [[ -f "$INSTALL_STATE_FILE" ]]; then
        source "$INSTALL_STATE_FILE"
        return 0
    fi
    return 1
}

clear_state() {
    rm -f "$INSTALL_STATE_FILE"
}

resume_installation() {
    if ! load_state; then
        log_warn "No incomplete installation found"
        read -rp "Press Enter to continue..."
        return
    fi

    show_banner
    echo -e "${YELLOW}Incomplete installation detected!${NC}"
    echo ""
    echo -e "  Last step: ${CYAN}${INSTALL_STEP}${NC}"
    echo -e "  Time: $(date -d @${INSTALL_TIME} 2>/dev/null || echo 'Unknown')"
    echo -e "  Log: ${INSTALL_LOG}"
    echo ""

    read -rp "Resume installation? [Y/n]: " confirm
    if [[ "${confirm,,}" != "n" ]]; then
        case $INSTALL_STEP in
            "deps") install_dependencies && build_from_source ;;
            "source") build_from_source ;;
            "xray") install_xray "$INSTALL_DIR" && configure_panel ;;
            "config") configure_panel ;;
            "service") create_service && start_service ;;
            *) log_warn "Unknown state, starting fresh installation"
               install_master ;;
        esac
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# DEPENDENCIES
# ═══════════════════════════════════════════════════════════════════════════════
install_dependencies() {
    log_step "Installing dependencies..."
    save_state "deps"

    case $OS_FAMILY in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq >> "$LOG_FILE" 2>&1
            apt-get install -y -qq curl wget git unzip jq sqlite3 nginx certbot \
                ca-certificates gnupg lsb-release >> "$LOG_FILE" 2>&1
            ;;
        centos|rhel|almalinux|rocky|fedora)
            if command -v dnf &>/dev/null; then
                dnf install -y -q curl wget git unzip jq sqlite nginx certbot \
                    ca-certificates >> "$LOG_FILE" 2>&1
            else
                yum install -y -q curl wget git unzip jq sqlite nginx certbot \
                    ca-certificates >> "$LOG_FILE" 2>&1
            fi
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm curl wget git unzip jq sqlite nginx certbot >> "$LOG_FILE" 2>&1
            ;;
        *)
            log_warn "Unknown OS family: ${OS_FAMILY}. Skipping package installation."
            ;;
    esac

    log "Dependencies installed"
    return 0
}

install_go() {
    log_step "Installing Go..."

    if command -v go &>/dev/null; then
        local go_version=$(go version | grep -oP 'go\d+\.\d+' | head -1)
        log "Go already installed: ${go_version}"
        return 0
    fi

    local GO_VERSION="1.21.5"
    local GO_TAR="go${GO_VERSION}.linux-${ARCH}.tar.gz"
    local GO_URL="https://go.dev/dl/${GO_TAR}"

    cd /tmp
    wget -q "$GO_URL" -O "$GO_TAR" >> "$LOG_FILE" 2>&1

    if [[ ! -f "$GO_TAR" ]]; then
        log_error "Failed to download Go"
        return 1
    fi

    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$GO_TAR" >> "$LOG_FILE" 2>&1
    rm -f "$GO_TAR"

    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/go.sh

    log "Go ${GO_VERSION} installed"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# BUILD FROM SOURCE
# ═══════════════════════════════════════════════════════════════════════════════
build_from_source() {
    log_step "Building MX-UI from source..."
    save_state "source"

    # Install Go if needed
    install_go || return 1
    export PATH=$PATH:/usr/local/go/bin

    # Clone or download
    cd /tmp
    rm -rf MX-UI MX-UI.zip

    if git clone --depth 1 "$REPO_URL" MX-UI >> "$LOG_FILE" 2>&1; then
        log "Repository cloned"
    else
        log_warn "Git clone failed, trying zip download..."
        wget -q "${REPO_URL}/archive/refs/heads/main.zip" -O MX-UI.zip >> "$LOG_FILE" 2>&1
        if [[ -f MX-UI.zip ]]; then
            unzip -q MX-UI.zip >> "$LOG_FILE" 2>&1
            mv MX-UI-main MX-UI 2>/dev/null || true
        else
            log_error "Failed to download source code"
            return 1
        fi
    fi

    cd MX-UI

    # Build binary
    log_step "Compiling binary (this may take a few minutes)..."

    if [[ -f cmd/mxui/main.go ]]; then
        go build -ldflags="-s -w" -o mxui ./cmd/mxui >> "$LOG_FILE" 2>&1
        if [[ -f mxui ]]; then
            log "Binary compiled successfully"
        else
            log_error "Compilation failed. Check log: $LOG_FILE"
            return 1
        fi
    else
        log_error "Source code not found"
        return 1
    fi

    # Create directories
    mkdir -p "$INSTALL_DIR"/{bin,config,data,logs,backups,certs,web,xray}

    # Copy files
    cp mxui "$INSTALL_DIR/bin/"
    chmod +x "$INSTALL_DIR/bin/mxui"

    # Copy web files
    if [[ -d Web ]]; then
        cp -r Web/* "$INSTALL_DIR/web/" 2>/dev/null || true
    fi

    cd /tmp
    rm -rf MX-UI MX-UI.zip

    log "MX-UI built and installed"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# XRAY INSTALLATION
# ═══════════════════════════════════════════════════════════════════════════════
install_xray() {
    local install_dir="${1:-$INSTALL_DIR}"

    log_step "Installing Xray core..."
    save_state "xray"

    mkdir -p "${install_dir}/xray"
    mkdir -p "${install_dir}/data/geo"

    cd /tmp

    # Download Xray - convert arch names for Xray release naming
    local xray_arch="${ARCH}"
    case "${ARCH}" in
        amd64) xray_arch="64" ;;
        arm64) xray_arch="arm64-v8a" ;;
        armv7) xray_arch="arm32-v7a" ;;
    esac

    local xray_url="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${xray_arch}.zip"
    log_info "Downloading Xray from: ${xray_url}"

    if wget -q --show-progress "$xray_url" -O xray.zip 2>&1 | tee -a "$LOG_FILE"; then
        if [[ -s xray.zip ]] && file xray.zip | grep -q "Zip"; then
            unzip -qo xray.zip -d "${install_dir}/xray/" >> "$LOG_FILE" 2>&1
            chmod +x "${install_dir}/xray/xray"
            rm -f xray.zip
            log "Xray core installed"
        else
            log_warn "Downloaded file is not a valid zip, removing..."
            rm -f xray.zip
        fi
    else
        log_warn "Failed to download Xray, continuing..."
    fi

    # Download geo files
    log_step "Downloading geo files..."
    wget -q "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" \
        -O "${install_dir}/data/geo/geoip.dat" >> "$LOG_FILE" 2>&1 || true
    wget -q "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" \
        -O "${install_dir}/data/geo/geosite.dat" >> "$LOG_FILE" 2>&1 || true

    # Create basic xray config
    cat > "${install_dir}/xray/config.json" << 'XRAYEOF'
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
XRAYEOF

    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════
configure_panel() {
    log_step "Configuring panel..."
    save_state "config"

    # Generate credentials
    local jwt_secret=$(openssl rand -hex 32)
    local admin_pass=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c12)
    local login_path=$(openssl rand -hex 4)
    local panel_port=${PANEL_PORT:-$(find_free_port 8080)}
    local single_port=${SINGLE_PORT:-$(find_free_port 443)}

    # Save credentials for display
    echo "ADMIN_USER=admin" > "${INSTALL_DIR}/admin_info"
    echo "ADMIN_PASS=${admin_pass}" >> "${INSTALL_DIR}/admin_info"
    echo "LOGIN_PATH=/${login_path}" >> "${INSTALL_DIR}/admin_info"
    echo "PANEL_PORT=${panel_port}" >> "${INSTALL_DIR}/admin_info"
    echo "SINGLE_PORT=${single_port}" >> "${INSTALL_DIR}/admin_info"
    chmod 600 "${INSTALL_DIR}/admin_info"

    # Create config file
    cat > "${INSTALL_DIR}/config/config.yaml" << CONFIGEOF
# MX-UI Configuration
server:
  host: "0.0.0.0"
  port: ${panel_port}

database:
  type: "sqlite"
  path: "${INSTALL_DIR}/data/mxui.db"

security:
  jwt_secret: "${jwt_secret}"

admin:
  username: "admin"
  password: "${admin_pass}"

panel:
  login_path: "/${login_path}"
  language: "fa"
  theme: "dark"

protocols:
  xray_enabled: true
  xray_path: "${INSTALL_DIR}/xray/xray"
  xray_config_path: "${INSTALL_DIR}/xray/config.json"

single_port:
  enabled: true
  port: ${single_port}
  tls:
    enabled: false
    reality: false

geo:
  geofile_path: "${INSTALL_DIR}/data/geo"

logging:
  level: "info"
  path: "${INSTALL_DIR}/logs"
CONFIGEOF

    log "Configuration created"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# SERVICE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════
create_service() {
    log_step "Creating systemd service..."
    save_state "service"

    # Main MX-UI service
    cat > /etc/systemd/system/mxui.service << SERVICEEOF
[Unit]
Description=MX-UI Panel Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/bin/mxui --config ${INSTALL_DIR}/config/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=65535
Environment="MXUI_CONFIG=${INSTALL_DIR}/config/config.yaml"

[Install]
WantedBy=multi-user.target
SERVICEEOF

    # Xray service
    cat > /etc/systemd/system/mxui-xray.service << XRAYSERVICEEOF
[Unit]
Description=MX-UI Xray Core
After=network.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/xray/xray run -config ${INSTALL_DIR}/xray/config.json
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
XRAYSERVICEEOF

    systemctl daemon-reload
    log "Systemd services created"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLI COMMAND
# ═══════════════════════════════════════════════════════════════════════════════
install_cli() {
    log_step "Installing CLI command..."

    cat > "$CLI_PATH" << 'CLIEOF'
#!/bin/bash

# MX-UI CLI Management Tool
VERSION="2.0.0"
INSTALL_DIR="/opt/mxui"
CONFIG_FILE="/opt/mxui/config/config.yaml"
LAST_LOG="/tmp/mxui_last_install.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

show_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                    MX-UI Management                           ║"
    echo "║                     Version: ${VERSION}                          ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

show_help() {
    show_banner
    echo -e "${BOLD}Usage:${NC} mxui [command]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}start${NC}          Start MX-UI service"
    echo -e "  ${GREEN}stop${NC}           Stop MX-UI service"
    echo -e "  ${GREEN}restart${NC}        Restart MX-UI service"
    echo -e "  ${GREEN}status${NC}         Show service status"
    echo ""
    echo -e "  ${BLUE}log${NC}            Show live logs"
    echo -e "  ${BLUE}info${NC}           Show admin credentials"
    echo -e "  ${BLUE}port${NC}           Change panel port"
    echo -e "  ${BLUE}reset${NC}          Reset admin password"
    echo ""
    echo -e "  ${CYAN}install${NC}        Run installer"
    echo -e "  ${CYAN}update${NC}         Update MX-UI"
    echo -e "  ${CYAN}uninstall${NC}      Uninstall MX-UI"
    echo ""
    echo -e "  ${YELLOW}check${NC}          System check"
    echo -e "  ${YELLOW}last-log${NC}       View last installation log"
    echo -e "  ${YELLOW}error${NC}          Show last error from log"
    echo ""
    echo -e "  ${PURPLE}enable${NC}         Enable auto-start"
    echo -e "  ${PURPLE}disable${NC}        Disable auto-start"
    echo ""
    echo -e "  ${NC}help${NC}           Show this help"
    echo ""
}

check_installed() {
    if [[ ! -d "$INSTALL_DIR" ]] || [[ ! -f "$INSTALL_DIR/bin/mxui" ]]; then
        echo -e "${YELLOW}MX-UI is not installed.${NC}"
        echo -e "Run: ${CYAN}mxui install${NC} to install"
        return 1
    fi
    return 0
}

start_service() {
    check_installed || return 1
    echo -e "${CYAN}Starting MX-UI...${NC}"
    systemctl start mxui mxui-xray 2>/dev/null
    sleep 2
    if systemctl is-active --quiet mxui; then
        echo -e "${GREEN}MX-UI started successfully${NC}"
    else
        echo -e "${RED}Failed to start MX-UI${NC}"
        echo -e "Check logs: ${CYAN}mxui log${NC}"
    fi
}

stop_service() {
    echo -e "${CYAN}Stopping MX-UI...${NC}"
    systemctl stop mxui mxui-xray 2>/dev/null
    echo -e "${GREEN}MX-UI stopped${NC}"
}

restart_service() {
    check_installed || return 1
    echo -e "${CYAN}Restarting MX-UI...${NC}"
    systemctl restart mxui mxui-xray 2>/dev/null
    sleep 2
    if systemctl is-active --quiet mxui; then
        echo -e "${GREEN}MX-UI restarted successfully${NC}"
    else
        echo -e "${RED}Failed to restart MX-UI${NC}"
    fi
}

show_status() {
    show_banner
    echo -e "${BOLD}Service Status${NC}"
    echo -e "═══════════════════════════════════════════════════════════"

    if systemctl is-active --quiet mxui 2>/dev/null; then
        echo -e "  MX-UI Panel:  ${GREEN}● Running${NC}"
    else
        echo -e "  MX-UI Panel:  ${RED}○ Stopped${NC}"
    fi

    if systemctl is-active --quiet mxui-xray 2>/dev/null; then
        echo -e "  Xray Core:    ${GREEN}● Running${NC}"
    else
        echo -e "  Xray Core:    ${RED}○ Stopped${NC}"
    fi

    echo ""

    if [[ -f "${INSTALL_DIR}/admin_info" ]]; then
        source "${INSTALL_DIR}/admin_info"
        local ip=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
        echo -e "${BOLD}Access URL${NC}"
        echo -e "═══════════════════════════════════════════════════════════"
        echo -e "  Panel: ${CYAN}http://${ip}:${PANEL_PORT}${LOGIN_PATH}${NC}"
    fi
    echo ""
}

show_info() {
    show_banner
    if [[ -f "${INSTALL_DIR}/admin_info" ]]; then
        source "${INSTALL_DIR}/admin_info"
        local ip=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')

        echo -e "${BOLD}Admin Credentials${NC}"
        echo -e "═══════════════════════════════════════════════════════════"
        echo -e "  Username:    ${CYAN}${ADMIN_USER}${NC}"
        echo -e "  Password:    ${CYAN}${ADMIN_PASS}${NC}"
        echo ""
        echo -e "${BOLD}Access Information${NC}"
        echo -e "═══════════════════════════════════════════════════════════"
        echo -e "  Panel URL:   ${CYAN}http://${ip}:${PANEL_PORT}${LOGIN_PATH}${NC}"
        echo -e "  Panel Port:  ${CYAN}${PANEL_PORT}${NC}"
        echo -e "  Login Path:  ${CYAN}${LOGIN_PATH}${NC}"
        echo -e "  Single Port: ${CYAN}${SINGLE_PORT}${NC}"
        echo ""
    else
        echo -e "${YELLOW}Admin info not found. MX-UI may not be properly installed.${NC}"
    fi
}

show_log() {
    check_installed || return 1
    echo -e "${CYAN}Showing live logs (Ctrl+C to exit)...${NC}"
    journalctl -u mxui -u mxui-xray -f --no-pager
}

show_last_log() {
    if [[ -f "$LAST_LOG" ]]; then
        less "$LAST_LOG"
    else
        echo -e "${YELLOW}No installation log found${NC}"
    fi
}

show_last_error() {
    if [[ -f "$LAST_LOG" ]]; then
        echo -e "${BOLD}Last errors from installation log:${NC}"
        grep -i "error\|fail\|fatal" "$LAST_LOG" | tail -20
    else
        echo -e "${YELLOW}No installation log found${NC}"
    fi
}

change_port() {
    check_installed || return 1
    read -rp "Enter new panel port [current: $(grep 'port:' $CONFIG_FILE | head -1 | awk '{print $2}')]: " new_port
    if [[ -n "$new_port" ]] && [[ "$new_port" =~ ^[0-9]+$ ]]; then
        sed -i "s/port: [0-9]*/port: $new_port/" "$CONFIG_FILE"
        sed -i "s/PANEL_PORT=.*/PANEL_PORT=$new_port/" "${INSTALL_DIR}/admin_info"
        echo -e "${GREEN}Port changed to $new_port${NC}"
        echo -e "Run ${CYAN}mxui restart${NC} to apply changes"
    else
        echo -e "${RED}Invalid port${NC}"
    fi
}

reset_password() {
    check_installed || return 1
    local new_pass=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c12)
    sed -i "s/ADMIN_PASS=.*/ADMIN_PASS=$new_pass/" "${INSTALL_DIR}/admin_info"
    echo -e "${GREEN}Password reset to: ${CYAN}$new_pass${NC}"
    echo -e "Run ${CYAN}mxui restart${NC} to apply changes"
}

run_installer() {
    if [[ -f "/tmp/mxui_install.sh" ]]; then
        bash /tmp/mxui_install.sh
    else
        curl -sL https://raw.githubusercontent.com/MATIN-X/MX-UI/main/install.sh | bash
    fi
}

case "${1:-}" in
    start)       start_service ;;
    stop)        stop_service ;;
    restart)     restart_service ;;
    status)      show_status ;;
    log|logs)    show_log ;;
    info)        show_info ;;
    port)        change_port ;;
    reset)       reset_password ;;
    install)     run_installer ;;
    update)      run_installer ;;
    uninstall)   run_installer ;;
    check)       run_installer ;;
    last-log)    show_last_log ;;
    error)       show_last_error ;;
    enable)      systemctl enable mxui mxui-xray 2>/dev/null && echo -e "${GREEN}Auto-start enabled${NC}" ;;
    disable)     systemctl disable mxui mxui-xray 2>/dev/null && echo -e "${YELLOW}Auto-start disabled${NC}" ;;
    help|--help|-h|"") show_help ;;
    *)           echo -e "${RED}Unknown command: $1${NC}"; show_help ;;
esac
CLIEOF

    chmod +x "$CLI_PATH"
    log "CLI command installed: mxui"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# START/STOP SERVICES
# ═══════════════════════════════════════════════════════════════════════════════
start_service() {
    log_step "Starting services..."
    systemctl enable mxui mxui-xray >> "$LOG_FILE" 2>&1
    systemctl start mxui-xray >> "$LOG_FILE" 2>&1
    sleep 1
    systemctl start mxui >> "$LOG_FILE" 2>&1
    sleep 2

    if systemctl is-active --quiet mxui; then
        log "MX-UI started successfully"
        return 0
    else
        log_error "Failed to start MX-UI"
        return 1
    fi
}

stop_services() {
    systemctl stop mxui mxui-xray 2>/dev/null
    log "Services stopped"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MASTER INSTALLATION
# ═══════════════════════════════════════════════════════════════════════════════
install_master() {
    show_banner
    echo -e "${BOLD}Master Panel Installation${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Installation method
    echo -e "${CYAN}Select installation method:${NC}"
    echo -e "  1) Quick Install (recommended)"
    echo -e "  2) Custom Install"
    echo ""
    read -rp "Enter choice [1]: " method_choice
    method_choice=${method_choice:-1}

    if [[ "$method_choice" == "2" ]]; then
        # Custom installation
        echo ""
        read -rp "Panel Port [${DEFAULT_PANEL_PORT}]: " PANEL_PORT
        PANEL_PORT=${PANEL_PORT:-$DEFAULT_PANEL_PORT}

        read -rp "Single Port [${DEFAULT_SINGLE_PORT}]: " SINGLE_PORT
        SINGLE_PORT=${SINGLE_PORT:-$DEFAULT_SINGLE_PORT}

        export PANEL_PORT SINGLE_PORT
    fi

    echo ""
    log_step "Starting installation..."

    # Check system
    detect_system || { log_error "System detection failed"; return 1; }

    # Install components
    install_dependencies || { log_error "Dependencies failed"; return 1; }
    build_from_source || { log_error "Build failed"; return 1; }
    install_xray "$INSTALL_DIR" || { log_error "Xray installation failed"; return 1; }
    configure_panel || { log_error "Configuration failed"; return 1; }
    create_service || { log_error "Service creation failed"; return 1; }
    install_cli || { log_error "CLI installation failed"; return 1; }
    start_service || { log_error "Service start failed"; return 1; }

    # Clear state and show success
    clear_state
    show_success
}

# ═══════════════════════════════════════════════════════════════════════════════
# NODE INSTALLATION
# ═══════════════════════════════════════════════════════════════════════════════
install_node() {
    show_banner
    echo -e "${BOLD}Node Installation${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    read -rp "Master URL (e.g., http://IP:8080): " MASTER_URL
    read -rp "Node Token: " NODE_TOKEN
    read -rp "Node Name [$(hostname)]: " NODE_NAME
    NODE_NAME=${NODE_NAME:-$(hostname)}

    log_step "Installing node..."

    detect_system || return 1
    install_dependencies || return 1

    mkdir -p "$NODE_DIR"/{bin,config,xray,logs}

    install_xray "$NODE_DIR" || return 1

    # Create node config
    cat > "${NODE_DIR}/config/node.yaml" << NODEEOF
node:
  name: "${NODE_NAME}"
  mode: "node"
master:
  url: "${MASTER_URL}"
  token: "${NODE_TOKEN}"
  sync_interval: 60
xray:
  path: "${NODE_DIR}/xray/xray"
  config_path: "${NODE_DIR}/xray/config.json"
logging:
  level: "info"
  path: "${NODE_DIR}/logs"
NODEEOF

    # Create node service
    cat > /etc/systemd/system/mxui-node.service << NODESERVICEEOF
[Unit]
Description=MX-UI Node Service
After=network.target

[Service]
Type=simple
WorkingDirectory=${NODE_DIR}
ExecStart=${NODE_DIR}/xray/xray run -config ${NODE_DIR}/xray/config.json
Restart=always
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
NODESERVICEEOF

    systemctl daemon-reload
    systemctl enable --now mxui-node

    log "Node installed successfully"
    echo ""
    echo -e "${GREEN}Node installation complete!${NC}"
    echo -e "Node Name: ${CYAN}${NODE_NAME}${NC}"
    echo ""

    read -rp "Press Enter to continue..."
}

# ═══════════════════════════════════════════════════════════════════════════════
# UPDATE
# ═══════════════════════════════════════════════════════════════════════════════
update_mxui() {
    show_banner
    echo -e "${BOLD}Update MX-UI${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    if [[ ! -d "$INSTALL_DIR" ]]; then
        log_error "MX-UI is not installed"
        read -rp "Press Enter to continue..."
        return
    fi

    log_step "Creating backup..."
    local backup_file="${BACKUP_DIR}/backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    mkdir -p "$BACKUP_DIR"
    tar -czf "$backup_file" -C "$INSTALL_DIR" data config 2>/dev/null || true
    log "Backup created: $backup_file"

    log_step "Stopping services..."
    stop_services

    log_step "Updating..."
    build_from_source || { log_error "Update failed"; return 1; }

    log_step "Starting services..."
    start_service

    log "Update completed successfully"
    echo ""
    read -rp "Press Enter to continue..."
}

# ═══════════════════════════════════════════════════════════════════════════════
# UNINSTALL
# ═══════════════════════════════════════════════════════════════════════════════
uninstall_mxui() {
    show_banner
    echo -e "${BOLD}Uninstall MX-UI${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${RED}WARNING: This will remove MX-UI and all data!${NC}"
    echo ""

    read -rp "Create backup before uninstalling? [Y/n]: " backup_confirm
    if [[ "${backup_confirm,,}" != "n" ]]; then
        local backup_file="/tmp/mxui_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
        tar -czf "$backup_file" -C "$INSTALL_DIR" . 2>/dev/null || true
        log "Backup saved to: $backup_file"
    fi

    read -rp "Type 'yes' to confirm uninstall: " confirm
    if [[ "$confirm" != "yes" ]]; then
        log "Uninstall cancelled"
        return
    fi

    log_step "Stopping services..."
    systemctl stop mxui mxui-xray mxui-node 2>/dev/null
    systemctl disable mxui mxui-xray mxui-node 2>/dev/null

    log_step "Removing files..."
    rm -f /etc/systemd/system/mxui*.service
    systemctl daemon-reload

    rm -rf "$INSTALL_DIR"
    rm -rf "$NODE_DIR"
    rm -f "$CLI_PATH"

    log "MX-UI uninstalled successfully"
    echo ""
    read -rp "Press Enter to continue..."
}

# ═══════════════════════════════════════════════════════════════════════════════
# SUCCESS MESSAGE
# ═══════════════════════════════════════════════════════════════════════════════
show_success() {
    if [[ -f "${INSTALL_DIR}/admin_info" ]]; then
        source "${INSTALL_DIR}/admin_info"
    fi

    local ip=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║            Installation Completed Successfully!                  ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Admin Credentials${NC}"
    echo -e "  ─────────────────────────────────────────────────────────────────"
    echo -e "  Username:     ${CYAN}${ADMIN_USER:-admin}${NC}"
    echo -e "  Password:     ${CYAN}${ADMIN_PASS:-N/A}${NC}"
    echo ""
    echo -e "  ${BOLD}Access Information${NC}"
    echo -e "  ─────────────────────────────────────────────────────────────────"
    echo -e "  Panel URL:    ${CYAN}http://${ip}:${PANEL_PORT:-8080}${LOGIN_PATH:-}${NC}"
    echo -e "  Panel Port:   ${CYAN}${PANEL_PORT:-8080}${NC}"
    echo -e "  Single Port:  ${CYAN}${SINGLE_PORT:-443}${NC}"
    echo ""
    echo -e "  ${BOLD}Quick Commands${NC}"
    echo -e "  ─────────────────────────────────────────────────────────────────"
    echo -e "  Status:       ${CYAN}mxui status${NC}"
    echo -e "  Logs:         ${CYAN}mxui log${NC}"
    echo -e "  Admin Info:   ${CYAN}mxui info${NC}"
    echo -e "  Restart:      ${CYAN}mxui restart${NC}"
    echo -e "  Help:         ${CYAN}mxui help${NC}"
    echo ""
    echo -e "  Log file:     ${YELLOW}${LOG_FILE}${NC}"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    read -rp "Press Enter to continue..."
}

# ═══════════════════════════════════════════════════════════════════════════════
# ADDITIONAL FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════
show_admin_info() {
    if [[ -f "${INSTALL_DIR}/admin_info" ]]; then
        source "${INSTALL_DIR}/admin_info"
        local ip=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')

        show_banner
        echo -e "${BOLD}Admin Credentials${NC}"
        echo -e "${WHITE}═══════════════════════════════════════════════════════════════════${NC}"
        echo -e "  Username:    ${CYAN}${ADMIN_USER}${NC}"
        echo -e "  Password:    ${CYAN}${ADMIN_PASS}${NC}"
        echo ""
        echo -e "${BOLD}Access Information${NC}"
        echo -e "${WHITE}───────────────────────────────────────────────────────────────────${NC}"
        echo -e "  Panel URL:   ${CYAN}http://${ip}:${PANEL_PORT}${LOGIN_PATH}${NC}"
        echo -e "  Panel Port:  ${CYAN}${PANEL_PORT}${NC}"
        echo -e "  Single Port: ${CYAN}${SINGLE_PORT}${NC}"
        echo ""
    else
        echo -e "${YELLOW}MX-UI is not installed or admin info not found${NC}"
    fi
    read -rp "Press Enter to continue..."
}

change_port() {
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        echo -e "${RED}Configuration file not found${NC}"
        read -rp "Press Enter to continue..."
        return
    fi

    show_banner
    echo -e "${BOLD}Change Panel Port${NC}"
    echo ""

    local current_port=$(grep -A1 'server:' "$CONFIG_FILE" | grep 'port:' | awk '{print $2}')
    read -rp "Enter new port [current: ${current_port}]: " new_port

    if [[ -n "$new_port" ]] && [[ "$new_port" =~ ^[0-9]+$ ]]; then
        sed -i "s/port: ${current_port}/port: ${new_port}/" "$CONFIG_FILE"
        sed -i "s/PANEL_PORT=.*/PANEL_PORT=${new_port}/" "${INSTALL_DIR}/admin_info"
        log "Port changed to $new_port"
        echo -e "${GREEN}Port changed. Restart to apply: ${CYAN}mxui restart${NC}"
    else
        echo -e "${RED}Invalid port${NC}"
    fi

    read -rp "Press Enter to continue..."
}

reset_password() {
    show_banner
    echo -e "${BOLD}Reset Admin Password${NC}"
    echo ""

    local new_pass=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c12)
    sed -i "s/ADMIN_PASS=.*/ADMIN_PASS=${new_pass}/" "${INSTALL_DIR}/admin_info" 2>/dev/null

    echo -e "${GREEN}Password reset to: ${CYAN}${new_pass}${NC}"
    echo -e "Restart to apply: ${CYAN}mxui restart${NC}"
    echo ""

    read -rp "Press Enter to continue..."
}

view_logs() {
    show_banner
    echo -e "${BOLD}View Logs${NC}"
    echo ""
    echo -e "  1) Live logs (journalctl)"
    echo -e "  2) Last installation log"
    echo -e "  3) Back"
    echo ""
    read -rp "Select option: " log_choice

    case $log_choice in
        1) journalctl -u mxui -u mxui-xray -f --no-pager ;;
        2)
            if [[ -f "$LAST_LOG" ]]; then
                less "$LAST_LOG"
            else
                echo -e "${YELLOW}No installation log found${NC}"
                read -rp "Press Enter..."
            fi
            ;;
    esac
}

check_service_status() {
    show_banner
    echo -e "${BOLD}Service Status${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    if systemctl is-active --quiet mxui 2>/dev/null; then
        echo -e "  MX-UI Panel:  ${GREEN}● Running${NC}"
    else
        echo -e "  MX-UI Panel:  ${RED}○ Stopped${NC}"
    fi

    if systemctl is-active --quiet mxui-xray 2>/dev/null; then
        echo -e "  Xray Core:    ${GREEN}● Running${NC}"
    else
        echo -e "  Xray Core:    ${RED}○ Stopped${NC}"
    fi

    if systemctl is-active --quiet mxui-node 2>/dev/null; then
        echo -e "  MX-UI Node:   ${GREEN}● Running${NC}"
    fi

    echo ""
    echo -e "${BOLD}Memory Usage${NC}"
    echo -e "${WHITE}───────────────────────────────────────────────────────────────────${NC}"
    ps aux | grep -E 'mxui|xray' | grep -v grep | awk '{printf "  %-15s %s MB\n", $11, $6/1024}'

    echo ""
    read -rp "Press Enter to continue..."
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
main() {
    # Initialize
    init_log
    check_root

    # Install CLI first (so mxui command works even if install fails)
    install_cli 2>/dev/null

    while true; do
        show_banner
        show_menu

        read -rp "Enter your choice [0-16]: " choice

        case $choice in
            1) install_master ;;
            2) install_node ;;
            3) update_mxui ;;
            4) uninstall_mxui ;;
            5) systemctl start mxui mxui-xray 2>/dev/null; log "Services started"; sleep 1 ;;
            6) systemctl stop mxui mxui-xray 2>/dev/null; log "Services stopped"; sleep 1 ;;
            7) systemctl restart mxui mxui-xray 2>/dev/null; log "Services restarted"; sleep 1 ;;
            8) check_service_status ;;
            9) view_logs ;;
            10) show_admin_info ;;
            11) change_port ;;
            12) reset_password ;;
            13) system_check ;;
            14) port_check ;;
            15) resume_installation ;;
            16)
                if [[ -f "$LAST_LOG" ]]; then
                    less "$LAST_LOG"
                else
                    echo -e "${YELLOW}No installation log found${NC}"
                    read -rp "Press Enter..."
                fi
                ;;
            0|q|Q)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                sleep 1
                ;;
        esac
    done
}

# Run
main "$@"
