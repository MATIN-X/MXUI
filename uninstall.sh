#!/bin/bash

#===============================================================================
#
#          FILE: uninstall.sh
#
#   DESCRIPTION: MXUI VPN Panel Uninstallation Script
#
#        AUTHOR: MXUI Team
#       VERSION: 1.0.0
#
#===============================================================================

set -e

#===============================================================================
# Colors
#===============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

#===============================================================================
# Configuration
#===============================================================================
MXUI_DIR="/opt/mxui"
MXUI_SERVICE_FILE="/etc/systemd/system/mxui.service"

#===============================================================================
# Functions
#===============================================================================
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    clear
    echo -e "${RED}"
    cat << "EOF"
    
    ███╗   ███╗██████╗       ██╗  ██╗
    ████╗ ████║██╔══██╗      ╚██╗██╔╝
    ██╔████╔██║██████╔╝█████╗ ╚███╔╝ 
    ██║╚██╔╝██║██╔══██╗╚════╝ ██╔██╗ 
    ██║ ╚═╝ ██║██║  ██║      ██╔╝ ██╗
    ╚═╝     ╚═╝╚═╝  ╚═╝      ╚═╝  ╚═╝
                                     
    UNINSTALLATION
    
EOF
    echo -e "${NC}"
    echo -e "${WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_installation() {
    if [ ! -d "$MXUI_DIR" ] && [ ! -f "$MXUI_SERVICE_FILE" ]; then
        log_error "MXUI is not installed on this system"
        exit 1
    fi
}

backup_data() {
    if [ -d "$MXUI_DIR/data" ]; then
        BACKUP_FILE="/root/mxui_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
        log "Creating backup at $BACKUP_FILE..."
        tar -czf "$BACKUP_FILE" -C "$MXUI_DIR" data 2>/dev/null || true
        log "Backup created: $BACKUP_FILE"
        echo -e "${YELLOW}  Keep this file if you want to restore data later${NC}"
    fi
}

stop_service() {
    log "Stopping MXUI service..."
    
    # Stop systemd service
    if systemctl is-active --quiet mxui 2>/dev/null; then
        systemctl stop mxui
        log "Service stopped"
    fi
    
    # Disable service
    if systemctl is-enabled --quiet mxui 2>/dev/null; then
        systemctl disable mxui
        log "Service disabled"
    fi
}

stop_docker() {
    log "Checking for Docker installation..."
    
    if command -v docker &> /dev/null; then
        # Stop Docker container
        if docker ps -q --filter "name=mxui" | grep -q .; then
            docker stop mxui
            docker rm mxui
            log "Docker container removed"
        fi
        
        # Stop Docker Compose
        if [ -f "$MXUI_DIR/docker-compose.yml" ]; then
            cd "$MXUI_DIR"
            docker compose down 2>/dev/null || true
            log "Docker Compose services stopped"
        fi
        
        # Remove Docker volumes (optional)
        if docker volume ls -q --filter "name=mxui" | grep -q .; then
            read -p "  Remove Docker volumes (data will be lost)? [y/N]: " remove_volumes
            if [[ "$remove_volumes" =~ ^[Yy]$ ]]; then
                docker volume rm $(docker volume ls -q --filter "name=mxui") 2>/dev/null || true
                log "Docker volumes removed"
            fi
        fi
    fi
}

remove_files() {
    log "Removing MXUI files..."
    
    # Remove service file
    if [ -f "$MXUI_SERVICE_FILE" ]; then
        rm -f "$MXUI_SERVICE_FILE"
        systemctl daemon-reload
        log "Service file removed"
    fi
    
    # Remove logrotate config
    if [ -f "/etc/logrotate.d/mxui" ]; then
        rm -f "/etc/logrotate.d/mxui"
        log "Logrotate config removed"
    fi
    
    # Remove sysctl config
    if [ -f "/etc/sysctl.d/99-mxui.conf" ]; then
        rm -f "/etc/sysctl.d/99-mxui.conf"
        log "Sysctl config removed"
    fi
    
    # Remove limits config
    if [ -f "/etc/security/limits.d/mxui.conf" ]; then
        rm -f "/etc/security/limits.d/mxui.conf"
        log "Limits config removed"
    fi
    
    # Remove credentials file
    if [ -f "/root/.mxui_credentials" ]; then
        rm -f "/root/.mxui_credentials"
        log "Credentials file removed"
    fi
}

remove_directory() {
    if [ -d "$MXUI_DIR" ]; then
        read -p "  Remove all MXUI files including data? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            rm -rf "$MXUI_DIR"
            log "MXUI directory removed"
        else
            log_warn "MXUI directory kept at $MXUI_DIR"
        fi
    fi
}

cleanup_firewall() {
    log "Cleaning up firewall rules..."
    
    # UFW
    if command -v ufw &> /dev/null; then
        ufw delete allow 8443/tcp 2>/dev/null || true
        ufw delete allow 8080/tcp 2>/dev/null || true
    fi
    
    # Firewalld
    if command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --remove-port=8443/tcp 2>/dev/null || true
        firewall-cmd --permanent --remove-port=8080/tcp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    fi
    
    log "Firewall rules cleaned"
}

#===============================================================================
# Main
#===============================================================================
main() {
    print_banner
    check_root
    check_installation
    
    echo -e "${RED}  ⚠️  WARNING: This will uninstall MXUI VPN Panel${NC}"
    echo ""
    read -p "  Are you sure you want to continue? [y/N]: " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Uninstallation cancelled."
        exit 0
    fi
    
    echo ""
    read -p "  Create backup before uninstalling? [Y/n]: " backup_confirm
    
    if [[ ! "$backup_confirm" =~ ^[Nn]$ ]]; then
        backup_data
    fi
    
    echo ""
    log "Starting uninstallation..."
    
    stop_service
    stop_docker
    remove_files
    cleanup_firewall
    remove_directory
    
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  ✓ MXUI VPN Panel has been uninstalled successfully!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    if [ -f "/root/mxui_backup_"*.tar.gz ] 2>/dev/null; then
        echo -e "${YELLOW}  Backup file(s) saved in /root/${NC}"
        ls -la /root/mxui_backup_*.tar.gz 2>/dev/null
        echo ""
    fi
    
    echo -e "${CYAN}  Thank you for using MXUI!${NC}"
    echo -e "${CYAN}  GitHub: https://github.com/MXUI-Panel/MXUI${NC}"
    echo ""
}

# Handle arguments
case "$1" in
    -y|--yes)
        # Non-interactive mode
        print_banner
        check_root
        check_installation
        backup_data
        stop_service
        stop_docker
        remove_files
        cleanup_firewall
        rm -rf "$MXUI_DIR"
        log "MXUI uninstalled successfully"
        ;;
    -h|--help)
        echo "MXUI Uninstallation Script"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  -y, --yes     Non-interactive mode (auto-confirm)"
        echo "  -h, --help    Show this help"
        echo ""
        exit 0
        ;;
    *)
        main
        ;;
esac
