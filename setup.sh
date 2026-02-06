#!/bin/bash
# KalnemiX Setup Script
# VritraSec - Security-first, Privacy-focused
# https://github.com/VritraSecz/KalnemiX

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Banner
clear
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                                                          ║"
echo "║              ⚡ KalnemiX Setup Script ⚡                 ║"
echo "║                                                          ║"
echo "║         VritraSec • OSINT & Reconnaissance Toolkit       ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Function to print colored messages
print_info() {
    echo -e "${CYAN}[~]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[x]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect Operating System
detect_os() {
    print_info "Detecting operating system..."
    
    # Check for Termux
    if [ -d "/data/data/com.termux/files/" ]; then
        OS="TERMUX"
        print_success "Detected: Termux (Android)"
        return 0
    fi
    
    # Check for Linux
    if [ "$(uname)" = "Linux" ]; then
        # Additional check to ensure it's not WSL or other non-standard Linux
        if [ -f /etc/os-release ]; then
            OS="LINUX"
            print_success "Detected: Linux"
            return 0
        fi
    fi
    
    # If we get here, OS is not supported
    OS="UNSUPPORTED"
    return 1
}

# Check if OS is supported
if ! detect_os; then
    print_error "Unsupported operating system detected!"
    echo
    print_warning "KalnemiX only supports:"
    echo -e "  ${GREEN}✓${NC} Linux (Debian, Ubuntu, Kali Linux, etc.)"
    echo -e "  ${GREEN}✓${NC} Termux (Android)"
    echo
    print_error "Your system: $(uname -s) $(uname -r)"
    echo
    print_info "If you're using WSL, please use native Linux instead."
    print_info "If you're using macOS, please use Linux VM or Termux."
    print_info "Windows is not supported."
    echo
    exit 1
fi

# Installation function for Termux
install_termux() {
    print_info "Starting installation for Termux..."
    echo
    
    # Update package lists
    print_info "Updating package lists..."
    apt update -y >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        print_success "Package lists updated"
    else
        print_error "Failed to update package lists"
        exit 1
    fi
    
    # Install system packages
    print_info "Installing system dependencies..."
    PACKAGES="python python-pip whois nmap openssl sslscan dnsutils traceroute exiftool libcap"
    
    for pkg in $PACKAGES; do
        print_info "Installing $pkg..."
        apt install "$pkg" -y >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            print_success "$pkg installed"
        else
            print_warning "$pkg installation failed (may already be installed)"
        fi
    done
    
    # Install Python packages
    print_info "Installing Python dependencies..."
    PYTHON_PACKAGES="beautifulsoup4 colorama dnspython html5lib python-nmap requests rich"
    
    for pkg in $PYTHON_PACKAGES; do
        print_info "Installing Python package: $pkg..."
        pip install "$pkg" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            print_success "$pkg installed"
        else
            print_warning "$pkg installation failed"
        fi
    done
    
    # Setup Termux-specific configurations
    print_info "Setting up Termux environment..."
    
    # Check Python version and set resolver path
    PYTHON_VERSION=$(python --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
    if [ -n "$PYTHON_VERSION" ]; then
        RESOLVER_PATH="/data/data/com.termux/files/usr/lib/python${PYTHON_VERSION}/site-packages/dns/resolver.py"
        if [ -f "$RESOLVER_PATH" ] && [ -f "core/resolver.py" ]; then
            print_info "Configuring DNS resolver..."
            rm -f "$RESOLVER_PATH"
            cp core/resolver.py "$(dirname "$RESOLVER_PATH")"
            print_success "DNS resolver configured"
        fi
    fi
    
    # Setup storage
    print_info "Setting up Termux storage..."
    termux-setup-storage >/dev/null 2>&1
    
    print_success "Termux installation completed!"
}

# Installation function for Linux
install_linux() {
    print_info "Starting installation for Linux..."
    echo
    
    # Check for sudo
    if ! command_exists sudo; then
        print_error "sudo is not installed. Please install it first."
        exit 1
    fi
    
    # Check if running as root (not recommended, but allow it)
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. Using direct commands instead of sudo."
        SUDO_CMD=""
    else
        SUDO_CMD="sudo"
        print_info "Checking sudo permissions..."
        $SUDO_CMD -v
        if [ $? -ne 0 ]; then
            print_error "sudo authentication failed"
            exit 1
        fi
    fi
    
    # Update package lists
    print_info "Updating package lists..."
    $SUDO_CMD apt-get update -y >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        print_success "Package lists updated"
    else
        print_error "Failed to update package lists"
        print_info "Trying alternative package manager..."
        # Try with apt instead of apt-get
        $SUDO_CMD apt update -y >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            print_error "Package manager update failed"
            exit 1
        fi
    fi
    
    # Install system packages
    print_info "Installing system dependencies..."
    PACKAGES="python3 python3-pip whois openssl sslscan nmap traceroute libimage-exiftool-perl dnsutils"
    
    for pkg in $PACKAGES; do
        print_info "Installing $pkg..."
        $SUDO_CMD apt-get install "$pkg" -y >/dev/null 2>&1 || $SUDO_CMD apt install "$pkg" -y >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            print_success "$pkg installed"
        else
            print_warning "$pkg installation failed (may already be installed)"
        fi
    done
    
    # Install Python packages
    print_info "Installing Python dependencies..."
    PYTHON_PACKAGES="beautifulsoup4 colorama dnspython html5lib python-nmap requests rich"
    
    # Check if pip3 exists
    if command_exists pip3; then
        PIP_CMD="pip3"
    elif command_exists pip; then
        PIP_CMD="pip"
    else
        print_error "pip is not installed"
        exit 1
    fi
    
    for pkg in $PYTHON_PACKAGES; do
        print_info "Installing Python package: $pkg..."
        $PIP_CMD install "$pkg" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            print_success "$pkg installed"
        else
            print_warning "$pkg installation failed"
        fi
    done
    
    print_success "Linux installation completed!"
}

# Verify installation
verify_installation() {
    echo
    print_info "Verifying installation..."
    echo
    
    MISSING=0
    
    # Check system tools
    TOOLS="python3 python whois nmap sslscan traceroute exiftool"
    for tool in $TOOLS; do
        if command_exists "$tool" || command_exists "${tool}3"; then
            print_success "$tool is installed"
        else
            print_error "$tool is missing"
            MISSING=$((MISSING + 1))
        fi
    done
    
    # Check Python packages
    print_info "Checking Python packages..."
    PYTHON_CMD="python3"
    if ! command_exists python3; then
        PYTHON_CMD="python"
    fi
    
    PYTHON_PACKAGES="bs4 colorama dns requests rich"
    for pkg in $PYTHON_PACKAGES; do
        if $PYTHON_CMD -c "import ${pkg//-/_}" 2>/dev/null; then
            print_success "Python package $pkg is installed"
        else
            print_error "Python package $pkg is missing"
            MISSING=$((MISSING + 1))
        fi
    done
    
    if [ $MISSING -eq 0 ]; then
        echo
        print_success "All dependencies verified successfully!"
        return 0
    else
        echo
        print_warning "Some dependencies are missing. Installation may be incomplete."
        return 1
    fi
}

# Main installation flow
echo
print_info "KalnemiX Setup Script v1.0.2"
print_info "Supported platforms: Linux & Termux only"
echo

# Perform installation based on OS
case "$OS" in
    TERMUX)
        install_termux
        ;;
    LINUX)
        install_linux
        ;;
    *)
        print_error "Unknown OS type"
        exit 1
        ;;
esac

# Verify installation
verify_installation

# Final message
echo
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}║           ✓ Installation Completed Successfully! ✓       ║${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo
print_success "KalnemiX is ready to use!"
echo
print_info "To launch KalnemiX:"
if [ "$OS" = "TERMUX" ]; then
    echo -e "  ${CYAN}python kalnemix.py${NC}"
    echo -e "  ${CYAN}python kalnemix.py --interactive${NC}"
else
    echo -e "  ${CYAN}python3 kalnemix.py${NC}"
    echo -e "  ${CYAN}python3 kalnemix.py --interactive${NC}"
    echo -e "  ${CYAN}python3 kalnemix.py --help${NC}"
fi
echo
print_info "For CLI usage examples, see README.md"
echo
print_info "Made with ❤️ by VritraSec"
echo
