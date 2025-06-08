#!/bin/bash

# IPDS (Intrusion Prevention and Detection System) Complete Setup Script
# Version: 1.0.0
# This script clones the project from GitHub, installs all dependencies, and builds the application

set -e  # Exit on error

# Configuration
GITHUB_REPO="https://github.com/uaytug/ipds.git"  # Replace with actual GitHub URL
PROJECT_NAME="ipds"
VERSION="v1.0.0"
INSTALL_DIR="$HOME/ipds-installation"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_section() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        ARCH=$(uname -m)
        print_status "Detected OS: macOS ($ARCH)"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
        print_status "Detected OS: Debian-based Linux"
    elif [[ -f /etc/redhat-release ]]; then
        OS="redhat"
        print_status "Detected OS: RedHat-based Linux"
    else
        print_error "Unsupported operating system. This script supports macOS, Debian, and RedHat-based Linux."
        exit 1
    fi
}

# Install Homebrew on macOS
install_homebrew() {
    if [[ "$OS" == "macos" ]] && ! command_exists brew; then
        print_section "Installing Homebrew"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        
        # Add Homebrew to PATH for Apple Silicon Macs
        if [[ "$ARCH" == "arm64" ]] && [[ -f "/opt/homebrew/bin/brew" ]]; then
            echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
            eval "$(/opt/homebrew/bin/brew shellenv)"
        fi
    fi
}

# Install Git if not present
install_git() {
    if ! command_exists git; then
        print_section "Installing Git"
        if [[ "$OS" == "macos" ]]; then
            brew install git
        elif [[ "$OS" == "debian" ]]; then
            sudo apt-get update && sudo apt-get install -y git
        elif [[ "$OS" == "redhat" ]]; then
            sudo yum install -y git
        fi
    fi
}

# Clone the repository
clone_repository() {
    print_section "Cloning IPDS Repository"
    
    # Create installation directory
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    
    # Clone the repository
    if [ -d "$PROJECT_NAME" ]; then
        print_warning "Project directory already exists. Pulling latest changes..."
        cd "$PROJECT_NAME"
        git fetch --all
        git checkout "$VERSION" || git checkout main
        git pull
    else
        print_status "Cloning repository from $GITHUB_REPO..."
        git clone "$GITHUB_REPO" "$PROJECT_NAME"
        cd "$PROJECT_NAME"
        
        # Checkout specific version if tag exists
        if git rev-parse "$VERSION" >/dev/null 2>&1; then
            git checkout "$VERSION"
        else
            print_warning "Version $VERSION not found, using main branch"
        fi
    fi
    
    PROJECT_DIR="$INSTALL_DIR/$PROJECT_NAME"
    print_status "Project cloned to: $PROJECT_DIR"
}

# Install system dependencies
install_system_deps() {
    print_section "Installing System Dependencies"
    
    if [[ "$OS" == "macos" ]]; then
        # Update Homebrew
        brew update
        
        # Install core dependencies
        brew install \
            node \
            python@3.11 \
            rust \
            libpcap \
            pkg-config \
            openssl \
            cmake \
            wget
        
        # Install MongoDB
        print_status "Installing MongoDB..."
        brew tap mongodb/brew
        brew install mongodb-community
        
        # Start MongoDB service
        brew services start mongodb-community
        
    elif [[ "$OS" == "debian" ]]; then
        # Update package list
        sudo apt-get update
        
        # Install basic dependencies
        sudo apt-get install -y \
            curl \
            wget \
            build-essential \
            pkg-config \
            libssl-dev \
            libpcap-dev \
            python3 \
            python3-pip \
            python3-venv \
            nodejs \
            npm \
            cmake \
            libgtk-3-dev \
            libwebkit2gtk-4.0-dev \
            libappindicator3-dev \
            librsvg2-dev \
            patchelf
        
        # Install Rust
        if ! command_exists rustc; then
            print_status "Installing Rust..."
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            source "$HOME/.cargo/env"
        fi
        
        # Install MongoDB
        if ! command_exists mongod; then
            print_status "Installing MongoDB..."
            wget -qO - https://www.mongodb.org/static/pgp/server-7.0.asc | sudo apt-key add -
            echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
            sudo apt-get update
            sudo apt-get install -y mongodb-org
            sudo systemctl start mongod
            sudo systemctl enable mongod
        fi
        
    elif [[ "$OS" == "redhat" ]]; then
        # Install basic dependencies
        sudo yum groupinstall -y "Development Tools"
        sudo yum install -y \
            openssl-devel \
            libpcap-devel \
            python3 \
            python3-pip \
            nodejs \
            npm \
            cmake
        
        # Install Rust
        if ! command_exists rustc; then
            print_status "Installing Rust..."
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            source "$HOME/.cargo/env"
        fi
        
        # Install MongoDB
        if ! command_exists mongod; then
            print_status "Installing MongoDB..."
            cat <<EOF | sudo tee /etc/yum.repos.d/mongodb-org-7.0.repo
[mongodb-org-7.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/\$releasever/mongodb-org/7.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-7.0.asc
EOF
            sudo yum install -y mongodb-org
            sudo systemctl start mongod
            sudo systemctl enable mongod
        fi
    fi
}

# Install Node.js dependencies
install_node_deps() {
    print_section "Installing Node.js Dependencies"
    
    cd "$PROJECT_DIR"
    
    # Check Node.js version
    NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -lt 16 ]; then
        print_error "Node.js version 16 or higher is required. Current version: $(node -v)"
        exit 1
    fi
    
    # Clean install
    print_status "Installing Node.js packages..."
    rm -rf node_modules package-lock.json
    npm install
    
    # Install Tauri CLI globally
    print_status "Installing Tauri CLI..."
    npm install -g @tauri-apps/cli
}

# Install Python dependencies
install_python_deps() {
    print_section "Installing Python Dependencies"
    
    cd "$PROJECT_DIR"
    
    # Create virtual environment
    print_status "Creating Python virtual environment..."
    python3 -m venv venv
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip setuptools wheel
    
    # Install PyTorch and other dependencies
    print_status "Installing Python packages..."
    cd src-tauri
    
    # Install PyTorch with appropriate backend
    if [[ "$OS" == "macos" ]] && [[ "$ARCH" == "arm64" ]]; then
        # For Apple Silicon
        pip install torch torchvision torchaudio
    else
        # For other systems
        pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
    fi
    
    # Install other requirements
    pip install -r requirements.txt
    
    cd ..
    deactivate
}

# Install Rust dependencies
install_rust_deps() {
    print_section "Installing Rust Dependencies"
    
    cd "$PROJECT_DIR"
    
    # Ensure Rust is in PATH
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
    
    # Update Rust
    print_status "Updating Rust toolchain..."
    rustup update stable
    
    # Install Tauri prerequisites
    print_status "Installing Tauri prerequisites..."
    cargo install tauri-cli
    
    # Build Rust dependencies
    print_status "Building Rust dependencies..."
    cd src-tauri
    cargo build --release
    cd ..
}

# Configure MongoDB
configure_mongodb() {
    print_section "Configuring MongoDB"
    
    # Create database directory
    mkdir -p "$PROJECT_DIR/data/db"
    
    # Create MongoDB configuration
    cat > "$PROJECT_DIR/mongodb.conf" << EOF
# MongoDB configuration for IPDS
storage:
  dbPath: $PROJECT_DIR/data/db
  journal:
    enabled: true

systemLog:
  destination: file
  logAppend: true
  path: $PROJECT_DIR/data/mongodb.log

net:
  port: 27017
  bindIp: 127.0.0.1

processManagement:
  fork: false
EOF
    
    print_status "MongoDB configured with data directory: $PROJECT_DIR/data/db"
}

# Build the application
build_app() {
    print_section "Building IPDS Application"
    
    cd "$PROJECT_DIR"
    
    # Build frontend
    print_status "Building frontend..."
    npm run build
    
    # Build Tauri application
    print_status "Building Tauri application..."
    npm run tauri build
    
    # Get build output location
    if [[ "$OS" == "macos" ]]; then
        APP_PATH="$PROJECT_DIR/src-tauri/target/release/bundle/macos/NeuroDefender.app"
        BINARY_PATH="$PROJECT_DIR/src-tauri/target/release/neurodefender"
    else
        APP_PATH="$PROJECT_DIR/src-tauri/target/release/neurodefender"
        BINARY_PATH="$APP_PATH"
    fi
    
    print_status "Application built successfully!"
    print_status "Binary location: $BINARY_PATH"
}

# Create startup scripts
create_startup_scripts() {
    print_section "Creating Startup Scripts"
    
    # Create run script
    cat > "$PROJECT_DIR/run_ipds.sh" << EOF
#!/bin/bash
# IPDS Startup Script

# Start MongoDB
echo "Starting MongoDB..."
if [[ "$OS" == "macos" ]]; then
    brew services start mongodb-community
else
    sudo systemctl start mongod
fi

# Activate Python environment
source "$PROJECT_DIR/venv/bin/activate"

# Run the application
cd "$PROJECT_DIR"
./src-tauri/target/release/neurodefender

deactivate
EOF
    
    chmod +x "$PROJECT_DIR/run_ipds.sh"
    
    # Create development run script
    cat > "$PROJECT_DIR/run_dev.sh" << EOF
#!/bin/bash
# IPDS Development Script

# Start MongoDB
echo "Starting MongoDB..."
if [[ "$OS" == "macos" ]]; then
    brew services start mongodb-community
else
    sudo systemctl start mongod
fi

# Activate Python environment
source "$PROJECT_DIR/venv/bin/activate"

# Run in development mode
cd "$PROJECT_DIR"
npm run tauri dev

deactivate
EOF
    
    chmod +x "$PROJECT_DIR/run_dev.sh"
    
    print_status "Startup scripts created:"
    print_status "  - Production: $PROJECT_DIR/run_ipds.sh"
    print_status "  - Development: $PROJECT_DIR/run_dev.sh"
}

# Create desktop entry for Linux
create_desktop_entry() {
    if [[ "$OS" != "macos" ]]; then
        print_section "Creating Desktop Entry"
        
        DESKTOP_FILE="$HOME/.local/share/applications/ipds.desktop"
        mkdir -p "$HOME/.local/share/applications"
        
        cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Name=IPDS - Intrusion Prevention Detection System
Comment=Multiplatform Intrusion Detection and Prevention System
Exec=$PROJECT_DIR/run_ipds.sh
Icon=$PROJECT_DIR/src-tauri/icons/icon.png
Terminal=false
Type=Application
Categories=Network;Security;System;
StartupNotify=true
EOF
        
        chmod +x "$DESKTOP_FILE"
        print_status "Desktop entry created at $DESKTOP_FILE"
    fi
}

# Verify installation
verify_installation() {
    print_section "Verifying Installation"
    
    # Check all components
    local all_good=true
    
    # Check Node.js
    if command_exists node; then
        print_status "✓ Node.js: $(node -v)"
    else
        print_error "✗ Node.js not found"
        all_good=false
    fi
    
    # Check Python
    if command_exists python3; then
        print_status "✓ Python: $(python3 --version)"
    else
        print_error "✗ Python not found"
        all_good=false
    fi
    
    # Check Rust
    if command_exists rustc; then
        print_status "✓ Rust: $(rustc --version)"
    else
        print_error "✗ Rust not found"
        all_good=false
    fi
    
    # Check MongoDB
    if command_exists mongod; then
        print_status "✓ MongoDB: $(mongod --version | head -n1)"
    else
        print_error "✗ MongoDB not found"
        all_good=false
    fi
    
    # Check if application binary exists
    if [ -f "$BINARY_PATH" ]; then
        print_status "✓ IPDS Application built successfully"
    else
        print_error "✗ IPDS Application binary not found"
        all_good=false
    fi
    
    if [ "$all_good" = true ]; then
        print_status "All components installed successfully!"
    else
        print_error "Some components failed to install"
        exit 1
    fi
}

# Print final instructions
print_instructions() {
    print_section "Installation Complete!"
    
    echo -e "${GREEN}IPDS v1.0.0 has been successfully installed!${NC}\n"
    
    echo -e "${CYAN}Installation Details:${NC}"
    echo -e "  • Project Location: $PROJECT_DIR"
    echo -e "  • Application Binary: $BINARY_PATH"
    echo -e "  • MongoDB Data: $PROJECT_DIR/data/db"
    echo -e "  • Python Environment: $PROJECT_DIR/venv"
    
    echo -e "\n${CYAN}To run IPDS:${NC}"
    echo -e "  • Production mode: $PROJECT_DIR/run_ipds.sh"
    echo -e "  • Development mode: $PROJECT_DIR/run_dev.sh"
    echo -e "  • Direct binary: $BINARY_PATH"
    
    echo -e "\n${CYAN}MongoDB Commands:${NC}"
    if [[ "$OS" == "macos" ]]; then
        echo -e "  • Start: brew services start mongodb-community"
        echo -e "  • Stop: brew services stop mongodb-community"
        echo -e "  • Status: brew services list | grep mongodb"
    else
        echo -e "  • Start: sudo systemctl start mongod"
        echo -e "  • Stop: sudo systemctl stop mongod"
        echo -e "  • Status: sudo systemctl status mongod"
    fi
    
    echo -e "\n${YELLOW}Note:${NC} Make sure MongoDB is running before starting IPDS"
    echo -e "\n${GREEN}Thank you for installing IPDS!${NC}"
}

# Main installation process
main() {
    clear
    echo -e "${MAGENTA}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                           ║"
    echo "║     IPDS - Intrusion Prevention Detection System          ║"
    echo "║                  Installation Script                      ║"
    echo "║                    Version 1.0.0                          ║"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}\n"
    
    # Start installation
    print_status "Starting IPDS installation process..."
    
    # Detect OS
    detect_os
    
    # Install Homebrew on macOS
    if [[ "$OS" == "macos" ]]; then
        install_homebrew
    fi
    
    # Install Git
    install_git
    
    # Clone repository
    clone_repository
    
    # Install system dependencies
    install_system_deps
    
    # Install Node.js dependencies
    install_node_deps
    
    # Install Python dependencies
    install_python_deps
    
    # Install Rust dependencies
    install_rust_deps
    
    # Configure MongoDB
    configure_mongodb
    
    # Build the application
    build_app
    
    # Create startup scripts
    create_startup_scripts
    
    # Create desktop entry for Linux
    create_desktop_entry
    
    # Verify installation
    verify_installation
    
    # Print final instructions
    print_instructions
}

# Handle script interruption
trap 'print_error "Installation interrupted!"; exit 1' INT TERM

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   print_error "Please do not run this script as root!"
   exit 1
fi

# Run main function
main "$@" 