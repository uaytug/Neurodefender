#!/bin/bash

# NeuroDefender Installation Script for MacOS and Linux
# This script installs all dependencies and builds the application

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
    else
        print_error "Unsupported operating system. This script supports MacOS and Debian-based Linux only."
        exit 1
    fi
    print_status "Detected OS: $OS"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Homebrew on MacOS
install_homebrew() {
    if ! command_exists brew; then
        print_status "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        
        # Add Homebrew to PATH for Apple Silicon Macs
        if [[ -f "/opt/homebrew/bin/brew" ]]; then
            echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
            eval "$(/opt/homebrew/bin/brew shellenv)"
        fi
    else
        print_status "Homebrew is already installed"
    fi
}

# Install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."
    
    if [[ "$OS" == "macos" ]]; then
        # Install dependencies using Homebrew
        brew update
        brew install node python@3.11 rust libpcap pkg-config openssl
        
        # Install MongoDB
        brew tap mongodb/brew
        brew install mongodb-community
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
            npm
        
        # Install Rust
        if ! command_exists rustc; then
            print_status "Installing Rust..."
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            source "$HOME/.cargo/env"
        fi
        
        # Install MongoDB
        if ! command_exists mongod; then
            print_status "Installing MongoDB..."
            wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
            echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
            sudo apt-get update
            sudo apt-get install -y mongodb-org
            sudo systemctl start mongod
            sudo systemctl enable mongod
        fi
    fi
}

# Install Node.js dependencies
install_node_deps() {
    print_status "Installing Node.js dependencies..."
    
    # Check if npm is installed
    if ! command_exists npm; then
        print_error "npm is not installed. Please install Node.js first."
        exit 1
    fi
    
    # Install dependencies
    npm install
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        print_status "Creating Python virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install PyTorch and other dependencies
    cd src-tauri
    pip install -r requirements.txt
    cd ..
    
    deactivate
}

# Install Rust dependencies
install_rust_deps() {
    print_status "Installing Rust dependencies..."
    
    # Install Tauri CLI
    if ! command_exists cargo-tauri; then
        cargo install tauri-cli
    fi
    
    # Build Rust dependencies
    cd src-tauri
    cargo build --release
    cd ..
}

# Build the application
build_app() {
    print_status "Building the application..."
    
    # Build frontend
    npm run build
    
    # Build Tauri app
    npm run tauri build
}

# Create desktop entry for Linux
create_desktop_entry() {
    if [[ "$OS" == "debian" ]]; then
        print_status "Creating desktop entry..."
        
        DESKTOP_FILE="$HOME/.local/share/applications/neurodefender.desktop"
        mkdir -p "$HOME/.local/share/applications"
        
        cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Name=NeuroDefender
Comment=Multiplatform Intrusion Detection and Prevention System
Exec=$PWD/src-tauri/target/release/neurodefender
Icon=$PWD/src-tauri/icons/icon.png
Terminal=false
Type=Application
Categories=Network;Security;
EOF
        
        chmod +x "$DESKTOP_FILE"
        print_status "Desktop entry created at $DESKTOP_FILE"
    fi
}

# Main installation process
main() {
    print_status "Starting NeuroDefender installation..."
    
    # Detect OS
    detect_os
    
    # Install Homebrew on MacOS
    if [[ "$OS" == "macos" ]]; then
        install_homebrew
    fi
    
    # Install system dependencies
    install_system_deps
    
    # Install Node.js dependencies
    install_node_deps
    
    # Install Python dependencies
    install_python_deps
    
    # Install Rust dependencies
    install_rust_deps
    
    # Build the application
    build_app
    
    # Create desktop entry for Linux
    create_desktop_entry
    
    print_status "Installation completed successfully!"
    print_status "You can run the application using: npm run tauri dev"
    print_status "Or run the built application from: src-tauri/target/release/neurodefender"
}

# Run main function
main 