#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check CPU cores
    CPU_CORES=$(nproc)
    if [ "$CPU_CORES" -lt 4 ]; then
        warning "Less than 4 CPU cores available ($CPU_CORES). Performance might be affected."
    fi
    
    # Check RAM
    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_RAM" -lt 16 ]; then
        warning "Less than 16GB RAM available (${TOTAL_RAM}GB). Performance might be affected."
    fi
    
    # Check disk space
    FREE_SPACE=$(df -h . | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "${FREE_SPACE%.*}" -lt 50 ]; then
        warning "Less than 50GB free space available (${FREE_SPACE}GB). Consider freeing up space."
    fi
}

# Install dependencies
install_dependencies() {
    log "Installing dependencies..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log "Installing Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        sudo usermod -aG docker $USER
        rm get-docker.sh
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        log "Installing Docker Compose..."
        sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
    fi
    
    # Install Rust if not present
    if ! command -v rustc &> /dev/null; then
        log "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
    fi
    
    # Install Go if not present
    if ! command -v go &> /dev/null; then
        log "Installing Go..."
        wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        source ~/.bashrc
        rm go1.21.0.linux-amd64.tar.gz
    fi
    
    # Install Python Poetry if not present
    if ! command -v poetry &> /dev/null; then
        log "Installing Poetry..."
        curl -sSL https://install.python-poetry.org | python3 -
    fi
}

# Build project components
build_components() {
    log "Building project components..."
    
    # Build security-core
    log "Building security-core..."
    cd security-core
    cargo build --release || error "Failed to build security-core"
    cd ..
    
    # Build NGFW core
    log "Building NGFW core..."
    cd ngfw-core
    cargo build --release || error "Failed to build NGFW core"
    cd ..
    
    # Build SIEM processor
    log "Building SIEM processor..."
    cd siem-processor
    go build ./cmd/main.go || error "Failed to build SIEM processor"
    cd ..
    
    # Install Python dependencies
    log "Installing Python dependencies..."
    cd phishing-protection
    poetry install || error "Failed to install Python dependencies"
    cd ..
}

# Configure environment
configure_environment() {
    log "Configuring environment..."
    
    # Create .env file if it doesn't exist
    if [ ! -f .env ]; then
        log "Creating .env file..."
        cat > .env << EOL
# Database configurations
DB_HOST=localhost
DB_PORT=5432
DB_USER=neurodefender
DB_PASSWORD=changeme

# Service ports
SIEM_PORT=8080
NGFW_PORT=8081
PHISHING_PORT=8082

# Logging
LOG_LEVEL=info
LOG_PATH=/var/log/neurodefender

# Security
JWT_SECRET=change_this_to_a_secure_secret
EOL
    fi
    
    # Create necessary directories
    sudo mkdir -p /var/log/neurodefender
    sudo chown -R $USER:$USER /var/log/neurodefender
}

# Start services
start_services() {
    log "Starting services..."
    
    # Start databases and dependencies
    docker-compose up -d
    
    # Start core services
    ./security-core/target/release/security-core &
    ./ngfw-core/target/release/ngfw-core &
    ./siem-processor/main &
    cd phishing-protection && poetry run python src/main.py &
    cd ..
    
    # Wait for services to start
    sleep 10
    
    # Check service status
    log "Checking service status..."
    docker-compose ps
}

# Health check
health_check() {
    log "Performing health check..."
    
    # Check if services are running
    if ! pgrep -f security-core > /dev/null; then
        error "Security core is not running"
    fi
    
    if ! pgrep -f ngfw-core > /dev/null; then
        error "NGFW core is not running"
    fi
    
    if ! pgrep -f "siem-processor/main" > /dev/null; then
        error "SIEM processor is not running"
    fi
    
    if ! pgrep -f "phishing-protection/src/main.py" > /dev/null; then
        error "Phishing protection is not running"
    fi
    
    log "All services are running"
}

# Main execution
main() {
    log "Starting NeuroDefender setup..."
    
    check_requirements
    install_dependencies
    build_components
    configure_environment
    start_services
    health_check
    
    log "NeuroDefender is now running!"
    log "Access the services at:"
    log "SIEM: http://localhost:8080"
    log "NGFW: http://localhost:8081"
    log "Phishing Protection: http://localhost:8082"
}

# Script execution
main "$@"