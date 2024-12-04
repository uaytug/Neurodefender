#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Environment detection
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    PLATFORM="windows"
else
    echo -e "${RED}Unsupported platform: $OSTYPE${NC}"
    exit 1
fi

# Deploy service based on platform
deploy_service() {
    echo -e "${GREEN}Deploying NeuroDefender Service...${NC}"
    
    if [[ "$PLATFORM" == "windows" ]]; then
        # Windows deployment
        powershell.exe -ExecutionPolicy Bypass -File service-automation/scripts/Install-Service.ps1
    else
        # Linux/MacOS deployment
        sudo cp service-automation/scripts/neurodefender.service /etc/systemd/system/
        sudo systemctl daemon-reload
        sudo systemctl enable neurodefender.service
        sudo systemctl start neurodefender.service
    fi
}

# Build service components
build_service() {
    echo -e "${GREEN}Building service components...${NC}"
    
    if [[ "$PLATFORM" == "windows" ]]; then
        dotnet build service-automation/NeuroDefender.Service.csproj -c Release
    else
        # For Linux/MacOS, build the service daemon
        gcc -o service-automation/bin/neurodefender-service service-automation/src/service.c
    fi
}

# Main deployment process
main() {
    # Create necessary directories
    mkdir -p service-automation/bin
    mkdir -p service-automation/logs
    mkdir -p service-automation/config
    
    # Build components
    build_service
    
    # Deploy service
    deploy_service
    
    echo -e "${GREEN}Deployment complete!${NC}"
}

# Execute main function
main "$@"