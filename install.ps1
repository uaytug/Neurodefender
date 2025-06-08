# NeuroDefender Installation Script for Windows
# This script installs all dependencies and builds the application
# Run this script as Administrator: powershell -ExecutionPolicy Bypass -File install.ps1

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    Write-Host "Right-click on PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Colors for output
function Write-Status {
    param($Message)
    Write-Host "[INFO] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Error-Message {
    param($Message)
    Write-Host "[ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

function Write-Warning-Message {
    param($Message)
    Write-Host "[WARNING] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

# Function to check if a command exists
function Test-CommandExists {
    param($Command)
    $null = Get-Command $Command -ErrorAction SilentlyContinue
    return $?
}

# Function to download and install a program
function Install-Program {
    param(
        [string]$Name,
        [string]$Url,
        [string]$Arguments = "/S"
    )
    
    Write-Status "Installing $Name..."
    $installer = "$env:TEMP\$Name-installer.exe"
    
    try {
        # Download installer
        Write-Status "Downloading $Name installer..."
        Invoke-WebRequest -Uri $Url -OutFile $installer -UseBasicParsing
        
        # Run installer
        Write-Status "Running $Name installer..."
        Start-Process -FilePath $installer -ArgumentList $Arguments -Wait
        
        # Clean up
        Remove-Item $installer -Force
        Write-Status "$Name installed successfully"
    }
    catch {
        Write-Error-Message "Failed to install $Name: $_"
        exit 1
    }
}

# Install Chocolatey if not present
function Install-Chocolatey {
    if (-not (Test-CommandExists "choco")) {
        Write-Status "Installing Chocolatey package manager..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        
        # Refresh environment variables
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    }
    else {
        Write-Status "Chocolatey is already installed"
    }
}

# Install system dependencies
function Install-SystemDependencies {
    Write-Status "Installing system dependencies..."
    
    # Install Visual Studio Build Tools (required for Rust)
    if (-not (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools")) {
        Write-Status "Installing Visual Studio Build Tools..."
        $vsUrl = "https://aka.ms/vs/17/release/vs_buildtools.exe"
        $vsInstaller = "$env:TEMP\vs_buildtools.exe"
        Invoke-WebRequest -Uri $vsUrl -OutFile $vsInstaller -UseBasicParsing
        
        Start-Process -FilePath $vsInstaller -ArgumentList `
            "--quiet", "--wait", "--norestart", "--nocache", `
            "--add", "Microsoft.VisualStudio.Workload.VCTools", `
            "--add", "Microsoft.VisualStudio.Component.Windows10SDK.19041", `
            "--includeRecommended" -Wait
        
        Remove-Item $vsInstaller -Force
    }
    
    # Install dependencies using Chocolatey
    choco install -y nodejs python rust mongodb npcap
    
    # Install OpenSSL
    choco install -y openssl
    
    # Set environment variables for OpenSSL
    $opensslPath = "C:\Program Files\OpenSSL-Win64"
    if (Test-Path $opensslPath) {
        [Environment]::SetEnvironmentVariable("OPENSSL_DIR", $opensslPath, "User")
        [Environment]::SetEnvironmentVariable("OPENSSL_LIB_DIR", "$opensslPath\lib", "User")
        [Environment]::SetEnvironmentVariable("OPENSSL_INCLUDE_DIR", "$opensslPath\include", "User")
    }
    
    # Refresh environment variables
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

# Install Node.js dependencies
function Install-NodeDependencies {
    Write-Status "Installing Node.js dependencies..."
    
    if (-not (Test-CommandExists "npm")) {
        Write-Error-Message "npm is not installed. Please install Node.js first."
        exit 1
    }
    
    # Install dependencies
    npm install
}

# Install Python dependencies
function Install-PythonDependencies {
    Write-Status "Installing Python dependencies..."
    
    # Create virtual environment if it doesn't exist
    if (-not (Test-Path "venv")) {
        Write-Status "Creating Python virtual environment..."
        python -m venv venv
    }
    
    # Activate virtual environment and install dependencies
    & ".\venv\Scripts\Activate.ps1"
    
    # Upgrade pip
    python -m pip install --upgrade pip
    
    # Install PyTorch and other dependencies
    Set-Location src-tauri
    pip install -r requirements.txt
    Set-Location ..
    
    deactivate
}

# Install Rust dependencies
function Install-RustDependencies {
    Write-Status "Installing Rust dependencies..."
    
    # Install Tauri CLI
    cargo install tauri-cli
    
    # Build Rust dependencies
    Set-Location src-tauri
    cargo build --release
    Set-Location ..
}

# Build the application
function Build-Application {
    Write-Status "Building the application..."
    
    # Build frontend
    npm run build
    
    # Build Tauri app
    npm run tauri build
}

# Create Start Menu shortcut
function Create-Shortcut {
    Write-Status "Creating Start Menu shortcut..."
    
    $shortcutPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\NeuroDefender.lnk"
    $targetPath = "$PWD\src-tauri\target\release\neurodefender.exe"
    $iconPath = "$PWD\src-tauri\icons\icon.ico"
    
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $targetPath
    $shortcut.WorkingDirectory = $PWD
    $shortcut.IconLocation = $iconPath
    $shortcut.Description = "Multiplatform Intrusion Detection and Prevention System"
    $shortcut.Save()
    
    Write-Status "Shortcut created at $shortcutPath"
}

# Main installation process
function Main {
    Write-Status "Starting NeuroDefender installation for Windows..."
    
    # Install Chocolatey
    Install-Chocolatey
    
    # Install system dependencies
    Install-SystemDependencies
    
    # Install Node.js dependencies
    Install-NodeDependencies
    
    # Install Python dependencies
    Install-PythonDependencies
    
    # Install Rust dependencies
    Install-RustDependencies
    
    # Build the application
    Build-Application
    
    # Create shortcut
    Create-Shortcut
    
    Write-Status "Installation completed successfully!"
    Write-Status "You can run the application using: npm run tauri dev"
    Write-Status "Or run the built application from: src-tauri\target\release\neurodefender.exe"
    Write-Host ""
    Write-Warning-Message "Note: You may need to restart your computer for all changes to take effect."
}

# Run main function
Main 