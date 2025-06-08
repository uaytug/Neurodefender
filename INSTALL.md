# NeuroDefender Installation Guide

This guide provides detailed instructions for installing NeuroDefender on MacOS, Windows, and Debian-based Linux distributions.

## Prerequisites

Before installing NeuroDefender, ensure your system meets the following requirements:

- **Operating System**: MacOS 10.15+, Windows 10/11, or Debian-based Linux (Ubuntu 20.04+, Debian 10+)
- **RAM**: Minimum 8GB (16GB recommended for ML features)
- **Storage**: At least 5GB free space
- **Network**: Active internet connection for downloading dependencies

## Quick Installation

We provide automated installation scripts for each platform:

### MacOS and Linux

```bash
# Make the script executable
chmod +x install.sh

# Run the installation script
./install.sh
```

### Windows

Run PowerShell as Administrator and execute:

```powershell
# Allow script execution
Set-ExecutionPolicy Bypass -Scope Process -Force

# Run the installation script
.\install.ps1
```

## Manual Installation

If you prefer to install manually or if the automated scripts fail, follow these platform-specific instructions:

### MacOS

1. **Install Homebrew** (if not already installed):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Install system dependencies**:
   ```bash
   brew update
   brew install node python@3.11 rust libpcap pkg-config openssl
   brew tap mongodb/brew
   brew install mongodb-community
   brew services start mongodb-community
   ```

3. **Install Node.js dependencies**:
   ```bash
   npm install
   ```

4. **Install Python dependencies**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   cd src-tauri
   pip install -r requirements.txt
   cd ..
   deactivate
   ```

5. **Install Rust dependencies**:
   ```bash
   cargo install tauri-cli
   cd src-tauri
   cargo build --release
   cd ..
   ```

6. **Build the application**:
   ```bash
   npm run build
   npm run tauri build
   ```

### Windows

1. **Install Chocolatey** (run as Administrator):
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
   iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
   ```

2. **Install Visual Studio Build Tools**:
   - Download from: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
   - Install with C++ build tools workload

3. **Install system dependencies**:
   ```powershell
   choco install -y nodejs python rust mongodb npcap openssl
   ```

4. **Set OpenSSL environment variables**:
   ```powershell
   [Environment]::SetEnvironmentVariable("OPENSSL_DIR", "C:\Program Files\OpenSSL-Win64", "User")
   [Environment]::SetEnvironmentVariable("OPENSSL_LIB_DIR", "C:\Program Files\OpenSSL-Win64\lib", "User")
   [Environment]::SetEnvironmentVariable("OPENSSL_INCLUDE_DIR", "C:\Program Files\OpenSSL-Win64\include", "User")
   ```

5. **Install Node.js dependencies**:
   ```powershell
   npm install
   ```

6. **Install Python dependencies**:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   cd src-tauri
   pip install -r requirements.txt
   cd ..
   deactivate
   ```

7. **Install Rust dependencies**:
   ```powershell
   cargo install tauri-cli
   cd src-tauri
   cargo build --release
   cd ..
   ```

8. **Build the application**:
   ```powershell
   npm run build
   npm run tauri build
   ```

### Debian-based Linux (Ubuntu/Debian)

1. **Update system packages**:
   ```bash
   sudo apt-get update
   sudo apt-get upgrade -y
   ```

2. **Install basic dependencies**:
   ```bash
   sudo apt-get install -y curl wget build-essential pkg-config libssl-dev libpcap-dev python3 python3-pip python3-venv nodejs npm
   ```

3. **Install Rust**:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source "$HOME/.cargo/env"
   ```

4. **Install MongoDB**:
   ```bash
   wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
   echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
   sudo apt-get update
   sudo apt-get install -y mongodb-org
   sudo systemctl start mongod
   sudo systemctl enable mongod
   ```

5. **Install Node.js dependencies**:
   ```bash
   npm install
   ```

6. **Install Python dependencies**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   cd src-tauri
   pip install -r requirements.txt
   cd ..
   deactivate
   ```

7. **Install Rust dependencies**:
   ```bash
   cargo install tauri-cli
   cd src-tauri
   cargo build --release
   cd ..
   ```

8. **Build the application**:
   ```bash
   npm run build
   npm run tauri build
   ```

## Post-Installation

### Running the Application

After successful installation, you can run NeuroDefender in two ways:

1. **Development mode** (with hot reload):
   ```bash
   npm run tauri dev
   ```

2. **Production build**:
   - **MacOS/Linux**: `./src-tauri/target/release/neurodefender`
   - **Windows**: `.\src-tauri\target\release\neurodefender.exe`

### Troubleshooting

#### Common Issues

1. **MongoDB connection errors**:
   - Ensure MongoDB is running:
     - MacOS: `brew services list`
     - Linux: `sudo systemctl status mongod`
     - Windows: Check Services app for MongoDB

2. **Python module not found**:
   - Ensure virtual environment is activated before installing dependencies
   - Try reinstalling with: `pip install --force-reinstall -r requirements.txt`

3. **Rust compilation errors**:
   - Update Rust: `rustup update`
   - Clean and rebuild: `cargo clean && cargo build --release`

4. **Permission errors on Linux/MacOS**:
   - For pcap access: `sudo setcap cap_net_raw,cap_net_admin=eip $(which neurodefender)`

#### Getting Help

If you encounter issues:

1. Check the [GitHub Issues](https://github.com/yourusername/neurodefender/issues)
2. Review error logs in `src-tauri/fallback.log`
3. Ensure all prerequisites are met
4. Try the manual installation steps

## Uninstallation

To uninstall NeuroDefender:

### MacOS/Linux
```bash
# Remove application files
rm -rf src-tauri/target
rm -rf node_modules
rm -rf venv
rm -rf dist

# Remove desktop entry (Linux only)
rm ~/.local/share/applications/neurodefender.desktop
```

### Windows
```powershell
# Remove application files
Remove-Item -Recurse -Force src-tauri\target
Remove-Item -Recurse -Force node_modules
Remove-Item -Recurse -Force venv
Remove-Item -Recurse -Force dist

# Remove Start Menu shortcut
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\NeuroDefender.lnk"
```

## Security Notes

- NeuroDefender requires elevated privileges for network packet capture
- On Linux/MacOS, you may need to run with `sudo` for full functionality
- Ensure your firewall allows the application to access the network
- The application uses MongoDB for data storage - secure your database appropriately

## License

See the LICENSE file in the project root for licensing information. 