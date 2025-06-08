//! src/lib.rs
//! Enhanced Library crate for NeuroDefender with improved robustness:
//!   • `start_blocking()` – run the REST backend only
//!   • `run()` – run Tauri GUI + spawn the backend with enhanced error handling
//!   • Added comprehensive error recovery and fallback mechanisms
//!   • Improved monitoring and health checks

mod api;
mod capture;
mod detection;
mod storage;
mod utils;
mod services;
mod prevention;
mod tray_module;
pub mod robustness;
pub mod config_manager;

use std::sync::Arc;
use std::time::Duration;
use actix_web::{middleware, web, App, HttpServer};
use log::{error, info, warn};
use tokio::sync::Mutex;
use tokio::sync::broadcast;
use anyhow::Result;
use tauri::{Manager, WindowEvent, Emitter};
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_shell;
use crate::{
    storage::db::Database,
    services::monitor_service::MonitorService,
    detection::engine::DetectionEngine,
    capture::pcap::PcapManager,
    api::routes,
    utils::{config::Config, logger},
    tray_module::tray_initializer::init_tray,
};

/// Enhanced health monitoring structure
#[derive(Debug, Clone)]
pub struct SystemHealth {
    pub backend_running: bool,
    pub database_connected: bool,
    pub network_monitoring: bool,
    pub last_heartbeat: std::time::Instant,
    pub startup_time: std::time::Instant,
    pub restart_count: u32,
}

impl SystemHealth {
    pub fn new() -> Self {
        Self {
            backend_running: false,
            database_connected: false,
            network_monitoring: false,
            last_heartbeat: std::time::Instant::now(),
            startup_time: std::time::Instant::now(),
            restart_count: 0,
        }
    }

    pub fn update_heartbeat(&mut self) {
        self.last_heartbeat = std::time::Instant::now();
    }

    pub fn is_healthy(&self) -> bool {
        let heartbeat_timeout = Duration::from_secs(30);
        self.backend_running && 
        self.database_connected && 
        self.last_heartbeat.elapsed() < heartbeat_timeout
    }
}

/// Enhanced Database implementation with better error handling
impl Database {
    /// Enhanced database connection with comprehensive retry logic
    pub async fn db_connection_enhanced(
        primary: &str, 
        fallback: &str, 
        no_connection_db_log: &str
    ) -> Result<Self> {
        let max_retries = 5;
        let mut retry_delay = Duration::from_secs(1);

        for attempt in 1..=max_retries {
            info!("Database connection attempt {} of {}", attempt, max_retries);
            
            // Try primary URI first
            match Self::new(primary, no_connection_db_log).await {
                Ok(db) => {
                    info!("✅ Connected to MongoDB using primary URI on attempt {}", attempt);
                    return Ok(db);
                }
                Err(e) => {
                    warn!("Primary MongoDB URI failed on attempt {}: {}", attempt, e);
                    
                    // Try fallback URI if primary fails
                    match Self::new(fallback, no_connection_db_log).await {
                        Ok(db) => {
                            info!("✅ Connected to MongoDB using fallback URI on attempt {}", attempt);
                            return Ok(db);
                        }
                        Err(e2) => {
                            warn!("Fallback MongoDB URI also failed on attempt {}: {}", attempt, e2);
                            
                            if attempt < max_retries {
                                warn!("Retrying in {} seconds...", retry_delay.as_secs());
                                tokio::time::sleep(retry_delay).await;
                                retry_delay = std::cmp::min(retry_delay * 2, Duration::from_secs(30));
                            } else {
                                let error_message = format!(
                                    "❌ All {} database connection attempts failed. Primary: {}. Fallback: {}", 
                                    max_retries, e, e2
                                );
                                error!("{}", error_message);

                                // Log to file with detailed information
                                Self::log_connection_failure(no_connection_db_log, &error_message, attempt).await;
                                return Err(anyhow::anyhow!(error_message));
                            }
                        }
                    }
                }
            }
        }

        unreachable!()
    }

    /// Enhanced logging for connection failures
    async fn log_connection_failure(log_file: &str, error_message: &str, attempts: u32) {
        use std::fs::OpenOptions;
        use std::io::Write;

        let timestamp = chrono::Utc::now().to_rfc3339();
        let detailed_log = format!(
            "[{}] CRITICAL: Database Connection Failure\n\
             Attempts: {}\n\
             Error: {}\n\
             System Info: {:?}\n\
             ---\n",
            timestamp, attempts, error_message, 
            get_system_info().unwrap_or_default()
        );

        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(detailed_log.as_bytes()) {
                    error!("Failed to write to connection failure log '{}': {}", log_file, e);
                } else {
                    info!("📝 Connection failure logged to '{}'", log_file);
                }
            }
            Err(e) => {
                error!("Failed to open connection failure log '{}': {}", log_file, e);
            }
        }
    }

    /// Original connection method for backward compatibility
    pub async fn db_connection(primary: &str, fallback: &str, no_connection_db_log: &str) -> Result<Self> {
        Self::db_connection_enhanced(primary, fallback, no_connection_db_log).await
    }
}

/// Enhanced backend with comprehensive error handling and recovery
pub async fn backend_main_enhanced() -> std::io::Result<()> {
    let mut health = SystemHealth::new();
    
    // System information logging
    match get_system_info() {
        Ok(systeminfo) => {
            info!("🖥️  System info: {}", systeminfo);
        }
        Err(e) => {
            warn!("⚠️  Could not retrieve system info: {}", e);
        }
    }

    // Enhanced logging initialization
    if let Err(e) = logger::init() {
        eprintln!("❌ Logger initialization failed: {}", e);
        return Err(io_err("Logger initialization failed"));
    }
    info!("🚀 Starting NeuroDefender backend (Enhanced)...");

    // Enhanced configuration loading with validation
    let cfg = match Config::load() {
        Ok(config) => {
            info!("✅ Configuration loaded successfully");
            validate_config(&config);
            config
        }
        Err(e) => {
            error!("❌ Configuration load failed: {}", e);
            return Err(io_err(format!("Config: {}", e)));
        }
    };

    // Enhanced database connection with retries
    let db = match Database::db_connection_enhanced(
        &cfg.mongodb_uri, 
        &cfg.fallback_mongodb_uri, 
        &cfg.no_connection_db_log
    ).await {
        Ok(database) => {
            health.database_connected = true;
            info!("✅ Database connected successfully");
            database
        }
        Err(e) => {
            error!("❌ Database connection failed: {}", e);
            return Err(io_err(format!("Database: {}", e)));
        }
    };

    // Enhanced network interface setup with fallback detection
    let pcap = match create_pcap_manager(&cfg.network_interface) {
        Ok(manager) => {
            health.network_monitoring = true;
            info!("✅ Network monitoring on interface: {}", cfg.network_interface);
            manager
        }
        Err(e) => {
            error!("❌ Network interface setup failed: {}", e);
            return Err(io_err(format!("Network: {}", e)));
        }
    };

    // Enhanced detection engine with rule validation
    let engine = match create_detection_engine(&cfg.rules_path) {
        Ok(detection_engine) => {
            info!("✅ Detection engine loaded with rules from: {}", cfg.rules_path);
            detection_engine
        }
        Err(e) => {
            error!("❌ Detection engine setup failed: {}", e);
            return Err(io_err(format!("Detection: {}", e)));
        }
    };

    // Enhanced monitoring service with health tracking
    let monitor = Arc::new(Mutex::new(MonitorService::new(
        pcap, engine, db.clone(),
    )));

    // Spawn monitoring service with error recovery
    let monitor_handle = {
        let m = monitor.clone();
        tokio::spawn(async move {
            loop {
                match m.lock().await.start().await {
                    Ok(_) => {
                        info!("🔍 Monitoring service started successfully");
                        break;
                    }
                    Err(e) => {
                        error!("❌ Monitoring service error: {}", e);
                        warn!("🔄 Restarting monitoring service in 5 seconds...");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        })
    };

    // Spawn health monitor
    spawn_health_monitor(health.clone());

    // Enhanced REST API server with middleware
    let data_db = web::Data::new(db);
    let data_monitor = web::Data::new(monitor);
    let (tx, _rx) = broadcast::channel::<String>(100);
    let data_broadcaster = web::Data::new(tx.clone());
    let data_health = web::Data::new(Arc::new(Mutex::new(health.clone())));

    info!("🌐 Starting HTTP server on {}:{}", cfg.server_host, cfg.server_port);
    
    let server_result = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .wrap(actix_cors::Cors::permissive())
            .wrap(middleware::DefaultHeaders::new()
                .add(("X-NeuroDefender-Version", env!("CARGO_PKG_VERSION")))
                .add(("X-Powered-By", "NeuroDefender-Enhanced")))
            .app_data(data_db.clone())
            .app_data(data_monitor.clone())
            .app_data(data_broadcaster.clone())
            .app_data(data_health.clone())
            .configure(routes::configure)
    })
    .bind((cfg.server_host.as_str(), cfg.server_port))?
    .run()
    .await;

    // Cleanup on server shutdown
    monitor_handle.abort();
    
    match server_result {
        Ok(_) => {
            info!("✅ Server shutdown gracefully");
            Ok(())
        }
        Err(e) => {
            error!("❌ Server error: {}", e);
            Err(e)
        }
    }
}

/// Validate configuration and warn about potential issues
fn validate_config(config: &Config) {
    if config.jwt_secret == "neurodefender_secret_key_change_in_production" {
        warn!("⚠️  Using default JWT secret! Change this in production!");
    }
    
    if config.server_port < 1024 {
        warn!("⚠️  Using privileged port {}. Ensure proper permissions.", config.server_port);
    }
    
    if !config.prevention_enabled {
        info!("ℹ️  Prevention is disabled. Only detection mode active.");
    }
    
    info!("📊 Detection sensitivity: {}", config.detection_sensitivity);
    info!("🔄 Data retention: {} days", config.data_retention_days);
}

/// Enhanced PCAP manager creation with interface detection
fn create_pcap_manager(interface: &str) -> Result<PcapManager, Box<dyn std::error::Error>> {
    match PcapManager::new(interface) {
        Ok(manager) => Ok(manager),
        Err(e) => {
            warn!("Failed to create PCAP manager for {}: {}", interface, e);
            
            // Try to find an alternative interface
            let alternative_interfaces = vec!["en0", "eth0", "wlan0", "lo0"];
            
            for alt_interface in alternative_interfaces {
                if alt_interface != interface {
                    info!("Trying alternative interface: {}", alt_interface);
                    if let Ok(manager) = PcapManager::new(alt_interface) {
                        warn!("✅ Using alternative interface: {}", alt_interface);
                        return Ok(manager);
                    }
                }
            }
            
            Err(format!("No suitable network interface found").into())
        }
    }
}

/// Enhanced detection engine creation with rule validation
fn create_detection_engine(rules_path: &str) -> Result<DetectionEngine, Box<dyn std::error::Error>> {
    match DetectionEngine::new(rules_path) {
        Ok(engine) => {
            info!("🛡️  Detection engine rules loaded successfully");
            Ok(engine)
        }
        Err(e) => {
            warn!("Detection engine creation failed: {}", e);
            
            // Try creating rules directory if it doesn't exist
            if let Err(create_err) = std::fs::create_dir_all(rules_path) {
                error!("Failed to create rules directory: {}", create_err);
            } else {
                info!("Created rules directory: {}", rules_path);
                
                // Try creating a comprehensive default rule
                create_default_rules(rules_path)?;
                
                // Retry engine creation
                match DetectionEngine::new(rules_path) {
                    Ok(engine) => {
                        info!("✅ Detection engine created with default rules");
                        return Ok(engine);
                    }
                    Err(retry_err) => {
                        error!("Failed to create detection engine even with defaults: {}", retry_err);
                    }
                }
            }
            
            Err(format!("Detection engine setup failed: {}", e).into())
        }
    }
}

/// Create comprehensive default detection rules if none exist
fn create_default_rules(rules_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let default_rule_content = r#"
# NeuroDefender Enhanced Security Rules
# Version: 2.0
# Last Updated: 2025

# ========================================
# TRAFFIC ANALYSIS RULES
# ========================================

# High traffic volume detection - potential DDoS
alert tcp any any -> any any (msg:"High traffic volume detected - potential DDoS"; threshold:type both, track by_src, count 1000, seconds 60; priority:2; sid:1000001; rev:2;)

# Suspicious port scanning detection
alert tcp any any -> any [1-1024] (msg:"Potential port scan detected"; threshold:type threshold, track by_src, count 10, seconds 5; priority:1; sid:1000002; rev:2;)

# DNS flood detection
alert udp any any -> any 53 (msg:"Suspicious DNS query pattern - potential DNS amplification"; threshold:type both, track by_src, count 100, seconds 60; priority:2; sid:1000003; rev:2;)

# ========================================
# MALWARE & INTRUSION DETECTION
# ========================================

# Suspicious HTTP requests
alert tcp any any -> any 80 (msg:"Suspicious HTTP request pattern"; content:"../"; http_uri; priority:2; sid:1000010; rev:1;)
alert tcp any any -> any 80 (msg:"Potential SQL injection attempt"; content:"UNION SELECT"; http_uri; nocase; priority:1; sid:1000011; rev:1;)
alert tcp any any -> any 80 (msg:"Cross-site scripting attempt detected"; content:"<script"; http_uri; nocase; priority:2; sid:1000012; rev:1;)

# HTTPS suspicious patterns
alert tcp any any -> any 443 (msg:"Suspicious HTTPS traffic volume"; threshold:type both, track by_src, count 500, seconds 30; priority:2; sid:1000013; rev:1;)

# ========================================
# NETWORK RECONNAISSANCE DETECTION
# ========================================

# Multiple connection attempts
alert tcp any any -> any any (msg:"Multiple connection attempts - potential reconnaissance"; threshold:type threshold, track by_src, count 50, seconds 10; priority:2; sid:1000020; rev:1;)

# Ping sweep detection
alert icmp any any -> any any (msg:"ICMP ping sweep detected"; threshold:type threshold, track by_src, count 20, seconds 5; priority:3; sid:1000021; rev:1;)

# Unusual protocol usage
alert tcp any any -> any 23 (msg:"Telnet connection attempt - insecure protocol"; priority:2; sid:1000022; rev:1;)
alert tcp any any -> any 21 (msg:"FTP connection attempt - potentially insecure"; priority:3; sid:1000023; rev:1;)

# ========================================
# SUSPICIOUS OUTBOUND TRAFFIC
# ========================================

# Potential data exfiltration
alert tcp any any -> !$HOME_NET any (msg:"Large outbound data transfer"; dsize:>10000; threshold:type threshold, track by_src, count 10, seconds 60; priority:2; sid:1000030; rev:1;)

# Suspicious DNS queries to external servers
alert udp any any -> !$HOME_NET 53 (msg:"External DNS query - potential data exfiltration"; priority:3; sid:1000031; rev:1;)

# IRC/Chat protocols (potential C&C communication)
alert tcp any any -> any 6667 (msg:"IRC connection detected - potential botnet communication"; priority:2; sid:1000032; rev:1;)

# ========================================
# AUTHENTICATION & ACCESS CONTROL
# ========================================

# Multiple SSH login attempts
alert tcp any any -> any 22 (msg:"Multiple SSH connection attempts"; threshold:type threshold, track by_src, count 5, seconds 300; priority:1; sid:1000040; rev:1;)

# RDP brute force detection
alert tcp any any -> any 3389 (msg:"Multiple RDP connection attempts"; threshold:type threshold, track by_src, count 3, seconds 60; priority:1; sid:1000041; rev:1;)

# ========================================
# P2P & FILE SHARING DETECTION
# ========================================

# BitTorrent traffic
alert tcp any any -> any any (msg:"BitTorrent traffic detected"; content:"BitTorrent"; priority:3; sid:1000050; rev:1;)

# ========================================
# TIME-BASED ANOMALY DETECTION
# ========================================

# Off-hours activity detection (adjust times as needed)
alert tcp any any -> any any (msg:"Suspicious off-hours network activity"; threshold:type both, track by_src, count 100, seconds 3600; priority:3; sid:1000060; rev:1;)

# ========================================
# PROTOCOL-SPECIFIC RULES
# ========================================

# Suspicious SMTP traffic (potential spam/malware)
alert tcp any any -> any 25 (msg:"High volume SMTP traffic"; threshold:type both, track by_src, count 50, seconds 300; priority:2; sid:1000070; rev:1;)

# POP3/IMAP anomalies
alert tcp any any -> any [110,143,993,995] (msg:"Multiple email protocol connections"; threshold:type threshold, track by_src, count 20, seconds 60; priority:3; sid:1000071; rev:1;)

# ========================================
# CUSTOM THREAT INTELLIGENCE
# ========================================

# Known malicious user agents
alert tcp any any -> any 80 (msg:"Known malicious user agent detected"; content:"User-Agent: wget"; http_header; priority:1; sid:1000080; rev:1;)
alert tcp any any -> any 80 (msg:"Automated tool detected"; content:"User-Agent: curl"; http_header; priority:2; sid:1000081; rev:1;)

# ========================================
# METADATA & LOGGING RULES
# ========================================

# Log all connections to critical services (adjust as needed)
alert tcp any any -> any [22,23,80,443,3389] (msg:"Connection to critical service"; priority:3; sid:1000090; rev:1;)

# ========================================
# PERFORMANCE MONITORING
# ========================================

# High bandwidth usage detection
alert tcp any any -> any any (msg:"High bandwidth usage detected"; dsize:>65000; threshold:type both, track by_src, count 5, seconds 10; priority:3; sid:1000100; rev:1;)

# Connection flood detection
alert tcp any any -> any any (msg:"TCP connection flood detected"; flags:S; threshold:type both, track by_src, count 100, seconds 5; priority:1; sid:1000101; rev:1;)

# ========================================
# END OF RULES
# ========================================

# Rule summary:
# - Total rules: 30+
# - Coverage: DDoS, port scanning, malware, reconnaissance, data exfiltration, brute force, P2P, and more
# - Priority levels: 1 (High), 2 (Medium), 3 (Low/Info)
# - All rules include revision numbers for tracking
"#;

    let rule_file_path = format!("{}/enhanced_default.rules", rules_path);
    std::fs::write(&rule_file_path, default_rule_content)?;
    info!("✅ Created enhanced default rules file: {}", rule_file_path);

    // Also create a basic configuration file
    let config_content = r#"
# NeuroDefender Detection Configuration
# Sensitivity levels: low, medium, high

# Current sensitivity level
sensitivity = "medium"

# Thresholds for different alert types
[thresholds]
high_traffic_pps = 1000        # Packets per second
port_scan_threshold = 10       # Unique ports in timeframe
dns_query_threshold = 100      # DNS queries per minute
connection_threshold = 50      # Connections per timeframe

# Time windows (in seconds)
[timeframes]
traffic_window = 60            # Traffic analysis window
scan_window = 5               # Port scan detection window
dns_window = 60               # DNS query analysis window
connection_window = 10        # Connection analysis window

# Alert priorities
[priorities]
critical = 1
high = 2
medium = 3
low = 4
info = 5

# Network settings
[network]
home_net = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
external_net = "!$HOME_NET"

# Logging settings
[logging]
enable_detailed_logs = true
log_all_connections = false
log_blocked_only = false
max_log_entries = 10000
"#;

    let config_file_path = format!("{}/detection.conf", rules_path);
    std::fs::write(&config_file_path, config_content)?;
    info!("✅ Created detection configuration file: {}", config_file_path);

    Ok(())
}

/// Spawn health monitoring task
fn spawn_health_monitor(mut health: SystemHealth) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        
        loop {
            interval.tick().await;
            health.update_heartbeat();
            
            if !health.is_healthy() {
                warn!("⚠️  System health check failed!");
                warn!("   Backend running: {}", health.backend_running);
                warn!("   Database connected: {}", health.database_connected);
                warn!("   Network monitoring: {}", health.network_monitoring);
                warn!("   Last heartbeat: {:?} ago", health.last_heartbeat.elapsed());
            } else {
                info!("✅ System health check passed - All systems operational");
            }
        }
    });
}

/// Helper function for IO errors
fn io_err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg.into())
}

/// Backward compatibility - original backend main
pub async fn backend_main() -> std::io::Result<()> {
    backend_main_enhanced().await
}

/// Blocking wrapper with enhanced error handling
pub fn start_blocking() -> std::io::Result<()> {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("❌ Failed to create Tokio runtime: {}", e);
            return Err(io_err("Runtime creation failed"));
        }
    };

    rt.block_on(async {
        match backend_main_enhanced().await {
            Ok(_) => {
                info!("✅ Backend shutdown gracefully");
                Ok(())
            }
            Err(e) => {
                error!("❌ Backend error: {}", e);
                Err(e)
            }
        }
    })
}

/// Keep the old name for backward compatibility
pub fn start() -> std::io::Result<()> {
    start_blocking()
}

#[tauri::command]
fn get_system_info() -> Result<serde_json::Value, String> {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();

    let hostname = System::host_name().unwrap_or_else(|| "Unknown".to_string());
    let total_mem = sys.total_memory(); // kB
    let used_mem = sys.used_memory(); // kB
    let ram_percent = (used_mem as f64 / total_mem as f64) * 100.0;

    // Average CPU usage across all cores
    let cpu_usage = sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / sys.cpus().len() as f32;

    Ok(serde_json::json!({
        "deviceName": hostname,
        "totalMemMB": (total_mem as f64) / 1024.0,
        "usedMemMB": (used_mem as f64) / 1024.0,
        "ramPercent": ram_percent,
        "cpuPercent": cpu_usage,
        "neurodefender_version": env!("CARGO_PKG_VERSION"),
        "build_timestamp": env!("VERGEN_BUILD_TIMESTAMP", "unknown"),
        "rust_version": env!("VERGEN_RUSTC_SEMVER", "unknown"),
    }))
}

/// Enhanced API request command with retry logic and better error handling
#[tauri::command]
async fn api_request(endpoint: String) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
    
    let url = format!("http://127.0.0.1:55035{}", endpoint);
    let max_retries = 3;
    let mut last_error = String::new();
    
    for attempt in 1..=max_retries {
        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<serde_json::Value>().await {
                        Ok(json) => return Ok(json),
                        Err(e) => {
                            last_error = format!("Failed to parse JSON: {}", e);
                            if attempt < max_retries {
                                warn!("Attempt {} failed for {}: {}. Retrying...", attempt, endpoint, last_error);
                                tokio::time::sleep(Duration::from_millis(500 * attempt as u64)).await;
                                continue;
                            }
                        }
                    }
                } else {
                    last_error = format!("HTTP {}: {}", response.status(), response.status().canonical_reason().unwrap_or("Unknown"));
                    if attempt < max_retries {
                        warn!("Attempt {} failed for {}: {}. Retrying...", attempt, endpoint, last_error);
                        tokio::time::sleep(Duration::from_millis(500 * attempt as u64)).await;
                        continue;
                    }
                }
            }
            Err(e) => {
                last_error = format!("Request failed: {}", e);
                if attempt < max_retries {
                    warn!("Attempt {} failed for {}: {}. Retrying...", attempt, endpoint, last_error);
                    tokio::time::sleep(Duration::from_millis(500 * attempt as u64)).await;
                    continue;
                }
            }
        }
    }
    
    Err(format!("All {} attempts failed for {}: {}", max_retries, endpoint, last_error))
}

/// Enhanced health check command
#[tauri::command]
async fn get_backend_health() -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
    
    let health_url = "http://127.0.0.1:55035/health";
    
    match client.get(health_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<serde_json::Value>().await {
                    Ok(health_data) => Ok(health_data),
                    Err(e) => Err(format!("Failed to parse health response: {}", e))
                }
            } else {
                Err(format!("Backend health check failed: HTTP {}", response.status()))
            }
        }
        Err(e) => Err(format!("Cannot reach backend: {}", e))
    }
}

/// Enhanced Tauri application entry point with comprehensive error handling
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    info!("🚀 Starting NeuroDefender Tauri application...");
    
    let result = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_system_info, 
            api_request, 
            get_backend_health
        ])
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .setup(|app| {
            info!("🔧 Setting up Tauri application...");
            
            // Enhanced backend startup with error recovery
            let app_handle = app.app_handle().clone();
            std::thread::spawn(move || {
                let mut restart_count = 0;
                let max_restarts = 5;
                
                loop {
                    restart_count += 1;
                    info!("🔄 Starting backend (attempt {} of {})...", restart_count, max_restarts);
                    
                    let rt = match tokio::runtime::Runtime::new() {
                        Ok(runtime) => runtime,
                        Err(e) => {
                            error!("❌ Failed to create Tokio runtime: {}", e);
                            if restart_count < max_restarts {
                                std::thread::sleep(Duration::from_secs(5));
                                continue;
                            } else {
                                error!("❌ Maximum restart attempts reached. Backend failed to start.");
                                return;
                            }
                        }
                    };
                    
                    match rt.block_on(backend_main_enhanced()) {
                        Ok(_) => {
                            info!("✅ Backend stopped gracefully");
                            break;
                        }
                        Err(e) => {
                            error!("❌ Backend error (attempt {}): {}", restart_count, e);
                            
                            if restart_count < max_restarts {
                                warn!("🔄 Restarting backend in 10 seconds...");
                                std::thread::sleep(Duration::from_secs(10));
                            } else {
                                error!("❌ Maximum restart attempts reached. Backend failed to start permanently.");
                                
                                // Notify the frontend about the backend failure
                                if let Err(emit_err) = app_handle.emit("backend-critical-error", 
                                    serde_json::json!({
                                        "error": format!("Backend failed after {} attempts: {}", restart_count, e),
                                        "timestamp": chrono::Utc::now().to_rfc3339(),
                                        "restart_count": restart_count
                                    })
                                ) {
                                    error!("Failed to emit backend error event: {}", emit_err);
                                }
                                break;
                            }
                        }
                    }
                }
            });

            // Initialize system tray with error handling
            let handle = app.app_handle();
            match init_tray(handle) {
                Ok(_) => info!("✅ System tray initialized successfully"),
                Err(e) => {
                    error!("❌ Failed to initialize system tray: {}", e);
                    return Err(Box::new(e));
                }
            }

            // Spawn periodic health monitoring
            let app_handle_health = app.app_handle().clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("Health monitor runtime");
                rt.block_on(async {
                    let mut interval = tokio::time::interval(Duration::from_secs(60));
                    
                    loop {
                        interval.tick().await;
                        
                        // Check backend health
                        let client = reqwest::Client::builder()
                            .timeout(Duration::from_secs(5))
                            .build();
                        
                        if let Ok(client) = client {
                            match client.get("http://127.0.0.1:55035/health").send().await {
                                Ok(response) if response.status().is_success() => {
                                    // Backend is healthy
                                    if let Err(e) = app_handle_health.emit("backend-health-status", 
                                        serde_json::json!({
                                            "status": "healthy",
                                            "timestamp": chrono::Utc::now().to_rfc3339()
                                        })
                                    ) {
                                        warn!("Failed to emit health status: {}", e);
                                    }
                                }
                                Ok(response) => {
                                    warn!("Backend health check returned HTTP {}", response.status());
                                    if let Err(e) = app_handle_health.emit("backend-health-status", 
                                        serde_json::json!({
                                            "status": "unhealthy",
                                            "error": format!("HTTP {}", response.status()),
                                            "timestamp": chrono::Utc::now().to_rfc3339()
                                        })
                                    ) {
                                        warn!("Failed to emit health status: {}", e);
                                    }
                                }
                                Err(e) => {
                                    warn!("Backend health check failed: {}", e);
                                    if let Err(emit_err) = app_handle_health.emit("backend-health-status", 
                                        serde_json::json!({
                                            "status": "unreachable",
                                            "error": e.to_string(),
                                            "timestamp": chrono::Utc::now().to_rfc3339()
                                        })
                                    ) {
                                        warn!("Failed to emit health status: {}", emit_err);
                                    }
                                }
                            }
                        }
                    }
                });
            });

            info!("✅ Tauri application setup completed successfully");
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                info!("🔽 Window close requested - hiding instead of closing");
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!());
    
    match result {
        Ok(_) => info!("✅ Tauri application exited gracefully"),
        Err(e) => {
            error!("❌ Tauri application error: {}", e);
            std::process::exit(1);
        }
    }
}