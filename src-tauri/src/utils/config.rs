use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use anyhow::{Result, Context};
use log::{info, warn, error};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    // Server settings
    pub server_host: String,
    pub server_port: u16,

    // Database settings
    pub mongodb_uri: String,
    pub fallback_mongodb_uri: String,
    pub no_connection_db_log: String,
    pub database_name: String,

    // Network settings
    pub network_interface: String,

    // Security settings
    pub jwt_secret: String,
    pub jwt_expiration: u64, // In seconds

    // Detection settings
    pub rules_path: String,
    pub detection_sensitivity: String, // "low", "medium", "high"

    // Logging settings
    pub log_level: String,
    pub log_file: Option<String>,

    // Data retention settings
    pub data_retention_days: u32,

    pub prevention_enabled: bool,
    pub prevention_use_native_firewall: bool,
    pub prevention_auto_block_duration: u32,
}

impl Config {
    /// Enhanced configuration loading with comprehensive validation and fallbacks
    pub fn load() -> Result<Self> {
        // Load environment variables from .env file if it exists
        dotenv::dotenv().ok();

        // Try multiple configuration file locations
        let config_paths = vec![
            std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.json".to_string()),
            "config.json".to_string(),
            "configs/config.json".to_string(),
            "/etc/neurodefender/config.json".to_string(),
            dirs::config_dir().map(|p| p.join("neurodefender/config.json").to_string_lossy().to_string()).unwrap_or_default(),
        ];

        let mut config_loaded = false;
        let mut config: Option<Config> = None;

        for config_path in &config_paths {
            if config_path.is_empty() {
                continue;
            }
            
            info!("Attempting to load configuration from: {}", config_path);
            
            if Path::new(config_path).exists() {
                match Self::load_from_file(config_path) {
                    Ok(loaded_config) => {
                        info!("✅ Configuration successfully loaded from: {}", config_path);
                        config = Some(loaded_config);
                        config_loaded = true;
                        break;
                    }
                    Err(e) => {
                        error!("❌ Failed to load config from {}: {}", config_path, e);
                        continue;
                    }
                }
            } else {
                warn!("Configuration file not found: {}", config_path);
            }
        }

        let final_config = if config_loaded {
            config.unwrap()
        } else {
            warn!("⚠️  No configuration file found. Using environment variables and defaults.");
            Self::from_environment_and_defaults()?
        };

        // Validate the configuration
        final_config.validate()?;
        
        info!("🔧 Configuration validation passed");
        Ok(final_config)
    }

    /// Load configuration from a specific file
    fn load_from_file(config_path: &str) -> Result<Self> {
        let mut file = File::open(config_path)
            .with_context(|| format!("Failed to open config file: {}", config_path))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .with_context(|| format!("Failed to read config file: {}", config_path))?;

        let config: Config = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", config_path))?;

        Ok(config)
    }

    /// Create configuration from environment variables and sensible defaults
    fn from_environment_and_defaults() -> Result<Self> {
        info!("Building configuration from environment variables and defaults");

        let config = Config {
            server_host: std::env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            server_port: std::env::var("SERVER_PORT")
                .unwrap_or_else(|_| "55035".to_string())
                .parse::<u16>()
                .unwrap_or(55035),

            mongodb_uri: std::env::var("MONGODB_URI")
                .unwrap_or_else(|_| "mongodb://localhost:27017".to_string()),
            fallback_mongodb_uri: std::env::var("FALLBACK_MONGODB_URI")
                .unwrap_or_else(|_| "your_mongodb_uri".to_string()),
            no_connection_db_log: std::env::var("NO_CONNECTION_DB_LOG")
                .unwrap_or_else(|_| "db_connection_fallback.log".to_string()),
            database_name: std::env::var("DATABASE_NAME")
                .unwrap_or_else(|_| "neurodefender".to_string()),

            network_interface: std::env::var("NETWORK_INTERFACE")
                .unwrap_or_else(|_| Self::detect_network_interface()),

            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| {
                    warn!("⚠️  JWT_SECRET not set, using default (INSECURE for production!)");
                    "neurodefender_secret_key_change_in_production".to_string()
                }),
            jwt_expiration: std::env::var("JWT_EXPIRATION")
                .unwrap_or_else(|_| "86400".to_string()) // 24 hours
                .parse::<u64>().unwrap_or(86400),

            rules_path: std::env::var("RULES_PATH")
                .unwrap_or_else(|_| "rules".to_string()),
            detection_sensitivity: std::env::var("DETECTION_SENSITIVITY")
                .unwrap_or_else(|_| "medium".to_string()),

            log_level: std::env::var("LOG_LEVEL")
                .unwrap_or_else(|_| "info".to_string()),
            log_file: std::env::var("LOG_FILE").ok(),

            data_retention_days: std::env::var("DATA_RETENTION_DAYS")
                .unwrap_or_else(|_| "30".to_string())
                .parse::<u32>().unwrap_or(30),

            prevention_enabled: std::env::var("PREVENTION_ENABLED")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(false),
            prevention_use_native_firewall: std::env::var("PREVENTION_USE_NATIVE_FIREWALL")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true),
            prevention_auto_block_duration: std::env::var("PREVENTION_BLOCK_DURATION")
                .unwrap_or_else(|_| "60".to_string())
                .parse::<u32>().unwrap_or(60),
        };

        Ok(config)
    }

    /// Comprehensive configuration validation
    pub fn validate(&self) -> Result<()> {
        let mut errors = Vec::new();

        // Validate server settings
        if self.server_host.is_empty() {
            errors.push("Server host cannot be empty".to_string());
        }

        if self.server_port == 0 || self.server_port > 65535 {
            errors.push(format!("Invalid server port: {}", self.server_port));
        }

        if self.server_port < 1024 && self.server_host == "0.0.0.0" {
            warn!("⚠️  Using privileged port {} with public binding. Ensure proper permissions and security.", self.server_port);
        }

        // Validate database settings
        if self.mongodb_uri.is_empty() {
            errors.push("MongoDB URI cannot be empty".to_string());
        }

        if self.database_name.is_empty() {
            errors.push("Database name cannot be empty".to_string());
        }

        // Validate security settings
        if self.jwt_secret == "neurodefender_secret_key_change_in_production" {
            warn!("⚠️  Using default JWT secret! This is INSECURE for production environments!");
        }

        if self.jwt_secret.len() < 32 {
            warn!("⚠️  JWT secret is shorter than 32 characters. Consider using a longer, more secure secret.");
        }

        if self.jwt_expiration < 300 {
            warn!("⚠️  JWT expiration is very short (< 5 minutes). This may cause usability issues.");
        }

        if self.jwt_expiration > 7 * 24 * 3600 {
            warn!("⚠️  JWT expiration is very long (> 7 days). This may pose a security risk.");
        }

        // Validate detection settings
        let valid_sensitivities = ["low", "medium", "high"];
        if !valid_sensitivities.contains(&self.detection_sensitivity.as_str()) {
            errors.push(format!("Invalid detection sensitivity: '{}'. Must be one of: {:?}", 
                self.detection_sensitivity, valid_sensitivities));
        }

        // Validate logging settings
        let valid_log_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_log_levels.contains(&self.log_level.as_str()) {
            errors.push(format!("Invalid log level: '{}'. Must be one of: {:?}", 
                self.log_level, valid_log_levels));
        }

        // Validate data retention
        if self.data_retention_days == 0 {
            warn!("⚠️  Data retention is set to 0 days. Data will be immediately purged.");
        }

        if self.data_retention_days > 365 {
            warn!("⚠️  Data retention is set to more than 1 year. This may consume significant storage.");
        }

        // Validate prevention settings
        if self.prevention_auto_block_duration == 0 {
            warn!("⚠️  Auto block duration is 0. Blocked IPs will never be automatically unblocked.");
        }

        // Check for required directories
        self.validate_paths()?;

        if !errors.is_empty() {
            return Err(anyhow::anyhow!("Configuration validation failed:\n{}", errors.join("\n")));
        }

        info!("🔧 Configuration validation successful");
        Ok(())
    }

    /// Validate required paths and create them if necessary
    fn validate_paths(&self) -> Result<()> {
        // Check rules path
        if !Path::new(&self.rules_path).exists() {
            warn!("Rules directory doesn't exist: {}. Will attempt to create it.", self.rules_path);
            std::fs::create_dir_all(&self.rules_path)
                .with_context(|| format!("Failed to create rules directory: {}", self.rules_path))?;
            info!("✅ Created rules directory: {}", self.rules_path);
        }

        // Check log file path if specified
        if let Some(log_file) = &self.log_file {
            if let Some(parent) = Path::new(log_file).parent() {
                if !parent.exists() {
                    warn!("Log directory doesn't exist: {}. Will attempt to create it.", parent.display());
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("Failed to create log directory: {}", parent.display()))?;
                    info!("✅ Created log directory: {}", parent.display());
                }
            }
        }

        Ok(())
    }

    /// Enhanced network interface detection with multiple fallbacks
    fn detect_network_interface() -> String {
        info!("🔍 Auto-detecting network interface...");

        // Platform-specific default interfaces to try
        let candidate_interfaces = Self::get_candidate_interfaces();

        for interface in &candidate_interfaces {
            if Self::interface_exists(interface) {
                info!("✅ Detected network interface: {}", interface);
                return interface.clone();
            }
        }

        warn!("⚠️  Could not detect a suitable network interface. Using fallback: en0");
        "en0".to_string()
    }

    /// Get platform-specific candidate interfaces
    fn get_candidate_interfaces() -> Vec<String> {
        #[cfg(target_os = "macos")]
        {
            vec!["en0".to_string(), "en1".to_string(), "lo0".to_string()]
        }

        #[cfg(target_os = "linux")]
        {
            vec!["eth0".to_string(), "ens33".to_string(), "wlan0".to_string(), "lo".to_string()]
        }

        #[cfg(target_os = "windows")]
        {
            vec!["Ethernet".to_string(), "Wi-Fi".to_string(), "Local Area Connection".to_string()]
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            vec!["eth0".to_string(), "en0".to_string()]
        }
    }

    /// Check if a network interface exists (simplified check)
    fn interface_exists(interface: &str) -> bool {
        // This is a simplified check. In a real implementation,
        // you'd use system calls to check interface existence
        
        #[cfg(target_os = "macos")]
        {
            std::process::Command::new("ifconfig")
                .arg(interface)
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        }

        #[cfg(target_os = "linux")]
        {
            Path::new(&format!("/sys/class/net/{}", interface)).exists()
        }

        #[cfg(target_os = "windows")]
        {
            // Windows interface checking would be more complex
            true // For now, assume it exists
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            true // Fallback for other platforms
        }
    }

    /// Display configuration summary (without sensitive information)
    pub fn display_summary(&self) {
        info!("📋 Configuration Summary:");
        info!("   Server: {}:{}", self.server_host, self.server_port);
        info!("   Database: {} (fallback configured)", 
            self.mongodb_uri.split('@').last().unwrap_or("unknown"));
        info!("   Network Interface: {}", self.network_interface);
        info!("   Rules Path: {}", self.rules_path);
        info!("   Detection Sensitivity: {}", self.detection_sensitivity);
        info!("   Log Level: {}", self.log_level);
        info!("   Prevention: {}", if self.prevention_enabled { "Enabled" } else { "Disabled" });
        info!("   Data Retention: {} days", self.data_retention_days);
    }
}

// Try to determine the default network interface (backward compatibility)
fn get_default_interface() -> String {
    Config::detect_network_interface()
}