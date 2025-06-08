use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tokio::fs;
use anyhow::{Context, Result};
use serde::{Serialize, Deserialize};
use log::{info, warn, error};
use notify::{Watcher, RecursiveMode, Event, Config as NotifyConfig};

/// System configuration with all settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    pub general: GeneralConfig,
    pub security: SecurityConfig,
    pub network: NetworkConfig,
    pub detection: DetectionConfig,
    pub performance: PerformanceConfig,
    pub logging: LoggingConfig,
    pub database: DatabaseConfig,
    pub api: ApiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub application_name: String,
    pub version: String,
    pub environment: String,
    pub auto_start: bool,
    pub run_in_background: bool,
    pub check_updates: bool,
    pub update_channel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enable_ids: bool,
    pub enable_ips: bool,
    pub max_alert_rate: u64,
    pub alert_retention_days: u32,
    pub block_duration_minutes: u32,
    pub whitelist_ips: Vec<String>,
    pub blacklist_ips: Vec<String>,
    pub threat_intelligence_feeds: Vec<String>,
    pub enable_machine_learning: bool,
    pub ml_model_path: Option<String>,
    pub enable_sandboxing: bool,
    pub quarantine_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub interfaces: Vec<String>,
    pub promiscuous_mode: bool,
    pub packet_buffer_size: usize,
    pub capture_filter: Option<String>,
    pub max_packet_size: usize,
    pub enable_deep_packet_inspection: bool,
    pub ssl_keylog_file: Option<String>,
    pub dns_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub rules_directory: String,
    pub custom_rules_enabled: bool,
    pub rule_update_interval_hours: u32,
    pub ml_threshold: f32,
    pub anomaly_detection_enabled: bool,
    pub behavioral_analysis_enabled: bool,
    pub heuristic_analysis_enabled: bool,
    pub signature_update_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub worker_threads: usize,
    pub max_memory_mb: usize,
    pub cpu_limit_percent: u8,
    pub cache_size_mb: usize,
    pub batch_processing_size: usize,
    pub processing_timeout_ms: u64,
    pub enable_compression: bool,
    pub enable_deduplication: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub log_level: String,
    pub log_directory: String,
    pub max_log_size_mb: usize,
    pub log_retention_days: u32,
    pub enable_syslog: bool,
    pub syslog_server: Option<String>,
    pub enable_json_logs: bool,
    pub log_sensitive_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub connection_string: String,
    pub max_connections: u32,
    pub connection_timeout_seconds: u32,
    pub enable_ssl: bool,
    pub ssl_ca_file: Option<String>,
    pub backup_enabled: bool,
    pub backup_interval_hours: u32,
    pub backup_retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub listen_address: String,
    pub listen_port: u16,
    pub enable_https: bool,
    pub ssl_cert_file: Option<String>,
    pub ssl_key_file: Option<String>,
    pub cors_origins: Vec<String>,
    pub rate_limit_requests: u64,
    pub rate_limit_window_seconds: u64,
    pub jwt_secret: String,
    pub jwt_expiry_hours: u32,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                application_name: "NeuroDefender".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                environment: "production".to_string(),
                auto_start: true,
                run_in_background: true,
                check_updates: true,
                update_channel: "stable".to_string(),
            },
            security: SecurityConfig {
                enable_ids: true,
                enable_ips: true,
                max_alert_rate: 1000,
                alert_retention_days: 90,
                block_duration_minutes: 60,
                whitelist_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
                blacklist_ips: vec![],
                threat_intelligence_feeds: vec![
                    "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz".to_string(),
                ],
                enable_machine_learning: true,
                ml_model_path: None,
                enable_sandboxing: false,
                quarantine_path: "./quarantine".to_string(),
            },
            network: NetworkConfig {
                interfaces: vec![],
                promiscuous_mode: true,
                packet_buffer_size: 10_000_000,
                capture_filter: None,
                max_packet_size: 65535,
                enable_deep_packet_inspection: true,
                ssl_keylog_file: None,
                dns_servers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
            },
            detection: DetectionConfig {
                rules_directory: "./rules".to_string(),
                custom_rules_enabled: true,
                rule_update_interval_hours: 24,
                ml_threshold: 0.85,
                anomaly_detection_enabled: true,
                behavioral_analysis_enabled: true,
                heuristic_analysis_enabled: true,
                signature_update_url: None,
            },
            performance: PerformanceConfig {
                worker_threads: num_cpus::get(),
                max_memory_mb: 2048,
                cpu_limit_percent: 80,
                cache_size_mb: 512,
                batch_processing_size: 1000,
                processing_timeout_ms: 5000,
                enable_compression: true,
                enable_deduplication: true,
            },
            logging: LoggingConfig {
                log_level: "info".to_string(),
                log_directory: "./logs".to_string(),
                max_log_size_mb: 100,
                log_retention_days: 30,
                enable_syslog: false,
                syslog_server: None,
                enable_json_logs: true,
                log_sensitive_data: false,
            },
            database: DatabaseConfig {
                connection_string: "mongodb://localhost:27017/neurodefender".to_string(),
                max_connections: 100,
                connection_timeout_seconds: 30,
                enable_ssl: false,
                ssl_ca_file: None,
                backup_enabled: true,
                backup_interval_hours: 24,
                backup_retention_days: 7,
            },
            api: ApiConfig {
                listen_address: "0.0.0.0".to_string(),
                listen_port: 3000,
                enable_https: false,
                ssl_cert_file: None,
                ssl_key_file: None,
                cors_origins: vec!["http://localhost:3000".to_string()],
                rate_limit_requests: 100,
                rate_limit_window_seconds: 60,
                jwt_secret: "change-me-in-production".to_string(),
                jwt_expiry_hours: 24,
            },
        }
    }
}

/// Configuration manager with hot reloading
pub struct ConfigManager {
    config: Arc<RwLock<SystemConfig>>,
    config_path: PathBuf,
    watcher: Option<notify::RecommendedWatcher>,
    update_channel: mpsc::Sender<ConfigUpdate>,
}

#[derive(Debug)]
pub enum ConfigUpdate {
    Reload,
    Update(SystemConfig),
}

impl ConfigManager {
    /// Create a new configuration manager
    pub async fn new<P: AsRef<Path>>(config_path: P) -> Result<Self> {
        let config_path = config_path.as_ref().to_path_buf();
        let config = Self::load_config(&config_path).await?;
        
        let (tx, mut rx) = mpsc::channel(10);
        
        let manager = Self {
            config: Arc::new(RwLock::new(config)),
            config_path: config_path.clone(),
            watcher: None,
            update_channel: tx.clone(),
        };
        
        // Start configuration update handler
        let config_clone = Arc::clone(&manager.config);
        let config_path_clone = config_path.clone();
        tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                match update {
                    ConfigUpdate::Reload => {
                        match Self::load_config(&config_path_clone).await {
                            Ok(new_config) => {
                                if let Err(e) = Self::validate_config(&new_config) {
                                    error!("Invalid configuration: {}", e);
                                    continue;
                                }
                                
                                let mut config = config_clone.write().await;
                                *config = new_config;
                                info!("Configuration reloaded successfully");
                            }
                            Err(e) => error!("Failed to reload configuration: {}", e),
                        }
                    }
                    ConfigUpdate::Update(new_config) => {
                        if let Err(e) = Self::validate_config(&new_config) {
                            error!("Invalid configuration update: {}", e);
                            continue;
                        }
                        
                        let mut config = config_clone.write().await;
                        *config = new_config;
                        info!("Configuration updated successfully");
                    }
                }
            }
        });
        
        Ok(manager)
    }
    
    /// Enable hot reloading of configuration
    pub fn enable_hot_reload(&mut self) -> Result<()> {
        let tx = self.update_channel.clone();
        
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    if event.kind.is_modify() {
                        let _ = tx.blocking_send(ConfigUpdate::Reload);
                    }
                }
                Err(e) => error!("Watch error: {:?}", e),
            }
        })?;
        
        watcher.watch(&self.config_path, RecursiveMode::NonRecursive)?;
        self.watcher = Some(watcher);
        
        info!("Configuration hot reload enabled for: {:?}", self.config_path);
        Ok(())
    }
    
    /// Load configuration from file
    async fn load_config(path: &Path) -> Result<SystemConfig> {
        if !path.exists() {
            info!("Configuration file not found, creating default configuration");
            let config = SystemConfig::default();
            Self::save_config(path, &config).await?;
            return Ok(config);
        }
        
        let contents = fs::read_to_string(path)
            .await
            .context("Failed to read configuration file")?;
        
        let config: SystemConfig = toml::from_str(&contents)
            .context("Failed to parse configuration file")?;
        
        Self::validate_config(&config)?;
        
        Ok(config)
    }
    
    /// Save configuration to file
    async fn save_config(path: &Path, config: &SystemConfig) -> Result<()> {
        let contents = toml::to_string_pretty(config)
            .context("Failed to serialize configuration")?;
        
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .context("Failed to create configuration directory")?;
        }
        
        fs::write(path, contents)
            .await
            .context("Failed to write configuration file")?;
        
        Ok(())
    }
    
    /// Validate configuration
    fn validate_config(config: &SystemConfig) -> Result<()> {
        // Validate general settings
        if config.general.application_name.is_empty() {
            return Err(anyhow::anyhow!("Application name cannot be empty"));
        }
        
        // Validate security settings
        if config.security.max_alert_rate == 0 {
            return Err(anyhow::anyhow!("Max alert rate must be greater than 0"));
        }
        
        if config.security.alert_retention_days == 0 {
            return Err(anyhow::anyhow!("Alert retention days must be greater than 0"));
        }
        
        // Validate network settings
        if config.network.packet_buffer_size == 0 {
            return Err(anyhow::anyhow!("Packet buffer size must be greater than 0"));
        }
        
        if config.network.max_packet_size == 0 || config.network.max_packet_size > 65535 {
            return Err(anyhow::anyhow!("Max packet size must be between 1 and 65535"));
        }
        
        // Validate performance settings
        if config.performance.worker_threads == 0 {
            return Err(anyhow::anyhow!("Worker threads must be greater than 0"));
        }
        
        if config.performance.cpu_limit_percent > 100 {
            return Err(anyhow::anyhow!("CPU limit cannot exceed 100%"));
        }
        
        // Validate API settings
        if config.api.listen_port == 0 {
            return Err(anyhow::anyhow!("API port must be greater than 0"));
        }
        
        if config.api.jwt_secret == "change-me-in-production" {
            warn!("Using default JWT secret - this is insecure in production!");
        }
        
        Ok(())
    }
    
    /// Get current configuration
    pub async fn get_config(&self) -> SystemConfig {
        self.config.read().await.clone()
    }
    
    /// Update configuration
    pub async fn update_config(&self, config: SystemConfig) -> Result<()> {
        self.update_channel.send(ConfigUpdate::Update(config)).await?;
        Ok(())
    }
    
    /// Get specific configuration section
    pub async fn get_security_config(&self) -> SecurityConfig {
        self.config.read().await.security.clone()
    }
    
    pub async fn get_network_config(&self) -> NetworkConfig {
        self.config.read().await.network.clone()
    }
    
    pub async fn get_detection_config(&self) -> DetectionConfig {
        self.config.read().await.detection.clone()
    }
    
    pub async fn get_performance_config(&self) -> PerformanceConfig {
        self.config.read().await.performance.clone()
    }
    
    /// Save current configuration to file
    pub async fn save(&self) -> Result<()> {
        let config = self.config.read().await;
        Self::save_config(&self.config_path, &*config).await
    }
} 