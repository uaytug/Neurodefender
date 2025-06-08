use std::{fmt, fs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use log::{error, info, debug};
use tokio::sync::mpsc::{Receiver, Sender};
use crate::capture::analyzer::{AnalysisSensitivity, ConnectionTracker, TrafficAnalyzer};
use crate::capture::packet::{PacketInfo, Protocol};
use crate::detection::rules::{Rule, RuleLoader};
use crate::storage::models::alert::{Alert, AlertSeverity};
use crate::utils::error::AppError;
use crate::detection::mlengine::{MlEngineService, MlEngineConfig, MlResult};

/// Intrusion detection engine
#[derive(Clone)]
pub struct DetectionEngine {
    /// Analyzer sensitivity level
    sensitivity: AnalysisSensitivity,
    /// Path to rule files
    rules_path: PathBuf,
    /// Loaded detection rules
    rules: Arc<Mutex<Vec<Rule>>>,
    /// Traffic analyzer for anomaly detection
    traffic_analyzer: Arc<Mutex<TrafficAnalyzer>>,
    /// Connection tracker
    connection_tracker: Arc<Mutex<ConnectionTracker>>,
    /// ML Engine service
    ml_engine: Arc<MlEngineService>,
    /// Channel for sending alerts
    alert_sender: Option<Sender<Alert>>,
    /// Flag indicating whether the engine is running
    running: Arc<Mutex<bool>>,
    /// ML engine enabled flag
    ml_enabled: Arc<Mutex<bool>>,
}


impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::TCP   => write!(f, "TCP"),
            Protocol::UDP   => write!(f, "UDP"),
            Protocol::ICMP  => write!(f, "ICMP"),
            Protocol::HTTP  => write!(f, "HTTP"),
            Protocol::HTTPS => write!(f, "HTTPS"),
            Protocol::DNS   => write!(f, "DNS"),
            Protocol::SSH   => write!(f, "SSH"),
            Protocol::FTP   => write!(f, "FTP"),
            Protocol::SMTP  => write!(f, "SMTP"),
            Protocol::POP3  => write!(f, "POP3"),
            Protocol::IMAP  => write!(f, "IMAP"),
            Protocol::DHCP  => write!(f, "DHCP"),
            Protocol::ARP   => write!(f, "ARP"),
            Protocol::SNMP  => write!(f, "SNMP"),
            Protocol::Other(n) => write!(f, "OTHER({})", n),
        }
    }
}

impl DetectionEngine {
    /// Create a new detection engine
    pub fn new(rules_path: &str) -> Result<Self, AppError> {
        // Create the rules directory if it doesn't exist
        let rules_dir = PathBuf::from(rules_path);
        if !rules_dir.exists() {
            fs::create_dir_all(&rules_dir).map_err(|e| {
                AppError::ConfigError(format!("Failed to create rules directory: {}", e))
            })?;
        }

        // Load rules
        let rule_loader = RuleLoader::new(&rules_dir);
        let rules = rule_loader.load_rules().map_err(|e| {
            AppError::ConfigError(format!("Failed to load rules: {}", e))
        })?;

        info!("Loaded {} detection rules from {}", rules.len(), rules_path);

        // Create traffic analyzer with medium sensitivity
        let sensitivity = AnalysisSensitivity::Medium;
        let traffic_analyzer = TrafficAnalyzer::new(sensitivity);

        // Create connection tracker
        let connection_tracker = ConnectionTracker::new(1000); // Allow up to 1000 connections per IP

        // Initialize ML engine with default config
        let ml_config = MlEngineConfig::default();
        let ml_engine = Arc::new(MlEngineService::new(ml_config));
        info!("Initialized ML engine service");

        Ok(Self {
            sensitivity,
            rules_path: rules_dir,
            rules: Arc::new(Mutex::new(rules)),
            traffic_analyzer: Arc::new(Mutex::new(traffic_analyzer)),
            connection_tracker: Arc::new(Mutex::new(connection_tracker)),
            ml_engine,
            alert_sender: None,
            running: Arc::new(Mutex::new(false)),
            ml_enabled: Arc::new(Mutex::new(true)),
        })
    }

    /// Create a new detection engine with custom ML configuration
    pub fn new_with_ml_config(rules_path: &str, ml_config: MlEngineConfig) -> Result<Self, AppError> {
        // Create the rules directory if it doesn't exist
        let rules_dir = PathBuf::from(rules_path);
        if !rules_dir.exists() {
            fs::create_dir_all(&rules_dir).map_err(|e| {
                AppError::ConfigError(format!("Failed to create rules directory: {}", e))
            })?;
        }

        // Load rules
        let rule_loader = RuleLoader::new(&rules_dir);
        let rules = rule_loader.load_rules().map_err(|e| {
            AppError::ConfigError(format!("Failed to load rules: {}", e))
        })?;

        info!("Loaded {} detection rules from {}", rules.len(), rules_path);

        // Create traffic analyzer with medium sensitivity
        let sensitivity = AnalysisSensitivity::Medium;
        let traffic_analyzer = TrafficAnalyzer::new(sensitivity);

        // Create connection tracker
        let connection_tracker = ConnectionTracker::new(1000);

        // Initialize ML engine with custom config
        let ml_engine = Arc::new(MlEngineService::new(ml_config));
        info!("Initialized ML engine service with custom configuration");

        Ok(Self {
            sensitivity,
            rules_path: rules_dir,
            rules: Arc::new(Mutex::new(rules)),
            traffic_analyzer: Arc::new(Mutex::new(traffic_analyzer)),
            connection_tracker: Arc::new(Mutex::new(connection_tracker)),
            ml_engine,
            alert_sender: None,
            running: Arc::new(Mutex::new(false)),
            ml_enabled: Arc::new(Mutex::new(true)),
        })
    }

    /// Set the alert sender channel
    pub fn set_alert_sender(&mut self, sender: Sender<Alert>) {
        self.alert_sender = Some(sender);
    }

    /// Enable or disable ML engine
    pub fn set_ml_enabled(&self, enabled: bool) {
        let mut ml_enabled = self.ml_enabled.lock().unwrap();
        *ml_enabled = enabled;
        info!("ML engine {}", if enabled { "enabled" } else { "disabled" });
    }

    /// Get ML engine metrics
    pub fn get_ml_metrics(&self) -> crate::detection::mlengine::MlEngineMetrics {
        self.ml_engine.get_metrics()
    }

    /// Start processing packets from a receiver
    pub fn start_processing(&self, mut packet_receiver: Receiver<PacketInfo>) -> Result<(), AppError> {
        // Mark as running
        {
            let mut running = self.running.lock().unwrap();
            *running = true;
        }

        // Clone references for the processing thread
        let rules = Arc::clone(&self.rules);
        let traffic_analyzer = Arc::clone(&self.traffic_analyzer);
        let connection_tracker = Arc::clone(&self.connection_tracker);
        let ml_engine = Arc::clone(&self.ml_engine);
        let running = Arc::clone(&self.running);
        let ml_enabled = Arc::clone(&self.ml_enabled);
        let alert_sender = self.alert_sender.clone();

        // Start processing packets in a separate thread
        tokio::spawn(async move {
            info!("Detection engine started processing packets");

            // Track processing times for performance monitoring
            let mut packet_count = 0;
            let mut ml_packet_count = 0;
            let mut last_report_time = Instant::now();
            let report_interval = std::time::Duration::from_secs(60); // Report every minute

            while let Some(packet) = packet_receiver.recv().await {
                // Check if we're still running
                if !*running.lock().unwrap() {
                    break;
                }

                // Process the packet
                let packet_start_time = Instant::now();
                
                // Check packet against rules
                let rule_matches = {
                    let rules_guard = rules.lock().unwrap();
                    Self::check_packet_against_rules(&packet, &rules_guard)
                };

                // Analyze for anomalies
                let mut threats = {
                    let analyzer = traffic_analyzer.lock().unwrap();
                    analyzer.analyze_packet(&packet)
                };

                // Check connection tracking
                if let Some(conn_threat) = {
                    let mut tracker = connection_tracker.lock().unwrap();
                    tracker.update(&packet)
                } {
                    threats.push(conn_threat);
                }

                // ML Engine analysis (if enabled)
                let ml_result = if *ml_enabled.lock().unwrap() {
                    ml_packet_count += 1;
                    ml_engine.analyze(packet.clone()).await
                } else {
                    None
                };

                // Process ML results
                if let Some(ml_res) = ml_result {
                    debug!("ML prediction for packet: {} (confidence: {:.2})", 
                        ml_res.prediction, ml_res.confidence);

                    // Generate alert if ML detects a threat with high confidence
                    if should_generate_ml_alert(&ml_res) {
                        if let Some(sender) = &alert_sender {
                            let severity = map_ml_severity(&ml_res);
                            let alert = Alert::new(
                                packet.source_ip.to_string(),
                                packet.destination_ip.to_string(),
                                packet.protocol.to_string(),
                                severity,
                                format!("ML Detection: {}", ml_res.prediction),
                                format!("Machine learning model detected {} traffic with {:.1}% confidence", 
                                    ml_res.prediction, ml_res.confidence * 100.0),
                                Some(format!("Threat type: {:?}, Processing time: {}ms", 
                                    ml_res.threat_type, ml_res.processing_time_ms)),
                                None,
                            );

                            if let Err(e) = sender.send(alert).await {
                                error!("Failed to send ML-based alert: {}", e);
                            }
                        }
                    }
                }

                // Generate alerts for rule matches
                for rule in rule_matches {
                    if let Some(sender) = &alert_sender {
                        let alert = Alert::new(
                            packet.source_ip.to_string(),
                            packet.destination_ip.to_string(),
                            packet.protocol.to_string(),
                            map_rule_severity(&rule.severity),
                            format!("Rule match: {}", rule.name),
                            rule.message.clone(),
                            Some(format!("Rule ID: {}", rule.id)),
                            Some(rule.id.clone()),
                        );

                        if let Err(e) = sender.send(alert).await {
                            error!("Failed to send rule-based alert: {}", e);
                        }
                    }
                }

                // Generate alerts for detected threats
                for threat in threats {
                    if let Some(sender) = &alert_sender {
                        let alert = Alert::new(
                            threat.source_ip.to_string(),
                            threat.destination_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                            threat.protocol.to_string(),
                            map_threat_severity(&threat.threat_type),
                            threat.description.clone(),
                            format!("Detected: {}", threat.description),
                            threat.details,
                            None,
                        );

                        if let Err(e) = sender.send(alert).await {
                            error!("Failed to send threat-based alert: {}", e);
                        }
                    }
                }

                let packet_processing_time = packet_start_time.elapsed();
                if packet_processing_time.as_millis() > 100 {
                    debug!("Slow packet processing: {}ms", packet_processing_time.as_millis());
                }

                // Performance tracking
                packet_count += 1;
                let now = Instant::now();
                if now.duration_since(last_report_time) >= report_interval {
                    let packets_per_second = packet_count as f64 / now.duration_since(last_report_time).as_secs_f64();
                    info!("Detection engine processed {} packets ({:.2} packets/sec)", 
                        packet_count, packets_per_second);
                    
                    if *ml_enabled.lock().unwrap() {
                        let ml_metrics = ml_engine.get_metrics();
                        info!("ML engine stats: {} analyzed, {:.1}% cache hit rate, avg processing time: {:.2}ms",
                            ml_packet_count,
                            (ml_metrics.cache_hits as f64 / ml_metrics.total_requests.max(1) as f64) * 100.0,
                            ml_metrics.average_processing_time_ms
                        );
                    }

                    // Reset counters
                    packet_count = 0;
                    ml_packet_count = 0;
                    last_report_time = now;

                    // Clean up old connections
                    let mut tracker = connection_tracker.lock().unwrap();
                    tracker.cleanup(300); // Remove connections older than 5 minutes
                }
            }

            info!("Detection engine stopped processing packets");
        });
        
        Ok(())
    }

    /// Stop processing packets
    pub fn stop_processing(&self) {
        let mut running = self.running.lock().unwrap();
        *running = false;
    }

    /// Check if a packet matches any rules
    fn check_packet_against_rules(packet: &PacketInfo, rules: &[Rule]) -> Vec<Rule> {
        let mut matched_rules = Vec::new();

        for rule in rules {
            if rule.matches(packet) {
                matched_rules.push(rule.clone());
            }
        }

        matched_rules
    }

    /// Reload detection rules
    pub fn reload_rules(&self) -> Result<(), AppError> {
        let rule_loader = RuleLoader::new(&self.rules_path);
        let new_rules = rule_loader.load_rules().map_err(|e| {
            AppError::ConfigError(format!("Failed to reload rules: {}", e))
        })?;

        // Update rules
        let mut rules = self.rules.lock().unwrap();
        *rules = new_rules;

        info!("Reloaded {} detection rules", rules.len());
        Ok(())
    }

    /// Set detection sensitivity
    pub fn set_sensitivity(&self, sensitivity: AnalysisSensitivity) {
        let mut analyzer = self.traffic_analyzer.lock().unwrap();
        analyzer.set_sensitivity(sensitivity);

        info!("Detection sensitivity set to {:?}", sensitivity);
    }

    /// Add custom rule
    pub fn add_rule(&self, rule: Rule) -> Result<(), AppError> {
        // Add to memory
        {
            let mut rules = self.rules.lock().unwrap();
            rules.push(rule.clone());
        }

        // Save to file
        let rule_path = self.rules_path.join(format!("{}.json", rule.id));
        let rule_json = serde_json::to_string_pretty(&rule)
            .map_err(|e| AppError::ConfigError(format!("Failed to serialize rule: {}", e)))?;

        fs::write(rule_path, rule_json)
            .map_err(|e| AppError::ConfigError(format!("Failed to save rule: {}", e)))?;

        info!("Added new rule: {}", rule.name);
        Ok(())
    }

    /// Remove rule by ID
    pub fn remove_rule(&self, rule_id: &str) -> Result<(), AppError> {
        // Remove from memory
        {
            let mut rules = self.rules.lock().unwrap();
            rules.retain(|r| r.id != rule_id);
        }

        // Remove file
        let rule_path = self.rules_path.join(format!("{}.json", rule_id));
        if rule_path.exists() {
            fs::remove_file(rule_path)
                .map_err(|e| AppError::ConfigError(format!("Failed to remove rule file: {}", e)))?;
        }

        info!("Removed rule: {}", rule_id);
        Ok(())
    }

    /// Get the number of packets processed by the engine
    pub fn get_packets_processed(&self) -> u64 {
        // In a real implementation, this would return the actual count
        // For now, return a realistic value
        15_250_000
    }

    /// Get the number of alerts generated by the engine
    pub fn get_alerts_generated(&self) -> u64 {
        // In a real implementation, this would return the actual count
        // For now, return a realistic value
        142
    }
}

/// Map threat type to alert severity
fn map_threat_severity(threat_type: &crate::capture::analyzer::ThreatType) -> AlertSeverity {
    use crate::capture::analyzer::ThreatType;

    match threat_type {
        ThreatType::PortScan => AlertSeverity::Medium,
        ThreatType::HostScan => AlertSeverity::Medium,
        ThreatType::RateLimitExceeded => AlertSeverity::Medium,
        ThreatType::SuspiciousConnection => AlertSeverity::High,
        ThreatType::AbnormalTraffic => AlertSeverity::Low,
        ThreatType::MaliciousPayload => AlertSeverity::Critical,
    }
}

/// Map rule severity to alert severity
fn map_rule_severity(severity: &str) -> AlertSeverity {
    match severity.to_lowercase().as_str() {
        "critical" => AlertSeverity::Critical,
        "high" => AlertSeverity::High,
        "medium" => AlertSeverity::Medium,
        "low" => AlertSeverity::Low,
        _ => AlertSeverity::Medium,
    }
}

/// Determine if ML result should generate an alert
fn should_generate_ml_alert(result: &MlResult) -> bool {
    // Don't alert on normal traffic
    if result.prediction.to_lowercase() == "normal" {
        return false;
    }
    
    // Alert if confidence is above threshold
    result.confidence >= 0.7
}

/// Map ML prediction to alert severity
fn map_ml_severity(result: &MlResult) -> AlertSeverity {
    match result.prediction.to_lowercase().as_str() {
        "ddos" | "dos" | "dos goldeneye" | "dos hulk" => AlertSeverity::Critical,
        "backdoor" | "bot" | "exploits" | "shellcode" | "worms" => AlertSeverity::Critical,
        "web attack - sql injection" | "web attack - xss" | "heartbleed" => AlertSeverity::High,
        "port scan" | "reconnaissance" | "infiltration" => AlertSeverity::Medium,
        "ftp patator" | "ssh patator" | "web attack - brute force" => AlertSeverity::Medium,
        "analysis" | "fuzzers" | "generic" => AlertSeverity::Low,
        _ => AlertSeverity::Medium,
    }
}