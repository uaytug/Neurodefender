use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use chrono::{DateTime, Utc};
use log::{info, warn, error};
use tokio::time;
use serde::{Serialize, Deserialize};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use crate::prevention::actions::{PreventionAction, PreventionSettings, ThreatCategory, ResponseStrategy, PreventionMetrics};
use crate::prevention::firewall::FirewallManager;
use crate::prevention::rate_limiter::{RateLimiter, RateLimiterConfig};
use crate::prevention::threat_intelligence::{ThreatIntelligenceManager, ThreatFeed, FeedFormat};
use crate::prevention::connection_tracker::{ConnectionTracker, ConnectionTrackerConfig};
use crate::storage::models::alert::Alert;
use crate::utils::error::AppError;

/// Represents a blocked IP with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedIP {
    /// The IP address
    pub ip: String,

    /// When the block was created
    pub blocked_at: DateTime<Utc>,

    /// When the block expires (None for permanent)
    pub expires_at: Option<DateTime<Utc>>,

    /// Reason for the block
    pub reason: String,

    /// Alert ID that triggered the block
    pub alert_id: Option<String>,

    /// Prevention action used
    pub action: PreventionAction,

    /// Threat category
    pub threat_category: Option<ThreatCategory>,
}

/// Tracks escalation state for an IP
#[derive(Debug, Clone)]
struct EscalationState {
    current_level: u8,
    last_action: PreventionAction,
    last_escalation: Instant,
    incident_count: u32,
}

/// Enhanced prevention manager with integrated components
pub struct PreventionManager {
    /// Firewall manager
    firewall: Arc<Mutex<FirewallManager>>,

    /// Prevention settings
    settings: RwLock<PreventionSettings>,

    /// IP addresses in the temporary block list with their expiration time
    temp_blocks: Arc<Mutex<HashMap<IpAddr, Instant>>>,

    /// Whitelisted IPs
    whitelist: Arc<Mutex<HashSet<IpAddr>>>,

    /// Blacklisted IPs
    blacklist: Arc<Mutex<HashSet<IpAddr>>>,

    /// Is the manager running
    running: Arc<AtomicBool>,

    /// Block history
    block_history: Arc<Mutex<Vec<BlockedIP>>>,

    /// Prevention metrics
    metrics: Arc<RwLock<PreventionMetrics>>,

    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,

    /// Threat intelligence manager
    threat_intel: Arc<ThreatIntelligenceManager>,

    /// Connection tracker
    connection_tracker: Arc<ConnectionTracker>,

    /// Response escalation tracking
    escalation_tracker: Arc<Mutex<HashMap<IpAddr, EscalationState>>>,
}

impl PreventionManager {
    /// Create a new enhanced prevention manager
    pub fn new(settings: PreventionSettings) -> Self {
        let use_native_firewall = settings.use_native_firewall;
        let whitelist_ips = settings.whitelist.clone();
        let blacklist_ips = settings.blacklist.clone();

        // Convert whitelist strings to IP addresses
        let mut whitelist = HashSet::new();
        for ip_str in whitelist_ips {
            match IpAddr::from_str(&ip_str) {
                Ok(ip) => {
                    whitelist.insert(ip);
                },
                Err(e) => {
                    warn!("Invalid IP address in whitelist: {} - {}", ip_str, e);
                }
            }
        }

        // Convert blacklist strings to IP addresses
        let mut blacklist = HashSet::new();
        for ip_str in blacklist_ips {
            match IpAddr::from_str(&ip_str) {
                Ok(ip) => {
                    blacklist.insert(ip);
                },
                Err(e) => {
                    warn!("Invalid IP address in blacklist: {} - {}", ip_str, e);
                }
            }
        }

        // Create rate limiter
        let rate_limiter_config = RateLimiterConfig {
            global_limit: settings.global_rate_limit,
            per_ip_limit: settings.per_ip_rate_limit,
            ..Default::default()
        };
        let rate_limiter = Arc::new(RateLimiter::new(rate_limiter_config));

        // Create threat intelligence manager
        let threat_feeds = settings.threat_feeds.iter().map(|url| {
            ThreatFeed {
                name: url.clone(),
                url: url.clone(),
                format: FeedFormat::PlainText,
                update_interval: Duration::from_secs(3600), // 1 hour
                enabled: settings.use_threat_intelligence,
                last_update: None,
            }
        }).collect();
        let threat_intel = Arc::new(ThreatIntelligenceManager::new(threat_feeds));

        // Create connection tracker
        let conn_tracker_config = ConnectionTrackerConfig {
            max_per_ip: settings.max_connections_per_ip,
            ..Default::default()
        };
        let connection_tracker = Arc::new(ConnectionTracker::new(conn_tracker_config));

        Self {
            firewall: Arc::new(Mutex::new(FirewallManager::new(use_native_firewall))),
            settings: RwLock::new(settings),
            temp_blocks: Arc::new(Mutex::new(HashMap::new())),
            whitelist: Arc::new(Mutex::new(whitelist)),
            blacklist: Arc::new(Mutex::new(blacklist)),
            running: Arc::new(AtomicBool::new(false)),
            block_history: Arc::new(Mutex::new(Vec::new())),
            metrics: Arc::new(RwLock::new(PreventionMetrics::default())),
            rate_limiter,
            threat_intel,
            connection_tracker,
            escalation_tracker: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start the prevention manager
    pub async fn start(&self) -> Result<(), AppError> {
        {
            let running = self.running.load(Ordering::Relaxed);
            if running {
                return Ok(()); // Already running
            }
            self.running.store(true, Ordering::Relaxed);
        }

        // Activate the firewall
        {
            let mut firewall = self.firewall.lock().unwrap();
            firewall.activate()?;
        }

        // Start rate limiter cleanup task
        let rate_limiter_clone = Arc::clone(&self.rate_limiter);
        rate_limiter_clone.start_cleanup_task();

        // Start threat intelligence manager
        let (use_threat_intel, connection_tracking) = {
            let settings = self.settings.read().unwrap();
            (settings.use_threat_intelligence, settings.connection_tracking)
        };
        
        if use_threat_intel {
            self.threat_intel.start().await
                .map_err(|e| AppError::PreventionError(format!("Failed to start threat intelligence: {}", e)))?;
        }

        // Start connection tracker
        if connection_tracking {
            self.connection_tracker.start()
                .map_err(|e| AppError::PreventionError(format!("Failed to start connection tracker: {}", e)))?;
        }

        // Process blacklisted IPs
        {
            let blacklist = self.blacklist.lock().unwrap();
            let firewall = self.firewall.lock().unwrap();
            for ip in blacklist.iter() {
                if let Err(e) = firewall.block_ip(*ip) {
                    error!("Failed to block blacklisted IP {}: {}", ip, e);
                }
            }
        }

        // Start background maintenance task
        let temp_blocks = Arc::clone(&self.temp_blocks);
        let firewall = Arc::clone(&self.firewall);
        let running = Arc::clone(&self.running);
        let escalation_tracker = Arc::clone(&self.escalation_tracker);

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60)); // Check every minute

            while running.load(Ordering::Relaxed) {
                interval.tick().await;

                // Clean up expired blocks
                let now = Instant::now();
                let mut expired_ips = Vec::new();

                {
                    let blocks = temp_blocks.lock().unwrap();
                    for (ip, expiry) in blocks.iter() {
                        if *expiry <= now {
                            expired_ips.push(*ip);
                        }
                    }
                }

                // Remove expired blocks
                if !expired_ips.is_empty() {
                    let firewall_guard = firewall.lock().unwrap();
                    let mut blocks = temp_blocks.lock().unwrap();

                    for ip in expired_ips {
                        if let Err(e) = firewall_guard.unblock_ip(ip) {
                            error!("Failed to remove expired block for IP {}: {}", ip, e);
                        } else {
                            info!("Removed expired block for IP: {}", ip);
                            blocks.remove(&ip);
                        }
                    }
                }

                // Clean up old escalation states
                {
                    let mut tracker = escalation_tracker.lock().unwrap();
                    tracker.retain(|_, state| {
                        now.duration_since(state.last_escalation) < Duration::from_secs(3600)
                    });
                }
            }
        });

        info!("Enhanced prevention manager started");
        Ok(())
    }

    /// Stop the prevention manager
    pub fn stop(&self) -> Result<(), AppError> {
        {
            let running = self.running.load(Ordering::Relaxed);
            if !running {
                return Ok(()); // Already stopped
            }
            self.running.store(false, Ordering::Relaxed);
        }

        // Stop sub-components
        self.threat_intel.stop();
        self.connection_tracker.stop();

        // Deactivate the firewall
        {
            let mut firewall = self.firewall.lock().unwrap();
            firewall.deactivate()?;
        }

        info!("Prevention manager stopped");
        Ok(())
    }

    /// Process a detected threat with enhanced intelligence
    pub async fn process_threat(&self, alert: &Alert, action: Option<PreventionAction>) -> Result<PreventionAction, AppError> {
        // Don't take action if prevention is disabled
        {
            let settings = self.settings.read().unwrap();
            if !settings.enabled {
                return Ok(PreventionAction::Monitor);
            }
        }

        // Parse source IP
        let source_ip = match IpAddr::from_str(&alert.source_ip) {
            Ok(ip) => ip,
            Err(_) => return Err(AppError::PreventionError(format!("Invalid source IP: {}", alert.source_ip))),
        };

        // Check blacklist first
        {
            let blacklist = self.blacklist.lock().unwrap();
            if blacklist.contains(&source_ip) {
                self.block_ip(source_ip, "Blacklisted IP", alert.alert_id.as_deref(), Some(ThreatCategory::PolicyViolation))?;
                return Ok(PreventionAction::BlockSource);
            }
        }

        // Check whitelist
        {
            let whitelist = self.whitelist.lock().unwrap();
            if whitelist.contains(&source_ip) {
                info!("Skipping prevention action for whitelisted IP: {}", source_ip);
                return Ok(PreventionAction::Monitor);
            }
        }

        // Check rate limits
        if !self.rate_limiter.check_rate_limit(source_ip, 1).unwrap_or(true) {
            info!("Rate limit exceeded for IP: {}", source_ip);
            self.handle_rate_limit_exceeded(source_ip, alert).await?;
            return Ok(PreventionAction::RateLimit);
        }

        // Check threat intelligence
        let threat_category = self.determine_threat_category(alert, &source_ip).await;
        
        // Get response strategy
        let (strategy, connection_tracking) = {
            let settings = self.settings.read().unwrap();
            let strategy = settings.response_strategies
                .get(&threat_category)
                .cloned()
                .unwrap_or_default();
            (strategy, settings.connection_tracking)
        };

        // Determine action based on escalation state
        let action = if let Some(action) = action {
            action
        } else {
            self.determine_escalated_action(&source_ip, &strategy, threat_category)
        };

        // Update metrics
        {
            let mut metrics = self.metrics.write().unwrap();
            metrics.total_threats_detected += 1;
            metrics.threats_by_category
                .entry(threat_category)
                .and_modify(|c| *c += 1)
                .or_insert(1);
            metrics.actions_taken
                .entry(action)
                .and_modify(|c| *c += 1)
                .or_insert(1);
        }

        // If the action is to monitor or alert only, return early
        if action == PreventionAction::Monitor || action == PreventionAction::Alert {
            return Ok(action);
        }

        // Take the appropriate action
        match action {
            PreventionAction::BlockSource => {
                self.block_ip(source_ip, &alert.description, alert.alert_id.as_deref(), Some(threat_category))?;
                
                // Terminate existing connections
                if connection_tracking {
                    let terminated = self.connection_tracker.terminate_connections_from_ip(&source_ip)
                        .unwrap_or(0);
                    if terminated > 0 {
                        info!("Terminated {} connections from blocked IP {}", terminated, source_ip);
                    }
                }
            },
            PreventionAction::BlockBoth => {
                self.block_ip(source_ip, &alert.description, alert.alert_id.as_deref(), Some(threat_category))?;

                // Also block destination if it's not a private/local address
                if let Ok(dest_ip) = IpAddr::from_str(&alert.destination_ip) {
                    if !Self::is_private_ip(&dest_ip) {
                        self.block_ip(dest_ip, &alert.description, alert.alert_id.as_deref(), Some(threat_category))?;
                    }
                }
            },
            PreventionAction::TerminateConnection => {
                // Try to find and terminate the specific connection
                if connection_tracking {
                    let terminated = self.connection_tracker.terminate_connections_from_ip(&source_ip)
                        .unwrap_or(0);
                    if terminated > 0 {
                        info!("Terminated {} connections from IP {}", terminated, source_ip);
                    }
                }
                
                // Also temporarily block the source
                self.temp_ban_ip(source_ip, Duration::from_secs(300), &alert.description)?;
            },
            PreventionAction::RateLimit => {
                // Rate limiting is already applied above
                info!("Rate limiting applied to IP: {}", source_ip);
            },
            PreventionAction::TempBan => {
                self.temp_ban_ip(source_ip, Duration::from_secs(1800), &alert.description)?;
            },
            PreventionAction::Quarantine => {
                // Mark all connections from this IP as suspicious
                if connection_tracking {
                    let connections = self.connection_tracker.get_connections_by_ip(&source_ip);
                    for conn in connections {
                        self.connection_tracker.mark_suspicious(conn.id, "Quarantined")?;
                    }
                }
                self.temp_ban_ip(source_ip, Duration::from_secs(3600), "Quarantined")?;
            },
            _ => {} // Other actions handled elsewhere
        }

        // Update escalation tracker
        {
            let mut tracker = self.escalation_tracker.lock().unwrap();
            let state = tracker.entry(source_ip).or_insert(EscalationState {
                current_level: 0,
                last_action: action,
                last_escalation: Instant::now(),
                incident_count: 0,
            });
            state.incident_count += 1;
            state.last_action = action;
        }

        Ok(action)
    }

    /// Determine threat category using enhanced intelligence
    async fn determine_threat_category(&self, alert: &Alert, ip: &IpAddr) -> ThreatCategory {
        // Check threat intelligence first
        if let Some(indicators) = self.threat_intel.check_ip(ip) {
            // Map threat types to categories
            if indicators.iter().any(|i| matches!(i.threat_type, 
                crate::prevention::threat_intelligence::ThreatType::Malware |
                crate::prevention::threat_intelligence::ThreatType::Exploit)) {
                return ThreatCategory::Malware;
            } else if indicators.iter().any(|i| matches!(i.threat_type,
                crate::prevention::threat_intelligence::ThreatType::Scanner)) {
                return ThreatCategory::PortScan;
            } else if indicators.iter().any(|i| matches!(i.threat_type,
                crate::prevention::threat_intelligence::ThreatType::Bruteforce)) {
                return ThreatCategory::BruteForce;
            }
        }

        // Check connection patterns
        let (connection_tracking, max_connections_per_ip) = {
            let settings = self.settings.read().unwrap();
            (settings.connection_tracking, settings.max_connections_per_ip)
        };
        
        if connection_tracking {
            let conn_count = self.connection_tracker.get_connection_count(ip);
            if conn_count > max_connections_per_ip as usize {
                return ThreatCategory::DDoS;
            }
        }

        // Fall back to description-based categorization
        let desc = alert.description.to_lowercase();
        
        if desc.contains("port scan") {
            ThreatCategory::PortScan
        } else if desc.contains("host scan") {
            ThreatCategory::HostScan
        } else if desc.contains("brute") || desc.contains("authentication") {
            ThreatCategory::BruteForce
        } else if desc.contains("ddos") || desc.contains("flood") {
            ThreatCategory::DDoS
        } else if desc.contains("malware") || desc.contains("virus") {
            ThreatCategory::Malware
        } else if desc.contains("exploit") || desc.contains("vulnerability") {
            ThreatCategory::Exploit
        } else if desc.contains("exfiltration") || desc.contains("data transfer") {
            ThreatCategory::DataExfiltration
        } else {
            ThreatCategory::AnomalousTraffic
        }
    }

    /// Determine escalated action based on incident history
    fn determine_escalated_action(
        &self,
        ip: &IpAddr,
        strategy: &ResponseStrategy,
        _category: ThreatCategory,
    ) -> PreventionAction {
        let mut tracker = self.escalation_tracker.lock().unwrap();
        
        let state = tracker.get_mut(ip);
        
        match state {
            None => strategy.initial_action,
            Some(state) => {
                let now = Instant::now();
                let time_since_last = now.duration_since(state.last_escalation);
                
                // Check if we should escalate
                if time_since_last < strategy.escalation_delay && 
                   state.current_level < strategy.max_escalation {
                    state.current_level += 1;
                    state.last_escalation = now;
                    strategy.escalation_action
                } else if time_since_last > Duration::from_secs(3600) {
                    // Reset escalation after 1 hour
                    state.current_level = 0;
                    state.last_escalation = now;
                    strategy.initial_action
                } else {
                    state.last_action
                }
            }
        }
    }

    /// Handle rate limit exceeded
    async fn handle_rate_limit_exceeded(&self, ip: IpAddr, _alert: &Alert) -> Result<(), AppError> {
        // Check if this IP is repeatedly hitting rate limits
        let escalation_state = {
            let tracker = self.escalation_tracker.lock().unwrap();
            tracker.get(&ip).map(|s| s.incident_count).unwrap_or(0)
        };

        if escalation_state > 5 {
            // Escalate to temporary ban
            self.temp_ban_ip(ip, Duration::from_secs(3600), "Repeated rate limit violations")?;
            warn!("IP {} temporarily banned for repeated rate limit violations", ip);
        } else {
            // Just log it
            warn!("Rate limit exceeded for IP {} (incident #{})", ip, escalation_state + 1);
        }

        Ok(())
    }

    /// Temporarily ban an IP
    fn temp_ban_ip(&self, ip: IpAddr, duration: Duration, reason: &str) -> Result<(), AppError> {
        // Block the IP
        {
            let firewall = self.firewall.lock().unwrap();
            firewall.block_ip(ip)?;
        }

        // Add to temporary blocks
        {
            let mut temp_blocks = self.temp_blocks.lock().unwrap();
            let expiry = Instant::now() + duration;
            temp_blocks.insert(ip, expiry);
        }

        // Add to block history
        {
            let mut history = self.block_history.lock().unwrap();
            let now = Utc::now();
            let expires_at = Some(now + chrono::Duration::from_std(duration).unwrap());

            history.push(BlockedIP {
                ip: ip.to_string(),
                blocked_at: now,
                expires_at,
                reason: reason.to_string(),
                alert_id: None,
                action: PreventionAction::TempBan,
                threat_category: None,
            });
        }

        info!("Temporarily banned IP {} for {:?}: {}", ip, duration, reason);
        Ok(())
    }

    /// Block an IP address
    pub fn block_ip(&self, ip: IpAddr, reason: &str, alert_id: Option<&str>, threat_category: Option<ThreatCategory>) -> Result<(), AppError> {
        // Check if the IP is whitelisted
        {
            let whitelist = self.whitelist.lock().unwrap();
            if whitelist.contains(&ip) {
                info!("Skipping block for whitelisted IP: {}", ip);
                return Ok(());
            }
        }

        // Get block duration
        let duration_minutes = {
            let settings = self.settings.read().unwrap();
            settings.auto_block_duration
        };

        // Block the IP
        {
            let firewall = self.firewall.lock().unwrap();
            firewall.block_ip(ip)?;
        }

        // Add to temporary blocks if duration is non-zero
        if duration_minutes > 0 {
            let mut temp_blocks = self.temp_blocks.lock().unwrap();
            let expiry = Instant::now() + Duration::from_secs(duration_minutes as u64 * 60);
            temp_blocks.insert(ip, expiry);
        }

        // Add to block history
        {
            let mut history = self.block_history.lock().unwrap();
            let now = Utc::now();
            let expires_at = if duration_minutes > 0 {
                Some(now + chrono::Duration::minutes(duration_minutes as i64))
            } else {
                None
            };

            history.push(BlockedIP {
                ip: ip.to_string(),
                blocked_at: now,
                expires_at,
                reason: reason.to_string(),
                alert_id: alert_id.map(|s| s.to_string()),
                action: PreventionAction::BlockSource,
                threat_category,
            });
        }

        info!("Blocked IP: {} for reason: {}", ip, reason);
        Ok(())
    }

    /// Unblock an IP address
    pub fn unblock_ip(&self, ip: IpAddr) -> Result<(), AppError> {
        // Remove from firewall
        {
            let firewall = self.firewall.lock().unwrap();
            firewall.unblock_ip(ip)?;
        }

        // Remove from temporary blocks
        {
            let mut temp_blocks = self.temp_blocks.lock().unwrap();
            temp_blocks.remove(&ip);
        }

        info!("Unblocked IP: {}", ip);
        Ok(())
    }

    /// Check if an IP is in the whitelist
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        let whitelist = self.whitelist.lock().unwrap();
        whitelist.contains(ip)
    }

    /// Add an IP to the whitelist
    pub fn add_to_whitelist(&self, ip: IpAddr) -> Result<(), AppError> {
        // Add to whitelist
        {
            let mut whitelist = self.whitelist.lock().unwrap();
            whitelist.insert(ip);
        }

        // Update settings
        {
            let mut settings = self.settings.write().unwrap();
            if !settings.whitelist.contains(&ip.to_string()) {
                settings.whitelist.push(ip.to_string());
            }
        }

        // If the IP is currently blocked, unblock it
        {
            let firewall = self.firewall.lock().unwrap();
            if firewall.is_ip_blocked(&ip) {
                firewall.unblock_ip(ip)?;

                // Also remove from temporary blocks
                let mut temp_blocks = self.temp_blocks.lock().unwrap();
                temp_blocks.remove(&ip);
            }
        }

        info!("Added IP to whitelist: {}", ip);
        Ok(())
    }

    /// Remove an IP from the whitelist
    pub fn remove_from_whitelist(&self, ip: &IpAddr) -> Result<(), AppError> {
        // Remove from whitelist
        {
            let mut whitelist = self.whitelist.lock().unwrap();
            whitelist.remove(ip);
        }

        // Update settings
        {
            let mut settings = self.settings.write().unwrap();
            settings.whitelist.retain(|s| s != &ip.to_string());
        }

        info!("Removed IP from whitelist: {}", ip);
        Ok(())
    }

    /// Get the currently blocked IPs
    pub fn get_blocked_ips(&self) -> Vec<BlockedIP> {
        let history = self.block_history.lock().unwrap();
        history.clone()
    }

    /// Get prevention settings
    pub fn get_settings(&self) -> PreventionSettings {
        self.settings.read().unwrap().clone()
    }

    /// Update prevention settings
    pub async fn update_settings(&self, new_settings: PreventionSettings) -> Result<(), AppError> {
        let use_native_firewall_changed;
        let enabled_changed;
        let was_enabled;

        {
            let mut settings = self.settings.write().unwrap();
            use_native_firewall_changed = settings.use_native_firewall != new_settings.use_native_firewall;
            was_enabled = settings.enabled;
            enabled_changed = settings.enabled != new_settings.enabled;

            // Update settings
            *settings = new_settings;
        }

        // If the native firewall setting changed, we need to restart the firewall
        if use_native_firewall_changed {
            let mut firewall = self.firewall.lock().unwrap();
            let use_native_firewall = {
                let settings = self.settings.read().unwrap();
                settings.use_native_firewall
            };

            // Deactivate and recreate with new setting
            firewall.deactivate()?;
            *firewall = FirewallManager::new(use_native_firewall);

            // Reactivate if prevention is enabled
            let enabled = {
                let settings = self.settings.read().unwrap();
                settings.enabled
            };

            if enabled {
                firewall.activate()?;
            }
        }

        // If enabled state changed
        if enabled_changed {
            if was_enabled {
                // Was enabled, now disabled
                self.stop()?;
            } else {
                // Was disabled, now enabled
                self.start().await?;
            }
        }

        // Process whitelist changes
        let new_whitelist = {
            let settings = self.settings.read().unwrap();
            settings.whitelist.clone()
        };

        let mut whitelist = self.whitelist.lock().unwrap();
        whitelist.clear();

        for ip_str in new_whitelist {
            match IpAddr::from_str(&ip_str) {
                Ok(ip) => {
                    whitelist.insert(ip);

                    // If the IP is currently blocked, unblock it
                    let firewall = self.firewall.lock().unwrap();
                    if firewall.is_ip_blocked(&ip) {
                        if let Err(e) = firewall.unblock_ip(ip) {
                            error!("Failed to unblock whitelisted IP {}: {}", ip, e);
                        }

                        // Also remove from temporary blocks
                        let mut temp_blocks = self.temp_blocks.lock().unwrap();
                        temp_blocks.remove(&ip);
                    }
                },
                Err(e) => {
                    warn!("Invalid IP address in whitelist: {} - {}", ip_str, e);
                }
            }
        }

        info!("Prevention settings updated");
        Ok(())
    }

    /// Check if an IP is private/local
    fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                ip.is_private() ||
                    ip.is_loopback() ||
                    ip.is_link_local() ||
                    ip.is_broadcast() ||
                    ip.is_documentation() ||
                    ip.is_unspecified()
            },
            IpAddr::V6(ip) => {
                ip.is_loopback() ||
                    ip.is_unspecified() ||
                    ip.is_unicast_link_local()
            }
        }
    }

    /// Is the prevention manager running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}