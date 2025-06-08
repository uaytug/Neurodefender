use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use tokio::time;
use log::{info, warn, error};
use reqwest;

/// Threat intelligence source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    pub name: String,
    pub url: String,
    pub format: FeedFormat,
    pub update_interval: Duration,
    pub enabled: bool,
    pub last_update: Option<DateTime<Utc>>,
}

/// Feed format types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedFormat {
    /// Plain text list of IPs (one per line)
    PlainText,
    /// CSV format with IP in first column
    CSV,
    /// JSON format
    JSON,
    /// STIX format
    STIX,
}

/// Threat indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub ip: IpAddr,
    pub threat_type: ThreatType,
    pub confidence: f32,
    pub source: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub tags: Vec<String>,
    pub description: Option<String>,
}

/// Types of threats
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatType {
    Malware,
    Botnet,
    Scanner,
    Bruteforce,
    Phishing,
    Spam,
    Proxy,
    Tor,
    VPN,
    Compromised,
    Exploit,
    Unknown,
}

/// IP reputation score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    pub ip: IpAddr,
    pub score: f32, // 0.0 (bad) to 100.0 (good)
    pub factors: HashMap<String, f32>,
    pub last_calculated: DateTime<Utc>,
}

/// GeoIP information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIPInfo {
    pub country_code: String,
    pub country_name: String,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

/// Threat intelligence manager
pub struct ThreatIntelligenceManager {
    /// Threat indicators database
    indicators: Arc<RwLock<HashMap<IpAddr, Vec<ThreatIndicator>>>>,
    
    /// IP reputation cache
    reputation_cache: Arc<RwLock<HashMap<IpAddr, ReputationScore>>>,
    
    /// GeoIP database
    geoip_cache: Arc<RwLock<HashMap<IpAddr, GeoIPInfo>>>,
    
    /// Configured threat feeds
    feeds: Arc<RwLock<Vec<ThreatFeed>>>,
    
    /// HTTP client for fetching feeds
    http_client: reqwest::Client,
    
    /// Is the manager running
    running: Arc<RwLock<bool>>,
}

impl ThreatIntelligenceManager {
    /// Create a new threat intelligence manager
    pub fn new(feeds: Vec<ThreatFeed>) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("NeuroDefender/1.0")
            .build()
            .unwrap_or_default();

        Self {
            indicators: Arc::new(RwLock::new(HashMap::new())),
            reputation_cache: Arc::new(RwLock::new(HashMap::new())),
            geoip_cache: Arc::new(RwLock::new(HashMap::new())),
            feeds: Arc::new(RwLock::new(feeds)),
            http_client,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the threat intelligence manager
    pub async fn start(&self) -> Result<(), String> {
        {
            let mut running = self.running.write().unwrap();
            if *running {
                return Ok(());
            }
            *running = true;
        }

        // Initial feed update
        self.update_all_feeds().await;

        // Start background update task
        let feeds = Arc::clone(&self.feeds);
        let indicators = Arc::clone(&self.indicators);
        let http_client = self.http_client.clone();
        let running = Arc::clone(&self.running);

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(300)); // Check every 5 minutes

            while *running.read().unwrap() {
                interval.tick().await;

                let feeds_to_update = {
                    let feeds = feeds.read().unwrap();
                    feeds.iter()
                        .filter(|f| f.enabled && Self::should_update_feed(f))
                        .cloned()
                        .collect::<Vec<_>>()
                };

                for feed in feeds_to_update {
                    if let Err(e) = Self::update_feed(&http_client, &feed, &indicators).await {
                        error!("Failed to update feed {}: {}", feed.name, e);
                    }
                }
            }
        });

        info!("Threat intelligence manager started");
        Ok(())
    }

    /// Stop the threat intelligence manager
    pub fn stop(&self) {
        let mut running = self.running.write().unwrap();
        *running = false;
        info!("Threat intelligence manager stopped");
    }

    /// Check if an IP is in the threat database
    pub fn check_ip(&self, ip: &IpAddr) -> Option<Vec<ThreatIndicator>> {
        let indicators = self.indicators.read().unwrap();
        indicators.get(ip).cloned()
    }

    /// Get reputation score for an IP
    pub fn get_reputation(&self, ip: &IpAddr) -> ReputationScore {
        // Check cache first
        {
            let cache = self.reputation_cache.read().unwrap();
            if let Some(score) = cache.get(ip) {
                if score.last_calculated > Utc::now() - chrono::Duration::hours(1) {
                    return score.clone();
                }
            }
        }

        // Calculate new score
        let score = self.calculate_reputation(ip);

        // Cache the result
        {
            let mut cache = self.reputation_cache.write().unwrap();
            cache.insert(*ip, score.clone());
        }

        score
    }

    /// Calculate reputation score for an IP
    fn calculate_reputation(&self, ip: &IpAddr) -> ReputationScore {
        let mut factors = HashMap::new();
        let mut total_score = 100.0;

        // Check threat indicators
        if let Some(threats) = self.check_ip(ip) {
            let threat_penalty = threats.len() as f32 * 20.0;
            factors.insert("threat_indicators".to_string(), -threat_penalty);
            total_score -= threat_penalty;

            // Additional penalty based on threat types
            for threat in &threats {
                let type_penalty = match threat.threat_type {
                    ThreatType::Malware => 30.0,
                    ThreatType::Botnet => 25.0,
                    ThreatType::Scanner => 15.0,
                    ThreatType::Bruteforce => 20.0,
                    ThreatType::Phishing => 25.0,
                    ThreatType::Spam => 10.0,
                    ThreatType::Proxy => 5.0,
                    ThreatType::Tor => 5.0,
                    ThreatType::VPN => 3.0,
                    ThreatType::Compromised => 20.0,
                    ThreatType::Exploit => 20.0,
                    ThreatType::Unknown => 10.0,
                };
                total_score -= type_penalty * threat.confidence;
            }
        }

        // Check if it's a private IP (higher trust)
        if Self::is_private_ip(ip) {
            factors.insert("private_ip".to_string(), 20.0);
            total_score += 20.0;
        }

        // GeoIP-based scoring
        if let Some(_geo_info) = self.get_geoip(ip) {
            // You can implement country-based scoring here
            // For example, penalize IPs from high-risk countries
            factors.insert("geoip".to_string(), 0.0);
        }

        ReputationScore {
            ip: *ip,
            score: total_score.max(0.0).min(100.0),
            factors,
            last_calculated: Utc::now(),
        }
    }

    /// Get GeoIP information for an IP
    pub fn get_geoip(&self, ip: &IpAddr) -> Option<GeoIPInfo> {
        let cache = self.geoip_cache.read().unwrap();
        cache.get(ip).cloned()
    }

    /// Add a manual threat indicator
    pub fn add_indicator(&self, indicator: ThreatIndicator) {
        let ip = indicator.ip; // Store IP before move
        let mut indicators = self.indicators.write().unwrap();
        indicators.entry(ip)
            .or_insert_with(Vec::new)
            .push(indicator);
        
        // Invalidate reputation cache for this IP
        let mut cache = self.reputation_cache.write().unwrap();
        cache.remove(&ip);
    }

    /// Remove indicators for an IP
    pub fn remove_indicators(&self, ip: &IpAddr) {
        let mut indicators = self.indicators.write().unwrap();
        indicators.remove(ip);
        
        // Invalidate reputation cache
        let mut cache = self.reputation_cache.write().unwrap();
        cache.remove(ip);
    }

    /// Update all enabled feeds
    async fn update_all_feeds(&self) {
        let feeds = self.feeds.read().unwrap().clone();
        
        for feed in feeds.iter().filter(|f| f.enabled) {
            if let Err(e) = Self::update_feed(&self.http_client, feed, &self.indicators).await {
                error!("Failed to update feed {}: {}", feed.name, e);
            }
        }
    }

    /// Check if a feed should be updated
    fn should_update_feed(feed: &ThreatFeed) -> bool {
        match feed.last_update {
            Some(last_update) => {
                let elapsed = Utc::now().signed_duration_since(last_update);
                elapsed.to_std().unwrap_or_default() >= feed.update_interval
            }
            None => true,
        }
    }

    /// Update a single threat feed
    async fn update_feed(
        client: &reqwest::Client,
        feed: &ThreatFeed,
        indicators: &Arc<RwLock<HashMap<IpAddr, Vec<ThreatIndicator>>>>
    ) -> Result<(), String> {
        info!("Updating threat feed: {}", feed.name);

        let response = client.get(&feed.url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch feed: {}", e))?;

        let content = response.text()
            .await
            .map_err(|e| format!("Failed to read feed content: {}", e))?;

        let new_indicators = match feed.format {
            FeedFormat::PlainText => Self::parse_plaintext_feed(&content, &feed.name),
            FeedFormat::CSV => Self::parse_csv_feed(&content, &feed.name),
            FeedFormat::JSON => Self::parse_json_feed(&content, &feed.name),
            FeedFormat::STIX => {
                warn!("STIX format not yet implemented");
                Vec::new()
            }
        };

        // Update indicators
        let mut indicators_map = indicators.write().unwrap();
        
        // Remove old indicators from this source
        indicators_map.retain(|_, indicators| {
            indicators.retain(|ind| ind.source != feed.name);
            !indicators.is_empty()
        });

        // Add new indicators
        for indicator in new_indicators {
            indicators_map.entry(indicator.ip)
                .or_insert_with(Vec::new)
                .push(indicator);
        }

        info!("Updated feed {} with {} indicators", feed.name, indicators_map.len());
        Ok(())
    }

    /// Parse plaintext IP list
    fn parse_plaintext_feed(content: &str, source: &str) -> Vec<ThreatIndicator> {
        let mut indicators = Vec::new();
        let now = Utc::now();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Ok(ip) = IpAddr::from_str(line) {
                indicators.push(ThreatIndicator {
                    ip,
                    threat_type: ThreatType::Unknown,
                    confidence: 0.8,
                    source: source.to_string(),
                    first_seen: now,
                    last_seen: now,
                    tags: vec![],
                    description: None,
                });
            }
        }

        indicators
    }

    /// Parse CSV feed
    fn parse_csv_feed(content: &str, source: &str) -> Vec<ThreatIndicator> {
        // Simple CSV parsing - assumes IP in first column
        let mut indicators = Vec::new();
        let now = Utc::now();

        for line in content.lines().skip(1) { // Skip header
            let parts: Vec<&str> = line.split(',').collect();
            if parts.is_empty() {
                continue;
            }

            if let Ok(ip) = IpAddr::from_str(parts[0].trim()) {
                let threat_type = if parts.len() > 1 {
                    match parts[1].trim().to_lowercase().as_str() {
                        "malware" => ThreatType::Malware,
                        "botnet" => ThreatType::Botnet,
                        "scanner" => ThreatType::Scanner,
                        _ => ThreatType::Unknown,
                    }
                } else {
                    ThreatType::Unknown
                };

                indicators.push(ThreatIndicator {
                    ip,
                    threat_type,
                    confidence: 0.8,
                    source: source.to_string(),
                    first_seen: now,
                    last_seen: now,
                    tags: vec![],
                    description: parts.get(2).map(|s| s.trim().to_string()),
                });
            }
        }

        indicators
    }

    /// Parse JSON feed
    fn parse_json_feed(_content: &str, _source: &str) -> Vec<ThreatIndicator> {
        // TODO: Implement JSON parsing based on specific feed formats
        Vec::new()
    }

    /// Check if an IP is private
    fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_private() || 
                ipv4.is_loopback() || 
                ipv4.is_link_local()
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() || 
                ipv6.is_unspecified()
            }
        }
    }

    /// Export threat indicators to file
    pub fn export_indicators(&self, path: &str) -> Result<(), String> {
        let indicators = self.indicators.read().unwrap();
        let export_data: Vec<&ThreatIndicator> = indicators
            .values()
            .flatten()
            .collect();

        let json = serde_json::to_string_pretty(&export_data)
            .map_err(|e| format!("Failed to serialize indicators: {}", e))?;

        std::fs::write(path, json)
            .map_err(|e| format!("Failed to write file: {}", e))?;

        info!("Exported {} indicators to {}", export_data.len(), path);
        Ok(())
    }

    /// Import threat indicators from file
    pub fn import_indicators(&self, path: &str) -> Result<(), String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        let imported: Vec<ThreatIndicator> = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse indicators: {}", e))?;

        let mut indicators = self.indicators.write().unwrap();
        
        for indicator in imported {
            indicators.entry(indicator.ip)
                .or_insert_with(Vec::new)
                .push(indicator);
        }

        info!("Imported indicators from {}", path);
        Ok(())
    }
} 