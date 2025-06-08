use std::fmt;
use serde::{Serialize, Deserialize};
use std::time::Duration;

/// Represents a prevention action to be taken in response to a threat
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PreventionAction {
    /// No action, just monitor
    Monitor,

    /// Alert only, but take no prevention action
    Alert,

    /// Block the source IP address
    BlockSource,

    /// Block both source and destination IP addresses
    BlockBoth,

    /// Terminate the connection
    TerminateConnection,

    /// Rate limit the source
    RateLimit,

    /// Temporarily ban the source
    TempBan,

    /// Redirect to honeypot
    RedirectHoneypot,

    /// Deep packet inspection
    DeepInspect,

    /// Quarantine the traffic
    Quarantine,
}

/// Threat severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Threat categories for better classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatCategory {
    PortScan,
    HostScan,
    BruteForce,
    DDoS,
    Malware,
    Exploit,
    DataExfiltration,
    AnomalousTraffic,
    PolicyViolation,
    Unknown,
}

/// Response strategy for different scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseStrategy {
    /// Initial action
    pub initial_action: PreventionAction,
    
    /// Escalation action if threat persists
    pub escalation_action: PreventionAction,
    
    /// Time before escalation
    pub escalation_delay: Duration,
    
    /// Maximum escalation level
    pub max_escalation: u8,
}

impl Default for ResponseStrategy {
    fn default() -> Self {
        Self {
            initial_action: PreventionAction::Alert,
            escalation_action: PreventionAction::BlockSource,
            escalation_delay: Duration::from_secs(300), // 5 minutes
            max_escalation: 3,
        }
    }
}

impl fmt::Display for PreventionAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Monitor => write!(f, "Monitor"),
            Self::Alert => write!(f, "Alert"),
            Self::BlockSource => write!(f, "Block Source"),
            Self::BlockBoth => write!(f, "Block Both"),
            Self::TerminateConnection => write!(f, "Terminate Connection"),
            Self::RateLimit => write!(f, "Rate Limit"),
            Self::TempBan => write!(f, "Temporary Ban"),
            Self::RedirectHoneypot => write!(f, "Redirect to Honeypot"),
            Self::DeepInspect => write!(f, "Deep Inspection"),
            Self::Quarantine => write!(f, "Quarantine"),
        }
    }
}

impl PreventionAction {
    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "monitor" => Some(Self::Monitor),
            "alert" => Some(Self::Alert),
            "blocksource" => Some(Self::BlockSource),
            "blockboth" => Some(Self::BlockBoth),
            "terminateconnection" => Some(Self::TerminateConnection),
            "ratelimit" => Some(Self::RateLimit),
            "tempban" => Some(Self::TempBan),
            "redirecthoneypot" => Some(Self::RedirectHoneypot),
            "deepinspect" => Some(Self::DeepInspect),
            "quarantine" => Some(Self::Quarantine),
            _ => None,
        }
    }

    /// Get severity weight for action
    pub fn severity_weight(&self) -> u8 {
        match self {
            Self::Monitor => 0,
            Self::Alert => 1,
            Self::RateLimit => 2,
            Self::DeepInspect => 3,
            Self::RedirectHoneypot => 4,
            Self::TempBan => 5,
            Self::TerminateConnection => 6,
            Self::Quarantine => 7,
            Self::BlockSource => 8,
            Self::BlockBoth => 9,
        }
    }
}

/// Advanced prevention settings with threat-specific configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreventionSettings {
    /// Is prevention active
    pub enabled: bool,

    /// Use OS native firewall
    pub use_native_firewall: bool,

    /// Response strategies per threat category
    pub response_strategies: std::collections::HashMap<ThreatCategory, ResponseStrategy>,

    /// Global rate limit (requests per minute)
    pub global_rate_limit: u32,

    /// Per-IP rate limit (requests per minute)
    pub per_ip_rate_limit: u32,

    /// Enable threat intelligence integration
    pub use_threat_intelligence: bool,

    /// Enable adaptive response (AI-based)
    pub adaptive_response: bool,

    /// Auto-block duration in minutes (0 for permanent)
    pub auto_block_duration: u32,

    /// Whitelist of IP addresses that should never be blocked
    pub whitelist: Vec<String>,

    /// Blacklist of IP addresses that should always be blocked
    pub blacklist: Vec<String>,

    /// GeoIP blocking - list of country codes to block
    pub geo_block_countries: Vec<String>,

    /// Enable connection tracking
    pub connection_tracking: bool,

    /// Maximum concurrent connections per IP
    pub max_connections_per_ip: u32,

    /// Enable honeypot redirection
    pub honeypot_enabled: bool,

    /// Honeypot address
    pub honeypot_address: Option<String>,

    /// Enable automatic threat reporting
    pub auto_report_threats: bool,

    /// Threat intelligence feeds
    pub threat_feeds: Vec<String>,
}

impl Default for PreventionSettings {
    fn default() -> Self {
        use std::collections::HashMap;
        
        let mut response_strategies = HashMap::new();
        
        // Configure default strategies per threat type
        response_strategies.insert(ThreatCategory::PortScan, ResponseStrategy {
            initial_action: PreventionAction::Alert,
            escalation_action: PreventionAction::TempBan,
            escalation_delay: Duration::from_secs(180),
            max_escalation: 2,
        });
        
        response_strategies.insert(ThreatCategory::BruteForce, ResponseStrategy {
            initial_action: PreventionAction::RateLimit,
            escalation_action: PreventionAction::BlockSource,
            escalation_delay: Duration::from_secs(60),
            max_escalation: 3,
        });
        
        response_strategies.insert(ThreatCategory::DDoS, ResponseStrategy {
            initial_action: PreventionAction::RateLimit,
            escalation_action: PreventionAction::BlockSource,
            escalation_delay: Duration::from_secs(30),
            max_escalation: 2,
        });
        
        response_strategies.insert(ThreatCategory::Malware, ResponseStrategy {
            initial_action: PreventionAction::Quarantine,
            escalation_action: PreventionAction::BlockBoth,
            escalation_delay: Duration::from_secs(0),
            max_escalation: 1,
        });
        
        response_strategies.insert(ThreatCategory::Exploit, ResponseStrategy {
            initial_action: PreventionAction::TerminateConnection,
            escalation_action: PreventionAction::BlockSource,
            escalation_delay: Duration::from_secs(0),
            max_escalation: 2,
        });

        Self {
            enabled: false,
            use_native_firewall: true,
            response_strategies,
            global_rate_limit: 10000, // 10k requests per minute globally
            per_ip_rate_limit: 100,   // 100 requests per minute per IP
            use_threat_intelligence: true,
            adaptive_response: true,
            auto_block_duration: 60, // 1 hour
            whitelist: vec![
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ],
            blacklist: vec![],
            geo_block_countries: vec![],
            connection_tracking: true,
            max_connections_per_ip: 50,
            honeypot_enabled: false,
            honeypot_address: None,
            auto_report_threats: true,
            threat_feeds: vec![
                "https://rules.emergingthreats.net/blockrules/compromised-ips.txt".to_string(),
                "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".to_string(),
            ],
        }
    }
}

/// Metrics for prevention actions
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PreventionMetrics {
    pub total_threats_detected: u64,
    pub threats_blocked: u64,
    pub threats_mitigated: u64,
    pub false_positives: u64,
    pub actions_taken: std::collections::HashMap<PreventionAction, u64>,
    pub threats_by_category: std::collections::HashMap<ThreatCategory, u64>,
}