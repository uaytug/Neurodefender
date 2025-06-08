pub mod firewall;
pub mod actions;
pub mod blocker;
pub mod rate_limiter;
pub mod threat_intelligence;
pub mod connection_tracker;

// Re-export commonly used types
#[allow(unused_imports)]
pub use actions::{PreventionAction, PreventionSettings, ThreatCategory, ThreatSeverity};
#[allow(unused_imports)]
pub use blocker::{PreventionManager, BlockedIP};
#[allow(unused_imports)]
pub use rate_limiter::{RateLimiter, RateLimiterConfig};
#[allow(unused_imports)]
pub use threat_intelligence::{ThreatIntelligenceManager, ThreatFeed, ThreatIndicator};
#[allow(unused_imports)]
pub use connection_tracker::{ConnectionTracker, Connection, ConnectionState};
