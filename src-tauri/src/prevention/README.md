# Enhanced Prevention Module

The prevention module has been significantly enhanced to provide a robust, production-ready intrusion prevention system with advanced features including rate limiting, threat intelligence, connection tracking, and adaptive response strategies.

## Key Features

### 1. **Advanced Prevention Actions**
- **Monitor**: Passive monitoring without intervention
- **Alert**: Generate alerts without blocking
- **BlockSource**: Block source IP address
- **BlockBoth**: Block both source and destination IPs
- **TerminateConnection**: Actively terminate specific connections
- **RateLimit**: Apply rate limiting to throttle traffic
- **TempBan**: Temporarily ban an IP for a specified duration
- **RedirectHoneypot**: Redirect suspicious traffic to a honeypot
- **DeepInspect**: Trigger deep packet inspection
- **Quarantine**: Isolate and monitor suspicious traffic

### 2. **Threat Intelligence Integration**
- External threat feed integration (multiple formats supported)
- Real-time IP reputation scoring
- Automatic threat indicator updates
- Support for multiple threat types (Malware, Botnet, Scanner, etc.)
- GeoIP-based blocking capabilities

### 3. **Advanced Rate Limiting**
- Multiple algorithms: Token Bucket, Sliding Window, Fixed Window
- Per-IP and global rate limits
- Burst handling capabilities
- Automatic cleanup of inactive states

### 4. **Connection Tracking**
- Real-time connection monitoring
- Per-IP connection limits
- Traffic statistics (bytes/packets)
- Connection state tracking
- Ability to terminate specific connections

### 5. **Adaptive Response System**
- Threat category-based response strategies
- Automatic escalation for repeat offenders
- Configurable escalation delays and levels
- Smart de-escalation after quiet periods

### 6. **Enhanced Security Features**
- IP whitelisting and blacklisting
- GeoIP-based blocking
- Automatic threat reporting
- Comprehensive metrics and statistics
- Honeypot integration support

## Configuration

```rust
use crate::prevention::{PreventionSettings, ThreatCategory, ResponseStrategy};
use std::time::Duration;
use std::collections::HashMap;

// Create advanced prevention settings
let mut response_strategies = HashMap::new();

// Configure response for port scanning
response_strategies.insert(ThreatCategory::PortScan, ResponseStrategy {
    initial_action: PreventionAction::Alert,
    escalation_action: PreventionAction::TempBan,
    escalation_delay: Duration::from_secs(180),
    max_escalation: 2,
});

// Configure response for DDoS attacks
response_strategies.insert(ThreatCategory::DDoS, ResponseStrategy {
    initial_action: PreventionAction::RateLimit,
    escalation_action: PreventionAction::BlockSource,
    escalation_delay: Duration::from_secs(30),
    max_escalation: 2,
});

let settings = PreventionSettings {
    enabled: true,
    use_native_firewall: true,
    response_strategies,
    global_rate_limit: 10000,
    per_ip_rate_limit: 100,
    use_threat_intelligence: true,
    adaptive_response: true,
    auto_block_duration: 60,
    whitelist: vec!["127.0.0.1".to_string()],
    blacklist: vec![],
    geo_block_countries: vec!["XX".to_string()],
    connection_tracking: true,
    max_connections_per_ip: 50,
    honeypot_enabled: true,
    honeypot_address: Some("192.168.1.100:8080".to_string()),
    auto_report_threats: true,
    threat_feeds: vec![
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt".to_string(),
    ],
};
```

## Usage Examples

### Basic Usage

```rust
use crate::prevention::PreventionManager;

// Create and start the prevention manager
let prevention_manager = PreventionManager::new(settings);
prevention_manager.start().await?;

// Process a threat
let action = prevention_manager.process_threat(&alert, None).await?;
println!("Action taken: {:?}", action);
```

### Manual IP Management

```rust
use std::net::IpAddr;
use std::str::FromStr;

// Block an IP manually
let ip = IpAddr::from_str("192.168.1.100")?;
prevention_manager.block_ip(
    ip, 
    "Manual block - suspicious activity", 
    None,
    Some(ThreatCategory::AnomalousTraffic)
)?;

// Add IP to whitelist
prevention_manager.add_to_whitelist(ip)?;

// Remove from whitelist
prevention_manager.remove_from_whitelist(&ip)?;
```

### Threat Intelligence Operations

```rust
// Check IP reputation
let reputation = prevention_manager.threat_intel.get_reputation(&ip);
println!("IP {} reputation score: {}", ip, reputation.score);

// Manually add threat indicator
use crate::prevention::threat_intelligence::{ThreatIndicator, ThreatType};
use chrono::Utc;

let indicator = ThreatIndicator {
    ip,
    threat_type: ThreatType::Scanner,
    confidence: 0.9,
    source: "Manual".to_string(),
    first_seen: Utc::now(),
    last_seen: Utc::now(),
    tags: vec!["port-scan".to_string()],
    description: Some("Detected scanning multiple ports".to_string()),
};

prevention_manager.threat_intel.add_indicator(indicator);
```

### Connection Tracking

```rust
use std::net::SocketAddr;
use crate::prevention::connection_tracker::Protocol;

// Track a new connection
let source = SocketAddr::from_str("192.168.1.100:54321")?;
let destination = SocketAddr::from_str("10.0.0.1:80")?;
let conn_id = prevention_manager.connection_tracker.track_connection(
    source,
    destination,
    Protocol::TCP
)?;

// Update connection traffic
prevention_manager.connection_tracker.update_connection_traffic(
    conn_id,
    1024,  // bytes
    10,    // packets
    true   // outbound
)?;

// Mark connection as suspicious
prevention_manager.connection_tracker.mark_suspicious(
    conn_id,
    "Unusual traffic pattern"
)?;

// Terminate connection
prevention_manager.connection_tracker.terminate_connection(conn_id)?;
```

### Rate Limiting

```rust
// Check if request should be rate limited
let allowed = prevention_manager.rate_limiter.check_rate_limit(ip, 1)?;
if !allowed {
    println!("Rate limit exceeded for IP: {}", ip);
}

// Get rate limit usage
if let Some((used, limit)) = prevention_manager.rate_limiter.get_ip_usage(ip) {
    println!("IP {} using {}/{} of rate limit", ip, used, limit);
}
```

### Metrics and Monitoring

```rust
// Get prevention metrics
let metrics = prevention_manager.get_metrics();
println!("Total threats detected: {}", metrics.total_threats_detected);
println!("Threats blocked: {}", metrics.threats_blocked);

// Get connection statistics
let conn_stats = prevention_manager.connection_tracker.get_stats();
println!("Active connections: {}", conn_stats.active_connections);
println!("Terminated connections: {}", conn_stats.terminated_connections);

// Export data
prevention_manager.threat_intel.export_indicators("/tmp/threat_indicators.json")?;
prevention_manager.connection_tracker.export_connections("/tmp/connections.json")?;
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Prevention Manager                        │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │  Firewall   │  │Rate Limiter  │  │Threat Intelligence│ │
│  │  Manager    │  │              │  │    Manager        │ │
│  └─────────────┘  └──────────────┘  └──────────────────┘ │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │ Connection  │  │  Escalation  │  │    Metrics &     │ │
│  │  Tracker    │  │   Tracker    │  │   Statistics     │ │
│  └─────────────┘  └──────────────┘  └──────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Performance Considerations

1. **Memory Usage**: The module maintains in-memory state for:
   - Active connections (configurable limit)
   - Rate limit states (auto-cleaned)
   - Threat indicators (cached)
   - Block history

2. **CPU Usage**: Background tasks run for:
   - Expired block cleanup (every minute)
   - Threat feed updates (configurable)
   - Connection state cleanup (every minute)
   - Rate limit state cleanup (every minute)

3. **Network Usage**: 
   - Threat feed downloads (periodic)
   - Firewall rule updates (on-demand)

## Security Best Practices

1. **Whitelist Critical IPs**: Always whitelist localhost and critical infrastructure IPs
2. **Configure Escalation Carefully**: Set appropriate escalation delays to avoid false positives
3. **Monitor Metrics**: Regularly review metrics to identify patterns and adjust settings
4. **Update Threat Feeds**: Keep threat intelligence feeds current and validated
5. **Test Firewall Rules**: Test firewall integration in a safe environment before production
6. **Set Appropriate Limits**: Configure rate limits based on your traffic patterns
7. **Regular Cleanup**: Export and archive old data periodically

## Troubleshooting

### Common Issues

1. **Firewall Integration Fails**
   - Check OS permissions (may need sudo/admin)
   - Verify firewall service is running
   - Check firewall command availability

2. **High Memory Usage**
   - Reduce connection tracking limits
   - Enable more aggressive cleanup intervals
   - Archive old block history

3. **False Positives**
   - Adjust threat detection sensitivity
   - Increase escalation delays
   - Add legitimate IPs to whitelist

4. **Performance Issues**
   - Reduce threat feed update frequency
   - Lower connection tracking limits
   - Disable unused features

## Future Enhancements

- Machine learning-based threat detection
- Distributed blocking across multiple nodes
- Advanced honeypot integration
- SIEM integration
- Custom threat feed formats
- IPv6 improvements
- WebSocket support for real-time updates 