use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::capture::packet::{Direction, PacketInfo, PacketStatistics, Protocol};

/// Thresholds for anomaly detection
#[derive(Debug, Clone)]
pub struct AnalysisThresholds {
    /// Packets per second threshold for rate-based detection
    pub packets_per_second: f64,
    /// Maximum number of ports a single IP can scan
    pub port_scan_threshold: usize,
    /// Maximum number of IPs a single IP can scan
    pub host_scan_threshold: usize,
    /// Duration window for scan detection (in seconds)
    pub scan_window_seconds: u64,
    /// Minimum packets required to establish a connection pattern
    pub min_packets_for_connection: usize,
}

impl Default for AnalysisThresholds {
    fn default() -> Self {
        Self {
            packets_per_second: 500.0,        // 500 pps is suspicious
            port_scan_threshold: 15,          // 15 ports in a short time suggests scanning
            host_scan_threshold: 10,          // 10 hosts in a short time suggests scanning
            scan_window_seconds: 10,          // Check within a 10-second window
            min_packets_for_connection: 3,    // At least 3 packets to consider it a connection
        }
    }
}

/// Sets analyzer sensitivity level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisSensitivity {
    Low,    // Lower false positives, may miss actual threats
    Medium, // Balanced
    High,   // Higher false positives, less likely to miss threats
}

impl AnalysisSensitivity {
    /// Convert from string representation
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "low" => Self::Low,
            "high" => Self::High,
            _ => Self::Medium, // Default to medium
        }
    }

    /// Get thresholds based on sensitivity level
    pub fn get_thresholds(&self) -> AnalysisThresholds {
        match self {
            Self::Low => AnalysisThresholds {
                packets_per_second: 1000.0,
                port_scan_threshold: 25,
                host_scan_threshold: 20,
                scan_window_seconds: 5,
                min_packets_for_connection: 5,
            },
            Self::Medium => AnalysisThresholds::default(),
            Self::High => AnalysisThresholds {
                packets_per_second: 300.0,
                port_scan_threshold: 10,
                host_scan_threshold: 5,
                scan_window_seconds: 30,
                min_packets_for_connection: 2,
            },
        }
    }
}

/// Potential security threat type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatType {
    PortScan,
    HostScan,
    RateLimitExceeded,
    SuspiciousConnection,
    AbnormalTraffic,
    MaliciousPayload,
}

/// Security threat information
#[derive(Debug, Clone)]
pub struct ThreatInfo {
    /// Type of threat detected
    pub threat_type: ThreatType,
    /// Time of detection
    pub timestamp: DateTime<Utc>,
    /// Source IP address
    pub source_ip: IpAddr,
    /// Destination IP address (if applicable)
    pub destination_ip: Option<IpAddr>,
    /// Source port (if applicable)
    pub source_port: Option<u16>,
    /// Destination port (if applicable)
    pub destination_port: Option<u16>,
    /// Protocol
    pub protocol: Protocol,
    /// Description of the threat
    pub description: String,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
    /// Additional details
    pub details: Option<String>,
}

/// Container for recently seen packets to detect patterns
#[derive(Debug)]
struct PacketWindow {
    /// Track source IPs and the ports they've connected to
    port_scan_tracker: HashMap<IpAddr, HashSet<u16>>,
    /// Track source IPs and the hosts they've connected to
    host_scan_tracker: HashMap<IpAddr, HashSet<IpAddr>>,
    /// Last time the window was cleared
    last_clear_time: Instant,
    /// Window duration
    window_duration: Duration,
    /// Packet statistics for the current window
    statistics: PacketStatistics,
}

impl PacketWindow {
    /// Create a new packet window
    fn new(window_seconds: u64) -> Self {
        Self {
            port_scan_tracker: HashMap::new(),
            host_scan_tracker: HashMap::new(),
            last_clear_time: Instant::now(),
            window_duration: Duration::from_secs(window_seconds),
            statistics: PacketStatistics::new(),
        }
    }

    /// Add a packet to the window and track potential scans
    fn add_packet(&mut self, packet: &PacketInfo) {
        // Update statistics
        self.statistics.update(packet);

        // Track for port scans (only if we have port information)
        if let (Some(dest_port), Direction::Inbound) = (packet.destination_port, packet.direction) {
            let ports = self.port_scan_tracker
                .entry(packet.source_ip)
                .or_insert_with(HashSet::new);
            ports.insert(dest_port);
        }

        // Track for host scans
        if packet.direction == Direction::Inbound || packet.direction == Direction::External {
            let hosts = self.host_scan_tracker
                .entry(packet.source_ip)
                .or_insert_with(HashSet::new);
            hosts.insert(packet.destination_ip);
        }

        // Check if we need to clear the window
        let now = Instant::now();
        if now.duration_since(self.last_clear_time) > self.window_duration {
            self.clear();
            self.last_clear_time = now;
        }
    }

    /// Clear the window
    fn clear(&mut self) {
        self.port_scan_tracker.clear();
        self.host_scan_tracker.clear();
        self.statistics = PacketStatistics::new();
    }

    /// Check for port scans
    fn check_port_scans(&self, threshold: usize) -> Vec<(IpAddr, usize)> {
        let mut scanners = Vec::new();

        for (ip, ports) in &self.port_scan_tracker {
            if ports.len() >= threshold {
                scanners.push((*ip, ports.len()));
            }
        }

        scanners
    }

    /// Check for host scans
    fn check_host_scans(&self, threshold: usize) -> Vec<(IpAddr, usize)> {
        let mut scanners = Vec::new();

        for (ip, hosts) in &self.host_scan_tracker {
            if hosts.len() >= threshold {
                scanners.push((*ip, hosts.len()));
            }
        }

        scanners
    }

    /// Get packet rate (packets per second)
    fn get_packet_rate(&self) -> f64 {
        self.statistics.packets_per_second()
    }
}

/// Network traffic analyzer for intrusion detection
pub struct TrafficAnalyzer {
    /// Analyzer sensitivity level
    sensitivity: AnalysisSensitivity,
    /// Analysis thresholds
    thresholds: AnalysisThresholds,
    /// Recent packet window for pattern detection
    packet_window: Mutex<PacketWindow>,
    /// Overall packet statistics
    statistics: Mutex<PacketStatistics>,
    /// Known safe IPs that should not trigger alerts
    safe_ips: Mutex<HashSet<IpAddr>>,
    /// Known malicious IPs that should always trigger alerts
    malicious_ips: Mutex<HashSet<IpAddr>>,
}

impl TrafficAnalyzer {
    /// Create a new traffic analyzer with the given sensitivity
    pub fn new(sensitivity: AnalysisSensitivity) -> Self {
        let thresholds = sensitivity.get_thresholds();
        let window_duration = thresholds.scan_window_seconds;

        Self {
            sensitivity,
            thresholds,
            packet_window: Mutex::new(PacketWindow::new(window_duration)),
            statistics: Mutex::new(PacketStatistics::new()),
            safe_ips: Mutex::new(HashSet::new()),
            malicious_ips: Mutex::new(HashSet::new()),
        }
    }

    /// Add a safe IP address
    pub fn add_safe_ip(&self, ip: IpAddr) {
        let mut safe_ips = self.safe_ips.lock().unwrap();
        safe_ips.insert(ip);
    }

    /// Add a malicious IP address
    pub fn add_malicious_ip(&self, ip: IpAddr) {
        let mut malicious_ips = self.malicious_ips.lock().unwrap();
        malicious_ips.insert(ip);
    }

    /// Analyze a packet and return any detected threats
    pub fn analyze_packet(&self, packet: &PacketInfo) -> Vec<ThreatInfo> {
        let mut threats = Vec::new();

        // Check for known malicious IPs first
        if let Ok(malicious_ips) = self.malicious_ips.lock() {
            if malicious_ips.contains(&packet.source_ip) {
                threats.push(ThreatInfo {
                    threat_type: ThreatType::SuspiciousConnection,
                    timestamp: Utc::now(),
                    source_ip: packet.source_ip,
                    destination_ip: Some(packet.destination_ip),
                    source_port: packet.source_port,
                    destination_port: packet.destination_port,
                    protocol: packet.protocol,
                    description: format!("Traffic from known malicious IP: {}", packet.source_ip),
                    confidence: 0.95,
                    details: None,
                });
            }
        }

        // Skip further analysis for known safe IPs
        if let Ok(safe_ips) = self.safe_ips.lock() {
            if safe_ips.contains(&packet.source_ip) {
                return threats;
            }
        }

        // Update packet window and statistics
        let mut window = self.packet_window.lock().unwrap();
        window.add_packet(packet);

        let mut stats = self.statistics.lock().unwrap();
        stats.update(packet);

        // Check for port scans
        let port_scanners = window.check_port_scans(self.thresholds.port_scan_threshold);
        for (scanner_ip, port_count) in port_scanners {
            if scanner_ip == packet.source_ip {
                threats.push(ThreatInfo {
                    threat_type: ThreatType::PortScan,
                    timestamp: Utc::now(),
                    source_ip: scanner_ip,
                    destination_ip: Some(packet.destination_ip),
                    source_port: packet.source_port,
                    destination_port: packet.destination_port,
                    protocol: packet.protocol,
                    description: format!("Port scan detected: {} ports scanned", port_count),
                    confidence: self.calculate_confidence(port_count, self.thresholds.port_scan_threshold),
                    details: Some(format!("Source IP {} scanned {} unique ports in {} seconds",
                                          scanner_ip, port_count, self.thresholds.scan_window_seconds)),
                });
            }
        }

        // Check for host scans
        let host_scanners = window.check_host_scans(self.thresholds.host_scan_threshold);
        for (scanner_ip, host_count) in host_scanners {
            if scanner_ip == packet.source_ip {
                threats.push(ThreatInfo {
                    threat_type: ThreatType::HostScan,
                    timestamp: Utc::now(),
                    source_ip: scanner_ip,
                    destination_ip: Some(packet.destination_ip),
                    source_port: packet.source_port,
                    destination_port: packet.destination_port,
                    protocol: packet.protocol,
                    description: format!("Host scan detected: {} hosts scanned", host_count),
                    confidence: self.calculate_confidence(host_count, self.thresholds.host_scan_threshold),
                    details: Some(format!("Source IP {} scanned {} unique hosts in {} seconds",
                                          scanner_ip, host_count, self.thresholds.scan_window_seconds)),
                });
            }
        }

        // Check for rate-based anomalies
        let packet_rate = window.get_packet_rate();
        if packet_rate > self.thresholds.packets_per_second {
            threats.push(ThreatInfo {
                threat_type: ThreatType::RateLimitExceeded,
                timestamp: Utc::now(),
                source_ip: packet.source_ip,
                destination_ip: Some(packet.destination_ip),
                source_port: packet.source_port,
                destination_port: packet.destination_port,
                protocol: packet.protocol,
                description: format!("Abnormal traffic rate: {:.2} packets/sec", packet_rate),
                confidence: self.calculate_rate_confidence(packet_rate, self.thresholds.packets_per_second),
                details: Some(format!("Traffic exceeded threshold of {} packets/sec",
                                      self.thresholds.packets_per_second)),
            });
        }

        // Add more analysis as needed...

        threats
    }

    /// Calculate confidence level based on threshold exceedance
    fn calculate_confidence(&self, value: usize, threshold: usize) -> f64 {
        let base_confidence = match self.sensitivity {
            AnalysisSensitivity::Low => 0.7,
            AnalysisSensitivity::Medium => 0.8,
            AnalysisSensitivity::High => 0.9,
        };

        // Increase confidence as the value exceeds the threshold more significantly
        let exceedance_factor = if value > threshold {
            (value as f64 / threshold as f64).min(2.0) - 1.0
        } else {
            0.0
        };

        (base_confidence + (exceedance_factor * 0.1)).min(0.99)
    }

    /// Calculate confidence level for rate-based detections
    fn calculate_rate_confidence(&self, rate: f64, threshold: f64) -> f64 {
        let base_confidence = match self.sensitivity {
            AnalysisSensitivity::Low => 0.7,
            AnalysisSensitivity::Medium => 0.8,
            AnalysisSensitivity::High => 0.9,
        };

        // Increase confidence as the rate exceeds the threshold more significantly
        let exceedance_factor = if rate > threshold {
            (rate / threshold).min(3.0) - 1.0
        } else {
            0.0
        };

        (base_confidence + (exceedance_factor * 0.1)).min(0.99)
    }

    /// Get current packet statistics
    pub fn get_statistics(&self) -> PacketStatistics {
        let stats = self.statistics.lock().unwrap();
        stats.clone()
    }

    /// Set analyzer sensitivity level
    pub fn set_sensitivity(&mut self, sensitivity: AnalysisSensitivity) {
        self.sensitivity = sensitivity;
        self.thresholds = sensitivity.get_thresholds();

        // Update window duration
        let window_duration = self.thresholds.scan_window_seconds;
        let mut window = self.packet_window.lock().unwrap();
        *window = PacketWindow::new(window_duration);
    }
}

/// ConnectionTracker tracks network connections for anomaly detection
pub struct ConnectionTracker {
    /// Tracks active connections by source IP, dest IP, source port, dest port, protocol
    active_connections: HashMap<(IpAddr, IpAddr, u16, u16, Protocol), ConnectionState>,
    /// Tracks connection counts by IP
    connection_counts: HashMap<IpAddr, usize>,
    /// Maximum number of concurrent connections allowed per IP
    max_connections_per_ip: usize,
}

/// Connection state tracking
#[derive(Debug, Clone)]
struct ConnectionState {
    /// When the connection was first seen
    first_seen: DateTime<Utc>,
    /// When the connection was last seen
    last_seen: DateTime<Utc>,
    /// Number of packets sent in this connection
    packet_count: usize,
    /// Total bytes transferred in this connection
    byte_count: usize,
    /// Whether the connection has been established (e.g., TCP handshake complete)
    established: bool,
    /// Whether the connection has been terminated
    terminated: bool,
}

impl ConnectionTracker {
    /// Create a new connection tracker
    pub fn new(max_connections_per_ip: usize) -> Self {
        Self {
            active_connections: HashMap::new(),
            connection_counts: HashMap::new(),
            max_connections_per_ip,
        }
    }

    /// Update the connection tracker with a packet
    pub fn update(&mut self, packet: &PacketInfo) -> Option<ThreatInfo> {
        // Need both ports to track a connection
        if let (Some(src_port), Some(dst_port)) = (packet.source_port, packet.destination_port) {
            // Create a connection key
            let key = (
                packet.source_ip,
                packet.destination_ip,
                src_port,
                dst_port,
                packet.protocol,
            );

            // Update or create connection state
            let now = Utc::now();
            if let Some(conn) = self.active_connections.get_mut(&key) {
                // Update existing connection
                conn.last_seen = now;
                conn.packet_count += 1;
                conn.byte_count += packet.size;

                // Check for connection establishment (TCP)
                if let Some(tcp_flags) = &packet.tcp_flags {
                    if tcp_flags.is_syn_ack() && !conn.established {
                        conn.established = true;
                    } else if tcp_flags.is_fin() || tcp_flags.is_rst() {
                        conn.terminated = true;
                        // Could remove from active_connections here
                    }
                }

                None
            } else {
                // New connection
                let conn = ConnectionState {
                    first_seen: now,
                    last_seen: now,
                    packet_count: 1,
                    byte_count: packet.size,
                    established: false,
                    terminated: false,
                };

                // Update the connection
                self.active_connections.insert(key, conn);

                // Update connection count for source IP
                let count = self.connection_counts.entry(packet.source_ip).or_insert(0);
                *count += 1;

                // Check if this IP has too many connections
                if *count > self.max_connections_per_ip {
                    Some(ThreatInfo {
                        threat_type: ThreatType::SuspiciousConnection,
                        timestamp: now,
                        source_ip: packet.source_ip,
                        destination_ip: Some(packet.destination_ip),
                        source_port: Some(src_port),
                        destination_port: Some(dst_port),
                        protocol: packet.protocol,
                        description: format!("Excessive connection count from IP: {}", packet.source_ip),
                        confidence: 0.8,
                        details: Some(format!("IP has {} active connections (max allowed: {})",
                                              count, self.max_connections_per_ip)),
                    })
                } else {
                    None
                }
            }
        } else {
            // Can't track stateless protocols without port information
            None
        }
    }

    /// Clean up old connections
    pub fn cleanup(&mut self, max_age_seconds: i64) {
        let now = Utc::now();
        let mut to_remove = Vec::new();

        // Find old connections to remove
        for (key, conn) in &self.active_connections {
            let age = now.signed_duration_since(conn.last_seen);
            if age.num_seconds() > max_age_seconds || conn.terminated {
                to_remove.push(*key);
            }
        }

        // Remove old connections and update counts
        for key in to_remove {
            self.active_connections.remove(&key);

            // Decrease connection count for this IP
            if let Some(count) = self.connection_counts.get_mut(&key.0) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.connection_counts.remove(&key.0);
                }
            }
        }
    }

    /// Get number of active connections
    pub fn get_connection_count(&self) -> usize {
        self.active_connections.len()
    }

    /// Get number of unique IPs with active connections
    pub fn get_unique_ip_count(&self) -> usize {
        self.connection_counts.len()
    }
}