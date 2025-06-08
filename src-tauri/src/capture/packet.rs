use std::net::IpAddr;
use std::ops::BitAnd;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

/// Protocols we're specifically tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Hash)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    HTTP,
    HTTPS,
    DNS,
    SSH,
    FTP,
    SMTP,
    POP3,
    IMAP,
    DHCP,
    ARP,
    SNMP,
    Other(u8),
}

/// Direction of a packet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Hash)]
pub enum Direction {
    Inbound,
    Outbound,
    Internal,
    External,
}

/// Basic packet information extracted from network captures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    /// Timestamp when the packet was captured
    pub timestamp: DateTime<Utc>,

    /// Source IP address
    pub source_ip: IpAddr,

    /// Destination IP address
    pub destination_ip: IpAddr,

    /// Source port (for TCP/UDP)
    pub source_port: Option<u16>,

    /// Destination port (for TCP/UDP)
    pub destination_port: Option<u16>,

    /// Protocol
    pub protocol: Protocol,

    /// Packet size in bytes
    pub size: usize,

    /// Packet direction relative to our network
    pub direction: Direction,

    /// TCP flags (if applicable)
    pub tcp_flags: Option<TcpFlags>,

    /// Packet payload size
    pub payload_size: usize,

    /// Hash of the packet payload (for identifying duplicates/patterns)
    pub payload_hash: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Vec<u8>>,
    
    
}

/// TCP Flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

pub fn get_flags() -> TcpFlags {
    let flags = TcpFlags {
        fin: false,
        syn: false,
        rst: false,
        psh: false,
        ack: false,
        urg: false,
        ece: false,
        cwr: false,
    };
    return flags;
}

impl BitAnd<i32> for TcpFlags {
    type Output = i32;

    fn bitand(self, rhs: i32) -> Self::Output {
        let mut result = 0;
        if self.fin { result |= 0b00000001; }
        if self.syn { result |= 0b00000010; }
        if self.rst { result |= 0b00000100; }
        if self.psh { result |= 0b00001000; }
        if self.ack { result |= 0b00010000; }
        if self.urg { result |= 0b00100000; }
        if self.ece { result |= 0b01000000; }
        if self.cwr { result |= 0b10000000; }
        result
    }
}

impl TcpFlags {
    /// Create TCP flags from a byte
    pub fn from_u8(flags: TcpFlags) -> Self {
        Self {
            fin: (flags & 0b00000001) != 0,
            syn: (flags & 0b00000010) != 0,
            rst: (flags & 0b00000100) != 0,
            psh: (flags & 0b00001000) != 0,
            ack: (flags & 0b00010000) != 0,
            urg: (flags & 0b00100000) != 0,
            ece: (flags & 0b01000000) != 0,
            cwr: (flags & 0b10000000) != 0,
        }
    }

    /// Check if this is a SYN packet
    pub fn is_syn(&self) -> bool {
        self.syn && !self.ack
    }

    /// Check if this is a SYN-ACK packet
    pub fn is_syn_ack(&self) -> bool {
        self.syn && self.ack
    }

    /// Check if this is a FIN packet
    pub fn is_fin(&self) -> bool {
        self.fin
    }

    /// Check if this is a RST packet
    pub fn is_rst(&self) -> bool {
        self.rst
    }

    /// Convert to a string representation (e.g., "S" for SYN, "SA" for SYN-ACK)
    pub fn to_string(&self) -> String {
        let mut result = String::new();

        if self.syn { result.push('S'); }
        if self.ack { result.push('A'); }
        if self.fin { result.push('F'); }
        if self.rst { result.push('R'); }
        if self.psh { result.push('P'); }
        if self.urg { result.push('U'); }
        if self.ece { result.push('E'); }
        if self.cwr { result.push('C'); }

        if result.is_empty() {
            result.push('.');
        }

        result
    }
}

/// Packet statistics for analyzed network traffic
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PacketStatistics {
    /// Total packets captured
    pub total_packets: usize,

    /// Total bytes captured
    pub total_bytes: usize,

    /// Packets by protocol
    pub packets_by_protocol: std::collections::HashMap<Protocol, usize>,

    /// Bytes by protocol
    pub bytes_by_protocol: std::collections::HashMap<Protocol, usize>,

    /// Packets by direction
    pub packets_by_direction: std::collections::HashMap<Direction, usize>,

    /// Unique source IPs seen
    pub unique_source_ips: usize,

    /// Unique destination IPs seen
    pub unique_destination_ips: usize,

    /// Start time of the capture
    pub start_time: Option<DateTime<Utc>>,

    /// End time of the capture
    pub end_time: Option<DateTime<Utc>>,

    /// Count of TCP SYN packets
    pub syn_packets: usize,

    /// Count of TCP RST packets
    pub rst_packets: usize,
}

impl PacketStatistics {
    /// Create a new, empty statistics object
    pub fn new() -> Self {
        Self::default()
    }

    /// Update statistics with information from a packet
    pub fn update(&mut self, packet: &PacketInfo) {
        // Update total counters
        self.total_packets += 1;
        self.total_bytes += packet.size;

        // Update protocol-specific counters
        *self.packets_by_protocol.entry(packet.protocol).or_insert(0) += 1;
        *self.bytes_by_protocol.entry(packet.protocol).or_insert(0) += packet.size;

        // Update direction counters
        *self.packets_by_direction.entry(packet.direction).or_insert(0) += 1;

        // Update timestamp info
        if let Some(start_time) = self.start_time {
            if packet.timestamp < start_time {
                self.start_time = Some(packet.timestamp);
            }
        } else {
            self.start_time = Some(packet.timestamp);
        }

        if let Some(end_time) = self.end_time {
            if packet.timestamp > end_time {
                self.end_time = Some(packet.timestamp);
            }
        } else {
            self.end_time = Some(packet.timestamp);
        }

        // Update TCP flags counters if applicable
        if let Some(tcp_flags) = &packet.tcp_flags {
            if tcp_flags.syn && !tcp_flags.ack {
                self.syn_packets += 1;
            }

            if tcp_flags.rst {
                self.rst_packets += 1;
            }
        }
    }

    /// Calculate packets per second
    pub fn packets_per_second(&self) -> f64 {
        match (self.start_time, self.end_time) {
            (Some(start), Some(end)) => {
                let duration = end.signed_duration_since(start);
                let seconds = duration.num_milliseconds() as f64 / 1000.0;
                if seconds > 0.0 {
                    self.total_packets as f64 / seconds
                } else {
                    0.0
                }
            },
            _ => 0.0,
        }
    }

    /// Calculate bytes per second
    pub fn bytes_per_second(&self) -> f64 {
        match (self.start_time, self.end_time) {
            (Some(start), Some(end)) => {
                let duration = end.signed_duration_since(start);
                let seconds = duration.num_milliseconds() as f64 / 1000.0;
                if seconds > 0.0 {
                    self.total_bytes as f64 / seconds
                } else {
                    0.0
                }
            },
            _ => 0.0,
        }
    }

    /// Merge with another statistics object
    pub fn merge(&mut self, other: &PacketStatistics) {
        self.total_packets += other.total_packets;
        self.total_bytes += other.total_bytes;

        // Merge protocol counters
        for (protocol, count) in &other.packets_by_protocol {
            *self.packets_by_protocol.entry(*protocol).or_insert(0) += count;
        }

        for (protocol, bytes) in &other.bytes_by_protocol {
            *self.bytes_by_protocol.entry(*protocol).or_insert(0) += bytes;
        }

        // Merge direction counters
        for (direction, count) in &other.packets_by_direction {
            *self.packets_by_direction.entry(*direction).or_insert(0) += count;
        }

        // Update timestamp info
        if let Some(other_start) = other.start_time {
            if let Some(self_start) = self.start_time {
                if other_start < self_start {
                    self.start_time = Some(other_start);
                }
            } else {
                self.start_time = Some(other_start);
            }
        }

        if let Some(other_end) = other.end_time {
            if let Some(self_end) = self.end_time {
                if other_end > self_end {
                    self.end_time = Some(other_end);
                }
            } else {
                self.end_time = Some(other_end);
            }
        }

        // Merge TCP flags counters
        self.syn_packets += other.syn_packets;
        self.rst_packets += other.rst_packets;
    }
}