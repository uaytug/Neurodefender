//! Packet analyzer module for deep packet inspection and protocol analysis.
//! 
//! This module provides packet analysis capabilities including header parsing,
//! protocol detection, payload analysis, and packet reassembly.

mod header_parser;
mod payload_parser;
mod protocol_identifier;
mod defragmentation;

// Re-export primary types and traits
pub use header_parser::{
    HeaderParser, HeaderParserError,
    EthernetHeader, IpHeader, TcpHeader, UdpHeader,
    TcpFlags,
};

pub use payload_parser::{
    PayloadParser, PayloadParserError,
    ProtocolType, ProtocolData,
    HttpData, TlsData, DnsData, DhcpData,
    ProtocolHandler,
};

pub use protocol_identifier::{
    ProtocolIdentifier, ProtocolIdentificationError,
    Protocol, ProtocolInfo,
};

pub use defragmentation::{
    Defragmenter, DefragmentationError,
    DefragmentationConfig,
};

use std::sync::Arc;
use thiserror::Error;
use crate::packet_processor::packet_buffer::{PacketBuffer, PacketBufferError};

/// Combined analyzer error type
#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error("Buffer error: {0}")]
    Buffer(#[from] PacketBufferError),

    #[error("Header parsing error: {0}")]
    HeaderParsing(#[from] HeaderParserError),

    #[error("Payload parsing error: {0}")]
    PayloadParsing(#[from] PayloadParserError),

    #[error("Protocol identification error: {0}")]
    ProtocolIdentification(#[from] ProtocolIdentificationError),

    #[error("Defragmentation error: {0}")]
    Defragmentation(#[from] DefragmentationError),
}

/// Analysis result for a packet
#[derive(Debug)]
pub struct PacketAnalysis {
    /// Ethernet header analysis
    pub ethernet: Option<EthernetHeader>,
    /// IP header analysis
    pub ip: Option<IpHeader>,
    /// TCP header analysis
    pub tcp: Option<TcpHeader>,
    /// UDP header analysis
    pub udp: Option<UdpHeader>,
    /// Protocol identification
    pub protocol: ProtocolInfo,
    /// Parsed protocol data
    pub protocol_data: Option<ProtocolData>,
    /// Analysis metadata
    pub metadata: std::collections::HashMap<String, String>,
}

/// Main packet analyzer that coordinates all analysis components
pub struct PacketAnalyzer {
    header_parser: HeaderParser,
    payload_parser: Arc<PayloadParser>,
    protocol_identifier: ProtocolIdentifier,
    defragmenter: Defragmenter,
}

impl PacketAnalyzer {
    /// Create a new packet analyzer
    pub fn new(config: AnalyzerConfig) -> Self {
        Self {
            header_parser: HeaderParser,
            payload_parser: Arc::new(PayloadParser::new(config.max_payload_size)),
            protocol_identifier: ProtocolIdentifier::new(),
            defragmenter: Defragmenter::new(config.defrag_config),
        }
    }

    /// Analyze a packet
    pub fn analyze_packet(&mut self, packet: &PacketBuffer) -> Result<PacketAnalysis, AnalyzerError> {
        // Parse Ethernet header
        let (ethernet, offset) = self.header_parser.parse_ethernet(packet)?;

        // Parse IP header if present
        let (ip, offset) = if ethernet.ethertype == 0x0800 {
            let (ip, next_offset) = self.header_parser.parse_ip(packet, offset)?;
            (Some(ip), next_offset)
        } else {
            (None, offset)
        };

        // Parse TCP/UDP headers if present
        let (tcp, udp, offset) = if let Some(ip_header) = &ip {
            match ip_header.protocol {
                6 => { // TCP
                    let (tcp, next_offset) = self.header_parser.parse_tcp(packet, offset)?;
                    (Some(tcp), None, next_offset)
                },
                17 => { // UDP
                    let (udp, next_offset) = self.header_parser.parse_udp(packet, offset)?;
                    (None, Some(udp), next_offset)
                },
                _ => (None, None, offset)
            }
        } else {
            (None, None, offset)
        };

        // Perform packet defragmentation if needed
        let packet_data = if let Some(ip_header) = &ip {
            if ip_header.more_fragments || ip_header.fragment_offset > 0 {
                match self.defragmenter.process_fragment(packet, ip_header)? {
                    Some(reassembled) => reassembled,
                    None => return Ok(PacketAnalysis {
                        ethernet: Some(ethernet),
                        ip,
                        tcp,
                        udp,
                        protocol: ProtocolInfo {
                            protocol: Protocol::UNKNOWN,
                            version: None,
                            confidence: 0.0,
                            metadata: std::collections::HashMap::new(),
                        },
                        protocol_data: None,
                        metadata: std::collections::HashMap::new(),
                    }),
                }
            } else {
                packet.data()?.to_vec()
            }
        } else {
            packet.data()?.to_vec()
        };

        // Identify protocol
        let protocol_info = self.protocol_identifier.identify_protocol(
            packet,
            tcp.as_ref(),
            udp.as_ref(),
        )?;

        // Parse protocol-specific payload
        let protocol_data = if protocol_info.protocol != Protocol::UNKNOWN {
            let context = payload_parser::ParsingContext {
                tcp_header: tcp.clone(),
                udp_header: udp.clone(),
                session_data: None,
            };

            let protocol_type = protocol_to_type(protocol_info.protocol);
            match self.payload_parser.parse_payload(packet, protocol_type, &context) {
                Ok(data) => Some(data),
                Err(_) => None,
            }
        } else {
            None
        };

        Ok(PacketAnalysis {
            ethernet: Some(ethernet),
            ip,
            tcp,
            udp,
            protocol: protocol_info,
            protocol_data,
            metadata: std::collections::HashMap::new(),
        })
    }
}

/// Configuration for the packet analyzer
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Maximum payload size to analyze
    pub max_payload_size: usize,
    /// Defragmentation configuration
    pub defrag_config: DefragmentationConfig,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            max_payload_size: 65536,
            defrag_config: DefragmentationConfig::default(),
        }
    }
}

/// Convert Protocol to ProtocolType
fn protocol_to_type(protocol: Protocol) -> ProtocolType {
    match protocol {
        Protocol::HTTP => ProtocolType::HTTP,
        Protocol::HTTPS => ProtocolType::TLS,
        Protocol::DNS => ProtocolType::DNS,
        Protocol::DHCP => ProtocolType::DHCP,
        _ => ProtocolType::Custom(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let config = AnalyzerConfig::default();
        let analyzer = PacketAnalyzer::new(config);
        // Verify analyzer is created successfully
    }

    #[test]
    fn test_error_conversion() {
        let buffer_error = PacketBufferError::InvalidLength;
        let analyzer_error: AnalyzerError = buffer_error.into();
        assert!(matches!(analyzer_error, AnalyzerError::Buffer(_)));
    }
}