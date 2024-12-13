use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

use crate::packet_processor::packet_buffer::{PacketBuffer, PacketBufferError};
use crate::packet_processor::packet_buffer::PacketBuffer;

#[derive(Debug, Error)]
pub enum HeaderParserError {
    #[error("Buffer error: {0}")]
    BufferError(#[from] PacketBufferError),

    #[error("Invalid header length")]
    InvalidLength,

    #[error("Invalid header version")]
    InvalidVersion,

    #[error("Invalid checksum")]
    InvalidChecksum,

    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(u8),
}

/// Ethernet header information
#[derive(Debug, Clone)]
pub struct EthernetHeader {
    pub source: [u8; 6],
    pub destination: [u8; 6],
    pub ethertype: u16,
}

/// IPv4 header information
#[derive(Debug, Clone)]
pub struct IpHeader {
    pub version: u8,
    pub header_length: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub options: Vec<u8>,
    pub more_fragments: bool,
}

/// TCP header information
#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Vec<u8>,
}

/// UDP header information
#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}

/// TCP flags
#[derive(Debug, Clone, Copy)]
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

/// Header parser for network packets
pub struct HeaderParser;

impl HeaderParser {
    /// Parse Ethernet header from packet
    pub fn parse_ethernet(packet: &PacketBuffer) -> Result<(EthernetHeader, usize), HeaderParserError> {
        let data = packet.data()?;
        if data.len() < 14 {
            return Err(HeaderParserError::InvalidLength);
        }

        let mut source = [0u8; 6];
        let mut destination = [0u8; 6];

        source.copy_from_slice(&data[0..6]);
        destination.copy_from_slice(&data[6..12]);
        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        Ok((EthernetHeader {
            source,
            destination,
            ethertype,
        }, 14))
    }

    /// Parse IP header from packet
    pub fn parse_ip(packet: &PacketBuffer, offset: usize) -> Result<(IpHeader, usize), HeaderParserError> {
        let data = packet.data()?;
        if data.len() < offset + 20 {
            return Err(HeaderParserError::InvalidLength);
        }

        let version = (data[offset] >> 4) & 0x0F;
        let header_length = (data[offset] & 0x0F) * 4;
        
        match version {
            4 => Self::parse_ipv4(packet, offset),
            6 => Self::parse_ipv6(packet, offset),
            _ => Err(HeaderParserError::InvalidVersion),
        }
    }

    /// Parse IPv4 header
    fn parse_ipv4(packet: &PacketBuffer, offset: usize) -> Result<(IpHeader, usize), HeaderParserError> {
        let data = packet.data()?;
        let header_length = (data[offset] & 0x0F) * 4;

        if data.len() < offset + header_length as usize {
            return Err(HeaderParserError::InvalidLength);
        }

        let dscp = data[offset + 1] >> 2;
        let ecn = data[offset + 1] & 0x03;
        let total_length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let identification = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
        let flags = (data[offset + 6] >> 5) & 0x07;
        let fragment_offset = u16::from_be_bytes([
            data[offset + 6] & 0x1F,
            data[offset + 7],
        ]);
        let ttl = data[offset + 8];
        let protocol = data[offset + 9];
        let checksum = u16::from_be_bytes([data[offset + 10], data[offset + 11]]);

        let mut source_addr = [0u8; 4];
        let mut dest_addr = [0u8; 4];
        source_addr.copy_from_slice(&data[offset + 12..offset + 16]);
        dest_addr.copy_from_slice(&data[offset + 16..offset + 20]);

        let mut options = Vec::new();
        if header_length > 20 {
            options.extend_from_slice(&data[offset + 20..offset + header_length as usize]);
        }

        Ok((IpHeader {
            version: 4,
            header_length,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            source: IpAddr::V4(Ipv4Addr::from(source_addr)),
            destination: IpAddr::V4(Ipv4Addr::from(dest_addr)),
            options,
            more_fragments: (flags & 0x01) != 0,
        }, header_length as usize))
    }

    /// Parse IPv6 header
    fn parse_ipv6(packet: &PacketBuffer, offset: usize) -> Result<(IpHeader, usize), HeaderParserError> {
        let data = packet.data()?;
        if data.len() < offset + 40 {
            return Err(HeaderParserError::InvalidLength);
        }

        let mut flow_label = [0u8; 4];
        flow_label[0] = data[offset] & 0x0F;
        flow_label[1] = data[offset + 1];
        flow_label[2] = data[offset + 2];
        flow_label[3] = data[offset + 3];

        let payload_length = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
        let next_header = data[offset + 6];
        let hop_limit = data[offset + 7];

        let mut source_addr = [0u8; 16];
        let mut dest_addr = [0u8; 16];
        source_addr.copy_from_slice(&data[offset + 8..offset + 24]);
        dest_addr.copy_from_slice(&data[offset + 24..offset + 40]);

        Ok((IpHeader {
            version: 6,
            header_length: 40,
            dscp: (flow_label[0] >> 2) & 0x3F,
            ecn: flow_label[0] & 0x03,
            total_length: payload_length + 40,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: hop_limit,
            protocol: next_header,
            checksum: 0,
            source: IpAddr::V6(Ipv6Addr::from(source_addr)),
            destination: IpAddr::V6(Ipv6Addr::from(dest_addr)),
            options: Vec::new(),
            more_fragments: false,
        }, 40))
    }

    /// Parse TCP header
    pub fn parse_tcp(packet: &PacketBuffer, offset: usize) -> Result<(TcpHeader, usize), HeaderParserError> {
        let data = packet.data()?;
        if data.len() < offset + 20 {
            return Err(HeaderParserError::InvalidLength);
        }

        let source_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let destination_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let sequence_number = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let acknowledgment_number = u32::from_be_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]);

        let data_offset = (data[offset + 12] >> 4) * 4;
        let flags_byte = data[offset + 13];
        let window_size = u16::from_be_bytes([data[offset + 14], data[offset + 15]]);
        let checksum = u16::from_be_bytes([data[offset + 16], data[offset + 17]]);
        let urgent_pointer = u16::from_be_bytes([data[offset + 18], data[offset + 19]]);

        let mut options = Vec::new();
        if data_offset > 20 {
            options.extend_from_slice(&data[offset + 20..offset + data_offset as usize]);
        }

        let flags = TcpFlags {
            fin: (flags_byte & 0x01) != 0,
            syn: (flags_byte & 0x02) != 0,
            rst: (flags_byte & 0x04) != 0,
            psh: (flags_byte & 0x08) != 0,
            ack: (flags_byte & 0x10) != 0,
            urg: (flags_byte & 0x20) != 0,
            ece: (flags_byte & 0x40) != 0,
            cwr: (flags_byte & 0x80) != 0,
        };

        Ok((TcpHeader {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_pointer,
            options,
        }, data_offset as usize))
    }

    /// Parse UDP header
    pub fn parse_udp(packet: &PacketBuffer, offset: usize) -> Result<(UdpHeader, usize), HeaderParserError> {
        let data = packet.data()?;
        if data.len() < offset + 8 {
            return Err(HeaderParserError::InvalidLength);
        }

        Ok((UdpHeader {
            source_port: u16::from_be_bytes([data[offset], data[offset + 1]]),
            destination_port: u16::from_be_bytes([data[offset + 2], data[offset + 3]]),
            length: u16::from_be_bytes([data[offset + 4], data[offset + 5]]),
            checksum: u16::from_be_bytes([data[offset + 6], data[offset + 7]]),
        }, 8))
    }

    /// Verify IP checksum
    pub fn verify_ip_checksum(header: &IpHeader) -> bool {
        // IPv6 doesn't use checksums
        if header.version == 6 {
            return true;
        }

        // Calculate checksum
        let mut sum: u32 = 0;
        
        // Add version, IHL, DSCP, ECN, and total length
        sum += ((header.version as u32) << 12)
            | ((header.header_length as u32) << 8)
            | ((header.dscp as u32) << 2)
            | (header.ecn as u32);
        sum += header.total_length as u32;

        // Add identification
        sum += header.identification as u32;

        // Add flags, fragment offset
        sum += (((header.flags as u32) << 13) | (header.fragment_offset as u32)) as u32;

        // Add TTL and protocol
        sum += ((header.ttl as u32) << 8) | (header.protocol as u32);

        // Skip checksum field

        // Add source and destination addresses
        match header.source {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                sum += ((octets[0] as u32) << 8) | (octets[1] as u32);
                sum += ((octets[2] as u32) << 8) | (octets[3] as u32);
            },
            _ => return false,
        }

        match header.destination {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                sum += ((octets[0] as u32) << 8) | (octets[1] as u32);
                sum += ((octets[2] as u32) << 8) | (octets[3] as u32);
            },
            _ => return false,
        }

        // Add carries
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Take one's complement
        let checksum = !sum as u16;
        
        checksum == header.checksum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_header_parsing() {
        let mut data = vec![0u8; 64];
        // Set source MAC
        data[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Set destination MAC
        data[6..12].copy_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        // Set EtherType to IPv4 (0x0800)
        data[12..14].copy_from_slice(&[0x08, 0x00]);

        let packet = PacketBuffer::new_with_data(&data).unwrap();
        let (header, offset) = HeaderParser::parse_ethernet(&packet).unwrap();

        assert_eq!(header.source, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(header.destination, [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        assert_eq!(header.ethertype, 0x0800);
        assert_eq!(offset, 14);
    }

    #[test]
    fn test_ipv4_header_parsing() {
        let mut data = vec![0u8; 64];
        // Set IPv4 header
        data[0] = 0x45; // Version and IHL
        data[1] = 0x00; // DSCP and ECN
        data[2..4].copy_from_slice(&[0x00, 0x3C]); // Total length
        data[4..6].copy_from_slice(&[0x1C, 0x46]); // Identification
        data[6..8].copy_from_slice(&[0x40, 0x00]); // Flags and Fragment Offset
        data[8] = 0x40; // TTL
        data[9] = 0x06; // Protocol (TCP)
        data[10..12].copy_from_slice(&[0xB1, 0xE6]); // Header checksum
        data[12..16].copy_from_slice(&[192, 168, 0, 1]); // Source IP
        data[16..20].copy_from_slice(&[192, 168, 0, 2]); // Destination IP

        let packet = PacketBuffer::new_with_data(&data).unwrap();
        let (header, offset) = HeaderParser::parse_ipv4(&packet, 0).unwrap();

        assert_eq!(header.version, 4);
        assert_eq!(header.header_length, 20);
        assert_eq!(header.dscp, 0);
        assert_eq!(header.ecn, 0);
        assert_eq!(header.total_length, 60);
        assert_eq!(header.identification, 7238);
        assert_eq!(header.flags, 2);
        assert_eq!(header.fragment_offset, 0);
        assert_eq!(header.ttl, 64);
        assert_eq!(header.protocol, 6);
        assert_eq!(header.checksum, 0xB1E6);
        assert_eq!(header.source, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));
        assert_eq!(header.destination, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)));
        assert_eq!(offset, 20);
    }

    #[test]
    fn test_tcp_header_parsing() {
        let mut data = vec![0u8; 64];
        // Set TCP header
        data[0..2].copy_from_slice(&[0x00, 0x50]); // Source port
        data[2..4].copy_from_slice(&[0x01, 0xBB]); // Destination port
        data[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Sequence number
        data[8..12].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Acknowledgment number
        data[12] = 0x50; // Data offset and reserved
        data[13] = 0x18; // Flags
        data[14..16].copy_from_slice(&[0xFF, 0xFF]); // Window size
        data[16..18].copy_from_slice(&[0x00, 0x00]); // Checksum
        data[18..20].copy_from_slice(&[0x00, 0x00]); // Urgent pointer

        let packet = PacketBuffer::new_with_data(&data).unwrap();
        let (header, offset) = HeaderParser::parse_tcp(&packet, 0).unwrap();

        assert_eq!(header.source_port, 80);
        assert_eq!(header.destination_port, 443);
        assert_eq!(header.sequence_number, 1);
        assert_eq!(header.acknowledgment_number, 0);
        assert_eq!(header.data_offset, 20);
        assert_eq!(header.flags.fin, false);
        assert_eq!(header.flags.syn, false);
        assert_eq!(header.flags.rst, false);
        assert_eq!(header.flags.psh, false);
        assert_eq!(header.flags.ack, true);
        assert_eq!(header.flags.urg, false);
        assert_eq!(header.flags.ece, false);
        assert_eq!(header.flags.cwr, false);
        assert_eq!(header.window_size, 65535);
        assert_eq!(header.checksum, 0);
        assert_eq!(header.urgent_pointer, 0);
        assert_eq!(offset, 20);
    }

    #[test]
    fn test_udp_header_parsing() {
        let mut data = vec![0u8; 64];
        // Set UDP header
        data[0..2].copy_from_slice(&[0x00, 0x35]); // Source port
        data[2..4].copy_from_slice(&[0x00, 0x35]); // Destination port
        data[4..6].copy_from_slice(&[0x00, 0x1C]); // Length
        data[6..8].copy_from_slice(&[0x00, 0x00]); // Checksum

        let packet = PacketBuffer::new_with_data(&data).unwrap();
        let (header, offset) = HeaderParser::parse_udp(&packet, 0).unwrap();

        assert_eq!(header.source_port, 53);
        assert_eq!(header.destination_port, 53);
        assert_eq!(header.length, 28);
        assert_eq!(header.checksum, 0);
        assert_eq!(offset, 8);
    }
}
