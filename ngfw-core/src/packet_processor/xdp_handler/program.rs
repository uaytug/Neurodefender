use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    programs::XdpContext,
    maps::PerfEventArray,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::packet_processor::xdp_handler::{
    maps::{FlowKey, FlowStats, XdpMaps},
    helpers::PacketParser,
};

// Performance monitoring events
#[map(name = "PERF_EVENTS")]
static mut PERF_EVENTS: PerfEventArray = PerfEventArray::with_max_entries(1024, 0);

// Main XDP program entry point
#[xdp(name = "neurodefender_xdp")]
pub fn neurodefender_xdp(ctx: XdpContext) -> u32 {
    match try_neurodefender_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_neurodefender_xdp(ctx: XdpContext) -> Result<u32, u32> {
    // Initialize packet parser
    let parser = PacketParser::new(&ctx)?;
    
    // Parse Ethernet header
    let eth = parser.parse_eth_header()?;
    match eth.ether_type {
        EtherType::Ipv4 => process_ipv4(ctx, parser)?,
        EtherType::Ipv6 => {
            // Log IPv6 packets for monitoring
            info!(&ctx, "IPv6 packet received, passing through");
            return Ok(xdp_action::XDP_PASS);
        }
        _ => {
            // Non-IP packets are passed through
            return Ok(xdp_action::XDP_PASS);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

fn process_ipv4(ctx: XdpContext, parser: PacketParser) -> Result<u32, u32> {
    // Parse IPv4 header
    let ip_hdr = parser.parse_ipv4_header()?;
    
    // Check if source IP is blacklisted
    let maps = XdpMaps::new().map_err(|_| 1u32)?;
    if maps.is_blacklisted(u32::from_be(ip_hdr.src_addr)) {
        return Ok(xdp_action::XDP_DROP);
    }

    // Process based on protocol
    match ip_hdr.proto {
        IpProto::Tcp => process_tcp(ctx, parser, ip_hdr)?,
        IpProto::Udp => process_udp(ctx, parser, ip_hdr)?,
        _ => {
            // Other IP protocols are passed through
            return Ok(xdp_action::XDP_PASS);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

fn process_tcp(ctx: XdpContext, parser: PacketParser, ip_hdr: &Ipv4Hdr) -> Result<u32, u32> {
    // Parse TCP header
    let tcp_hdr = parser.parse_tcp_header()?;
    
    // Create flow key for tracking
    let flow_key = FlowKey {
        src_ip: u32::from_be(ip_hdr.src_addr),
        dst_ip: u32::from_be(ip_hdr.dst_addr),
        src_port: u16::from_be(tcp_hdr.source),
        dst_port: u16::from_be(tcp_hdr.dest),
        protocol: IpProto::Tcp as u8,
    };

    // Update flow statistics
    let mut maps = XdpMaps::new().map_err(|_| 1u32)?;
    update_flow_stats(&mut maps, &ctx, &flow_key, ip_hdr.len as u64)?;

    // Apply security checks
    if should_block_tcp_traffic(&tcp_hdr, &flow_key) {
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

fn process_udp(ctx: XdpContext, parser: PacketParser, ip_hdr: &Ipv4Hdr) -> Result<u32, u32> {
    // Parse UDP header
    let udp_hdr = parser.parse_udp_header()?;
    
    // Create flow key for tracking
    let flow_key = FlowKey {
        src_ip: u32::from_be(ip_hdr.src_addr),
        dst_ip: u32::from_be(ip_hdr.dst_addr),
        src_port: u16::from_be(udp_hdr.source),
        dst_port: u16::from_be(udp_hdr.dest),
        protocol: IpProto::Udp as u8,
    };

    // Update flow statistics
    let mut maps = XdpMaps::new().map_err(|_| 1u32)?;
    update_flow_stats(&mut maps, &ctx, &flow_key, ip_hdr.len as u64)?;

    // Apply security checks
    if should_block_udp_traffic(&udp_hdr, &flow_key) {
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

fn update_flow_stats(maps: &mut XdpMaps, ctx: &XdpContext, key: &FlowKey, bytes: u64) -> Result<(), u32> {
    let mut stats = maps.get_flow(key).unwrap_or(FlowStats {
        packets: 0,
        bytes: 0,
        start_time: bpf_ktime_get_ns() as u64,
        last_seen: 0,
        flags: 0,
    });

    stats.packets += 1;
    stats.bytes += bytes;
    stats.last_seen = bpf_ktime_get_ns() as u64;

    maps.update_flow(ctx, key, &stats).map_err(|_| 1u32)
}

fn should_block_tcp_traffic(tcp_hdr: &TcpHdr, flow_key: &FlowKey) -> bool {
    // Implement TCP-specific security checks
    // For example, SYN flood protection, port scan detection
    false
}

fn should_block_udp_traffic(udp_hdr: &UdpHdr, flow_key: &FlowKey) -> bool {
    // Implement UDP-specific security checks
    // For example, amplification attack protection
    false
}

#[inline(always)]
fn bpf_ktime_get_ns() -> u64 {
    unsafe { core::arch::asm!("" : "={r0}"(0u64) : : : "volatile") }
}