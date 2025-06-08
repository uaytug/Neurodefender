use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use log::{debug, error, info, warn};
use pcap::{Active, Capture, Device};
use sha2::{Digest, Sha256};

use crate::capture::packet::{get_flags, Direction, PacketInfo, Protocol, TcpFlags};
use crate::utils::error::AppError;

/// Traffic statistics for tracking real-time network usage
#[derive(Debug, Clone)]
struct TrafficStats {
    inbound_bytes: u64,
    outbound_bytes: u64,
    internal_bytes: u64,
    protocol_bytes: HashMap<String, u64>,
    start_time: Instant,
    last_update: Instant,
    active_connections: HashMap<(IpAddr, u16, IpAddr, u16), Instant>,
}

impl TrafficStats {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            inbound_bytes: 0,
            outbound_bytes: 0,
            internal_bytes: 0,
            protocol_bytes: HashMap::new(),
            start_time: now,
            last_update: now,
            active_connections: HashMap::new(),
        }
    }

    fn update(&mut self, packet: &PacketInfo) {
        // Update byte counters based on direction
        match packet.direction {
            Direction::Inbound => self.inbound_bytes += packet.size as u64,
            Direction::Outbound => self.outbound_bytes += packet.size as u64,
            Direction::Internal => self.internal_bytes += packet.size as u64,
            Direction::External => {} // Don't count external traffic
        }

        // Update protocol statistics
        let protocol_name = format!("{:?}", packet.protocol);
        *self.protocol_bytes.entry(protocol_name).or_insert(0) += packet.size as u64;

        // Track active connections (TCP/UDP only)
        if let (Some(src_port), Some(dst_port)) = (packet.source_port, packet.destination_port) {
            let conn_key = (packet.source_ip, src_port, packet.destination_ip, dst_port);
            self.active_connections.insert(conn_key, Instant::now());
        }

        // Clean up old connections (older than 60 seconds)
        let now = Instant::now();
        self.active_connections.retain(|_, last_seen| {
            now.duration_since(*last_seen) < Duration::from_secs(60)
        });

        self.last_update = now;
    }

    fn get_bytes_per_second(&self, bytes: u64) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            bytes as f64 / elapsed
        } else {
            0.0
        }
    }
}

/// Historical data point for traffic tracking
#[derive(Debug, Clone)]
struct HistoricalDataPoint {
    timestamp: chrono::DateTime<chrono::Utc>,
    inbound_mbps: f64,
    outbound_mbps: f64,
}

#[derive(Clone)]
pub struct PcapManager {
    interface: String,
    local_ips: Vec<IpAddr>,
    filter: Option<String>,
    snaplen: i32,
    promisc: bool,
    timeout: i32,
    // Real-time traffic statistics
    current_stats: Arc<Mutex<TrafficStats>>,
    // Historical data for the last 24 hours
    historical_data: Arc<Mutex<Vec<HistoricalDataPoint>>>,
    // Interval statistics (reset every second)
    interval_stats: Arc<Mutex<TrafficStats>>,
}

impl PcapManager {
    pub fn new(interface_name: &str) -> Result<Self, AppError> {
        let devices = Device::list().map_err(|e| {
            AppError::CaptureError(format!("Failed to list network devices: {}", e))
        })?;

        let interface = if interface_name == "default" {
            match Device::lookup() {
                Ok(default_device) => {
                    let def_dev = default_device.clone();
                    let name_def_dev = def_dev
                        .ok_or_else(|| AppError::CaptureError("Default device not found".to_string()))?
                        .name;
                    info!("Using default network interface: {}", name_def_dev);
                    name_def_dev
                }
                Err(e) => {
                    warn!("Failed to find default interface: {}", e);
                    if let Some(first_device) = devices.first() {
                        info!("Falling back to first available interface: {}", first_device.name);
                        first_device.name.clone()
                    } else {
                        return Err(AppError::CaptureError(
                            "No network interfaces available".to_string(),
                        ));
                    }
                }
            }
        } else {
            if let Some(device) = devices.iter().find(|d| d.name == interface_name) {
                device.name.clone()
            } else {
                return Err(AppError::CaptureError(format!(
                    "Network interface not found: {}",
                    interface_name
                )));
            }
        };

        let local_ips = Self::get_local_ips(&interface, &devices)?;

        Ok(Self {
            interface,
            local_ips,
            filter: None,
            snaplen: 65535,
            promisc: true,
            timeout: 500,
            current_stats: Arc::new(Mutex::new(TrafficStats::new())),
            historical_data: Arc::new(Mutex::new(Vec::new())),
            interval_stats: Arc::new(Mutex::new(TrafficStats::new())),
        })
    }

    pub fn list_interfaces() -> Result<Vec<Device>, AppError> {
        Device::list().map_err(|e| {
            AppError::CaptureError(format!("Failed to list network devices: {}", e))
        })
    }

    fn get_local_ips(interface_name: &str, devices: &[Device]) -> Result<Vec<IpAddr>, AppError> {
        if let Some(device) = devices.iter().find(|d| d.name == interface_name) {
            let mut ips = Vec::new();
            for addr in &device.addresses {
                // The addr field is already of type IpAddr
                ips.push(addr.addr);
            }
            Ok(ips)
        } else {
            Err(AppError::CaptureError(format!(
                "Network interface not found: {}",
                interface_name
            )))
        }
    }

    pub fn set_filter(&mut self, filter: String) {
        self.filter = Some(filter);
    }

    pub fn start_capture(&self) -> Result<Receiver<PacketInfo>, AppError> {
        let (tx, rx) = mpsc::channel();

        let interface = self.interface.clone();
        let filter = self.filter.clone();
        let local_ips = self.local_ips.clone();
        let snaplen = self.snaplen;
        let promisc = self.promisc;
        let timeout = self.timeout;
        let current_stats = Arc::clone(&self.current_stats);
        let historical_data = Arc::clone(&self.historical_data);
        let interval_stats = Arc::clone(&self.interval_stats);

        thread::spawn(move || {
            if let Err(e) = Self::capture_thread(
                interface, 
                filter, 
                local_ips, 
                snaplen, 
                promisc, 
                timeout, 
                tx,
                current_stats,
                historical_data,
                interval_stats,
            ) {
                error!("Packet capture error: {}", e);
            }
        });

        // Start a thread to collect historical data every minute
        let historical_data_clone = Arc::clone(&self.historical_data);
        let interval_stats_clone = Arc::clone(&self.interval_stats);
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(60));
                
                let stats = interval_stats_clone.lock().unwrap();
                let inbound_bps = stats.get_bytes_per_second(stats.inbound_bytes);
                let outbound_bps = stats.get_bytes_per_second(stats.outbound_bytes);
                
                let data_point = HistoricalDataPoint {
                    timestamp: chrono::Utc::now(),
                    inbound_mbps: (inbound_bps * 8.0) / 1_000_000.0,
                    outbound_mbps: (outbound_bps * 8.0) / 1_000_000.0,
                };
                
                let mut history = historical_data_clone.lock().unwrap();
                history.push(data_point);
                
                // Keep only last 24 hours of data
                let cutoff = chrono::Utc::now() - chrono::Duration::hours(24);
                history.retain(|dp| dp.timestamp > cutoff);
            }
        });

        Ok(rx)
    }

    fn capture_thread(
        interface: String,
        filter: Option<String>,
        local_ips: Vec<IpAddr>,
        snaplen: i32,
        promisc: bool,
        timeout: i32,
        tx: Sender<PacketInfo>,
        current_stats: Arc<Mutex<TrafficStats>>,
        historical_data: Arc<Mutex<Vec<HistoricalDataPoint>>>,
        interval_stats: Arc<Mutex<TrafficStats>>,
    ) -> Result<(), AppError> {
        info!("Starting packet capture on interface: {}", interface);

        let mut cap = Capture::from_device(&*interface)
            .map_err(|e| AppError::CaptureError(format!("Failed to open device: {}", e)))?
            .snaplen(snaplen)
            .promisc(promisc)
            .timeout(timeout)
            .open()
            .map_err(|e| AppError::CaptureError(format!("Failed to open capture: {}", e)))?;

        if let Some(filter_str) = filter {
            debug!("Applying filter: {}", filter_str);
            cap.filter(&filter_str, false)
                .map_err(|e| AppError::CaptureError(format!("Failed to set filter: {}", e)))?;
        }

        Self::capture_loop(cap, local_ips, tx, current_stats, interval_stats)
    }

    fn capture_loop(
        mut cap: Capture<Active>,
        local_ips: Vec<IpAddr>,
        tx: Sender<PacketInfo>,
        current_stats: Arc<Mutex<TrafficStats>>,
        interval_stats: Arc<Mutex<TrafficStats>>,
    ) -> Result<(), AppError> {
        let mut last_interval_reset = Instant::now();
        
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Ok(packet_info) = Self::parse_packet(&packet.data, &local_ips) {
                        // Update statistics
                        {
                            let mut stats = current_stats.lock().unwrap();
                            stats.update(&packet_info);
                        }
                        {
                            let mut stats = interval_stats.lock().unwrap();
                            stats.update(&packet_info);
                        }
                        
                        // Reset interval stats every second
                        if last_interval_reset.elapsed() > Duration::from_secs(1) {
                            let mut stats = interval_stats.lock().unwrap();
                            *stats = TrafficStats::new();
                            last_interval_reset = Instant::now();
                        }
                        
                        if tx.send(packet_info).is_err() {
                            warn!("Failed to send packet information - receiver disconnected");
                            break;
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    error!("Error capturing packet: {}", e);
                    if !matches!(e, pcap::Error::TimeoutExpired) {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    fn parse_packet(packet_data: &[u8], local_ips: &[IpAddr]) -> Result<PacketInfo, anyhow::Error> {
        let sliced_packet = SlicedPacket::from_ethernet(packet_data)
            .context("Failed to parse Ethernet packet")?;

        let (source_ip, dest_ip, protocol_number) = match &sliced_packet.ip {
            Some(InternetSlice::Ipv4(ipv4, ..)) => {
                let source = IpAddr::V4(Ipv4Addr::from(ipv4.source_addr()));
                let dest = IpAddr::V4(Ipv4Addr::from(ipv4.destination_addr()));
                (source, dest, ipv4.protocol())
            }
            Some(InternetSlice::Ipv6(ipv6, ..)) => {
                let source = IpAddr::V6(Ipv6Addr::from(ipv6.source_addr()));
                let dest = IpAddr::V6(Ipv6Addr::from(ipv6.destination_addr()));
                (source, dest, ipv6.next_header())
            }
            None => return Err(anyhow::anyhow!("No IP layer found in packet")),
        };

        let (source_port, dest_port, tcp_flags) = match &sliced_packet.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                let flags = TcpFlags::from_u8(get_flags());
                (Some(tcp.source_port()), Some(tcp.destination_port()), Some(flags))
            }
            Some(TransportSlice::Udp(udp)) => (
                Some(udp.source_port()),
                Some(udp.destination_port()),
                None,
            ),
            _ => (None, None, None),
        };

        let protocol = match protocol_number {
            6 => match (source_port, dest_port) {
                (Some(80), _) | (_, Some(80)) => Protocol::HTTP,
                (Some(443), _) | (_, Some(443)) => Protocol::HTTPS,
                (Some(22), _) | (_, Some(22)) => Protocol::SSH,
                (Some(21), _) | (_, Some(21)) => Protocol::FTP,
                (Some(25), _) | (_, Some(25)) => Protocol::SMTP,
                (Some(110), _) | (_, Some(110)) => Protocol::POP3,
                (Some(143), _) | (_, Some(143)) => Protocol::IMAP,
                _ => Protocol::TCP,
            },
            17 => match (source_port, dest_port) {
                (Some(53), _) | (_, Some(53)) => Protocol::DNS,
                (Some(67), _) | (Some(68), _) | (_, Some(67)) | (_, Some(68)) => Protocol::DHCP,
                _ => Protocol::UDP,
            },
            1 => Protocol::ICMP,
            2 => Protocol::Other(2),
            _ => Protocol::Other(protocol_number),
        };

        let direction = if local_ips.contains(&source_ip) && local_ips.contains(&dest_ip) {
            Direction::Internal
        } else if local_ips.contains(&source_ip) {
            Direction::Outbound
        } else if local_ips.contains(&dest_ip) {
            Direction::Inbound
        } else {
            Direction::External
        };

        let payload_size = sliced_packet.payload.len();
        let payload_hash = Sha256::digest(&sliced_packet.payload) 
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();



        const MAX_STORED_PAYLOAD: usize = 4096;
        let payload_data = sliced_packet.payload.to_vec();
        Ok(PacketInfo {
            timestamp: Utc::now(),
            source_ip,
            destination_ip: dest_ip,
            source_port,
            destination_port: dest_port,
            protocol,
            size: packet_data.len(),
            direction,
            tcp_flags,
            payload_size,
            payload_hash: Some(payload_hash),
            payload: Some(payload_data),
        })
    }

    /// Get inbound bytes per second
    pub fn get_inbound_bytes_per_sec(&self) -> Result<u64, crate::utils::error::AppError> {
        let stats = self.interval_stats.lock().unwrap();
        Ok(stats.get_bytes_per_second(stats.inbound_bytes) as u64)
    }

    /// Get outbound bytes per second
    pub fn get_outbound_bytes_per_sec(&self) -> Result<u64, crate::utils::error::AppError> {
        let stats = self.interval_stats.lock().unwrap();
        Ok(stats.get_bytes_per_second(stats.outbound_bytes) as u64)
    }

    /// Get protocol statistics
    pub fn get_protocol_stats(&self) -> Result<std::collections::HashMap<String, u64>, crate::utils::error::AppError> {
        let stats = self.current_stats.lock().unwrap();
        Ok(stats.protocol_bytes.clone())
    }

    /// Get total inbound bytes
    pub fn get_total_inbound_bytes(&self) -> Result<u64, crate::utils::error::AppError> {
        let stats = self.current_stats.lock().unwrap();
        Ok(stats.inbound_bytes)
    }

    /// Get total outbound bytes
    pub fn get_total_outbound_bytes(&self) -> Result<u64, crate::utils::error::AppError> {
        let stats = self.current_stats.lock().unwrap();
        Ok(stats.outbound_bytes)
    }

    /// Get total internal bytes
    pub fn get_total_internal_bytes(&self) -> Result<u64, crate::utils::error::AppError> {
        let stats = self.current_stats.lock().unwrap();
        Ok(stats.internal_bytes)
    }

    /// Get historical traffic data
    pub fn get_traffic_history(&self, hours: u32) -> Result<Vec<(chrono::DateTime<chrono::Utc>, f64, f64)>, crate::utils::error::AppError> {
        let history = self.historical_data.lock().unwrap();
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(hours as i64);
        
        let result: Vec<(chrono::DateTime<chrono::Utc>, f64, f64)> = history
            .iter()
            .filter(|dp| dp.timestamp > cutoff)
            .map(|dp| (dp.timestamp, dp.inbound_mbps, dp.outbound_mbps))
            .collect();
        
        Ok(result)
    }

    /// Get active connections count
    pub fn get_active_connections(&self) -> Result<u64, crate::utils::error::AppError> {
        let stats = self.current_stats.lock().unwrap();
        Ok(stats.active_connections.len() as u64)
    }
}