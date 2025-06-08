// Updated MonitorService in services/monitor_service.rs
// This shows the changes needed to incorporate prevention

use log::{debug, error, info};
use tokio::sync::mpsc::{self};
use std::sync::Arc;
use std::net::IpAddr;
use std::str::FromStr;


use crate::capture::analyzer::AnalysisSensitivity;
use crate::capture::packet::PacketInfo;
use crate::capture::pcap::PcapManager;
use crate::detection::engine::DetectionEngine;
use crate::prevention::actions::PreventionSettings;
use crate::prevention::blocker::PreventionManager;
use crate::storage::db::Database;
use crate::storage::models::alert::Alert;
use crate::storage::repositories::alert_repo::AlertRepository;
use crate::utils::error::AppError;

/// Service for monitoring network traffic
#[derive(Clone)]
pub struct MonitorService {
    /// Packet capture manager
    pcap_manager: PcapManager,
    /// Detection engine
    detection_engine: DetectionEngine,
    /// Prevention manager
    prevention_manager: Arc<PreventionManager>,
    /// Database connection
    db: Database,
    /// Flag indicating whether the service is running
    running: bool,
    /// The network interface being monitored
    interface: String,
}

impl MonitorService {
    /// Create a new monitor service
    pub fn new(
        pcap_manager: PcapManager,
        detection_engine: DetectionEngine,
        db: Database,
    ) -> Self {
        // Create default prevention settings
        let prevention_settings = PreventionSettings::default();
        let prevention_manager = PreventionManager::new(prevention_settings);

        Self {
            interface: "unknown".to_string(), // Will be set during start
            pcap_manager,
            detection_engine,
            prevention_manager: Arc::new(prevention_manager),
            db,
            running: false,
        }
    }

    /// Start the monitoring service
    pub async fn start(&mut self) -> Result<(), AppError> {
        if self.running {
            return Err(AppError::MonitorError("Monitor already running".to_string()));
        }

        info!("Starting monitor service on interface: {}", self.interface);

        // Start the prevention system if enabled
        {
            let prevention_settings = self.prevention_manager.get_settings();
            if prevention_settings.enabled {
                info!("Starting prevention manager...");
                self.prevention_manager.start().await?;
            }
        }

        // Create alert repository
        let alert_repo = AlertRepository::new(self.db.clone());

        // Create channels for alerts
        let (alert_tx, mut alert_rx) = mpsc::channel::<Alert>(100);

        // Set alert sender in detection engine
        self.detection_engine.set_alert_sender(alert_tx.clone());

        // Start packet capture
        let std_packet_rx = self.pcap_manager.start_capture()?;

        // Convert std channel to tokio channel
        let (tx, packet_rx) = mpsc::channel::<PacketInfo>(100);
        tokio::spawn(async move {
            while let Ok(packet) = std_packet_rx.recv() {
                if tx.send(packet).await.is_err() {
                    break;
                }
            }
        });

        // Start packet processing in detection engine
        self.detection_engine.start_processing(packet_rx)?;

        // Set running flag
        self.running = true;

        // Clone the prevention manager for the async task
        let prevention_manager_clone = Arc::clone(&self.prevention_manager);

        // Process alerts in a separate task
        tokio::spawn(async move {
            while let Some(alert) = alert_rx.recv().await {
                // Save alert to database
                match alert_repo.insert(alert.clone()).await {
                    Ok(saved_alert) => {
                        debug!("Alert saved to database with ID: {:?}", saved_alert.id);

                        // Process the alert for prevention if prevention is enabled
                        match prevention_manager_clone.process_threat(&saved_alert, None).await {
                            Ok(action) => {
                                info!("Prevention action taken: {:?} for alert ID: {:?}", action, saved_alert.id);
                                // TODO: Optionally update alert with action taken
                            }
                            Err(e) => {
                                error!("Failed to process threat for alert {:?}: {}", saved_alert.id, e);
                            }
                        }
                    },
                    Err(e) => error!("Failed to save alert: {}", e),
                }
            }
        });

        info!("Monitoring service started");

        Ok(())
    }

    /// Stop the monitoring service
    pub fn stop(&mut self) {
        if !self.running {
            return;
        }

        // Stop detection engine
        self.detection_engine.stop_processing();

        // Stop prevention manager if it's running
        if self.prevention_manager.is_running() {
            if let Err(e) = self.prevention_manager.stop() {
                error!("Failed to stop prevention manager: {}", e);
            }
        }

        // Set running flag
        self.running = false;

        info!("Monitoring service stopped");
    }

    /// Check if the service is running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get the current network interface
    pub fn get_interface(&self) -> &str {
        &self.interface
    }

    /// Set the detection sensitivity
    pub fn set_sensitivity(&self, sensitivity: AnalysisSensitivity) -> Result<(), AppError> {
        self.detection_engine.set_sensitivity(sensitivity);
        Ok(())
    }

    /// Reload detection rules
    pub fn reload_rules(&self) -> Result<(), AppError> {
        self.detection_engine.reload_rules()
    }

    /// Get the prevention manager
    pub fn get_prevention_manager(&self) -> Arc<PreventionManager> {
        self.prevention_manager.clone()
    }

    /// Get prevention settings
    pub fn get_prevention_settings(&self) -> PreventionSettings {
        self.prevention_manager.get_settings()
    }

    /// Update prevention settings
    pub async fn update_prevention_settings(&self, settings: PreventionSettings) -> Result<(), AppError> {
        self.prevention_manager.update_settings(settings).await
    }

    /// Block an IP address
    pub fn block_ip(&self, ip_str: &str, reason: &str) -> Result<(), AppError> {
        use std::net::IpAddr;
        use std::str::FromStr;
        
        let ip = IpAddr::from_str(ip_str)
            .map_err(|e| AppError::ValidationError(format!("Invalid IP address: {}", e)))?;
        
        self.prevention_manager.block_ip(ip, reason, None, None)
    }

    /// Unblock an IP address
    pub fn unblock_ip(&self, ip_str: &str) -> Result<(), AppError> {
        let ip = IpAddr::from_str(ip_str)
            .map_err(|e| AppError::ValidationError(format!("Invalid IP address: {} - {}", ip_str, e)))?;

        self.prevention_manager.unblock_ip(ip)
    }

    /// Get a list of blocked IPs
    pub fn get_blocked_ips(&self) -> Vec<crate::prevention::blocker::BlockedIP> {
        self.prevention_manager.get_blocked_ips()
    }

    /// Get CPU usage percentage
    pub async fn get_cpu_usage(&self) -> Result<f64, AppError> {
        let sys_info = self.get_system_info().await?;
        Ok(sys_info.cpu_usage)
    }

    /// Get memory usage percentage
    pub async fn get_memory_usage(&self) -> Result<f64, AppError> {
        let sys_info = self.get_system_info().await?;
        Ok(sys_info.memory_usage)
    }

    /// Get disk usage percentage
    pub async fn get_disk_usage(&self) -> Result<f64, AppError> {
        let sys_info = self.get_system_info().await?;
        Ok(sys_info.disk_usage)
    }

    /// Get system uptime in seconds
    pub async fn get_system_uptime(&self) -> Result<u64, AppError> {
        #[cfg(target_os = "linux")]
        {
            let uptime = std::fs::read_to_string("/proc/uptime")
                .map_err(|e| AppError::SystemError(format!("Failed to read uptime: {}", e)))?;
            let uptime_secs = uptime.split_whitespace()
                .next()
                .ok_or_else(|| AppError::SystemError("Invalid uptime format".to_string()))?
                .parse::<f64>()
                .map_err(|e| AppError::SystemError(format!("Failed to parse uptime: {}", e)))?;
            Ok(uptime_secs as u64)
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            
            let output = Command::new("sysctl")
                .args(&["-n", "kern.boottime"])
                .output()
                .map_err(|e| AppError::SystemError(format!("Failed to get boot time: {}", e)))?;
            
            let output_str = String::from_utf8_lossy(&output.stdout);
            // Parse the output which is typically in format: { sec = 1620000000, usec = 0 } ...
            let boot_time_str = output_str
                .split('=')
                .nth(1)
                .ok_or_else(|| AppError::SystemError("Invalid boot time format".to_string()))?
                .trim()
                .split(',')
                .next()
                .ok_or_else(|| AppError::SystemError("Invalid boot time format".to_string()))?
                .trim();
            
            let boot_time = boot_time_str
                .parse::<i64>()
                .map_err(|e| AppError::SystemError(format!("Failed to parse boot time: {}", e)))?;
            
            let now = chrono::Utc::now().timestamp();
            Ok((now - boot_time) as u64)
        }

        #[cfg(target_os = "windows")]
        {
            use std::time::Duration;
            use winapi::um::sysinfoapi::{GetTickCount64};
            
            // Get system uptime in milliseconds
            let uptime_ms = unsafe { GetTickCount64() };
            Ok(uptime_ms / 1000)  // Convert to seconds
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            // Fallback for other platforms
            Ok(0)
        }
    }

    /// Get network interfaces information
    pub async fn get_network_interfaces(&self) -> Result<Vec<serde_json::Value>, AppError> {
        // Instead of using pnet directly, which may not be available,
        // we'll use a simplified approach to get network interfaces
        
        #[cfg(target_os = "linux")]
        {
            // For Linux, try to read from /sys/class/net
            use std::fs;
            let net_dir = "/sys/class/net";
            let mut result = Vec::new();
            
            match fs::read_dir(net_dir) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        // Skip loopback interfaces
                        if name == "lo" {
                            continue;
                        }
                        
                        // Get status
                        let status = match fs::read_to_string(format!("{}/{}/operstate", net_dir, name)) {
                            Ok(state) => {
                                let state = state.trim();
                                if state == "up" { "up" } else { "down" }
                            },
                            Err(_) => "unknown",
                        };
                        
                        // Get interface statistics
                        let stats = self.get_interface_stats(&name).await?;
                        
                        let interface_data = serde_json::json!({
                            "name": name,
                            "tx_bytes": stats.tx_bytes,
                            "rx_bytes": stats.rx_bytes,
                            "tx_packets": stats.tx_packets,
                            "rx_packets": stats.rx_packets,
                            "tx_errors": stats.tx_errors,
                            "rx_errors": stats.rx_errors,
                            "status": status
                        });
                        
                        result.push(interface_data);
                    }
                },
                Err(e) => {
                    return Err(AppError::SystemError(format!("Failed to read network interfaces: {}", e)));
                }
            }
            
            Ok(result)
        }
        
        #[cfg(target_os = "macos")]
        {
            // For macOS, use ifconfig command
            use std::process::Command;
            
            let output = Command::new("ifconfig")
                .output()
                .map_err(|e| AppError::SystemError(format!("Failed to get network interfaces: {}", e)))?;
            
            let output_str = String::from_utf8_lossy(&output.stdout);
            let mut result = Vec::new();
            
            let mut current_interface = String::new();
            let mut is_loopback = false;
            let mut is_up = false;
            
            for line in output_str.lines() {
                if line.contains(": flags=") {
                    // New interface section
                    if !current_interface.is_empty() && !is_loopback {
                        // Add the previous interface to the result
                        let stats = self.get_interface_stats(&current_interface).await?;
                        
                        let interface_data = serde_json::json!({
                            "name": current_interface,
                            "tx_bytes": stats.tx_bytes,
                            "rx_bytes": stats.rx_bytes,
                            "tx_packets": stats.tx_packets,
                            "rx_packets": stats.rx_packets,
                            "tx_errors": stats.tx_errors,
                            "rx_errors": stats.rx_errors,
                            "status": if is_up { "up" } else { "down" }
                        });
                        
                        result.push(interface_data);
                    }
                    
                    // Parse the new interface name
                    let parts: Vec<&str> = line.split(": ").collect();
                    current_interface = parts[0].trim().to_string();
                    
                    // Check if it's a loopback interface
                    is_loopback = line.contains("LOOPBACK");
                    is_up = line.contains("UP");
                }
            }
            
            // Add the last interface if it wasn't a loopback
            if !current_interface.is_empty() && !is_loopback {
                let stats = self.get_interface_stats(&current_interface).await?;
                
                let interface_data = serde_json::json!({
                    "name": current_interface,
                    "tx_bytes": stats.tx_bytes,
                    "rx_bytes": stats.rx_bytes,
                    "tx_packets": stats.tx_packets,
                    "rx_packets": stats.rx_packets,
                    "tx_errors": stats.tx_errors,
                    "rx_errors": stats.rx_errors,
                    "status": if is_up { "up" } else { "down" }
                });
                
                result.push(interface_data);
            }
            
            Ok(result)
        }
        
        #[cfg(target_os = "windows")]
        {
            // For Windows, use a simplified approach
            let mut rng = rand::thread_rng();
            let interface_names = ["Ethernet", "Wi-Fi", "Ethernet 2"];
            let mut result = Vec::new();
            
            for name in interface_names {
                // Generate some random stats for demonstration
                let tx_bytes = rng.gen_range(100_000..2_000_000_000);
                let rx_bytes = rng.gen_range(100_000..4_000_000_000);
                
                let interface_data = serde_json::json!({
                    "name": name,
                    "tx_bytes": tx_bytes,
                    "rx_bytes": rx_bytes,
                    "tx_packets": tx_bytes / 1500,
                    "rx_packets": rx_bytes / 1500,
                    "tx_errors": 0,
                    "rx_errors": rng.gen_range(0..10),
                    "status": "up"
                });
                
                result.push(interface_data);
            }
            
            Ok(result)
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            // For other platforms, return a default interface
            let mut result = Vec::new();
            let interface_data = serde_json::json!({
                "name": "eth0",
                "tx_bytes": 1250000000,
                "rx_bytes": 3450000,
                "tx_packets": 1450000,
                "rx_packets": 2350000,
                "tx_errors": 0,
                "rx_errors": 2,
                "status": "up"
            });
            
            result.push(interface_data);
            Ok(result)
        }
    }

    /// Get interface statistics for a specific network interface
    async fn get_interface_stats(&self, interface_name: &str) -> Result<InterfaceStats, AppError> {
        #[cfg(target_os = "linux")]
        {
            let path = format!("/sys/class/net/{}/statistics", interface_name);
            let tx_bytes = std::fs::read_to_string(format!("{}/tx_bytes", path))
                .map_err(|_| AppError::SystemError(format!("Failed to read tx_bytes for {}", interface_name)))?
                .trim()
                .parse::<u64>()
                .map_err(|_| AppError::SystemError(format!("Failed to parse tx_bytes for {}", interface_name)))?;

            let rx_bytes = std::fs::read_to_string(format!("{}/rx_bytes", path))
                .map_err(|_| AppError::SystemError(format!("Failed to read rx_bytes for {}", interface_name)))?
                .trim()
                .parse::<u64>()
                .map_err(|_| AppError::SystemError(format!("Failed to parse rx_bytes for {}", interface_name)))?;

            let tx_packets = std::fs::read_to_string(format!("{}/tx_packets", path))
                .map_err(|_| AppError::SystemError(format!("Failed to read tx_packets for {}", interface_name)))?
                .trim()
                .parse::<u64>()
                .map_err(|_| AppError::SystemError(format!("Failed to parse tx_packets for {}", interface_name)))?;

            let rx_packets = std::fs::read_to_string(format!("{}/rx_packets", path))
                .map_err(|_| AppError::SystemError(format!("Failed to read rx_packets for {}", interface_name)))?
                .trim()
                .parse::<u64>()
                .map_err(|_| AppError::SystemError(format!("Failed to parse rx_packets for {}", interface_name)))?;

            let tx_errors = std::fs::read_to_string(format!("{}/tx_errors", path))
                .map_err(|_| AppError::SystemError(format!("Failed to read tx_errors for {}", interface_name)))?
                .trim()
                .parse::<u64>()
                .map_err(|_| AppError::SystemError(format!("Failed to parse tx_errors for {}", interface_name)))?;

            let rx_errors = std::fs::read_to_string(format!("{}/rx_errors", path))
                .map_err(|_| AppError::SystemError(format!("Failed to read rx_errors for {}", interface_name)))?
                .trim()
                .parse::<u64>()
                .map_err(|_| AppError::SystemError(format!("Failed to parse rx_errors for {}", interface_name)))?;

            Ok(InterfaceStats {
                tx_bytes,
                rx_bytes,
                tx_packets,
                rx_packets,
                tx_errors,
                rx_errors,
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            // For non-Linux platforms, we'll use the data from the packet capture if available
            // Otherwise, provide reasonable default values
            if self.running && interface_name == self.interface {
                // TODO: Get actual stats from the pcap_manager or detection_engine
                // For now, use placeholder values
                Ok(InterfaceStats {
                    tx_bytes: 1250000000,
                    rx_bytes: 3450000,
                    tx_packets: 1450000,
                    rx_packets: 2350000,
                    tx_errors: 0,
                    rx_errors: 2,
                })
            } else {
                // Return default values for interfaces that aren't being monitored
                Ok(InterfaceStats::default())
            }
        }
    }

    /// Get monitoring status information
    pub async fn get_monitoring_status(&self) -> Result<serde_json::Value, AppError> {
        let status = serde_json::json!({
            "is_running": self.running,
            "started_at": chrono::Utc::now().to_rfc3339(), // TODO: Store actual start time
            "packets_processed": self.detection_engine.get_packets_processed(),
            "alerts_generated": self.detection_engine.get_alerts_generated()
        });

        Ok(status)
    }

    /// Get system information including CPU, memory, and disk usage
    async fn get_system_info(&self) -> Result<SystemInfo, AppError> {
        #[cfg(target_os = "linux")]
        {
            // Read CPU usage from /proc/stat
            let cpu_usage = self.get_linux_cpu_usage()?;
            
            // Read memory usage from /proc/meminfo
            let memory_usage = self.get_linux_memory_usage()?;
            
            // Read disk usage for root partition
            let disk_usage = self.get_linux_disk_usage("/")?;
            
            Ok(SystemInfo {
                cpu_usage,
                memory_usage,
                disk_usage,
            })
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            
            // Get CPU usage using top command
            let cpu_output = Command::new("top")
                .args(&["-l", "1", "-n", "0"])
                .output()
                .map_err(|e| AppError::SystemError(format!("Failed to get CPU usage: {}", e)))?;
            
            let cpu_output_str = String::from_utf8_lossy(&cpu_output.stdout);
            let cpu_usage = cpu_output_str
                .lines()
                .find(|line| line.contains("CPU usage"))
                .map(|line| {
                    line.split(':')
                        .nth(1)
                        .unwrap_or("")
                        .trim()
                        .split(' ')
                        .next()
                        .unwrap_or("0.0")
                        .trim_end_matches('%')
                        .parse::<f64>()
                        .unwrap_or(0.0)
                })
                .unwrap_or(0.0);
            
            // Get memory usage using vm_stat command
            let mem_output = Command::new("vm_stat")
                .output()
                .map_err(|e| AppError::SystemError(format!("Failed to get memory usage: {}", e)))?;
            
            let mem_output_str = String::from_utf8_lossy(&mem_output.stdout);
            let _page_size = 4096; // Default page size for macOS
            
            let mut pages_free = 0;
            let mut pages_active = 0;
            let mut pages_inactive = 0;
            let mut pages_speculative = 0;
            let mut pages_wired = 0;
            
            for line in mem_output_str.lines() {
                if line.contains("Pages free") {
                    pages_free = line.split(':').nth(1).unwrap_or("0").trim().trim_end_matches('.').parse::<u64>().unwrap_or(0);
                } else if line.contains("Pages active") {
                    pages_active = line.split(':').nth(1).unwrap_or("0").trim().trim_end_matches('.').parse::<u64>().unwrap_or(0);
                } else if line.contains("Pages inactive") {
                    pages_inactive = line.split(':').nth(1).unwrap_or("0").trim().trim_end_matches('.').parse::<u64>().unwrap_or(0);
                } else if line.contains("Pages speculative") {
                    pages_speculative = line.split(':').nth(1).unwrap_or("0").trim().trim_end_matches('.').parse::<u64>().unwrap_or(0);
                } else if line.contains("Pages wired down") {
                    pages_wired = line.split(':').nth(1).unwrap_or("0").trim().trim_end_matches('.').parse::<u64>().unwrap_or(0);
                }
            }
            
            let total_pages = pages_free + pages_active + pages_inactive + pages_speculative + pages_wired;
            let used_pages = total_pages - pages_free - pages_speculative;
            let memory_usage = (used_pages as f64 / total_pages as f64) * 100.0;
            
            // Get disk usage using df command
            let disk_output = Command::new("df")
                .args(&["-h", "/"])
                .output()
                .map_err(|e| AppError::SystemError(format!("Failed to get disk usage: {}", e)))?;
            
            let disk_output_str = String::from_utf8_lossy(&disk_output.stdout);
            let disk_usage = disk_output_str
                .lines()
                .nth(1)
                .map(|line| {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() >= 5 {
                        fields[4].trim_end_matches('%').parse::<f64>().unwrap_or(0.0)
                    } else {
                        0.0
                    }
                })
                .unwrap_or(0.0);
            
            Ok(SystemInfo {
                cpu_usage,
                memory_usage,
                disk_usage,
            })
        }

        #[cfg(target_os = "windows")]
        {
            use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
            use winapi::um::psapi::{GetPerformanceInfo, PERFORMANCE_INFORMATION};
            use std::mem::zeroed;
            
            // Get system information
            let mut sys_info: SYSTEM_INFO = unsafe { zeroed() };
            unsafe { GetSystemInfo(&mut sys_info) };
            
            // Get performance information
            let mut perf_info: PERFORMANCE_INFORMATION = unsafe { zeroed() };
            let perf_info_size = std::mem::size_of::<PERFORMANCE_INFORMATION>() as u32;
            unsafe { GetPerformanceInfo(&mut perf_info, perf_info_size) };
            
            // Calculate CPU usage (simplified approach)
            let cpu_usage = 50.0; // This would need a more sophisticated approach to calculate accurately
            
            // Calculate memory usage
            let total_memory = perf_info.PhysicalTotal as f64;
            let available_memory = perf_info.PhysicalAvailable as f64;
            let memory_usage = ((total_memory - available_memory) / total_memory) * 100.0;
            
            // Get disk usage (simplified approach)
            let disk_usage = 60.0; // This would need to be calculated using GetDiskFreeSpaceEx
            
            Ok(SystemInfo {
                cpu_usage,
                memory_usage,
                disk_usage,
            })
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            // Fallback for other platforms
            Ok(SystemInfo {
                cpu_usage: 50.0,
                memory_usage: 50.0,
                disk_usage: 50.0,
            })
        }
    }

    #[cfg(target_os = "linux")]
    fn get_linux_cpu_usage(&self) -> Result<f64, AppError> {
        let stat1 = std::fs::read_to_string("/proc/stat")
            .map_err(|e| AppError::SystemError(format!("Failed to read CPU usage: {}", e)))?;
        let cpu1 = stat1.lines().next().unwrap_or("");
        let cpu1_values: Vec<u64> = cpu1.split_whitespace()
            .skip(1) // Skip "cpu" prefix
            .map(|val| val.parse::<u64>().unwrap_or(0))
            .collect();
        
        // Sleep for a short time
        std::thread::sleep(std::time::Duration::from_millis(100));
        
        let stat2 = std::fs::read_to_string("/proc/stat")
            .map_err(|e| AppError::SystemError(format!("Failed to read CPU usage: {}", e)))?;
        let cpu2 = stat2.lines().next().unwrap_or("");
        let cpu2_values: Vec<u64> = cpu2.split_whitespace()
            .skip(1) // Skip "cpu" prefix
            .map(|val| val.parse::<u64>().unwrap_or(0))
            .collect();
        
        if cpu1_values.len() < 4 || cpu2_values.len() < 4 {
            return Err(AppError::SystemError("Invalid CPU usage data".to_string()));
        }
        
        // Calculate the total CPU time
        let total1: u64 = cpu1_values.iter().sum();
        let total2: u64 = cpu2_values.iter().sum();
        
        // Calculate the idle time
        let idle1 = cpu1_values[3];
        let idle2 = cpu2_values[3];
        
        // Calculate the CPU usage
        let totald = total2 - total1;
        let idled = idle2 - idle1;
        
        if totald == 0 {
            return Ok(0.0);
        }
        
        let cpu_usage = ((totald - idled) as f64 / totald as f64) * 100.0;
        Ok(cpu_usage)
    }

    #[cfg(target_os = "linux")]
    fn get_linux_memory_usage(&self) -> Result<f64, AppError> {
        let meminfo = std::fs::read_to_string("/proc/meminfo")
            .map_err(|e| AppError::SystemError(format!("Failed to read memory usage: {}", e)))?;
        
        let mut total_mem = 0;
        let mut available_mem = 0;
        
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                total_mem = line.split_whitespace()
                    .nth(1)
                    .unwrap_or("0")
                    .parse::<u64>()
                    .unwrap_or(0);
            } else if line.starts_with("MemAvailable:") {
                available_mem = line.split_whitespace()
                    .nth(1)
                    .unwrap_or("0")
                    .parse::<u64>()
                    .unwrap_or(0);
            }
        }
        
        if total_mem == 0 {
            return Err(AppError::SystemError("Failed to get total memory".to_string()));
        }
        
        let memory_usage = ((total_mem - available_mem) as f64 / total_mem as f64) * 100.0;
        Ok(memory_usage)
    }

    #[cfg(target_os = "linux")]
    fn get_linux_disk_usage(&self, mount_point: &str) -> Result<f64, AppError> {
        use std::process::Command;
        
        let output = Command::new("df")
            .args(&["-h", mount_point])
            .output()
            .map_err(|e| AppError::SystemError(format!("Failed to get disk usage: {}", e)))?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let disk_usage = output_str
            .lines()
            .nth(1)
            .map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 5 {
                    fields[4].trim_end_matches('%').parse::<f64>().unwrap_or(0.0)
                } else {
                    0.0
                }
            })
            .unwrap_or(0.0);
        
        Ok(disk_usage)
    }

    /// Get current traffic metrics
    pub async fn get_current_traffic_metrics(&self) -> Result<TrafficMetrics, AppError> {
        Ok(TrafficMetrics {
            inbound_mbps: self.get_current_inbound_traffic().await?,
            outbound_mbps: self.get_current_outbound_traffic().await?,
        })
    }

    /// Get current inbound traffic in Mbps
    pub async fn get_current_inbound_traffic(&self) -> Result<f64, AppError> {
        // Get traffic data from the packet capture manager
        if self.running {
            // In a real implementation, this would get the actual traffic rate
            // For now, simulate a realistic value
            let inbound_bytes_per_sec = self.pcap_manager.get_inbound_bytes_per_sec()?;
            Ok((inbound_bytes_per_sec as f64 * 8.0) / 1_000_000.0) // Convert bytes to Mbps
        } else {
            Ok(0.0)
        }
    }

    /// Get current outbound traffic in Mbps
    pub async fn get_current_outbound_traffic(&self) -> Result<f64, AppError> {
        // Get traffic data from the packet capture manager
        if self.running {
            // In a real implementation, this would get the actual traffic rate
            // For now, simulate a realistic value
            let outbound_bytes_per_sec = self.pcap_manager.get_outbound_bytes_per_sec()?;
            Ok((outbound_bytes_per_sec as f64 * 8.0) / 1_000_000.0) // Convert bytes to Mbps
        } else {
            Ok(0.0)
        }
    }

    /// Get traffic breakdown by protocol
    pub async fn get_traffic_by_protocol(&self) -> Result<Vec<serde_json::Value>, AppError> {
        let protocol_stats = self.pcap_manager.get_protocol_stats()?;
        
        let mut result = Vec::new();
        for (protocol, bytes) in protocol_stats {
            result.push(serde_json::json!({
                "protocol": protocol,
                "bytes": bytes
            }));
        }
        
        Ok(result)
    }

    /// Get traffic breakdown by protocol as a map
    pub async fn get_traffic_by_protocol_map(&self) -> Result<std::collections::HashMap<String, u64>, AppError> {
        let protocol_stats = self.pcap_manager.get_protocol_stats()?;
        Ok(protocol_stats)
    }

    /// Get traffic breakdown by direction
    pub async fn get_traffic_by_direction(&self) -> Result<Vec<serde_json::Value>, AppError> {
        let inbound = self.pcap_manager.get_total_inbound_bytes()?;
        let outbound = self.pcap_manager.get_total_outbound_bytes()?;
        let internal = self.pcap_manager.get_total_internal_bytes()?;
        
        let result = vec![
            serde_json::json!({
                "direction": "Inbound",
                "bytes": inbound
            }),
            serde_json::json!({
                "direction": "Outbound",
                "bytes": outbound
            }),
            serde_json::json!({
                "direction": "Internal",
                "bytes": internal
            })
        ];
        
        Ok(result)
    }

    /// Get historical traffic data
    pub async fn get_traffic_history(&self, hours: u32) -> Result<Vec<serde_json::Value>, AppError> {
        let history = self.pcap_manager.get_traffic_history(hours)?;
        
        let mut result = Vec::new();
        for (timestamp, inbound, outbound) in history {
            result.push(serde_json::json!({
                "timestamp": timestamp.to_rfc3339(),
                "inbound": inbound,
                "outbound": outbound
            }));
        }
        
        Ok(result)
    }

    /// Get active connections count
    pub async fn get_active_connections(&self) -> Result<u64, AppError> {
        if self.running {
            Ok(self.pcap_manager.get_active_connections()?)
        } else {
            Ok(0)
        }
    }

    /// Get count of blocked connections today
    pub async fn get_blocked_connections_today(&self) -> Result<u64, AppError> {
        if self.running {
            // Get the metrics from prevention manager
            let blocked_ips = self.prevention_manager.get_blocked_ips();
            let today = chrono::Utc::now().date_naive();
            
            // Count IPs blocked today
            let blocked_today = blocked_ips.iter()
                .filter(|ip| ip.blocked_at.date_naive() == today)
                .count() as u64;
                
            Ok(blocked_today)
        } else {
            Ok(0)
        }
    }

    /// Get the last scan time
    pub async fn get_last_scan_time(&self) -> Result<chrono::DateTime<chrono::Utc>, AppError> {
        // In a real implementation, this would get the actual last scan time
        // For now, return current time
        Ok(chrono::Utc::now())
    }
}

/// Traffic metrics
#[derive(Debug, Clone)]
pub struct TrafficMetrics {
    /// Inbound traffic in Mbps
    pub inbound_mbps: f64,
    /// Outbound traffic in Mbps
    pub outbound_mbps: f64,
}

/// Network interface statistics
#[derive(Debug, Clone)]
pub struct InterfaceStats {
    /// Total transmitted bytes
    pub tx_bytes: u64,
    /// Total received bytes
    pub rx_bytes: u64,
    /// Total transmitted packets
    pub tx_packets: u64,
    /// Total received packets
    pub rx_packets: u64,
    /// Transmission errors
    pub tx_errors: u64,
    /// Reception errors
    pub rx_errors: u64,
}

impl Default for InterfaceStats {
    fn default() -> Self {
        Self {
            tx_bytes: 0,
            rx_bytes: 0,
            tx_packets: 0,
            rx_packets: 0,
            tx_errors: 0,
            rx_errors: 0,
        }
    }
}

/// System information
#[derive(Debug, Clone)]
pub struct SystemInfo {
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage percentage
    pub memory_usage: f64,
    /// Disk usage percentage
    pub disk_usage: f64,
}