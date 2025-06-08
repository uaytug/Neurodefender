use std::collections::HashSet;
use std::net::IpAddr;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use log::{info, warn, error};
use crate::utils::error::AppError;

/// Firewall manager for implementing prevention actions
pub struct FirewallManager {
    /// Set of blocked IP addresses
    blocked_ips: Arc<Mutex<HashSet<IpAddr>>>,

    /// Operating system
    os_type: String,

    /// Is the firewall active
    active: bool,

    /// Use native firewall integration
    use_native_firewall: bool,
}

impl FirewallManager {
    /// Create a new firewall manager
    pub fn new(use_native_firewall: bool) -> Self {
        let os_type = std::env::consts::OS.to_string();

        Self {
            blocked_ips: Arc::new(Mutex::new(HashSet::new())),
            os_type,
            active: false,
            use_native_firewall,
        }
    }

    /// Activate the firewall
    pub fn activate(&mut self) -> Result<(), AppError> {
        if self.active {
            return Ok(());
        }

        if self.use_native_firewall {
            match self.os_type.as_str() {
                "linux" => {
                    // Ensure iptables is available
                    let status = Command::new("iptables")
                        .arg("-L")
                        .status()
                        .map_err(|e| AppError::PreventionError(format!("Failed to check iptables: {}", e)))?;

                    if !status.success() {
                        return Err(AppError::PreventionError("iptables is not available".to_string()));
                    }

                    // Create a chain for NeuroDefender
                    Command::new("iptables")
                        .args(["-N", "NEURODEFENDER"])
                        .output()
                        .map_err(|e| AppError::PreventionError(format!("Failed to create iptables chain: {}", e)))?;

                    // Link the chain into the INPUT chain
                    Command::new("iptables")
                        .args(["-I", "INPUT", "-j", "NEURODEFENDER"])
                        .output()
                        .map_err(|e| AppError::PreventionError(format!("Failed to insert iptables rule: {}", e)))?;

                    info!("Firewall activated (Linux/iptables)");
                },
                "macos" => {
                    // Check if pfctl is available
                    let status = Command::new("pfctl")
                        .arg("-sa")
                        .status()
                        .map_err(|e| AppError::PreventionError(format!("Failed to check pfctl: {}", e)))?;

                    if !status.success() {
                        return Err(AppError::PreventionError("pfctl is not available".to_string()));
                    }

                    // Create a temporary pf ruleset file
                    let pf_file = "/tmp/neurodefender.pf";
                    std::fs::write(pf_file, "table <neurodefender_block> persist\nblock in quick from <neurodefender_block> to any\n")
                        .map_err(|e| AppError::PreventionError(format!("Failed to create pf ruleset: {}", e)))?;

                    // Load the ruleset
                    Command::new("pfctl")
                        .args(["-f", pf_file])
                        .output()
                        .map_err(|e| AppError::PreventionError(format!("Failed to load pf ruleset: {}", e)))?;

                    info!("Firewall activated (macOS/pf)");
                },
                "windows" => {
                    // For Windows, we'll use the built-in Windows Firewall via netsh
                    let status = Command::new("netsh")
                        .args(["advfirewall", "show", "currentprofile"])
                        .status()
                        .map_err(|e| AppError::PreventionError(format!("Failed to check Windows Firewall: {}", e)))?;

                    if !status.success() {
                        return Err(AppError::PreventionError("Windows Firewall is not available".to_string()));
                    }

                    // Create a rule group for NeuroDefender
                    Command::new("netsh")
                        .args(["advfirewall", "firewall", "add", "rule",
                            "name=NeuroDefender", "dir=in", "action=block",
                            "enable=yes", "profile=any", "description=NeuroDefender Block Rule"])
                        .output()
                        .map_err(|e| AppError::PreventionError(format!("Failed to create Windows Firewall rule: {}", e)))?;

                    info!("Firewall activated (Windows)");
                },
                os => {
                    warn!("Native firewall integration not supported on {}", os);
                    self.use_native_firewall = false;
                }
            }
        }

        self.active = true;
        Ok(())
    }

    /// Deactivate the firewall
    pub fn deactivate(&mut self) -> Result<(), AppError> {
        if !self.active {
            return Ok(());
        }

        if self.use_native_firewall {
            match self.os_type.as_str() {
                "linux" => {
                    // Remove the chain from INPUT
                    Command::new("iptables")
                        .args(["-D", "INPUT", "-j", "NEURODEFENDER"])
                        .output()
                        .ok();

                    // Flush the chain
                    Command::new("iptables")
                        .args(["-F", "NEURODEFENDER"])
                        .output()
                        .ok();

                    // Delete the chain
                    Command::new("iptables")
                        .args(["-X", "NEURODEFENDER"])
                        .output()
                        .ok();

                    info!("Firewall deactivated (Linux/iptables)");
                },
                "macos" => {
                    // Delete the table
                    Command::new("pfctl")
                        .args(["-t", "neurodefender_block", "-T", "flush"])
                        .output()
                        .ok();

                    info!("Firewall deactivated (macOS/pf)");
                },
                "windows" => {
                    // Remove the firewall rule
                    Command::new("netsh")
                        .args(["advfirewall", "firewall", "delete", "rule", "name=NeuroDefender"])
                        .output()
                        .ok();

                    info!("Firewall deactivated (Windows)");
                },
                _ => {}
            }
        }

        // Clear the blocked IPs
        let mut ips = self.blocked_ips.lock().unwrap();
        ips.clear();

        self.active = false;
        Ok(())
    }

    /// Block an IP address
    pub fn block_ip(&self, ip: IpAddr) -> Result<(), AppError> {
        if !self.active {
            return Err(AppError::PreventionError("Firewall is not active".to_string()));
        }

        // Add to our set first
        {
            let mut ips = self.blocked_ips.lock().unwrap();
            if ips.contains(&ip) {
                // Already blocked
                return Ok(());
            }
            ips.insert(ip);
        }

        // If using native firewall, apply the block
        if self.use_native_firewall {
            match self.os_type.as_str() {
                "linux" => {
                    let output: Output = Command::new("iptables")
                        .args(["-A", "NEURODEFENDER", "-s", &ip.to_string(), "-j", "DROP"])
                        .output()
                        .map_err(|e| AppError::PreventionError(format!("Failed to add iptables rule: {}", e)))?;

                    if !output.status.success() {
                        return Err(AppError::PreventionError(format!(
                            "Failed to block IP {}: {}",
                            ip,
                            String::from_utf8_lossy(&output.stderr)
                        )));
                    }
                },
                "macos" => {
                    let output: Output = Command::new("pfctl")
                        .args(["-t", "neurodefender_block", "-T", "add", &ip.to_string()])
                        .output()
                        .map_err(|e| AppError::PreventionError(format!("Failed to add pf rule: {}", e)))?;

                    if !output.status.success() {
                        return Err(AppError::PreventionError(format!(
                            "Failed to block IP {}: {}",
                            ip,
                            String::from_utf8_lossy(&output.stderr)
                        )));
                    }
                },
                "windows" => {
                    let output: Output = Command::new("netsh")
                        .args(["advfirewall", "firewall", "add", "rule",
                            &format!("name=NeuroDefender-{}", ip),
                            "dir=in", "action=block", "enable=yes",
                            &format!("remoteip={}", ip)])
                        .output()
                        .map_err(|e| AppError::PreventionError(format!("Failed to add Windows Firewall rule: {}", e)))?;

                    if !output.status.success() {
                        return Err(AppError::PreventionError(format!(
                            "Failed to block IP {}: {}",
                            ip,
                            String::from_utf8_lossy(&output.stderr)
                        )));
                    }
                },
                _ => {
                    // Log a warning but don't error
                    warn!("Native firewall integration not supported on {}. IP {} not blocked at OS level.", self.os_type, ip);
                }
            }
        }

        info!("Blocked IP: {}", ip);
        Ok(())
    }

    /// Unblock an IP address
    pub fn unblock_ip(&self, ip: IpAddr) -> Result<(), AppError> {
        if !self.active {
            return Err(AppError::PreventionError("Firewall is not active".to_string()));
        }

        // Remove from our set first
        {
            let mut ips = self.blocked_ips.lock().unwrap();
            if !ips.contains(&ip) {
                // Not blocked
                return Ok(());
            }
            ips.remove(&ip);
        }

        // If using native firewall, remove the block
        if self.use_native_firewall {
            match self.os_type.as_str() {
                "linux" => {
                    let output: Output = Command::new("iptables")
                        .args(["-D", "NEURODEFENDER", "-s", &ip.to_string(), "-j", "DROP"])
                        .output()
                        .map_err(|e| AppError::PreventionError(format!("Failed to remove iptables rule: {}", e)))?;

                    if !output.status.success() {
                        return Err(AppError::PreventionError(format!(
                            "Failed to unblock IP {}: {}",
                            ip,
                            String::from_utf8_lossy(&output.stderr)
                        )));
                    }
                },
                "macos" => {
                    let output: Output = Command::new("pfctl")
                        .args(["-t", "neurodefender_block", "-T", "delete", &ip.to_string()])
                        .output()
                        .map_err(|e| AppError::PreventionError(format!("Failed to remove pf rule: {}", e)))?;

                    if !output.status.success() {
                        return Err(AppError::PreventionError(format!(
                            "Failed to unblock IP {}: {}",
                            ip,
                            String::from_utf8_lossy(&output.stderr)
                        )));
                    }
                },
                "windows" => {
                    let output: Output = Command::new("netsh")
                        .args(["advfirewall", "firewall", "delete", "rule",
                            &format!("name=NeuroDefender-{}", ip)])
                        .output()
                        .map_err(|e| AppError::PreventionError(format!("Failed to remove Windows Firewall rule: {}", e)))?;

                    if !output.status.success() {
                        return Err(AppError::PreventionError(format!(
                            "Failed to unblock IP {}: {}",
                            ip,
                            String::from_utf8_lossy(&output.stderr)
                        )));
                    }
                },
                _ => {
                    // Log a warning but don't error
                    warn!("Native firewall integration not supported on {}. IP {} not unblocked at OS level.", self.os_type, ip);
                }
            }
        }

        info!("Unblocked IP: {}", ip);
        Ok(())
    }

    /// Get a list of blocked IP addresses
    pub fn get_blocked_ips(&self) -> Vec<IpAddr> {
        let ips = self.blocked_ips.lock().unwrap();
        ips.iter().cloned().collect()
    }

    /// Check if an IP address is blocked
    pub fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        let ips = self.blocked_ips.lock().unwrap();
        ips.contains(ip)
    }

    /// Get the active status of the firewall
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Drop for FirewallManager {
    fn drop(&mut self) {
        // Attempt to clean up firewall rules when the manager is dropped
        if self.active {
            if let Err(e) = self.deactivate() {
                error!("Failed to deactivate firewall during cleanup: {}", e);
            }
        }
    }
}