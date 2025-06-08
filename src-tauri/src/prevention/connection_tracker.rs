use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use log::{info, warn, debug};
use tokio::time;

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    New,
    Established,
    Closing,
    Closed,
    Suspicious,
    Blocked,
}

/// Network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Other(u8),
}

/// Connection metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: u64,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub protocol: Protocol,
    pub state: ConnectionState,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub flags: HashSet<String>,
}

impl Connection {
    /// Create a new connection
    pub fn new(id: u64, source: SocketAddr, destination: SocketAddr, protocol: Protocol) -> Self {
        let now = Utc::now();
        Self {
            id,
            source,
            destination,
            protocol,
            state: ConnectionState::New,
            created_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            flags: HashSet::new(),
        }
    }

    /// Update activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Get connection duration
    pub fn duration(&self) -> Duration {
        let elapsed = Utc::now().signed_duration_since(self.created_at);
        elapsed.to_std().unwrap_or(Duration::from_secs(0))
    }

    /// Check if connection is idle
    pub fn is_idle(&self, timeout: Duration) -> bool {
        let elapsed = Utc::now().signed_duration_since(self.last_activity);
        elapsed.to_std().unwrap_or(Duration::from_secs(0)) > timeout
    }
}

/// Connection tracking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionTrackerConfig {
    /// Maximum connections to track
    pub max_connections: usize,
    
    /// Connection idle timeout
    pub idle_timeout: Duration,
    
    /// Maximum connections per IP
    pub max_per_ip: u32,
    
    /// Enable connection state tracking
    pub track_state: bool,
    
    /// Enable traffic statistics
    pub track_stats: bool,
    
    /// Connection cleanup interval
    pub cleanup_interval: Duration,
}

impl Default for ConnectionTrackerConfig {
    fn default() -> Self {
        Self {
            max_connections: 100000,
            idle_timeout: Duration::from_secs(300), // 5 minutes
            max_per_ip: 100,
            track_state: true,
            track_stats: true,
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

/// Connection tracker
pub struct ConnectionTracker {
    /// Configuration
    config: RwLock<ConnectionTrackerConfig>,
    
    /// Active connections
    connections: Arc<Mutex<HashMap<u64, Connection>>>,
    
    /// Connection index by source IP
    connections_by_ip: Arc<Mutex<HashMap<IpAddr, HashSet<u64>>>>,
    
    /// Connection ID counter
    next_id: Arc<Mutex<u64>>,
    
    /// Is tracking active
    active: Arc<RwLock<bool>>,
    
    /// Connection statistics
    stats: Arc<RwLock<ConnectionStats>>,
}

/// Connection statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionStats {
    pub total_connections: u64,
    pub active_connections: u64,
    pub blocked_connections: u64,
    pub terminated_connections: u64,
    pub bytes_total: u64,
    pub packets_total: u64,
}

impl ConnectionTracker {
    /// Create a new connection tracker
    pub fn new(config: ConnectionTrackerConfig) -> Self {
        Self {
            config: RwLock::new(config),
            connections: Arc::new(Mutex::new(HashMap::new())),
            connections_by_ip: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
            active: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(ConnectionStats::default())),
        }
    }

    /// Start the connection tracker
    pub fn start(&self) -> Result<(), String> {
        {
            let mut active = self.active.write().unwrap();
            if *active {
                return Ok(());
            }
            *active = true;
        }

        // Start cleanup task
        let connections = Arc::clone(&self.connections);
        let connections_by_ip = Arc::clone(&self.connections_by_ip);
        let config = self.config.read().unwrap().clone();
        let active = Arc::clone(&self.active);

        tokio::spawn(async move {
            let mut interval = time::interval(config.cleanup_interval);

            while *active.read().unwrap() {
                interval.tick().await;

                // Clean up idle connections
                let mut to_remove = Vec::new();
                {
                    let conns = connections.lock().unwrap();
                    for (id, conn) in conns.iter() {
                        if conn.is_idle(config.idle_timeout) {
                            to_remove.push(*id);
                        }
                    }
                }

                if !to_remove.is_empty() {
                    let mut conns = connections.lock().unwrap();
                    let mut by_ip = connections_by_ip.lock().unwrap();

                    for id in to_remove {
                        if let Some(conn) = conns.remove(&id) {
                            // Remove from IP index
                            if let Some(ip_conns) = by_ip.get_mut(&conn.source.ip()) {
                                ip_conns.remove(&id);
                                if ip_conns.is_empty() {
                                    by_ip.remove(&conn.source.ip());
                                }
                            }
                            debug!("Removed idle connection {}", id);
                        }
                    }
                }
            }
        });

        info!("Connection tracker started");
        Ok(())
    }

    /// Stop the connection tracker
    pub fn stop(&self) {
        let mut active = self.active.write().unwrap();
        *active = false;
        info!("Connection tracker stopped");
    }

    /// Track a new connection
    pub fn track_connection(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        protocol: Protocol,
    ) -> Result<u64, String> {
        if !*self.active.read().unwrap() {
            return Err("Connection tracker is not active".to_string());
        }

        // Check connection limits
        {
            let config = self.config.read().unwrap();
            let conns = self.connections.lock().unwrap();
            
            if conns.len() >= config.max_connections {
                return Err("Maximum connection limit reached".to_string());
            }
        }

        // Check per-IP limit
        {
            let config = self.config.read().unwrap();
            let by_ip = self.connections_by_ip.lock().unwrap();
            
            if let Some(ip_conns) = by_ip.get(&source.ip()) {
                if ip_conns.len() >= config.max_per_ip as usize {
                    return Err(format!("Maximum connections per IP reached for {}", source.ip()));
                }
            }
        }

        // Create new connection
        let conn_id = {
            let mut next_id = self.next_id.lock().unwrap();
            let id = *next_id;
            *next_id += 1;
            id
        };

        let connection = Connection::new(conn_id, source, destination, protocol);

        // Add to tracking
        {
            let mut connections = self.connections.lock().unwrap();
            connections.insert(conn_id, connection);
        }

        // Update IP index
        {
            let mut by_ip = self.connections_by_ip.lock().unwrap();
            by_ip.entry(source.ip())
                .or_insert_with(HashSet::new)
                .insert(conn_id);
        }

        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.total_connections += 1;
            stats.active_connections += 1;
        }

        debug!("Tracking new connection {} from {} to {}", conn_id, source, destination);
        Ok(conn_id)
    }

    /// Update connection state
    pub fn update_connection_state(&self, conn_id: u64, new_state: ConnectionState) -> Result<(), String> {
        let mut connections = self.connections.lock().unwrap();
        
        if let Some(conn) = connections.get_mut(&conn_id) {
            conn.state = new_state;
            conn.update_activity();
            
            if new_state == ConnectionState::Closed {
                // Update stats
                let mut stats = self.stats.write().unwrap();
                stats.active_connections = stats.active_connections.saturating_sub(1);
            }
            
            Ok(())
        } else {
            Err(format!("Connection {} not found", conn_id))
        }
    }

    /// Update connection traffic statistics
    pub fn update_connection_traffic(
        &self,
        conn_id: u64,
        bytes: u64,
        packets: u64,
        is_outbound: bool,
    ) -> Result<(), String> {
        let mut connections = self.connections.lock().unwrap();
        
        if let Some(conn) = connections.get_mut(&conn_id) {
            if is_outbound {
                conn.bytes_sent += bytes;
                conn.packets_sent += packets;
            } else {
                conn.bytes_received += bytes;
                conn.packets_received += packets;
            }
            conn.update_activity();
            
            // Update global stats
            {
                let mut stats = self.stats.write().unwrap();
                stats.bytes_total += bytes;
                stats.packets_total += packets;
            }
            
            Ok(())
        } else {
            Err(format!("Connection {} not found", conn_id))
        }
    }

    /// Get connection by ID
    pub fn get_connection(&self, conn_id: u64) -> Option<Connection> {
        let connections = self.connections.lock().unwrap();
        connections.get(&conn_id).cloned()
    }

    /// Get connections by IP
    pub fn get_connections_by_ip(&self, ip: &IpAddr) -> Vec<Connection> {
        let by_ip = self.connections_by_ip.lock().unwrap();
        let connections = self.connections.lock().unwrap();
        
        if let Some(conn_ids) = by_ip.get(ip) {
            conn_ids.iter()
                .filter_map(|id| connections.get(id).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get all active connections
    pub fn get_active_connections(&self) -> Vec<Connection> {
        let connections = self.connections.lock().unwrap();
        connections.values()
            .filter(|conn| conn.state != ConnectionState::Closed)
            .cloned()
            .collect()
    }

    /// Terminate a connection
    pub fn terminate_connection(&self, conn_id: u64) -> Result<(), String> {
        self.update_connection_state(conn_id, ConnectionState::Blocked)?;
        
        // In a real implementation, this would interact with the OS to actually
        // terminate the connection (e.g., sending RST packets)
        
        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.terminated_connections += 1;
        }
        
        info!("Terminated connection {}", conn_id);
        Ok(())
    }

    /// Terminate all connections from an IP
    pub fn terminate_connections_from_ip(&self, ip: &IpAddr) -> Result<u32, String> {
        let conn_ids: Vec<u64> = {
            let by_ip = self.connections_by_ip.lock().unwrap();
            by_ip.get(ip).cloned().unwrap_or_default().into_iter().collect()
        };
        
        let mut terminated = 0;
        for conn_id in conn_ids {
            if self.terminate_connection(conn_id).is_ok() {
                terminated += 1;
            }
        }
        
        info!("Terminated {} connections from IP {}", terminated, ip);
        Ok(terminated)
    }

    /// Mark connection as suspicious
    pub fn mark_suspicious(&self, conn_id: u64, reason: &str) -> Result<(), String> {
        let mut connections = self.connections.lock().unwrap();
        
        if let Some(conn) = connections.get_mut(&conn_id) {
            conn.state = ConnectionState::Suspicious;
            conn.flags.insert(format!("suspicious:{}", reason));
            conn.update_activity();
            
            warn!("Connection {} marked as suspicious: {}", conn_id, reason);
            Ok(())
        } else {
            Err(format!("Connection {} not found", conn_id))
        }
    }

    /// Get connection statistics
    pub fn get_stats(&self) -> ConnectionStats {
        self.stats.read().unwrap().clone()
    }

    /// Check if an IP has too many connections
    pub fn check_connection_limit(&self, ip: &IpAddr) -> bool {
        let config = self.config.read().unwrap();
        let by_ip = self.connections_by_ip.lock().unwrap();
        
        if let Some(ip_conns) = by_ip.get(ip) {
            ip_conns.len() < config.max_per_ip as usize
        } else {
            true
        }
    }

    /// Get connection count for an IP
    pub fn get_connection_count(&self, ip: &IpAddr) -> usize {
        let by_ip = self.connections_by_ip.lock().unwrap();
        by_ip.get(ip).map(|conns| conns.len()).unwrap_or(0)
    }

    /// Export connections to file
    pub fn export_connections(&self, path: &str) -> Result<(), String> {
        let connections = self.connections.lock().unwrap();
        let export_data: Vec<&Connection> = connections.values().collect();

        let json = serde_json::to_string_pretty(&export_data)
            .map_err(|e| format!("Failed to serialize connections: {}", e))?;

        std::fs::write(path, json)
            .map_err(|e| format!("Failed to write file: {}", e))?;

        info!("Exported {} connections to {}", export_data.len(), path);
        Ok(())
    }
} 