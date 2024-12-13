use aya_bpf::{
    maps::{HashMap, LruHashMap, PerfEventArray},
    BpfContext,
};
use core::time::Duration;

// Constants for map sizes and limits
const MAX_ENTRIES: u32 = 100_000;
const MAX_FLOWS: u32 = 50_000;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

#[derive(Clone)]
#[repr(C)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Clone)]
#[repr(C)]
pub struct FlowStats {
    pub packets: u64,
    pub bytes: u64,
    pub start_time: u64,
    pub last_seen: u64,
    pub flags: u32,
}

// Map definitions for various XDP functionalities
pub struct XdpMaps {
    // Flow tracking map
    flow_table: LruHashMap<FlowKey, FlowStats>,
    
    // Blacklist for immediate dropping
    blacklist: HashMap<u32, u8>,
    
    // Rate limiting counters
    rate_limits: HashMap<u32, u32>,
    
    // Performance monitoring events
    perf_events: PerfEventArray,
}

impl XdpMaps {
    pub fn new() -> Result<Self, &'static str> {
        Ok(Self {
            flow_table: LruHashMap::with_max_entries(MAX_FLOWS, 0)?,
            blacklist: HashMap::with_max_entries(MAX_ENTRIES, 0)?,
            rate_limits: HashMap::with_max_entries(MAX_ENTRIES, 0)?,
            perf_events: PerfEventArray::new()?,
        })
    }

    // Flow table operations
    pub fn update_flow(&mut self, ctx: &BpfContext, key: &FlowKey, stats: &FlowStats) -> Result<(), i64> {
        self.flow_table.insert(key, stats, 0)
    }

    pub fn get_flow(&self, key: &FlowKey) -> Option<FlowStats> {
        self.flow_table.get(key).ok()
    }

    // Blacklist operations
    pub fn is_blacklisted(&self, ip: u32) -> bool {
        self.blacklist.get(&ip).is_ok()
    }

    pub fn update_blacklist(&mut self, ip: u32, reason: u8) -> Result<(), i64> {
        self.blacklist.insert(&ip, &reason, 0)
    }

    // Rate limiting operations
    pub fn check_rate_limit(&mut self, ip: u32, limit: u32) -> bool {
        let current = self.rate_limits.get(&ip).unwrap_or(&0);
        *current < limit
    }

    pub fn increment_rate_counter(&mut self, ip: u32) -> Result<(), i64> {
        let current = self.rate_limits.get(&ip).unwrap_or(&0);
        self.rate_limits.insert(&ip, &(current + 1), 0)
    }

    // Performance monitoring
    pub fn emit_event(&mut self, ctx: &BpfContext, data: &[u8]) -> Result<(), i64> {
        self.perf_events.output(ctx, data, 0)
    }

    // Cleanup and maintenance
    pub fn cleanup_expired(&mut self, current_time: u64) {
        // Implement cleanup logic for expired entries
        // This would typically be called from a periodic maintenance task
    }
}

// Helper functions for map operations
pub mod helpers {
    use super::*;

    pub fn create_flow_key(
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> FlowKey {
        FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    pub fn create_flow_stats(
        packets: u64,
        bytes: u64,
        start_time: u64,
        flags: u32,
    ) -> FlowStats {
        FlowStats {
            packets,
            bytes,
            start_time,
            last_seen: start_time,
            flags,
        }
    }

    pub fn calculate_flow_hash(key: &FlowKey) -> u32 {
        // Implement a fast hash function for flow keys
        // This is used for consistent flow distribution
        let mut hash = 17u32;
        hash = hash.wrapping_mul(31).wrapping_add(key.src_ip);
        hash = hash.wrapping_mul(31).wrapping_add(key.dst_ip);
        hash = hash.wrapping_mul(31).wrapping_add(key.src_port as u32);
        hash = hash.wrapping_mul(31).wrapping_add(key.dst_port as u32);
        hash = hash.wrapping_mul(31).wrapping_add(key.protocol as u32);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_key_creation() {
        let key = helpers::create_flow_key(
            0x0A000001, // 10.0.0.1
            0x0A000002, // 10.0.0.2
            12345,
            80,
            6, // TCP
        );
        assert_eq!(key.src_ip, 0x0A000001);
        assert_eq!(key.dst_ip, 0x0A000002);
        assert_eq!(key.src_port, 12345);
        assert_eq!(key.dst_port, 80);
        assert_eq!(key.protocol, 6);
    }

    #[test]
    fn test_flow_hash() {
        let key1 = helpers::create_flow_key(0x0A000001, 0x0A000002, 12345, 80, 6);
        let key2 = helpers::create_flow_key(0x0A000001, 0x0A000002, 12345, 80, 6);
        let hash1 = helpers::calculate_flow_hash(&key1);
        let hash2 = helpers::calculate_flow_hash(&key2);
        assert_eq!(hash1, hash2);
    }
}