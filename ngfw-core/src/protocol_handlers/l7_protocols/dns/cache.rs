use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use log::{info, warn};

// A simple representation of a DNS packet
struct DnsPacket {
    query: String,
    response: String,
    // Add more fields as necessary for a real DNS packet
}

struct DnsCacheEntry {
    response: String,
    expiry: Instant,
}

pub struct DnsCache {
    cache: Arc<RwLock<HashMap<String, DnsCacheEntry>>>,
    ttl: Duration,
}

impl DnsCache {
    pub fn new(ttl: Duration) -> Self {
        DnsCache {
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    pub fn get(&self, query: &str) -> Option<String> {
        let cache = self.cache.read().expect("Failed to acquire read lock");
        if let Some(entry) = cache.get(query) {
            if entry.expiry > Instant::now() {
                info!("Cache hit for query: {}", query);
                return Some(entry.response.clone());
            }
        }
        None
    }

    pub fn insert(&self, query: String, response: String) {
        let expiry = Instant::now() + self.ttl;
        let mut cache = self.cache.write().expect("Failed to acquire write lock");
        cache.insert(query, DnsCacheEntry { response, expiry });
        info!("Inserted query into cache: {}", query);
    }

    pub fn handle_packet(&self, packet: DnsPacket) {
        if packet.query.is_empty() {
            warn!("Invalid DNS query: query is empty");
            return;
        }

        if let Some(cached_response) = self.get(&packet.query) {
            info!("Cache hit: {}", cached_response);
            return;
        }

        let resolved_response = self.resolve_dns(&packet.query);
        self.insert(packet.query.clone(), resolved_response.clone());
        info!("Resolved and cached: {}", resolved_response);
    }

    fn resolve_dns(&self, query: &str) -> String {
        format!("Resolved IP for {}", query)
    }

    pub fn cleanup_expired(&self) {
        let mut cache = self.cache.write().expect("Failed to acquire write lock");
        let now = Instant::now();
        cache.retain(|_, entry| entry.expiry > now);
        info!("Cleaned up expired cache entries");
    }
}
