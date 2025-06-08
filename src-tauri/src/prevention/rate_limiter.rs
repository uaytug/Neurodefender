use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time;
use log::{debug, info};

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    capacity: u32,
    tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self, tokens: u32) -> bool {
        self.refill();
        
        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        self.last_refill = now;
    }
}

/// Sliding window counter for more accurate rate limiting
#[derive(Debug)]
struct SlidingWindowCounter {
    window_size: Duration,
    limit: u32,
    requests: Vec<Instant>,
}

impl SlidingWindowCounter {
    fn new(window_size: Duration, limit: u32) -> Self {
        Self {
            window_size,
            limit,
            requests: Vec::new(),
        }
    }

    fn try_record(&mut self) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window_size;
        
        // Remove old requests outside the window
        self.requests.retain(|&req_time| req_time > cutoff);
        
        if self.requests.len() < self.limit as usize {
            self.requests.push(now);
            true
        } else {
            false
        }
    }

    fn current_count(&self) -> u32 {
        let now = Instant::now();
        let cutoff = now - self.window_size;
        
        self.requests.iter()
            .filter(|&&req_time| req_time > cutoff)
            .count() as u32
    }
}

/// Rate limiting algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitAlgorithm {
    TokenBucket,
    SlidingWindow,
    FixedWindow,
}

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    pub algorithm: RateLimitAlgorithm,
    pub global_limit: u32,
    pub per_ip_limit: u32,
    pub window_size: Duration,
    pub burst_size: u32,
    pub cleanup_interval: Duration,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            algorithm: RateLimitAlgorithm::SlidingWindow,
            global_limit: 10000,
            per_ip_limit: 100,
            window_size: Duration::from_secs(60),
            burst_size: 10,
            cleanup_interval: Duration::from_secs(300),
        }
    }
}

/// IP-specific rate limit state
enum RateLimitState {
    TokenBucket(TokenBucket),
    SlidingWindow(SlidingWindowCounter),
}

/// Advanced rate limiter
pub struct RateLimiter {
    config: RateLimiterConfig,
    ip_states: Arc<Mutex<HashMap<IpAddr, RateLimitState>>>,
    global_state: Arc<Mutex<RateLimitState>>,
    last_cleanup: Arc<Mutex<Instant>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimiterConfig) -> Self {
        let global_state = match config.algorithm {
            RateLimitAlgorithm::TokenBucket => {
                let refill_rate = config.global_limit as f64 / config.window_size.as_secs_f64();
                RateLimitState::TokenBucket(TokenBucket::new(
                    config.global_limit + config.burst_size,
                    refill_rate,
                ))
            }
            RateLimitAlgorithm::SlidingWindow | RateLimitAlgorithm::FixedWindow => {
                RateLimitState::SlidingWindow(SlidingWindowCounter::new(
                    config.window_size,
                    config.global_limit,
                ))
            }
        };

        Self {
            config,
            ip_states: Arc::new(Mutex::new(HashMap::new())),
            global_state: Arc::new(Mutex::new(global_state)),
            last_cleanup: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Check if a request from an IP should be allowed
    pub fn check_rate_limit(&self, ip: IpAddr, tokens: u32) -> Result<bool, String> {
        // Check global rate limit first
        {
            let mut global_state = self.global_state.lock().unwrap();
            let global_allowed = match &mut *global_state {
                RateLimitState::TokenBucket(bucket) => bucket.try_consume(tokens),
                RateLimitState::SlidingWindow(counter) => {
                    if tokens == 1 {
                        counter.try_record()
                    } else {
                        // For sliding window, we can only check single requests
                        false
                    }
                }
            };

            if !global_allowed {
                debug!("Global rate limit exceeded");
                return Ok(false);
            }
        }

        // Check per-IP rate limit
        {
            let mut ip_states = self.ip_states.lock().unwrap();
            
            let ip_state = ip_states.entry(ip).or_insert_with(|| {
                match self.config.algorithm {
                    RateLimitAlgorithm::TokenBucket => {
                        let refill_rate = self.config.per_ip_limit as f64 / self.config.window_size.as_secs_f64();
                        RateLimitState::TokenBucket(TokenBucket::new(
                            self.config.per_ip_limit + self.config.burst_size,
                            refill_rate,
                        ))
                    }
                    RateLimitAlgorithm::SlidingWindow | RateLimitAlgorithm::FixedWindow => {
                        RateLimitState::SlidingWindow(SlidingWindowCounter::new(
                            self.config.window_size,
                            self.config.per_ip_limit,
                        ))
                    }
                }
            });

            let allowed = match ip_state {
                RateLimitState::TokenBucket(bucket) => bucket.try_consume(tokens),
                RateLimitState::SlidingWindow(counter) => {
                    if tokens == 1 {
                        counter.try_record()
                    } else {
                        false
                    }
                }
            };

            if !allowed {
                debug!("Per-IP rate limit exceeded for {}", ip);
            }

            Ok(allowed)
        }
    }

    /// Get current usage statistics for an IP
    pub fn get_ip_usage(&self, ip: IpAddr) -> Option<(u32, u32)> {
        let ip_states = self.ip_states.lock().unwrap();
        
        ip_states.get(&ip).map(|state| {
            match state {
                RateLimitState::TokenBucket(bucket) => {
                    let used = self.config.per_ip_limit - bucket.tokens as u32;
                    (used, self.config.per_ip_limit)
                }
                RateLimitState::SlidingWindow(counter) => {
                    (counter.current_count(), self.config.per_ip_limit)
                }
            }
        })
    }

    /// Get global usage statistics
    pub fn get_global_usage(&self) -> (u32, u32) {
        let global_state = self.global_state.lock().unwrap();
        
        match &*global_state {
            RateLimitState::TokenBucket(bucket) => {
                let used = self.config.global_limit - bucket.tokens as u32;
                (used, self.config.global_limit)
            }
            RateLimitState::SlidingWindow(counter) => {
                (counter.current_count(), self.config.global_limit)
            }
        }
    }

    /// Clean up old IP states
    pub fn cleanup_old_states(&self) {
        let mut last_cleanup = self.last_cleanup.lock().unwrap();
        let now = Instant::now();
        
        if now.duration_since(*last_cleanup) < self.config.cleanup_interval {
            return;
        }

        let mut ip_states = self.ip_states.lock().unwrap();
        let initial_count = ip_states.len();
        
        // For sliding window, remove IPs with no recent activity
        if matches!(self.config.algorithm, RateLimitAlgorithm::SlidingWindow | RateLimitAlgorithm::FixedWindow) {
            ip_states.retain(|_ip, state| {
                if let RateLimitState::SlidingWindow(counter) = state {
                    counter.current_count() > 0
                } else {
                    true
                }
            });
        }
        
        let removed = initial_count - ip_states.len();
        if removed > 0 {
            info!("Cleaned up {} inactive IP rate limit states", removed);
        }
        
        *last_cleanup = now;
    }

    /// Reset rate limits for a specific IP
    pub fn reset_ip_limit(&self, ip: IpAddr) {
        let mut ip_states = self.ip_states.lock().unwrap();
        ip_states.remove(&ip);
        info!("Reset rate limit for IP: {}", ip);
    }

    /// Reset all rate limits
    pub fn reset_all_limits(&self) {
        {
            let mut ip_states = self.ip_states.lock().unwrap();
            ip_states.clear();
        }
        
        {
            let mut global_state = self.global_state.lock().unwrap();
            *global_state = match self.config.algorithm {
                RateLimitAlgorithm::TokenBucket => {
                    let refill_rate = self.config.global_limit as f64 / self.config.window_size.as_secs_f64();
                    RateLimitState::TokenBucket(TokenBucket::new(
                        self.config.global_limit + self.config.burst_size,
                        refill_rate,
                    ))
                }
                RateLimitAlgorithm::SlidingWindow | RateLimitAlgorithm::FixedWindow => {
                    RateLimitState::SlidingWindow(SlidingWindowCounter::new(
                        self.config.window_size,
                        self.config.global_limit,
                    ))
                }
            };
        }
        
        info!("Reset all rate limits");
    }

    /// Update configuration
    pub fn update_config(&mut self, new_config: RateLimiterConfig) {
        self.config = new_config;
        self.reset_all_limits();
        info!("Updated rate limiter configuration");
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                self.cleanup_old_states();
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10, 1.0);
        
        // Should be able to consume up to capacity
        assert!(bucket.try_consume(5));
        assert!(bucket.try_consume(5));
        assert!(!bucket.try_consume(1));
        
        // Wait and refill
        std::thread::sleep(Duration::from_secs(2));
        assert!(bucket.try_consume(2));
    }

    #[test]
    fn test_sliding_window() {
        let mut counter = SlidingWindowCounter::new(Duration::from_secs(1), 3);
        
        // Should allow up to limit
        assert!(counter.try_record());
        assert!(counter.try_record());
        assert!(counter.try_record());
        assert!(!counter.try_record());
        
        // Wait for window to pass
        std::thread::sleep(Duration::from_secs(1));
        assert!(counter.try_record());
    }
} 