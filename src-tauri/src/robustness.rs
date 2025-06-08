use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU64, Ordering}};
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use tokio::sync::RwLock;
use anyhow::Result;
use log::{error, warn, info};
use serde::{Serialize, Deserialize};
use sysinfo::{System, Disks, Networks};

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,     // Normal operation
    Open,       // Failure state, rejecting requests
    HalfOpen,   // Testing if service has recovered
}

/// Circuit breaker for preventing cascading failures
pub struct CircuitBreaker {
    state: Arc<RwLock<CircuitState>>,
    failure_count: AtomicU64,
    success_count: AtomicU64,
    last_failure_time: Arc<RwLock<Option<Instant>>>,
    failure_threshold: u64,
    success_threshold: u64,
    timeout: Duration,
    half_open_timeout: Duration,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u64, success_threshold: u64, timeout: Duration) -> Self {
        Self {
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            failure_count: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            last_failure_time: Arc::new(RwLock::new(None)),
            failure_threshold,
            success_threshold,
            timeout,
            half_open_timeout: Duration::from_secs(30),
        }
    }

    pub async fn call<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        let state = self.state.read().await;
        
        match *state {
            CircuitState::Open => {
                // Check if we should transition to half-open
                if let Some(last_failure) = *self.last_failure_time.read().await {
                    if last_failure.elapsed() > self.timeout {
                        drop(state);
                        let mut state = self.state.write().await;
                        *state = CircuitState::HalfOpen;
                        info!("Circuit breaker transitioning to half-open state");
                    } else {
                        return Err(anyhow::anyhow!("Circuit breaker is open"));
                    }
                } else {
                    return Err(anyhow::anyhow!("Circuit breaker is open"));
                }
            }
            _ => {}
        }

        // Execute the function
        match f() {
            Ok(result) => {
                self.on_success().await;
                Ok(result)
            }
            Err(e) => {
                self.on_failure().await;
                Err(e)
            }
        }
    }

    async fn on_success(&self) {
        let state = self.state.read().await;
        
        match *state {
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.success_threshold {
                    drop(state);
                    let mut state = self.state.write().await;
                    *state = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::SeqCst);
                    self.success_count.store(0, Ordering::SeqCst);
                    info!("Circuit breaker closed after successful recovery");
                }
            }
            CircuitState::Closed => {
                self.failure_count.store(0, Ordering::SeqCst);
            }
            _ => {}
        }
    }

    async fn on_failure(&self) {
        let state = self.state.read().await;
        
        match *state {
            CircuitState::Closed => {
                let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.failure_threshold {
                    drop(state);
                    let mut state = self.state.write().await;
                    *state = CircuitState::Open;
                    let mut last_failure = self.last_failure_time.write().await;
                    *last_failure = Some(Instant::now());
                    warn!("Circuit breaker opened after {} failures", count);
                }
            }
            CircuitState::HalfOpen => {
                drop(state);
                let mut state = self.state.write().await;
                *state = CircuitState::Open;
                let mut last_failure = self.last_failure_time.write().await;
                *last_failure = Some(Instant::now());
                self.success_count.store(0, Ordering::SeqCst);
                warn!("Circuit breaker reopened after failure in half-open state");
            }
            _ => {}
        }
    }

    pub async fn get_state(&self) -> CircuitState {
        *self.state.read().await
    }
}

/// Rate limiter for preventing resource exhaustion
pub struct RateLimiter {
    window_size: Duration,
    max_requests: u64,
    requests: Arc<Mutex<VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new(window_size: Duration, max_requests: u64) -> Self {
        Self {
            window_size,
            max_requests,
            requests: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub fn check_rate_limit(&self) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();
        
        // Remove old requests outside the window
        while let Some(&front) = requests.front() {
            if now.duration_since(front) > self.window_size {
                requests.pop_front();
            } else {
                break;
            }
        }
        
        // Check if we're within the limit
        if requests.len() as u64 >= self.max_requests {
            false
        } else {
            requests.push_back(now);
            true
        }
    }
}

/// Health check system for monitoring component health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub component: String,
    pub healthy: bool,
    pub last_check: chrono::DateTime<chrono::Utc>,
    pub error_count: u64,
    pub details: Option<String>,
}

pub struct HealthMonitor {
    checks: Arc<RwLock<Vec<HealthCheck>>>,
    statuses: Arc<RwLock<Vec<HealthStatus>>>,
    check_interval: Duration,
    is_running: Arc<AtomicBool>,
}

struct HealthCheck {
    name: String,
    check_fn: Box<dyn Fn() -> Result<()> + Send + Sync>,
}

impl HealthMonitor {
    pub fn new(check_interval: Duration) -> Self {
        Self {
            checks: Arc::new(RwLock::new(Vec::new())),
            statuses: Arc::new(RwLock::new(Vec::new())),
            check_interval,
            is_running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn add_check<F>(&self, name: String, check_fn: F) -> Result<()>
    where
        F: Fn() -> Result<()> + Send + Sync + 'static,
    {
        let checks = Arc::clone(&self.checks);
        tokio::spawn(async move {
            let mut checks = checks.write().await;
            checks.push(HealthCheck {
                name,
                check_fn: Box::new(check_fn),
            });
        });
        Ok(())
    }

    pub async fn start(&self) {
        if self.is_running.load(Ordering::SeqCst) {
            return;
        }

        self.is_running.store(true, Ordering::SeqCst);
        let checks = Arc::clone(&self.checks);
        let statuses = Arc::clone(&self.statuses);
        let interval = self.check_interval;
        let is_running = Arc::clone(&self.is_running);

        tokio::spawn(async move {
            while is_running.load(Ordering::SeqCst) {
                let checks = checks.read().await;
                let mut new_statuses = Vec::new();

                for check in checks.iter() {
                    let result = (check.check_fn)();
                    let status = HealthStatus {
                        component: check.name.clone(),
                        healthy: result.is_ok(),
                        last_check: chrono::Utc::now(),
                        error_count: if result.is_err() { 1 } else { 0 },
                        details: result.err().map(|e| e.to_string()),
                    };
                    new_statuses.push(status);
                }

                let mut statuses = statuses.write().await;
                *statuses = new_statuses;

                tokio::time::sleep(interval).await;
            }
        });
    }

    pub async fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }

    pub async fn get_statuses(&self) -> Vec<HealthStatus> {
        self.statuses.read().await.clone()
    }

    pub async fn is_healthy(&self) -> bool {
        self.statuses.read().await.iter().all(|s| s.healthy)
    }
}

/// Automatic recovery system
pub struct RecoverySystem {
    recovery_strategies: Arc<RwLock<Vec<RecoveryStrategy>>>,
    max_retry_attempts: u32,
    retry_delay: Duration,
}

struct RecoveryStrategy {
    name: String,
    condition_fn: Box<dyn Fn() -> bool + Send + Sync>,
    recovery_fn: Box<dyn Fn() -> Result<()> + Send + Sync>,
}

impl RecoverySystem {
    pub fn new(max_retry_attempts: u32, retry_delay: Duration) -> Self {
        Self {
            recovery_strategies: Arc::new(RwLock::new(Vec::new())),
            max_retry_attempts,
            retry_delay,
        }
    }

    pub async fn add_strategy<C, R>(&self, name: String, condition_fn: C, recovery_fn: R)
    where
        C: Fn() -> bool + Send + Sync + 'static,
        R: Fn() -> Result<()> + Send + Sync + 'static,
    {
        let mut strategies = self.recovery_strategies.write().await;
        strategies.push(RecoveryStrategy {
            name,
            condition_fn: Box::new(condition_fn),
            recovery_fn: Box::new(recovery_fn),
        });
    }

    pub async fn check_and_recover(&self) -> Result<()> {
        let strategies = self.recovery_strategies.read().await;
        
        for strategy in strategies.iter() {
            if (strategy.condition_fn)() {
                info!("Recovery condition met for: {}", strategy.name);
                
                for attempt in 1..=self.max_retry_attempts {
                    match (strategy.recovery_fn)() {
                        Ok(_) => {
                            info!("Recovery successful for: {} (attempt {})", strategy.name, attempt);
                            return Ok(());
                        }
                        Err(e) => {
                            warn!("Recovery attempt {} failed for {}: {}", attempt, strategy.name, e);
                            if attempt < self.max_retry_attempts {
                                tokio::time::sleep(self.retry_delay).await;
                            }
                        }
                    }
                }
                
                error!("All recovery attempts failed for: {}", strategy.name);
            }
        }
        
        Ok(())
    }
}

/// Resource monitoring and management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMetrics {
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub memory_total: u64,
    pub disk_usage: u64,
    pub disk_total: u64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub open_file_descriptors: u32,
    pub thread_count: u32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub struct ResourceMonitor {
    metrics_history: Arc<RwLock<VecDeque<ResourceMetrics>>>,
    max_history_size: usize,
    alert_thresholds: Arc<RwLock<AlertThresholds>>,
}

#[derive(Debug, Clone)]
struct AlertThresholds {
    cpu_threshold: f32,
    memory_threshold: f32,
    disk_threshold: f32,
}

impl ResourceMonitor {
    pub fn new(max_history_size: usize) -> Self {
        Self {
            metrics_history: Arc::new(RwLock::new(VecDeque::with_capacity(max_history_size))),
            max_history_size,
            alert_thresholds: Arc::new(RwLock::new(AlertThresholds {
                cpu_threshold: 80.0,
                memory_threshold: 85.0,
                disk_threshold: 90.0,
            })),
        }
    }

    pub async fn collect_metrics(&self) -> Result<ResourceMetrics> {
        let mut sys = System::new_all();
        sys.refresh_all();
        
        // Get CPU usage
        let cpu_usage = sys.cpus().iter()
            .map(|cpu| cpu.cpu_usage())
            .sum::<f32>() / sys.cpus().len() as f32;
            
        let memory_usage = sys.used_memory();
        let memory_total = sys.total_memory();
        
        // Get disk usage using separate Disks object
        let disks = Disks::new_with_refreshed_list();
        let mut disk_usage = 0;
        let mut disk_total = 0;
        for disk in &disks {
            disk_usage += disk.total_space() - disk.available_space();
            disk_total += disk.total_space();
        }
        
        // Get network usage using separate Networks object
        let networks = Networks::new_with_refreshed_list();
        let mut network_rx_bytes = 0;
        let mut network_tx_bytes = 0;
        for (_, data) in &networks {
            network_rx_bytes += data.total_received();
            network_tx_bytes += data.total_transmitted();
        }
        
        let metrics = ResourceMetrics {
            cpu_usage,
            memory_usage,
            memory_total,
            disk_usage,
            disk_total,
            network_rx_bytes,
            network_tx_bytes,
            open_file_descriptors: 0, // Platform-specific
            thread_count: sys.processes().len() as u32,
            timestamp: chrono::Utc::now(),
        };
        
        // Store metrics in history
        let mut history = self.metrics_history.write().await;
        if history.len() >= self.max_history_size {
            history.pop_front();
        }
        history.push_back(metrics.clone());
        
        // Check thresholds
        self.check_thresholds(&metrics).await;
        
        Ok(metrics)
    }

    async fn check_thresholds(&self, metrics: &ResourceMetrics) {
        let thresholds = self.alert_thresholds.read().await;
        
        if metrics.cpu_usage > thresholds.cpu_threshold {
            warn!("CPU usage alert: {}% (threshold: {}%)", metrics.cpu_usage, thresholds.cpu_threshold);
        }
        
        let memory_percent = (metrics.memory_usage as f32 / metrics.memory_total as f32) * 100.0;
        if memory_percent > thresholds.memory_threshold {
            warn!("Memory usage alert: {:.1}% (threshold: {}%)", memory_percent, thresholds.memory_threshold);
        }
        
        if metrics.disk_total > 0 {
            let disk_percent = (metrics.disk_usage as f32 / metrics.disk_total as f32) * 100.0;
            if disk_percent > thresholds.disk_threshold {
                warn!("Disk usage alert: {:.1}% (threshold: {}%)", disk_percent, thresholds.disk_threshold);
            }
        }
    }

    pub async fn get_metrics_history(&self) -> Vec<ResourceMetrics> {
        self.metrics_history.read().await.iter().cloned().collect()
    }
}

/// Chaos engineering for testing system resilience
pub struct ChaosMonkey {
    enabled: Arc<AtomicBool>,
    failure_probability: f64,
    delay_probability: f64,
    max_delay_ms: u64,
}

impl ChaosMonkey {
    pub fn new(failure_probability: f64, delay_probability: f64, max_delay_ms: u64) -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(false)),
            failure_probability,
            delay_probability,
            max_delay_ms,
        }
    }

    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
        warn!("Chaos Monkey enabled - system may experience random failures!");
    }

    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
        info!("Chaos Monkey disabled");
    }

    pub async fn maybe_inject_failure(&self) -> Result<()> {
        if !self.enabled.load(Ordering::SeqCst) {
            return Ok(());
        }

        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Maybe inject a failure
        if rng.gen::<f64>() < self.failure_probability {
            return Err(anyhow::anyhow!("Chaos Monkey injected failure"));
        }

        // Maybe inject a delay
        if rng.gen::<f64>() < self.delay_probability {
            let delay = rng.gen_range(0..self.max_delay_ms);
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }

        Ok(())
    }
}

/// Distributed tracing for debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSpan {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub operation_name: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub tags: std::collections::HashMap<String, String>,
    pub status: SpanStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpanStatus {
    Ok,
    Error(String),
}

pub struct DistributedTracer {
    spans: Arc<RwLock<Vec<TraceSpan>>>,
    max_spans: usize,
}

impl DistributedTracer {
    pub fn new(max_spans: usize) -> Self {
        Self {
            spans: Arc::new(RwLock::new(Vec::with_capacity(max_spans))),
            max_spans,
        }
    }

    pub async fn start_span(&self, operation_name: String, parent_span_id: Option<String>) -> String {
        use uuid::Uuid;
        
        let span = TraceSpan {
            trace_id: Uuid::new_v4().to_string(),
            span_id: Uuid::new_v4().to_string(),
            parent_span_id,
            operation_name,
            start_time: chrono::Utc::now(),
            end_time: None,
            tags: std::collections::HashMap::new(),
            status: SpanStatus::Ok,
        };
        
        let span_id = span.span_id.clone();
        
        let mut spans = self.spans.write().await;
        if spans.len() >= self.max_spans {
            spans.remove(0);
        }
        spans.push(span);
        
        span_id
    }

    pub async fn end_span(&self, span_id: &str, status: SpanStatus) {
        let mut spans = self.spans.write().await;
        if let Some(span) = spans.iter_mut().find(|s| s.span_id == span_id) {
            span.end_time = Some(chrono::Utc::now());
            span.status = status;
        }
    }

    pub async fn add_tag(&self, span_id: &str, key: String, value: String) {
        let mut spans = self.spans.write().await;
        if let Some(span) = spans.iter_mut().find(|s| s.span_id == span_id) {
            span.tags.insert(key, value);
        }
    }

    pub async fn get_trace(&self, trace_id: &str) -> Vec<TraceSpan> {
        self.spans
            .read()
            .await
            .iter()
            .filter(|s| s.trace_id == trace_id)
            .cloned()
            .collect()
    }
} 