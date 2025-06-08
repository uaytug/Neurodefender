mod mlengine;
mod python_worker;

use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tokio::time::interval;
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use crate::capture::packet::PacketInfo;
use python_worker::PythonWorker;

/// ML Engine configuration
#[derive(Debug, Clone)]
pub struct MlEngineConfig {
    /// Maximum batch size for processing
    pub batch_size: usize,
    /// Maximum wait time before processing a partial batch
    pub batch_timeout_ms: u64,
    /// Number of worker processes
    pub num_workers: usize,
    /// Confidence threshold for alerts
    pub confidence_threshold: f64,
    /// Enable caching of results
    pub enable_cache: bool,
    /// Cache size limit
    pub cache_size: usize,
    /// Model path
    pub model_path: String,
}

impl Default for MlEngineConfig {
    fn default() -> Self {
        Self {
            batch_size: 32,
            batch_timeout_ms: 100,
            num_workers: 2,
            confidence_threshold: 0.7,
            enable_cache: true,
            cache_size: 10000,
            model_path: "rdpahalavan/bert-network-packet-flow-header-payload".to_string(),
        }
    }
}

/// Result returned by the ML engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlResult {
    pub prediction: String,
    pub confidence: f64,
    pub threat_type: Option<String>,
    pub processing_time_ms: u64,
}

/// Request to analyze a packet
struct AnalysisRequest {
    packet: PacketInfo,
    response_tx: oneshot::Sender<Option<MlResult>>,
}

/// ML Engine service that manages the Python backend
pub struct MlEngineService {
    config: MlEngineConfig,
    request_tx: mpsc::Sender<AnalysisRequest>,
    metrics: Arc<Mutex<MlEngineMetrics>>,
}

/// Metrics for monitoring ML engine performance
#[derive(Debug, Default, Clone)]
pub struct MlEngineMetrics {
    pub total_requests: u64,
    pub successful_predictions: u64,
    pub failed_predictions: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub average_processing_time_ms: f64,
    pub batch_count: u64,
}

impl MlEngineService {
    /// Create a new ML engine service
    pub fn new(config: MlEngineConfig) -> Self {
        let (request_tx, request_rx) = mpsc::channel(1000);
        let metrics = Arc::new(Mutex::new(MlEngineMetrics::default()));
        
        // Start the background processing task
        let service = Self {
            config: config.clone(),
            request_tx,
            metrics: metrics.clone(),
        };
        
        // Spawn the processing loop
        tokio::spawn(Self::processing_loop(config, request_rx, metrics));
        
        service
    }
    
    /// Analyze a packet with the ML engine
    pub async fn analyze(&self, packet: PacketInfo) -> Option<MlResult> {
        let (response_tx, response_rx) = oneshot::channel();
        
        let request = AnalysisRequest {
            packet,
            response_tx,
        };
        
        // Send request to processing queue
        if let Err(e) = self.request_tx.send(request).await {
            error!("Failed to send ML analysis request: {}", e);
            return None;
        }
        
        // Wait for response
        match response_rx.await {
            Ok(result) => result,
            Err(e) => {
                error!("Failed to receive ML analysis response: {}", e);
                None
            }
        }
    }
    
    /// Get current metrics
    pub fn get_metrics(&self) -> MlEngineMetrics {
        self.metrics.lock().unwrap().clone()
    }
    
    /// Background processing loop
    async fn processing_loop(
        config: MlEngineConfig,
        mut request_rx: mpsc::Receiver<AnalysisRequest>,
        metrics: Arc<Mutex<MlEngineMetrics>>,
    ) {
        info!("ML Engine processing loop started");
        
        // Initialize Python backend pool
        let backend_pool = match PythonBackendPool::new(config.num_workers, &config.model_path) {
            Ok(pool) => pool,
            Err(e) => {
                error!("Failed to initialize Python backend pool: {}", e);
                return;
            }
        };
        
        // Batch processing buffer
        let mut batch_buffer: VecDeque<AnalysisRequest> = VecDeque::new();
        let mut batch_timer = interval(Duration::from_millis(config.batch_timeout_ms));
        
        // Result cache
        let mut cache = if config.enable_cache {
            Some(ResultCache::new(config.cache_size))
        } else {
            None
        };
        
        loop {
            tokio::select! {
                // Receive new requests
                Some(request) = request_rx.recv() => {
                    // Update metrics
                    {
                        let mut m = metrics.lock().unwrap();
                        m.total_requests += 1;
                    }
                    
                    // Check cache first
                    if let Some(ref mut cache) = cache {
                        if let Some(cached_result) = cache.get(&request.packet) {
                            // Cache hit
                            {
                                let mut m = metrics.lock().unwrap();
                                m.cache_hits += 1;
                            }
                            let _ = request.response_tx.send(Some(cached_result));
                            continue;
                        } else {
                            // Cache miss
                            let mut m = metrics.lock().unwrap();
                            m.cache_misses += 1;
                        }
                    }
                    
                    // Add to batch buffer
                    batch_buffer.push_back(request);
                    
                    // Process if batch is full
                    if batch_buffer.len() >= config.batch_size {
                        Self::process_batch(
                            &backend_pool,
                            &mut batch_buffer,
                            &metrics,
                            cache.as_mut(),
                        ).await;
                    }
                }
                
                // Batch timeout - process partial batch
                _ = batch_timer.tick() => {
                    if !batch_buffer.is_empty() {
                        Self::process_batch(
                            &backend_pool,
                            &mut batch_buffer,
                            &metrics,
                            cache.as_mut(),
                        ).await;
                    }
                }
            }
        }
    }
    
    /// Process a batch of requests
    async fn process_batch(
        backend_pool: &PythonBackendPool,
        batch_buffer: &mut VecDeque<AnalysisRequest>,
        metrics: &Arc<Mutex<MlEngineMetrics>>,
        mut cache: Option<&mut ResultCache>,
    ) {
        let batch_size = batch_buffer.len();
        let start_time = Instant::now();
        
        // Extract packets from requests
        let mut requests: Vec<AnalysisRequest> = Vec::new();
        let mut packets: Vec<PacketInfo> = Vec::new();
        
        for _ in 0..batch_size {
            if let Some(request) = batch_buffer.pop_front() {
                packets.push(request.packet.clone());
                requests.push(request);
            }
        }
        
        // Process batch with backend
        match backend_pool.process_batch(packets).await {
            Ok(results) => {
                let processing_time = start_time.elapsed().as_millis() as u64;
                
                // Send results back to requesters
                for (request, result) in requests.into_iter().zip(results.into_iter()) {
                    // Update cache
                    if let Some(ref mut cache) = cache {
                        if let Some(ref res) = result {
                            cache.insert(request.packet.clone(), res.clone());
                        }
                    }
                    
                    // Send response
                    let _ = request.response_tx.send(result);
                }
                
                // Update metrics
                {
                    let mut m = metrics.lock().unwrap();
                    m.successful_predictions += batch_size as u64;
                    m.batch_count += 1;
                    
                    // Update average processing time
                    let total_time = m.average_processing_time_ms * m.batch_count as f64;
                    m.average_processing_time_ms = (total_time + processing_time as f64) / (m.batch_count as f64);
                }
                
                debug!("Processed batch of {} packets in {}ms", batch_size, processing_time);
            }
            Err(e) => {
                error!("Failed to process batch: {}", e);
                
                // Send error responses
                for request in requests {
                    let _ = request.response_tx.send(None);
                }
                
                // Update metrics
                {
                    let mut m = metrics.lock().unwrap();
                    m.failed_predictions += batch_size as u64;
                }
            }
        }
    }
}

/// Python backend pool for managing worker processes
struct PythonBackendPool {
    workers: Vec<PythonWorker>,
    current_worker: Arc<Mutex<usize>>,
}

impl PythonBackendPool {
    fn new(num_workers: usize, model_path: &str) -> Result<Self, String> {
        let mut workers = Vec::new();
        
        for i in 0..num_workers {
            match PythonWorker::new(i, model_path) {
                Ok(worker) => {
                    info!("Initialized Python worker {}", i);
                    workers.push(worker);
                }
                Err(e) => {
                    error!("Failed to initialize Python worker {}: {}", i, e);
                    // Clean up already created workers
                    drop(workers);
                    return Err(format!("Failed to initialize worker pool: {}", e));
                }
            }
        }
        
        if workers.is_empty() {
            return Err("No workers could be initialized".to_string());
        }
        
        Ok(Self {
            workers,
            current_worker: Arc::new(Mutex::new(0)),
        })
    }
    
    async fn process_batch(&self, packets: Vec<PacketInfo>) -> Result<Vec<Option<MlResult>>, String> {
        // Get next worker in round-robin fashion
        let worker_idx = {
            let mut current = self.current_worker.lock().unwrap();
            let idx = *current;
            *current = (*current + 1) % self.workers.len();
            idx
        };
        
        let worker = &self.workers[worker_idx];
        
        // Check if worker is alive
        if !worker.is_alive() {
            error!("Worker {} is not alive, attempting to use next worker", worker_idx);
            // Try next worker
            if self.workers.len() > 1 {
                let next_idx = (worker_idx + 1) % self.workers.len();
                let next_worker = &self.workers[next_idx];
                if next_worker.is_alive() {
                    return next_worker.process_batch(packets).await;
                }
            }
            return Err("No alive workers available".to_string());
        }
        
        // Process with selected worker
        worker.process_batch(packets).await
    }
}

/// Simple LRU cache for ML results
struct ResultCache {
    cache: std::collections::HashMap<String, (MlResult, Instant)>,
    max_size: usize,
    ttl: Duration,
}

impl ResultCache {
    fn new(max_size: usize) -> Self {
        Self {
            cache: std::collections::HashMap::new(),
            max_size,
            ttl: Duration::from_secs(300), // 5 minute TTL
        }
    }
    
    fn get(&mut self, packet: &PacketInfo) -> Option<MlResult> {
        let key = Self::packet_key(packet);
        
        if let Some((result, timestamp)) = self.cache.get(&key) {
            if timestamp.elapsed() < self.ttl {
                return Some(result.clone());
            } else {
                // Expired entry
                self.cache.remove(&key);
            }
        }
        
        None
    }
    
    fn insert(&mut self, packet: PacketInfo, result: MlResult) {
        // Simple eviction if cache is full
        if self.cache.len() >= self.max_size {
            // Remove oldest entry (simple implementation)
            if let Some(oldest_key) = self.cache.keys().next().cloned() {
                self.cache.remove(&oldest_key);
            }
        }
        
        let key = Self::packet_key(&packet);
        self.cache.insert(key, (result, Instant::now()));
    }
    
    fn packet_key(packet: &PacketInfo) -> String {
        format!("{}-{}-{}-{}", 
            packet.source_ip, 
            packet.destination_ip, 
            packet.protocol, 
            packet.size
        )
    }
}

/// Public API for backward compatibility
pub async fn analyze_with_ml_engine(packet: &PacketInfo) -> Option<MlResult> {
    // This would use a global instance of MlEngineService
    // For now, return a placeholder
    warn!("Legacy analyze_with_ml_engine called - should use MlEngineService");
    None
}
