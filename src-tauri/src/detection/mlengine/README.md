# Enhanced ML Engine for Network Intrusion Detection

## Overview

The enhanced ML engine provides efficient and scalable machine learning-based network intrusion detection capabilities. It features:

- **Batch Processing**: Process multiple packets together for improved throughput
- **Connection Pooling**: Persistent Python worker processes eliminate startup overhead
- **Caching**: LRU cache for frequently seen packet patterns
- **Async Processing**: Non-blocking packet analysis
- **Performance Monitoring**: Built-in metrics and statistics
- **Fault Tolerance**: Automatic worker recovery and health checks

## Architecture

```
┌─────────────────────┐
│  Detection Engine   │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  MlEngineService    │
├─────────────────────┤
│ • Request Queue     │
│ • Batch Buffer      │
│ • Result Cache      │
│ • Metrics Tracking  │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│ PythonBackendPool   │
├─────────────────────┤
│ • Worker Pool       │
│ • Load Balancing    │
│ • Health Monitoring │
└──────────┬──────────┘
           │
     ┌─────┴─────┬─────────┐
     │           │         │
┌────▼───┐ ┌────▼───┐ ┌───▼────┐
│Worker 0│ │Worker 1│ │Worker N│
└────────┘ └────────┘ └────────┘
```

## Configuration

### Default Configuration

```rust
MlEngineConfig {
    batch_size: 32,              // Max packets per batch
    batch_timeout_ms: 100,       // Max wait before processing partial batch
    num_workers: 2,              // Number of Python worker processes
    confidence_threshold: 0.7,   // Min confidence for alerts
    enable_cache: true,          // Enable result caching
    cache_size: 10000,          // Max cached results
    model_path: "rdpahalavan/bert-network-packet-flow-header-payload",
}
```

### Custom Configuration

```rust
use crate::detection::mlengine::MlEngineConfig;
use crate::detection::engine::DetectionEngine;

let ml_config = MlEngineConfig {
    batch_size: 64,
    batch_timeout_ms: 50,
    num_workers: 4,
    confidence_threshold: 0.8,
    enable_cache: true,
    cache_size: 20000,
    model_path: "custom-model-path",
};

let engine = DetectionEngine::new_with_ml_config("./rules", ml_config)?;
```

## Usage

### Basic Usage

```rust
// Create detection engine with default ML config
let mut engine = DetectionEngine::new("./rules")?;

// Enable/disable ML engine
engine.set_ml_enabled(true);

// Start processing packets
engine.start_processing(packet_receiver)?;
```

### Advanced Usage

```rust
// Get ML engine metrics
let metrics = engine.get_ml_metrics();
println!("ML Engine Stats:");
println!("  Total requests: {}", metrics.total_requests);
println!("  Cache hit rate: {:.1}%", 
    (metrics.cache_hits as f64 / metrics.total_requests as f64) * 100.0);
println!("  Avg processing time: {:.2}ms", metrics.average_processing_time_ms);
```

## ML Model

The engine uses a BERT-based model trained on network packet data. It can classify traffic into 24 categories:

- **Normal Traffic**: Regular, benign network activity
- **Attack Types**: DDoS, DoS variants, Port Scans, Web Attacks, etc.
- **Malware**: Backdoors, Bots, Worms, Shellcode
- **Exploits**: Heartbleed, SQL Injection, XSS
- **Reconnaissance**: Port scanning, host discovery
- **Authentication Attacks**: Brute force, credential stuffing

## Performance Optimization

### Batch Processing
- Packets are grouped into batches for efficient GPU/CPU utilization
- Configurable batch size and timeout ensure low latency

### Caching
- LRU cache stores recent predictions
- Identical packets skip ML processing
- 5-minute TTL prevents stale results

### Worker Pool
- Multiple Python processes handle requests in parallel
- Round-robin load balancing
- Automatic failover if a worker crashes

### Async Processing
- Non-blocking packet analysis
- Separate processing thread prevents packet drops
- Backpressure handling for high traffic

## Monitoring

The engine provides comprehensive metrics:

```rust
pub struct MlEngineMetrics {
    pub total_requests: u64,
    pub successful_predictions: u64,
    pub failed_predictions: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub average_processing_time_ms: f64,
    pub batch_count: u64,
}
```

## Python Backend

The Python backend (`py_engine.py`) features:

- Persistent model loading
- Batch inference support
- GPU acceleration (if available)
- Structured logging
- Health checks
- Performance tracking

### Running the Python Backend

```bash
# Install dependencies
pip install transformers torch numpy

# Run as a service
python3 py_engine.py --service

# Test single prediction
echo '{"source_ip": "192.168.1.1", "destination_ip": "10.0.0.1", "protocol": "TCP"}' | python3 py_engine.py
```

## Troubleshooting

### Common Issues

1. **Python process fails to start**
   - Ensure Python 3.x is installed
   - Check that required packages are installed
   - Verify `py_engine.py` is in the correct location

2. **Low performance**
   - Increase batch size for better throughput
   - Add more workers for parallel processing
   - Enable GPU support in PyTorch

3. **High memory usage**
   - Reduce cache size
   - Lower number of workers
   - Use a smaller model

### Debug Logging

Enable debug logging to troubleshoot issues:

```rust
env_logger::Builder::from_env(env_logger::Env::default()
    .default_filter_or("debug"))
    .init();
```

## Future Enhancements

- Model hot-reloading without service restart
- Support for multiple models
- A/B testing capabilities
- Real-time model performance tracking
- Automatic model updates
- Distributed processing support 