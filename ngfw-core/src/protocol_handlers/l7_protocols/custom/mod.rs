pub mod grpc;
pub mod websocket;

use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::packet_processor::packet_analyzer::ProtocolInfo;
use crate::threat_detection::ml_engine::inference::Engine as MLEngine;
use crate::secure_channel::tls::TLSInspector;

/// Common trait for all custom protocol handlers
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    /// Initialize the protocol handler
    async fn initialize(&self) -> Result<(), Box<dyn std::error::Error>>;

    /// Process incoming data for the protocol
    async fn process_data(&self, data: &[u8]) -> Result<ProtocolInfo, Box<dyn std::error::Error>>;

    /// Clean up any resources used by the handler
    async fn cleanup(&self) -> Result<(), Box<dyn std::error::Error>>;
}

/// Configuration for custom protocol handlers
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    pub enabled: bool,
    pub max_connections: usize,
    pub timeout: std::time::Duration,
    pub tls_inspection: bool,
}

/// Factory for creating protocol handlers
pub struct ProtocolHandlerFactory {
    ml_engine: Arc<MLEngine>,
    tls_inspector: Arc<TLSInspector>,
    config: Arc<RwLock<ProtocolConfig>>,
}

impl ProtocolHandlerFactory {
    pub fn new(
        ml_engine: Arc<MLEngine>,
        tls_inspector: Arc<TLSInspector>,
        config: ProtocolConfig,
    ) -> Self {
        Self {
            ml_engine,
            tls_inspector,
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Create a new gRPC handler
    pub fn create_grpc_handler(&self) -> grpc::GRPCHandler {
        grpc::GRPCHandler::new(
            Arc::clone(&self.ml_engine),
            Arc::clone(&self.tls_inspector),
        )
    }

    /// Create a new WebSocket handler
    pub fn create_websocket_handler(&self) -> websocket::WebSocketHandler {
        websocket::WebSocketHandler::new(
            Arc::clone(&self.ml_engine),
            Arc::clone(&self.tls_inspector),
        )
    }

    /// Update protocol configuration
    pub async fn update_config(&self, config: ProtocolConfig) {
        *self.config.write().await = config;
    }

    /// Get current protocol configuration
    pub async fn get_config(&self) -> ProtocolConfig {
        self.config.read().await.clone()
    }
}

/// Utility functions for protocol handlers
pub mod utils {
    use std::time::{Duration, Instant};

    /// Calculate rate over a time window
    pub fn calculate_rate(count: u64, start_time: Instant) -> f64 {
        let duration = start_time.elapsed();
        if duration.as_secs() == 0 {
            return 0.0;
        }
        count as f64 / duration.as_secs_f64()
    }

    /// Check if duration exceeds timeout
    pub fn is_timeout(start_time: Instant, timeout: Duration) -> bool {
        start_time.elapsed() > timeout
    }

    /// Calculate exponential moving average
    pub fn calculate_ema(current: f64, new_value: f64, alpha: f64) -> f64 {
        alpha * new_value + (1.0 - alpha) * current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_protocol_factory() {
        let config = ProtocolConfig {
            enabled: true,
            max_connections: 1000,
            timeout: std::time::Duration::from_secs(30),
            tls_inspection: true,
        };

        // Create mock ML engine and TLS inspector for testing
        let ml_engine = Arc::new(MLEngine::default());
        let tls_inspector = Arc::new(TLSInspector::default());

        let factory = ProtocolHandlerFactory::new(ml_engine, tls_inspector, config.clone());

        // Test configuration management
        factory.update_config(config.clone()).await;
        let retrieved_config = factory.get_config().await;
        assert_eq!(retrieved_config.max_connections, config.max_connections);

        // Test handler creation
        let grpc_handler = factory.create_grpc_handler();
        let websocket_handler = factory.create_websocket_handler();

        // Add more specific tests as needed
    }

    #[test]
    async fn test_utils() {
        let start_time = Instant::now();
        std::thread::sleep(Duration::from_secs(1));

        // Test rate calculation
        let rate = utils::calculate_rate(100, start_time);
        assert!(rate > 0.0);

        // Test timeout check
        let timeout = Duration::from_secs(2);
        assert!(!utils::is_timeout(start_time, timeout));

        // Test EMA calculation
        let ema = utils::calculate_ema(1.0, 2.0, 0.2);
        assert!((ema - 1.2).abs() < f64::EPSILON);
    }
}