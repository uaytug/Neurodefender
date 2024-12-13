//! DPDK handler module for packet processing.
//! 
//! This module provides a safe interface to DPDK (Data Plane Development Kit)
//! functionality, including memory management, packet handling, and queue management.

mod config;
mod init;
mod memory_pool;
mod packet_buffer;
mod queue_manager;

// Re-export primary types and traits
pub use config::{DPDKConfig, NumaConfig, PortConfig, ConfigError};
pub use init::{DPDKContext, DPDKError};
pub use memory_pool::{MemoryPool, MemoryPoolManager, MemoryPoolError};
pub use packet_buffer::{PacketBuffer, PacketBufferChain, PacketBufferError};
pub use queue_manager::{QueueManager, RxQueue, TxQueue, QueueConfig, QueueError};

// Internal types used by the module
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Represents a DPDK port
#[derive(Debug)]
pub struct Port {
    /// Port ID
    id: u16,
    /// Port configuration
    config: PortConfig,
    /// Queue manager
    queue_manager: QueueManager,
    /// Started status
    started: AtomicBool,
}

impl Port {
    /// Creates a new port with the specified configuration
    pub fn new(id: u16, config: PortConfig, memory_pool: Arc<MemoryPool>) -> Result<Self, DPDKError> {
        let queue_manager = QueueManager::new(id, memory_pool);
        
        Ok(Self {
            id,
            config,
            queue_manager,
            started: AtomicBool::new(false),
        })
    }

    /// Returns the port ID
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Returns a reference to the port configuration
    pub fn config(&self) -> &PortConfig {
        &self.config
    }

    /// Returns a mutable reference to the queue manager
    pub fn queue_manager_mut(&mut self) -> &mut QueueManager {
        &mut self.queue_manager
    }
}

/// DPDK handler error consolidating all possible error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("DPDK error: {0}")]
    DPDK(#[from] DPDKError),

    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("Memory pool error: {0}")]
    MemoryPool(#[from] MemoryPoolError),

    #[error("Packet buffer error: {0}")]
    PacketBuffer(#[from] PacketBufferError),

    #[error("Queue error: {0}")]
    Queue(#[from] QueueError),
}

/// Result type for DPDK operations
pub type Result<T> = std::result::Result<T, Error>;

/// Module-wide initialization
pub fn initialize(config: DPDKConfig) -> Result<DPDKContext> {
    DPDKContext::initialize(config).map_err(Error::DPDK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;

    #[test]
    fn test_port_creation() {
        let config = PortConfig {
            rx_queues: NonZeroU32::new(1).unwrap(),
            tx_queues: NonZeroU32::new(1).unwrap(),
            // ... other config fields ...
        };

        let memory_pool = Arc::new(unsafe {
            MemoryPool::new(
                "test_pool",
                NonZeroU32::new(1024).unwrap(),
                2048,
                0,
                32,
            )
            .unwrap()
        });

        let port = Port::new(0, config, memory_pool);
        assert!(port.is_ok());
    }
}