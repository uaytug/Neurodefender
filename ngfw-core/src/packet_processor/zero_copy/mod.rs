use std::io::Result;

// Module declarations
pub mod ring_buffer;
pub mod memory_pool;
pub mod dma;

// Re-exports of main types for easier access
pub use ring_buffer::{RingBuffer, RingBufferStats};
pub use memory_pool::{MemoryPool, DMABuffer, MemoryPoolStats};
pub use dma::{DMAContext, DMADescriptor};

/// Configuration for zero-copy operations
#[derive(Debug, Clone)]
pub struct ZeroCopyConfig {
    /// Size of the ring buffer (must be power of 2)
    pub ring_buffer_size: usize,
    /// Size of individual DMA buffers
    pub buffer_size: usize,
    /// Maximum number of buffers in the memory pool
    pub max_buffers: usize,
    /// Maximum DMA transfer size
    pub max_transfer_size: usize,
    /// Number of descriptors to process in one batch
    pub batch_size: usize,
}

impl Default for ZeroCopyConfig {
    fn default() -> Self {
        Self {
            ring_buffer_size: 1024,    // Default to 1024 descriptors
            buffer_size: 2048,         // 2KB buffers
            max_buffers: 4096,         // Maximum 4096 buffers
            max_transfer_size: 65536,  // 64KB maximum transfer
            batch_size: 32,            // Process 32 descriptors per batch
        }
    }
}

/// Manages zero-copy packet processing operations
pub struct ZeroCopyManager {
    /// Ring buffer for DMA descriptors
    ring_buffer: RingBuffer,
    /// Memory pool for packet buffers
    memory_pool: MemoryPool,
    /// DMA context for transfers
    dma_context: DMAContext,
    /// Configuration settings
    config: ZeroCopyConfig,
}

impl ZeroCopyManager {
    /// Creates a new zero-copy manager with the specified configuration
    pub fn new(config: ZeroCopyConfig) -> Result<Self> {
        // Create ring buffer
        let ring_buffer = RingBuffer::new(config.ring_buffer_size);
        
        // Create memory pool
        let mut memory_pool = MemoryPool::new(config.buffer_size, config.max_buffers);
        
        // Pre-allocate some buffers (25% of max)
        let pre_alloc_count = config.max_buffers / 4;
        memory_pool.pre_allocate(pre_alloc_count);
        
        // Create DMA context
        let dma_context = DMAContext::new(
            std::sync::Arc::new(tokio::sync::Mutex::new(memory_pool.clone())),
            std::sync::Arc::new(tokio::sync::Mutex::new(ring_buffer.clone())),
            config.max_transfer_size,
            config.batch_size,
        );

        Ok(Self {
            ring_buffer,
            memory_pool,
            dma_context,
            config,
        })
    }

    /// Returns a reference to the DMA context
    pub fn dma_context(&self) -> &DMAContext {
        &self.dma_context
    }

    /// Returns a reference to the ring buffer
    pub fn ring_buffer(&self) -> &RingBuffer {
        &self.ring_buffer
    }

    /// Returns a reference to the memory pool
    pub fn memory_pool(&self) -> &MemoryPool {
        &self.memory_pool
    }

    /// Returns the current configuration
    pub fn config(&self) -> &ZeroCopyConfig {
        &self.config
    }

    /// Returns statistics for all components
    pub fn get_stats(&self) -> ZeroCopyStats {
        ZeroCopyStats {
            ring_buffer_stats: self.ring_buffer.get_stats(),
            memory_pool_stats: self.memory_pool.get_stats(),
        }
    }
}

/// Combined statistics for zero-copy operations
#[derive(Debug)]
pub struct ZeroCopyStats {
    /// Ring buffer statistics
    pub ring_buffer_stats: RingBufferStats,
    /// Memory pool statistics
    pub memory_pool_stats: MemoryPoolStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_copy_manager_creation() {
        let config = ZeroCopyConfig::default();
        let manager = ZeroCopyManager::new(config).unwrap();
        
        assert_eq!(manager.ring_buffer().capacity(), 1024);
        assert!(manager.ring_buffer().is_empty());
    }

    #[test]
    fn test_custom_configuration() {
        let config = ZeroCopyConfig {
            ring_buffer_size: 256,
            buffer_size: 4096,
            max_buffers: 1000,
            max_transfer_size: 32768,
            batch_size: 16,
        };
        
        let manager = ZeroCopyManager::new(config.clone()).unwrap();
        assert_eq!(manager.config().ring_buffer_size, 256);
        assert_eq!(manager.config().buffer_size, 4096);
    }

    #[test]
    fn test_pre_allocation() {
        let config = ZeroCopyConfig {
            max_buffers: 100,
            ..Default::default()
        };
        
        let manager = ZeroCopyManager::new(config).unwrap();
        // Should have pre-allocated 25% of max_buffers
        assert_eq!(manager.memory_pool().allocated_buffers(), 25);
    }
}