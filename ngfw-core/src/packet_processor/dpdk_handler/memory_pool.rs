use std::ffi::CString;
use std::ptr;
use std::sync::Arc;
use thiserror::Error;

use super::config::DPDKConfig;
use std::num::NonZeroU32;

#[derive(Debug, Error)]
pub enum MemoryPoolError {
    #[error("Failed to create memory pool: {0}")]
    CreationFailed(String),

    #[error("Failed to allocate buffer: {0}")]
    AllocationFailed(String),

    #[error("Invalid pool configuration: {0}")]
    InvalidConfig(String),

    #[error("Pool capacity exceeded")]
    CapacityExceeded,

    #[error("Memory pool not initialized")]
    Uninitialized,
}

/// Represents a DPDK memory pool for packet buffers
pub struct MemoryPool {
    /// Raw pointer to DPDK mempool
    pool: *mut dpdk_sys::rte_mempool,
    /// Number of buffers in the pool
    capacity: NonZeroU32,
    /// Size of each buffer
    buffer_size: u32,
    /// NUMA node ID
    socket_id: u32,
    /// Cache size per core
    cache_size: u32,
}

/// Wrapper for safe memory pool management
pub struct MemoryPoolManager {
    pools: Vec<Arc<MemoryPool>>,
    config: DPDKConfig,
}

unsafe impl Send for MemoryPool {}
unsafe impl Sync for MemoryPool {}

impl MemoryPool {
    /// Creates a new memory pool
    pub unsafe fn new(
        name: &str,
        capacity: NonZeroU32,
        buffer_size: u32,
        socket_id: u32,
        cache_size: u32,
    ) -> Result<Self, MemoryPoolError> {
        // Create a unique pool name
        let pool_name = CString::new(name)
            .map_err(|e| MemoryPoolError::CreationFailed(e.to_string()))?;

        // Calculate required memory size
        let required_mem = Self::calculate_memory_size(capacity.get(), buffer_size, cache_size);
        
        // Create the memory pool
        let pool = dpdk_sys::rte_pktmbuf_pool_create(
            pool_name.as_ptr(),
            capacity.get(),
            cache_size as u32,
            0, // priv_size, using default
            buffer_size as u16,
            socket_id as i32,
        );

        if pool.is_null() {
            return Err(MemoryPoolError::CreationFailed(
                format!("rte_pktmbuf_pool_create failed on socket {}", socket_id)
            ));
        }

        Ok(Self {
            pool,
            capacity,
            buffer_size,
            socket_id,
            cache_size,
        })
    }

    /// Allocates a packet buffer from the pool
    pub unsafe fn alloc_mbuf(&self) -> Result<*mut dpdk_sys::rte_mbuf, MemoryPoolError> {
        let mbuf = dpdk_sys::rte_pktmbuf_alloc(self.pool);
        
        if mbuf.is_null() {
            return Err(MemoryPoolError::AllocationFailed(
                "Failed to allocate packet buffer".to_string()
            ));
        }

        Ok(mbuf)
    }

    /// Allocates a bulk of packet buffers
    pub unsafe fn alloc_bulk(
        &self,
        count: u32,
    ) -> Result<Vec<*mut dpdk_sys::rte_mbuf>, MemoryPoolError> {
        let mut mbufs = Vec::with_capacity(count as usize);
        mbufs.set_len(count as usize);

        let result = dpdk_sys::rte_pktmbuf_alloc_bulk(
            self.pool,
            mbufs.as_mut_ptr(),
            count as u32,
        );

        if result != 0 {
            return Err(MemoryPoolError::AllocationFailed(
                "Failed to allocate bulk packet buffers".to_string()
            ));
        }

        Ok(mbufs)
    }

    /// Returns available space in the pool
    pub fn available_space(&self) -> u32 {
        unsafe { dpdk_sys::rte_mempool_avail_count(self.pool) }
    }

    /// Returns total capacity of the pool
    pub fn capacity(&self) -> u32 {
        self.capacity.get()
    }

    /// Returns the buffer size
    pub fn buffer_size(&self) -> u32 {
        self.buffer_size
    }

    /// Calculate required memory size for the pool
    fn calculate_memory_size(capacity: u32, buffer_size: u32, cache_size: u32) -> u64 {
        let mbuf_size = buffer_size as u64 + std::mem::size_of::<dpdk_sys::rte_mbuf>() as u64;
        let total_buffers = capacity as u64 + (cache_size as u64 * num_cpus::get() as u64);
        mbuf_size * total_buffers
    }
}

impl MemoryPoolManager {
    /// Creates a new memory pool manager
    pub fn new(config: DPDKConfig) -> Self {
        Self {
            pools: Vec::new(),
            config,
        }
    }

    /// Initializes memory pools based on configuration
    pub fn initialize(&mut self) -> Result<(), MemoryPoolError> {
        // Clear existing pools
        self.pools.clear();

        // Create pools for each NUMA node
        for (node_id, &memory_size) in &self.config.numa_config.memory_per_node {
            let pool = self.create_pool_for_node(*node_id, memory_size)?;
            self.pools.push(Arc::new(pool));
        }

        Ok(())
    }

    /// Creates a memory pool for a specific NUMA node
    fn create_pool_for_node(
        &self,
        node_id: u32,
        memory_size: NonZeroU32,
    ) -> Result<MemoryPool, MemoryPoolError> {
        let cache_size = self.calculate_cache_size();
        let pool_name = format!("mbuf_pool_{}", node_id);

        unsafe {
            MemoryPool::new(
                &pool_name,
                self.config.nb_desc,
                dpdk_sys::RTE_MBUF_DEFAULT_BUF_SIZE as u32,
                node_id,
                cache_size,
            )
        }
    }

    /// Calculates optimal cache size based on configuration
    fn calculate_cache_size(&self) -> u32 {
        let base_cache_size = (self.config.nb_desc.get() / self.config.max_lcores.get())
            .min(512) // Maximum cache size
            .max(32); // Minimum cache size

        // Round to nearest power of 2
        let power = (base_cache_size as f64).log2().ceil() as u32;
        1 << power
    }

    /// Gets a memory pool for a specific NUMA node
    pub fn get_pool(&self, socket_id: u32) -> Option<Arc<MemoryPool>> {
        self.pools
            .iter()
            .find(|pool| unsafe { pool.socket_id == socket_id })
            .cloned()
    }

    /// Gets the optimal pool for the current CPU
    pub fn get_optimal_pool(&self) -> Option<Arc<MemoryPool>> {
        let current_socket = unsafe { dpdk_sys::rte_socket_id() as u32 };
        self.get_pool(current_socket)
            .or_else(|| self.pools.first().cloned())
    }
}

impl Drop for MemoryPool {
    fn drop(&mut self) {
        unsafe {
            if !self.pool.is_null() {
                dpdk_sys::rte_mempool_free(self.pool);
                self.pool = ptr::null_mut();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;

    #[test]
    fn test_memory_pool_manager_creation() {
        let config = DPDKConfig::default();
        let manager = MemoryPoolManager::new(config);
        assert!(manager.pools.is_empty());
    }

    #[test]
    fn test_cache_size_calculation() {
        let mut config = DPDKConfig::default();
        config.nb_desc = NonZeroU32::new(1024).unwrap();
        config.max_lcores = NonZeroU32::new(16).unwrap();
        
        let manager = MemoryPoolManager::new(config);
        let cache_size = manager.calculate_cache_size();
        
        assert!(cache_size >= 32);
        assert!(cache_size <= 512);
        // Verify it's a power of 2
        assert_eq!(cache_size & (cache_size - 1), 0);
    }

    #[test]
    fn test_memory_size_calculation() {
        let capacity = 1024;
        let buffer_size = 2048;
        let cache_size = 32;
        
        let size = MemoryPool::calculate_memory_size(capacity, buffer_size, cache_size);
        assert!(size > 0);
    }
}