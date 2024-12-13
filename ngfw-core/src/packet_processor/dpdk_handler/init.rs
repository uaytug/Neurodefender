use std::ffi::{CString, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

use super::config::{DPDKConfig, PortConfig, ConfigError};

/// Tracks DPDK initialization state
static DPDK_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Error)]
pub enum DPDKError {
    #[error("DPDK already initialized")]
    AlreadyInitialized,
    
    #[error("DPDK initialization failed: {0}")]
    InitializationFailed(String),
    
    #[error("Port initialization failed: {0}")]
    PortInitializationFailed(String),
    
    #[error("Memory allocation failed: {0}")]
    MemoryAllocationFailed(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(#[from] ConfigError),
    
    #[error("System error: {0}")]
    SystemError(String),
}

pub struct DPDKContext {
    /// Memory pool handlers
    memory_pools: Vec<*mut c_void>,
    /// Initialized port handlers
    port_handlers: Vec<*mut c_void>,
    /// Configuration used for initialization
    config: DPDKConfig,
}

impl DPDKContext {
    /// Initialize DPDK with the provided configuration
    pub fn initialize(config: DPDKConfig) -> Result<Self, DPDKError> {
        // Ensure DPDK isn't already initialized
        if DPDK_INITIALIZED.load(Ordering::SeqCst) {
            return Err(DPDKError::AlreadyInitialized);
        }

        // Validate configuration
        config.validate()?;

        // Convert configuration to EAL arguments
        let eal_args = Self::prepare_eal_args(&config)?;
        
        // Initialize EAL
        unsafe {
            Self::init_eal(&eal_args)?;
        }

        // Initialize memory pools
        let memory_pools = unsafe {
            Self::init_memory_pools(&config)?
        };

        // Initialize ports
        let port_handlers = unsafe {
            Self::init_ports(&config)?
        };

        // Mark DPDK as initialized
        DPDK_INITIALIZED.store(true, Ordering::SeqCst);

        Ok(Self {
            memory_pools,
            port_handlers,
            config,
        })
    }

    /// Prepare EAL (Environment Abstraction Layer) arguments
    fn prepare_eal_args(config: &DPDKConfig) -> Result<Vec<CString>, DPDKError> {
        let mut args = Vec::new();

        // Add program name
        args.push(CString::new("neurodefender-ngfw").unwrap());

        // Memory channels
        args.push(CString::new("-n").unwrap());
        args.push(CString::new(config.memory_channels.get().to_string()).unwrap());

        // Hugepage configuration
        args.push(CString::new("--huge-dir").unwrap());
        args.push(CString::new("/dev/hugepages").unwrap());

        // NUMA configuration
        if let Some(socket_mem) = Self::format_socket_mem(&config.numa_config.memory_per_node) {
            args.push(CString::new("--socket-mem").unwrap());
            args.push(CString::new(socket_mem).unwrap());
        }

        // Add extra parameters
        for (key, value) in &config.extra_params {
            args.push(CString::new(format!("--{}", key)).unwrap());
            if !value.is_empty() {
                args.push(CString::new(value.clone()).unwrap());
            }
        }

        Ok(args)
    }

    /// Initialize the EAL
    unsafe fn init_eal(args: &[CString]) -> Result<(), DPDKError> {
        let mut argv: Vec<*mut i8> = args.iter()
            .map(|arg| arg.as_ptr() as *mut i8)
            .collect();

        // Call DPDK's EAL initialization
        if dpdk_sys::rte_eal_init(argv.len() as i32, argv.as_mut_ptr()) < 0 {
            return Err(DPDKError::InitializationFailed(
                "EAL initialization failed".to_string()
            ));
        }

        Ok(())
    }

    /// Initialize memory pools
    unsafe fn init_memory_pools(config: &DPDKConfig) -> Result<Vec<*mut c_void>, DPDKError> {
        let mut pools = Vec::new();

        // Calculate cache size based on number of lcores
        let cache_size = (config.nb_desc.get() / config.max_lcores.get())
            .min(512) // Maximum cache size
            .max(32); // Minimum cache size

        // Create memory pool for each NUMA node
        for (node_id, _) in &config.numa_config.memory_per_node {
            let pool_name = CString::new(format!("mbuf_pool_{}", node_id)).unwrap();
            
            let pool = dpdk_sys::rte_pktmbuf_pool_create(
                pool_name.as_ptr(),
                config.nb_desc.get(),
                cache_size,
                0, // Private data size
                dpdk_sys::RTE_MBUF_DEFAULT_BUF_SIZE as u16,
                *node_id as i32,
            );

            if pool.is_null() {
                return Err(DPDKError::MemoryAllocationFailed(
                    format!("Failed to create memory pool for NUMA node {}", node_id)
                ));
            }

            pools.push(pool as *mut c_void);
        }

        Ok(pools)
    }

    /// Initialize network ports
    unsafe fn init_ports(config: &DPDKConfig) -> Result<Vec<*mut c_void>, DPDKError> {
        let mut handlers = Vec::new();

        for (port_name, port_config) in &config.port_configs {
            let port = Self::init_single_port(port_name, port_config)?;
            handlers.push(port);
        }

        Ok(handlers)
    }

    /// Initialize a single network port
    unsafe fn init_single_port(
        port_name: &str,
        config: &PortConfig
    ) -> Result<*mut c_void, DPDKError> {
        // Port configuration logic
        // This is a placeholder - actual implementation would configure:
        // - RSS settings
        // - Hardware offload features
        // - Queue setup
        // - Flow rules
        unimplemented!("Port initialization to be implemented")
    }

    /// Format socket memory configuration string
    fn format_socket_mem(memory_per_node: &std::collections::HashMap<u32, std::num::NonZeroU32>) -> Option<String> {
        if memory_per_node.is_empty() {
            return None;
        }

        let max_socket = *memory_per_node.keys().max()?;
        let mut mem_values = vec!["0"; (max_socket + 1) as usize];

        for (socket, memory) in memory_per_node {
            mem_values[*socket as usize] = &memory.get().to_string();
        }

        Some(mem_values.join(","))
    }
}

impl Drop for DPDKContext {
    fn drop(&mut self) {
        unsafe {
            // Clean up memory pools
            for pool in &self.memory_pools {
                dpdk_sys::rte_mempool_free(*pool as *mut dpdk_sys::rte_mempool);
            }

            // Clean up port handlers
            for port in &self.port_handlers {
                dpdk_sys::rte_eth_dev_close(*port as u16);
            }

            // Clean up EAL
            dpdk_sys::rte_eal_cleanup();
        }

        DPDK_INITIALIZED.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;

    #[test]
    fn test_eal_args_preparation() {
        let config = DPDKConfig::default();
        let args = DPDKContext::prepare_eal_args(&config).unwrap();
        
        assert!(args.len() >= 5); // At minimum: program name, -n, channels, huge-dir, path
        assert_eq!(args[0].to_str().unwrap(), "neurodefender-ngfw");
    }

    #[test]
    fn test_socket_mem_formatting() {
        let mut memory_map = std::collections::HashMap::new();
        memory_map.insert(0, NonZeroU32::new(1024).unwrap());
        memory_map.insert(1, NonZeroU32::new(1024).unwrap());
        
        let socket_mem = DPDKContext::format_socket_mem(&memory_map).unwrap();
        assert_eq!(socket_mem, "1024,1024");
    }
}