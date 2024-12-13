use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;

#[derive(Debug, Clone)]
pub struct DPDKConfig {
    /// Number of memory channels
    pub memory_channels: NonZeroU32,
    /// Size of memory pool in MB
    pub memory_pool_size: NonZeroU32,
    /// Number of descriptors per queue
    pub nb_desc: NonZeroU32,
    /// Maximum number of lcores to use
    pub max_lcores: NonZeroU32,
    /// Size of hugepage in GB
    pub hugepage_size: NonZeroU32,
    /// NUMA node configurations
    pub numa_config: NumaConfig,
    /// NIC-specific configurations
    pub port_configs: HashMap<String, PortConfig>,
    /// Additional DPDK parameters
    pub extra_params: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct NumaConfig {
    /// Memory allocation policy
    pub policy: NumaPolicy,
    /// Memory allocated per node in GB
    pub memory_per_node: HashMap<u32, NonZeroU32>,
}

#[derive(Debug, Clone)]
pub struct PortConfig {
    /// Number of RX queues
    pub rx_queues: NonZeroU32,
    /// Number of TX queues
    pub tx_queues: NonZeroU32,
    /// RSS (Receive Side Scaling) configuration
    pub rss_config: RSSConfig,
    /// Hardware offload configurations
    pub offload_config: OffloadConfig,
}

#[derive(Debug, Clone)]
pub struct RSSConfig {
    /// RSS hash functions to enable
    pub hash_functions: Vec<RSSHashFunction>,
    /// RSS key
    pub hash_key: [u8; 40],
    /// Queue mapping policy
    pub queue_policy: RSSQueuePolicy,
}

#[derive(Debug, Clone)]
pub struct OffloadConfig {
    /// Enable TCP segmentation offload
    pub tcp_tso: bool,
    /// Enable UDP segmentation offload
    pub udp_tso: bool,
    /// Enable RX checksum verification
    pub rx_checksum: bool,
    /// Enable TX checksum generation
    pub tx_checksum: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NumaPolicy {
    Strict,
    Preferred,
    Interleaved,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RSSHashFunction {
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    TcpIpv4,
    UdpIpv4,
    TcpIpv6,
    UdpIpv6,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RSSQueuePolicy {
    Symmetric,
    Simple,
    Custom,
}

impl Default for DPDKConfig {
    fn default() -> Self {
        Self {
            memory_channels: NonZeroU32::new(4).unwrap(),
            memory_pool_size: NonZeroU32::new(8192).unwrap(), // 8GB
            nb_desc: NonZeroU32::new(1024).unwrap(),
            max_lcores: NonZeroU32::new(32).unwrap(),
            hugepage_size: NonZeroU32::new(1).unwrap(), // 1GB
            numa_config: NumaConfig::default(),
            port_configs: HashMap::new(),
            extra_params: HashMap::new(),
        }
    }
}

impl Default for NumaConfig {
    fn default() -> Self {
        let mut memory_per_node = HashMap::new();
        memory_per_node.insert(0, NonZeroU32::new(4).unwrap()); // 4GB for node 0
        Self {
            policy: NumaPolicy::Preferred,
            memory_per_node,
        }
    }
}

impl DPDKConfig {
    /// Creates a new DPDK configuration with custom parameters
    pub fn new(
        memory_channels: NonZeroU32,
        memory_pool_size: NonZeroU32,
        nb_desc: NonZeroU32,
        max_lcores: NonZeroU32,
    ) -> Self {
        Self {
            memory_channels,
            memory_pool_size,
            nb_desc,
            max_lcores,
            ..Default::default()
        }
    }

    /// Adds a port configuration
    pub fn add_port_config(&mut self, port_name: String, config: PortConfig) {
        self.port_configs.insert(port_name, config);
    }

    /// Sets NUMA configuration
    pub fn set_numa_config(&mut self, config: NumaConfig) {
        self.numa_config = config;
    }

    /// Validates the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate memory configuration
        if self.memory_pool_size.get() < 1024 {
            return Err(ConfigError::InvalidMemorySize);
        }

        // Validate descriptor configuration
        if self.nb_desc.get() < 64 || self.nb_desc.get() > 4096 {
            return Err(ConfigError::InvalidDescriptorCount);
        }

        // Validate port configurations
        for (port_name, config) in &self.port_configs {
            if config.rx_queues.get() > 256 || config.tx_queues.get() > 256 {
                return Err(ConfigError::InvalidQueueCount(port_name.clone()));
            }
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Invalid memory pool size")]
    InvalidMemorySize,
    #[error("Invalid descriptor count")]
    InvalidDescriptorCount,
    #[error("Invalid queue count for port {0}")]
    InvalidQueueCount(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DPDKConfig::default();
        assert_eq!(config.memory_channels.get(), 4);
        assert_eq!(config.memory_pool_size.get(), 8192);
        assert_eq!(config.nb_desc.get(), 1024);
    }

    #[test]
    fn test_custom_config() {
        let config = DPDKConfig::new(
            NonZeroU32::new(8).unwrap(),
            NonZeroU32::new(16384).unwrap(),
            NonZeroU32::new(2048).unwrap(),
            NonZeroU32::new(64).unwrap(),
        );
        assert_eq!(config.memory_channels.get(), 8);
        assert_eq!(config.memory_pool_size.get(), 16384);
        assert_eq!(config.nb_desc.get(), 2048);
    }

    #[test]
    fn test_validation() {
        let mut config = DPDKConfig::default();
        assert!(config.validate().is_ok());

        // Test invalid memory size
        config.memory_pool_size = NonZeroU32::new(512).unwrap();
        assert!(matches!(config.validate(), Err(ConfigError::InvalidMemorySize)));
    }
}