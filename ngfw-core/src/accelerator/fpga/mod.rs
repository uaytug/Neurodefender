// src/accelerator/fpga/mod.rs

use std::io::Result;

// Module declarations
pub mod verilog;
pub mod driver;

// Re-export main types
pub use driver::{FPGADriver, DriverConfig};
pub use verilog::VerilogConfig;

/// FPGA Accelerator capabilities
#[derive(Debug, Clone)]
pub enum AcceleratorCapability {
    PatternMatching,
    DeepPacketInspection,
    Encryption,
    Compression,
    Custom(String),
}

/// FPGA Configuration
#[derive(Debug, Clone)]
pub struct FPGAConfig {
    /// Device path (e.g., "/dev/fpga0")
    pub device_path: String,
    /// Available capabilities
    pub capabilities: Vec<AcceleratorCapability>,
    /// Buffer size for DMA transfers
    pub buffer_size: usize,
    /// Clock frequency in MHz
    pub clock_freq: u32,
    /// Driver configuration
    pub driver_config: DriverConfig,
    /// Verilog configuration
    pub verilog_config: VerilogConfig,
}

impl Default for FPGAConfig {
    fn default() -> Self {
        Self {
            device_path: "/dev/fpga0".to_string(),
            capabilities: vec![
                AcceleratorCapability::PatternMatching,
                AcceleratorCapability::DeepPacketInspection,
            ],
            buffer_size: 1 << 20, // 1MB
            clock_freq: 200,      // 200MHz
            driver_config: DriverConfig::default(),
            verilog_config: VerilogConfig::default(),
        }
    }
}

/// FPGA Accelerator interface
pub struct FPGAAccelerator {
    /// Configuration
    config: FPGAConfig,
    /// Driver instance
    driver: FPGADriver,
    /// Status
    status: AcceleratorStatus,
}

/// Status of the FPGA accelerator
#[derive(Debug, Clone)]
pub struct AcceleratorStatus {
    /// Power state
    pub powered_on: bool,
    /// Configuration loaded
    pub configured: bool,
    /// Current clock frequency
    pub current_freq: u32,
    /// Temperature in Celsius
    pub temperature: f32,
    /// Utilization percentage
    pub utilization: f32,
}

impl FPGAAccelerator {
    /// Creates a new FPGA accelerator instance
    pub fn new(config: FPGAConfig) -> Result<Self> {
        let driver = FPGADriver::new(&config.driver_config)?;
        
        Ok(Self {
            config,
            driver,
            status: AcceleratorStatus {
                powered_on: false,
                configured: false,
                current_freq: 0,
                temperature: 0.0,
                utilization: 0.0,
            },
        })
    }

    /// Initializes the FPGA with bitstream
    pub fn initialize(&mut self) -> Result<()> {
        // Power up sequence
        self.driver.power_up()?;
        self.status.powered_on = true;

        // Load bitstream
        self.driver.load_bitstream(&self.config.verilog_config)?;
        self.status.configured = true;

        // Set clock frequency
        self.driver.set_clock_freq(self.config.clock_freq)?;
        self.status.current_freq = self.config.clock_freq;

        Ok(())
    }

    /// Processes a batch of data using the FPGA
    pub fn process_batch(&mut self, data: &[u8], operation: &AcceleratorCapability) -> Result<Vec<u8>> {
        // Check if operation is supported
        if !self.config.capabilities.contains(operation) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Operation not supported by FPGA"
            ));
        }

        // Process data using appropriate hardware blocks
        match operation {
            AcceleratorCapability::PatternMatching => {
                self.driver.run_pattern_matching(data)
            },
            AcceleratorCapability::DeepPacketInspection => {
                self.driver.run_dpi(data)
            },
            AcceleratorCapability::Encryption => {
                self.driver.run_encryption(data)
            },
            AcceleratorCapability::Compression => {
                self.driver.run_compression(data)
            },
            AcceleratorCapability::Custom(op) => {
                self.driver.run_custom(data, op)
            },
        }
    }

    /// Updates accelerator status
    pub fn update_status(&mut self) -> Result<()> {
        let temp = self.driver.read_temperature()?;
        let util = self.driver.read_utilization()?;
        
        self.status.temperature = temp;
        self.status.utilization = util;
        
        Ok(())
    }

    /// Returns current accelerator status
    pub fn get_status(&self) -> &AcceleratorStatus {
        &self.status
    }

    /// Shuts down the FPGA
    pub fn shutdown(&mut self) -> Result<()> {
        self.driver.power_down()?;
        self.status.powered_on = false;
        self.status.configured = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fpga_creation() {
        let config = FPGAConfig::default();
        let accelerator = FPGAAccelerator::new(config).unwrap();
        assert!(!accelerator.status.powered_on);
        assert!(!accelerator.status.configured);
    }

    #[test]
    fn test_capabilities() {
        let config = FPGAConfig::default();
        assert!(config.capabilities.contains(&AcceleratorCapability::PatternMatching));
        assert!(config.capabilities.contains(&AcceleratorCapability::DeepPacketInspection));
    }

    #[test]
    fn test_custom_capability() {
        let custom_cap = AcceleratorCapability::Custom("AES-GCM".to_string());
        let config = FPGAConfig {
            capabilities: vec![custom_cap.clone()],
            ..Default::default()
        };
        assert!(config.capabilities.contains(&custom_cap));
    }
}