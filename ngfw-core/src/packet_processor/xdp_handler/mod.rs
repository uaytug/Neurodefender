//! XDP (eXpress Data Path) handler module for high-performance packet processing.
//! 
//! This module provides functionality for loading, managing, and interacting with
//! XDP programs, including maps, program lifecycle, and helper functions.

mod helpers;
mod program;
mod maps;
mod verifier;

// Re-export primary types and functionality
pub use helpers::{
    XdpMapHelper, XdpPacketHelper, XdpContextHelper,
    XdpRedirectHelper, XdpHelperError, MapFlags,
};

pub use program::{
    XdpProgram, ProgramError, XdpProgramConfig,
    XdpAction, ProgramStats,
};

pub use maps::{
    MapDefinition, MapType, MapConfig, MapError,
    MapFlags as BpfMapFlags,
};

pub use verifier::{
    ProgramVerifier, VerificationError,
    VerifierLog, VerifierConfig,
};

use std::path::PathBuf;
use thiserror::Error;
use libbpf_sys as bpf;

/// Combined error type for XDP operations
#[derive(Debug, Error)]
pub enum XdpError {
    #[error("Program error: {0}")]
    Program(#[from] ProgramError),

    #[error("Map error: {0}")]
    Map(#[from] MapError),

    #[error("Helper error: {0}")]
    Helper(#[from] XdpHelperError),

    #[error("Verification error: {0}")]
    Verification(#[from] VerificationError),

    #[error("System error: {0}")]
    System(#[from] std::io::Error),
}

/// XDP program mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XdpMode {
    /// Native XDP mode
    Native,
    /// Generic/SKB mode
    Generic,
    /// Hardware offload mode
    Offload,
}

/// Configuration for XDP handler
#[derive(Debug, Clone)]
pub struct XdpConfig {
    /// Program mode
    pub mode: XdpMode,
    /// Program path or bytecode
    pub program: ProgramSource,
    /// Program configurations
    pub program_config: XdpProgramConfig,
    /// Map configurations
    pub map_configs: Vec<MapConfig>,
    /// Verifier configuration
    pub verifier_config: VerifierConfig,
}

/// Program source
#[derive(Debug, Clone)]
pub enum ProgramSource {
    /// Path to program file
    Path(PathBuf),
    /// Raw bytecode
    Bytecode(Vec<u8>),
}

/// Main XDP handler
pub struct XdpHandler {
    /// Loaded XDP program
    program: XdpProgram,
    /// Map helpers
    maps: std::collections::HashMap<String, XdpMapHelper>,
    /// Program verifier
    verifier: ProgramVerifier,
    /// Handler configuration
    config: XdpConfig,
}

impl XdpHandler {
    /// Create a new XDP handler
    pub fn new(config: XdpConfig) -> Result<Self, XdpError> {
        // Initialize program verifier
        let verifier = ProgramVerifier::new(config.verifier_config.clone());

        // Load and verify program
        let program = match &config.program {
            ProgramSource::Path(path) => {
                XdpProgram::load_from_file(path, &config.program_config)?
            },
            ProgramSource::Bytecode(code) => {
                XdpProgram::load_from_bytecode(code, &config.program_config)?
            },
        };

        // Verify program
        verifier.verify_program(&program)?;

        // Initialize maps
        let mut maps = std::collections::HashMap::new();
        for map_config in &config.map_configs {
            let map_fd = program.get_map_fd(&map_config.name)?;
            maps.insert(
                map_config.name.clone(),
                XdpMapHelper::new(map_fd),
            );
        }

        Ok(Self {
            program,
            maps,
            verifier,
            config,
        })
    }

    /// Attach XDP program to interface
    pub fn attach(&self, interface: &str) -> Result<(), XdpError> {
        let flags = match self.config.mode {
            XdpMode::Native => bpf::XDP_FLAGS_DRV_MODE,
            XdpMode::Generic => bpf::XDP_FLAGS_SKB_MODE,
            XdpMode::Offload => bpf::XDP_FLAGS_HW_MODE,
        };

        self.program.attach(interface, flags)?;
        Ok(())
    }

    /// Detach XDP program from interface
    pub fn detach(&self, interface: &str) -> Result<(), XdpError> {
        self.program.detach(interface)?;
        Ok(())
    }

    /// Get map helper by name
    pub fn get_map(&self, name: &str) -> Option<&XdpMapHelper> {
        self.maps.get(name)
    }

    /// Get program statistics
    pub fn get_stats(&self) -> Result<ProgramStats, XdpError> {
        self.program.get_stats()
    }

    /// Update program
    pub fn update_program(&mut self, new_source: ProgramSource) -> Result<(), XdpError> {
        // Load and verify new program
        let new_program = match new_source {
            ProgramSource::Path(path) => {
                XdpProgram::load_from_file(&path, &self.config.program_config)?
            },
            ProgramSource::Bytecode(code) => {
                XdpProgram::load_from_bytecode(&code, &self.config.program_config)?
            },
        };

        // Verify new program
        self.verifier.verify_program(&new_program)?;

        // Replace old program
        let old_program = std::mem::replace(&mut self.program, new_program);
        
        // Clean up old program
        drop(old_program);

        Ok(())
    }
}

impl Drop for XdpHandler {
    fn drop(&mut self) {
        // Cleanup will be handled by individual components
        // through their own Drop implementations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn create_test_config() -> XdpConfig {
        XdpConfig {
            mode: XdpMode::Generic,
            program: ProgramSource::Path(PathBuf::from("test_program.o")),
            program_config: XdpProgramConfig::default(),
            map_configs: vec![],
            verifier_config: VerifierConfig::default(),
        }
    }

    #[test]
    fn test_mode_conversion() {
        assert_eq!(
            XdpMode::Native as i32,
            bpf::XDP_FLAGS_DRV_MODE
        );
    }

    #[test]
    fn test_config_creation() {
        let config = create_test_config();
        assert_eq!(config.mode, XdpMode::Generic);
    }
}