use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use thiserror::Error;

use super::header_parser::IpHeader;
use crate::packet_processor::packet_buffer::{PacketBuffer, PacketBufferError};

#[derive(Debug, Error)]
pub enum DefragmentationError {
    #[error("Buffer error: {0}")]
    BufferError(#[from] PacketBufferError),

    #[error("Invalid fragment")]
    InvalidFragment,

    #[error("Fragment overlap")]
    FragmentOverlap,

    #[error("Reassembly timeout")]
    Timeout,

    #[error("Memory limit exceeded")]
    MemoryLimitExceeded,
}

/// Configuration for the defragmentation engine
#[derive(Debug, Clone)]
pub struct DefragmentationConfig {
    /// Maximum time to wait for all fragments
    pub timeout: Duration,
    /// Maximum memory usage for fragments
    pub memory_limit: usize,
    /// Maximum number of concurrent reassemblies
    pub max_reassemblies: usize,
    /// Minimum fragment size
    pub min_fragment_size: usize,
}

impl Default for DefragmentationConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            memory_limit: 16 * 1024 * 1024, // 16MB
            max_reassemblies: 1024,
            min_fragment_size: 64,
        }
    }
}

/// Key used to identify IP fragments belonging to the same packet
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct FragmentKey {
    /// Source IP address
    source: IpAddr,
    /// Destination IP address
    destination: IpAddr,
    /// IP identification field
    identification: u16,
    /// Protocol
    protocol: u8,
}

/// Fragment metadata
#[derive(Debug)]
struct Fragment {
    /// Offset in the original packet
    offset: u16,
    /// Fragment data
    data: Vec<u8>,
    /// More fragments flag
    more_fragments: bool,
}

/// Tracks fragments for a single packet reassembly
#[derive(Debug)]
struct ReassemblyState {
    /// Received fragments
    fragments: Vec<Fragment>,
    /// Total length if known
    total_length: Option<u16>,
    /// Creation time for timeout tracking
    created_at: Instant,
    /// Total memory used by fragments
    memory_used: usize,
}

/// Main defragmentation engine
pub struct Defragmenter {
    /// Configuration
    config: DefragmentationConfig,
    /// Active reassemblies
    reassemblies: HashMap<FragmentKey, ReassemblyState>,
    /// Total memory used
    total_memory: usize,
}

impl Defragmenter {
    /// Creates a new defragmenter with the specified configuration
    pub fn new(config: DefragmentationConfig) -> Self {
        Self {
            config,
            reassemblies: HashMap::new(),
            total_memory: 0,
        }
    }

    /// Process an IP fragment
    pub fn process_fragment(&mut self, packet: &PacketBuffer, header: &IpHeader) 
        -> Result<Option<Vec<u8>>, DefragmentationError> 
    {
        // Create fragment key
        let key = FragmentKey {
            source: header.source,
            destination: header.destination,
            identification: header.identification,
            protocol: header.protocol,
        };

        // Get fragment data
        let data = packet.data()?;
        if data.len() < self.config.min_fragment_size {
            return Err(DefragmentationError::InvalidFragment);
        }

        // Create fragment
        let fragment = Fragment {
            offset: header.fragment_offset,
            data: data.to_vec(),
            more_fragments: header.more_fragments,
        };

        // Process fragment
        self.add_fragment(key, fragment)
    }

    /// Add a fragment to reassembly state
    fn add_fragment(&mut self, key: FragmentKey, fragment: Fragment) 
        -> Result<Option<Vec<u8>>, DefragmentationError> 
    {
        // Check memory limits
        let fragment_size = fragment.data.len();
        if self.total_memory + fragment_size > self.config.memory_limit {
            return Err(DefragmentationError::MemoryLimitExceeded);
        }

        // Get or create reassembly state
        let state = self.reassemblies
            .entry(key.clone())
            .or_insert_with(|| ReassemblyState {
                fragments: Vec::new(),
                total_length: None,
                created_at: Instant::now(),
                memory_used: 0,
            });

        // Check timeout
        if state.created_at.elapsed() > self.config.timeout {
            self.remove_reassembly(&key);
            return Err(DefragmentationError::Timeout);
        }

        // Check overlap
        for existing in &state.fragments {
            if ranges_overlap(
                existing.offset,
                existing.offset + existing.data.len() as u16,
                fragment.offset,
                fragment.offset + fragment.data.len() as u16,
            ) {
                return Err(DefragmentationError::FragmentOverlap);
            }
        }

        // Add fragment
        state.memory_used += fragment_size;
        self.total_memory += fragment_size;
        state.fragments.push(fragment);

        // Check if packet is complete
        if self.is_packet_complete(&state) {
            let reassembled = self.reassemble_packet(&key)?;
            self.remove_reassembly(&key);
            Ok(Some(reassembled))
        } else {
            Ok(None)
        }
    }

    /// Check if all fragments have been received
    fn is_packet_complete(&self, state: &ReassemblyState) -> bool {
        if state.fragments.is_empty() {
            return false;
        }

        // Sort fragments by offset
        let mut fragments: Vec<_> = state.fragments.iter().collect();
        fragments.sort_by_key(|f| f.offset);

        // Check for gaps
        let mut expected_offset = 0u16;
        for fragment in &fragments[..fragments.len() - 1] {
            if fragment.offset != expected_offset {
                return false;
            }
            expected_offset = fragment.offset + fragment.data.len() as u16;
        }

        // Check last fragment
        let last = fragments.last().unwrap();
        last.offset == expected_offset && !last.more_fragments
    }

    /// Reassemble complete packet
    fn reassemble_packet(&self, key: &FragmentKey) -> Result<Vec<u8>, DefragmentationError> {
        let state = self.reassemblies.get(key)
            .ok_or(DefragmentationError::InvalidFragment)?;

        // Sort fragments by offset
        let mut fragments: Vec<_> = state.fragments.iter().collect();
        fragments.sort_by_key(|f| f.offset);

        // Calculate total length
        let total_length: usize = fragments.iter()
            .map(|f| f.data.len())
            .sum();

        // Allocate buffer and copy fragments
        let mut buffer = Vec::with_capacity(total_length);
        for fragment in fragments {
            buffer.extend_from_slice(&fragment.data);
        }

        Ok(buffer)
    }

    /// Remove reassembly state and update memory tracking
    fn remove_reassembly(&mut self, key: &FragmentKey) {
        if let Some(state) = self.reassemblies.remove(key) {
            self.total_memory -= state.memory_used;
        }
    }

    /// Cleanup expired reassemblies
    pub fn cleanup_expired(&mut self) {
        let expired: Vec<_> = self.reassemblies.iter()
            .filter(|(_, state)| state.created_at.elapsed() > self.config.timeout)
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired {
            self.remove_reassembly(&key);
        }
    }
}

/// Check if two ranges overlap
fn ranges_overlap(start1: u16, end1: u16, start2: u16, end2: u16) -> bool {
    start1 < end2 && start2 < end1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_config() -> DefragmentationConfig {
        DefragmentationConfig {
            timeout: Duration::from_secs(1),
            memory_limit: 1024,
            max_reassemblies: 10,
            min_fragment_size: 8,
        }
    }

    fn create_test_key() -> FragmentKey {
        FragmentKey {
            source: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            identification: 1234,
            protocol: 6,
        }
    }

    #[test]
    fn test_ranges_overlap() {
        assert!(ranges_overlap(0, 10, 5, 15));
        assert!(ranges_overlap(5, 15, 0, 10));
        assert!(!ranges_overlap(0, 10, 10, 20));
        assert!(!ranges_overlap(10, 20, 0, 10));
    }

    #[test]
    fn test_fragment_handling() {
        let config = create_test_config();
        let mut defrag = Defragmenter::new(config);
        let key = create_test_key();

        // Add first fragment
        let fragment1 = Fragment {
            offset: 0,
            data: vec![1, 2, 3, 4],
            more_fragments: true,
        };
        
        let result = defrag.add_fragment(key.clone(), fragment1);
        assert!(result.unwrap().is_none());
    }
}