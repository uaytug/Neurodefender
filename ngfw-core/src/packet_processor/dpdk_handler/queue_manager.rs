use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use thiserror::Error;

use super::memory_pool::MemoryPool;
use super::packet_buffer::{PacketBuffer, PacketBufferError};

#[derive(Debug, Error)]
pub enum QueueError {
    #[error("Failed to configure queue: {0}")]
    ConfigurationError(String),

    #[error("Failed to start queue: {0}")]
    StartError(String),

    #[error("Failed to stop queue: {0}")]
    StopError(String),

    #[error("Buffer error: {0}")]
    BufferError(#[from] PacketBufferError),

    #[error("Queue is full")]
    QueueFull,

    #[error("Queue is empty")]
    QueueEmpty,

    #[error("Invalid queue ID: {0}")]
    InvalidQueueId(u16),
}

/// Represents a DPDK RX queue
pub struct RxQueue {
    /// Port ID
    port_id: u16,
    /// Queue ID
    queue_id: u16,
    /// Memory pool for packet buffers
    memory_pool: Arc<MemoryPool>,
    /// Queue statistics
    stats: RxQueueStats,
}

/// Represents a DPDK TX queue
pub struct TxQueue {
    /// Port ID
    port_id: u16,
    /// Queue ID
    queue_id: u16,
    /// Queue statistics
    stats: TxQueueStats,
}

/// Statistics for RX queue
#[derive(Default)]
pub struct RxQueueStats {
    packets_received: AtomicU16,
    bytes_received: AtomicU16,
    errors: AtomicU16,
    dropped: AtomicU16,
    no_buffer_drops: AtomicU16,
}

/// Statistics for TX queue
#[derive(Default)]
pub struct TxQueueStats {
    packets_sent: AtomicU16,
    bytes_sent: AtomicU16,
    errors: AtomicU16,
}

/// Queue configuration parameters
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Number of descriptors
    pub nb_desc: u16,
    /// Hardware offload configuration
    pub offloads: u64,
    /// Queue threshold configuration
    pub threshold: QueueThreshold,
}

/// Queue threshold configuration
#[derive(Debug, Clone)]
pub struct QueueThreshold {
    /// Prefetch threshold
    pub pthresh: u8,
    /// Host threshold
    pub hthresh: u8,
    /// Write-back threshold
    pub wthresh: u8,
}

impl RxQueue {
    /// Creates a new RX queue
    pub fn new(
        port_id: u16,
        queue_id: u16,
        memory_pool: Arc<MemoryPool>,
        config: &QueueConfig,
    ) -> Result<Self, QueueError> {
        unsafe {
            // Configure RX queue
            let mut rx_conf = std::mem::zeroed::<dpdk_sys::rte_eth_rxconf>();
            rx_conf.rx_thresh = dpdk_sys::rte_eth_thresh {
                pthresh: config.threshold.pthresh,
                hthresh: config.threshold.hthresh,
                wthresh: config.threshold.wthresh,
            };
            rx_conf.offloads = config.offloads;

            if dpdk_sys::rte_eth_rx_queue_setup(
                port_id,
                queue_id,
                config.nb_desc,
                dpdk_sys::rte_eth_dev_socket_id(port_id) as u32,
                &rx_conf,
                memory_pool.as_ptr() as *mut dpdk_sys::rte_mempool,
            ) != 0 {
                return Err(QueueError::ConfigurationError(
                    format!("Failed to configure RX queue {}", queue_id)
                ));
            }
        }

        Ok(Self {
            port_id,
            queue_id,
            memory_pool,
            stats: RxQueueStats::default(),
        })
    }

    /// Receives packets from the queue
    pub fn receive(&mut self, max_packets: u16) -> Result<Vec<PacketBuffer>, QueueError> {
        let mut mbufs = Vec::with_capacity(max_packets as usize);
        mbufs.resize(max_packets as usize, std::ptr::null_mut());

        let received = unsafe {
            dpdk_sys::rte_eth_rx_burst(
                self.port_id,
                self.queue_id,
                mbufs.as_mut_ptr(),
                max_packets,
            )
        };

        let mut packets = Vec::with_capacity(received as usize);
        for i in 0..received as usize {
            let mbuf = mbufs[i];
            if !mbuf.is_null() {
                packets.push(PacketBuffer::from_mbuf(mbuf, Arc::clone(&self.memory_pool)));
            }
        }

        // Update statistics
        self.stats.packets_received.fetch_add(received, Ordering::Relaxed);

        Ok(packets)
    }

    /// Returns the current statistics
    pub fn stats(&self) -> RxQueueStats {
        self.stats.clone()
    }
}

impl TxQueue {
    /// Creates a new TX queue
    pub fn new(
        port_id: u16,
        queue_id: u16,
        config: &QueueConfig,
    ) -> Result<Self, QueueError> {
        unsafe {
            // Configure TX queue
            let mut tx_conf = std::mem::zeroed::<dpdk_sys::rte_eth_txconf>();
            tx_conf.tx_thresh = dpdk_sys::rte_eth_thresh {
                pthresh: config.threshold.pthresh,
                hthresh: config.threshold.hthresh,
                wthresh: config.threshold.wthresh,
            };
            tx_conf.offloads = config.offloads;

            if dpdk_sys::rte_eth_tx_queue_setup(
                port_id,
                queue_id,
                config.nb_desc,
                dpdk_sys::rte_eth_dev_socket_id(port_id) as u32,
                &tx_conf,
            ) != 0 {
                return Err(QueueError::ConfigurationError(
                    format!("Failed to configure TX queue {}", queue_id)
                ));
            }
        }

        Ok(Self {
            port_id,
            queue_id,
            stats: TxQueueStats::default(),
        })
    }

    /// Transmits packets through the queue
    pub fn transmit(&mut self, packets: &[PacketBuffer]) -> Result<u16, QueueError> {
        if packets.is_empty() {
            return Ok(0);
        }

        let mbufs: Vec<_> = packets.iter()
            .map(|p| unsafe { p.as_ptr() })
            .collect();

        let sent = unsafe {
            dpdk_sys::rte_eth_tx_burst(
                self.port_id,
                self.queue_id,
                mbufs.as_ptr(),
                packets.len() as u16,
            )
        };

        // Update statistics
        self.stats.packets_sent.fetch_add(sent, Ordering::Relaxed);

        Ok(sent)
    }

    /// Returns the current statistics
    pub fn stats(&self) -> TxQueueStats {
        self.stats.clone()
    }
}

/// Queue manager to handle multiple RX and TX queues
pub struct QueueManager {
    rx_queues: Vec<RxQueue>,
    tx_queues: Vec<TxQueue>,
    port_id: u16,
    memory_pool: Arc<MemoryPool>,
}

impl QueueManager {
    /// Creates a new queue manager
    pub fn new(
        port_id: u16,
        memory_pool: Arc<MemoryPool>,
    ) -> Self {
        Self {
            rx_queues: Vec::new(),
            tx_queues: Vec::new(),
            port_id,
            memory_pool,
        }
    }

    /// Configures queues based on the provided configuration
    pub fn configure(
        &mut self,
        nb_rx_queues: u16,
        nb_tx_queues: u16,
        config: &QueueConfig,
    ) -> Result<(), QueueError> {
        // Configure RX queues
        for queue_id in 0..nb_rx_queues {
            let rx_queue = RxQueue::new(
                self.port_id,
                queue_id,
                Arc::clone(&self.memory_pool),
                config,
            )?;
            self.rx_queues.push(rx_queue);
        }

        // Configure TX queues
        for queue_id in 0..nb_tx_queues {
            let tx_queue = TxQueue::new(self.port_id, queue_id, config)?;
            self.tx_queues.push(tx_queue);
        }

        Ok(())
    }

    /// Gets a reference to an RX queue
    pub fn get_rx_queue(&mut self, queue_id: u16) -> Result<&mut RxQueue, QueueError> {
        self.rx_queues
            .get_mut(queue_id as usize)
            .ok_or_else(|| QueueError::InvalidQueueId(queue_id))
    }

    /// Gets a reference to a TX queue
    pub fn get_tx_queue(&mut self, queue_id: u16) -> Result<&mut TxQueue, QueueError> {
        self.tx_queues
            .get_mut(queue_id as usize)
            .ok_or_else(|| QueueError::InvalidQueueId(queue_id))
    }

    /// Returns the number of RX queues
    pub fn nb_rx_queues(&self) -> u16 {
        self.rx_queues.len() as u16
    }

    /// Returns the number of TX queues
    pub fn nb_tx_queues(&self) -> u16 {
        self.tx_queues.len() as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;

    fn create_test_config() -> QueueConfig {
        QueueConfig {
            nb_desc: 1024,
            offloads: 0,
            threshold: QueueThreshold {
                pthresh: 8,
                hthresh: 8,
                wthresh: 4,
            },
        }
    }

    #[test]
    fn test_queue_manager_creation() {
        let pool = Arc::new(unsafe {
            MemoryPool::new(
                "test_pool",
                NonZeroU32::new(1024).unwrap(),
                2048,
                0,
                32,
            )
            .unwrap()
        });

        let manager = QueueManager::new(0, pool);
        assert_eq!(manager.nb_rx_queues(), 0);
        assert_eq!(manager.nb_tx_queues(), 0);
    }

    #[test]
    fn test_queue_config() {
        let config = create_test_config();
        assert_eq!(config.nb_desc, 1024);
        assert_eq!(config.threshold.pthresh, 8);
    }
}