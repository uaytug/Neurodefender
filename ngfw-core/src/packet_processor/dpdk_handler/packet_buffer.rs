use std::ptr;
use std::slice;
use thiserror::Error;
use std::sync::Arc;

use super::memory_pool::{MemoryPool, MemoryPoolError};

#[derive(Debug, Error)]
pub enum PacketBufferError {
    #[error("Memory pool error: {0}")]
    MemoryPoolError(#[from] MemoryPoolError),

    #[error("Failed to allocate packet buffer")]
    AllocationFailed,

    #[error("Buffer capacity exceeded")]
    CapacityExceeded,

    #[error("Invalid buffer operation: {0}")]
    InvalidOperation(String),

    #[error("Null buffer pointer")]
    NullPointer,
}

/// A safe wrapper around DPDK's rte_mbuf
pub struct PacketBuffer {
    /// Raw pointer to DPDK mbuf
    mbuf: *mut dpdk_sys::rte_mbuf,
    /// Reference to the memory pool
    pool: Arc<MemoryPool>,
}

/// Represents a chain of packet buffers
pub struct PacketBufferChain {
    /// Head of the chain
    head: PacketBuffer,
    /// Total length of all buffers in the chain
    total_length: usize,
}

unsafe impl Send for PacketBuffer {}
unsafe impl Sync for PacketBuffer {}

impl PacketBuffer {
    /// Allocates a new packet buffer from the specified memory pool
    pub fn new(pool: Arc<MemoryPool>) -> Result<Self, PacketBufferError> {
        let mbuf = unsafe { pool.alloc_mbuf() }
            .map_err(PacketBufferError::MemoryPoolError)?;

        Ok(Self { mbuf, pool })
    }

    /// Allocates multiple packet buffers at once
    pub fn allocate_bulk(
        pool: Arc<MemoryPool>,
        count: usize,
    ) -> Result<Vec<Self>, PacketBufferError> {
        let mbufs = unsafe { pool.alloc_bulk(count as u32) }
            .map_err(PacketBufferError::MemoryPoolError)?;

        Ok(mbufs
            .into_iter()
            .map(|mbuf| Self {
                mbuf,
                pool: Arc::clone(&pool),
            })
            .collect())
    }

    /// Returns a mutable slice of the packet data
    pub fn data_mut(&mut self) -> Result<&mut [u8], PacketBufferError> {
        unsafe {
            if self.mbuf.is_null() {
                return Err(PacketBufferError::NullPointer);
            }

            let data_ptr = dpdk_sys::rte_pktmbuf_mtod(self.mbuf, *mut u8);
            let data_len = (*self.mbuf).data_len as usize;

            if data_ptr.is_null() {
                return Err(PacketBufferError::NullPointer);
            }

            Ok(slice::from_raw_parts_mut(data_ptr, data_len))
        }
    }

    /// Returns a slice of the packet data
    pub fn data(&self) -> Result<&[u8], PacketBufferError> {
        unsafe {
            if self.mbuf.is_null() {
                return Err(PacketBufferError::NullPointer);
            }

            let data_ptr = dpdk_sys::rte_pktmbuf_mtod(self.mbuf, *const u8);
            let data_len = (*self.mbuf).data_len as usize;

            if data_ptr.is_null() {
                return Err(PacketBufferError::NullPointer);
            }

            Ok(slice::from_raw_parts(data_ptr, data_len))
        }
    }

    /// Prepends data to the buffer
    pub fn prepend(&mut self, data: &[u8]) -> Result<(), PacketBufferError> {
        unsafe {
            if self.mbuf.is_null() {
                return Err(PacketBufferError::NullPointer);
            }

            let headroom = dpdk_sys::rte_pktmbuf_headroom(self.mbuf) as usize;
            if data.len() > headroom {
                return Err(PacketBufferError::CapacityExceeded);
            }

            let prepend_ptr = dpdk_sys::rte_pktmbuf_prepend(self.mbuf, data.len() as u16);
            if prepend_ptr.is_null() {
                return Err(PacketBufferError::InvalidOperation(
                    "Failed to prepend data".to_string()
                ));
            }

            ptr::copy_nonoverlapping(data.as_ptr(), prepend_ptr as *mut u8, data.len());
            Ok(())
        }
    }

    /// Appends data to the buffer
    pub fn append(&mut self, data: &[u8]) -> Result<(), PacketBufferError> {
        unsafe {
            if self.mbuf.is_null() {
                return Err(PacketBufferError::NullPointer);
            }

            let tailroom = dpdk_sys::rte_pktmbuf_tailroom(self.mbuf) as usize;
            if data.len() > tailroom {
                return Err(PacketBufferError::CapacityExceeded);
            }

            let append_ptr = dpdk_sys::rte_pktmbuf_append(self.mbuf, data.len() as u16);
            if append_ptr.is_null() {
                return Err(PacketBufferError::InvalidOperation(
                    "Failed to append data".to_string()
                ));
            }

            ptr::copy_nonoverlapping(data.as_ptr(), append_ptr as *mut u8, data.len());
            Ok(())
        }
    }

    /// Adjusts the data length of the buffer
    pub fn trim(&mut self, len: usize) -> Result<(), PacketBufferError> {
        unsafe {
            if self.mbuf.is_null() {
                return Err(PacketBufferError::NullPointer);
            }

            if dpdk_sys::rte_pktmbuf_trim(self.mbuf, len as u16) < 0 {
                return Err(PacketBufferError::InvalidOperation(
                    "Failed to trim buffer".to_string()
                ));
            }

            Ok(())
        }
    }

    /// Returns the buffer length
    pub fn len(&self) -> usize {
        unsafe {
            if self.mbuf.is_null() {
                return 0;
            }
            (*self.mbuf).data_len as usize
        }
    }

    /// Returns whether the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the total buffer capacity
    pub fn capacity(&self) -> usize {
        unsafe {
            if self.mbuf.is_null() {
                return 0;
            }
            (*self.mbuf).buf_len as usize
        }
    }

    /// Get the raw mbuf pointer
    pub(crate) unsafe fn as_ptr(&self) -> *mut dpdk_sys::rte_mbuf {
        self.mbuf
    }
}

impl PacketBufferChain {
    /// Creates a new chain with an initial buffer
    pub fn new(buffer: PacketBuffer) -> Self {
        let total_length = buffer.len();
        Self {
            head: buffer,
            total_length,
        }
    }

    /// Appends a buffer to the chain
    pub fn append_buffer(&mut self, buffer: PacketBuffer) -> Result<(), PacketBufferError> {
        unsafe {
            if self.head.mbuf.is_null() {
                return Err(PacketBufferError::NullPointer);
            }

            dpdk_sys::rte_pktmbuf_chain(self.head.mbuf, buffer.mbuf);
            self.total_length += buffer.len();
            
            // Buffer is now owned by the chain
            std::mem::forget(buffer);
            
            Ok(())
        }
    }

    /// Returns the total length of all buffers in the chain
    pub fn total_len(&self) -> usize {
        self.total_length
    }

    /// Iterates over all buffers in the chain
    pub fn iter(&self) -> PacketBufferChainIterator {
        PacketBufferChainIterator {
            current: self.head.mbuf,
            _marker: std::marker::PhantomData,
        }
    }
}

pub struct PacketBufferChainIterator<'a> {
    current: *mut dpdk_sys::rte_mbuf,
    _marker: std::marker::PhantomData<&'a PacketBufferChain>,
}

impl<'a> Iterator for PacketBufferChainIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.is_null() {
            return None;
        }

        unsafe {
            let data_ptr = dpdk_sys::rte_pktmbuf_mtod(self.current, *const u8);
            let data_len = (*self.current).data_len as usize;
            self.current = (*self.current).next;

            Some(slice::from_raw_parts(data_ptr, data_len))
        }
    }
}

impl Drop for PacketBuffer {
    fn drop(&mut self) {
        unsafe {
            if !self.mbuf.is_null() {
                dpdk_sys::rte_pktmbuf_free(self.mbuf);
                self.mbuf = ptr::null_mut();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;

    fn create_test_pool() -> Arc<MemoryPool> {
        unsafe {
            MemoryPool::new(
                "test_pool",
                NonZeroU32::new(1024).unwrap(),
                2048,
                0,
                32,
            )
            .unwrap()
            .into()
        }
    }

    #[test]
    fn test_packet_buffer_allocation() {
        let pool = create_test_pool();
        let buffer = PacketBuffer::new(pool).unwrap();
        assert!(buffer.len() == 0);
        assert!(buffer.capacity() > 0);
    }

    #[test]
    fn test_packet_buffer_data_operations() {
        let pool = create_test_pool();
        let mut buffer = PacketBuffer::new(pool).unwrap();
        
        let test_data = b"test data";
        buffer.append(test_data).unwrap();
        
        assert_eq!(buffer.len(), test_data.len());
        assert_eq!(buffer.data().unwrap(), test_data);
    }

    #[test]
    fn test_packet_buffer_chain() {
        let pool = create_test_pool();
        let buffer1 = PacketBuffer::new(Arc::clone(&pool)).unwrap();
        let buffer2 = PacketBuffer::new(Arc::clone(&pool)).unwrap();
        
        let mut chain = PacketBufferChain::new(buffer1);
        chain.append_buffer(buffer2).unwrap();
        
        assert_eq!(chain.total_len(), 0);  // Both buffers are empty
    }
}