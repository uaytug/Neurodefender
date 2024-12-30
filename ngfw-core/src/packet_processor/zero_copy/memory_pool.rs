use std::alloc::{alloc, dealloc, Layout};
use std::collections::VecDeque;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Represents a memory buffer aligned for DMA operations
#[repr(C, align(64))]
pub struct DMABuffer {
    /// Pointer to the allocated memory
    ptr: NonNull<u8>,
    /// Size of the buffer
    size: usize,
    /// Original layout used for deallocation
    layout: Layout,
}

impl DMABuffer {
    /// Creates a new DMA buffer with the specified size
    fn new(size: usize) -> Option<Self> {
        // Ensure size is aligned to cache line
        let aligned_size = (size + 63) & !63;
        
        // Create memory layout for aligned allocation
        let layout = Layout::from_size_align(aligned_size, 64).ok()?;
        
        // Allocate memory
        let ptr = unsafe {
            NonNull::new(alloc(layout))
        }?;
        
        Some(Self {
            ptr,
            size: aligned_size,
            layout,
        })
    }

    /// Returns the address of the buffer
    pub fn addr(&self) -> usize {
        self.ptr.as_ptr() as usize
    }

    /// Returns a mutable pointer to the buffer
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Returns the size of the buffer
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for DMABuffer {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

/// Memory pool for managing DMA buffers
pub struct MemoryPool {
    /// Available buffers in the pool
    available_buffers: VecDeque<DMABuffer>,
    /// Size of each buffer in the pool
    buffer_size: usize,
    /// Maximum number of buffers in the pool
    max_buffers: usize,
    /// Current number of allocated buffers
    allocated_buffers: AtomicUsize,
    /// Statistics for monitoring
    stats: MemoryPoolStats,
}

/// Statistics for memory pool monitoring
#[derive(Debug, Default)]
pub struct MemoryPoolStats {
    /// Total number of allocations
    allocations: AtomicUsize,
    /// Total number of deallocations
    deallocations: AtomicUsize,
    /// Number of allocation failures
    allocation_failures: AtomicUsize,
    /// Peak number of buffers in use
    peak_usage: AtomicUsize,
}

impl MemoryPool {
    /// Creates a new memory pool with specified buffer size and maximum number of buffers
    pub fn new(buffer_size: usize, max_buffers: usize) -> Self {
        Self {
            available_buffers: VecDeque::with_capacity(max_buffers),
            buffer_size,
            max_buffers,
            allocated_buffers: AtomicUsize::new(0),
            stats: MemoryPoolStats::default(),
        }
    }

    /// Allocates a buffer from the pool
    pub fn allocate(&mut self, size: usize) -> Option<DMABuffer> {
        if size > self.buffer_size {
            self.stats.allocation_failures.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Try to get a buffer from the pool
        if let Some(buffer) = self.available_buffers.pop_front() {
            self.stats.allocations.fetch_add(1, Ordering::Relaxed);
            self.update_peak_usage();
            return Some(buffer);
        }

        // Create new buffer if limit not reached
        if self.allocated_buffers.load(Ordering::Relaxed) < self.max_buffers {
            match DMABuffer::new(self.buffer_size) {
                Some(buffer) => {
                    self.allocated_buffers.fetch_add(1, Ordering::Relaxed);
                    self.stats.allocations.fetch_add(1, Ordering::Relaxed);
                    self.update_peak_usage();
                    Some(buffer)
                }
                None => {
                    self.stats.allocation_failures.fetch_add(1, Ordering::Relaxed);
                    None
                }
            }
        } else {
            self.stats.allocation_failures.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Returns a buffer to the pool
    pub fn deallocate(&mut self, buffer: DMABuffer) {
        self.available_buffers.push_back(buffer);
        self.stats.deallocations.fetch_add(1, Ordering::Relaxed);
    }

    /// Updates the peak usage statistic
    fn update_peak_usage(&self) {
        let current = self.allocated_buffers.load(Ordering::Relaxed) -
                     self.available_buffers.len();
        let mut peak = self.stats.peak_usage.load(Ordering::Relaxed);
        while current > peak {
            match self.stats.peak_usage.compare_exchange(
                peak,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current_peak) => peak = current_peak,
            }
        }
    }

    /// Returns current statistics
    pub fn get_stats(&self) -> MemoryPoolStats {
        MemoryPoolStats {
            allocations: AtomicUsize::new(
                self.stats.allocations.load(Ordering::Relaxed)),
            deallocations: AtomicUsize::new(
                self.stats.deallocations.load(Ordering::Relaxed)),
            allocation_failures: AtomicUsize::new(
                self.stats.allocation_failures.load(Ordering::Relaxed)),
            peak_usage: AtomicUsize::new(
                self.stats.peak_usage.load(Ordering::Relaxed)),
        }
    }

    /// Returns the number of available buffers
    pub fn available_buffers(&self) -> usize {
        self.available_buffers.len()
    }

    /// Returns the total number of allocated buffers
    pub fn allocated_buffers(&self) -> usize {
        self.allocated_buffers.load(Ordering::Relaxed)
    }

    /// Pre-allocates a specified number of buffers
    pub fn pre_allocate(&mut self, count: usize) -> usize {
        let mut allocated = 0;
        for _ in 0..count {
            if let Some(buffer) = DMABuffer::new(self.buffer_size) {
                self.available_buffers.push_back(buffer);
                self.allocated_buffers.fetch_add(1, Ordering::Relaxed);
                allocated += 1;
            } else {
                break;
            }
        }
        allocated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_pool_creation() {
        let pool = MemoryPool::new(1024, 10);
        assert_eq!(pool.buffer_size, 1024);
        assert_eq!(pool.max_buffers, 10);
        assert_eq!(pool.available_buffers(), 0);
    }

    #[test]
    fn test_buffer_allocation() {
        let mut pool = MemoryPool::new(1024, 10);
        let buffer = pool.allocate(512).unwrap();
        assert_eq!(buffer.size(), 1024);
        assert_eq!(pool.allocated_buffers(), 1);
    }

    #[test]
    fn test_buffer_deallocation() {
        let mut pool = MemoryPool::new(1024, 10);
        let buffer = pool.allocate(512).unwrap();
        pool.deallocate(buffer);
        assert_eq!(pool.available_buffers(), 1);
    }

    #[test]
    fn test_pre_allocation() {
        let mut pool = MemoryPool::new(1024, 10);
        let count = pool.pre_allocate(5);
        assert_eq!(count, 5);
        assert_eq!(pool.available_buffers(), 5);
    }

    #[test]
    fn test_allocation_limits() {
        let mut pool = MemoryPool::new(1024, 2);
        let _buffer1 = pool.allocate(512);
        let _buffer2 = pool.allocate(512);
        let buffer3 = pool.allocate(512);
        assert!(buffer3.is_none());
    }

    #[test]
    fn test_size_limits() {
        let mut pool = MemoryPool::new(1024, 10);
        let buffer = pool.allocate(2048);
        assert!(buffer.is_none());
    }
}