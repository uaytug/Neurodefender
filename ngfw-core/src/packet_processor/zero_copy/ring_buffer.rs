use std::sync::atomic::{AtomicUsize, Ordering};
use super::dma::DMADescriptor;

/// Ring buffer for managing DMA descriptors
pub struct RingBuffer {
    /// Array of descriptor slots
    descriptors: Box<[Option<Box<DMADescriptor>>]>,
    /// Head index (producer)
    head: AtomicUsize,
    /// Tail index (consumer)
    tail: AtomicUsize,
    /// Size of the ring buffer
    size: usize,
    /// Mask for fast modulo operations (size must be power of 2)
    mask: usize,
    /// Statistics for monitoring
    stats: RingBufferStats,
}

/// Statistics for ring buffer monitoring
#[derive(Debug, Default)]
pub struct RingBufferStats {
    /// Total number of descriptors enqueued
    enqueued: AtomicUsize,
    /// Total number of descriptors dequeued
    dequeued: AtomicUsize,
    /// Number of failed enqueue attempts (buffer full)
    enqueue_failures: AtomicUsize,
    /// Number of failed dequeue attempts (buffer empty)
    dequeue_failures: AtomicUsize,
}

impl RingBuffer {
    /// Creates a new ring buffer with the specified size (must be power of 2)
    pub fn new(size: usize) -> Self {
        assert!(size.is_power_of_two(), "Ring buffer size must be power of 2");
        
        let descriptors = (0..size)
            .map(|_| None)
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self {
            descriptors,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            size,
            mask: size - 1,
            stats: RingBufferStats::default(),
        }
    }

    /// Returns the next available descriptor for enqueueing
    pub fn get_next_descriptor(&mut self) -> Option<&mut DMADescriptor> {
        let head = self.head.load(Ordering::Relaxed);
        let next_head = (head + 1) & self.mask;

        // Check if buffer is full
        if next_head == self.tail.load(Ordering::Acquire) {
            self.stats.enqueue_failures.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Initialize new descriptor if slot is empty
        if self.descriptors[head].is_none() {
            self.descriptors[head] = Some(Box::new(DMADescriptor::new()));
        }

        // Update head pointer
        self.head.store(next_head, Ordering::Release);
        self.stats.enqueued.fetch_add(1, Ordering::Relaxed);

        // Return mutable reference to descriptor
        self.descriptors[head]
            .as_mut()
            .map(|desc| desc.as_mut())
    }

    /// Returns the next completed descriptor
    pub fn get_completed_descriptor(&mut self) -> Option<&mut DMADescriptor> {
        let tail = self.tail.load(Ordering::Relaxed);

        // Check if buffer is empty
        if tail == self.head.load(Ordering::Acquire) {
            self.stats.dequeue_failures.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Check if descriptor is completed
        if let Some(desc) = self.descriptors[tail].as_mut() {
            if desc.is_completed() {
                // Update tail pointer
                self.tail.store((tail + 1) & self.mask, Ordering::Release);
                self.stats.dequeued.fetch_add(1, Ordering::Relaxed);
                return Some(desc);
            }
        }

        None
    }

    /// Returns the number of descriptors currently in the ring buffer
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        (head - tail) & self.mask
    }

    /// Returns true if the ring buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns true if the ring buffer is full
    pub fn is_full(&self) -> bool {
        self.len() == self.size - 1
    }

    /// Returns the total capacity of the ring buffer
    pub fn capacity(&self) -> usize {
        self.size
    }

    /// Returns current statistics
    pub fn get_stats(&self) -> RingBufferStats {
        RingBufferStats {
            enqueued: AtomicUsize::new(
                self.stats.enqueued.load(Ordering::Relaxed)),
            dequeued: AtomicUsize::new(
                self.stats.dequeued.load(Ordering::Relaxed)),
            enqueue_failures: AtomicUsize::new(
                self.stats.enqueue_failures.load(Ordering::Relaxed)),
            dequeue_failures: AtomicUsize::new(
                self.stats.dequeue_failures.load(Ordering::Relaxed)),
        }
    }

    /// Clears all descriptors from the ring buffer
    pub fn clear(&mut self) {
        for desc in self.descriptors.iter_mut() {
            *desc = None;
        }
        self.head.store(0, Ordering::Release);
        self.tail.store(0, Ordering::Release);
    }
}

impl DMADescriptor {
    /// Creates a new DMA descriptor
    fn new() -> Self {
        Self {
            src_addr: 0,
            dst_addr: 0,
            length: 0,
            flags: 0,
            status: 0,
            next: None,
        }
    }

    /// Returns true if the descriptor has completed
    fn is_completed(&self) -> bool {
        (self.status & 1) == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_creation() {
        let buffer = RingBuffer::new(16);
        assert_eq!(buffer.capacity(), 16);
        assert!(buffer.is_empty());
        assert!(!buffer.is_full());
    }

    #[test]
    fn test_descriptor_enqueue_dequeue() {
        let mut buffer = RingBuffer::new(4);
        
        // Enqueue descriptors
        let desc1 = buffer.get_next_descriptor();
        assert!(desc1.is_some());
        
        let desc2 = buffer.get_next_descriptor();
        assert!(desc2.is_some());
        
        assert_eq!(buffer.len(), 2);

        // Complete and dequeue descriptor
        if let Some(desc) = desc1 {
            desc.status = 1; // Mark as completed
            let completed = buffer.get_completed_descriptor();
            assert!(completed.is_some());
        }

        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn test_buffer_full() {
        let mut buffer = RingBuffer::new(4);
        
        // Fill buffer
        for _ in 0..3 {
            assert!(buffer.get_next_descriptor().is_some());
        }
        
        // Should fail on full buffer
        assert!(buffer.get_next_descriptor().is_none());
        assert!(buffer.is_full());
    }

    #[test]
    fn test_buffer_empty() {
        let mut buffer = RingBuffer::new(4);
        assert!(buffer.get_completed_descriptor().is_none());
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_clear_buffer() {
        let mut buffer = RingBuffer::new(4);
        
        // Add some descriptors
        buffer.get_next_descriptor();
        buffer.get_next_descriptor();
        
        assert_eq!(buffer.len(), 2);
        
        // Clear buffer
        buffer.clear();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn test_statistics() {
        let mut buffer = RingBuffer::new(4);
        
        // Generate some statistics
        buffer.get_next_descriptor();
        buffer.get_next_descriptor();
        buffer.get_completed_descriptor(); // Should fail
        
        let stats = buffer.get_stats();
        assert_eq!(stats.enqueued.load(Ordering::Relaxed), 2);
        assert_eq!(stats.dequeue_failures.load(Ordering::Relaxed), 1);
    }
}