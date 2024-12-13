use std::mem;
use std::ptr;
use thiserror::Error;
use libbpf_sys as bpf;

#[derive(Debug, Error)]
pub enum XdpHelperError {
    #[error("Map operation failed: {0}")]
    MapError(String),

    #[error("Invalid map key")]
    InvalidKey,

    #[error("Invalid map value")]
    InvalidValue,

    #[error("Buffer too small")]
    BufferTooSmall,

    #[error("Memory allocation failed")]
    AllocationError,

    #[error("System error: {0}")]
    SystemError(String),
}

/// Safe wrapper for XDP map operations
pub struct XdpMapHelper {
    /// Map file descriptor
    map_fd: i32,
}

/// Map element flags
#[derive(Debug, Clone, Copy)]
pub struct MapFlags {
    pub no_exist: bool,
    pub exist: bool,
    pub lock: bool,
}

impl XdpMapHelper {
    /// Create new map helper
    pub fn new(map_fd: i32) -> Self {
        Self { map_fd }
    }

    /// Update map element
    pub fn update_elem<K, V>(&self, key: &K, value: &V, flags: MapFlags) -> Result<(), XdpHelperError> {
        let flag_value = Self::convert_flags(flags);

        let result = unsafe {
            bpf::bpf_map_update_elem(
                self.map_fd,
                ptr::from_ref(key) as *const _,
                ptr::from_ref(value) as *const _,
                flag_value,
            )
        };

        if result != 0 {
            Err(XdpHelperError::MapError(format!(
                "Failed to update map element: {}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(())
        }
    }

    /// Lookup map element
    pub fn lookup_elem<K, V>(&self, key: &K) -> Result<V, XdpHelperError> {
        let mut value: V = unsafe { mem::zeroed() };

        let result = unsafe {
            bpf::bpf_map_lookup_elem(
                self.map_fd,
                ptr::from_ref(key) as *const _,
                ptr::from_mut(&mut value) as *mut _,
            )
        };

        if result != 0 {
            Err(XdpHelperError::MapError(format!(
                "Failed to lookup map element: {}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(value)
        }
    }

    /// Delete map element
    pub fn delete_elem<K>(&self, key: &K) -> Result<(), XdpHelperError> {
        let result = unsafe {
            bpf::bpf_map_delete_elem(
                self.map_fd,
                ptr::from_ref(key) as *const _,
            )
        };

        if result != 0 {
            Err(XdpHelperError::MapError(format!(
                "Failed to delete map element: {}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(())
        }
    }

    /// Get next key
    pub fn get_next_key<K>(&self, key: Option<&K>) -> Result<K, XdpHelperError> {
        let mut next_key: K = unsafe { mem::zeroed() };

        let result = unsafe {
            bpf::bpf_map_get_next_key(
                self.map_fd,
                key.map_or(ptr::null(), |k| ptr::from_ref(k)) as *const _,
                ptr::from_mut(&mut next_key) as *mut _,
            )
        };

        if result != 0 {
            Err(XdpHelperError::MapError(format!(
                "Failed to get next key: {}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(next_key)
        }
    }

    /// Convert map flags to u64
    fn convert_flags(flags: MapFlags) -> u64 {
        let mut result = 0;
        if flags.no_exist {
            result |= bpf::BPF_NOEXIST;
        }
        if flags.exist {
            result |= bpf::BPF_EXIST;
        }
        if flags.lock {
            result |= bpf::BPF_F_LOCK;
        }
        result
    }
}

/// XDP helper functions for packet manipulation
pub struct XdpPacketHelper<'a> {
    data: *mut u8,
    data_end: *mut u8,
    _lifetime: std::marker::PhantomData<&'a mut [u8]>,
}

impl<'a> XdpPacketHelper<'a> {
    /// Create new packet helper
    pub fn new(data: *mut u8, data_end: *mut u8) -> Self {
        Self {
            data,
            data_end,
            _lifetime: std::marker::PhantomData,
        }
    }

    /// Check if there's enough space for a given type
    pub fn has_space<T>(&self, offset: usize) -> bool {
        unsafe {
            self.data.add(offset + mem::size_of::<T>()) <= self.data_end
        }
    }

    /// Get reference to data at offset
    pub fn get_data<T>(&self, offset: usize) -> Result<&'a T, XdpHelperError> {
        if !self.has_space::<T>(offset) {
            return Err(XdpHelperError::BufferTooSmall);
        }

        Ok(unsafe {
            &*(self.data.add(offset) as *const T)
        })
    }

    /// Get mutable reference to data at offset
    pub fn get_data_mut<T>(&mut self, offset: usize) -> Result<&'a mut T, XdpHelperError> {
        if !self.has_space::<T>(offset) {
            return Err(XdpHelperError::BufferTooSmall);
        }

        Ok(unsafe {
            &mut *(self.data.add(offset) as *mut T)
        })
    }

    /// Adjust packet data size
    pub fn adjust_size(&mut self, adjustment: i32) -> Result<(), XdpHelperError> {
        if adjustment > 0 {
            if !self.has_space::<u8>(adjustment as usize) {
                return Err(XdpHelperError::BufferTooSmall);
            }
        }

        unsafe {
            self.data_end = self.data_end.offset(adjustment as isize);
        }
        
        Ok(())
    }
}

/// Helper for XDP program context
pub struct XdpContextHelper {
    ctx: *mut bpf::xdp_md,
}

impl XdpContextHelper {
    /// Create new context helper
    pub fn new(ctx: *mut bpf::xdp_md) -> Self {
        Self { ctx }
    }

    /// Get packet data
    pub fn get_packet_data(&mut self) -> Result<XdpPacketHelper, XdpHelperError> {
        let data = unsafe { (*self.ctx).data as *mut u8 };
        let data_end = unsafe { (*self.ctx).data_end as *mut u8 };

        Ok(XdpPacketHelper::new(data, data_end))
    }

    /// Get interface index
    pub fn get_interface_index(&self) -> i32 {
        unsafe { (*self.ctx).ingress_ifindex }
    }
}

/// XDP redirect helper
pub struct XdpRedirectHelper {
    target_ifindex: i32,
}

impl XdpRedirectHelper {
    /// Create new redirect helper
    pub fn new(target_ifindex: i32) -> Self {
        Self { target_ifindex }
    }

    /// Redirect packet
    pub fn redirect(&self) -> Result<(), XdpHelperError> {
        let result = unsafe {
            bpf::bpf_redirect(self.target_ifindex, 0)
        };

        if result != 0 {
            Err(XdpHelperError::SystemError(format!(
                "Failed to redirect packet: {}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_flags_conversion() {
        let flags = MapFlags {
            no_exist: true,
            exist: false,
            lock: true,
        };

        let value = XdpMapHelper::convert_flags(flags);
        assert_ne!(value & bpf::BPF_NOEXIST, 0);
        assert_eq!(value & bpf::BPF_EXIST, 0);
        assert_ne!(value & bpf::BPF_F_LOCK, 0);
    }

    #[test]
    fn test_packet_helper_space_check() {
        let mut data = [0u8; 100];
        let helper = XdpPacketHelper::new(
            data.as_mut_ptr(),
            unsafe { data.as_mut_ptr().add(100) }
        );

        assert!(helper.has_space::<u32>(0));
        assert!(!helper.has_space::<[u8; 101]>(0));
    }
}