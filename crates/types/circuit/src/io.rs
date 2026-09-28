#[allow(unused_imports, clippy::single_component_path_imports)]
use openvm::platform as openvm_platform;

/// Read the witnesses from the hint stream.
///
/// rkyv needs special alignment for its data structures, use a pre-aligned buffer with rkyv::access_unchecked
/// is more efficient than rkyv::access.
#[cfg(target_os = "openvm")]
#[inline(always)]
pub fn read_witnesses_rkyv_raw() -> Vec<u8> {
    use std::alloc::{GlobalAlloc, Layout, System};
    openvm_riscv_guest::hint_input();
    // The hint-stream length prefix is a single 8-byte word on the rv64 guest.
    let mut len: u64 = 0;
    openvm_riscv_guest::hint_store_u64!((&mut len) as *mut u64);
    let num_words = (len as usize).div_ceil(8);
    let size = num_words * 8;
    let layout = Layout::from_size_align(size, 16).unwrap();
    let ptr_start = unsafe { System.alloc(layout) };
    // SAFETY: `ptr_start` points to an allocation of `size == num_words * 8` bytes,
    // so the chunked dword writes stay within the allocation.
    unsafe { openvm_riscv_guest::hint_buffer_chunked(ptr_start, num_words) };
    unsafe { Vec::from_raw_parts(ptr_start, len as usize, size) }
}

/// Read the witnesses from the hint stream.
pub fn read_witnesses() -> Vec<u8> {
    #[cfg(not(target_os = "openvm"))]
    return openvm::io::read_vec(); // avoid compiler complaint
    #[cfg(target_os = "openvm")]
    return read_witnesses_rkyv_raw();
}
