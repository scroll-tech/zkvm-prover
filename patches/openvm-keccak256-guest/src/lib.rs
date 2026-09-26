#![no_std]

#[cfg(any(openvm_intrinsics, target_os = "openvm"))]
use openvm_platform::alloc::AlignedBuf;

pub const OPCODE: u8 = 0x0b;
pub const KECCAKF_FUNCT3: u8 = 0b100;
pub const KECCAKF_FUNCT7: u8 = 0;
pub const XORIN_FUNCT3: u8 = 0b100;
pub const XORIN_FUNCT7: u8 = 1;

pub const KECCAK_WIDTH_BYTES: usize = 200;
pub const KECCAK_RATE: usize = 136;
pub const KECCAK_OUTPUT_SIZE: usize = 32;
pub const MIN_ALIGN: usize = 8;

/// Compile-time toggle: `false` disables the aligned-stack staging fast path in
/// `native_xorin` (for A/B cycle measurement).
#[cfg(any(openvm_intrinsics, target_os = "openvm"))]
const FAST_XORIN: bool = true;

/// XOR `len` bytes from `input` into `buffer` using the native XORIN instruction.
///
/// # Panics
///
/// Panics if `len > KECCAK_RATE` (136): the XORIN circuit absorbs at most `KECCAK_RATE` bytes
/// per instruction, so a larger length would execute but fail to prove.
///
/// # Safety
///
/// - `buffer` must point to a buffer of at least `len` bytes.
/// - `input` must point to a buffer of at least `len` bytes.
#[cfg(any(openvm_intrinsics, target_os = "openvm"))]
#[no_mangle]
pub unsafe extern "C" fn native_xorin(buffer: *mut u8, input: *const u8, len: usize) {
    assert!(
        len <= KECCAK_RATE,
        "native_xorin: len exceeds the XORIN circuit's maximum rate of {} bytes",
        KECCAK_RATE
    );
    if len == 0 {
        return;
    }
    unsafe {
        let buffer_aligned = buffer as usize % MIN_ALIGN == 0;
        let input_aligned = input as usize % MIN_ALIGN == 0;
        let len_aligned = len % MIN_ALIGN == 0;
        let all_aligned = buffer_aligned && input_aligned && len_aligned;

        if all_aligned {
            __native_xorin(buffer, input, len);
        } else if buffer_aligned && FAST_XORIN {
            // Fast path: stage the (possibly unaligned) input in an aligned stack
            // buffer. The XORIN instruction consumes a whole number of 8-byte
            // words, so zero the tail padding to leave those state words
            // unchanged (x ^ 0 = x). This avoids two heap allocations and the
            // buffer copy round-trip of the generic path below.
            #[repr(align(8))]
            struct Stage([u8; KECCAK_RATE]);

            let adjusted_len = len.next_multiple_of(MIN_ALIGN);
            let mut stage = core::mem::MaybeUninit::<Stage>::uninit();
            let stage_ptr = stage.as_mut_ptr() as *mut u8;
            core::ptr::copy_nonoverlapping(input, stage_ptr, len);
            core::ptr::write_bytes(stage_ptr.add(len), 0, adjusted_len - len);
            __native_xorin(buffer, stage_ptr, adjusted_len);
        } else {
            let adjusted_len = len.next_multiple_of(MIN_ALIGN);
            let aligned_buffer;
            let aligned_input;

            let actual_buffer = if buffer_aligned && len_aligned {
                buffer
            } else {
                aligned_buffer = AlignedBuf::uninit(adjusted_len, MIN_ALIGN);
                core::ptr::copy_nonoverlapping(buffer, aligned_buffer.ptr, len);
                aligned_buffer.ptr
            };

            let actual_input = if input_aligned && len_aligned {
                input
            } else {
                aligned_input = AlignedBuf::uninit(adjusted_len, MIN_ALIGN);
                core::ptr::copy_nonoverlapping(input, aligned_input.ptr, len);
                aligned_input.ptr
            };

            __native_xorin(actual_buffer, actual_input, adjusted_len);

            if !buffer_aligned || !len_aligned {
                core::ptr::copy_nonoverlapping(actual_buffer as *const u8, buffer, len);
            }
        }
    }
}

/// Apply the Keccak-f\[1600\] permutation to the 200-byte state buffer.
///
/// # Safety
///
/// - `buffer` must point to a buffer of at least `KECCAK_WIDTH_BYTES` (200) bytes.
#[cfg(any(openvm_intrinsics, target_os = "openvm"))]
#[no_mangle]
pub unsafe extern "C" fn native_keccakf(buffer: *mut u8) {
    unsafe {
        if buffer as usize % MIN_ALIGN == 0 {
            __native_keccakf(buffer);
        } else {
            let aligned_buffer = AlignedBuf::new(buffer, KECCAK_WIDTH_BYTES, MIN_ALIGN);
            __native_keccakf(aligned_buffer.ptr);
            core::ptr::copy_nonoverlapping(
                aligned_buffer.ptr as *const u8,
                buffer,
                KECCAK_WIDTH_BYTES,
            );
        }
    }
}

#[cfg(any(openvm_intrinsics, target_os = "openvm"))]
#[inline(always)]
fn __native_xorin(mut buffer: *mut u8, input: *const u8, len: usize) {
    openvm_platform::custom_insn_r!(
        opcode = OPCODE,
        funct3 = XORIN_FUNCT3,
        funct7 = XORIN_FUNCT7,
        rd = InOut buffer,
        rs1 = In input,
        rs2 = In len
    );
}

#[cfg(any(openvm_intrinsics, target_os = "openvm"))]
#[inline(always)]
fn __native_keccakf(mut buffer: *mut u8) {
    openvm_platform::custom_insn_r!(
        opcode = OPCODE,
        funct3 = KECCAKF_FUNCT3,
        funct7 = KECCAKF_FUNCT7,
        rd = InOut buffer,
        rs1 = Const "x0",
        rs2 = Const "x0",
    );
}

