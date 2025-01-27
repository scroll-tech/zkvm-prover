use alloy_primitives::B256;
use tiny_keccak::{Hasher, Keccak};

/// From the utility of ether-rs
///
/// Computes the Keccak-256 hash of input bytes.
///
/// Note that strings are interpreted as UTF-8 bytes,
pub fn keccak256<T: AsRef<[u8]>>(bytes: T) -> B256 {
    let mut output = [0u8; 32];

    let mut hasher = Keccak::v256();
    hasher.update(bytes.as_ref());
    hasher.finalize(&mut output);

    B256::from(output)
}
