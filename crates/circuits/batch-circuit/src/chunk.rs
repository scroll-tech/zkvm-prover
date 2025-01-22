// copied from sbv's chunk, and enable serialize

use alloy_primitives::B256;
use tiny_keccak::{Hasher, Keccak};
pub use circuit_input_types::batch::*;

/// Public input hash for a given chunk is defined as
/// keccak(
///     chain id ||
///     prev state root ||
///     post state root ||
///     withdraw root ||
///     chunk data hash ||
///     chunk txdata hash
/// )
pub fn public_input_hash(chunk: &ChunkInfo, tx_bytes_hash: &B256) -> B256 {
    // TODO: reuse sbv's implement?
    let mut hasher = Keccak::v256();

    hasher.update(&chunk.chain_id.to_be_bytes());
    hasher.update(chunk.prev_state_root.as_ref());
    hasher.update(chunk.post_state_root.as_slice());
    #[cfg(feature = "scroll")]
    assert!(chunk.withdraw_root.is_some(), "withdraw root is required");
    hasher.update(chunk.withdraw_root.as_ref().unwrap_or_default().as_slice());
    hasher.update(chunk.data_hash.as_slice());
    hasher.update(tx_bytes_hash.as_slice());

    let mut public_input_hash = B256::ZERO;
    hasher.finalize(&mut public_input_hash.0);
    public_input_hash
}
