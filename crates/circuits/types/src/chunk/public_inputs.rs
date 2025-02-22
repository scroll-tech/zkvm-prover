use alloy_primitives::B256;
use rkyv::{Archive, Deserialize, Serialize};

use crate::{PublicInputs, utils::keccak256};

/// Represents header-like information for the chunk.
#[derive(Debug, Clone, Archive, Serialize, Deserialize, serde::Serialize, serde::Deserialize)]
#[rkyv(derive(Debug))]
pub struct ChunkInfo {
    /// The EIP-155 chain ID for all txs in the chunk.
    #[rkyv()]
    pub chain_id: u64,
    /// The state root before applying the chunk.
    #[rkyv()]
    pub prev_state_root: B256,
    /// The state root after applying the chunk.
    #[rkyv()]
    pub post_state_root: B256,
    /// The withdrawals root after applying the chunk.
    #[rkyv()]
    pub withdraw_root: B256,
    /// Digest of L1 message txs force included in the chunk.
    #[rkyv()]
    pub data_hash: B256,
    /// Digest of L2 tx data flattened over all L2 txs in the chunk.
    #[rkyv()]
    pub tx_data_digest: B256,
}

impl From<&ArchivedChunkInfo> for ChunkInfo {
    fn from(archived: &ArchivedChunkInfo) -> Self {
        Self {
            chain_id: archived.chain_id.into(),
            prev_state_root: archived.prev_state_root.into(),
            post_state_root: archived.post_state_root.into(),
            withdraw_root: archived.withdraw_root.into(),
            data_hash: archived.data_hash.into(),
            tx_data_digest: archived.tx_data_digest.into(),
        }
    }
}

impl PublicInputs for ChunkInfo {
    /// Public input hash for a given chunk is defined as
    ///
    /// keccak(
    ///     chain id ||
    ///     prev state root ||
    ///     post state root ||
    ///     withdraw root ||
    ///     chunk data hash ||
    ///     tx data hash
    /// )
    fn pi_hash(&self) -> B256 {
        keccak256(
            std::iter::empty()
                .chain(&self.chain_id.to_be_bytes())
                .chain(self.prev_state_root.as_slice())
                .chain(self.post_state_root.as_slice())
                .chain(self.withdraw_root.as_slice())
                .chain(self.data_hash.as_slice())
                .chain(self.tx_data_digest.as_slice())
                .cloned()
                .collect::<Vec<u8>>(),
        )
    }

    /// Validate public inputs between 2 contiguous chunks.
    ///
    /// - chain id MUST match
    /// - state roots MUST be chained
    fn validate(&self, prev_pi: &Self) {
        assert_eq!(self.chain_id, prev_pi.chain_id);
        assert_eq!(self.prev_state_root, prev_pi.post_state_root);
    }
}
