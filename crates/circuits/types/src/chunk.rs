use rkyv::{Deserialize, Serialize, Archive, option::ArchivedOption};
use alloy_primitives::B256;
use tiny_keccak::{Hasher, Keccak};

/// The chunk info in sbv is not compatible with prover (lacking of withdraw_root)
/// We still keep the struct in legacy prover now
#[derive(Debug, Clone, Archive, Serialize, Deserialize, serde::Serialize, serde::Deserialize)]
#[rkyv(derive(Debug))]
pub struct ChunkInfo {
    #[rkyv()]
    pub chain_id: u64,
    #[rkyv()]
    pub prev_state_root: B256,
    #[rkyv()]
    pub post_state_root: B256,
    #[rkyv()]
    pub withdraw_root: Option<B256>,
    #[rkyv()]
    pub data_hash: B256,
}

impl From<&ArchivedChunkInfo> for ChunkInfo {
    fn from(ci: &ArchivedChunkInfo) -> Self {
        Self {
            chain_id: ci.chain_id.into(),
            prev_state_root: ci.prev_state_root.into(),
            post_state_root: ci.post_state_root.into(),
            withdraw_root: match ci.withdraw_root{
                ArchivedOption::None => None,
                ArchivedOption::Some(v) => Some(v.into()),
            },
            data_hash: ci.data_hash.into(),         
        }
    }
}

impl ChunkInfo {
    /// Public input hash for a given chunk is defined as
    /// keccak(
    ///     chain id ||
    ///     prev state root ||
    ///     post state root ||
    ///     withdraw root ||
    ///     chunk data hash ||
    ///     chunk txdata hash
    /// )
    pub fn public_input_hash(&self, tx_bytes_hash: &B256) -> B256 {
        // TODO: reuse sbv's implement?
        let mut hasher = Keccak::v256();

        hasher.update(&self.chain_id.to_be_bytes());
        hasher.update(self.prev_state_root.as_ref());
        hasher.update(self.post_state_root.as_slice());
        #[cfg(feature = "scroll")]
        assert!(self.withdraw_root.is_some(), "withdraw root is required");
        hasher.update(self.withdraw_root.as_ref().unwrap_or_default().as_slice());
        hasher.update(self.data_hash.as_slice());
        hasher.update(tx_bytes_hash.as_slice());

        let mut public_input_hash = B256::ZERO;
        hasher.finalize(&mut public_input_hash.0);
        public_input_hash
    }

}