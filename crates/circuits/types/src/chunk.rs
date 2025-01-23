use rkyv::{Deserialize, Serialize, Archive, option::ArchivedOption};
use alloy_primitives::B256;

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
    /// Construct by block traces
    #[must_use]
    pub fn from_blocks_iter<'a, I: IntoIterator<Item = &'a Block> + Clone>(
        chain_id: u64,
        prev_state_root: B256,
        iter: I,
    ) -> Self {
        let last_block = iter.clone().into_iter().last().expect("at least one block");

        let data_hash = cycle_track!(
            {
                let mut data_hasher = Keccak::v256();
                for block in iter.clone().into_iter() {
                    block.hash_da_header(&mut data_hasher);
                }
                for block in iter.into_iter() {
                    block.hash_l1_msg(&mut data_hasher);
                }
                let mut data_hash = B256::ZERO;
                data_hasher.finalize(&mut data_hash.0);
                data_hash
            },
            "Keccak::v256"
        );

        ChunkInfo {
            chain_id,
            prev_state_root,
            post_state_root: last_block.state_root,
            data_hash,
        }
    }


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

}