use alloy_primitives::B256;

use crate::{PublicInputs, utils::keccak256};

/// Represents fields required to compute the public-inputs digest of a bundle.
pub struct BundleInfo {
    /// The EIP-155 chain ID of all txs in the bundle.
    pub chain_id: u64,
    /// The number of batches bundled together in the bundle.
    pub num_batches: u32,
    /// The last finalized on-chain state root.
    pub prev_state_root: B256,
    /// The last finalized on-chain batch hash.
    pub prev_batch_hash: B256,
    /// The state root after applying every batch in the bundle.
    ///
    /// Upon verification of the EVM-verifiable bundle proof, this state root will be finalized
    /// on-chain.
    pub post_state_root: B256,
    /// The batch hash of the last batch in the bundle.
    ///
    /// Upon verification of the EVM-verifiable bundle proof, this batch hash will be finalized
    /// on-chain.
    pub batch_hash: B256,
    /// The withdrawals root at the last block in the last chunk in the last batch in the bundle.
    pub withdraw_root: B256,
}

impl PublicInputs for BundleInfo {
    /// Public input hash for a bundle is defined as
    ///
    /// keccak(
    ///     chain id ||
    ///     num batches ||
    ///     prev state root ||
    ///     prev batch hash ||
    ///     post state root ||
    ///     batch hash ||
    ///     withdraw root
    /// )
    fn pi_hash(&self) -> B256 {
        keccak256(
            std::iter::empty()
                .chain(self.chain_id.to_be_bytes().as_slice())
                .chain(self.num_batches.to_be_bytes().as_slice())
                .chain(self.prev_state_root.as_slice())
                .chain(self.prev_batch_hash.as_slice())
                .chain(self.post_state_root.as_slice())
                .chain(self.batch_hash.as_slice())
                .chain(self.withdraw_root.as_slice())
                .cloned()
                .collect::<Vec<u8>>(),
        )
    }

    fn validate(&self, _prev_pi: &Self) {
        unreachable!("bundle is the last layer and is not aggregated by any other circuit");
    }
}
