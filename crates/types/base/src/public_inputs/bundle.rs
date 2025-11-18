use alloy_primitives::B256;

use crate::{
    public_inputs::MultiVersionPublicInputs,
    utils::keccak256,
    version::{Domain, STFVersion, Version},
};

/// Represents fields required to compute the public-inputs digest of a bundle.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct BundleInfo {
    /// The EIP-155 chain ID of all txs in the bundle.
    pub chain_id: u64,
    /// The L1 msg queue hash at the end of the last batch in the bundle.
    /// Not a phase 1 field so we make it omitable
    #[serde(default)]
    pub msg_queue_hash: B256,
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
    /// Optional encryption key, used in the case of domain=Validium.
    pub encryption_key: Option<Box<[u8]>>,
}

impl BundleInfo {
    /// Public input hash for a bundle (euclidv1 or da-codec@v6) is defined as
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
    pub fn pi_hash_euclidv1(&self) -> B256 {
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

    /// Public input for a bundle (euclidv2 or da-codec@v7) is defined as
    ///
    /// concat(
    ///     chain id ||
    ///     msg_queue_hash ||
    ///     num batches ||
    ///     prev state root ||
    ///     prev batch hash ||
    ///     post state root ||
    ///     batch hash ||
    ///     withdraw root
    /// )   
    pub fn pi_euclidv2(&self) -> Vec<u8> {
        std::iter::empty()
            .chain(self.chain_id.to_be_bytes().as_slice())
            .chain(self.msg_queue_hash.as_slice())
            .chain(self.num_batches.to_be_bytes().as_slice())
            .chain(self.prev_state_root.as_slice())
            .chain(self.prev_batch_hash.as_slice())
            .chain(self.post_state_root.as_slice())
            .chain(self.batch_hash.as_slice())
            .chain(self.withdraw_root.as_slice())
            .cloned()
            .collect()
    }

    pub fn pi_hash_euclidv2(&self) -> B256 {
        keccak256(self.pi_euclidv2())
    }

    pub fn pi_feynman(&self) -> Vec<u8> {
        self.pi_euclidv2()
    }

    pub fn pi_galileo(&self) -> Vec<u8> {
        self.pi_euclidv2()
    }

    pub fn pi_hash_versioned(&self, version: Version, pi: &[u8]) -> B256 {
        keccak256(
            std::iter::empty()
                .chain(
                    B256::left_padding_from(version.as_version_byte().to_be_bytes().as_slice())
                        .as_slice(),
                )
                .chain(pi)
                .cloned()
                .collect::<Vec<u8>>(),
        )
    }

    pub fn pi_validium_v1(&self) -> Vec<u8> {
        std::iter::empty()
            .chain(self.pi_euclidv2().as_slice())
            .chain(self.encryption_key.as_ref().expect("domain=Validium"))
            .cloned()
            .collect()
    }
}

pub type VersionedBundleInfo = (BundleInfo, Version);

impl MultiVersionPublicInputs for BundleInfo {
    fn pi_hash_by_version(&self, version: Version) -> B256 {
        match (version.domain, version.stf_version) {
            (Domain::Scroll, STFVersion::V6) => self.pi_hash_euclidv1(),
            (Domain::Scroll, STFVersion::V7) => self.pi_hash_euclidv2(),
            (Domain::Scroll, STFVersion::V8) => {
                self.pi_hash_versioned(version, self.pi_feynman().as_slice())
            }
            (Domain::Scroll, STFVersion::V9) => {
                self.pi_hash_versioned(version, self.pi_galileo().as_slice())
            }
            (Domain::Validium, STFVersion::V1) => {
                self.pi_hash_versioned(version, self.pi_validium_v1().as_slice())
            }
            (domain, stf_version) => {
                unreachable!("unsupported version=({domain:?}, {stf_version:?})")
            }
        }
    }

    fn validate(&self, _prev_pi: &Self, _version: Version) {
        unreachable!("bundle is the last layer and is not aggregated by any other circuit");
    }
}

/// Represents fields required to compute the public-inputs digest of a legacy bundle, i.e.
/// pre-valdium bundle.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LegacyBundleInfo {
    /// The EIP-155 chain ID of all txs in the bundle.
    pub chain_id: u64,
    /// The L1 msg queue hash at the end of the last batch in the bundle.
    /// Not a phase 1 field so we make it omitable
    #[serde(default)]
    pub msg_queue_hash: B256,
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

impl From<BundleInfo> for LegacyBundleInfo {
    fn from(value: BundleInfo) -> Self {
        Self {
            chain_id: value.chain_id,
            msg_queue_hash: value.msg_queue_hash,
            num_batches: value.num_batches,
            prev_state_root: value.prev_state_root,
            prev_batch_hash: value.prev_batch_hash,
            post_state_root: value.post_state_root,
            batch_hash: value.batch_hash,
            withdraw_root: value.withdraw_root,
        }
    }
}
