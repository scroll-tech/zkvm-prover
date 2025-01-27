use alloy_primitives::B256;
use rkyv::{Archive, Deserialize, Serialize};

use crate::{
    ProofCarryingWitness, PublicInputs, proof::RootProofWithPublicValues, utils::keccak256,
};

#[derive(Clone, Debug, Archive, Serialize, Deserialize, serde::Serialize, serde::Deserialize)]
#[rkyv(derive(Debug))]
pub struct BatchInfo {
    #[rkyv()]
    pub parent_state_root: B256,
    #[rkyv()]
    pub parent_batch_hash: B256,
    #[rkyv()]
    pub state_root: B256,
    #[rkyv()]
    pub batch_hash: B256,
    #[rkyv()]
    pub chain_id: u64,
    #[rkyv()]
    pub withdraw_root: B256,
}

impl From<&ArchivedBatchInfo> for BatchInfo {
    fn from(archived: &ArchivedBatchInfo) -> Self {
        Self {
            parent_state_root: archived.parent_state_root.into(),
            parent_batch_hash: archived.parent_batch_hash.into(),
            state_root: archived.state_root.into(),
            batch_hash: archived.batch_hash.into(),
            chain_id: archived.chain_id.into(),
            withdraw_root: archived.withdraw_root.into(),
        }
    }
}

impl PublicInputs for BatchInfo {
    fn pi_hash(&self) -> B256 {
        keccak256(
            std::iter::empty()
                .chain(self.parent_state_root.as_slice())
                .chain(self.parent_batch_hash.as_slice())
                .chain(self.state_root.as_slice())
                .chain(self.batch_hash.as_slice())
                .chain(self.chain_id.to_be_bytes().as_slice())
                .chain(self.withdraw_root.as_slice())
                .cloned()
                .collect::<Vec<u8>>(),
        )
    }

    fn validate(&self, prev_pi: &Self) {
        assert_eq!(self.parent_state_root, prev_pi.state_root);
        assert_eq!(self.parent_batch_hash, prev_pi.batch_hash);
        assert_eq!(self.chain_id, prev_pi.chain_id);
    }
}

#[derive(Clone, Debug, Archive, Serialize, Deserialize)]
#[rkyv(derive(Debug))]
pub struct BundleWitness {
    pub batch_proofs: Vec<RootProofWithPublicValues>,
    pub batch_infos: Vec<BatchInfo>,
}

impl ProofCarryingWitness for ArchivedBundleWitness {
    fn get_proofs(&self) -> Vec<RootProofWithPublicValues> {
        self.batch_proofs
            .iter()
            .map(|archived| RootProofWithPublicValues {
                flattened_proof: archived
                    .flattened_proof
                    .iter()
                    .map(|u32_le| u32_le.to_native())
                    .collect(),
                public_values: archived
                    .public_values
                    .iter()
                    .map(|u32_le| u32_le.to_native())
                    .collect(),
            })
            .collect()
    }
}

pub struct BundleInfo {
    pub chain_id: u64,
    pub num_batches: u32,
    pub prev_state_root: B256,
    pub prev_batch_hash: B256,
    pub post_state_root: B256,
    pub batch_hash: B256,
    pub withdraw_root: B256,
}

impl PublicInputs for BundleInfo {
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
