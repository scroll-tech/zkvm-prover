use scroll_zkvm_circuit_input_types::bundle::BundleWitness;

use crate::{
    BatchProof,
    task::{ProvingTask, flatten_wrapped_proof},
};

/// Message indicating a sanity check failure.
const BUNDLE_SANITY_MSG: &str = "bundle must have at least one batch";

#[derive(Clone)]
pub struct BundleProvingTask {
    pub batch_proofs: Vec<BatchProof>,
}

impl ProvingTask for BundleProvingTask {
    fn identifier(&self) -> String {
        assert!(!self.batch_proofs.is_empty(), "{BUNDLE_SANITY_MSG}",);

        let (first, last) = (
            self.batch_proofs
                .first()
                .expect(BUNDLE_SANITY_MSG)
                .metadata
                .batch_hash,
            self.batch_proofs
                .last()
                .expect(BUNDLE_SANITY_MSG)
                .metadata
                .batch_hash,
        );

        format!("{first}-{last}")
    }

    fn to_witness_serialized(&self) -> Result<rkyv::util::AlignedVec, rkyv::rancor::Error> {
        let witness = BundleWitness {
            batch_proofs: self
                .batch_proofs
                .iter()
                .map(flatten_wrapped_proof)
                .collect(),
            batch_infos: self
                .batch_proofs
                .iter()
                .map(|wrapped_proof| wrapped_proof.metadata.batch_info.clone())
                .collect(),
        };
        rkyv::to_bytes::<rkyv::rancor::Error>(&witness)
    }
}
