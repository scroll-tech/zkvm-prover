use openvm_native_recursion::hints::Hintable;
use openvm_sdk::StdIn;
use scroll_zkvm_types::{
    bundle::{BundleInfo, BundleWitness},
    public_inputs::ForkName,
};

use crate::{
    AsRootProof, BatchProof,
    task::{ProvingTask, guest_version},
};

/// Message indicating a sanity check failure.
const BUNDLE_SANITY_MSG: &str = "bundle must have at least one batch";

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct BundleProvingTask {
    pub batch_proofs: Vec<BatchProof>,
    /// for sanity check
    pub bundle_info: Option<BundleInfo>,
    /// Fork name specify
    pub fork_name: String,
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

    fn fork_name(&self) -> ForkName {
        ForkName::from(self.fork_name.as_str())
    }

    fn build_guest_input_inner(&self, stdin: &mut StdIn) -> Result<(), rkyv::rancor::Error> {
        let witness = BundleWitness {
            batch_proofs: self.batch_proofs.iter().map(|proof| proof.into()).collect(),
            batch_infos: self
                .batch_proofs
                .iter()
                .map(|wrapped_proof| wrapped_proof.metadata.batch_info.clone())
                .collect(),
            fork_name: ForkName::from(self.fork_name.as_str()),
        };
        let serialized = witness.rkyv_serialize(guest_version())?;
        stdin.write_bytes(&serialized);
        for batch_proof in &self.batch_proofs {
            let root_input = &batch_proof.as_root_proof();
            let streams = if self.fork_name() >= ForkName::Feynman {
                root_input.proofs[0].write()
            } else {
                root_input.write()
            };
            for s in &streams {
                stdin.write_field(s);
            }
        }
        Ok(())
    }
}
