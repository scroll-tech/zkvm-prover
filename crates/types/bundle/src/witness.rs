use rkyv::util::AlignedVec;
use types_base::{
    aggregation::{AggregationInput, ProgramCommitment, ProofCarryingWitness},
    fork_name::ForkName,
    public_inputs::{batch::BatchInfo, bundle::BundleInfo},
};

/// The witness for the bundle circuit.
#[derive(Clone, Debug, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
#[rkyv(derive(Debug))]
pub struct BundleWitnessEuclid {
    /// Batch proofs being aggregated in the bundle.
    #[rkyv()]
    pub batch_proofs: Vec<AggregationInput>,
    /// Public-input values for the corresponding batch proofs.
    #[rkyv()]
    pub batch_infos: Vec<BatchInfo>,
}

/// The witness for the bundle circuit.
#[derive(Clone, Debug, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
#[rkyv(derive(Debug))]
pub struct BundleWitness {
    /// Batch proofs being aggregated in the bundle.
    #[rkyv()]
    pub batch_proofs: Vec<AggregationInput>,
    /// Public-input values for the corresponding batch proofs.
    #[rkyv()]
    pub batch_infos: Vec<BatchInfo>,
    /// The code version specify the chain spec
    #[rkyv()]
    pub fork_name: ForkName,
}

impl BundleWitness {
    /// Convert the `BundleWitness` into a `BundleWitnessEuclid`.
    pub fn into_euclid(self) -> BundleWitnessEuclid {
        BundleWitnessEuclid {
            batch_proofs: self.batch_proofs,
            batch_infos: self.batch_infos,
        }
    }
    /// See ChunkWitnessEuclid::rkyv_serialize for details.
    pub fn rkyv_serialize(
        &self,
        guest_version: Option<ForkName>,
    ) -> Result<AlignedVec, rkyv::rancor::Error> {
        let guest_version = guest_version.unwrap_or(self.fork_name.clone());
        if guest_version >= ForkName::Feynman {
            // Use the new rkyv serialization for Feynman and later forks
            rkyv::to_bytes::<rkyv::rancor::Error>(self)
        } else {
            // Use the old rkyv serialization for earlier forks
            rkyv::to_bytes::<rkyv::rancor::Error>(&self.clone().into_euclid())
        }
    }
}

impl ProofCarryingWitness for ArchivedBundleWitness {
    fn get_proofs(&self) -> Vec<AggregationInput> {
        self.batch_proofs
            .iter()
            .map(|archived| AggregationInput {
                public_values: archived
                    .public_values
                    .iter()
                    .map(|u32_le| u32_le.to_native())
                    .collect(),
                commitment: ProgramCommitment::from(&archived.commitment),
            })
            .collect()
    }
}

impl From<&ArchivedBundleWitness> for BundleInfo {
    fn from(witness: &ArchivedBundleWitness) -> Self {
        assert!(
            !witness.batch_infos.is_empty(),
            "at least one batch in a bundle"
        );

        let (first_batch, last_batch) = (
            witness
                .batch_infos
                .first()
                .expect("at least one batch in bundle"),
            witness
                .batch_infos
                .last()
                .expect("at least one batch in bundle"),
        );

        let chain_id = first_batch.chain_id.into();
        let num_batches = u32::try_from(witness.batch_infos.len()).expect("num_batches: u32");
        let prev_state_root = first_batch.parent_state_root.into();
        let prev_batch_hash = first_batch.parent_batch_hash.into();
        let post_state_root = last_batch.state_root.into();
        let batch_hash = last_batch.batch_hash.into();
        let withdraw_root = last_batch.withdraw_root.into();
        let msg_queue_hash = last_batch.post_msg_queue_hash.into();

        BundleInfo {
            chain_id,
            num_batches,
            prev_state_root,
            prev_batch_hash,
            post_state_root,
            batch_hash,
            withdraw_root,
            msg_queue_hash,
        }
    }
}
