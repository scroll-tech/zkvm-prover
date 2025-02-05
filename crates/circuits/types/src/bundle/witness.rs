use crate::{ProofCarryingWitness, batch::BatchInfo, proof::RootProofWithPublicValues};

/// The witness for the bundle circuit.
#[derive(Clone, Debug, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
#[rkyv(derive(Debug))]
pub struct BundleWitness {
    /// Batch proofs being aggregated in the bundle.
    #[rkyv()]
    pub batch_proofs: Vec<RootProofWithPublicValues>,
    /// Public-input values for the corresponding batch proofs.
    #[rkyv()]
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
                program_commit: archived
                    .program_commit
                    .map(|ct| ct.map(|u32_le| u32_le.to_native())),
            })
            .collect()
    }
}
