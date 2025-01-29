use scroll_zkvm_circuit_input_types::batch::BatchHeader;

use crate::{
    Error, Prover, ProverType,
    proof::{BatchProofMetadata, RootProof},
    task::batch::BatchProvingTask,
};

/// Prover for [`BatchCircuit`].
pub type BatchProver = Prover<BatchProverType>;

pub struct BatchProverType;

impl ProverType for BatchProverType {
    const NAME: &'static str = "batch";

    const EVM: bool = false;

    type ProvingTask = BatchProvingTask;

    type ProofType = RootProof;

    type ProofMetadata = BatchProofMetadata;

    fn metadata_with_prechecks(task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error> {
        let batch_info = task.into();
        let batch_hash = task.batch_header.batch_hash();

        Ok(BatchProofMetadata {
            batch_info,
            batch_hash,
        })
    }
}
