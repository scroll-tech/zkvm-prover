use scroll_zkvm_circuit_input_types::batch::BatchHeader;

use crate::{
    Error, Prover, ProverType,
    commitments::batch::{EXE_COMMIT as BATCH_EXE_COMMIT, LEAF_COMMIT as BATCH_LEAF_COMMIT},
    proof::{BatchProofMetadata, RootProof},
    setup::read_app_config,
    task::batch::BatchProvingTask,
};

/// Prover for [`BatchCircuit`].
pub type BatchProver = Prover<BatchProverType>;

pub struct BatchProverType;

impl ProverType for BatchProverType {
    const NAME: &'static str = "batch";

    const EVM: bool = false;

    const EXE_COMMIT: [u32; 8] = BATCH_EXE_COMMIT;

    const LEAF_COMMIT: [u32; 8] = BATCH_LEAF_COMMIT;

    type ProvingTask = BatchProvingTask;

    type ProofType = RootProof;

    type ProofMetadata = BatchProofMetadata;

    fn read_app_config<P: AsRef<std::path::Path>>(
        path_app_config: P,
    ) -> Result<openvm_sdk::config::AppConfig<openvm_sdk::config::SdkVmConfig>, Error> {
        let mut app_config = read_app_config(path_app_config)?;
        app_config.app_vm_config.system.config = app_config
            .app_vm_config
            .system
            .config
            .with_max_segment_len(8388508 * 2);
        Ok(app_config)
    }

    fn metadata_with_prechecks(task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error> {
        let batch_info = task.into();
        let batch_hash = task.batch_header.batch_hash();

        Ok(BatchProofMetadata {
            batch_info,
            batch_hash,
        })
    }
}
