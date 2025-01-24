use std::sync::Arc;

use openvm_circuit::{arch::SingleSegmentVmExecutor, system::program::trace::VmCommittedExe};
use openvm_native_recursion::hints::Hintable;
use openvm_sdk::{NonRootCommittedExe, Sdk, StdIn, config::SdkVmConfig, keygen::AppProvingKey};
use scroll_zkvm_circuit_input_types::batch::BatchHeader;

use crate::{
    Error, Prover, ProverType, WrappedProof,
    proof::{BatchProofMetadata, RootProof},
    prover::AGG_STARK_PROVING_KEY,
    task::{ProvingTask, batch::BatchProvingTask},
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

    fn build_proof_metadata(task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error> {
        let batch_hash = task.batch_header.batch_hash();
        Ok(BatchProofMetadata { batch_hash })
    }

    fn gen_proof(
        app_pk: Arc<AppProvingKey<SdkVmConfig>>,
        app_committed_exe: Arc<NonRootCommittedExe>,
        task: &Self::ProvingTask,
    ) -> Result<WrappedProof<Self::ProofMetadata, Self::ProofType>, Error> {
        let agg_stark_pk = AGG_STARK_PROVING_KEY
            .get()
            .ok_or(Error::GenProof(String::from(
                "agg stark pk not initialized! Prover::setup",
            )))?;

        let serialized = task.serialized_into();

        let mut stdin = StdIn::default();
        stdin.write_bytes(&serialized);

        let task_id = task.identifier();

        tracing::debug!(name: "generate_root_proof", ?task_id);
        let proof = Sdk
            .generate_root_verifier_input(
                Arc::clone(&app_pk),
                Arc::clone(&app_committed_exe),
                agg_stark_pk.clone(),
                stdin,
            )
            .map_err(|e| Error::GenProof(e.to_string()))?;

        tracing::debug!(name: "construct_metadata", ?task_id);
        let metadata = Self::build_proof_metadata(task)?;

        let wrapped_proof = WrappedProof::new(metadata, proof);

        Ok(wrapped_proof)
    }

    fn verify_proof(
        proof: &WrappedProof<Self::ProofMetadata, Self::ProofType>,
    ) -> Result<(), Error> {
        let agg_stark_pk = AGG_STARK_PROVING_KEY
            .get()
            .ok_or(Error::VerifyProof(String::from(
                "agg stark pk not initialized! Prover::setup",
            )))?;

        let root_verifier_pk = &agg_stark_pk.root_verifier_pk;
        let vm = SingleSegmentVmExecutor::new(root_verifier_pk.vm_pk.vm_config.clone());
        let exe: &VmCommittedExe<_> = &root_verifier_pk.root_committed_exe;

        let _ = vm
            .execute_and_compute_heights(exe.exe.clone(), proof.proof.write())
            .map_err(|e| Error::VerifyProof(e.to_string()))?;

        Ok(())
    }
}
