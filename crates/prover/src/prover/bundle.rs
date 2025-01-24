use std::sync::Arc;

use openvm_native_recursion::halo2::EvmProof;
use openvm_sdk::{NonRootCommittedExe, config::SdkVmConfig, keygen::AppProvingKey};

use crate::{
    Error, Prover, ProverType, WrappedProof, proof::BundleProofMetadata,
    task::bundle::BundleProvingTask,
};

/// Prover for [`BundleCircuit`].
pub type BundleProver = Prover<BundleProverType>;

pub struct BundleProverType;

impl ProverType for BundleProverType {
    const NAME: &'static str = "bundle";

    const EVM: bool = true;

    type ProvingTask = BundleProvingTask;

    type ProofType = EvmProof;

    type ProofMetadata = BundleProofMetadata;

    fn build_proof_metadata(_task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error> {
        unimplemented!()
    }

    fn gen_proof(
        _app_pk: Arc<AppProvingKey<SdkVmConfig>>,
        _app_committed_exe: Arc<NonRootCommittedExe>,
        _task: &Self::ProvingTask,
    ) -> Result<WrappedProof<Self::ProofMetadata, Self::ProofType>, Error> {
        unimplemented!()
    }

    fn verify_proof(
        _proof: &WrappedProof<Self::ProofMetadata, Self::ProofType>,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}
