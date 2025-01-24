use openvm_native_recursion::halo2::EvmProof;

use crate::{
    Error, Prover, ProverType, proof::BundleProofMetadata, task::bundle::BundleProvingTask,
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
}
