use openvm_native_recursion::halo2::EvmProof;

use crate::{
    Error, Prover, ProverType,
    proof::BundleProofMetadata,
    task::{ProvingTask, bundle::BundleProvingTask},
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

    fn metadata_with_prechecks(task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error> {
        let err_prefix = format!("metadata_with_prechecks for task_id={}", task.identifier());

        for w in task.batch_proofs.windows(2) {
            if w[1].metadata.batch_info.chain_id != w[0].metadata.batch_info.chain_id {
                return Err(Error::GenProof(format!("{err_prefix}: chain_id mismatch")));
            }

            if w[1].metadata.batch_info.parent_state_root != w[0].metadata.batch_info.state_root {
                return Err(Error::GenProof(format!(
                    "{err_prefix}: state_root not chained"
                )));
            }

            if w[1].metadata.batch_info.parent_batch_hash != w[0].metadata.batch_info.batch_hash {
                return Err(Error::GenProof(format!(
                    "{err_prefix}: batch_hash not chained"
                )));
            }
        }

        Ok(BundleProofMetadata)
    }
}
