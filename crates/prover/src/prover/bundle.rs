use openvm_native_recursion::halo2::EvmProof;
use scroll_zkvm_circuit_input_types::{PublicInputs, bundle::BundleInfo};

use crate::{
    Error, Prover, ProverType,
    commitments::bundle::{EXE_COMMIT as BUNDLE_EXE_COMMIT, LEAF_COMMIT as BUNDLE_LEAF_COMMIT},
    proof::BundleProofMetadata,
    setup::read_app_config,
    task::{ProvingTask, bundle::BundleProvingTask},
};

use openvm_stark_sdk::config::FriParameters;

/// Prover for [`BundleCircuit`].
pub type BundleProver = Prover<BundleProverType>;

pub struct BundleProverType;

impl ProverType for BundleProverType {
    const NAME: &'static str = "bundle";

    const EVM: bool = true;

    const EXE_COMMIT: [u32; 8] = BUNDLE_EXE_COMMIT;

    const LEAF_COMMIT: [u32; 8] = BUNDLE_LEAF_COMMIT;

    type ProvingTask = BundleProvingTask;

    type ProofType = EvmProof;

    type ProofMetadata = BundleProofMetadata;

    fn read_app_config<P: AsRef<std::path::Path>>(
        path_app_config: P,
    ) -> Result<openvm_sdk::config::AppConfig<openvm_sdk::config::SdkVmConfig>, Error> {
        let mut app_config = read_app_config(path_app_config)?;
        app_config.app_vm_config.castf = Some(openvm_native_circuit::CastFExtension);

        app_config.app_fri_params.fri_params =
            FriParameters::standard_with_100_bits_conjectured_security(1 /* app_log_blowup */);
        app_config.app_vm_config.system.config = app_config
            .app_vm_config
            .system
            .config
            .with_max_segment_len((1 << 22) - 100);

        Ok(app_config)
    }

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

        let (first_batch, last_batch) = (
            &task
                .batch_proofs
                .first()
                .expect("at least one batch in bundle")
                .metadata
                .batch_info,
            &task
                .batch_proofs
                .last()
                .expect("at least one batch in bundle")
                .metadata
                .batch_info,
        );

        let chain_id = first_batch.chain_id;
        let num_batches = u32::try_from(task.batch_proofs.len()).expect("num_batches: u32");
        let prev_state_root = first_batch.parent_state_root;
        let prev_batch_hash = first_batch.parent_batch_hash;
        let post_state_root = last_batch.state_root;
        let batch_hash = last_batch.batch_hash;
        let withdraw_root = last_batch.withdraw_root;

        let bundle_info = BundleInfo {
            chain_id,
            num_batches,
            prev_state_root,
            prev_batch_hash,
            post_state_root,
            batch_hash,
            withdraw_root,
        };
        let bundle_pi_hash = bundle_info.pi_hash();

        Ok(BundleProofMetadata {
            bundle_info,
            bundle_pi_hash,
        })
    }
}
