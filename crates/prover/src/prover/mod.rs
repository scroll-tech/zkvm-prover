use std::{
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::Arc,
};

use once_cell::sync::OnceCell;
use openvm_circuit::{arch::SingleSegmentVmExecutor, system::program::trace::VmCommittedExe};
use openvm_native_recursion::{
    halo2::{EvmProof, utils::CacheHalo2ParamsReader, wrapper::EvmVerifier},
    hints::Hintable,
};
use openvm_sdk::{
    NonRootCommittedExe, Sdk, StdIn,
    config::{AggConfig, AggStarkConfig, SdkVmConfig},
    keygen::{AggStarkProvingKey, AppProvingKey, RootVerifierProvingKey},
    prover::ContinuationProver,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;
use serde::{Serialize, de::DeserializeOwned};
use tracing::{debug, instrument};

use crate::{
    Error, WrappedProof,
    proof::RootProof,
    setup::{read_app_exe, read_app_pk},
    task::ProvingTask,
};

mod batch;
pub use batch::{BatchProver, BatchProverType};

mod bundle;
pub use bundle::{BundleProver, BundleProverType};

mod chunk;
pub use chunk::{ChunkProver, ChunkProverType};

/// Proving key for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
static AGG_STARK_PROVING_KEY: OnceCell<AggStarkProvingKey> = OnceCell::new();

/// The default directory to locate openvm's halo2 SRS parameters.
const DEFAULT_PARAMS_DIR: &str = concat!(env!("HOME"), "/.openvm/params/");

/// Types used in the outermost proof construction and verification, i.e. the EVM-compatible layer.
pub struct EvmProverVerifier {
    /// This is required only for [BundleProver].
    pub continuation_prover: ContinuationProver<SdkVmConfig>,
    /// The contract bytecode for the EVM verifier contract.
    pub verifier_contract: EvmVerifier,
}

/// Generic prover.
pub struct Prover<Type> {
    /// Commitment to app exe.
    pub app_committed_exe: Arc<NonRootCommittedExe>,
    /// App specific proving key.
    pub app_pk: Arc<AppProvingKey<SdkVmConfig>>,
    /// Optional data for the outermost layer, i.e. EVM-compatible.
    pub evm_prover: Option<EvmProverVerifier>,
    /// Optional directory to cache generated proofs. If such a cached proof is located, then its
    /// returned instead of re-generating a proof.
    pub cache_dir: Option<PathBuf>,

    _type: PhantomData<Type>,
}

/// Alias for convenience.
type InitRes = Result<(Arc<VmCommittedExe<SC>>, Arc<AppProvingKey<SdkVmConfig>>), Error>;

/// Alias for convenience.
pub type SC = BabyBearPoseidon2Config;

impl<Type: ProverType> Prover<Type> {
    /// Setup the [`Prover`] given paths to the application's exe and proving key.
    #[instrument("Prover::setup", skip_all, fields(path_exe, path_pk, cache_dir))]
    pub fn setup<P: AsRef<Path>>(
        path_exe: P,
        path_pk: P,
        cache_dir: Option<P>,
    ) -> Result<Self, Error> {
        let (app_committed_exe, app_pk) = Self::init(path_exe, path_pk)?;

        // TODO(rohit): allow to pass custom halo2-params path.
        let halo2_params_reader = CacheHalo2ParamsReader::new(DEFAULT_PARAMS_DIR);
        let agg_pk = Sdk
            .agg_keygen(
                AggConfig::default(),
                &halo2_params_reader,
                None::<&RootVerifierProvingKey>,
            )
            .map_err(|e| Error::Setup {
                path: PathBuf::from(DEFAULT_PARAMS_DIR),
                src: e.to_string(),
            })?;

        let evm_prover = Type::EVM.then_some({
            let verifier_contract = Sdk
                .generate_snark_verifier_contract(&halo2_params_reader, &agg_pk)
                .expect("openvm_sdk::generate_snark_verifier_contract should succeed");

            let continuation_prover = ContinuationProver::new(
                &halo2_params_reader,
                Arc::clone(&app_pk),
                Arc::clone(&app_committed_exe),
                agg_pk,
            );

            EvmProverVerifier {
                continuation_prover,
                verifier_contract,
            }
        });

        Ok(Self {
            app_committed_exe,
            app_pk,
            evm_prover,
            cache_dir: cache_dir.map(|path| PathBuf::from(path.as_ref())),
            _type: PhantomData,
        })
    }

    /// Early-return if a proof is found in disc, otherwise generate and return the proof after
    /// writing to disc.
    #[instrument("Prover::gen_proof", skip_all, fields(task_id))]
    pub fn gen_proof(
        &self,
        task: &Type::ProvingTask,
    ) -> Result<WrappedProof<Type::ProofMetadata, RootProof>, Error> {
        let task_id = task.identifier();

        // Try reading proof from cache if available, and early return in that case.
        if let Some(dir) = &self.cache_dir {
            let path_proof = dir.join(Self::fd_proof(task));
            debug!(name: "try_read_proof", ?task_id, ?path_proof);

            if let Ok(proof) = crate::utils::read_json_deep(&path_proof) {
                debug!(name: "early_return_proof", ?task_id);
                return Ok(proof);
            }
        }

        // Generate a new proof.
        assert!(!Type::EVM, "Prover::gen_proof not for EVM-prover");
        let metadata = Self::metadata_with_prechecks(task)?;
        let proof = self.gen_proof_stark(task)?;
        let wrapped_proof = WrappedProof::new(metadata, proof);

        // Write proof to disc if caching was enabled.
        if let Some(dir) = &self.cache_dir {
            let path_proof = dir.join(Self::fd_proof(task));
            debug!(name: "try_write_proof", ?task_id, ?path_proof);

            crate::utils::write_json(&path_proof, &wrapped_proof)?;
        }

        Ok(wrapped_proof)
    }

    /// Early-return if a proof is found in disc, otherwise generate and return the proof after
    /// writing to disc.
    #[instrument("Prover::gen_proof_evm", skip_all, fields(task_id))]
    pub fn gen_proof_evm(
        &self,
        task: &Type::ProvingTask,
    ) -> Result<WrappedProof<Type::ProofMetadata, EvmProof>, Error> {
        let task_id = task.identifier();

        // Try reading proof from cache if available, and early return in that case.
        if let Some(dir) = &self.cache_dir {
            let path_proof = dir.join(Self::fd_proof(task));
            debug!(name: "try_read_proof", ?task_id, ?path_proof);

            if let Ok(proof) = crate::utils::read_json_deep(&path_proof) {
                debug!(name: "early_return_proof", ?task_id);
                return Ok(proof);
            }
        }

        // Generate a new proof.
        assert!(Type::EVM, "Prover::gen_proof_evm only for EVM-prover");
        let metadata = Self::metadata_with_prechecks(task)?;
        let proof = self.gen_proof_snark(task)?;
        let wrapped_proof = WrappedProof::new(metadata, proof);

        // Write proof to disc if caching was enabled.
        if let Some(dir) = &self.cache_dir {
            let path_proof = dir.join(Self::fd_proof(task));
            debug!(name: "try_write_proof", ?task_id, ?path_proof);

            crate::utils::write_json(&path_proof, &wrapped_proof)?;
        }

        Ok(wrapped_proof)
    }

    /// Validate some pre-checks on the proving task and construct proof metadata.
    #[instrument("Prover::metadata_with_prechecks", skip_all, fields(?task_id = task.identifier()))]
    pub fn metadata_with_prechecks(task: &Type::ProvingTask) -> Result<Type::ProofMetadata, Error> {
        Type::metadata_with_prechecks(task)
    }

    /// Verify a [root proof][root_proof].
    ///
    /// [root_proof][RootProof]
    #[instrument("Prover::verify_proof", skip_all, fields(?metadata = proof.metadata))]
    pub fn verify_proof(
        &self,
        proof: &WrappedProof<Type::ProofMetadata, RootProof>,
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

    /// Verify an [evm proof][evm_proof].
    ///
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    #[instrument("Prover::verify_proof_evm", skip_all)]
    pub fn verify_proof_evm(
        &self,
        proof: &WrappedProof<Type::ProofMetadata, EvmProof>,
    ) -> Result<(), Error> {
        Sdk.verify_evm_proof(
            &self.evm_prover.as_ref().expect("").verifier_contract,
            &proof.proof,
        )
        .then_some(())
        .ok_or(Error::VerifyProof(
            "EVM-proof verification failed".to_string(),
        ))
    }

    /// File descriptor for the proof saved to disc.
    #[instrument("Prover::fd_proof", skip_all, fields(task_id = task.identifier(), path_proof))]
    fn fd_proof(task: &Type::ProvingTask) -> String {
        let path_proof = format!("{}-{}.json", Type::NAME, task.identifier());
        path_proof
    }

    /// Read app exe, proving key and return committed data.
    #[instrument("Prover::init", fields(path_exe, path_pk))]
    fn init<P: AsRef<Path>>(path_exe: P, path_pk: P) -> InitRes {
        let app_exe = read_app_exe(path_exe)?;
        let app_pk = read_app_pk(path_pk)?;
        let app_committed_exe = Sdk
            .commit_app_exe(app_pk.app_fri_params(), app_exe)
            .map_err(|e| Error::Commit(e.to_string()))?;

        let _agg_stark_pk = AGG_STARK_PROVING_KEY
            .get_or_init(|| AggStarkProvingKey::keygen(AggStarkConfig::default()));

        Ok((app_committed_exe, Arc::new(app_pk)))
    }

    /// Generate a [root proof][root_proof].
    ///
    /// [root_proof][openvm_sdk::verifier::root::types::RootVmVerifierInput]
    fn gen_proof_stark(&self, task: &Type::ProvingTask) -> Result<RootProof, Error> {
        let agg_stark_pk = AGG_STARK_PROVING_KEY
            .get()
            .ok_or(Error::GenProof(String::from(
                "agg stark pk not initialized! Prover::setup",
            )))?;

        let serialized = task
            .to_witness_serialized()
            .map_err(|e| Error::GenProof(e.to_string()))?;

        let mut stdin = StdIn::default();
        stdin.write_bytes(&serialized);

        let task_id = task.identifier();

        tracing::debug!(name: "generate_root_verifier_input", ?task_id);
        Sdk.generate_root_verifier_input(
            Arc::clone(&self.app_pk),
            Arc::clone(&self.app_committed_exe),
            agg_stark_pk.clone(),
            stdin,
        )
        .map_err(|e| Error::GenProof(e.to_string()))
    }

    /// Generate an [evm proof][evm_proof].
    ///
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    fn gen_proof_snark(&self, task: &Type::ProvingTask) -> Result<EvmProof, Error> {
        let serialized = task
            .to_witness_serialized()
            .map_err(|e| Error::GenProof(e.to_string()))?;

        let mut stdin = StdIn::default();
        stdin.write_bytes(&serialized);

        Ok(self
            .evm_prover
            .as_ref()
            .expect("Prover::gen_proof_snark expects EVM-prover setup")
            .continuation_prover
            .generate_proof_for_evm(stdin))
    }
}

pub trait ProverType {
    /// The name given to the prover, this is also used as a prefix while storing generated proofs
    /// to disc.
    const NAME: &'static str;

    /// Whether this prover generates SNARKs that are EVM-verifiable. In our context, only the
    /// [`BundleProver`] has the EVM set to `true`.
    const EVM: bool;

    /// The task provided as argument during proof generation process.
    type ProvingTask: ProvingTask;

    /// The proof type, i.e. whether [root proof][root_proof] or [evm proof][evm_proof].
    ///
    /// [root_proof][openvm_sdk::verifier::root::types::RootVmVerifierInput]
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    type ProofType: Serialize + DeserializeOwned;

    /// The metadata accompanying the wrapper proof generated by this prover.
    type ProofMetadata: Serialize + DeserializeOwned + std::fmt::Debug;

    /// Provided the proving task, computes the proof metadata.
    fn metadata_with_prechecks(task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error>;
}
