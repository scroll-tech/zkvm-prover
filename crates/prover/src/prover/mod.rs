use std::{
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::Arc,
};

use once_cell::sync::OnceCell;
use openvm_circuit::system::program::trace::VmCommittedExe;
use openvm_native_recursion::halo2::wrapper::EvmVerifier;
use openvm_sdk::{
    NonRootCommittedExe, Sdk,
    config::{AggStarkConfig, SdkVmConfig},
    keygen::{AggStarkProvingKey, AppProvingKey, Halo2ProvingKey},
};
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;
use serde::{Serialize, de::DeserializeOwned};
use tracing::{debug, instrument};

use crate::{
    Error, WrappedProof,
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

/// Types used in the outermost proof construction and verification, i.e. the EVM-compatible layer.
pub struct OutermostData {
    /// Halo2 proving key. This is required only for [BundleProver].
    pub halo2_pk: Halo2ProvingKey,
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
    pub outermost_data: Option<OutermostData>,
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
    /// Early-return if a proof is found in disc, otherwise generate and return the proof after
    /// writing to disc.
    #[instrument("Prover::gen_proof", skip_all, fields(task_id))]
    pub fn gen_proof(
        &self,
        task: &Type::ProvingTask,
    ) -> Result<WrappedProof<Type::ProofMetadata, Type::ProofType>, Error> {
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
        let proof = self.gen_proof_inner(task)?;

        // Write proof to disc if caching was enabled.
        if let Some(dir) = &self.cache_dir {
            let path_proof = dir.join(Self::fd_proof(task));
            debug!(name: "try_write_proof", ?task_id, ?path_proof);

            crate::utils::write_json(&path_proof, &proof)?;
        }

        Ok(proof)
    }

    /// Setup the [`Prover`] given paths to the application's exe and proving key.
    #[instrument("Prover::setup", skip_all, fields(path_exe, path_pk, cache_dir))]
    pub fn setup<P: AsRef<Path>>(
        path_exe: P,
        path_pk: P,
        cache_dir: Option<P>,
    ) -> Result<Self, Error> {
        let (app_committed_exe, app_pk) = Self::init(path_exe, path_pk)?;

        Ok(Self {
            app_committed_exe,
            app_pk,
            outermost_data: None,
            cache_dir: cache_dir.map(|path| PathBuf::from(path.as_ref())),
            _type: PhantomData,
        })
    }

    /// Construct proof metadata from proving task.
    #[instrument("Prover::metadata", skip_all, fields(?task_id = task.identifier()))]
    pub fn metadata(task: &Type::ProvingTask) -> Result<Type::ProofMetadata, Error> {
        Type::build_proof_metadata(task)
    }

    /// Verify a [root proof][root_proof] or [evm proof][evm_proof].
    ///
    /// [root_proof][openvm_sdk::verifier::root::types::RootVmVerifierInput]
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    #[instrument("Prover::verify_proof", skip_all, fields(?metadata = proof.metadata))]
    pub fn verify_proof(
        &self,
        proof: &WrappedProof<Type::ProofMetadata, Type::ProofType>,
    ) -> Result<(), Error> {
        Type::verify_proof(proof)
    }

    /// Generate a [root proof][root_proof] or [evm proof][evm_proof].
    ///
    /// [root_proof][openvm_sdk::verifier::root::types::RootVmVerifierInput]
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    #[instrument("Prover::gen_proof_inner", skip_all, fields(task_id))]
    fn gen_proof_inner(
        &self,
        task: &Type::ProvingTask,
    ) -> Result<WrappedProof<Type::ProofMetadata, Type::ProofType>, Error> {
        Type::gen_proof(
            Arc::clone(&self.app_pk),
            Arc::clone(&self.app_committed_exe),
            task,
        )
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

    /// File descriptor for the proof saved to disc.
    #[instrument("Prover::fd_proof", skip_all, fields(task_id = task.identifier(), path_proof))]
    fn fd_proof(task: &Type::ProvingTask) -> String {
        let path_proof = format!("{}-{}.json", Type::NAME, task.identifier());
        path_proof
    }
}

pub trait ProverType {
    const NAME: &'static str;

    const EVM: bool;

    type ProvingTask: ProvingTask;

    type ProofType: Serialize + DeserializeOwned;

    type ProofMetadata: Serialize + DeserializeOwned + std::fmt::Debug;

    fn build_proof_metadata(task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error>;

    fn gen_proof(
        app_pk: Arc<AppProvingKey<SdkVmConfig>>,
        app_committed_exe: Arc<NonRootCommittedExe>,
        task: &Self::ProvingTask,
    ) -> Result<WrappedProof<Self::ProofMetadata, Self::ProofType>, Error>;

    fn verify_proof(
        proof: &WrappedProof<Self::ProofMetadata, Self::ProofType>,
    ) -> Result<(), Error>;
}
