use std::{
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

use crate::{
    Error,
    setup::{read_app_exe, read_app_pk},
    task::ProvingTask,
};

mod batch;
pub use batch::BatchProver;

mod bundle;
pub use bundle::BundleProver;

mod chunk;
pub use chunk::ChunkProver;

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
pub struct Prover<VC> {
    /// Commitment to app exe.
    pub app_committed_exe: Arc<NonRootCommittedExe>,
    /// App specific proving key.
    pub app_pk: Arc<AppProvingKey<VC>>,
    /// Optional data for the outermost layer, i.e. EVM-compatible.
    pub outermost_data: Option<OutermostData>,
    /// Optional directory to cache generated proofs. If such a cached proof is located, then its
    /// returned instead of re-generating a proof.
    pub cache_dir: Option<PathBuf>,
}

pub trait ProofCachingProver: Sized {
    fn cache_dir(&self) -> Option<&PathBuf>;
}

impl<VC> ProofCachingProver for Prover<VC> {
    fn cache_dir(&self) -> Option<&PathBuf> {
        self.cache_dir.as_ref()
    }
}

/// Alias for convenience.
type InitRes = Result<(Arc<VmCommittedExe<SC>>, Arc<AppProvingKey<SdkVmConfig>>), Error>;

/// Alias for convenience.
pub type SC = BabyBearPoseidon2Config;

/// Trait that defines required behaviour from a zkvm-based prover/verifier.
pub trait ProverVerifier: ProofCachingProver {
    /// The input witness type for proof generation.
    type ProvingTask: ProvingTask;

    /// The output proof type.
    type Proof: Clone + Serialize + DeserializeOwned;

    /// The metadata accompanying the generated proof.
    type ProofMetadata: Clone + Serialize + DeserializeOwned;

    /// Prefix for cached data.
    const PREFIX: &str;

    /// Whether or not the prover is the outermost proving layer, i.e. EVM-compatible. When this is
    /// true, the prover initialises a HALO2-proving key for the SNARK proof to be verified in EVM.
    ///
    /// This is `true` for [`BundleProver`].
    const EVM: bool;

    /// Read app exe, proving key and return committed data.
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
    fn fd_proof(task: &Self::ProvingTask) -> String {
        format!("{}-{}.json", Self::PREFIX, task.identifier())
    }

    /// Setup the [`Prover`] given paths to the application's exe and proving key.
    fn setup<P: AsRef<Path>>(path_exe: P, path_pk: P, cache_dir: Option<P>) -> Result<Self, Error>;

    /// Construct proof metadata from proving task.
    fn metadata(task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error>;

    /// Early-return if a proof is found in disc, otherwise generate and return the proof after
    /// writing to disc.
    fn gen_proof(&self, task: &Self::ProvingTask) -> Result<Self::Proof, Error> {
        // Try reading proof from cache if available, and early return in that case.
        if let Some(dir) = self.cache_dir() {
            let path_proof = dir.join(Self::fd_proof(task));
            if let Ok(proof) = crate::utils::read_json_deep(&path_proof) {
                return Ok(proof);
            }
        }

        // Generate a new proof.
        let proof = self.gen_proof_inner(task)?;

        // Write proof to disc if caching was enabled.
        if let Some(dir) = self.cache_dir() {
            let path_proof = dir.join(Self::fd_proof(task));
            crate::utils::write_json(&path_proof, &proof)?;
        }

        Ok(proof)
    }

    /// Generate a [root proof][root_proof] or [evm proof][evm_proof].
    ///
    /// [root_proof][openvm_sdk::verifier::root::types::RootVmVerifierInput]
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    fn gen_proof_inner(&self, task: &Self::ProvingTask) -> Result<Self::Proof, Error>;

    /// Verify a [root proof][root_proof] or [evm proof][evm_proof].
    ///
    /// [root_proof][openvm_sdk::verifier::root::types::RootVmVerifierInput]
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    fn verify_proof(&self, proof: Self::Proof) -> Result<(), Error>;
}
