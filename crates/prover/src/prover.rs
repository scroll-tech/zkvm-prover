use std::{path::Path, sync::Arc};

use once_cell::sync::OnceCell;
use openvm_circuit::system::program::trace::VmCommittedExe;
use openvm_sdk::{
    NonRootCommittedExe, Sdk,
    config::SdkVmConfig,
    keygen::{AggStarkProvingKey, AppProvingKey, Halo2ProvingKey},
    verifier::root::types::RootVmVerifierInput,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;
use rkyv::{api::high::HighSerializer, ser::allocator::ArenaHandle, util::AlignedVec};

use crate::{Error, read_app_exe, read_app_pk};

type SC = BabyBearPoseidon2Config;

/// Proving key for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
static AGG_STARK_PROVING_KEY: OnceCell<AggStarkProvingKey> = OnceCell::new();

/// Generic prover.
pub struct TypeProver<VC> {
    /// Commitment to app exe.
    pub app_committed_exe: Arc<NonRootCommittedExe>,
    /// App specific proving key.
    pub app_pk: Arc<AppProvingKey<VC>>,
    /// Optional halo2 proving key. This is required only for [BundleProver].
    pub halo2_pk: Option<Halo2ProvingKey>,
}

/// Prover for [`ChunkCircuit`].
pub type ChunkProver = TypeProver<SdkVmConfig>;
/// Prover for [`BatchCircuit`].
pub type BatchProver = TypeProver<SdkVmConfig>;
/// Prover for [`BundleCircuit`].
pub type BundleProver = TypeProver<SdkVmConfig>;

/// Alias for convenience.
type InitRes = Result<(Arc<VmCommittedExe<SC>>, Arc<AppProvingKey<SdkVmConfig>>), Error>;

/// Trait that defines required behaviour from a zkvm-based prover/verifier.
pub trait ProverVerifier: Sized {
    /// The input witness type for proof generation.
    type Witness: for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rkyv::rancor::Error>>;

    /// The output proof type.
    type Proof: Clone;

    const EVM: bool;

    fn init<P: AsRef<Path>>(path_exe: P, path_pk: P) -> InitRes {
        let app_exe = read_app_exe(path_exe)?;
        let app_pk = read_app_pk(path_pk)?;
        let app_committed_exe = Sdk
            .commit_app_exe(app_pk.app_fri_params(), app_exe)
            .map_err(|e| Error::Commit(e.to_string()))?;

        Ok((app_committed_exe, Arc::new(app_pk)))
    }

    fn setup<P: AsRef<Path>>(path_exe: P, path_pk: P) -> Result<Self, Error>;

    /// Generate a [root proof][openvm_sdk::verifier::root::types::RootVmVerifierInput] or [evm
    /// proof][openvm_native_recursion::halo2::EvmProof].
    fn gen_proof(&self, witness: &Self::Witness) -> Result<Self::Proof, Error> {
        let _serialized = rkyv::to_bytes::<rkyv::rancor::Error>(witness)
            .map_err(|e| Error::GenProof(e.to_string()))?;

        unimplemented!()
    }

    /// Verify proof.
    fn verify_proof(&self, _proof: Self::Proof) -> Result<(), Error> {
        unimplemented!()
    }
}

impl ProverVerifier for ChunkProver {
    type Witness = Vec<usize>;

    type Proof = RootVmVerifierInput<SC>;

    const EVM: bool = false;

    fn setup<P: AsRef<Path>>(path_exe: P, path_pk: P) -> Result<Self, Error> {
        let (app_committed_exe, app_pk) = Self::init(path_exe, path_pk)?;

        Ok(Self {
            app_committed_exe,
            app_pk,
            halo2_pk: None,
        })
    }
}
