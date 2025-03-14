use std::{
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::Arc,
};

use once_cell::sync::Lazy;
use openvm_circuit::{arch::SingleSegmentVmExecutor, system::program::trace::VmCommittedExe};
use openvm_native_recursion::{
    halo2::{
        EvmProof,
        utils::{CacheHalo2ParamsReader, Halo2ParamsReader},
        wrapper::{EvmVerifier, Halo2WrapperProvingKey},
    },
    hints::Hintable,
};
pub use openvm_sdk::{self, F, SC};
use openvm_sdk::{
    NonRootCommittedExe, Sdk, StdIn,
    commit::AppExecutionCommit,
    config::{AggConfig, AggStarkConfig, SdkVmConfig},
    keygen::{AggStarkProvingKey, AppProvingKey, RootVerifierProvingKey},
    prover::{AggStarkProver, AppProver, ContinuationProver},
};
use serde::{Serialize, de::DeserializeOwned};
use tracing::{debug, instrument};

use crate::{
    Error, WrappedProof,
    proof::RootProof,
    setup::{read_app_config, read_app_exe},
    task::{ProvingTask, flatten_wrapped_proof},
};

mod batch;
pub use batch::{BatchProver, BatchProverType};

mod bundle;
pub use bundle::{BundleProver, BundleProverType};

mod chunk;
pub use chunk::{ChunkProver, ChunkProverType};
/// Proving key for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
static AGG_STARK_PROVING_KEY: Lazy<AggStarkProvingKey> =
    Lazy::new(|| AggStarkProvingKey::keygen(AggStarkConfig::default()));

/// The default directory to locate openvm's halo2 SRS parameters.
const DEFAULT_PARAMS_DIR: &str = concat!(env!("HOME"), "/.openvm/params/");

/// File descriptor for the root verifier's VM config.
const FD_ROOT_VERIFIER_VM_CONFIG: &str = "root-verifier-vm-config";

/// File descriptor for the root verifier's committed exe.
const FD_ROOT_VERIFIER_COMMITTED_EXE: &str = "root-verifier-committed-exe";

/// Types used in the outermost proof construction and verification, i.e. the EVM-compatible layer.
pub struct EvmProverVerifier {
    /// This is required only for [BundleProver].
    pub continuation_prover: ContinuationProver<SdkVmConfig>,
    /// The halo2 proving key.
    pub halo2_pk: Halo2WrapperProvingKey,
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
type InitRes = (
    Arc<VmCommittedExe<SC>>,
    Arc<AppProvingKey<SdkVmConfig>>,
    AppExecutionCommit<F>,
);

#[derive(Debug, Clone, Default)]
pub struct ProverConfig {
    pub segment_len: Option<usize>,
}

impl<Type: ProverType> Prover<Type> {
    /// Setup the [`Prover`] given paths to the application's exe and proving key.
    #[instrument("Prover::setup", fields(path_exe, path_app_config, cache_dir))]
    pub fn setup<P: AsRef<Path>>(
        path_exe: P,
        path_app_config: P,
        cache_dir: Option<P>,
        prover_config: ProverConfig,
    ) -> Result<Self, Error> {
        let (app_committed_exe, app_pk, _) =
            Self::init(&path_exe, &path_app_config, prover_config)?;

        let evm_prover = Type::EVM
            .then(|| {
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

                let halo2_params = halo2_params_reader
                    .read_params(agg_pk.halo2_pk.wrapper.pinning.metadata.config_params.k);
                let path_verifier_sol = path_exe
                    .as_ref()
                    .parent()
                    .map(|dir| dir.join("verifier.sol"));
                let path_verifier_bin = path_exe
                    .as_ref()
                    .parent()
                    .map(|dir| dir.join("verifier.bin"));
                let verifier_contract = EvmVerifier(scroll_zkvm_verifier::evm::gen_evm_verifier::<
                    scroll_zkvm_verifier::evm::halo2_aggregation::AggregationCircuit,
                >(
                    &halo2_params,
                    agg_pk.halo2_pk.wrapper.pinning.pk.get_vk(),
                    agg_pk.halo2_pk.wrapper.pinning.metadata.num_pvs.clone(),
                    path_verifier_sol.as_deref(),
                ));
                if let Some(path) = path_verifier_bin {
                    crate::utils::write(path, &verifier_contract.0)?;
                }

                let halo2_pk = agg_pk.halo2_pk.wrapper.clone();
                let continuation_prover = ContinuationProver::new(
                    &halo2_params_reader,
                    Arc::clone(&app_pk),
                    Arc::clone(&app_committed_exe),
                    agg_pk,
                );

                Ok::<EvmProverVerifier, Error>(EvmProverVerifier {
                    continuation_prover,
                    halo2_pk,
                    verifier_contract,
                })
            })
            .transpose()?;

        Ok(Self {
            app_committed_exe,
            app_pk,
            evm_prover,
            cache_dir: cache_dir.map(|path| PathBuf::from(path.as_ref())),
            _type: PhantomData,
        })
    }

    /// Read app exe, proving key and return committed data.
    #[instrument("Prover::init", fields(path_exe, path_app_config))]
    pub fn init<P: AsRef<Path>>(
        path_exe: P,
        path_app_config: P,
        prover_config: ProverConfig,
    ) -> Result<InitRes, Error> {
        let app_exe = read_app_exe(path_exe)?;
        let mut app_config = read_app_config(path_app_config)?;
        let segment_len = prover_config.segment_len.unwrap_or(Type::SEGMENT_SIZE);
        app_config.app_vm_config.system.config = app_config
            .app_vm_config
            .system
            .config
            .with_max_segment_len(segment_len);

        let app_pk = Sdk
            .app_keygen(app_config)
            .map_err(|e| Error::Keygen(e.to_string()))?;
        let app_committed_exe = Sdk
            .commit_app_exe(app_pk.app_fri_params(), app_exe)
            .map_err(|e| Error::Commit(e.to_string()))?;

        // print the 2 exe commitments
        use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
        let commits = AppExecutionCommit::compute(
            &app_pk.app_vm_pk.vm_config,
            &app_committed_exe,
            &app_pk.leaf_committed_exe,
        );
        let exe_commit = commits.exe_commit.map(|x| x.as_canonical_u32());
        let leaf_commit = commits
            .leaf_vm_verifier_commit
            .map(|x| x.as_canonical_u32());
        debug!(name: "exe-commitment", prover_name = Type::NAME, raw = ?exe_commit, as_bn254 = ?commits.exe_commit_to_bn254());
        debug!(name: "leaf-commitment", prover_name = Type::NAME, raw = ?leaf_commit, as_bn254 = ?commits.app_config_commit_to_bn254());
        Ok((app_committed_exe, Arc::new(app_pk), commits))
    }

    /// Dump assets required to setup verifier-only mode.
    pub fn dump_verifier<P: AsRef<Path>>(&self, dir: P) -> Result<(PathBuf, PathBuf), Error> {
        if !Type::EVM {
            return Err(Error::Custom(
                "dump_verifier only at bundle-prover".to_string(),
            ));
        };
        let root_verifier_pk = &AGG_STARK_PROVING_KEY.root_verifier_pk;
        let vm_config = root_verifier_pk.vm_pk.vm_config.clone();
        let root_committed_exe: &VmCommittedExe<_> = &root_verifier_pk.root_committed_exe;

        let path_vm_config = dir.as_ref().join(FD_ROOT_VERIFIER_VM_CONFIG);
        let path_root_committed_exe = dir.as_ref().join(FD_ROOT_VERIFIER_COMMITTED_EXE);

        crate::utils::write_bin(&path_vm_config, &vm_config)?;
        crate::utils::write_bin(&path_root_committed_exe, &root_committed_exe)?;

        Ok((path_vm_config, path_root_committed_exe))
    }

    /// Pick up app commit as "vk" in proof, to distinguish from which circuit the proof comes
    pub fn get_app_vk(&self) -> Vec<u8> {
        use openvm_sdk::commit::AppExecutionCommit;
        use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
        use scroll_zkvm_circuit_input_types::proof::ProgramCommitment;

        let app_pk = &self.app_pk;

        let commits = AppExecutionCommit::compute(
            &app_pk.app_vm_pk.vm_config,
            &self.app_committed_exe,
            &app_pk.leaf_committed_exe,
        );

        let exe = commits.exe_commit.map(|v| v.as_canonical_u32());
        let leaf = commits
            .leaf_vm_verifier_commit
            .map(|v| v.as_canonical_u32());

        ProgramCommitment { exe, leaf }.serialize()
    }

    /// Pick up the actual vk (serialized) for evm proof, would be empty if prover
    /// do not contain evm prover
    pub fn get_evm_vk(&self) -> Vec<u8> {
        self.evm_prover
            .as_ref()
            .map(|evm_prover| {
                scroll_zkvm_verifier::evm::serialize_vk(evm_prover.halo2_pk.pinning.pk.get_vk())
            })
            .unwrap_or_default()
    }

    /// Early-return if a proof is found in disc, otherwise generate and return the proof after
    /// writing to disc.
    #[instrument("Prover::gen_proof", skip_all, fields(task_id, prover_name = Type::NAME))]
    pub fn gen_proof(
        &self,
        task: &Type::ProvingTask,
    ) -> Result<WrappedProof<Type::ProofMetadata>, Error> {
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
        let wrapped_proof = WrappedProof::new(metadata, proof, Some(self.get_app_vk().as_slice()));

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
    ) -> Result<WrappedProof<Type::ProofMetadata>, Error> {
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
        let wrapped_proof = WrappedProof::new(metadata, proof, Some(self.get_evm_vk().as_slice()));

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
    pub fn verify_proof(&self, proof: &WrappedProof<Type::ProofMetadata>) -> Result<(), Error> {
        let agg_stark_pk = &AGG_STARK_PROVING_KEY;

        let root_verifier_pk = &agg_stark_pk.root_verifier_pk;
        let vm_executor = SingleSegmentVmExecutor::new(root_verifier_pk.vm_pk.vm_config.clone());
        let exe: &VmCommittedExe<_> = &root_verifier_pk.root_committed_exe;

        let root_proof = proof.proof.as_root_proof().ok_or(Error::VerifyProof(
            "verify_proof expects RootProof".to_string(),
        ))?;
        vm_executor
            .execute_and_compute_heights(exe.exe.clone(), root_proof.write())
            .map_err(|e| Error::VerifyProof(e.to_string()))?;

        let aggregation_input = flatten_wrapped_proof(proof);
        if aggregation_input.commitment.exe != Type::EXE_COMMIT {
            return Err(Error::VerifyProof(format!(
                "EXE_COMMIT mismatch: expected={:?}, got={:?}",
                Type::EXE_COMMIT,
                aggregation_input.commitment.exe,
            )));
        }
        if aggregation_input.commitment.leaf != Type::LEAF_COMMIT {
            return Err(Error::VerifyProof(format!(
                "LEAF_COMMIT mismatch: expected={:?}, got={:?}",
                Type::LEAF_COMMIT,
                aggregation_input.commitment.leaf,
            )));
        }

        Ok(())
    }

    /// Verify an [evm proof][evm_proof].
    ///
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    #[instrument("Prover::verify_proof_evm", skip_all)]
    pub fn verify_proof_evm(&self, proof: &WrappedProof<Type::ProofMetadata>) -> Result<(), Error> {
        let evm_proof = proof.proof.as_evm_proof().ok_or(Error::VerifyProof(
            "verify_proof_evm expects EvmProof".to_string(),
        ))?;
        let contract = &self
            .evm_prover
            .as_ref()
            .expect("uninited")
            .verifier_contract;
        let gas_cost = scroll_zkvm_verifier::evm::verify_evm_proof(contract, &evm_proof)
            .map_err(|e| Error::VerifyProof(format!("EVM-proof verification failed: {e}")))?;

        tracing::info!(name: "verify_evm_proof", ?gas_cost);

        Ok(())
    }

    /// Execute the guest program to get the cycle count.
    pub fn execute_and_check(&self, stdin: &StdIn, mock_prove: bool) -> Result<u64, Error> {
        let config = self.app_pk.app_vm_pk.vm_config.clone();
        let exe = self.app_committed_exe.exe.clone();
        let debug_input = crate::utils::vm::DebugInput {
            mock_prove,
            commited_exe: mock_prove.then(|| self.app_committed_exe.clone()),
        };
        let exec_result = crate::utils::vm::execute_guest(config, exe, stdin, &debug_input)?;
        Ok(exec_result.total_cycle as u64)
    }

    /// File descriptor for the proof saved to disc.
    #[instrument("Prover::fd_proof", skip_all, fields(task_id = task.identifier(), path_proof))]
    fn fd_proof(task: &Type::ProvingTask) -> String {
        let path_proof = format!("{}-{}.json", Type::NAME, task.identifier());
        path_proof
    }

    /// Generate a [root proof][root_proof].
    ///
    /// [root_proof][openvm_sdk::verifier::root::types::RootVmVerifierInput]
    fn gen_proof_stark(&self, task: &Type::ProvingTask) -> Result<RootProof, Error> {
        let stdin = task
            .build_guest_input()
            .map_err(|e| Error::GenProof(e.to_string()))?;

        let mock_prove = std::env::var("MOCK_PROVE").as_deref() == Ok("true");
        // Here we always do an execution of the guest program to get the cycle count.
        // and do precheck before proving like ensure PI != 0
        self.execute_and_check(&stdin, mock_prove)?;

        let task_id = task.identifier();

        tracing::debug!(name: "generate_root_verifier_input", ?task_id);
        let app_prover = AppProver::new(
            self.app_pk.app_vm_pk.clone(),
            self.app_committed_exe.clone(),
        );
        // TODO: should we cache the app_proof?
        let app_proof = app_prover.generate_app_proof(stdin);
        tracing::info!("app proof generated for {} task {task_id}", Type::NAME);
        let agg_prover = AggStarkProver::new(
            AGG_STARK_PROVING_KEY.clone(),
            self.app_pk.leaf_committed_exe.clone(),
        );
        let proof = agg_prover.generate_root_verifier_input(app_proof);
        Ok(proof)
    }

    /// Generate an [evm proof][evm_proof].
    ///
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    fn gen_proof_snark(&self, task: &Type::ProvingTask) -> Result<EvmProof, Error> {
        let stdin = task
            .build_guest_input()
            .map_err(|e| Error::GenProof(e.to_string()))?;

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

    /// The size of a segment, i.e. the max height of its chips.
    const SEGMENT_SIZE: usize;

    /// The app program's exe commitment.
    const EXE_COMMIT: [u32; 8];

    /// The app program's leaf commitment.
    const LEAF_COMMIT: [u32; 8];

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
