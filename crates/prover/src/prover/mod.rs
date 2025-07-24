use std::{
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::Arc,
};

use once_cell::sync::Lazy;
use openvm_circuit::system::program::trace::VmCommittedExe;
use openvm_native_recursion::{
    halo2::{
        RawEvmProof,
        utils::{CacheHalo2ParamsReader, Halo2ParamsReader},
        wrapper::Halo2WrapperProvingKey,
    },
    hints::Hintable,
};
use openvm_sdk::{config::SdkVmCpuBuilder, fs::read_exe_from_file};
use openvm_sdk::{
    DefaultStaticVerifierPvHandler, NonRootCommittedExe, Sdk, StdIn,
    commit::AppExecutionCommit,
    config::{AggConfig, AggStarkConfig, SdkVmConfig},
    keygen::{AggProvingKey, AggStarkProvingKey, AppProvingKey},
    prover::{AggStarkProver, AppProver, EvmHalo2Prover},
    types::EvmProof as OpenVmEvmProf,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Engine;
use scroll_zkvm_verifier::verifier::verify_stark_proof;
use tracing::{debug, instrument};

// Re-export from openvm_sdk.
pub use openvm_sdk::{self, SC};

use crate::{
    Error,
    proof::{PersistableProof, ProofMetadata, WrappedProof},
    setup::{read_app_config},
    task::ProvingTask,
};

use scroll_zkvm_types::proof::{EvmProof, ProofEnum, StarkProof};

mod batch;
pub use batch::{BatchProver, BatchProverType};

mod bundle;
pub use bundle::{BundleProverEuclidV2, BundleProverTypeEuclidV2, GenericBundleProverType};

mod chunk;
pub use chunk::{ChunkProver, ChunkProverType, GenericChunkProverType};

/// Proving key for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
static AGG_STARK_PROVING_KEY: Lazy<AggStarkProvingKey> =
    Lazy::new(|| AggStarkProvingKey::keygen(AggStarkConfig::default()).unwrap());

/// The default directory to locate openvm's halo2 SRS parameters.
const DEFAULT_PARAMS_DIR: &str = concat!(env!("HOME"), "/.openvm/params/");

/// The environment variable that needs to be set in order to configure the directory from where
/// Prover can read HALO2 trusted setup parameters.
const ENV_HALO2_PARAMS_DIR: &str = "ENV_HALO2_PARAMS_DIR";

/// File descriptor for the root verifier's VM config.
const FD_ROOT_VERIFIER_VM_CONFIG: &str = "root-verifier-vm-config";

/// File descriptor for the root verifier's committed exe.
const FD_ROOT_VERIFIER_COMMITTED_EXE: &str = "root-verifier-committed-exe";

pub trait Commitments {
    const EXE_COMMIT: [u32; 8];
    const LEAF_COMMIT: [u32; 8];
}

/// Types used in the outermost proof construction and verification, i.e. the EVM-compatible layer.
/// This is required only for [BundleProver].
pub struct EvmProverVerifier {
    pub reader: CacheHalo2ParamsReader,
    pub agg_pk: AggProvingKey,
    /// The contract bytecode for the EVM verifier contract.
    pub verifier_contract: Vec<u8>,
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
    pub config: ProverConfig,

    _type: PhantomData<Type>,
}

/// Alias for convenience.
type InitRes = (Arc<VmCommittedExe<SC>>, Arc<AppProvingKey<SdkVmConfig>>);

/// Configure the [`Prover`].
#[derive(Debug, Clone, Default)]
pub struct ProverConfig {
    /// Path to find applications's app.vmexe.
    pub path_app_exe: PathBuf,
    /// Path to find application's OpenVM config.
    pub path_app_config: PathBuf,
    /// An optional directory to cache generated proofs.
    ///
    /// If a proof is already available in the cache directory, the proof generation method will
    /// early return with the available proof on disk.
    pub dir_cache: Option<PathBuf>,
    /// An optional directory to locate HALO2 trusted setup parameters.
    pub dir_halo2_params: Option<PathBuf>,
    /// The maximum length for a single OpenVM segment.
    pub segment_len: Option<usize>,
}

impl<Type: ProverType> Prover<Type> {
    /// Setup the [`Prover`] given paths to the application's exe and proving key.
    #[instrument("Prover::setup")]
    pub fn setup(config: ProverConfig) -> Result<Self, Error> {
        let (app_committed_exe, app_pk) = Self::init(&config)?;

        let evm_prover = Type::EVM
            .then(|| Self::setup_evm_prover(&config))
            .transpose()?;

        Ok(Self {
            app_committed_exe,
            app_pk,
            evm_prover,
            cache_dir: config.dir_cache.clone(),
            config: config,
            _type: PhantomData,
        })
    }

    /// Read app exe, proving key and return committed data.
    #[instrument("Prover::init")]
    pub fn init(config: &ProverConfig) -> Result<InitRes, Error> {
        let app_exe = read_exe_from_file(&config.path_app_exe).unwrap();
        let mut app_config = read_app_config(&config.path_app_config)?;
        let segment_len = config.segment_len.unwrap_or(Type::SEGMENT_SIZE);
        app_config.app_vm_config.system.config = app_config
            .app_vm_config
            .system
            .config
            .with_max_segment_len(segment_len);

        let sdk = Sdk::new();
        let app_pk = sdk
            .app_keygen(app_config)
            .map_err(|e| Error::Keygen(e.to_string()))?;
        let app_committed_exe = sdk
            .commit_app_exe(app_pk.app_fri_params(), app_exe)
            .map_err(|e| Error::Commit(e.to_string()))?;

        Ok((app_committed_exe, Arc::new(app_pk)))
    }

    /// Directly dump the universal verifier, and also persist the staffs if path is provided
    pub fn dump_universal_verifier<P: AsRef<Path>>(
        &self,
        dir: Option<P>,
    ) -> Result<scroll_zkvm_verifier::verifier::UniversalVerifier, Error> {
        use scroll_zkvm_verifier::verifier::UniversalVerifier as Verifier;

        let root_verifier_pk = &AGG_STARK_PROVING_KEY.root_verifier_pk;
        let vm_config = root_verifier_pk.vm_pk.vm_config.clone();
        let root_committed_exe: &VmCommittedExe<_> = &root_verifier_pk.root_committed_exe;

        if let Some(dir) = dir {
            let path_vm_config = dir.as_ref().join(FD_ROOT_VERIFIER_VM_CONFIG);
            let path_root_committed_exe = dir.as_ref().join(FD_ROOT_VERIFIER_COMMITTED_EXE);

            crate::utils::write_bin(&path_vm_config, &vm_config)?;
            crate::utils::write_bin(&path_root_committed_exe, &root_committed_exe)?;
            // note the verifier.bin has been written in setup evm prover
        }

        Ok(if let Some(evm_prover) = &self.evm_prover {
            Verifier {
                //vm_executor: SingleSegmentVmExecutor::new(vm_config),
                root_committed_exe: root_committed_exe.clone(),
                evm_verifier: evm_prover.verifier_contract.clone(),
            }
        } else {
            Verifier {
                //vm_executor: SingleSegmentVmExecutor::new(vm_config),
                root_committed_exe: root_committed_exe.clone(),
                evm_verifier: Vec::new(),
            }
        })
    }

    /// Dump assets required to setup verifier-only mode.
    pub fn dump_verifier<P: AsRef<Path>>(&self, dir: P) -> Result<PathBuf, Error> {
        if !Type::EVM {
            return Err(Error::Custom(
                "dump_verifier only at bundle-prover".to_string(),
            ));
        };
        let root_verifier_pk = &AGG_STARK_PROVING_KEY.root_verifier_pk;
        let root_committed_exe: &VmCommittedExe<_> = &root_verifier_pk.root_committed_exe;

        let path_root_committed_exe = dir.as_ref().join(FD_ROOT_VERIFIER_COMMITTED_EXE);

        crate::utils::write_bin(&path_root_committed_exe, &root_committed_exe)?;

        Ok(path_root_committed_exe)
    }

    /// Pick up loaded app commit as "vk" in proof, to distinguish from which circuit the proof comes
    pub fn get_app_vk(&self) -> Vec<u8> {
        let commits = AppExecutionCommit::compute(
            &self.app_pk.app_vm_pk.vm_config,
            &self.app_committed_exe,
            &self.app_pk.leaf_committed_exe,
        );

        let exe = commits.app_exe_commit.to_u32_digest();
        let leaf = commits.app_vm_commit.to_u32_digest();

        scroll_zkvm_types::types_agg::ProgramCommitment { exe, leaf }.serialize()
    }

    /// Pick up the actual vk (serialized) for evm proof, would be empty if prover
    /// do not contain evm prover
    pub fn get_evm_vk(&self) -> Vec<u8> {
        self.evm_prover
            .as_ref()
            .map(|evm_prover| {
                scroll_zkvm_verifier::evm::serialize_vk(
                    evm_prover.agg_pk.halo2_pk.wrapper.pinning.pk.get_vk(),
                )
            })
            .unwrap_or_default()
    }

    /// Simple wrapper of gen_proof_stark/snark, Early-return if a proof is found in disc,
    /// otherwise generate and return the proof after writing to disc.
    #[instrument("Prover::gen_proof_universal", skip_all, fields(task_id, prover_name = Type::NAME))]
    pub fn gen_proof_universal(
        &self,
        task: &impl ProvingTask,
        with_snark: bool,
    ) -> Result<ProofEnum, Error> {
        // Generate a new proof.
        Ok(if !with_snark {
            self.gen_proof_stark(task)?.into()
        } else {
            EvmProof::from(self.gen_proof_snark(task)?).into()
        })
    }

    /// Early-return if a proof is found in disc, otherwise generate and return the proof after
    /// writing to disc.
    /// TODO: would be deprecated later
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

            if let Ok(proof) =
                <WrappedProof<Type::ProofMetadata> as PersistableProof>::from_json(&path_proof)
            {
                verify_stark_proof(
                    proof.proof.as_root_proof().unwrap(),
                    Type::EXE_COMMIT,
                    Type::VM_COMMIT,
                )
                .unwrap();
                debug!(name: "early_return_proof", ?task_id);
                return Ok(proof);
            }
        }

        // Generate a new proof.
        assert!(!Type::EVM, "Prover::gen_proof not for EVM-prover");
        let metadata = Self::metadata_with_prechecks(task)?;

        // sanity check for using expected program commit
        let _ = Self::get_verify_program_commitment(&self.app_committed_exe, &self.app_pk, false);

        let proof = self.gen_proof_universal(task, false)?;
        let wrapped_proof = metadata.new_proof(proof, Some(self.get_app_vk().as_slice()));

        wrapped_proof.sanity_check(task.fork_name());

        // Write proof to disc if caching was enabled.
        if let Some(dir) = &self.cache_dir {
            let path_proof = dir.join(Self::fd_proof(task));
            debug!(name: "try_write_root_proof", ?task_id, ?path_proof);

            wrapped_proof.dump(&path_proof)?;
        }

        Ok(wrapped_proof)
    }

    /// Early-return if a proof is found in disc, otherwise generate and return the proof after
    /// writing to disc.
    /// TODO: would be deprecated later
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

            if let Ok(proof) =
                <WrappedProof<Type::ProofMetadata> as PersistableProof>::from_json(&path_proof)
            {
                debug!(name: "early_return_proof", ?task_id);
                return Ok(proof);
            }
        }

        // Generate a new proof.
        assert!(Type::EVM, "Prover::gen_proof_evm only for EVM-prover");
        let metadata = Self::metadata_with_prechecks(task)?;

        // sanity check for using expected program commit
        let _ = Self::get_verify_program_commitment(&self.app_committed_exe, &self.app_pk, false);

        let proof = self.gen_proof_snark(task)?;

        // sanity check for evm proof match the program commit
        assert_eq!(
            proof.app_commit.app_exe_commit.to_u32_digest(),
            Type::EXE_COMMIT,
            "commitment is not match in generate evm proof",
        );
        assert_eq!(
            proof.app_commit.app_vm_commit.to_u32_digest(),
            Type::VM_COMMIT,
            "commitment is not match in generate evm proof",
        );

        let wrapped_proof =
            metadata.new_proof(EvmProof::from(proof), Some(self.get_evm_vk().as_slice()));

        wrapped_proof.sanity_check(task.fork_name());

        // Write proof to disc if caching was enabled.
        if let Some(dir) = &self.cache_dir {
            let path_proof = dir.join(Self::fd_proof(task));
            debug!(name: "try_write_proof", ?task_id, ?path_proof);

            wrapped_proof.dump(&path_proof)?;
        }

        Ok(wrapped_proof)
    }

    /// Validate some pre-checks on the proving task and construct proof metadata.
    #[instrument("Prover::metadata_with_prechecks", skip_all, fields(?task_id = task.identifier()))]
    pub fn metadata_with_prechecks(task: &Type::ProvingTask) -> Result<Type::ProofMetadata, Error> {
        Type::metadata_with_prechecks(task)
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
        let gas_cost =
            scroll_zkvm_verifier::evm::verify_evm_proof(contract, &evm_proof.clone().into())
                .map_err(|e| Error::VerifyProof(format!("EVM-proof verification failed: {e}")))?;

        tracing::info!(name: "verify_evm_proof", ?gas_cost);

        Ok(())
    }

    /// Execute the guest program to get the cycle count.
    pub fn execute_and_check(&self, stdin: &StdIn) -> Result<u64, Error> {
        let config = self.app_pk.app_vm_pk.vm_config.clone();
        let exe = self.app_committed_exe.exe.clone();
        let exec_result = crate::utils::vm::execute_guest(config, exe, stdin)?;
        Ok(exec_result.total_cycle as u64)
    }

    /// Setup the EVM prover-verifier.
    fn setup_evm_prover(config: &ProverConfig) -> Result<EvmProverVerifier, Error> {
        // The HALO2 directory is set in the following order:
        // 1. If the optional dir_halo2_params is set: use it.
        // 2. If the optional dir_halo2_params is not set: try to read from env variable.
        // 3. If the env var is not set: use the default directory.
        let dir_halo2_params = config
            .dir_halo2_params
            .clone()
            .ok_or(std::env::var(ENV_HALO2_PARAMS_DIR))
            .unwrap_or(Path::new(DEFAULT_PARAMS_DIR).to_path_buf());

        let halo2_params_reader = CacheHalo2ParamsReader::new(&dir_halo2_params);
        let agg_pk = Sdk::new()
            .agg_keygen(
                AggConfig::default(),
                &halo2_params_reader,
                &DefaultStaticVerifierPvHandler,
            )
            .map_err(|e| Error::Setup {
                path: dir_halo2_params,
                src: e.to_string(),
            })?;

        let path_verifier_bin = config
            .path_app_exe
            .parent()
            .map(|dir| dir.join("verifier.bin"));
        let verifier_contract = Sdk::new()
            .generate_halo2_verifier_solidity(&halo2_params_reader, &agg_pk)
            .unwrap();
        if let Some(path) = path_verifier_bin {
            crate::utils::write(path, &verifier_contract.artifact.bytecode)?;
        }

        Ok(EvmProverVerifier {
            reader: halo2_params_reader,
            //halo2_prover,
            agg_pk,
            verifier_contract: verifier_contract.artifact.bytecode,
        })
    }

    /// File descriptor for the proof saved to disc.
    #[instrument("Prover::fd_proof", skip_all, fields(task_id = task.identifier(), path_proof))]
    fn fd_proof(task: &impl ProvingTask) -> String {
        let path_proof = format!("{}-{}.json", Type::NAME, task.identifier());
        path_proof
    }

    /// Generate a [root proof][root_proof].
    ///
    /// [root_proof][openvm_sdk::verifier::root::types::RootVmVerifierInput]
    fn gen_proof_stark(&self, task: &impl ProvingTask) -> Result<StarkProof, Error> {
        let stdin = task
            .build_guest_input()
            .map_err(|e| Error::GenProof(e.to_string()))?;

        // Here we always do an execution of the guest program to get the cycle count.
        // and do precheck before proving like ensure PI != 0
        self.execute_and_check(&stdin)?;

        let task_id = task.identifier();

        tracing::debug!(name: "generate_root_verifier_input", ?task_id);
        let sdk = Sdk::new();
        let proof = sdk
            .generate_e2e_stark_proof(
                SdkVmCpuBuilder,
                self.app_pk.clone(),
                self.app_committed_exe.clone(),
                AGG_STARK_PROVING_KEY.clone(),
                stdin,
            )
            .unwrap();
        println!("verifing root proof");
        verify_stark_proof(&proof, Type::EXE_COMMIT, Type::VM_COMMIT).unwrap();
        println!("verifing root proof done");
        Ok(proof)
    }

    /// Generate an [evm proof][evm_proof].
    ///
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    fn gen_proof_snark(&self, task: &impl ProvingTask) -> Result<OpenVmEvmProf, Error> {
        let stdin = task
            .build_guest_input()
            .map_err(|e| Error::GenProof(e.to_string()))?;
        let sdk = Sdk::new();
        let evm_proof = sdk
            .generate_evm_proof(
                &self.evm_prover.as_ref().unwrap().reader,
                SdkVmCpuBuilder,
                self.app_pk.clone(),
                self.app_committed_exe.clone(),
                self.evm_prover.as_ref().unwrap().agg_pk.clone(),
                stdin,
            )
            .unwrap();

        Ok(evm_proof)
    }

    fn get_verify_program_commitment(
        app_committed_exe: &NonRootCommittedExe,
        app_pk: &AppProvingKey<SdkVmConfig>,
        debug_out: bool,
    ) -> (AppExecutionCommit, [[u32; 8]; 2]) {
        let commits = AppExecutionCommit::compute(
            &app_pk.app_vm_pk.vm_config,
            app_committed_exe,
            &app_pk.leaf_committed_exe,
        );

        let exe_commit = commits.app_exe_commit.to_u32_digest();
        let vm_commit = commits.app_vm_commit.to_u32_digest();

        // print the 2 exe commitments
        if debug_out {
            debug!(name: "exe-commitment", prover_name = Type::NAME, raw = ?exe_commit, as_bn254 = ?commits.app_exe_commit.to_bn254());
            debug!(name: "vm-commitment", prover_name = Type::NAME, raw = ?vm_commit, as_bn254 = ?commits.app_vm_commit.to_bn254());
        }

        assert_eq!(
            vm_commit,
            Type::VM_COMMIT,
            "read unmatched app commitment from app"
        );
        assert_eq!(
            exe_commit,
            Type::EXE_COMMIT,
            "read unmatched exe commitment from app"
        );
        (commits, [exe_commit, vm_commit])
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

    /// The app program's vm commitment.
    const VM_COMMIT: [u32; 8];

    /// The task provided as argument during proof generation process.
    type ProvingTask: ProvingTask;

    /// The metadata accompanying the wrapper proof generated by this prover.
    type ProofMetadata: ProofMetadata;

    /// Provided the proving task, computes the proof metadata.
    fn metadata_with_prechecks(task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error>;
}
