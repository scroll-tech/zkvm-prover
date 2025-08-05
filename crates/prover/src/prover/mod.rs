use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use once_cell::sync::Lazy;
use openvm_circuit::system::program::trace::VmCommittedExe;
use openvm_native_recursion::halo2::{
    RawEvmProof,
    utils::{CacheHalo2ParamsReader, Halo2ParamsReader},
    wrapper::Halo2WrapperProvingKey,
};
use openvm_sdk::{
    DefaultStaticVerifierPvHandler, NonRootCommittedExe, Sdk, StdIn,
    commit::AppExecutionCommit,
    config::{AggConfig, AggStarkConfig, SdkVmConfig},
    keygen::{AggProvingKey, AggStarkProvingKey, AppProvingKey},
    types::EvmProof as OpenVmEvmProf,
};
use openvm_sdk::{config::SdkVmCpuBuilder, fs::read_exe_from_file};
use scroll_zkvm_types::{proof::OpenVmEvmProof, types_agg::ProgramCommitment};
use scroll_zkvm_verifier::verifier::UniversalVerifier;
use tracing::instrument;

// Re-export from openvm_sdk.
pub use openvm_sdk::{self, SC};

use crate::{Error, setup::read_app_config, task::ProvingTask};

use scroll_zkvm_types::proof::{EvmProof, ProofEnum, StarkProof};

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

/// Types used in the outermost proof construction and verification, i.e. the EVM-compatible layer.
/// This is required only for [BundleProver].
pub struct EvmProverVerifier {
    pub reader: CacheHalo2ParamsReader,
    pub agg_pk: AggProvingKey,
    /// The contract bytecode for the EVM verifier contract.
    pub verifier_contract: Vec<u8>,
}

/// Generic prover.
pub struct Prover {
    /// Prover name
    pub prover_name: String,
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

const COMMON_SEGMENT_SIZE: usize = (1 << 22) - 100;

impl Prover {
    /// Setup the [`Prover`] given paths to the application's exe and proving key.
    #[instrument("Prover::setup")]
    pub fn setup(config: ProverConfig, with_evm: bool, name: Option<&str>) -> Result<Self, Error> {
        let (app_committed_exe, app_pk) = Self::init(&config)?;

        let evm_prover = with_evm
            .then(|| Self::setup_evm_prover(&config))
            .transpose()?;

        Ok(Self {
            app_committed_exe,
            app_pk,
            evm_prover,
            cache_dir: config.dir_cache.clone(),
            config: config,
            prover_name: name.unwrap_or("universal").to_string(),
        })
    }

    /// Read app exe, proving key and return committed data.
    #[instrument("Prover::init")]
    pub fn init(config: &ProverConfig) -> Result<InitRes, Error> {
        let app_exe = read_exe_from_file(&config.path_app_exe).unwrap();
        let mut app_config = read_app_config(&config.path_app_config)?;
        let segment_len = config.segment_len.unwrap_or(COMMON_SEGMENT_SIZE);
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
                evm_verifier: evm_prover.verifier_contract.clone(),
            }
        } else {
            Verifier {
                evm_verifier: Vec::new(),
            }
        })
    }

    /// Dump assets required to setup verifier-only mode.
    pub fn dump_verifier<P: AsRef<Path>>(&self, dir: P) -> Result<PathBuf, Error> {
        if self.evm_prover.is_none() {
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
    pub fn get_app_commitment(&self) -> ProgramCommitment {
        let commits = AppExecutionCommit::compute(
            &self.app_pk.app_vm_pk.vm_config,
            &self.app_committed_exe,
            &self.app_pk.leaf_committed_exe,
        );

        let exe = commits.app_exe_commit.to_u32_digest();
        let leaf = commits.app_vm_commit.to_u32_digest();

        ProgramCommitment { exe, leaf }
    }
    /// Pick up loaded app commit as "vk" in proof, to distinguish from which circuit the proof comes
    pub fn get_app_vk(&self) -> Vec<u8> {
        self.get_app_commitment().serialize()
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
    #[instrument("Prover::gen_proof_universal", skip_all, fields(task_id))]
    pub fn gen_proof_universal(
        &self,
        task: &impl ProvingTask,
        with_snark: bool,
    ) -> Result<ProofEnum, Error> {
        let task_id = task.identifier();
        tracing::debug!(name: "generate_root_verifier_input", task_id);

        let stdin = task
            .build_guest_input()
            .map_err(|e| Error::GenProof(e.to_string()))?;

        // Generate a new proof.
        let proof = if !with_snark {
            self.gen_proof_stark(stdin)?.into()
        } else {
            EvmProof::from(self.gen_proof_snark(stdin)?).into()
        };

        tracing::info!(
            "app proof generated for {}, task id {task_id}, isevm {with_snark}",
            self.prover_name
        );
        Ok(proof)
    }

    /// Execute the guest program to get the cycle count.
    pub fn execute_and_check_with_full_result(
        &self,
        stdin: &StdIn,
    ) -> Result<crate::utils::vm::ExecutionResult, Error> {
        let config = self.app_pk.app_vm_pk.vm_config.clone();
        let exe = self.app_committed_exe.exe.clone();
        let exec_result = crate::utils::vm::execute_guest(config, exe, stdin)?;
        Ok(exec_result)
    }

    /// Execute the guest program to get the cycle count.
    pub fn execute_and_check(&self, stdin: &StdIn) -> Result<u64, Error> {
        self.execute_and_check_with_full_result(stdin)
            .map(|res| res.total_cycle)
    }

    /// Setup the EVM prover-verifier.
    fn setup_evm_prover(config: &ProverConfig) -> Result<EvmProverVerifier, Error> {
        tracing::info!("setting up evm prover");
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
        tracing::info!("setting up evm prover 1");
        let pk_file = std::env::var("HOME").unwrap() + "/.openvm/agg_halo2.pk";
        println!("pk_file {pk_file}");
        let is_pk_file_existed = std::path::Path::new(&pk_file).exists();
        println!("is_pk_file_existed {is_pk_file_existed}");
        let agg_pk = if is_pk_file_existed {
            // 1.5min
            AggProvingKey {
                agg_stark_pk: AGG_STARK_PROVING_KEY.clone(),
                halo2_pk: openvm_sdk::fs::read_agg_halo2_pk_from_file(pk_file).unwrap(),
            }
        } else {
            // 5min
            Sdk::new()
                .agg_keygen(
                    AggConfig::default(),
                    &halo2_params_reader,
                    &DefaultStaticVerifierPvHandler,
                )
                .map_err(|e| Error::Setup {
                    path: dir_halo2_params,
                    src: e.to_string(),
                })?
        };

        tracing::info!("setting up evm prover 2");
        let path_verifier_bin = config
            .path_app_exe
            .parent()
            .map(|dir| dir.join("verifier.bin"));
        let verifier_contract = Sdk::new()
            .generate_halo2_verifier_solidity(&halo2_params_reader, &agg_pk)
            .unwrap();
        tracing::info!("setting up evm prover 3");
        if let Some(path) = path_verifier_bin {
            crate::utils::write(path, &verifier_contract.artifact.bytecode)?;
        }

        tracing::info!("sett up evm prover done");
        Ok(EvmProverVerifier {
            reader: halo2_params_reader,
            //halo2_prover,
            agg_pk,
            verifier_contract: verifier_contract.artifact.bytecode,
        })
    }

    /// Generate a [root proof][root_proof].
    ///
    /// [root_proof][openvm_sdk::verifier::root::types::RootVmVerifierInput]
    pub fn gen_proof_stark(&self, stdin: StdIn) -> Result<StarkProof, Error> {
        // Here we always do an execution of the guest program to get the cycle count.
        // and do precheck before proving like ensure PI != 0

        tracing::info!("===> cycle total");
        let cycle = self.execute_and_check(&stdin)?;
        tracing::info!("cycle total {}", cycle);
        //unimplemented!("stop");
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
        // TODO: cache it
        let comm = self.get_app_commitment();
        let proof = StarkProof {
            proof: proof.proof,
            user_public_values: proof.user_public_values,
            exe_commitment: comm.exe,
            vm_commitment: comm.leaf,
        };
        println!("verifing root proof");
        UniversalVerifier::verify_stark_proof(&proof, &comm.serialize()).unwrap();
        println!("verifing root proof done");
        Ok(proof)
    }

    /// Generate an [evm proof][evm_proof].
    ///
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    pub fn gen_proof_snark(&self, stdin: StdIn) -> Result<OpenVmEvmProof, Error> {
        let cycle = self.execute_and_check(&stdin)?;
        tracing::info!("cycle total {}", cycle);
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
}
