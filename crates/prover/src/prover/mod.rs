use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use once_cell::sync::Lazy;
use openvm_circuit::{arch::SingleSegmentVmExecutor, system::program::trace::VmCommittedExe};
use openvm_native_recursion::halo2::{
    RawEvmProof,
    utils::{CacheHalo2ParamsReader, Halo2ParamsReader},
    wrapper::Halo2WrapperProvingKey,
};
use openvm_sdk::{
    DefaultStaticVerifierPvHandler, NonRootCommittedExe, Sdk, StdIn,
    commit::AppExecutionCommit,
    config::{AggConfig, AggStarkConfig, SdkVmConfig},
    keygen::{AggStarkProvingKey, AppProvingKey},
    prover::{AggStarkProver, AppProver, EvmHalo2Prover},
};
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Engine;
use tracing::instrument;

// Re-export from openvm_sdk.
pub use openvm_sdk::{self, SC};

use crate::{
    Error,
    setup::{read_app_config, read_app_exe},
    task::ProvingTask,
};

use scroll_zkvm_types::proof::{EvmProof, ProofEnum, RootProof};

/// Proving key for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
static AGG_STARK_PROVING_KEY: Lazy<AggStarkProvingKey> =
    Lazy::new(|| AggStarkProvingKey::keygen(AggStarkConfig::default()));

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
pub struct EvmProverVerifier {
    /// This is required only for [BundleProver].
    pub halo2_prover: EvmHalo2Prover<SdkVmConfig, BabyBearPoseidon2Engine>,
    /// The halo2 proving key.
    pub halo2_pk: Halo2WrapperProvingKey,
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
    pub segment_len: usize,
}

impl Prover {
    /// Setup the [`Prover`] given paths to the application's exe and proving key.
    #[instrument("Prover::setup")]
    pub fn setup(config: ProverConfig, with_evm: bool, name: Option<&str>) -> Result<Self, Error> {
        let (app_committed_exe, app_pk) = Self::init(&config)?;

        let evm_prover = with_evm
            .then(|| Self::setup_evm_prover(&config, &app_committed_exe, &app_pk))
            .transpose()?;

        Ok(Self {
            app_committed_exe,
            app_pk,
            evm_prover,
            cache_dir: config.dir_cache,
            prover_name: name.unwrap_or("universal").to_string(),
        })
    }

    /// Read app exe, proving key and return committed data.
    #[instrument("Prover::init")]
    pub fn init(config: &ProverConfig) -> Result<InitRes, Error> {
        let app_exe = read_app_exe(&config.path_app_exe)?;
        let mut app_config = read_app_config(&config.path_app_config)?;
        let segment_len = config.segment_len;
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
                vm_executor: SingleSegmentVmExecutor::new(vm_config),
                root_committed_exe: root_committed_exe.clone(),
                evm_verifier: evm_prover.verifier_contract.clone(),
            }
        } else {
            Verifier {
                vm_executor: SingleSegmentVmExecutor::new(vm_config),
                root_committed_exe: root_committed_exe.clone(),
                evm_verifier: Vec::new(),
            }
        })
    }

    /// Dump assets required to setup verifier-only mode.
    pub fn dump_verifier<P: AsRef<Path>>(&self, dir: P) -> Result<(PathBuf, PathBuf), Error> {
        if self.evm_prover.is_none() {
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
                scroll_zkvm_verifier::evm::serialize_vk(evm_prover.halo2_pk.pinning.pk.get_vk())
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

        let stdin = task.build_guest_input()
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

    /// Setup the EVM prover-verifier.
    fn setup_evm_prover(
        config: &ProverConfig,
        app_committed_exe: &Arc<NonRootCommittedExe>,
        app_pk: &Arc<AppProvingKey<SdkVmConfig>>,
    ) -> Result<EvmProverVerifier, Error> {
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

        let halo2_params = halo2_params_reader
            .read_params(agg_pk.halo2_pk.wrapper.pinning.metadata.config_params.k);
        let path_verifier_sol = config
            .path_app_exe
            .parent()
            .map(|dir| dir.join("verifier.sol"));
        let path_verifier_bin = config
            .path_app_exe
            .parent()
            .map(|dir| dir.join("verifier.bin"));
        let verifier_contract = scroll_zkvm_verifier::evm::gen_evm_verifier::<
            scroll_zkvm_verifier::evm::halo2_aggregation::AggregationCircuit,
        >(
            &halo2_params,
            agg_pk.halo2_pk.wrapper.pinning.pk.get_vk(),
            agg_pk.halo2_pk.wrapper.pinning.metadata.num_pvs.clone(),
            path_verifier_sol.as_deref(),
        );
        if let Some(path) = path_verifier_bin {
            crate::utils::write(path, &verifier_contract)?;
        }

        let halo2_pk = agg_pk.halo2_pk.wrapper.clone();
        let halo2_prover = EvmHalo2Prover::new(
            &halo2_params_reader,
            Arc::clone(app_pk),
            Arc::clone(app_committed_exe),
            agg_pk,
            Default::default(),
        );

        Ok(EvmProverVerifier {
            halo2_prover,
            halo2_pk,
            verifier_contract,
        })
    }

    /// Generate a [root proof][root_proof].
    ///
    /// [root_proof][openvm_sdk::verifier::root::types::RootVmVerifierInput]
    pub fn gen_proof_stark(&self, stdin: StdIn) -> Result<RootProof, Error> {
        let mock_prove = std::env::var("MOCK_PROVE").as_deref() == Ok("true");
        // Here we always do an execution of the guest program to get the cycle count.
        // and do precheck before proving like ensure PI != 0
        self.execute_and_check(&stdin, mock_prove)?;

        let app_prover = AppProver::<_, BabyBearPoseidon2Engine>::new(
            self.app_pk.app_vm_pk.clone(),
            self.app_committed_exe.clone(),
        );
        // TODO: should we cache the app_proof?
        let app_proof = app_prover.generate_app_proof(stdin);

        let agg_prover = AggStarkProver::<BabyBearPoseidon2Engine>::new(
            AGG_STARK_PROVING_KEY.clone(),
            self.app_pk.leaf_committed_exe.clone(),
            Default::default(),
        );
        let proof = agg_prover.generate_root_verifier_input(app_proof);
        Ok(proof)
    }

    /// Generate an [evm proof][evm_proof].
    ///
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    pub fn gen_proof_snark(&self, stdin: StdIn) -> Result<RawEvmProof, Error> {

        let evm_proof: RawEvmProof = self
            .evm_prover
            .as_ref()
            .expect("Prover::gen_proof_snark expects EVM-prover setup")
            .halo2_prover
            .generate_proof_for_evm(stdin)
            .try_into()
            .map_err(|e| Error::GenProof(format!("{}", e)))?;

        Ok(evm_proof)
    }
}
