use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use openvm_circuit::arch::instructions::exe::VmExe;
use openvm_native_circuit::NativeCpuBuilder;
use openvm_native_recursion::halo2::utils::CacheHalo2ParamsReader;
use openvm_sdk::{
    DefaultStaticVerifierPvHandler, F, GenericSdk, Sdk, StdIn,
    commit::AppExecutionCommit,
    config::{AppConfig, SdkVmConfig, SdkVmCpuBuilder},
    fs::read_object_from_file,
    keygen::{AggProvingKey, AppProvingKey},
    prover::StarkProver,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::{
    BabyBearPermutationEngine, BabyBearPoseidon2Engine,
};
use scroll_zkvm_types::{proof::OpenVmEvmProof, types_agg::ProgramCommitment};
use scroll_zkvm_verifier::verifier::{UniversalVerifier, AGG_STARK_PROVING_KEY};
use tracing::instrument;

// Re-export from openvm_sdk.
pub use openvm_sdk::{self};

use crate::{Error, setup::read_app_config, task::ProvingTask};

use scroll_zkvm_types::proof::{EvmProof, ProofEnum, StarkProof};
/// The default directory to locate openvm's halo2 SRS parameters.
const DEFAULT_PARAMS_DIR: &str = concat!(env!("HOME"), "/.openvm/params/");

/// The environment variable that needs to be set in order to configure the directory from where
/// Prover can read HALO2 trusted setup parameters.
const ENV_HALO2_PARAMS_DIR: &str = "ENV_HALO2_PARAMS_DIR";

/// Generic prover.
pub struct Prover {
    /// Prover name
    pub prover_name: String,
    /// Commitment to app exe.
    pub app_exe: Arc<VmExe<F>>,
    /// App specific proving key.
    // pub app_pk: Arc<AppProvingKey<SdkVmConfig>>,
    /// The commitments for the app execution.
    //pub commits: AppExecutionCommit,
    /// Optional data for the outermost layer, i.e. EVM-compatible.
    //pub evm_prover: Option<EvmProver>,
    /// Configuration for the prover.
    pub config: ProverConfig,
    pub sdk: Sdk,
    pub prover: StarkProver<BabyBearPoseidon2Engine, SdkVmCpuBuilder, NativeCpuBuilder>,
}

/// Configure the [`Prover`].
#[derive(Debug, Clone, Default)]
pub struct ProverConfig {
    /// Path to find applications's app.vmexe.
    pub path_app_exe: PathBuf,
    /// Path to find application's OpenVM config.
    pub path_app_config: PathBuf,
    /// The maximum length for a single OpenVM segment.
    pub segment_len: Option<usize>,
}

const DEFAULT_SEGMENT_SIZE: usize = (1 << 22) - 100;

impl Prover {
    /// Setup the [`Prover`] given paths to the application's exe and proving key.
    #[instrument("Prover::setup")]
    pub fn setup(config: ProverConfig, with_evm: bool, name: Option<&str>) -> Result<Self, Error> {
        tracing::info!("prover setup");
        let app_exe: VmExe<F> = read_object_from_file(&config.path_app_exe).unwrap();
        let app_exe = Arc::new(app_exe);
        let mut app_config = read_app_config(&config.path_app_config)?;
        let segment_len = config.segment_len.unwrap_or(DEFAULT_SEGMENT_SIZE);
        app_config.app_vm_config.system.config = app_config
            .app_vm_config
            .system
            .config
            .with_max_segment_len(segment_len);

        tracing::info!("setup1");
        let sdk = Sdk::new(app_config).unwrap();
        tracing::info!("setup15");
        let sdk = sdk.with_agg_pk(AGG_STARK_PROVING_KEY.clone());

        let prover = sdk.prover(app_exe.clone()).unwrap();
        tracing::info!("prover setup done");
        Ok(Self {
            sdk,
            prover,
            app_exe,
            config,
            prover_name: name.unwrap_or("universal").to_string(),
        })
    }

    /// Pick up loaded app commit, to distinguish from which circuit the proof comes
    pub fn get_app_commitment(&self) -> ProgramCommitment {
        let commits = self.prover.app_commit();
        let exe = commits.app_exe_commit.to_u32_digest();
        let vm = commits.app_vm_commit.to_u32_digest();
        ProgramCommitment { exe, vm }
    }

    /// Pick up loaded app commit as "vk" in proof, to distinguish from which circuit the proof comes
    pub fn get_app_vk(&self) -> Vec<u8> {
        self.get_app_commitment().serialize()
    }

    /// Pick up the actual vk (serialized) for evm proof, would be empty if prover
    /// do not contain evm prover
    pub fn get_evm_vk(&self) -> Vec<u8> {
        scroll_zkvm_verifier::evm::serialize_vk(self.sdk.halo2_pk().wrapper.pinning.pk.get_vk())
    }

    /// Simple wrapper of gen_proof_stark/snark, Early-return if a proof is found in disc,
    /// otherwise generate and return the proof after writing to disc.
    #[instrument("Prover::gen_proof_universal", skip_all, fields(task_id))]
    pub fn gen_proof_universal(
        &mut self,
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
        let config = self.sdk.app_config(); // app_pk.app_vm_pk.vm_config.clone();
        let exe = self.app_exe.clone();
        let exec_result =
            crate::utils::vm::execute_guest(config.app_vm_config.clone(), exe, stdin)?;
        tracing::info!(
            "total cycle of {}: {}",
            self.prover_name,
            exec_result.total_cycle
        );
        Ok(exec_result)
    }

    /// Execute the guest program to get the cycle count.
    pub fn execute_and_check(&self, stdin: &StdIn) -> Result<u64, Error> {
        self.execute_and_check_with_full_result(stdin)
            .map(|res| res.total_cycle)
    }

    /*
    /// Setup the EVM prover-verifier.
    fn setup_evm_prover() -> Result<EvmProver, Error> {
        tracing::info!("Setting up EVM prover...");

        // The HALO2 directory is set in the following order:
        // 1. If the `ENV_HALO2_PARAMS_DIR` env variable is set: read it.
        // 2. If the env var is not set: use the default directory.
        let dir_halo2_params: PathBuf = std::env::var(ENV_HALO2_PARAMS_DIR)
            .map(PathBuf::from)
            .unwrap_or(Path::new(DEFAULT_PARAMS_DIR).to_path_buf());
        tracing::info!(
            "Using Halo2 params directory: {}",
            dir_halo2_params.display()
        );

        let halo2_params_reader = CacheHalo2ParamsReader::new(&dir_halo2_params);

        let pk_file = std::env::var("HOME").unwrap_or_default() + "/.openvm/agg_halo2.pk";
        let agg_pk = if Path::new(&pk_file).exists() {
            tracing::info!("Found existing aggregation proving key at {pk_file}, loading...");
            // 1.5min
            let agg_pk = AggProvingKey {
                agg_stark_pk: AGG_STARK_PROVING_KEY.clone(),
                halo2_pk: openvm_sdk::fs::read_agg_halo2_pk_from_file(&pk_file)
                    .expect("loading pk err, delete it?"),
            };
            tracing::info!("Successfully loaded aggregation proving key.");
            agg_pk
        } else {
            tracing::info!(
                "No existing aggregation proving key found at {pk_file}. Generating a new one... (this may take a while)"
            );
            // 5min
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
            tracing::info!("Successfully generated new aggregation proving key.");
            agg_pk
        };

        tracing::info!("EVM prover setup complete.");
        Ok(EvmProver {
            reader: halo2_params_reader,
            agg_pk,
        })

    }
    */

    /// Generate a [root proof][root_proof].
    ///
    /// [root_proof][openvm_sdk::verifier::root::types::RootVmVerifierInput]
    pub fn gen_proof_stark(&mut self, stdin: StdIn) -> Result<StarkProof, Error> {
        // Here we always do an execution of the guest program to get the cycle count.
        // and do precheck before proving like ensure PI != 0
        self.execute_and_check(&stdin)?;

        ///let sdk = Sdk::new();
        let proof = self
            .prover
            .prove(stdin)
            .map_err(|e| Error::GenProof(e.to_string()))?;
        //let comm = self.get_app_commitment();
        let proof = StarkProof {
            proofs: vec![proof.inner],
            public_values: proof.user_public_values,
            //exe_commitment: comm.exe,
            //vm_commitment: comm.vm,
        };
        tracing::info!("verifing stark proof");
        //UniversalVerifier::verify_stark_proof(&proof, &comm.serialize())
        //    .map_err(|e| Error::VerifyProof(e.to_string()))?;
        tracing::info!("verifing stark proof done");
        Ok(proof)
    }

    /// Generate an [evm proof][evm_proof].
    ///
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    pub fn gen_proof_snark(&self, stdin: StdIn) -> Result<OpenVmEvmProof, Error> {
        self.execute_and_check(&stdin)?;

        //let sdk = Sdk::new();
        //let evm_prover = self.evm_prover.as_ref().expect("evm prover not inited");
        let evm_proof = self
            .sdk
            .prove_evm(self.app_exe.clone(), stdin)
            .map_err(|e| Error::GenProof(format!("{}", e)))?;

        Ok(evm_proof)
    }
}
