use std::{
    path::PathBuf,
    sync::{Arc, OnceLock},
};

#[cfg(not(feature = "cuda"))]
use openvm_native_circuit::NativeCpuBuilder as NativeBuilder;
#[cfg(feature = "cuda")]
use openvm_native_circuit::NativeGpuBuilder as NativeBuilder;

use openvm_circuit::arch::instructions::exe::VmExe;
use openvm_sdk::{DefaultStarkEngine, config::SdkVmBuilder};
use openvm_sdk::{
    F, Sdk, StdIn,
    config::{AppConfig, SdkVmConfig},
    prover::StarkProver,
};
use scroll_zkvm_types::{proof::OpenVmEvmProof, types_agg::ProgramCommitment, utils::serialize_vk};
use scroll_zkvm_verifier::verifier::{AGG_STARK_PROVING_KEY, UniversalVerifier};
use tracing::instrument;

type SDKAppConfig = AppConfig<SdkVmConfig>;

// Re-export from openvm_sdk.
pub use openvm_sdk::{self};

use crate::setup::read_app_exe;
use crate::{Error, setup::read_app_config, task::ProvingTask};

use scroll_zkvm_types::proof::{EvmProof, ProofEnum, StarkProof, StarkProofStat};

/// Generic prover.
pub struct Prover {
    /// Prover name
    pub prover_name: String,
    /// The program exe.
    pub app_exe: Arc<VmExe<F>>,
    /// Prover configuration.
    pub config: ProverConfig,
    /// SDKConfig
    app_config: SDKAppConfig,
    /// Lazily initialized SDK
    sdk: OnceLock<Sdk>,
    /// Lazily initialized stark prover
    prover: OnceLock<StarkProver<DefaultStarkEngine, SdkVmBuilder, NativeBuilder>>,
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

const DEFAULT_SEGMENT_SIZE: usize = (1 << 22) - 1000;

impl Prover {
    /// Setup the [`Prover`] given paths to the application's exe and proving key.
    #[instrument("Prover::setup")]
    pub fn setup(config: ProverConfig, name: Option<&str>) -> Result<Self, Error> {
        let mut app_config = read_app_config(&config.path_app_config)?;
        let segment_len = config.segment_len.unwrap_or(DEFAULT_SEGMENT_SIZE);
        let segmentation_limits = &mut app_config.app_vm_config.system.config.segmentation_limits;
        segmentation_limits.max_trace_height = segment_len as u32;
        segmentation_limits.max_cells = 1_200_000_000_usize; // For 24G vram

        let app_exe = read_app_exe(&config.path_app_exe)?;
        Ok(Self {
            app_exe: Arc::new(app_exe),
            config,
            prover_name: name.unwrap_or("universal").to_string(),
            app_config,
            sdk: OnceLock::new(),
            prover: OnceLock::new(),
        })
    }

    /// Release OpenVM SDK resources
    pub fn reset(&mut self) {
        self.sdk = OnceLock::new();
        self.prover = OnceLock::new();
    }

    /// Get or initialize the SDK lazily
    fn get_sdk(&self) -> Result<&Sdk, Error> {
        self.sdk.get_or_try_init(|| {
            tracing::info!("Lazy initializing SDK...");
            let sdk = Sdk::new(self.app_config.clone()).expect("sdk init failed");

            // 45s for first time
            let sdk = sdk.with_agg_pk(AGG_STARK_PROVING_KEY.clone());
            Ok(sdk)
        })
    }

    /// Get or initialize the prover lazily
    fn get_prover_mut(
        &mut self,
    ) -> Result<&mut StarkProver<DefaultStarkEngine, SdkVmBuilder, NativeBuilder>, Error> {
        if self.prover.get().is_none() {
            tracing::info!("Lazy initializing prover...");
            let sdk = self.get_sdk()?;
            // 5s
            let prover = sdk.prover(self.app_exe.clone()).unwrap();
            let _ = self.prover.set(prover);
        }
        Ok(self.prover.get_mut().unwrap())
    }
    /// Pick up loaded app commit, to distinguish from which circuit the proof comes
    pub fn get_app_commitment(&mut self) -> ProgramCommitment {
        let prover = self.get_prover_mut().expect("Failed to initialize prover");
        let commits = prover.app_commit();
        let exe = commits.app_exe_commit.to_u32_digest();
        let vm = commits.app_vm_commit.to_u32_digest();
        ProgramCommitment { exe, vm }
    }

    /// Pick up loaded app commit as "vk" in proof, to distinguish from which circuit the proof comes
    pub fn get_app_vk(&mut self) -> Vec<u8> {
        serialize_vk::serialize(&self.get_app_commitment())
    }

    /// Pick up the actual vk (serialized) for evm proof, would be empty if prover
    /// do not contain evm prover
    pub fn get_evm_vk(&self) -> Vec<u8> {
        let sdk = self.get_sdk().expect("Failed to initialize SDK");
        scroll_zkvm_verifier::evm::serialize_vk(sdk.halo2_pk().wrapper.pinning.pk.get_vk())
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

        let stdin = task.build_guest_input();

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
        let sdk = self.get_sdk()?;
        let t = std::time::Instant::now();
        let exec_result = crate::utils::vm::execute_guest(
            sdk,
            self.app_config.app_vm_config.as_ref(),
            self.app_exe.clone(),
            stdin,
        )
        .map_err(|e| Error::GenProof(e.to_string()))?;
        let execution_time_mills = t.elapsed().as_millis() as u64;
        let execution_time_s = execution_time_mills as f32 / 1000.0f32;
        let exec_speed = (exec_result.total_cycle as f32 / 1_000_000.0f32) / execution_time_s; // MHz
        tracing::info!(
            "total cycle of {}: {}, exec speed: {:.2}MHz, exec time: {:2}s",
            self.prover_name,
            exec_result.total_cycle,
            exec_speed,
            execution_time_s
        );
        Ok(exec_result)
    }

    /// Execute the guest program to get the cycle count.
    pub fn execute_and_check(&self, stdin: &StdIn) -> Result<u64, Error> {
        self.execute_and_check_with_full_result(stdin)
            .map(|res| res.total_cycle)
    }

    /// Generate a [root proof][root_proof].
    ///
    /// [root_proof][openvm_sdk::verifier::root::types::RootVmVerifierInput]
    pub fn gen_proof_stark(&mut self, stdin: StdIn) -> Result<StarkProof, Error> {
        // Here we always do an execution of the guest program to get the cycle count.
        // and do precheck before proving like ensure PI != 0
        let t = std::time::Instant::now();
        let total_cycles = self.execute_and_check(&stdin)?;
        let execution_time_mills = t.elapsed().as_millis() as u64;

        let t = std::time::Instant::now();
        let prover = self.get_prover_mut()?;
        let proof = prover.prove(stdin);
        let proving_time_mills = t.elapsed().as_millis() as u64;
        let proving_time_s = proving_time_mills as f32 / 1000.0f32;
        let prove_speed = (total_cycles as f32 / 1_000_000.0f32) / proving_time_s; // MHz
        tracing::info!(
            "{} proving speed: {:.2}MHz, cycles: {total_cycles}, time: {:.2}s",
            self.prover_name,
            prove_speed,
            proving_time_s
        );
        let proof = proof.map_err(|e| Error::GenProof(e.to_string()))?;
        let stat = StarkProofStat {
            total_cycles,
            proving_time_mills,
            execution_time_mills,
        };
        let proof = StarkProof {
            proofs: vec![proof.inner],
            public_values: proof.user_public_values,
            //exe_commitment: comm.exe,
            //vm_commitment: comm.vm,
            stat,
        };
        tracing::info!("verifing stark proof");
        UniversalVerifier::verify_stark_proof_with_vk(
            &AGG_STARK_PROVING_KEY.get_agg_vk(),
            &proof,
            &self.get_app_vk(),
        )
        .map_err(|e| Error::VerifyProof(e.to_string()))?;
        tracing::info!("verifing stark proof done");
        Ok(proof)
    }

    /// Generate an [evm proof][evm_proof].
    ///
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    pub fn gen_proof_snark(&mut self, stdin: StdIn) -> Result<OpenVmEvmProof, Error> {
        self.execute_and_check(&stdin)?;

        let sdk = self.get_sdk()?;
        let evm_proof = sdk
            .prove_evm(self.app_exe.clone(), stdin)
            .map_err(|e| Error::GenProof(format!("{}", e)))?;

        Ok(evm_proof)
    }
}
