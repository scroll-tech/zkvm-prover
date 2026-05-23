use std::{
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use openvm_circuit::arch::instructions::{exe::VmExe, DEFERRAL_AS};
use openvm_sdk::{F, Sdk, StdIn, SC};
use openvm_sdk::config::{AggregationConfig, AggregationSystemParams, AggregationTreeConfig, AppConfig};
use openvm_sdk_config::SdkVmConfig;
use openvm_stark_sdk::{
    config::{internal_params_with_100_bits_security, leaf_params_with_100_bits_security, root_params_with_100_bits_security},
    openvm_stark_backend::{codec::Encode, p3_field::PrimeField32},
};
use scroll_zkvm_types::{proof::OpenVmEvmProof, types_agg::ProgramCommitment, utils::serialize_vk};
use scroll_zkvm_verifier::verifier::UniversalVerifier;
use tracing::instrument;

use openvm_deferral_circuit::DeferralFn;
use openvm_sdk::prover::DeferralProver;
use openvm_verify_stark_circuit::extension::verify_stark_deferral_fn;

#[cfg(feature = "cuda")]
use openvm_cuda_backend::BabyBearPoseidon2GpuEngine as DeferralEngine;
#[cfg(feature = "cuda")]
use openvm_verify_stark_circuit::prover::DeferredVerifyGpuProver as VerifyProver;
#[cfg(feature = "cuda")]
use openvm_verify_stark_circuit::prover::DeferredVerifyGpuCircuitProver as VerifyCircuitProver;

#[cfg(not(feature = "cuda"))]
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2CpuEngine as DeferralEngine;
#[cfg(not(feature = "cuda"))]
use openvm_verify_stark_circuit::prover::DeferredVerifyCpuProver as VerifyProver;
#[cfg(not(feature = "cuda"))]
use openvm_verify_stark_circuit::prover::DeferredVerifyCpuCircuitProver as VerifyCircuitProver;

type SdkAppConfig = AppConfig<SdkVmConfig>;

// Re-export from openvm_sdk.
pub use openvm_sdk::{self};

/// Default aggregation parameters shared by all provers.
fn default_agg_params() -> AggregationSystemParams {
    AggregationSystemParams {
        leaf: leaf_params_with_100_bits_security(),
        internal: internal_params_with_100_bits_security(),
    }
}

/// Default aggregation-tree shape used by chunk, batch, and bundle provers.
///
/// Must stay in sync with [`generate_evm_verifier`](crates/build-guest/src/main.rs).
const DEFAULT_AGG_TREE_CONFIG: AggregationTreeConfig = AggregationTreeConfig {
    num_children_internal: 2,
    num_children_leaf: 2,
};

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
    app_config: SdkAppConfig,
    /// Lazily initialized SDK
    sdk: OnceLock<Sdk>,
    /// Optional deferral prover for aggregation circuits.
    ///
    /// The prover itself is moved into the SDK during `enable_deferral()`, so this
    /// field is never read directly. It is kept to make the type explicit.
    #[allow(dead_code)]
    deferral_prover: Option<DeferralProver>,
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
        let segmentation_limits = &mut app_config.app_vm_config.system.config.segmentation_config.limits;
        segmentation_limits.max_trace_height = segment_len as u32;
        segmentation_limits.max_memory = 1_200_000_000_usize; // For 24G vram

        let app_exe = read_app_exe(&config.path_app_exe)?;
        Ok(Self {
            app_exe: Arc::new(app_exe),
            config,
            prover_name: name.unwrap_or("universal").to_string(),
            app_config,
            sdk: OnceLock::new(),
            deferral_prover: None,
        })
    }

    /// Release OpenVM SDK resources
    pub fn reset(&mut self) {
        self.sdk = OnceLock::new();
    }

    /// Get or initialize the SDK lazily.
    ///
    /// For leaf circuits (chunk) this returns a plain SDK.  
    /// For aggregation circuits (batch/bundle) call [`enable_deferral`] first so
    /// the SDK includes the deferral prover required by OpenVM v2+.
    fn get_sdk(&self) -> Result<&Sdk, Error> {
        self.sdk.get_or_try_init(|| {
            tracing::info!("Lazy initializing SDK...");
            let sdk = Sdk::builder()
                .app_config(self.app_config.clone())
                .agg_params(default_agg_params())
                .agg_tree_config(DEFAULT_AGG_TREE_CONFIG)
                .build()
                .map_err(|e| Error::GenProof(e.to_string()))?;
            Ok(sdk)
        })
    }

    /// Pick up loaded app commit, to distinguish from which circuit the proof comes
    pub fn get_app_commitment(&self) -> ProgramCommitment {
        let sdk = self.get_sdk().expect("Failed to initialize SDK");
        let prover = sdk
            .prover(self.app_exe.clone())
            .expect("Failed to initialize prover");
        let exe_digest = prover.app_prover.app_exe_commit();
        let vm_digest = prover.app_vm_commit();
        let exe: [u32; 8] = std::array::from_fn(|i| exe_digest[i].as_canonical_u32());
        let vm: [u32; 8] = std::array::from_fn(|i| vm_digest[i].as_canonical_u32());
        ProgramCommitment { exe, vm }
    }

    /// Get the SDK for this prover.
    pub fn sdk(&self) -> Result<&Sdk, Error> {
        self.get_sdk()
    }

    /// Pick up loaded app commit as "vk" in proof, to distinguish from which circuit the proof comes
    pub fn get_app_vk(&self) -> Vec<u8> {
        serialize_vk::serialize(&self.get_app_commitment())
    }

    /// Pick up the actual vk (serialized) for evm proof, would be empty if prover
    /// do not contain evm prover
    pub fn get_evm_vk(&self) -> Vec<u8> {
        let sdk = self.get_sdk().expect("Failed to initialize SDK");
        scroll_zkvm_verifier::evm::serialize_vk(sdk.halo2_pk().wrapper.pinning.pk.get_vk())
    }

    /// Enable deferred STARK verification by configuring this prover's SDK
    /// to use the child prover's aggregation VK for deferral proof generation.
    ///
    /// This method pre-builds the SDK with deferral enabled. After calling this,
    /// `get_sdk()` will return the deferral-enabled SDK directly.
    ///
    /// # Why deferral is needed
    ///
    /// OpenVM v2+ uses a deferred compute model for aggregation circuits (batch,
    /// bundle).  The aggregation prover does not verify child STARK proofs
    /// directly; instead it generates "deferral proofs" that are verified later
    /// by the root verifier.  This requires:
    ///
    /// 1. A `DeferralProver` built from the **child** circuit's aggregation VK.
    /// 2. A `deferral` extension injected into the VM config.
    /// 3. Extra memory space (`DEFERRAL_AS`) reserved for deferral state.
    pub fn enable_deferral(&mut self, child_prover: &Prover) -> Result<(), Error> {
        let child_sdk = child_prover.get_sdk()?;
        let agg_prover = child_sdk.agg_prover();
        let ir_vk = agg_prover.internal_recursive_prover.get_vk();
        let ir_pcs_data = agg_prover
            .internal_recursive_prover
            .get_self_vk_pcs_data()
            .ok_or_else(|| Error::GenProof("missing child VK PCS data".to_string()))?;

        let system_config = child_sdk.app_config().app_vm_config.as_ref().clone();
        let memory_dimensions = system_config.memory_config.memory_dimensions();
        let num_user_pvs = system_config.num_public_values;

        let def_circuit_params = internal_params_with_100_bits_security();
        let child_def_hook_commit = child_sdk.def_hook_commit();
        let deferred_verify_prover = VerifyProver::new::<DeferralEngine>(
            ir_vk.clone(),
            ir_pcs_data.commitment.into(),
            def_circuit_params,
            memory_dimensions,
            num_user_pvs,
            child_def_hook_commit,
            0,
        );
        let verify_stark_prover = VerifyCircuitProver::new(deferred_verify_prover);

        let hook_params = root_params_with_100_bits_security();
        let agg_config = AggregationConfig {
            params: default_agg_params(),
        };
        let deferral_prover = DeferralProver::new(verify_stark_prover, agg_config, hook_params);

        let deferral_ext = deferral_prover
            .make_extension(vec![Arc::new(DeferralFn::new(verify_stark_deferral_fn))]);

        self.app_config.app_vm_config.deferral = Some(deferral_ext);
        self.app_config.app_vm_config.system.config.memory_config.addr_spaces
            [DEFERRAL_AS as usize]
            .num_cells = 1 << 25;

        // Pre-build SDK with deferral enabled so get_sdk() returns it directly.
        self.reset();
        let sdk = Sdk::builder()
            .app_config(self.app_config.clone())
            .agg_params(default_agg_params())
            .agg_tree_config(DEFAULT_AGG_TREE_CONFIG)
            .deferral_prover(deferral_prover)
            .build()
            .map_err(|e| Error::GenProof(e.to_string()))?;
        self.sdk
            .set(sdk)
            .map_err(|_| Error::GenProof("sdk already set".to_string()))?;

        Ok(())
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
            self.gen_proof_stark(stdin, &[])?.into()
        } else {
            EvmProof::from(self.gen_proof_snark(stdin, &[])?).into()
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
    pub fn gen_proof_stark(
        &self,
        stdin: StdIn,
        def_inputs: &[openvm_sdk::DeferralInput],
    ) -> Result<StarkProof, Error> {
        // Here we always do an execution of the guest program to get the cycle count.
        // and do precheck before proving like ensure PI != 0
        let t = std::time::Instant::now();
        let total_cycles = self.execute_and_check(&stdin)?;
        let execution_time_mills = t.elapsed().as_millis() as u64;

        let t = std::time::Instant::now();
        let sdk = self.get_sdk()?;
        let (vm_stark_proof, baseline) = sdk
            .prove(self.app_exe.clone(), stdin, def_inputs)
            .map_err(|e| Error::GenProof(e.to_string()))?;
        let proving_time_mills = t.elapsed().as_millis() as u64;
        let proving_time_s = proving_time_mills as f32 / 1000.0f32;
        let prove_speed = (total_cycles as f32 / 1_000_000.0f32) / proving_time_s; // MHz
        tracing::info!(
            "{} proving speed: {:.2}MHz, cycles: {total_cycles}, time: {:.2}s",
            self.prover_name,
            prove_speed,
            proving_time_s
        );

        let stat = StarkProofStat {
            total_cycles,
            proving_time_mills,
            execution_time_mills,
        };

        // Encode the inner proof
        let proof_bytes = vm_stark_proof
            .inner
            .encode_to_vec()
            .map_err(|e| Error::GenProof(e.to_string()))?;

        // Encode user public values proof
        let mut user_pvs_buf = Vec::new();
        vm_stark_proof
            .user_pvs_proof
            .encode::<SC, _>(&mut user_pvs_buf)
            .map_err(|e| Error::GenProof(e.to_string()))?;

        // Encode baseline
        let baseline_bytes =
            serde_json::to_vec(&baseline).map_err(|e| Error::GenProof(e.to_string()))?;

        // Encode deferral Merkle proofs
        let mut deferral_merkle_proofs = Vec::new();
        if let Some(ref proofs) = vm_stark_proof.deferral_merkle_proofs {
            proofs
                .encode(&mut deferral_merkle_proofs)
                .map_err(|e| Error::GenProof(e.to_string()))?;
        }

        let proof = StarkProof {
            proof: proof_bytes,
            user_pvs_proof: user_pvs_buf,
            baseline: baseline_bytes,
            deferral_merkle_proofs,
            stat,
        };

        tracing::info!("verifing stark proof");
        let agg_vk = self.get_sdk()?.agg_vk();
        UniversalVerifier::verify_stark_proof_with_vk(
            &agg_vk,
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
    pub fn gen_proof_snark(
        &self,
        stdin: StdIn,
        def_inputs: &[openvm_sdk::DeferralInput],
    ) -> Result<OpenVmEvmProof, Error> {
        self.execute_and_check(&stdin)?;

        let sdk = self.get_sdk()?;
        let evm_proof = sdk
            .prove_evm(self.app_exe.clone(), stdin, def_inputs)
            .map_err(|e| Error::GenProof(format!("{}", e)))?;

        Ok(evm_proof)
    }
}
