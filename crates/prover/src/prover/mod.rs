use std::{
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::Arc,
};

use metrics_util::{MetricKind, debugging::DebugValue};
use once_cell::sync::OnceCell;
use openvm_circuit::{
    arch::{SingleSegmentVmExecutor, VmExecutor, VmExecutorResult},
    system::{memory::tree::public_values::extract_public_values, program::trace::VmCommittedExe},
};
use openvm_native_recursion::{
    halo2::{
        EvmProof,
        utils::{CacheHalo2ParamsReader, Halo2ParamsReader},
        wrapper::{EvmVerifier, Halo2WrapperProvingKey},
    },
    hints::Hintable,
};
use openvm_sdk::{
    F, NonRootCommittedExe, Sdk, StdIn,
    commit::AppExecutionCommit,
    config::{AggConfig, AggStarkConfig, AppConfig, SdkVmConfig},
    keygen::{AggStarkProvingKey, AppProvingKey, RootVerifierProvingKey},
    prover::ContinuationProver,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;
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
static AGG_STARK_PROVING_KEY: OnceCell<AggStarkProvingKey> = OnceCell::new();

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
pub type ProgramCommitments = [[u32; 8]; 2];
type InitRes = Result<
    (
        Arc<VmCommittedExe<SC>>,
        Arc<AppProvingKey<SdkVmConfig>>,
        ProgramCommitments,
    ),
    Error,
>;

/// Alias for convenience.
pub type SC = BabyBearPoseidon2Config;

impl<Type: ProverType> Prover<Type> {
    /// Setup the [`Prover`] given paths to the application's exe and proving key.
    #[instrument("Prover::setup", fields(path_exe, path_app_config, cache_dir))]
    pub fn setup<P: AsRef<Path>>(
        path_exe: P,
        path_app_config: P,
        cache_dir: Option<P>,
    ) -> Result<Self, Error> {
        let (app_committed_exe, app_pk, _) = Self::init(&path_exe, &path_app_config)?;

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
    pub fn init<P: AsRef<Path>>(path_exe: P, path_app_config: P) -> InitRes {
        let app_exe = read_app_exe(path_exe)?;
        let app_config = Type::read_app_config(path_app_config)?;
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

        let _agg_stark_pk = AGG_STARK_PROVING_KEY
            .get_or_init(|| AggStarkProvingKey::keygen(AggStarkConfig::default()));

        Ok((app_committed_exe, Arc::new(app_pk), [
            exe_commit,
            leaf_commit,
        ]))
    }

    /// Dump assets required to setup verifier-only mode.
    pub fn dump_verifier<P: AsRef<Path>>(&self, dir: P) -> Result<(PathBuf, PathBuf), Error> {
        if !Type::EVM {
            return Err(Error::Custom(
                "dump_verifier only at bundle-prover".to_string(),
            ));
        };

        let agg_stark_pk = AGG_STARK_PROVING_KEY.get().ok_or(Error::Custom(
            "AGG_STARK_PROVING_KEY is not setup".to_string(),
        ))?;
        let root_verifier_pk = &agg_stark_pk.root_verifier_pk;
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
    #[instrument("Prover::gen_proof", skip_all, fields(task_id))]
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
        let agg_stark_pk = AGG_STARK_PROVING_KEY
            .get()
            .ok_or(Error::VerifyProof(String::from(
                "agg stark pk not initialized! Prover::setup",
            )))?;

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
        let gas_cost = scroll_zkvm_verifier::evm::verify_evm_proof(
            &self.evm_prover.as_ref().expect("").verifier_contract,
            &evm_proof,
        )
        .map_err(|e| Error::VerifyProof(format!("EVM-proof verification failed: {e}")))?;

        tracing::info!(name: "verify_evm_proof", ?gas_cost);

        Ok(())
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
        let agg_stark_pk = AGG_STARK_PROVING_KEY
            .get()
            .ok_or(Error::GenProof(String::from(
                "agg stark pk not initialized! Prover::setup",
            )))?;

        let stdin = task
            .build_guest_input()
            .map_err(|e| Error::GenProof(e.to_string()))?;

        if let Some((_cycle_count, executor_result)) = self.execute_guest(&stdin)? {
            self.mock_prove_if_needed(executor_result)?;
        }

        let task_id = task.identifier();

        tracing::debug!(name: "generate_root_verifier_input", ?task_id);
        Sdk.generate_root_verifier_input(
            Arc::clone(&self.app_pk),
            Arc::clone(&self.app_committed_exe),
            agg_stark_pk.clone(),
            stdin,
        )
        .map_err(|e| Error::GenProof(e.to_string()))
    }

    /// Execute the guest program to get the cycle count.
    ///
    /// Runs only if the GUEST_PROFILING environment variable has been set to "true".
    fn execute_guest(&self, stdin: &StdIn) -> Result<Option<(u64, VmExecutorResult<SC>)>, Error> {
        use openvm_circuit::arch::VmConfig;
        use openvm_stark_sdk::openvm_stark_backend::p3_field::Field;

        if std::env::var("GUEST_PROFILING").as_deref() != Ok("true") {
            return Ok(None);
        }

        let config = self.app_pk.app_vm_pk.vm_config.clone();
        let system_config = <SdkVmConfig as VmConfig<F>>::system(&config);
        let vm = VmExecutor::new(config.clone());

        let mut segments = vm
            .execute_segments(self.app_committed_exe.exe.clone(), stdin.clone())
            .map_err(|e| Error::GenProof(e.to_string()))?;
        let final_memory = std::mem::take(&mut segments.last_mut().unwrap().final_memory);
        let mut metric_snapshots = vec![];
        let executor_result = VmExecutorResult {
            per_segment: segments
                .into_iter()
                .map(|seg| {
                    let recorder = metrics_util::debugging::DebuggingRecorder::new();
                    let snapshotter = recorder.snapshotter();
                    let seg_proof_input = metrics::with_local_recorder(&recorder, || {
                        seg.generate_proof_input(Some(
                            self.app_committed_exe.committed_program.clone(),
                        ))
                    });
                    metric_snapshots.push(snapshotter.snapshot());
                    seg_proof_input
                })
                .collect(),
            final_memory,
        };

        tracing::debug!(name: "segment length", segment_len = executor_result.per_segment.len());

        // extract and check public values
        let final_memory = executor_result.final_memory.as_ref().unwrap();
        let public_values: Vec<F> = extract_public_values(
            &system_config.memory_config.memory_dimensions(),
            system_config.num_public_values,
            final_memory,
        );
        tracing::debug!(name: "public_values after guest execution", ?public_values);
        if public_values.iter().all(|x| x.is_zero()) {
            return Err(Error::GenProof("public_values are all 0s".to_string()));
        }

        let mut counter_sum = std::collections::HashMap::<String, u64>::new();
        for (idx, metric_snapshot) in metric_snapshots.into_iter().enumerate() {
            let metrics = metric_snapshot.into_vec();
            for (ckey, _, _, value) in metrics {
                match ckey.kind() {
                    MetricKind::Gauge => {}
                    MetricKind::Counter => {
                        let value = match value {
                            DebugValue::Counter(v) => v,
                            _ => panic!("unexpected value type"),
                        };
                        tracing::debug!(
                            "metric of segment {}: {}=>{}",
                            idx,
                            ckey.key().name(),
                            value
                        );
                        // add to `counter_sum`
                        let counter_name = ckey.key().name().to_string();
                        let counter_value = counter_sum.entry(counter_name).or_insert(0);
                        *counter_value += value;
                    }
                    MetricKind::Histogram => {}
                }
            }
        }
        for (name, value) in counter_sum.iter() {
            tracing::debug!("metric of all segments: {}=>{}", name, value);
        }

        let total_cycle = counter_sum.get("total_cycles").cloned().unwrap_or(0);
        Ok(Some((total_cycle, executor_result)))
    }

    /// Runs only if the MOCK_PROVE environment variable has been set to "true".
    fn mock_prove_if_needed(&self, result: VmExecutorResult<SC>) -> Result<(), Error> {
        use openvm_circuit::arch::VmConfig;
        use openvm_stark_sdk::{
            config::baby_bear_poseidon2::BabyBearPoseidon2Engine, engine::StarkFriEngine,
        };

        if std::env::var("MOCK_PROVE").as_deref() != Ok("true") {
            return Ok(());
        }

        let engine = BabyBearPoseidon2Engine::new(self.app_pk.app_vm_pk.fri_params);
        let airs = self
            .app_pk
            .app_vm_pk
            .vm_config
            .create_chip_complex()
            .unwrap()
            .airs();

        for result in result.per_segment {
            let (used_airs, per_air) = result
                .per_air
                .into_iter()
                .map(|(air_id, x)| (airs[air_id].clone(), x))
                .unzip();
            engine.run_test(used_airs, per_air).unwrap();
        }

        Ok(())
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

    /// Read the app config from the given path.
    fn read_app_config<P: AsRef<Path>>(
        path_app_config: P,
    ) -> Result<AppConfig<SdkVmConfig>, Error> {
        let mut config = read_app_config(path_app_config)?;
        config.app_vm_config.system.config = config
            .app_vm_config
            .system
            .config
            .with_max_segment_len(Self::SEGMENT_SIZE);
        Ok(config)
    }

    /// Provided the proving task, computes the proof metadata.
    fn metadata_with_prechecks(task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error>;
}
