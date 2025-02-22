use std::{
    collections::BTreeMap,
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::Arc,
};

use metrics_util::{MetricKind, debugging::DebugValue};
use once_cell::sync::Lazy;
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

use crate::{Error, WrappedProof, proof::RootProof, setup::read_app_exe, task::ProvingTask};

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

/// Alias for convenience.
pub type SC = BabyBearPoseidon2Config;

/// Load config and exe, and also return pk and commits.
pub fn init_exe<P: AsRef<Path>>(
    path_exe: P,
    app_config: AppConfig<SdkVmConfig>,
) -> Result<InitRes, Error> {
    let app_exe = read_app_exe(path_exe)?;
    let app_pk = Sdk
        .app_keygen(app_config)
        .map_err(|e| Error::Keygen(e.to_string()))?;
    let app_committed_exe = Sdk
        .commit_app_exe(app_pk.app_fri_params(), app_exe)
        .map_err(|e| Error::Commit(e.to_string()))?;

    let commits = AppExecutionCommit::compute(
        &app_pk.app_vm_pk.vm_config,
        &app_committed_exe,
        &app_pk.leaf_committed_exe,
    );
    Ok((app_committed_exe, Arc::new(app_pk), commits))
}

impl<Type: ProverType> Prover<Type> {
    /// Setup the [`Prover`] given paths to the application's exe and proving key.
    #[instrument("Prover::setup", fields(path_exe, path_app_config, cache_dir))]
    pub fn setup<P: AsRef<Path>>(
        path_exe: P,
        path_app_config: P,
        cache_dir: Option<P>,
    ) -> Result<Self, Error> {
        let app_config = Type::read_app_config(path_app_config)?;
        let (app_committed_exe, app_pk, _) = Self::init(&path_exe, app_config)?;

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
    #[instrument("Prover::init", fields(path_exe))]
    pub fn init<P: AsRef<Path>>(
        path_exe: P,
        app_config: AppConfig<SdkVmConfig>,
    ) -> Result<InitRes, Error> {
        let (app_committed_exe, app_pk, commits) = init_exe(path_exe, app_config)?;

        // print the 2 exe commitments
        use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
        let exe_commit = commits.exe_commit.map(|x| x.as_canonical_u32());
        let leaf_commit = commits
            .leaf_vm_verifier_commit
            .map(|x| x.as_canonical_u32());
        debug!(name: "exe-commitment", prover_name = Type::NAME, raw = ?exe_commit, as_bn254 = ?commits.exe_commit_to_bn254());
        debug!(name: "leaf-commitment", prover_name = Type::NAME, raw = ?leaf_commit, as_bn254 = ?commits.app_config_commit_to_bn254());
        Ok((app_committed_exe, app_pk, commits))
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
    ) -> Result<WrappedProof<Type::ProofMetadata, RootProof>, Error> {
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
    ) -> Result<WrappedProof<Type::ProofMetadata, EvmProof>, Error> {
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
    pub fn verify_proof(
        &self,
        proof: &WrappedProof<Type::ProofMetadata, RootProof>,
    ) -> Result<(), Error> {
        let agg_stark_pk = &AGG_STARK_PROVING_KEY;

        let root_verifier_pk = &agg_stark_pk.root_verifier_pk;
        let vm = SingleSegmentVmExecutor::new(root_verifier_pk.vm_pk.vm_config.clone());
        let exe: &VmCommittedExe<_> = &root_verifier_pk.root_committed_exe;

        let _ = vm
            .execute_and_compute_heights(exe.exe.clone(), proof.proof.write())
            .map_err(|e| Error::VerifyProof(e.to_string()))?;

        Ok(())
    }

    /// Verify an [evm proof][evm_proof].
    ///
    /// [evm_proof][openvm_native_recursion::halo2::EvmProof]
    #[instrument("Prover::verify_proof_evm", skip_all)]
    pub fn verify_proof_evm(
        &self,
        proof: &WrappedProof<Type::ProofMetadata, EvmProof>,
    ) -> Result<(), Error> {
        let gas_cost = scroll_zkvm_verifier::evm::verify_evm_proof(
            &self
                .evm_prover
                .as_ref()
                .expect("uninited")
                .verifier_contract,
            &proof.proof,
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
        let stdin = task
            .build_guest_input()
            .map_err(|e| Error::GenProof(e.to_string()))?;

        let mock_prove = std::env::var("MOCK_PROVE").as_deref() == Ok("true");
        let guest_profiling = std::env::var("GUEST_PROFILING").as_deref() == Ok("true");
        if mock_prove || guest_profiling {
            let (cycle_count, executor_result) = self.execute_guest(&stdin, guest_profiling)?;
            tracing::info!(name: "total cycle count", ?cycle_count);
            if mock_prove {
                self.mock_prove(executor_result)?;
            }
        }

        let task_id = task.identifier();

        tracing::debug!(name: "generate_root_verifier_input", ?task_id);
        Sdk.generate_root_verifier_input(
            Arc::clone(&self.app_pk),
            Arc::clone(&self.app_committed_exe),
            AGG_STARK_PROVING_KEY.clone(),
            stdin,
        )
        .map_err(|e| Error::GenProof(e.to_string()))
    }

    /// Execute the guest program to get the cycle count.
    ///
    /// If the GUEST_PROFILING environment variable has been set to "true",
    /// row_usage/cell_usage/counter_per_op metrics are also collected.
    pub fn execute_guest(
        &self,
        stdin: &StdIn,
        profile: bool,
    ) -> Result<(u64, VmExecutorResult<SC>), Error> {
        use openvm_circuit::arch::VmConfig;
        use openvm_stark_sdk::openvm_stark_backend::p3_field::Field;

        let mut config = self.app_pk.app_vm_pk.vm_config.clone();
        if profile {
            config.system.config = config.system.config.with_profiling();
        }
        let vm = VmExecutor::new(config.clone());

        let mut segments = vm
            .execute_segments(self.app_committed_exe.exe.clone(), stdin.clone())
            .map_err(|e| Error::GenProof(e.to_string()))?;
        tracing::info!(name: "segment length", segment_len = segments.len());

        let final_memory = std::mem::take(&mut segments.last_mut().unwrap().final_memory);
        let mut metric_snapshots = vec![];
        let executor_result = VmExecutorResult {
            per_segment: segments
                .into_iter()
                .map(|seg| {
                    use metrics_tracing_context::TracingContextLayer;
                    use metrics_util::layers::Layer;
                    let recorder = metrics_util::debugging::DebuggingRecorder::new();
                    let snapshotter = recorder.snapshotter();
                    // zzhang: i don't know why this TracingContextLayer is needed, but i copied it from
                    // "stark-backend" repo.
                    let recorder = TracingContextLayer::all().layer(recorder);
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

        // extract and check public values
        let final_memory = executor_result.final_memory.as_ref().unwrap();
        let system_config = <SdkVmConfig as VmConfig<F>>::system(&config);
        let public_values: Vec<F> = extract_public_values(
            &system_config.memory_config.memory_dimensions(),
            system_config.num_public_values,
            final_memory,
        );
        tracing::debug!(name: "public_values after guest execution", ?public_values);
        if public_values.iter().all(|x| x.is_zero()) {
            return Err(Error::GenProof("public_values are all 0s".to_string()));
        }

        let mut counter_sum = BTreeMap::<String, BTreeMap<String, u64>>::new();
        for (idx, metric_snapshot) in metric_snapshots.into_iter().enumerate() {
            let metrics = metric_snapshot.into_vec();
            for (ckey, _, _, value) in metrics {
                match ckey.kind() {
                    MetricKind::Counter => {
                        let value = match value {
                            DebugValue::Counter(v) => v,
                            _ => panic!("unexpected value type"),
                        };
                        tracing::debug!(
                            "metric of segment {}: {}=>{}, {ckey:?}",
                            idx,
                            ckey.key().name(),
                            value
                        );
                        let label = ckey
                            .key()
                            .labels()
                            .map(|l| l.value())
                            .filter(|l| !l.is_empty())
                            .collect::<Vec<_>>()
                            .join("|");
                        let counter_name = ckey.key().name().to_string();
                        let counter_map =
                            counter_sum.entry(counter_name).or_insert(BTreeMap::new());
                        let counter_value = counter_map.entry(label).or_insert(0);
                        *counter_value += value;
                    }
                    MetricKind::Gauge => {}
                    MetricKind::Histogram => {}
                }
            }
        }

        if profile {
            let mut bench_report = String::new();
            use std::fmt::Write;
            writeln!(&mut bench_report, "guest profiling:").unwrap();
            for (counter_name, values) in counter_sum.iter() {
                writeln!(&mut bench_report, "{counter_name}:").unwrap();
                let mut sorted_values: Vec<_> = values.iter().collect();
                sorted_values.sort_by(|a, b| b.1.cmp(a.1));
                for (label, value) in sorted_values {
                    writeln!(&mut bench_report, "  {label}\t{value}").unwrap();
                }
                writeln!(&mut bench_report).unwrap();
            }
            println!("{}", bench_report);
        }

        let total_cycle = *counter_sum.get("total_cycles").unwrap().get("").unwrap();
        Ok((total_cycle, executor_result))
    }

    /// Runs only if the MOCK_PROVE environment variable has been set to "true".
    fn mock_prove(&self, result: VmExecutorResult<SC>) -> Result<(), Error> {
        use openvm_circuit::arch::VmConfig;
        use openvm_stark_sdk::{
            config::baby_bear_poseidon2::BabyBearPoseidon2Engine, engine::StarkFriEngine,
        };

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
    fn read_app_config<P: AsRef<Path>>(path_app_config: P)
    -> Result<AppConfig<SdkVmConfig>, Error>;

    /// Provided the proving task, computes the proof metadata.
    fn metadata_with_prechecks(task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error>;
}
