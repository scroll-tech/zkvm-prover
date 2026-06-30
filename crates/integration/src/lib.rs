use cargo_metadata::MetadataCommand;
use once_cell::sync::OnceCell;
use openvm_circuit::arch::deferral::DeferralState;
use openvm_sdk::{DeferralInput, Sdk, StdIn};
use openvm_stark_sdk::openvm_stark_backend::codec::Decode;
use openvm_verify_stark_circuit::extension::{get_deferral_state, get_raw_deferral_results};
use openvm_verify_stark_host::{vk::VmStarkVerifyingKey, VmStarkProof};
use scroll_zkvm_prover::{
    Prover,
    setup::{read_app_config, read_app_exe},
    utils::{read_json, vm::ExecutionResult, write_json},
};
use scroll_zkvm_types::{
    ProvingTask as UniversalProvingTask,
    proof::{EvmProof, ProofEnum, StarkProof},
    public_inputs::{ForkName, Version},
    types_agg::ProgramCommitment,
    utils::serialize_vk,
};
use scroll_zkvm_verifier::verifier::{AGG_STARK_PROVING_KEY, UniversalVerifier};
use std::collections::HashMap;
use std::{
    io::Cursor,
    path::{Path, PathBuf},
    process,
    sync::LazyLock,
};
use tracing::instrument;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

pub mod testers;

pub mod utils;

/// Directory to store proofs on disc.
const DIR_PROOFS: &str = "proofs";

/// File descriptor for app openvm config.
const FD_APP_CONFIG: &str = "openvm.toml";

/// File descriptor for app exe.
const FD_APP_EXE: &str = "app.vmexe";

/// Environment variable used to set the test-run's output directory for assets.
const ENV_OUTPUT_DIR: &str = "OUTPUT_DIR";

/// When set to "1", run STARK and SNARK proving in separate subprocesses so that
/// the SNARK step starts with a clean CUDA context.
const ENV_SPLIT_STARK_SNARK: &str = "SCROLL_ZKVM_SPLIT_STARK_SNARK";

/// Enviroment settings for test: fork
pub fn testing_hardfork() -> ForkName {
    testing_version().fork
}

/// Test settings (version).
pub fn testing_version() -> Version {
    Version::galileo_v2()
}

pub fn testing_version_validium() -> Version {
    Version::validium_v1()
}

/// Read the 'GUEST_VERSION' from the environment variable.
/// If not existed, return "dev" as default
/// The returned value will be used to locate asset files: $workspace/releases/$guest_version
pub static GUEST_VERSION: LazyLock<&str> = LazyLock::new(|| {
    let ver = std::env::var("GUEST_VERSION").unwrap_or_else(|_| "dev".to_string());
    eprintln!("GUEST_VERSION = {ver}");
    Box::leak(ver.into_boxed_str())
});

pub static WORKSPACE_ROOT: LazyLock<&Path> = LazyLock::new(|| {
    let path = MetadataCommand::new()
        .no_deps()
        .exec()
        .expect("failed to execute cargo-metadata")
        .workspace_root
        .into_std_path_buf();
    eprintln!("PROJECT_ROOT_DIR = {}", path.display());
    Box::leak(path.into_boxed_path())
});

pub static ASSET_BASE_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    let path = WORKSPACE_ROOT.join("releases").join(*GUEST_VERSION);
    eprintln!("ASSET_BASE_DIR = {}", path.display());
    path
});

/// Path to store release assets, root directory of zkvm-prover repository.
pub static DIR_OUTPUT: LazyLock<&Path> = LazyLock::new(|| {
    let path = WORKSPACE_ROOT.join(".output");
    std::fs::create_dir_all(&path).expect("failed to create output directory");
    eprintln!("DIR_OUTPUT = {}", path.display());
    Box::leak(path.into_boxed_path())
});

pub static PROGRAM_COMMITMENTS: LazyLock<HashMap<String, ProgramCommitment>> =
    LazyLock::new(|| {
        let mut commitments =
            load_program_commitments().expect("failed to load program commitments");
        commitments.shrink_to_fit();
        eprintln!("PROGRAM_COMMITMENTS = {commitments:#?}");
        commitments
    });

/// Every test run will write assets to a new directory.
///
/// Possibly one of the following:
/// - <DIR_OUTPUT>/chunk-tests-{timestamp}
/// - <DIR_OUTPUT>/batch-tests-{timestamp}
/// - <DIR_OUTPUT>/bundle-tests-{timestamp}
pub static DIR_TESTRUN: OnceCell<PathBuf> = OnceCell::new();

pub trait PartialProvingTask: serde::Serialize {
    fn identifier(&self) -> String;
    fn fork_name(&self) -> ForkName;

    fn archive(&self) -> eyre::Result<Vec<u8>>
    where
        Self: Sized,
    {
        let bytes: Vec<u8> = {
            let config = bincode::config::standard();
            bincode::serde::encode_to_vec(self, config)?
        };
        Ok(bytes)
    }
}

/// Circuit that implements functionality required to run e2e tests in specified phase (chunk/batch/bundle).
pub trait ProverTester {
    /// Tester witness type
    type Witness: PartialProvingTask;

    /// Tester metadata type
    type Metadata;

    /// Naming for tester
    const NAME: &str;

    /// Path to the corresponding circuit's project directory.
    const PATH_PROJECT_ROOT: &str;

    /// Prefix to use while naming app-specific data like app exe, app pk, etc.
    const DIR_ASSETS: &str;

    /// Setup directory structure for the test suite.
    fn setup(setup_logger: bool) -> eyre::Result<()> {
        dotenvy::dotenv().ok();

        // Setup tracing subscriber.
        if setup_logger {
            crate::setup_logger()?;
        }

        // If user has set an output directory, use it.
        let dir_testrun = if let Ok(env_dir) = std::env::var(ENV_OUTPUT_DIR) {
            let dir = Path::new(&env_dir);
            if std::fs::exists(dir).is_err() {
                tracing::error!("OUTPUT_DIR={dir:?} not found");
                process::exit(1);
            }
            dir.into()
        } else {
            // Create the <OUTPUT>/{DIR_ASSETS}-test-{timestamp} for test-run.
            let testrun = format!(
                "{}-tests-{}",
                Self::DIR_ASSETS,
                chrono::Utc::now().format("%Y%m%d_%H%M%S"),
            );
            DIR_OUTPUT.join(testrun)
        };

        // Set the path for the current test-run.
        DIR_TESTRUN
            .set(dir_testrun)
            .map_err(|dir| eyre::eyre!("could not set test-run dir: {dir:?}"))?;

        Ok(())
    }

    /// Load the app config.
    fn load() -> eyre::Result<(PathBuf, PathBuf)> {
        let path_app_config = ASSET_BASE_DIR.join(Self::NAME).join(FD_APP_CONFIG);
        let path_app_exe = ASSET_BASE_DIR.join(Self::NAME).join(FD_APP_EXE);
        Ok((path_app_config, path_app_exe))
    }

    /// Load the prover
    #[instrument("Prover::load_prover")]
    fn load_prover(with_evm: bool) -> eyre::Result<Prover> {
        let (path_app_config, path_app_exe) = Self::load()?;

        let path_assets = DIR_TESTRUN
            .get()
            .ok_or(eyre::eyre!("missing testrun dir"))?
            .join(Self::DIR_ASSETS);
        std::fs::create_dir_all(&path_assets)?;

        let config = scroll_zkvm_prover::ProverConfig {
            path_app_exe,
            path_app_config,
            ..Default::default()
        };
        let prover = Prover::setup(config, Some(Self::NAME))?;

        Ok(prover)
    }

    /// File descriptor for the proof saved to disc.
    #[instrument("Prover::fd_proof", skip_all, fields(task_id = task.identifier(), path_proof))]
    fn fd_proof(task: &impl PartialProvingTask) -> String {
        let path_proof = format!("{}-{}.json", Self::NAME, task.identifier());
        path_proof
    }

    fn build_universal_task<'a>(
        witness: &Self::Witness,
        aggregated_proofs: impl Iterator<Item = &'a StarkProof>,
        input_commits: Vec<[u8; 32]>,
    ) -> eyre::Result<UniversalProvingTask> {
        Ok(UniversalProvingTask {
            serialized_witness: vec![witness.archive()?],
            aggregated_proofs: aggregated_proofs.cloned().collect(),
            fork_name: witness.fork_name().as_str().to_string(),
            identifier: witness.identifier(),
            vk: Default::default(),
            input_commits,
        })
    }

    fn build_guest_input<'a>(
        witness: &Self::Witness,
        aggregated_proofs: impl Iterator<Item = &'a StarkProof>,
    ) -> eyre::Result<StdIn> {
        use scroll_zkvm_prover::task::ProvingTask;
        Ok(Self::build_universal_task(witness, aggregated_proofs, vec![])?.build_guest_input())
    }
}

pub trait TaskProver {
    fn name(&self) -> &str;
    fn prove_task(&mut self, t: &UniversalProvingTask, gen_snark: bool) -> eyre::Result<ProofEnum>;
    fn prove_task_with_deferral(
        &mut self,
        t: &UniversalProvingTask,
        gen_snark: bool,
        def_inputs: &[DeferralInput],
        def_states: &[DeferralState],
    ) -> eyre::Result<ProofEnum> {
        // Default: ignore deferral inputs for backward compatibility.
        let _ = def_inputs;
        let _ = def_states;
        self.prove_task(t, gen_snark)
    }
    fn get_vk(&mut self) -> eyre::Result<Vec<u8>>;
    fn get_agg_vk(&self) -> eyre::Result<openvm_stark_sdk::openvm_stark_backend::keygen::types::MultiStarkVerifyingKey<openvm_sdk::SC>>;
}

impl TaskProver for Prover {
    fn name(&self) -> &str {
        self.prover_name.as_str()
    }

    fn prove_task(&mut self, t: &UniversalProvingTask, gen_snark: bool) -> eyre::Result<ProofEnum> {
        use scroll_zkvm_prover::task::ProvingTask;
        let stdin = t.build_guest_input();
        if !gen_snark {
            // gen stark proof
            Ok(self.gen_proof_stark(stdin, &[])?.into())
        } else {
            let proof: EvmProof = self.gen_proof_snark(stdin, &[])?.into();
            Ok(proof.into())
        }
    }

    fn prove_task_with_deferral(
        &mut self,
        t: &UniversalProvingTask,
        gen_snark: bool,
        def_inputs: &[DeferralInput],
        def_states: &[DeferralState],
    ) -> eyre::Result<ProofEnum> {
        use scroll_zkvm_prover::task::ProvingTask;
        let mut stdin = t.build_guest_input();
        stdin.deferrals = def_states.to_vec();
        if !gen_snark {
            Ok(self.gen_proof_stark(stdin, def_inputs)?.into())
        } else {
            let proof: EvmProof = self.gen_proof_snark(stdin, def_inputs)?.into();
            Ok(proof.into())
        }
    }

    fn get_vk(&mut self) -> eyre::Result<Vec<u8>> {
        Ok(self.get_app_vk())
    }

    fn get_agg_vk(&self) -> eyre::Result<openvm_stark_sdk::openvm_stark_backend::keygen::types::MultiStarkVerifyingKey<openvm_sdk::SC>> {
        Ok((*self.sdk()?.agg_vk()).clone())
    }
}

/// Enviroment settings for test: fork dir
pub fn testdata_fork_directory() -> String {
    testing_hardfork().to_string()
}

/// The outcome of a successful prove-verify run.
pub struct ProveVerifyOutcome<T, P> {
    /// Single or multiple proving tasks.
    pub tasks: Vec<T>,
    /// Verified proofs for the proving tasks.
    pub proofs: Vec<P>,
}

impl<T: Clone, P: Clone> ProveVerifyOutcome<T, P> {
    pub fn single(task: T, proof: P) -> Self {
        Self {
            tasks: vec![task],
            proofs: vec![proof],
        }
    }

    pub fn multi(tasks: &[T], proofs: &[P]) -> Self {
        Self {
            tasks: tasks.to_vec(),
            proofs: proofs.to_vec(),
        }
    }
}

/// Setup test environment
fn setup_logger() -> eyre::Result<()> {
    let fmt_layer = tracing_subscriber::fmt::layer()
        .pretty()
        .with_span_events(FmtSpan::CLOSE);

    #[cfg(feature = "limit-logs")]
    {
        let filters = tracing_subscriber::filter::Targets::new()
            .with_target("scroll_zkvm_prover", tracing::Level::INFO)
            .with_target("scroll_zkvm_integration", tracing::Level::DEBUG);

        tracing_subscriber::registry()
            .with(fmt_layer)
            .with(filters)
            .try_init()?;
    }

    #[cfg(not(feature = "limit-logs"))]
    {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(fmt_layer)
            .with(metrics_tracing_context::MetricsLayer::new())
            .try_init()?;
    }

    Ok(())
}

/// Light weight testing to simply execute the vm program for test
#[instrument("tester_execute", skip_all)]
pub fn tester_execute<T: ProverTester>(
    witness: &T::Witness,
    proofs: &[ProofEnum],
) -> eyre::Result<ExecutionResult> {
    let (path_app_config, path_app_exe) = T::load()?;
    let app_exe = read_app_exe(&path_app_exe)?;
    let app_config = read_app_config(&path_app_config)?;
    let stdin = T::build_guest_input(
        witness,
        proofs
            .iter()
            .map(|p| p.as_stark_proof().expect("must be stark proof")),
    )?;

    let _app_vm_config = app_config.app_vm_config.clone();
    let sdk = Sdk::builder()
        .app_config(app_config)
        .agg_pk(AGG_STARK_PROVING_KEY.clone())
        .build()
        .map_err(|e| eyre::eyre!("sdk build failed: {e}"))?;
    let ret = scroll_zkvm_prover::utils::vm::execute_guest(&sdk, app_exe, &stdin)?;
    Ok(ret)
}

/// Decode a [`StarkProof`] into a [`VmStarkProof`].
fn decode_stark_proof(proof: &StarkProof) -> eyre::Result<VmStarkProof> {
    use openvm_circuit::system::memory::merkle::public_values::UserPublicValuesProof;

    let inner = openvm_stark_sdk::openvm_stark_backend::proof::Proof::decode_from_bytes(&proof.proof)
        .map_err(|e| eyre::eyre!("decode proof failed: {e}"))?;
    let user_pvs_proof =
        UserPublicValuesProof::decode::<openvm_sdk::SC, _>(&mut Cursor::new(&proof.user_pvs_proof))
            .map_err(|e| eyre::eyre!("decode user_pvs_proof failed: {e}"))?;
    let deferral_merkle_proofs = if proof.deferral_merkle_proofs.is_empty() {
        None
    } else {
        Some(openvm_verify_stark_host::deferral::DeferralMerkleProofs::decode(
            &mut Cursor::new(&proof.deferral_merkle_proofs),
        ).map_err(|e| eyre::eyre!("decode deferral_merkle_proofs failed: {e}"))?)
    };
    Ok(VmStarkProof {
        inner,
        user_pvs_proof,
        deferral_merkle_proofs,
    })
}

/// Compute deferral inputs and states from child proofs.
pub fn compute_deferral_data(
    child_prover: &Prover,
    proofs: &[&StarkProof],
) -> eyre::Result<(Vec<[u8; 32]>, Vec<DeferralInput>, Vec<DeferralState>)> {
    let sdk = child_prover
        .sdk()
        .map_err(|e| eyre::eyre!("failed to get child sdk: {e}"))?;
    let mvk = (*sdk.agg_vk()).clone();
    let stark_prover = sdk
        .prover(child_prover.app_exe.clone())
        .map_err(|e| eyre::eyre!("failed to create stark prover: {e}"))?;
    let baseline = stark_prover.generate_baseline();
    let vk = VmStarkVerifyingKey { mvk, baseline };

    let vm_proofs: Vec<VmStarkProof> = proofs
        .iter()
        .map(|p| decode_stark_proof(p))
        .collect::<eyre::Result<Vec<_>>>()?;

    let raw_results = get_raw_deferral_results(&vk, &vm_proofs)
        .map_err(|e| eyre::eyre!("get_raw_deferral_results failed: {e}"))?;

    let input_commits: Vec<[u8; 32]> = raw_results
        .iter()
        .map(|r| r.input.as_slice().try_into().expect("input commit must be 32 bytes"))
        .collect();

    let deferral_inputs = vec![DeferralInput::from_inputs(&vm_proofs)];

    let deferral_state = get_deferral_state(&vk, &vm_proofs, 0)
        .map_err(|e| eyre::eyre!("get_deferral_state failed: {e}"))?;

    Ok((input_commits, deferral_inputs, vec![deferral_state]))
}

/// End-to-end test for proving witnesses of the same prover.
#[instrument(name = "prove_verify", skip_all, fields(task_id, prover_name = prover.name()))]
pub fn prove_verify<T: ProverTester>(
    prover: &mut impl TaskProver,
    witness: &T::Witness,
    proofs: &[ProofEnum],
) -> eyre::Result<ProofEnum> {
    prove_verify_with_deferral::<T>(prover, witness, proofs, None)
}

/// End-to-end test with deferred STARK verification (v2).
#[instrument(name = "prove_verify_with_deferral", skip_all, fields(task_id, prover_name = prover.name()))]
pub fn prove_verify_with_deferral<T: ProverTester>(
    prover: &mut impl TaskProver,
    witness: &T::Witness,
    proofs: &[ProofEnum],
    child_prover: Option<&Prover>,
) -> eyre::Result<ProofEnum> {
    // Setup prover.
    let cache_dir = DIR_TESTRUN
        .get()
        .ok_or(eyre::eyre!("missing assets dir"))?
        .join(T::DIR_ASSETS)
        .join(DIR_PROOFS);
    std::fs::create_dir_all(&cache_dir)?;
    let vk = prover.get_vk()?;

    // Try reading proof from cache if available, and early return in that case.
    let task_id = witness.identifier();

    let path_proof = cache_dir.join(T::fd_proof(witness));
    tracing::debug!(name: "try_read_proof", ?task_id, ?path_proof);

    let proof = if let Ok(proof) = read_json::<_, ProofEnum>(&path_proof) {
        tracing::debug!(name: "early_return_proof", ?task_id);
        proof
    } else {
        let stark_proofs: Vec<&StarkProof> = proofs
            .iter()
            .map(|p| p.as_stark_proof().expect("must be stark proof"))
            .collect();

        let (input_commits, def_inputs, def_states) = if let Some(child) = child_prover {
            compute_deferral_data(child, &stark_proofs)?
        } else {
            (vec![], vec![], vec![])
        };

        let task = T::build_universal_task(
            witness,
            stark_proofs.into_iter(),
            input_commits,
        )?;
        // Construct stark proof for the circuit.
        let proof = if def_inputs.is_empty() {
            prover.prove_task(&task, false)?
        } else {
            prover.prove_task_with_deferral(&task, false, &def_inputs, &def_states)?
        };
        write_json(&path_proof, &proof)?;
        tracing::debug!(name: "cached_proof", ?task_id);

        proof
    };

    // Verify proof using the prover's own aggregation VK (required for deferral-enabled circuits).
    let agg_vk = prover.get_agg_vk()?;
    UniversalVerifier::verify_stark_proof_with_vk(
        &agg_vk,
        proof.as_stark_proof().expect("should be stark proof"),
        &vk,
    )?;

    Ok(proof)
}

/// End-to-end test for a single proving task to generate an EVM-verifiable SNARK proof.
#[instrument(name = "prove_verify_single_evm", skip_all)]
pub fn prove_verify_single_evm<T>(
    prover: &mut impl TaskProver,
    witness: &T::Witness,
    proofs: &[ProofEnum],
) -> eyre::Result<ProofEnum>
where
    T: ProverTester,
{
    prove_verify_single_evm_with_deferral::<T>(prover, witness, proofs, None)
}

/// Locate the `prover-split` binary used to run STARK/SNARK in separate processes.
/// The binary is expected next to the current test executable
/// (`target/<profile>/prover-split`). The Makefile / CI must build it beforehand
/// (`cargo build --release --bin prover-split`).
fn prover_split_binary_path() -> eyre::Result<PathBuf> {
    let mut path = std::env::current_exe()?;
    path.pop(); // deps/
    path.pop(); // <profile>/
    path.push("prover-split");
    if !path.exists() {
        eyre::bail!("prover-split binary not found at {path:?}; run `cargo build --release --bin prover-split` first");
    }
    Ok(path)
}

/// Generate the final EVM proof in a fresh `prover-split` subprocess.
///
/// The parent test process already ran chunk/batch STARK proving, which leaves
/// the CUDA context with a large memory footprint. Spawning a new process for
/// the bundle STARK + SNARK steps gives the SNARK step a clean CUDA context and
/// avoids the 24 GB GPU OOM that occurs when everything runs in one process.
fn prove_evm_split<T>(
    task: &UniversalProvingTask,
    def_inputs: &[DeferralInput],
    def_states: &[DeferralState],
    task_id: &str,
) -> eyre::Result<ProofEnum>
where
    T: ProverTester,
{
    let binary = prover_split_binary_path()?;
    let work_dir = DIR_TESTRUN
        .get()
        .ok_or(eyre::eyre!("missing testrun dir"))?
        .join("split")
        .join(task_id);
    std::fs::create_dir_all(&work_dir)?;

    // Use bincode (not JSON) because DeferralState contains HashMap keys that
    // are not valid JSON strings.
    let task_file = work_dir.join("task.bin");
    let def_inputs_file = work_dir.join("def_inputs.bin");
    let def_states_file = work_dir.join("def_states.bin");
    let proof_file = work_dir.join("proof.json");

    std::fs::write(&task_file, bincode_v1::serialize(task)?)?;
    std::fs::write(&def_inputs_file, bincode_v1::serialize(def_inputs)?)?;
    std::fs::write(&def_states_file, bincode_v1::serialize(def_states)?)?;

    tracing::info!("spawning EVM proof subprocess");
    let status = std::process::Command::new(&binary)
        .arg("evm")
        .arg("--asset-base-dir")
        .arg(ASSET_BASE_DIR.as_path())
        .arg("--circuit")
        .arg(T::NAME)
        .arg("--task")
        .arg(&task_file)
        .arg("--def-inputs")
        .arg(&def_inputs_file)
        .arg("--def-states")
        .arg(&def_states_file)
        .arg("--output")
        .arg(&proof_file)
        .status()?;
    if !status.success() {
        eyre::bail!("EVM proof subprocess failed");
    }

    let proof: ProofEnum = read_json(&proof_file)
        .map_err(|e| eyre::eyre!("failed to read EVM proof: {e}"))?;
    Ok(proof)
}

/// End-to-end EVM proof with deferred STARK verification (v2).
#[instrument(name = "prove_verify_single_evm_with_deferral", skip_all)]
pub fn prove_verify_single_evm_with_deferral<T>(
    prover: &mut impl TaskProver,
    witness: &T::Witness,
    proofs: &[ProofEnum],
    child_prover: Option<&Prover>,
) -> eyre::Result<ProofEnum>
where
    T: ProverTester,
{
    // Setup prover.
    let path_assets = DIR_TESTRUN
        .get()
        .ok_or(eyre::eyre!("missing testrun dir"))?
        .join(T::DIR_ASSETS);
    let cache_dir = path_assets.join(DIR_PROOFS);
    std::fs::create_dir_all(&cache_dir)?;

    // Dump verifier-only assets to disk.
    let path_verifier_dir = ASSET_BASE_DIR.join("verifier");
    let verifier = UniversalVerifier::setup(&path_verifier_dir)?;

    // Try reading proof from cache if available, and early return in that case.
    let task_id = witness.identifier();

    let path_proof = cache_dir.join(T::fd_proof(witness));
    tracing::debug!(name: "try_read_evm_proof", ?task_id, ?path_proof);

    let proof = if let Ok(proof) = read_json::<_, ProofEnum>(&path_proof) {
        tracing::debug!(name: "early_return_evm_proof", ?task_id);
        proof
    } else {
        let stark_proofs: Vec<&StarkProof> = proofs
            .iter()
            .map(|p| p.as_stark_proof().expect("must be stark proof"))
            .collect();

        let (input_commits, def_inputs, def_states) = if let Some(child) = child_prover {
            compute_deferral_data(child, &stark_proofs)?
        } else {
            (vec![], vec![], vec![])
        };

        let task = T::build_universal_task(
            witness,
            stark_proofs.into_iter(),
            input_commits,
        )?;
        // Construct the final EVM proof. For circuits that use deferral (bundle),
        // default to a fresh subprocess so the Halo2 SNARK step starts with a clean
        // CUDA context. Set SCROLL_ZKVM_SPLIT_STARK_SNARK=0 to run in-process.
        let proof = if def_inputs.is_empty() {
            prover.prove_task(&task, true)?
        } else if std::env::var(ENV_SPLIT_STARK_SNARK).as_deref() == Ok("0") {
            prover.prove_task_with_deferral(&task, true, &def_inputs, &def_states)?
        } else {
            prove_evm_split::<T>(&task, &def_inputs, &def_states, &task_id)?
        };
        write_json(&path_proof, &proof)?;
        tracing::debug!(name: "cached_evm_proof", ?task_id);
        proof
    };

    let vk = prover.get_vk()?;
    // Verify proof.
    let gas = verifier.verify_evm_proof(
        &proof
            .clone()
            .into_evm_proof()
            .expect("must be evm proof")
            .into(),
        &vk,
    )?;
    tracing::info!("evm verify gas cost = {gas}");

    Ok(proof)
}

fn load_program_commitments() -> eyre::Result<HashMap<String, ProgramCommitment>> {
    use base64::{Engine, prelude::BASE64_STANDARD};
    let file_path = ASSET_BASE_DIR.join("verifier").join("openVmVk.json");
    let commitments: HashMap<String, String> = {
        let file = std::fs::File::open(&file_path)?;
        serde_json::from_reader(file)?
    };
    let mut result = HashMap::new();
    for (program, commitment_string) in commitments {
        let program = program.strip_suffix("_vk").unwrap().to_string();
        let commitment_bytes = hex::decode(&commitment_string)
            .or_else(|_| BASE64_STANDARD.decode(commitment_string))
            .map_err(|_| eyre::eyre!("Failed to decode program commitment for {}", program))?;
        let commitment = serialize_vk::deserialize(&commitment_bytes);
        result.insert(program, commitment);
    }
    Ok(result)
}

#[test]
fn test_project_root() {
    println!("Project root directory: {}", WORKSPACE_ROOT.display());
    assert!(
        WORKSPACE_ROOT.exists(),
        "Project root directory does not exist"
    );
    let crates = WORKSPACE_ROOT.join("crates");
    assert!(
        crates.exists(),
        "Expected 'crates' directory in project root"
    );
    assert!(
        crates.join("circuits").exists(),
        "Expected 'circuits' directory in project root"
    );
    assert!(
        crates.join("integration").exists(),
        "Expected 'integration' directory in project root"
    );
}
