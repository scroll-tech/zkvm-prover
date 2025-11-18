use crate::axiom::AxiomProver;
use cargo_metadata::MetadataCommand;
use once_cell::sync::OnceCell;
use openvm_sdk::{Sdk, StdIn};
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
    path::{Path, PathBuf},
    process,
    sync::LazyLock,
};
use tracing::instrument;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

pub mod testers;

pub mod utils;

mod axiom;

/// Directory to store proofs on disc.
const DIR_PROOFS: &str = "proofs";

/// File descriptor for app openvm config.
const FD_APP_CONFIG: &str = "openvm.toml";

/// File descriptor for app exe.
const FD_APP_EXE: &str = "app.vmexe";

/// Environment variable used to set the test-run's output directory for assets.
const ENV_OUTPUT_DIR: &str = "OUTPUT_DIR";

/// Enviroment settings for test: fork
pub fn testing_hardfork() -> ForkName {
    ForkName::Feynman
}

/// Test settings (version).
pub fn testing_version() -> Version {
    Version::feynman()
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

pub static AXIOM_PROGRAM_IDS: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    let axiom_program_ids = ASSET_BASE_DIR.join("axiom_program_ids.json");
    let mut program_ids: HashMap<String, String> =
        read_json(&axiom_program_ids).expect("failed to read axiom program ids");
    program_ids.shrink_to_fit();
    eprintln!("AXIOM_PROGRAM_IDS = {program_ids:#?}");
    program_ids
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

    fn legacy_rkyv_archive(&self) -> eyre::Result<Vec<u8>>;

    fn archive(&self) -> eyre::Result<Vec<u8>>
    where
        Self: Sized,
    {
        let bytes: Vec<u8> = match GUEST_VERSION.as_ref() {
            "0.5.2" => self.legacy_rkyv_archive()?,
            _ => {
                let config = bincode::config::standard();
                bincode::serde::encode_to_vec(self, config)?
            }
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
            is_openvm_v13: *GUEST_VERSION == "0.5.2",
            ..Default::default()
        };
        let prover = Prover::setup(config, Some(Self::NAME))?;

        Ok(prover)
    }

    /// Load the axiom program prover
    fn load_axiom_prover() -> eyre::Result<AxiomProver> {
        let mut prover = Self::load_prover(false)?;
        let vk = prover.get_app_commitment();
        let vk = hex::encode(serialize_vk::serialize(&vk));
        let program_id = AXIOM_PROGRAM_IDS
            .get(&vk)
            .ok_or_else(|| eyre::eyre!("missing axiom program id for {}: {}", Self::NAME, vk))?
            .to_string();
        let prover = AxiomProver::from_env(
            Self::NAME.to_string(),
            scroll_zkvm_types::axiom::get_config_id(Self::NAME).to_string(),
            program_id,
        );
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
    ) -> eyre::Result<UniversalProvingTask> {
        Ok(UniversalProvingTask {
            serialized_witness: vec![witness.archive()?],
            aggregated_proofs: aggregated_proofs.cloned().collect(),
            fork_name: witness.fork_name().as_str().to_string(),
            identifier: witness.identifier(),
            vk: Default::default(),
        })
    }

    fn build_guest_input<'a>(
        witness: &Self::Witness,
        aggregated_proofs: impl Iterator<Item = &'a StarkProof>,
    ) -> eyre::Result<StdIn> {
        use scroll_zkvm_prover::task::ProvingTask;
        Ok(Self::build_universal_task(witness, aggregated_proofs)?.build_guest_input())
    }
}

pub trait TaskProver {
    fn name(&self) -> &str;
    fn prove_task(&mut self, t: &UniversalProvingTask, gen_snark: bool) -> eyre::Result<ProofEnum>;
    fn get_vk(&mut self) -> eyre::Result<Vec<u8>>;
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
            Ok(self.gen_proof_stark(stdin)?.into())
        } else {
            let proof: EvmProof = self.gen_proof_snark(stdin)?.into();
            Ok(proof.into())
        }
    }

    fn get_vk(&mut self) -> eyre::Result<Vec<u8>> {
        Ok(self.get_app_vk())
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

    let sdk = Sdk::new(app_config)?;
    let ret = scroll_zkvm_prover::utils::vm::execute_guest(&sdk, app_exe, &stdin)?;
    Ok(ret)
}

/// End-to-end test for proving witnesses of the same prover.
#[instrument(name = "prove_verify", skip_all, fields(task_id, prover_name = prover.name()))]
pub fn prove_verify<T: ProverTester>(
    prover: &mut impl TaskProver,
    witness: &T::Witness,
    proofs: &[ProofEnum],
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
        let task = T::build_universal_task(
            witness,
            proofs
                .iter()
                .map(|p| p.as_stark_proof().expect("must be stark proof")),
        )?;
        // Construct stark proof for the circuit.
        let proof = prover.prove_task(&task, false)?;
        write_json(&path_proof, &proof)?;
        tracing::debug!(name: "cached_proof", ?task_id);

        proof
    };

    // Verify proof.
    UniversalVerifier::verify_stark_proof_with_vk(
        &AGG_STARK_PROVING_KEY.get_agg_vk(),
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
        let task = T::build_universal_task(
            witness,
            proofs
                .iter()
                .map(|p| p.as_stark_proof().expect("must be stark proof")),
        )?;
        // Construct stark proof for the circuit.
        let proof = prover.prove_task(&task, true)?;
        write_json(&path_proof, &proof)?;
        tracing::debug!(name: "cached_evm_proof", ?task_id);
        proof
    };

    let vk = prover.get_vk()?;
    // Verify proof.
    verifier.verify_evm_proof(
        &proof
            .clone()
            .into_evm_proof()
            .expect("must be evm proof")
            .into(),
        &vk,
    )?;

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
