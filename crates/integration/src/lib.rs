use cargo_metadata::MetadataCommand;
use once_cell::sync::OnceCell;
use openvm_sdk::StdIn;
use scroll_zkvm_prover::{
    Prover,
    utils::{read_json, vm::ExecutionResult, write_json},
};
use scroll_zkvm_types::{
    proof::{EvmProof, ProofEnum, StarkProof},
    public_inputs::ForkName,
};
use scroll_zkvm_verifier::verifier::UniversalVerifier;
use std::{
    path::{Path, PathBuf},
    process,
    sync::LazyLock,
};
use tracing::instrument;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

pub mod testers;

pub mod utils;

pub mod commitments;

pub trait PartialProvingTask {
    fn identifier(&self) -> String;

    fn write_guest_input(&self, stdin: &mut StdIn) -> Result<(), rkyv::rancor::Error>;

    fn fork_name(&self) -> ForkName;
}

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

/// Path to store release assets, root directory of zkvm-prover repository.
static DIR_OUTPUT: LazyLock<&Path> = LazyLock::new(|| {
    let path = WORKSPACE_ROOT.join(".output");
    std::fs::create_dir_all(&path).expect("failed to create output directory");
    eprintln!("DIR_OUTPUT = {}", path.display());
    Box::leak(path.into_boxed_path())
});

/// Directory to store proofs on disc.
const DIR_PROOFS: &str = "proofs";

/// File descriptor for app openvm config.
const FD_APP_CONFIG: &str = "openvm.toml";

/// File descriptor for app exe.
const FD_APP_EXE: &str = "app.vmexe";

/// Environment variable used to set the test-run's output directory for assets.
const ENV_OUTPUT_DIR: &str = "OUTPUT_DIR";

/// Every test run will write assets to a new directory.
///
/// Possibly one of the following:
/// - <DIR_OUTPUT>/chunk-tests-{timestamp}
/// - <DIR_OUTPUT>/batch-tests-{timestamp}
/// - <DIR_OUTPUT>/bundle-tests-{timestamp}
static DIR_TESTRUN: OnceCell<PathBuf> = OnceCell::new();

/// Circuit that implements functionality required to run e2e tests in specified phase (chunk/batch/bundle).
pub trait ProverTester {
    /// Tester witness type
    type Witness: rkyv::Archive + PartialProvingTask;

    /// Tester metadata type
    type Metadata: for<'a> TryFrom<&'a <Self::Witness as rkyv::Archive>::Archived>;

    /// Naming for tester
    const NAME: &str;

    /// Path to the corresponding circuit's project directory.
    const PATH_PROJECT_ROOT: &str;

    /// Prefix to use while naming app-specific data like app exe, app pk, etc.
    const DIR_ASSETS: &str;

    /// Setup directory structure for the test suite.
    fn setup() -> eyre::Result<()> {
        // Setup tracing subscriber.
        setup_logger()?;

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
        let assets_version = "dev";
        let release_dir = WORKSPACE_ROOT.join("releases").join(assets_version);
        let path_app_config = release_dir.join(Self::NAME).join(FD_APP_CONFIG);
        let path_app_exe = release_dir.join(Self::NAME).join(FD_APP_EXE);
        Ok((path_app_config, path_app_exe))
    }

    /// Load the prover with caching
    #[instrument("Prover::load_prover")]
    fn load_prover(with_evm: bool) -> eyre::Result<Prover> {
        // Since Prover doesn't implement Clone or Send, we can't cache instances directly
        // Instead, we'll use a simple approach to ensure setup happens only once per test run

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


        let prover = scroll_zkvm_prover::Prover::setup(config, with_evm, Some(Self::NAME))?;

        Ok(prover)
    }

    /// File descriptor for the proof saved to disc.
    #[instrument("Prover::fd_proof", skip_all, fields(task_id = task.identifier(), path_proof))]
    fn fd_proof(task: &impl PartialProvingTask) -> String {
        let path_proof = format!("{}-{}.json", Self::NAME, task.identifier());
        path_proof
    }

    fn build_guest_input<'a>(
        witness: &Self::Witness,
        aggregated_proofs: impl Iterator<Item = &'a StarkProof>,
    ) -> Result<StdIn, rkyv::rancor::Error> {
        use openvm_native_recursion::hints::Hintable;

        let mut stdin = StdIn::default();
        witness.write_guest_input(&mut stdin)?;

        for proof in aggregated_proofs {
            let streams = proof.proofs[0].write();
            for s in &streams {
                stdin.write_field(s);
            }
        }
        Ok(stdin)
    }
}

/// Enviroment settings for test: fork
pub fn testing_hardfork() -> ForkName {
    ForkName::Feynman
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
    prover: &Prover,
    witness: &T::Witness,
    proofs: &[ProofEnum],
) -> eyre::Result<ExecutionResult> {
    let stdin = T::build_guest_input(
        witness,
        proofs
            .iter()
            .map(|p| p.as_stark_proof().expect("must be stark proof")),
    )?;

    let ret = prover.execute_and_check_with_full_result(&stdin)?;
    Ok(ret)
}

/// End-to-end test for proving witnesses of the same prover.
#[instrument(name = "prove_verify", skip_all, fields(task_id))]
pub fn prove_verify<T: ProverTester>(
    prover: &mut Prover,
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
    let vk = prover.get_app_vk();

    // Try reading proof from cache if available, and early return in that case.
    let task_id = witness.identifier();

    let path_proof = cache_dir.join(T::fd_proof(witness));
    tracing::debug!(name: "try_read_proof", ?task_id, ?path_proof);

    let proof = if let Ok(proof) = read_json::<_, ProofEnum>(&path_proof) {
        tracing::debug!(name: "early_return_proof", ?task_id);
        proof
    } else {
        let stdin = T::build_guest_input(
            witness,
            proofs
                .iter()
                .map(|p| p.as_stark_proof().expect("must be stark proof")),
        )?;
        // Construct stark proof for the circuit.
        let proof = prover.gen_proof_stark(stdin)?.into();
        write_json(&path_proof, &proof)?;
        tracing::debug!(name: "cached_proof", ?task_id);

        proof
    };

    // Verify proof.
    UniversalVerifier::new()
        .verify_stark_proof(proof.as_stark_proof().expect("should be stark proof"), &vk)?;

    Ok(proof)
}

/// End-to-end test for a single proving task to generate an EVM-verifiable SNARK proof.
#[instrument(name = "prove_verify_single_evm", skip_all)]
pub fn prove_verify_single_evm<T>(
    prover: &Prover,
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
    let path_verifier_code = WORKSPACE_ROOT
        .join("releases")
        .join("dev")
        .join("verifier")
        .join("verifier.bin");
    let verifier =
        scroll_zkvm_verifier::verifier::UniversalVerifier::setup(Some(&path_verifier_code))?;

    // Try reading proof from cache if available, and early return in that case.
    let task_id = witness.identifier();

    let path_proof = cache_dir.join(T::fd_proof(witness));
    tracing::debug!(name: "try_read_evm_proof", ?task_id, ?path_proof);

    let proof = if let Ok(proof) = read_json::<_, ProofEnum>(&path_proof) {
        tracing::debug!(name: "early_return_evm_proof", ?task_id);
        proof
    } else {
        let stdin = T::build_guest_input(
            witness,
            proofs
                .iter()
                .map(|p| p.as_stark_proof().expect("must be stark proof")),
        )?;
        // Construct stark proof for the circuit.
        let proof: EvmProof = prover.gen_proof_snark(stdin)?.into();
        write_json(&path_proof, &proof)?;
        tracing::debug!(name: "cached_evm_proof", ?task_id);
        proof.into()
    };

    let vk = prover.get_app_vk();
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
