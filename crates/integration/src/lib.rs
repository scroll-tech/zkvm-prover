use cargo_metadata::MetadataCommand;
use once_cell::sync::OnceCell;
use openvm_sdk::{StdIn, F};
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
use std::{
    path::{Path, PathBuf},
    process,
    sync::LazyLock,
};
use openvm_circuit::arch::instructions::exe::VmExe;
use openvm_sdk::config::{AppConfig, SdkVmConfig};
use tracing::instrument;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

pub mod testers;

pub mod utils;

mod axiom;

/// Directory to store proofs on disc.
const DIR_PROOFS: &str = "proofs";

/// File descriptor for app openvm config.
const FD_APP_CONFIG: &str = "openvm.toml";

/// File descriptor for app elf.
const FD_APP_ELF: &str = "app.elf";

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
pub fn guest_version() -> String {
    std::env::var("GUEST_VERSION").unwrap_or_else(|_| "dev".to_string())
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

#[derive(Debug, Clone)]
pub struct AssetPaths {
    pub app_config: PathBuf,
    pub app_elf: PathBuf,
    pub app_exe: PathBuf,
}

impl AssetPaths {
    pub fn read_app_config(&self) -> eyre::Result<AppConfig<SdkVmConfig>> {
        Ok(read_app_config(self.app_config.as_path())?)
    }

    pub fn read_app_elf(&self) -> eyre::Result<Vec<u8>> {
        Ok(std::fs::read(self.app_elf.as_path())?)
    }

    pub fn read_app_exe(&self) -> eyre::Result<VmExe<F>> {
        Ok(read_app_exe(self.app_exe.as_path())?)
    }

    pub fn read_raw_app_exe(&self) -> eyre::Result<Vec<u8>> {
        Ok(std::fs::read(self.app_exe.as_path())?)
    }
}

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
        let bytes: Vec<u8> = match guest_version().as_str() {
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

    /// Load the assets paths
    fn get_asset_paths() -> eyre::Result<AssetPaths> {
        let assets_version = guest_version();
        let release_dir = WORKSPACE_ROOT.join("releases").join(assets_version);
        let app_config = release_dir.join(Self::NAME).join(FD_APP_CONFIG);
        let app_elf = release_dir.join(Self::NAME).join(FD_APP_ELF);
        let app_exe = release_dir.join(Self::NAME).join(FD_APP_EXE);
        Ok(AssetPaths {
            app_config,
            app_elf,
            app_exe,
        })
    }

    /// Load the prover
    #[instrument("Prover::load_prover")]
    fn load_prover(with_evm: bool) -> eyre::Result<Prover> {
        let paths = Self::get_asset_paths()?;

        let path_assets = DIR_TESTRUN
            .get()
            .ok_or(eyre::eyre!("missing testrun dir"))?
            .join(Self::DIR_ASSETS);
        std::fs::create_dir_all(&path_assets)?;

        let config = scroll_zkvm_prover::ProverConfig {
            path_app_exe: paths.app_exe,
            path_app_config: paths.app_config,
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
    fn get_vk(&mut self) -> Vec<u8>;
}

impl TaskProver for Prover {
    fn name(&self) -> &str {self.prover_name.as_str()}

    fn get_vk(&mut self) -> Vec<u8> { self.get_app_vk() }

    fn prove_task(&mut self, t: &UniversalProvingTask, gen_snark: bool) -> eyre::Result<ProofEnum>{
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
    let assets = T::get_asset_paths()?;
    let app_exe = assets.read_app_exe()?;
    let app_config = assets.read_app_config()?;
    let stdin = T::build_guest_input(
        witness,
        proofs
            .iter()
            .map(|p| p.as_stark_proof().expect("must be stark proof")),
    )?;

    let ret =
        scroll_zkvm_prover::utils::vm::execute_guest(app_config.app_vm_config, &app_exe, &stdin)?;
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
    let vk = prover.get_vk();

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
    let path_verifier_dir = WORKSPACE_ROOT
        .join("releases")
        .join(guest_version())
        .join("verifier");
    let verifier = scroll_zkvm_verifier::verifier::UniversalVerifier::setup(&path_verifier_dir)?;

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

    let vk = prover.get_vk();
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

pub fn load_program_commitments(program: &str) -> eyre::Result<ProgramCommitment> {
    use base64::{Engine, prelude::BASE64_STANDARD};
    let file_path = WORKSPACE_ROOT
        .join("releases")
        .join(guest_version())
        .join("verifier")
        .join("openVmVk.json");
    let json_value: serde_json::Value = {
        let file = std::fs::File::open(&file_path)?;
        serde_json::from_reader(file)?
    };
    let commitment_string = json_value[&format!("{}_vk", program)]
        .as_str()
        .ok_or_else(|| eyre::eyre!("Missing or invalid program commitment for {}", program))?;
    let commitment_bytes = hex::decode(commitment_string)
        .or_else(|_| BASE64_STANDARD.decode(commitment_string))
        .map_err(|_| eyre::eyre!("Failed to decode program commitment for {}", program))?;
    let commitment = serialize_vk::deserialize(&commitment_bytes);
    Ok(commitment)
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
